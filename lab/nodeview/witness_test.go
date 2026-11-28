package nodeview

import (
	"encoding/binary"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"slices"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/wire"
)

var seed117TrustedRoutes = [][3]uint8{{3, 0, 4}, {0, 1, 4}, {3, 2, 4}, {0, 2, 4}, {1, 0, 4}, {3, 2, 4}, {0, 3, 4}, {3, 1, 4}, {0, 2, 4}, {2, 0, 4}, {0, 1, 4}, {2, 3, 4}, {1, 2, 4}, {0, 2, 4}, {2, 1, 4}, {3, 2, 4}, {2, 0, 4}, {3, 2, 4}, {0, 3, 4}, {1, 2, 4}, {2, 3, 4}, {3, 2, 4}, {3, 0, 4}, {1, 0, 4}, {2, 0, 4}, {0, 1, 4}, {3, 1, 4}, {0, 3, 4}, {2, 3, 4}, {2, 1, 4}, {1, 3, 4}, {2, 1, 4}}

func TestRouteConnectionsKnown(t *testing.T) {
	routes := seed117TrustedRoutes
	var entry, middle, exit [5]int
	for _, r := range routes {
		entry[r[0]]++
		middle[r[1]]++
		exit[r[2]]++
	}
	if entry != [5]int{9, 5, 9, 9, 0} || middle != [5]int{7, 8, 10, 7, 0} || exit != [5]int{0, 0, 0, 0, 32} {
		t.Fatalf("route split %v %v %v", entry, middle, exit)
	}
	// base = [2*(9+7), 2*(5+8), 2*(9+10), 2*(9+7), 1*32]
	base, ok := routeConnections(routes, make([]uint64, len(routes)))
	if !ok || base != [5]uint64{32, 26, 38, 32, 32} {
		t.Fatalf("base %v", base)
	}
	ones := make([]uint64, len(routes))
	for i := range ones {
		ones[i] = 1
	}
	// every side rebuilt once doubles each count
	if got, ok := routeConnections(routes, ones); !ok || got != [5]uint64{64, 52, 76, 64, 64} {
		t.Fatalf("one rebuild each %v", got)
	}
	// relay 2 is entry or middle for 19 sides; 15 of them with R = 3 give 38 + 2*3*15 = 128
	rebuilt := make([]uint64, len(routes))
	through := 0
	for i, r := range routes {
		if (r[0] == 2 || r[1] == 2) && through < 15 {
			rebuilt[i] = 3
			through++
		}
	}
	got, ok := routeConnections(routes, rebuilt)
	if !ok || through != 15 || got[2] != 128 {
		t.Fatalf("relay 2 at the cap %v", got)
	}
	for i, r := range routes {
		if rebuilt[i] == 3 && (r[0] == 2 || r[1] == 2) {
			rebuilt[i]++
			break
		}
	}
	if got, ok = routeConnections(routes, rebuilt); !ok || got[2] != 130 {
		t.Fatalf("one more rebuild %v", got)
	}
	if _, ok = routeConnections(routes, rebuilt[:31]); ok {
		t.Fatal("length mismatch accepted")
	}
	if _, ok = routeConnections([][3]uint8{{5, 0, 4}}, []uint64{0}); ok {
		t.Fatal("node 5 accepted")
	}
	if _, ok = routeConnections([][3]uint8{{1, 1, 4}}, []uint64{0}); ok {
		t.Fatal("repeated node accepted")
	}
	if _, ok = routeConnections([][3]uint8{{0, 1, 4}}, []uint64{math.MaxUint64}); ok {
		t.Fatal("overflow accepted")
	}
}

type witnessClock struct{ ns int64 }

func (c *witnessClock) now() int64 { return c.ns }

func witnessCollector(t *testing.T, clock *witnessClock) *collector {
	t.Helper()
	buffer, e := secmem.New(32768)
	if e != nil {
		t.Fatal(e)
	}
	c := &collector{arena: &lockedArena{buffer: buffer}, keys: make(map[*secmem.Buffer]keyTag), bindings: make(map[uint64]uint32), transportIndex: make(map[transportKey][]int), contexts: make(map[[32]byte]*setupView), observerValid: true, now: clock.now}
	t.Cleanup(c.close)
	return c
}

func TestObserveConnCumulativeBoundary(t *testing.T) {
	clock := &witnessClock{ns: 1000}
	c := witnessCollector(t, clock)
	var last *observedConn
	for i := range maxConnections {
		o, e := observeConn(&providerIOConn{local: uint16(20000 + i), remote: 30000}, c, true)
		if e != nil {
			t.Fatalf("connection %d: %v", i, e)
		}
		if i < maxConnections-1 {
			_ = o.Close()
		} else {
			last = o
		}
	}
	if c.err != ReasonNone || c.summary.ConnectionsHighWater != 128 || len(c.view.connections) != 128 {
		t.Fatal("128 distinct connections were not admitted")
	}
	clock.ns = 2000
	if _, e := observeConn(&providerIOConn{local: 21000, remote: 30000}, c, true); reasonOf(e) != ReasonLimit {
		t.Fatal("129th connection admitted")
	}
	if c.err != ReasonLimit || !c.latch.set || c.latch.site != siteConnCap || c.latch.connections != 128 || c.latch.at != 2000 || c.latch.phase != phaseBeforeBegin {
		t.Fatalf("latch %+v", c.latch)
	}
	_ = last.Close()
	clock.ns = 3000
	if _, e := observeConn(&providerIOConn{local: 21001, remote: 30000}, c, true); reasonOf(e) != ReasonLimit {
		t.Fatal("closing a connection freed a slot of the cumulative table")
	}
	if c.latch.at != 2000 || len(c.view.connections) != 128 {
		t.Fatal("second refusal rewrote the latch")
	}
}

func TestObserveConnPortPairAfterClose(t *testing.T) {
	clock := &witnessClock{ns: 1000000000}
	a := witnessCollector(t, clock)
	o, e := observeConn(&providerIOConn{local: 40000, remote: 50000}, a, true)
	if e != nil {
		t.Fatal(e)
	}
	clock.ns = 1200000000
	_ = o.Close()
	// closed at 1.2 s, reused at 1.75 s: 550 ms
	clock.ns = 1750000000
	if _, e = observeConn(&providerIOConn{local: 40000, remote: 50000}, a, true); reasonOf(e) != ReasonContract {
		t.Fatal("closed pair reused")
	}
	if a.latch.site != sitePortPair || a.err != ReasonContract || a.latch.closedAgeNS != 550000000 || a.latch.at != 1750000000 {
		t.Fatalf("latch %+v", a.latch)
	}
	clock.ns = 1900000000
	if _, e = observeConn(&providerIOConn{local: 40000, remote: 50000}, a, true); e == nil {
		t.Fatal("second reuse admitted")
	}
	if a.latch.site != sitePortPair || a.latch.at != 1750000000 || a.latch.closedAgeNS != 550000000 {
		t.Fatal("second hit rewrote the latch")
	}

	clock.ns = 1000000000
	b := witnessCollector(t, clock)
	o, e = observeConn(&providerIOConn{local: 50000, remote: 40000}, b, false)
	if e != nil {
		t.Fatal(e)
	}
	clock.ns = 1200000000
	_ = o.Close()
	clock.ns = 1750000000
	if _, e = observeConn(&providerIOConn{local: 50000, remote: 40000}, b, false); reasonOf(e) != ReasonContract || b.latch.site != sitePortPair || b.latch.closedAgeNS != 550000000 {
		t.Fatal("far end of the same pair was not latched the same way")
	}

	clock.ns = 2000000000
	d := witnessCollector(t, clock)
	o, e = observeConn(&providerIOConn{local: 40001, remote: 50001}, d, true)
	if e != nil {
		t.Fatal(e)
	}
	_ = o.Close()
	// Close takes its time before the lock, so a later close can be seen by an earlier start
	clock.ns = 1500000000
	if _, e = observeConn(&providerIOConn{local: 40001, remote: 50001}, d, true); reasonOf(e) != ReasonContract || d.latch.closedAgeNS != 0 || d.latch.site != sitePortPair {
		t.Fatalf("closed after start did not saturate: %+v", d.latch)
	}
}

func TestEveryLimitSiteMapped(t *testing.T) {
	want := map[string][]string{
		"siteConnCap": {"observeConn"}, "sitePortPair": {"observeConn"}, "siteFramePending": {"frame"}, "siteFramesCap": {"frame"},
		"siteTransportPending": {"transport"}, "siteTransportCap": {"transport"}, "siteCellsCap": {"hopOperation"},
		"siteContextsCap": {"setupOpened"}, "siteSetupDuplicate": {"setupOpened"}, "siteInventoryContexts": {"inventory"},
		"siteInventoryPending": {"inventory"}, "siteAssociatePending": {"associate"}, "siteGenerationWrap": {"generation"},
		"siteArena": {"copy"}, "siteTruthRecords": {"alias"}, "siteEqualityWrap": {"alias"},
		"siteMailboxRecords": {"observeDeliver", "observeDeliver"}, "siteKeyContexts": {"DeriveKey"},
		"siteCallbackOverflow": {"recordLocked"}, "siteGeneric": {"fail"},
	}
	got := map[string][]string{}
	fs := token.NewFileSet()
	for _, name := range []string{"observe.go", "frames.go", "peer.go", "provider.go", "overhead.go"} {
		file, e := parser.ParseFile(fs, name, nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				reason, _ := call.Args[0].(*ast.Ident)
				switch sel.Sel.Name {
				case "fail":
					if reason != nil && reason.Name == "ReasonLimit" {
						t.Errorf("%s: collector limit failure without a site in %s", fs.Position(call.Pos()), fn.Name.Name)
					}
				case "failAt":
					site, _ := call.Args[1].(*ast.Ident)
					if site == nil {
						t.Errorf("%s: site is not a constant", fs.Position(call.Pos()))
						return true
					}
					if reason != nil && reason.Name == "ReasonLimit" && site.Name == "siteGeneric" {
						t.Errorf("%s: limit failure with the generic site", fs.Position(call.Pos()))
					}
					got[site.Name] = append(got[site.Name], fn.Name.Name)
				}
				return true
			})
		}
	}
	if len(got) != len(want) {
		t.Fatalf("sites %v", got)
	}
	for site, funcs := range want {
		if !slices.Equal(got[site], funcs) {
			t.Errorf("%s at %v, want %v", site, got[site], funcs)
		}
	}
	if len(latchSiteNames) != int(siteLast)+1 {
		t.Fatal("site names out of step")
	}
}

func TestResidenceCounts(t *testing.T) {
	full := stageInput | stageWritten
	cells := []cellView{
		{inputTime: 0, writeTime: 500000000, localTime: 10, stages: full},
		{inputTime: 0, writeTime: 1200000000, localTime: 10, stages: full},
		{inputTime: 100000000, writeTime: 3700000000, localTime: 10, stages: full},
		{inputTime: 0, writeTime: 7000000000, localTime: 10, stages: full},
		{inputTime: 0, writeTime: 9000000000, localTime: 10, stages: stageInput},
		{inputTime: 0, writeTime: 9000000000, localTime: 500, stages: full},
	}
	// residences 0.5, 1.2, 3.6, 7.0 s inside the window; >= 3.5 s: 3.6 and 7.0; >= 7 s: 7.0
	over3500, over7, maxNS := residenceCounts(cells, func(t int64) bool { return t < 100 })
	if over3500 != 2 || over7 != 1 || maxNS != 7000000000 {
		t.Fatal(over3500, over7, maxNS)
	}
}

func TestDeliverThirds(t *testing.T) {
	s := int64(1000000000)
	us := int64(1000)
	rows := []mailboxObservation{
		{CallNS: 1 * s, ReturnNS: 1*s + 40*us, Complete: true},
		{CallNS: 5 * s, ReturnNS: 5*s + 60*us, Complete: true},
		{CallNS: 15 * s, ReturnNS: 15*s + 80*us, Complete: true},
		{CallNS: 25 * s, ReturnNS: 25*s + 100*us, Complete: true},
		{CallNS: 29 * s, ReturnNS: 29*s + 120*us, Complete: true},
	}
	// window [0, 30 s): early [0, 10 s) 40+60 us, late [20, 30 s) 100+120 us
	ec, ens, lc, lns := deliverThirds(rows, 0, 30*s)
	if ec != 2 || ens != 100000 || lc != 2 || lns != 220000 {
		t.Fatal(ec, ens, lc, lns)
	}
}

func TestLatchOffset(t *testing.T) {
	epoch := int64(5000000000)
	if int64(latchOffset(epoch-150000000, epoch)) != -150000000 || int64(latchOffset(epoch+2000000000, epoch)) != 2000000000 || latchOffset(epoch, 0) != 0 {
		t.Fatal("offset")
	}
	for _, c := range []struct {
		at      int64
		begun   bool
		cleanup bool
		want    uint8
	}{{10, false, true, phaseBeforeBegin}, {10, true, false, phaseLead}, {epoch, true, false, phaseWindow}, {2 * epoch, true, false, phaseDrain}, {epoch, true, true, phaseCleanup}} {
		if got := latchPhase(c.at, c.begun, epoch, 2*epoch, c.cleanup); got != c.want {
			t.Fatal(c, got)
		}
	}
}

func TestFailAtSites(t *testing.T) {
	cases := []struct {
		site   latchSite
		reason Reason
		run    func(*collector)
	}{
		{siteConnCap, ReasonLimit, func(c *collector) {
			c.view.connections = make([]connectionView, maxConnections)
			_, _ = observeConn(&providerIOConn{local: 1, remote: 2}, c, true)
		}},
		{siteFramePending, ReasonLimit, func(c *collector) {
			c.pendingFrames = make([]int, maxPendingFrames)
			(&observedConn{c: c, generation: 1}).frame(make([]byte, 528), 0, 1)
		}},
		{siteFramesCap, ReasonLimit, func(c *collector) {
			c.view.frames = make([]frameView, maxLifecycles*2)
			(&observedConn{c: c, generation: 1}).frame(make([]byte, 528), 0, 1)
		}},
		{siteTransportPending, ReasonLimit, func(c *collector) {
			c.pendingTransports = make([]int, maxPendingFrames)
			providerIOTransport(c, 1, true, make([]byte, 528), 7)
		}},
		{siteTransportCap, ReasonLimit, func(c *collector) {
			c.transports = make([]transportView, maxLifecycles*2)
			providerIOTransport(c, 1, true, make([]byte, 528), 7)
		}},
		{siteInventoryContexts, ReasonLimit, func(c *collector) {
			c.summary.ContextsHighWater = maxContexts + 1
			c.summary.PendingHighWater = maxPendingFrames + 1
			c.inventory()
		}},
		{siteInventoryPending, ReasonLimit, func(c *collector) {
			c.summary.PendingHighWater = maxPendingFrames + 1
			c.inventory()
		}},
		{siteAssociatePending, ReasonLimit, func(c *collector) {
			c.view.frames = make([]frameView, maxPendingFrames+1)
			for i := range c.view.frames {
				c.pendingFrames = append(c.pendingFrames, i)
			}
			c.associate()
		}},
		{siteGenerationWrap, ReasonLimit, func(c *collector) {
			c.next = math.MaxUint32
			c.generation()
		}},
		{siteArena, ReasonLimit, func(c *collector) {
			c.copy(make([]byte, 65536))
		}},
		{siteTruthRecords, ReasonLimit, func(c *collector) {
			m := &mailboxCapture{queues: make([]equalityEntry, maxTruthRecords)}
			m.alias(c, []byte{1}, false)
		}},
		{siteEqualityWrap, ReasonLimit, func(c *collector) {
			m := &mailboxCapture{next: math.MaxUint32}
			m.alias(c, []byte{1}, false)
		}},
		{siteCallbackOverflow, ReasonLimit, func(c *collector) {
			c.summary.CallbackNS = math.MaxUint64
			c.recordLocked(0, true)
		}},
		{siteSetupDuplicate, ReasonContract, func(c *collector) {
			context := [32]byte{1}
			c.view.setups = []setupView{{context: context}}
			witnessSetupOpened(c, context)
		}},
		{siteContextsCap, ReasonContract, func(c *collector) {
			c.view.setups = make([]setupView, maxContexts)
			witnessSetupOpened(c, [32]byte{1})
		}},
		{siteCellsCap, ReasonLimit, func(c *collector) {
			c.view.setups = []setupView{{hop: 5, circuit: 9}}
			c.view.cells = make([]cellView, maxLifecycles)
			nonce := make([]byte, 16)
			binary.BigEndian.PutUint64(nonce[8:], 9)
			ad := make([]byte, 11)
			ad[0], ad[1] = wire.Version, byte(wire.KindData)
			c.hopOperation(5, true, nonce, make([]byte, wire.BodySize), make([]byte, wire.BodySize-16), ad, 1)
		}},
		{siteMailboxRecords, ReasonLimit, func(c *collector) {
			c.mailboxOrder = maxTruthRecords
			witnessDeliver(c)
		}},
		{siteMailboxRecords, ReasonLimit, func(c *collector) {
			c.view.mailbox = make([]mailboxObservation, maxTruthRecords)
			witnessDeliver(c)
		}},
		{siteKeyContexts, ReasonLimit, func(c *collector) {
			base, e := suite.New(jcrypto.SuiteC25519)
			if e != nil {
				panic(e)
			}
			c.view.setups = make([]setupView, maxContexts)
			secret, e := secmem.New(base.KeySize())
			if e != nil {
				panic(e)
			}
			defer secret.Release()
			context, e := jcrypto.NewContext(base, "witness/test", []byte("site"))
			if e != nil {
				panic(e)
			}
			k, e := (&observedProvider{CryptoProvider: base, collector: c}).DeriveKey(secret, "cell", context, base.KeySize())
			if e == nil {
				k.Release()
			}
		}},
	}
	for _, x := range cases {
		t.Run(x.site.String(), func(t *testing.T) {
			c := witnessCollector(t, &witnessClock{ns: 10})
			x.run(c)
			if c.err != x.reason || !c.latch.set || c.latch.site != x.site {
				t.Fatalf("err %s latch %+v", c.err, c.latch)
			}
		})
	}
}

func TestFailAtKeepsFirstFailure(t *testing.T) {
	clock := &witnessClock{ns: 10}
	c := witnessCollector(t, clock)
	c.failAt(ReasonContract, sitePortPair, 5)
	first := c.latch
	clock.ns = 20
	c.next = math.MaxUint32
	c.generation()
	c.copy(make([]byte, 65536))
	c.fail(ReasonLimit)
	if c.err != ReasonContract || c.latch != first || c.latch.site != sitePortPair || c.latch.closedAgeNS != 5 || c.latch.at != 10 {
		t.Fatalf("err %s latch %+v", c.err, c.latch)
	}
}

func witnessSetupOpened(c *collector, context [32]byte) {
	nonce := make([]byte, 16)
	binary.BigEndian.PutUint64(nonce[8:], 3)
	plain := make([]byte, 80)
	c.setupOpened(1, keyTag{purpose: "setup", context: context}, nonce, []byte{1}, plain, []byte{wire.Version, byte(wire.KindControl), 0}, 1)
}

func witnessDeliver(c *collector) {
	c.peer = true
	payload := mailbox.Request{Tag: 1}.Bytes()
	inner := binary.BigEndian.AppendUint16(nil, uint16(len(payload)))
	c.view.cells = []cellView{{circuit: 9, stages: stageLocal, inner: c.copy(append(inner, payload...))}}
	deliver := observeDeliver(c, nil, func(uint64, []byte) []byte { return mailbox.Reply{Tag: 1}.Bytes() })
	deliver(9, payload)
}
