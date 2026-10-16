package lab

import (
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"slices"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/internal/verify"
	"github.com/jimichi-org/jimichi/pki"
)

// a bundle of name under ca, signed at at for an hour
func enrolledBundle(t *testing.T, p jcrypto.CryptoProvider, ca *pki.CA, name string, at time.Time) []byte {
	t.Helper()
	addr := name + ".jimichi.svc.cluster.local:9000"
	id, err := pki.NewIdentity(p, name, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(id.Close)
	var nonce [pki.NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	raw, err := id.Request(nonce)
	if err != nil {
		t.Fatal(err)
	}
	req, err := pki.ParseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Issue(req, at, at.Add(72*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Install(cert.Marshal(), at); err != nil {
		t.Fatal(err)
	}
	keys := make([][]byte, 2)
	for i := range keys {
		priv, pub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		priv.Release()
		keys[i] = pub
	}
	id.SetKeys(keys[0], keys[1], 0)
	if err := id.Refresh(at, time.Hour); err != nil {
		t.Fatal(err)
	}
	b, ok := id.Bundle()
	if !ok {
		t.Fatal("no bundle")
	}
	return b
}

// the masks of TestSampleMirrorPathsIsTheChoiceOfTheClient made of bundles:
// a node an entry does not hold is served nothing or a bundle of a second CA,
// in turn. The client's own reading of each mirror holds what the mask says,
// and its own rule and draw on the path stream of the seed give the sample
func TestSampleMirrorPathsIsTheDrawOfTheClientOverBundles(t *testing.T) {
	p, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	session, second := mustCA(t, p), mustCA(t, p)
	addrs := make([]string, 6)
	honest := make([][]byte, 6)
	rogue := make([][]byte, 6)
	for i := range addrs {
		name := fmt.Sprintf("relay-%d", i+1)
		addrs[i] = name + ".jimichi.svc.cluster.local:9000"
		honest[i] = enrolledBundle(t, p, session, name, at)
		rogue[i] = enrolledBundle(t, p, second, name, at)
	}
	mirrors := fullMirrors(6)
	mirrors[0][2], mirrors[0][5] = false, false
	mirrors[1][0], mirrors[1][2], mirrors[1][3] = false, false, false
	mirrors[4][1] = false
	trust := pki.Policy{Anchor: session.Anchor(), Skew: pki.Skew}
	views := make([]verify.View, 6)
	turn := 0
	for entry, mask := range mirrors {
		served := make([][]byte, 6)
		for node, held := range mask {
			switch {
			case held:
				served[node] = honest[node]
			case turn%2 == 1:
				served[node] = rogue[node]
				turn++
			default:
				turn++
			}
		}
		v, err := verify.Mirror(p, true, trust, addrs, served, at)
		if err != nil {
			t.Fatal(err)
		}
		views[entry] = v
		if !slices.Equal(views[entry].Usable(), mask) {
			t.Fatalf("entry %d: the client holds %v, the mask says %v", entry, views[entry].Usable(), mask)
		}
	}
	if turn < 6 {
		t.Fatal("the masks leave out too few nodes to try both kinds")
	}

	paths, refused, err := SampleMirrorPaths(mirrors, 3, 2, 600, 3)
	if err != nil {
		t.Fatal(err)
	}
	stream := mrand.New(mrand.NewSource(Derive(3, streamPaths)))
	built, turned := 0, 0
	for attempt := 0; attempt < 600; attempt++ {
		entry, err := client.ChooseEntry(6, stream)
		if err != nil {
			t.Fatal(err)
		}
		if verdict, _, _ := views[entry].Judge(entry, 3, 2); verdict != client.MirrorTaken {
			turned++
			continue
		}
		want, err := views[entry].Draw(entry, 3, stream)
		if err != nil {
			t.Fatal(err)
		}
		if built >= len(paths) || !slices.Equal(paths[built], want) {
			t.Fatalf("attempt %d: the client draws %v, the sample holds %v", attempt, want, paths[min(built, len(paths)-1)])
		}
		built++
	}
	if built != len(paths) || turned != refused || turned == 0 {
		t.Fatalf("%d paths and %d refused, the client gives %d and %d", len(paths), refused, built, turned)
	}
}

func mustCA(t *testing.T, p jcrypto.CryptoProvider) *pki.CA {
	t.Helper()
	ca, err := pki.NewCA(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Close)
	return ca
}
