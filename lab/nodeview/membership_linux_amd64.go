//go:build linux && amd64

package nodeview

import (
	"context"
	"crypto/rand"
	"net"
	"time"

	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/internal/verify"
	"github.com/jimichi-org/jimichi/pki"
)

func membershipProbe(ctx context.Context, c Config, task executionTask) (result RunResult, audit []RankAudit, training []encodedTrainingRow, resultErr error) {
	row := RunResult{Configuration: task.coordinate.ID, Phase: c.Phase, Repeat: task.repeat, Counts: Counts{Planned: 1, Attempted: 1}, QueueJoined: Number{Reason: ReasonNoView}, PutQ: Number{Reason: ReasonNoView}, PutBaseline: Number{Reason: ReasonNoView}, RequestLDA: Number{Reason: ReasonNoView}, RecordLDA: Number{Reason: ReasonNoView}}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	arena, e := newArena(4096)
	if e != nil {
		return row, nil, nil, e
	}
	f := &fixture{ctx: ctx, cancel: cancel, suite: c.Suite, arena: arena, binaryDigest: c.binarySHA, resources: c.resources}
	defer closeTaskFixture(f, &result, &resultErr)
	p, e := suite.New(c.Suite)
	if e != nil {
		return row, nil, nil, fail(ReasonEnrollment)
	}
	ca, e := pki.NewCA(p)
	if e != nil {
		return row, nil, nil, fail(ReasonEnrollment)
	}
	defer ca.Close()
	var listeners []net.Listener
	defer func() {
		for _, listener := range listeners {
			listener.Close()
		}
	}()
	var addresses []string
	for range 5 {
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			return row, nil, nil, fail(ReasonChild)
		}
		listeners = append(listeners, listener)
		addresses = append(addresses, listener.Addr().String())
	}
	child, e := f.spawn(roleRelay, false)
	if e != nil {
		return row, nil, nil, e
	}
	until := time.Now().Add(30 * time.Second)
	r, e := child.expect(ctx, opBoot, until)
	if e != nil {
		return row, nil, nil, e
	}
	if r.u8() != roleRelay || r.u8() != byte(c.Suite) {
		return row, nil, nil, fail(ReasonIPC)
	}
	child.port = r.u16()
	if child.port == 0 || r.u8() != 1 || r.end() != nil {
		return row, nil, nil, fail(ReasonIPC)
	}
	now := time.Now()
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return row, nil, nil, fail(ReasonChild)
	}
	w := encoder{}
	w.ascii("unlisted", 32)
	w.u16(child.port)
	w.raw(nonce[:])
	w.ascii(ca.Anchor().String(), 256)
	w.i64(now.Add(-time.Minute).Unix())
	w.i64(now.Add(time.Hour).Unix())
	w.i64(int64(10 * time.Minute))
	if e := child.writer.send(opChallenge, w); e != nil {
		return row, nil, nil, e
	}
	r, e = child.expect(ctx, opRequest, until)
	if e != nil {
		return row, nil, nil, e
	}
	request, e := decodeEnrollmentRequest(r, p, nonce, "unlisted", loopback(child.port))
	if e != nil {
		return row, nil, nil, e
	}
	clear(nonce[:])
	cert, e := ca.Issue(request, now.Add(-time.Minute), now.Add(time.Hour))
	if e != nil {
		return row, nil, nil, fail(ReasonEnrollment)
	}
	w = encoder{}
	w.bytes(cert.Marshal(), 2048)
	if e := child.writer.send(opCertificate, w); e != nil {
		return row, nil, nil, e
	}
	r, e = child.expect(ctx, opBundle, until)
	if e != nil {
		return row, nil, nil, e
	}
	bundle := append([]byte(nil), r.bytes(4096)...)
	if r.end() != nil {
		return row, nil, nil, fail(ReasonIPC)
	}
	if _, e = verify.Peer(p, policy(ca.Anchor()), loopback(child.port), bundle, now); e != nil {
		return row, nil, nil, fail(ReasonEnrollment)
	}
	entries := make([]pki.MirrorEntry, 5)
	for i := range entries {
		entries[i] = pki.MirrorEntry{Addr: loopback(child.port), Bundle: bundle}
	}
	view, e := verify.MirrorEntries(p, verify.Options{Auth: true, Trust: policy(ca.Anchor())}, addresses, entries, now)
	if e != nil {
		return row, nil, nil, fail(ReasonEnrollment)
	}
	for i := range addresses {
		row.MembershipChecks++
		if view.Missing(i) == nil || view.Holds([]int{i}) {
			return row, nil, nil, fail(ReasonContract)
		}
		row.MembershipRejected++
	}
	w = encoder{}
	w.u8(0)
	if e := child.writer.send(opStop, w); e != nil {
		return row, nil, nil, e
	}
	if e = f.finishOne(child); e != nil {
		return row, nil, nil, e
	}
	row.Counts.Refused = 1
	row.MaxRSS = child.maxRSS
	return row, nil, nil, nil
}
