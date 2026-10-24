package pki

import (
	"testing"
	"time"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

// the published time of one identity never goes back, whatever the clock
// says, and never below the floor a rotation sets; the lifetime is counted from
// published, so it stays the ttl until the certificate cuts it
func TestIdentityPublishedNeverDecreases(t *testing.T) {
	eachSuite(t, func(t *testing.T, p jcrypto.CryptoProvider) {
		e := newEnv(t, p)
		n := e.node(t, "relay-1")
		ttl := time.Hour
		times := func(b []byte) (published, expires int64) {
			parsed, err := ParseBundle(b)
			if err != nil {
				t.Fatal(err)
			}
			d, err := ParseDescriptor(parsed.Descriptor)
			if err != nil {
				t.Fatal(err)
			}
			return d.Published, d.Expires
		}
		m := func(minutes int) int64 { return t0.Add(time.Duration(minutes) * time.Minute).Unix() }
		for _, c := range []struct {
			what      string
			floor     int64
			now       time.Time
			published int64
		}{
			{"the first signing", 0, t0.Add(10 * time.Minute), m(10)},
			{"the clock set back", 0, t0.Add(5 * time.Minute), m(10)},
			{"a floor above the clock", m(30), t0.Add(20 * time.Minute), m(30)},
			{"a floor below the last published", m(0), t0.Add(25 * time.Minute), m(30)},
			{"the clock past both", m(0), t0.Add(40 * time.Minute), m(40)},
		} {
			if c.floor != 0 {
				n.id.SetFloor(c.floor)
			}
			published, expires := times(n.bundle(t, c.now, ttl))
			if published != c.published || expires != published+int64(ttl/time.Second) {
				t.Fatalf("%s: published %d expires %d, want %d and the ttl after it", c.what, published, expires, c.published)
			}
		}
		published, expires := times(n.bundle(t, until.Add(-30*time.Minute), ttl))
		if published != until.Add(-30*time.Minute).Unix() || expires != until.Unix() {
			t.Fatalf("close to not_after: published %d expires %d, want the clock and not_after", published, expires)
		}
		n.id.SetFloor(until.Unix())
		wantErr(t, "a floor at not_after", n.id.Refresh(until.Add(-10*time.Minute), ttl), ErrCertTime)
		if _, ok := n.id.Bundle(); ok {
			t.Fatal("the bundle outlived a published time at not_after")
		}
	})
}
