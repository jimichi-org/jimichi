package vault

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/secmem"
)

// Agree runs under the read lock and Take under the write lock: every Agree
// either sees the key or refuses, and none reads a released one
func TestTakeDuringAgree(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		_, file := mustCreate(t, p, volume(t, "a", []byte("x")))
		v, _ := mustOpen(t, p, file, password(t, "a"))
		id := v.Identity()
		peer, peerPub, err := p.GenerateEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Release()
		ctx, err := jcrypto.NewContext(p, "test", id.Public(), peerPub)
		if err != nil {
			t.Fatal(err)
		}
		want, err := p.Agree(peer, id.Public(), ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer want.Release()

		var wg sync.WaitGroup
		var agreed, refused atomic.Int64
		start := make(chan struct{})
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for range 20 {
					got, err := id.Agree(peerPub, ctx)
					if err != nil {
						refused.Add(1)
						continue
					}
					if !got.Equal(want) {
						t.Error("Agree gave another secret")
					}
					got.Release()
					agreed.Add(1)
				}
			}()
		}
		var priv, fetch *secmem.Buffer
		var pub []byte
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			priv, pub, fetch = id.Take()
		}()
		close(start)
		wg.Wait()
		defer priv.Release()
		defer fetch.Release()
		if agreed.Load()+refused.Load() != 160 {
			t.Fatalf("%d agreed and %d refused of 160", agreed.Load(), refused.Load())
		}
		if !bytes.Equal(pub, id.Public()) || priv == nil || fetch == nil {
			t.Fatal("Take did not move the keys")
		}
		if _, err := id.Agree(peerPub, ctx); err == nil {
			t.Fatal("Agree after Take")
		}
		if id.Fetch() != nil {
			t.Fatal("Fetch after Take")
		}
		again, againPub, againFetch := id.Take()
		if again != nil || againFetch != nil || !bytes.Equal(againPub, pub) {
			t.Fatal("a second Take gave keys")
		}
		taken, err := p.Agree(priv, peerPub, ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer taken.Release()
		if !taken.Equal(want) {
			t.Fatal("the taken key agrees to another secret")
		}
		v.Close()
		if priv.Bytes() == nil || fetch.Bytes() == nil {
			t.Fatal("Close released keys that Take had moved")
		}
	})
}

func TestCloseReleases(t *testing.T) {
	eachSuite(t, func(t *testing.T, p *spy) {
		_, file := mustCreate(t, p, volume(t, "a", []byte("x")))
		v, _, err := open(p, file, password(t, "a"))
		if err != nil {
			t.Fatal(err)
		}
		fetch := v.Identity().Fetch()
		v.Close()
		if fetch.Bytes() != nil || v.Content() != nil || v.Identity().Fetch() != nil {
			t.Fatal("Close of a volume kept its keys or content")
		}
		if _, err := v.Identity().Agree(v.Identity().Public(), jcrypto.Context{}); err == nil {
			t.Fatal("Agree after Close")
		}
		v.Close()

		d, err := Prepare(p, volume(t, "a", []byte("x")))
		if err != nil {
			t.Fatal(err)
		}
		key, plain, dfetch := d.key, d.plain, d.Identity().Fetch()
		d.Close()
		if key.Bytes() != nil || plain.Bytes() != nil || dfetch.Bytes() != nil {
			t.Fatal("Close of a draft kept its keys or content")
		}
		d.Close()

		d, err = Prepare(p, volume(t, "a", []byte("x")))
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		key, plain = d.key, d.plain
		if err := d.Write(vaultPath(t), nil); err != nil {
			t.Fatal(err)
		}
		if key.Bytes() != nil || plain.Bytes() != nil {
			t.Fatal("the volume key or content outlived the write")
		}
		if d.Identity().Fetch() == nil {
			t.Fatal("the write released the identity")
		}
	})
}
