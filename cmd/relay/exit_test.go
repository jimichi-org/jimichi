package main

import (
	"bytes"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/mailbox"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
)

func TestCheckExit(t *testing.T) {
	def := mailbox.DefaultLimits()
	for _, exit := range []string{exitEcho, exitMailbox, exitNone} {
		if err := checkExit(exit, def); err != nil {
			t.Fatalf("-exit %s: %v", exit, err)
		}
	}
	for _, exit := range []string{"", "Echo", "mailboxes", "true"} {
		if err := checkExit(exit, def); err == nil {
			t.Fatalf("-exit %q accepted", exit)
		}
	}
	for _, change := range []func(*mailbox.Limits){
		func(l *mailbox.Limits) { l.TTL = 0 },
		func(l *mailbox.Limits) { l.Depth = 0 },
		func(l *mailbox.Limits) { l.Queues = -1 },
		func(l *mailbox.Limits) { l.Records = 0 },
	} {
		lim := def
		change(&lim)
		if err := checkExit(exitMailbox, lim); err == nil {
			t.Fatalf("-exit mailbox with limits %+v accepted", lim)
		}
		if err := checkExit(exitEcho, lim); err != nil {
			t.Fatalf("the mailbox limits matter to an echo exit: %v", err)
		}
	}
}

func TestStatsCarryMailboxCountersOnlyForAMailbox(t *testing.T) {
	n := &node{ttl: time.Hour, now: time.Now, logger: log.New(&logBuffer{}, "", 0)}
	counters := func() relay.Counters { return relay.Counters{Accepted: 1} }
	plain := httptest.NewServer(n.adminMux(counters, nil))
	defer plain.Close()
	if _, body := call(t, http.MethodGet, plain.URL+"/stats", nil); bytes.Contains(body, []byte("mailbox")) {
		t.Fatalf("/stats of a node that is no mailbox: %s", body)
	}

	box := httptest.NewServer(n.adminMux(counters, func() mailbox.Counters {
		return mailbox.Counters{Requests: 1, Queues: 2, Records: 3, Bindings: 4, Puts: 5, PutFull: 6,
			PutRefused: 7, Fetches: 8, Hits: 9, Expired: 10, Evicted: 11, Bad: 12}
	}))
	defer box.Close()
	_, body := call(t, http.MethodGet, box.URL+"/stats", nil)
	for _, want := range []string{
		`"accepted":1`, `"mailbox_requests":1`, `"mailbox_queues":2`, `"mailbox_records":3`, `"mailbox_bindings":4`,
		`"mailbox_puts":5`, `"mailbox_put_full":6`, `"mailbox_put_refused":7`, `"mailbox_fetches":8`,
		`"mailbox_hits":9`, `"mailbox_expired":10`, `"mailbox_evicted":11`, `"mailbox_bad":12`,
	} {
		if !bytes.Contains(body, []byte(want)) {
			t.Fatalf("/stats %s lacks %s", body, want)
		}
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// the binary as each exit: what one request gets back, the start line, the
// minute line without mailbox counters and /stats with them for a mailbox only
func TestEveryExitMode(t *testing.T) {
	p, err := suite.New(jcrypto.SuiteC25519)
	if err != nil {
		t.Fatal(err)
	}
	var fetchCap [mailbox.CapSize]byte
	fetchCap[0] = 0x42
	own, err := mailbox.QueueID(p, fetchCap[:])
	if err != nil {
		t.Fatal(err)
	}
	req := mailbox.Request{Tag: 5, Fetch: fetchCap, Put: own}
	copy(req.Record[:], "record")

	for _, exit := range []string{exitEcho, exitMailbox, exitNone} {
		t.Run(exit, func(t *testing.T) {
			stats := freeAddr(t)
			cfg := config{
				listen: "127.0.0.1:0", info: "127.0.0.1:0", stats: stats,
				exit: exit, mailbox: mailbox.DefaultLimits(), logEvery: 20 * time.Millisecond,
				descriptorTTL: time.Hour, onionRotate: time.Hour,
			}
			var out logBuffer
			stop := make(chan os.Signal, 1)
			done := make(chan error, 1)
			go func() { done <- serveNode(p, cfg, log.New(&out, "", 0), stop) }()
			defer func() {
				stop <- os.Interrupt
				select {
				case err := <-done:
					if err != nil {
						t.Errorf("serveNode = %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Error("the node did not stop")
				}
			}()
			for limit := time.Now().Add(5 * time.Second); !listening.MatchString(out.String()); time.Sleep(10 * time.Millisecond) {
				if time.Now().After(limit) {
					t.Fatalf("the node did not start: %q", out.String())
				}
			}
			if !strings.Contains(out.String(), ", exit="+exit+"\n") {
				t.Fatalf("start line without exit=%s: %q", exit, out.String())
			}
			addrs := listening.FindStringSubmatch(out.String())
			code, bundle := call(t, http.MethodGet, "http://"+addrs[2]+"/descriptor", nil)
			if code != http.StatusOK {
				t.Fatalf("GET /descriptor = %d", code)
			}
			v, err := pki.Unverified(p, addrs[1], bundle)
			if err != nil {
				t.Fatal(err)
			}
			cl, err := client.Dial(client.Config{Provider: p, Chain: []client.Node{{Addr: addrs[1], StaticPub: v.OnionPub, LinkPub: v.LinkPub}}})
			if err != nil {
				t.Fatal(err)
			}
			defer cl.Close()
			if err := cl.Send(req.Bytes()); err != nil {
				t.Fatal(err)
			}
			var reply []byte
			select {
			case reply = <-cl.Replies():
			case <-time.After(500 * time.Millisecond):
			}
			switch exit {
			case exitEcho:
				if !bytes.Equal(reply, req.Bytes()) {
					t.Fatalf("echo reply of %d bytes", len(reply))
				}
			case exitNone:
				if reply != nil {
					t.Fatalf("a reply of %d bytes from an exit that sends cover", len(reply))
				}
			case exitMailbox:
				r, err := mailbox.ParseReply(reply)
				if err == nil {
					err = r.Answers(&req)
				}
				if err != nil || r.Status != mailbox.PutStored|mailbox.StatusRecord || r.Record != req.Record {
					t.Fatalf("mailbox reply %x...: %v", reply[:min(4, len(reply))], err)
				}
			}

			for limit := time.Now().Add(5 * time.Second); !strings.Contains(out.String(), "counters accepted="); time.Sleep(10 * time.Millisecond) {
				if time.Now().After(limit) {
					t.Fatalf("no counters line: %q", out.String())
				}
			}
			if strings.Contains(out.String(), "mailbox_") {
				t.Fatalf("mailbox counters on stdout: %q", out.String())
			}
			_, body := call(t, http.MethodGet, "http://"+stats+"/stats", nil)
			hasMailbox := bytes.Contains(body, []byte(`"mailbox_requests":1`)) &&
				bytes.Contains(body, []byte(`"mailbox_puts":1`)) && bytes.Contains(body, []byte(`"mailbox_hits":1`))
			if hasMailbox != (exit == exitMailbox) || exit != exitMailbox && bytes.Contains(body, []byte("mailbox")) {
				t.Fatalf("/stats of -exit %s: %s", exit, body)
			}
		})
	}
}
