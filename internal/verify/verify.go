// Package verify takes node keys from bundles the way the system does: a
// client reads every bundle of its entry's mirror on its own and draws its
// chain among those that pass, and a node takes a peer's keys only from a
// bundle that passes.
package verify

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/pki"
	"github.com/jimichi-org/jimichi/relay"
)

var ErrNoBundle = errors.New("the entry holds no bundle for it")

// the nodes of an entry's mirror whose bundles pass the check
type View struct {
	nodes []pki.Verified
	// position in nodes of every listed node, or -1
	at []int
	// listed index of every node in nodes
	listed []int
	// why a served bundle of a listed node did not pass
	failed []error
}

// bundles[i] is what the entry served for addrs[i], nil when it serves none.
// Every bundle is read on its own, and one that does not pass is a node left
// out like one the entry does not serve; bundles are not compared with each
// other, since the setup and the link of a node bind its own identity
func Mirror(p jcrypto.CryptoProvider, auth bool, trust pki.Policy, addrs []string, bundles [][]byte, now time.Time) (View, error) {
	if len(bundles) != len(addrs) {
		return View{}, fmt.Errorf("verify: %d addresses for %d bundles", len(addrs), len(bundles))
	}
	v := View{at: make([]int, len(addrs)), failed: make([]error, len(addrs))}
	for i, b := range bundles {
		v.at[i] = -1
		if b == nil {
			continue
		}
		node, err := readNode(p, auth, trust, addrs[i], b, now)
		if err != nil {
			v.failed[i] = err
			continue
		}
		v.at[i] = len(v.nodes)
		v.nodes = append(v.nodes, *node)
		v.listed = append(v.listed, i)
	}
	return v, nil
}

func readNode(p jcrypto.CryptoProvider, auth bool, trust pki.Policy, addr string, bundle []byte, now time.Time) (*pki.Verified, error) {
	if auth {
		return pki.Verify(p, trust, addr, bundle, now)
	}
	return pki.Unverified(p, addr, bundle)
}

// the nodes whose bundles passed, in the listed order; the keys are copies, so
// writing into them cannot change the chain the view builds
func (v View) Nodes() []pki.Verified {
	nodes := slices.Clone(v.nodes)
	for i := range nodes {
		nodes[i].Identity = bytes.Clone(nodes[i].Identity)
		nodes[i].LinkPub = bytes.Clone(nodes[i].LinkPub)
		nodes[i].OnionPub = bytes.Clone(nodes[i].OnionPub)
	}
	return nodes
}

// why listed node i is not usable, nil when it is
func (v View) Missing(i int) error {
	if v.at[i] >= 0 {
		return nil
	}
	if v.failed[i] != nil {
		return v.failed[i]
	}
	return ErrNoBundle
}

func (v View) Usable() []bool {
	usable := make([]bool, len(v.at))
	for i, place := range v.at {
		usable[i] = place >= 0
	}
	return usable
}

func (v View) Judge(entry, hops, missing int) (verdict client.MirrorVerdict, absent, allowed int) {
	return client.JudgeMirror(v.Usable(), entry, hops, missing)
}

func (v View) JudgeTo(entry, exit, hops, missing int) (verdict client.MirrorVerdict, absent, allowed int) {
	return client.JudgeMirrorTo(v.Usable(), entry, exit, hops, missing)
}

// client.ChooseRest among the nodes that passed, numbered in the listed order;
// the path comes back as listed indices
func (v View) Draw(entry, hops int, rnd io.Reader) ([]int, error) {
	places, err := client.ChooseRest(v.place(entry), len(v.nodes), hops, rnd)
	if err != nil {
		return nil, err
	}
	return v.listedOf(places), nil
}

// client.ChooseRestTo the way Draw is client.ChooseRest
func (v View) DrawTo(entry, exit, hops int, rnd io.Reader) ([]int, error) {
	places, err := client.ChooseRestTo(v.place(entry), v.place(exit), len(v.nodes), hops, rnd)
	if err != nil {
		return nil, err
	}
	return v.listedOf(places), nil
}

func (v View) Holds(path []int) bool {
	for _, i := range path {
		if v.at[i] < 0 {
			return false
		}
	}
	return true
}

// every node of path must be held
func (v View) Chain(path []int) []client.Node {
	places := make([]int, len(path))
	for i, listed := range path {
		places[i] = v.at[listed]
	}
	return chainOf(v.nodes, places)
}

// -1, which no choice takes, for an index outside the list
func (v View) place(i int) int {
	if i < 0 || i >= len(v.at) {
		return -1
	}
	return v.at[i]
}

func (v View) listedOf(places []int) []int {
	path := make([]int, len(places))
	for i, place := range places {
		path[i] = v.listed[place]
	}
	return path
}

// the identity is empty without authentication, and then nothing binds one
func chainOf(nodes []pki.Verified, path []int) []client.Node {
	chain := make([]client.Node, len(path))
	for i, node := range path {
		v := nodes[node]
		chain[i] = client.Node{Addr: v.Addr, StaticPub: v.OnionPub, LinkPub: v.LinkPub, Identity: v.Identity}
	}
	return chain
}

// what a node extends to at addr: the link key and the certified identity the
// link binds. A node allows pki.Skew and takes no flag for it
func Peer(p jcrypto.CryptoProvider, anchor pki.Anchor, addr string, bundle []byte, now time.Time) (relay.Peer, error) {
	v, err := pki.Verify(p, pki.Policy{Anchor: anchor, Skew: pki.Skew}, addr, bundle, now)
	if err != nil {
		return relay.Peer{}, err
	}
	return relay.Peer{LinkPub: v.LinkPub, Identity: v.Identity}, nil
}

// an unsigned bundle certifies nothing, so the link to the peer binds no identity
func UnverifiedPeer(p jcrypto.CryptoProvider, addr string, bundle []byte) (relay.Peer, error) {
	v, err := pki.Unverified(p, addr, bundle)
	if err != nil {
		return relay.Peer{}, err
	}
	return relay.Peer{LinkPub: v.LinkPub}, nil
}
