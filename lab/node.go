package lab

import (
	"sync"
	"time"

	"github.com/jimichi-org/jimichi/client"
	jcrypto "github.com/jimichi-org/jimichi/crypto"
	"github.com/jimichi-org/jimichi/relay"
)

// Node is one relay configured as Execute configures its own, for a chain
// whose exit runs outside Execute
type Node struct {
	n    *node
	once sync.Once
}

func StartNode(p jcrypto.CryptoProvider, period time.Duration) (*Node, error) {
	n, err := startNode(p, period, false, nil)
	if err != nil {
		return nil, err
	}
	return &Node{n: n}, nil
}

func (n *Node) Client() client.Node { return client.Node{Addr: n.n.addr, StaticPub: n.n.pub} }

func (n *Node) Counters() relay.Counters { return n.n.relay.Stats().Snapshot() }

func (n *Node) KeyLocked() bool { return n.n.priv.Locked() }

// closes the relay and releases its static key
func (n *Node) Stop() { n.once.Do(func() { stopNode(n.n) }) }
