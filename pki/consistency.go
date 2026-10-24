package pki

import (
	"bytes"

	jcrypto "github.com/jimichi-org/jimichi/crypto"
)

// Rule is what two statements of one node can break: something a node that
// signs its descriptors the way cmd/relay does never produces, whatever its
// clock, so a pair that breaks one is the node's own doing
type Rule uint8

const (
	RuleIdentity Rule = iota + 1
	RuleCert
	RuleLinkKey
	RuleOnionKeyPerEpoch
	RuleEpochPerKey
	RuleEpochOrder
	RuleEpochOverlap
)

var ruleTexts = [...]string{
	RuleIdentity:         "two identities at one address",
	RuleCert:             "two certificates for one identity",
	RuleLinkKey:          "two link keys",
	RuleOnionKeyPerEpoch: "two onion keys in one epoch",
	RuleEpochPerKey:      "one onion key in two epochs",
	RuleEpochOrder:       "an older epoch published after a newer one",
	RuleEpochOverlap:     "epochs two apart overlap",
}

func (r Rule) String() string {
	if r == 0 || int(r) >= len(ruleTexts) {
		return "consistent"
	}
	return ruleTexts[r]
}

// Compare applies the rules to two statements of one address and returns the
// first one they break, 0 when none. It is symmetric. A node publishes one
// identity, one certificate and one link key per process and one onion key per
// epoch; it signs epochs in order of their published time; and the rotation to
// e+2 waits until every descriptor of e has expired for a verifier Skew behind,
// so an epoch ends Skew before the epoch after next begins. Adjacent epochs
// overlap during the grace period, which the rules allow
func Compare(a, b *Verified) Rule {
	switch {
	case !bytes.Equal(a.Identity, b.Identity):
		return RuleIdentity
	case a.CertHash != b.CertHash:
		return RuleCert
	case !bytes.Equal(a.LinkPub, b.LinkPub):
		return RuleLinkKey
	case a.Epoch == b.Epoch:
		if !bytes.Equal(a.OnionPub, b.OnionPub) {
			return RuleOnionKeyPerEpoch
		}
		return 0
	case bytes.Equal(a.OnionPub, b.OnionPub):
		return RuleEpochPerKey
	}
	lo, hi := a, b
	if hi.Epoch < lo.Epoch {
		lo, hi = b, a
	}
	switch {
	case hi.DescFrom.Before(lo.DescFrom):
		return RuleEpochOrder
	case hi.Epoch-lo.Epoch >= 2 && hi.DescFrom.Before(lo.DescUntil.Add(Skew)):
		return RuleEpochOverlap
	}
	return 0
}

// Proof is two bundles of one address that break a rule, the smaller first
// bytewise, so one pair has one encoding and carries no trace of who saw which
// first. Anyone with the anchor verifies it
type Proof struct {
	A []byte
	B []byte
}

func NewProof(a, b []byte) (*Proof, error) {
	switch bytes.Compare(a, b) {
	case 0:
		return nil, ErrNoConflict
	case 1:
		a, b = b, a
	}
	return &Proof{A: bytes.Clone(a), B: bytes.Clone(b)}, nil
}

type Conflict struct {
	Addr  string
	Rule  Rule
	Proof Proof
}

// VerifyConflict is the check every reader of a proof makes: both bundles pass
// VerifyStatement under pol at addr and Compare finds a rule they break. The
// pki error of the first bundle that fails comes back as it is, two consistent
// bundles give ErrNoConflict
func VerifyConflict(p jcrypto.CryptoProvider, pol Policy, addr string, pr Proof) (*Conflict, error) {
	c, _, _, err := VerifyProof(p, pol, addr, pr)
	return c, err
}

// VerifyProof is VerifyConflict that also hands back the two statements, in
// the order of the canonical proof it returns, so a reader that records them
// does not verify the pair twice
func VerifyProof(p jcrypto.CryptoProvider, pol Policy, addr string, pr Proof) (*Conflict, *Verified, *Verified, error) {
	a, err := VerifyStatement(p, pol, addr, pr.A)
	if err != nil {
		return nil, nil, nil, err
	}
	b, err := VerifyStatement(p, pol, addr, pr.B)
	if err != nil {
		return nil, nil, nil, err
	}
	rule := Compare(a, b)
	if rule == 0 {
		return nil, nil, nil, ErrNoConflict
	}
	canonical, err := NewProof(pr.A, pr.B)
	if err != nil {
		return nil, nil, nil, err
	}
	if !bytes.Equal(canonical.A, pr.A) {
		a, b = b, a
	}
	return &Conflict{Addr: addr, Rule: rule, Proof: *canonical}, a, b, nil
}
