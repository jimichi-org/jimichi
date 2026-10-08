# CryptoProvider

English | [Русский](../ru/CRYPTO.md)

Status: both suites are implemented and pass providertest. c25519 is the default, so results are
comparable with international work. GOST is the second suite and is compared with it on cost. The
suite is chosen with -suite on the node, the client and the testbed; a node publishes its suite
next to its key, and a client on another suite refuses to start.

## Operations

| Operation | GOST (crypto/gost) | Default suite (crypto/c25519) |
|---|---|---|
| Ephemeral pair | GOST R 34.10-2012, 256 bit, paramSetA (TC26) | X25519 |
| Key agreement | VKO_GOSTR3410_2012_256 (R 50.1.113-2016; RFC 7836, 4.3.1), UKM from the transcript hash, then the KDF | X25519, then HKDF-SHA-256 with the transcript hash |
| KDF | KDF_GOSTR3411_2012_256 (R 50.1.113-2016; RFC 7836, 4.5) | HKDF-SHA-256 (RFC 5869) |
| AEAD | Kuznyechik-MGM (R 1323565.1.026-2019), 16-byte nonce, 16-byte tag | XChaCha20-Poly1305, 24-byte nonce, 16-byte tag |
| Signature | GOST R 34.10-2012, 256 bit | Ed25519 |
| Hash | Streebog-256 | SHA-256 |

Different nonce sizes and overheads are visible through the interface: wire hardcodes no sizes.

## Interface

```go
type Suite uint8

type CryptoProvider interface {
	Suite() Suite

	GenerateEphemeral() (priv *secmem.Buffer, pub []byte, err error)
	Agree(priv *secmem.Buffer, peerPub []byte, ctx Context) (*secmem.Buffer, error)
	MixKey(chain, secret *secmem.Buffer, ctx Context) (*secmem.Buffer, error)
	DeriveKey(secret *secmem.Buffer, purpose string, ctx Context, size int) (*secmem.Buffer, error)
	KeySize() int

	NewAEAD(key *secmem.Buffer) (AEAD, error)

	GenerateSigning() (priv *secmem.Buffer, pub []byte, err error)
	Sign(priv *secmem.Buffer, msg []byte) ([]byte, error)
	Verify(pub, msg, sig []byte) bool

	Hash(data ...[]byte) []byte
}

type AEAD interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, ad []byte) []byte
	Open(dst, nonce, ciphertext, ad []byte) ([]byte, error)
	// Destroy drops the cipher; whether its key copy is wiped depends on the library.
	Destroy()
}

const ContextSize = 32

type Context struct{ /* the suite and the transcript hash */ }

func NewContext(p CryptoProvider, exchange string, parts ...[]byte) (Context, error)
func (c Context) Sum() []byte
func (c Context) Suite() Suite
func (c Context) Valid() bool

func TranscriptBytes(s Suite, exchange string, parts ...[]byte) ([]byte, error)
func Label(s Suite, purpose string) ([]byte, error)
func DeriveLabel(s Suite, purpose string) ([]byte, error)
```

Decisions taken:
- Secrets cross the interface only as *secmem.Buffer. Public keys and signatures are []byte: they
  are not secret, and a type per suite would complicate wire.
- Agree, MixKey and DeriveKey take a Context: the hash of the exchange transcript, 32 bytes. It
  binds every secret and every key to the public keys of both sides, the parameters of the
  exchange, the suite and the scheme version. The provider refuses the zero Context and a context
  of another suite, so no key can be derived without a transcript. The layout and the formulas
  are under "Key derivation".
- The provider builds the KDF label from the scheme version, the suite and the purpose. A caller
  passes the purpose only and cannot supply a label string of its own.
- MixKey chains a second agreement onto the first: the result depends on both secrets and stays
  KeySize long.
- KeySize reports the AEAD key length so that wire never hardcodes 32 bytes.
- DeriveKey in both suites takes a secret of exactly KeySize bytes and a size from 1 to KeySize;
  a key shorter than KeySize is the prefix of the full one. wire takes 16 bytes for the control
  cell replay tag and 8 bytes for each counter offset.
- An AEAD is safe for concurrent use: a node peels and wraps layers under one key from different
  goroutines. gogost's MGM keeps per-call state, so the GOST suite serialises calls with a lock.
  providertest checks this with concurrent Seal and Open.
- Nonces are assigned by the caller: the provider neither stores nor counts them. link numbers the
  frames of one direction of a link from zero and puts the number in the last 8 bytes of the
  nonce, the rest zero. wire builds the nonce of a cell layer from the direction, the circuit id
  and the counter. The cell format rules out a nonce repeating under one key. In a 16-byte nonce
  the top bit is always zero, as MGM requires: wire puts the counter with the direction first and
  the random circuit id last, and link leaves the leading bytes zero.
- GenerateSigning issues the long-term pair for node authentication, separate from the ephemeral
  one.
- crypto/rand is the only standard-library crypto package used outside crypto/: randomness for
  identifiers, serial numbers and padding. It is not counted as a primitive.

## Key derivation

Every secret and every key depends on the transcript of its exchange, on the suite and on the
scheme version, and, when nodes are authenticated, on the identity of the node. A substituted
public key, identity, mode, suite or version on either side gives different keys, and the first
AEAD check fails.

### Label

`label = ASCII("jimichi/v2/" || suite || "/" || purpose)`, the suite being `c25519` or `gost`.
A label holds no 0x00 byte and is at most 50 bytes long.

| purpose | Label length, c25519 / GOST | Derived by | Key size |
|---|---|---|---|
| `agree` | 23 / 21 | the provider, inside Agree | 32 |
| `mix` | 21 / 19 | the provider, inside MixKey | 32 |
| `setup` | 23 / 21 | wire, the setup layer key | 32 |
| `cell` | 22 / 20 | wire, the hop key | 32 |
| `setup/replay` | 30 / 28 | wire, the control cell replay tag | 16 |
| `counter/fwd`, `counter/bwd` | 29 / 27 | wire, the counter offsets | 8 |
| `link/i2r`, `link/r2i` | 26 / 24 | link, the frame keys | 32 |
| `noise/key` | 27 / 25 | noise, the key of a handshake message | 32 |
| `noise/split/i2r`, `noise/split/r2i` | 33 / 31 | noise, the direction keys after the handshake | 32 |
| `e2e/step/key` | 30 / 28 | e2e, the record key | 32 |
| `e2e/step/next` | 31 / 29 | e2e, the next key of the ratchet chain | 32 |

- A purpose and an exchange name: `[a-z0-9]+(/[a-z0-9]+)*`, 1 to 32 bytes.
- `agree`, `mix` and anything that starts with `transcript/` are reserved to the provider:
  DeriveKey with such a purpose returns an error, so a caller cannot reproduce the output of
  Agree or MixKey.
- The signature domain strings (section "Signatures") are versioned on their own and are not
  part of this scheme.

### Transcript

```
T  = ASCII("jimichi/v2/" || suite || "/transcript/" || exchange) || 0x00 || u8(n)
     || n times: u16be(part length) || part
th = Hash(T)        SHA-256 or Streebog-256, 32 bytes
```

- 1 to 255 parts, each 1 to 65535 bytes.
- The layout is unambiguous: the string holds no 0x00, and after it come a separator, the number
  of parts and the length of every part. The same bytes cut at other places give another hash.
- NewContext takes the hash and the suite name from the provider it is given, so a context is as
  trustworthy as that provider: the type guarantees that a context is present, not that it is the
  suite hash of a transcript. wire, link and relay pass the provider of the suite itself. The
  hash is not picked by suite inside crypto: the GOST package imports crypto itself, so
  Streebog would have to come into the interface package straight from a third-party library,
  and the interface package imports no crypto library. Nor would it help: a wrapper that returns
  bytes of its choosing from Hash returns them from Agree and DeriveKey just as well.
- NewContext copies the parts into T and hashes it at once: a slice of a cell body cannot change
  between two derivations.
- The transcript consists of public data and is not signed with the node signing key. Sum
  returns a copy of the hash.

Circuit setup, exchange `setup`, one context per hop:

| No. | Part | Bytes | Client | Node |
|---|---|---|---|---|
| 1 | version | 1 | the cell format version | the cell format version |
| 2 | hop index | 1 | the number of the hop in the chain | the counter field of the control cell |
| 3 | link id | 8, big endian | chosen for the hop | from the cell header |
| 4 | onion key | public key | from the verified descriptor | the public half of the onion key being tried |
| 5 | client ephemeral key | public key | generated | the bytes at the start of the layer |
| 6 | node identity key, only when nodes are authenticated | signing key | from the verified certificate | its own, the one its certificate certifies |

T is 120 bytes long on c25519 and 182 on GOST; with part 6, 154 and 248.

Link, exchange `link`:

| No. | Part | Bytes |
|---|---|---|
| 1 | version | 1 |
| 2 | mode | 1: 0x00 anonymous, 0x01 authenticated |
| 3 | initiator ephemeral key | as in the hello after the mode byte |
| 4 | responder ephemeral key | as sent |
| 5 | responder link key, in mode 0x01 only | the initiator takes it from the descriptor, the responder uses its published one |
| 6 | responder identity key, in mode 0x01 only and when nodes are authenticated | the initiator takes it from the verified certificate, the responder uses its own |

T in modes 0x00 and 0x01: 109 and 143 bytes on c25519, 171 and 237 on GOST; with part 6, 177
and 303.

Node identity:
- The identity key is the public signing key of the node that its certificate certifies
  (Verified.Identity). It is made at node start and lives as long as the process, so it stays the
  same when the node is enrolled again, unlike the bytes of the certificate.
- A node with -auth binds its identity key from the start: to every setup it opens and to every
  authenticated link it accepts. Before its certificate it serves no descriptor and extends no
  circuit, so nobody knows the keys to reach it by. The client takes the identity key of every
  node of the chain from its verified certificate, a node takes the identity key of the next node
  from that peer's descriptor in its cache.
- Without node authentication (-auth=false) both sides bind the empty identity: part 6 is left
  out and the transcript has one part fewer. The layout admits no empty part, and the number of
  parts tells the two forms apart. A node with -auth and a client or neighbouring node without it
  agree on no key: this is a configuration mismatch, and a setup or link handshake between them
  fails.
- A setup layer and an authenticated link open only at the node that holds the private half of
  the key and binds the same identity.

The exchanges of the end-to-end layer are listed under "End-to-end layer".

### Formulas

c25519: HKDF-SHA-256 (RFC 5869: Extract in section 2.2, Expand in section 2.3, one output
block), `info(p) = label(p) || 0x00 || th`.

| Operation | Computation |
|---|---|
| Agree | `Z = X25519(priv, pub)`; `PRK = HMAC(key = th, Z)`; `HMAC(PRK, info(agree) \|\| 0x01)` |
| MixKey | `PRK = HMAC(key = chain, secret)`; `HMAC(PRK, info(mix) \|\| 0x01)` |
| DeriveKey | `HMAC(secret, info(purpose) \|\| 0x01)[0:size]` |

GOST: VKO_GOSTR3410_2012_256 and KDF_GOSTR3411_2012_256 (RFC 7836, sections 4.3.1 and 4.5),
`KDF(K, label, seed) = HMAC_Streebog256(K, 0x01 || label || 0x00 || seed || 0x01 || 0x00)`.

| Operation | Computation |
|---|---|
| Agree | `UKM = th[0:8]` as a little-endian number, zero replaced by one; `KEK = VKO(priv, pub, UKM)` after the point checks; `KDF(KEK, label(agree), th)` |
| MixKey | `KDF(chain, label(mix), th \|\| secret)` |
| DeriveKey | `KDF(secret, label(purpose), th)[0:size]` |

The GOST profile:
- K_in is always 256 bits: the KEK, the output of Agree or the output of MixKey.
- label is a constant of the scheme without 0x00, seed is always 32 bytes, 64 in MixKey. RFC 7836
  (4.5) requires the protocol to assign label and seed and recommends fixing their lengths.
- The output is one block, at most 32 bytes.
- A 64-bit UKM is taken from the start of the transcript hash, and the whole hash goes into the
  seed. RFC 7836 (4.3.1) allows a UKM of up to half the public key size and recommends 64 bits or
  more when at least one side uses a static key. gogost multiplies the shared point by the UKM
  in a separate scalar multiplication, and a wider factor would lengthen it.
- In MixKey the second secret takes the seed position. The function is the same, but the seed is
  not a public value here: this departs from the usual use of KDF_GOSTR3411_2012_256. The
  reasoning: HMAC is treated as a pseudorandom function in the key chain and as an extractor in
  the message, which holds secret, so the output is unknown as long as at least one of the two
  secrets is unknown. This work gives no formal proof for the composition.

### Who calls what

Setup: the client and the node build the same `ctx = NewContext(p, "setup", ...)`,
`secret = Agree(.., ctx)`, then DeriveKey under the same ctx for `setup`, `cell`, `counter/fwd`,
`counter/bwd`. The node also derives `setup/replay`; the client does not derive the replay tag.
A node holding two onion keys builds a context for each of them: a
layer built for the key of one epoch does not open under the key of another.

Link, both agreements under one context:

| Mode | Agreements | The key the frame keys are derived from |
|---|---|---|
| 0x00 | ephemeral with ephemeral (ee) | `ee` |
| 0x01 | the initiator's ephemeral key with the responder's link key (es), then ee | `MixKey(chain = es, secret = ee, ctx)` |

The frame keys: DeriveKey with `link/i2r` and `link/r2i`. The responder's first frame confirms
the whole transcript: if a single byte of it differs between the sides, the frame does not open.

The key pair check, exchange `relay/keycheck`: the node generates a one-time pair and, under a
context made of the public key being checked and the one-time public key, agrees a secret from
both sides. The two secrets must be equal; no key is derived from them and both are released at
once. The link key is checked at node start, every onion key before the ring takes it: the first
one at start, the next ones at each rotation. A node whose published link key does not agree with
its private key (the public key of another pair, or one the agreement refuses) does not start:
it would otherwise confirm no authenticated link and, with -onion-rotate 0, where the link key
also serves as the onion key, open no setup. An onion pair that does not agree is refused the
same way, since the node would open no setup under it: at start the node does not run, at a
rotation the published key stays in place and the attempt is counted as a failed rotation. A
check that fails for another reason, no room to lock a secret above all, reports that reason and
not a bad pair.

### Rules for changes

- The scheme version (now `v2`) changes with any change to the transcript layout, to the
  formulas, or to the name or size of an existing purpose. Versions are not compatible with each
  other, and there is no version negotiation: nodes and clients are updated together. The version
  is not visible on the wire, and the cell version byte (wire.Version) does not change with the
  key scheme.
- A new purpose does not change the version: it adds a row to the label table and a golden
  vector in crypto/providertest.
- The golden vectors pin the composition: the hashes of five transcripts (the setup and both
  link modes without an identity, the setup and the authenticated link with an identity key),
  every derived key, MixKey and Agree on fixed keys, for both suites. The comment next to them
  says how to recompute the values without this code. Both VKO examples of RFC 7836 (appendix B,
  examples 7 and 8) are on the 512-bit paramSetA, so the GOST primitives are checked against the
  examples of the standards in the tests of crypto/gost (VKO_GOSTR3410_2012_256 against example
  7, KDF_GOSTR3411_2012_256 against example 9), and the composition on the 256-bit paramSetA is
  pinned by the vectors of the scheme with the intermediate values (the transcript hash, the UKM,
  the KEK) written down in crypto/providertest. They were computed by an independent
  implementation that is not part of the repository; everything but the KEK is a hash or an HMAC
  and can be recomputed with any Streebog implementation.
- The end-to-end layer is pinned by vectors of the whole KK handshake and the first records on
  both suites (e2e/vectors_test.go, noise/vector_test.go), with the intermediate values and the
  way to recompute them in the comment. The c25519 values come from a separate Python
  implementation, the GOST values from a composition harness over the providers that matched the
  Python one byte for byte on c25519; every GOST primitive is held by a standard example as well.

The provider checks are the same in both suites and run in this order: sizes of the secrets, the
context, the label, the public key.

| Argument | Rule | Error |
|---|---|---|
| priv | the private key length of the suite | ErrBadKeySize |
| secret, chain | exactly KeySize | ErrBadKeySize |
| size | 1 to KeySize | ErrBadKeySize |
| ctx | made by NewContext with a provider of the same suite | ErrBadContext |
| purpose, exchange | the name format; in DeriveKey not one reserved to the provider | ErrBadLabel |
| transcript parts | 1 to 255, each 1 to 65535 bytes | ErrBadContext |
| peerPub | the length; a point of small order (on c25519 X25519 itself refuses it); in GOST also a point off the curve or with a coordinate not below p | ErrBadPublicKey |

## Signatures

The pki package takes signatures and hashes only through the CryptoProvider (Sign, Verify, Hash)
and has no primitives of its own.

| Key | What it signs | Domain string |
|---|---|---|
| CA key | node certificate | `jimichi/cert/v1\x00` |
| node signing key | certificate request | `jimichi/csr/v1\x00` |
| node signing key | node descriptor | `jimichi/descriptor/v1\x00` |

- The domain string precedes the body in the signed message only. A signature over one kind of
  object never verifies as a signature over another, even if the bodies coincide byte for byte.
- ca_id (the first 8 bytes) and cert_hash (32 bytes) come from the suite's Hash: SHA-256 or
  Streebog-256.
- Verify rejects a public key of small order before it looks at the signature: under such a key a
  signature for any message can be made without the private key. crypto/ed25519 verifies without
  the cofactor and accepts such keys (under the neutral point R = [S]B passes), so c25519 first
  decodes the key, requires its canonical encoding and rejects a point that the cofactor 8 takes
  to the neutral point. GOST rejects points off the curve and points of order 2 and 4; the neutral
  point has no affine encoding. providertest checks small-order keys for both suites.
- A rule for callers: in GOST the signing key comes from the same generator on the same curve as
  the ephemeral pair, so a signing key must never be used for key agreement, nor an agreement key
  for signing. The interface does not check this.
- Identity signatures never authenticate client messages. A client has no signing key: its
  identity key is an agreement key and never goes into Sign. A sender's signature over a message
  or a transcript would prove to a third party who sent it. The packages of the end-to-end layer
  (noise, e2e) do not call GenerateSigning, Sign or Verify. Their tests check this twice: the
  source of the packages holds no such call, and every test of the packages, the refused,
  replayed and forged inputs included, runs on a provider on which such a call fails the test.
  Only the CA and the nodes sign.
- The CA key and the node signing key are held in secmem buffers, and pki hands out only the
  public keys. The copies libraries make during generation and signing are listed under
  "Known gaps".

## Node keys

| Key | What it does | Lives |
|---|---|---|
| Node signing key | signs the certificate request and the descriptors; its public half (the identity key) goes into the setup and link transcripts of the node when nodes are authenticated (section "Transcript") | until the process ends |
| Link key | mixed into the handshake by whoever opens a link to the node, which authenticates the node on that link | until the process ends |
| Onion key | the client agrees the layer secret of a circuit setup with it | with -onion-rotate one period as the published key and the grace period after it; without rotation the link key serves in this role until the process ends |
| Hop keys of a circuit | open and seal the cells of one circuit at one node | until the circuit is torn down |
| Frame keys of a link | seal the frames of one link; derived from the agreement of the two ephemeral keys and, in the authenticated mode, also from the agreement with the responder's link key (section "Key derivation") | until the link closes |

- The signing, link and onion keys are generated through the CryptoProvider straight into secmem
  buffers. An onion key is released, its buffer zeroed, at the end of its grace period
  (ARCHITECTURE, onion key epochs) and when the process ends.
- A setup costs the node one agreement per onion key it holds: one outside the grace period, two
  within it, which is two VKO on the GOST suite.
- Releasing an onion key wipes its secmem buffer only. The copies of the scalar that the
  libraries made during agreements stay on the heap until that memory is reused ("Known gaps").

## End-to-end layer

Two clients run a layer of their own on top of the circuit: the contact card, a handshake on the
KK pattern and a hash ratchet per direction (packages noise and e2e). Nodes do not open it: to
them a record of the layer is part of the cell payload. Records travel through a mailbox at the
exit (package mailbox, `-exit mailbox`) and the conversation driver (package conversation); the
client `cmd/client -peer` uses them (ARCHITECTURE, "The -peer client").

Every operation of the layer goes through the provider's Agree, MixKey, DeriveKey, Hash and AEAD,
so the formulas of the suites are those under "Formulas". The suites differ only in the suite
byte of the card, the public key length P, the nonce length and the length L of the zero
handshake payload.

| | c25519 | GOST |
|---|---|---|
| P / nonce / tag | 32 / 24 / 16 | 64 / 16 / 16 |
| record | 392 | 392 |
| L, zeroes in kk1 and kk2 | 343 | 311 |
| inner of a data record / largest body | 371 / 368 | 371 / 368 |
| card with a 38-byte address, text | 89 bytes, 127 characters | 121 bytes, 169 characters |

### Exchanges

| Exchange | Parts | T length, c25519 / GOST |
|---|---|---|
| `noise/e2e/kk` | 0x01, the initiator's card, the responder's card | 228 / 290 |
| `noise/hash` | h, data d | 77 + len(d) / 75 + len(d) |
| `noise/dh` | h, the token byte | 76 / 74 |
| `noise/key` | h | 74 / 72 |
| `noise/split` | h | 76 / 74 |
| `e2e/step` | SID, direction, u32be(n) | 82 / 80 |
| `e2e/card` | the card | 130 / 160 |
| `e2e/check` | a one-time public key, the peer's key | 108 / 170 |
| `mailbox/queue` | the fetch capability F, 16 bytes (package mailbox) | 62 / 60 |

The lengths for cards and for the exchange `e2e/card` assume a 38-byte mailbox address.

### Contact card

```
u8 version = 1 | u8 suite (1 GOST, 2 c25519) | u8 address length | mailbox address | queue, 16 bytes | identity key, P bytes
```

- The canonical form: decoding and encoding give the same bytes, and no trailing bytes are
  allowed. The address passes the pki rules for node addresses, the queue is not all zeroes, and
  the key is exactly P bytes.
- The queue is the first 16 bytes of the hash of the `mailbox/queue` transcript of the fetch
  capability F (`mailbox.QueueID`). A card from a peer carries only the queue, so its parser
  takes any queue that is not all zeroes; the conversation driver checks its own card's queue
  against F.
- The text is `<suite>:<base64 with padding>`; the prefix equals the suite inside the card, and a
  round trip proves the one spelling, as for the trust anchor.
- `card_hash` is the hash of the `e2e/card` transcript of the card, 32 bytes. There is no short
  fingerprint.

### The noise machine

State: h (32 bytes, public), ck (secmem, empty until the first agreement), the own static key
(only through the Static interface: the public key and Agree), the peer's static key, the own
ephemeral key (secmem), the peer's ephemeral key, the message number.

| Operation | Definition |
|---|---|
| start | `h = Hash(T("noise/"+name, prologue...))`; then MixHash of the pre-message keys, the initiator's first |
| MixHash(d) | `h = Hash(T(noise/hash, h, d))`, d not empty |
| token e, writing | `(e, E) = GenerateEphemeral()`; E into the message; MixHash(E) |
| token e, reading | the next P bytes as the peer's ephemeral key RE; MixHash(RE) |
| DH token t | `ctx = NewContext(noise/dh, h, [t])`; `sec = Agree(own, theirs, ctx)`; the first: `ck = sec`, then `ck = MixKey(ck, sec, ctx)`, the old ck and sec released |
| EncryptAndHash(pt) | `k = DeriveKey(ck, noise/key, NewContext(noise/key, h), 32)`; `c = AEAD(k).Seal(nonce 0, pt, ad = h)`; k released; MixHash(c). Without ck an error |
| DecryptAndHash(c) | the same k, Open, MixHash(c) |
| Split | `ctx = NewContext(noise/split, h)`; `i2r`, `r2i` = DeriveKey(ck, noise/split/i2r and noise/split/r2i, ctx, 32); SID = h; ck and e released |

The order within one message: MixHash of the record kind (done by e2e), token e, the DH tokens in
the order of the pattern (h does not change between them, the token byte in the context tells
them apart), then EncryptAndHash of the payload.

Tokens: e = 1, s = 2, ee = 3, es = 4, se = 5, ss = 6. The first letter of a DH token names the
initiator's key, the second the responder's:

| Token | Initiator (own, theirs) | Responder (own, theirs) |
|---|---|---|
| ee | e, re | e, re |
| es | e, rs | s, re |
| se | s, re | e, rs |
| ss | s, rs | s, rs |

- The zero nonce is safe: every key from EncryptAndHash serves one Seal, h changes after every
  ciphertext, and the ephemeral key is fresh. The top bit of the zero nonce is 0, as MGM needs.
- Reading a message changes nothing on an error: the values are computed in temporary buffers and
  applied only after a successful Open and the payload check, otherwise released, and h goes back
  to the end of the previous message, the MixHash of the kind included. A forged message does not
  break a handshake that waits for the real one.
- Token s inside a message (sending a static key) is not supported yet.
- Only the provider gives an ephemeral key; the API cannot set one. Only the vectors and the
  deniability check need a given ephemeral key, and a wrapper around the CryptoProvider is
  enough for them.

This is Noise-shaped, not an instance of the Noise Protocol Framework: Agree returns a KDF output,
not a raw DH result; h and ck go through the provider's Context; no initial ck comes from the
protocol name. Noise vectors (cacophony) do not apply, and the GOST variant is non-standard. The
properties of the KK pattern are claimed by analogy; there is no formal model.

### KK handshake

- The initiator is the side whose identity key is smaller in a byte-wise comparison. Equal keys,
  or the own queue in the peer's card, are refused. There are no simultaneous initiations.
- Before a session the peer's key is checked by a trial agreement of a one-time pair with it under
  the context `e2e/check` (the one-time public key, the peer's key). The output and the one-time
  key are released at once, and the identity key takes no part; a key the agreement refuses
  means the card is refused.
- Name `e2e/kk` (exchange `noise/e2e/kk`), prologue `[0x01, the initiator's card, the responder's
  card]`, pre-messages: the initiator's key S_I, then the responder's key S_R.
- Before every handshake message MixHash([record kind]): the kind enters h, the ad and every key
  after it.
- kk1: `01 | E_I | c1`, kk2: `02 | E_R | c2`; c is EncryptAndHash of L zero bytes. On reading the
  payload must be all zeroes.
- A side spends 4 Agree, 3 MixKey, 4 DeriveKey (2 message keys and 2 in Split), 16 transcript
  hashes and 1 GenerateEphemeral on the handshake; the check of the peer's key adds one more
  GenerateEphemeral and Agree per session.

| Formula | c25519 | GOST |
|---|---|---|
| output of a DH token, th = the hash of the `noise/dh` context | `HMAC(HMAC(th, X25519(a, B)), label(agree) \|\| 0x00 \|\| th \|\| 0x01)` | `KDF(VKO(a, B, UKM = th[0:8]), label(agree), th)` |
| ck from the second token on | `HMAC(HMAC(ck, sec), label(mix) \|\| 0x00 \|\| th \|\| 0x01)` | `KDF(ck, label(mix), th \|\| sec)` |
| message key, Split, ratchet step | `HMAC(key, label(purpose) \|\| 0x00 \|\| th \|\| 0x01)` | `KDF(key, label(purpose), th)` |
| record cipher, nonce 0 | XChaCha20-Poly1305: subkey HChaCha20(k, 0^16), ChaCha20-Poly1305 with nonce 0^12 | Kuznyechik-MGM, nonce 0^16 |

Session states: handshaking, established, confirmed (the responder after the initiator's first
data record), stale. The epoch grows with every change of session.

| Rule | Initiator | Responder |
|---|---|---|
| handshake record | kk1 is offered until the mailbox has stored it | kk2 is offered until the mailbox has stored it or the initiator's first record has arrived |
| waiting | kk2 is awaited for 60 s from the moment kk1 was stored, otherwise a new handshake with a fresh e_I | none |
| copies | a kk2 equal byte for byte to the accepted one is a copy; any other kk2 is refused without a change of state | a kk1 equal byte for byte to the accepted one is a copy; a kk1 whose E_I is in the ring of the last 64 seen (filled after a successful Open, the oldest pushed out) is a replay |
| new handshake | after going stale, or when the record numbers ran out | a fresh kk1 that opens replaces the session if there is none, it is unconfirmed or it is stale; otherwise it is refused |
| first records | right after kk2 a data record (real or dummy): the confirmation for the responder | real messages only after the confirmation, dummies at any time |
| going stale | 450 answered fetches (90 s at a 200 ms period) without an opened record of the responder | the same without a record of the initiator; a stale responder seals nothing, so the initiator goes stale too and starts a handshake the responder will accept |

An opened record clears staleness. A session in which each side puts a record more often than
once in 90 s does not go stale; the schedule of records is set by the conversation driver
(ARCHITECTURE, subsection "Conversation").

The payload security levels from the Noise table for the KK pattern, and what the rules do with
them:

| Message | Authentication | Confidentiality | Rule |
|---|---|---|---|
| kk1 | 1: key-compromise impersonation (KCI), whoever holds the responder's key forges a kk1 in the initiator's name; replayable | 2 | no data; the ring catches a replay; KCI and a replay of an old kk1 outside the ring reset only a session that is absent, unconfirmed or stale: the data keys need se = DH(s_I, e_R), without them no confirmation comes, and a live session cannot be reset |
| kk2 | 2 | 4 | no data |
| data | 2 | 5 | the ratchet on top |

- Unknown key share and identity misbinding: both cards are in the prologue, both static keys in
  the pre-messages.
- Reflection: the directions have different Split keys and a direction byte in the context of
  every ratchet step, and the record kind enters h.
- Identity hiding: KK sends no static keys.

### Hash ratchet

Each direction has a chain ck_n (secmem) and a number n; ck_0 is i2r or r2i from Split.

```
ctx_n   = NewContext(e2e/step, SID, [d], u32be(n))      d: 0x01 i2r, 0x02 r2i
mk_n    = DeriveKey(ck_n, e2e/step/key,  ctx_n, 32)
ck_n+1  = DeriveKey(ck_n, e2e/step/next, ctx_n, 32)     ck_n released at once
record  = 03 | u32be(n) | AEAD(mk_n).Seal(nonce 0, inner, ad = 03 | u32be(n))
inner   = flags (bit 0: dummy, the rest 0) | u16be(length) | body | zeroes, 371 bytes in all
```

- The sender assigns n when it seals and never uses it twice; a repeated record is a copy of the
  same bytes. At number 2^32 - 1 the session ends and the initiator starts a new handshake.
- The receiver keeps the next expected number and a bitmap of the 64 numbers below it:
  - a number below the expected one with its bit set: a copy;
  - a number below the expected one without its bit, or below the bitmap: a late record;
  - a number more than 64 past the expected one: outside the window;
  - otherwise a temporary copy of the chain steps to n, the record is opened, and only on success
    does the state change (the skipped numbers count as lost). A forged number costs at most 64
    steps. Skipped keys are not stored.
- After a gap of more than 64 records in one direction, such as a burst dropped at the mailbox
  or a long outage, every later record of that direction is outside the window and is lost as
  well. Only a new session brings the direction back: the receiving side opens nothing and goes
  stale, a stale side seals nothing, so the other side goes stale too, and the initiator starts a
  new handshake. With a fetch every 200 ms this takes at most 2 x 90 s plus the 60 s wait for kk2.
- A dummy record is empty. Non-zero padding, extra flag bits, a length above 368 and a dummy
  with a body are refused. A real record and a dummy one cost the same provider calls.
- Forward secrecy per record. There is no post-compromise recovery (no DH ratchet); a new
  handshake after going stale gives it as a side effect, not on a schedule.

### Client keys

| Key | Made by | Where | Lives |
|---|---|---|---|
| client identity key (static agreement key) | GenerateEphemeral at start | secmem | until the process ends |
| fetch capability F | crypto/rand | secmem; a copy in every request on the client heap and in the clear at the mailbox | until the -peer client process ends |
| one-time key of the card check | GenerateEphemeral | secmem | one agreement when a session is made |
| e_I | GenerateEphemeral | secmem | until kk2 or a new handshake: the wait for kk1 to be stored plus 60 s |
| e_R | GenerateEphemeral | secmem | the writing of kk2 only |
| Agree outputs, ck, handshake message keys | Agree, MixKey, DeriveKey | secmem | one step |
| ratchet chains | Split, DeriveKey | secmem | until the next record in that direction |
| mk_n | DeriveKey | secmem; on c25519 a copy in the AEAD struct | one Seal or Open, then Destroy |

An established session holds the identity key and two ratchet chains; the initiator also holds
e_I and ck until kk2; a record that skips numbers adds a temporary chain and a record key while
it is taken.

### Deniability

Claim: offline deniability for both parties. A session transcript (kk1, kk2 and every data
record), even together with the recipient's private keys, does not prove to a third party that
the sender took part in the session, unless the judge holds an independent trusted record of who
transmitted these ciphertexts and when. The two parties are symmetric peers: the sender can be the
initiator or the responder, so a forgery by either party in either role is the same procedure with
the labels swapped, and the check below covers the forger in both roles.

The perfect simulation argument:

1. Every byte of a transcript is a deterministic function of public values (both cards, E_I,
   E_R), the plaintexts and four Agree outputs: es, ss, ee and se. The context of each output is
   built from public values only: h at the token and the token byte.
2. Agree is symmetric under one Context on both suites: Agree(a, B, ctx) = Agree(b, A, ctx). The
   conformance tests of the providers check this (agreement both ways and the golden agreement
   vectors), and so do the vectors of the end-to-end layer: both sides of every DH token get one
   output.
3. The recipient knows its own static key and draws both ephemeral keys itself, with the same
   GenerateEphemeral the honest parties use. The sender's key enters two outputs, and the
   recipient computes each of them from its own side; the other two depend only on ephemeral
   keys it drew itself.

| Sender | Outputs with the sender's key | How the recipient computes them |
|---|---|---|
| initiator | ss = DH(s_I, s_R), se = DH(s_I, e_R) | Agree(s_R, S_I), Agree(e_R, S_I) |
| responder | es = DH(e_I, s_R), ss = DH(s_I, s_R) | Agree(e_I, S_R), Agree(s_I, S_R) |

4. The nonces are fixed, the handshake payloads are zero, and the transcript holds no other
   random value. So a forgery is distributed exactly like a genuine transcript with the same
   plaintexts, with no computational assumption, even for a judge handed both static keys.
5. Only a value that the sender alone can compute, that is a signature, would break this. Hence
   the rule under "Signatures": identity signatures never authenticate client messages.

The witnessed transcript condition: the argument speaks only of the bytes of a transcript. A
mailbox or an observer of the sender's link colluding with the recipient lifts the condition: a
log of put requests by circuit together with the binding of a circuit to the sender's address
(collusion with the entry or a correlation attack) is an independent record of who transmitted
the ciphertexts, and the simulation does not cover it.

The check: the lab/scenario package and `cmd/lab -set deny`.

- Genuine runs a real session of two identities. Forge builds a session with the same plaintexts
  holding the recipient's private keys only. Verify plays a transcript to a fresh session of the
  recipient: every record of the sender must open to the text it claims, every record of the
  recipient must come out again byte for byte.
- Both sides of the forgery are the production e2e session. The sender's side goes through the
  noise.Static interface: a stand-in key knows only the public half of the sender's key and
  answers every agreement with the agreement of the recipient's key, static or ephemeral, with
  that half (step 3). A wrapper over the CryptoProvider records the recipient's ephemeral key and
  hands it back for the check; the production API cannot set an ephemeral key.
- The check runs on both suites with the recipient in both roles. The genuine and the forged
  transcript pass Verify and have the same structure: the same records by author, kind and size,
  the same clear header (the kind and the record number) and the same claimed texts. Two
  forgeries of one script share no ephemeral key and no record.
- The negative control: a forgery made with a fresh key in place of the recipient's passes Verify
  under that key, and under the recipient's key Verify refuses its first record, a cryptographic
  mismatch and not a check of names.
- A provider wrapper that sees every agreement sees the recipient's private key in the forgery,
  so the forgery goes through it, and sees the sender's private key in the genuine session and
  neither in the forgery nor in the checks. A test draws the sender outside lab/scenario and
  wipes its private key before the first call: the forgery still passes Verify.
- The report `artifacts/deny-<suite>-<time>.json` carries the verdicts with the record at which
  the control is refused, the assumption and the records in hex (the handshake records hold the
  public ephemeral keys), and no byte of a secret key: a test reads it as a closed schema and
  searches it for every piece of every secret of the run. It is a demonstration on concrete keys,
  not a measurement.

Not claimed: online deniability, that is against a judge acting together with the recipient
during the session; deniability of metadata (mailbox records, network observations, circuit
timings); a witnessed transcript; a sender's device compromised before the session. There is no
formal model: the argument rests on the symmetry of Agree, which the tests check, and on the
transcript holding no other value.

## Memory (crypto/secmem)

- A buffer comes from mmap on pages of its own outside the Go heap, then mlock and
  madvise(MADV_DONTDUMP).
- Release: zeroing, munlock, munmap. A second Release does not panic.
- Process: prctl(PR_SET_DUMPABLE, 0), RLIMIT_CORE=0. This closes ptrace and /proc/pid/mem for the
  same uid and does nothing against root.
- Off-heap pages, locking, dump exclusion and process hardening work in the Linux build only. On
  other systems a buffer is a slice on the Go heap that reports itself as not locked, and release
  does nothing but zero it, and that only with zeroing on. Process hardening returns an error
  there: with the default flags a node, a client and jimichi enroll refuse to start and run only
  with -harden=false and a -keymem without lock.
- In a container mlock is bounded by RLIMIT_MEMLOCK. A node checks the budget at start, before
  it makes its first key, and refuses to run below 80 KiB, or when locking was asked for and
  failed. A rotating node holds one locked page per onion key, two at most, and, when memory
  allows, four more that it gives back right before it makes the next key: one for the key,
  three for its key pair check. It takes them at start, after the pair checks of its keys, after
  each rotation and, if there was no room then, again once the replaced key is released. It does
  not take a new onion key whose page is not locked.
- Every measure is switched by configuration, so its contribution can be measured:

| Flag | What it turns on |
|---|---|
| -keymem all | every measure, the default |
| -keymem none | baseline build: keys on the Go heap, no locking, no dump exclusion, no zeroing |
| -keymem offheap,lock,dontdump | everything but zeroing: zeroing's effect on a process dump shows only with keys on the heap (none against zero), since off-heap pages are gone from the process after munmap |
| -keymem offheap,lock,dontdump,zero | any subset; lock and dontdump need offheap |
| -harden | prctl(PR_SET_DUMPABLE, 0) and RLIMIT_CORE=0 for the process |

## Libraries

- GOST: gogost 5.14.1 by Sergey Matveev (GPLv3), module github.com/pedroalbanese/gogost. The
  author's domain go.cypherpunks.su did not answer and the Go proxy has no copy, so a mirror with
  the same version number in its code is used, pinned in go.mod and go.sum (pseudo-version of
  commit 44a1f1ec2524). Whether its code equals the author's release has not been checked against
  an independent source, the check is planned
  ([#50](https://github.com/jimichi-org/jimichi/issues/50)). The library packages of the mirror
  were checked: no network or file I/O, and unsafe only in the fast XOR. Known-answer tests in
  crypto/gost check the standards: VKO against RFC 7836, the KDF against R 50.1.113-2016,
  Kuznyechik-MGM against RFC 9058, Streebog-256 against RFC 6986.
- The peer's point is checked before VKO: coordinates below p, the point on the curve and not in
  the subgroup of order 2 or 4. The library does not do this itself, and an off-curve point would
  let a peer draw the node's link or onion key out piece by piece. For mixed points the cofactor
  of 4 is cleared inside VKO.
- The UKM for VKO is the first 8 bytes of the transcript hash as a little-endian number, zero
  replaced by one; the whole hash seeds the KDF. The technique follows KEG (RFC 9189, section
  8.3.1), where the UKM is the first 16 bytes of a hash and zero is replaced by one in the same
  way. The provider takes no other UKM length.
- Signing feeds the Streebog digest in gogost's byte order. Only this system verifies the
  signatures, so interoperability with other implementations is not claimed.
- c25519: golang.org/x/crypto (curve25519, chacha20poly1305, hkdf). Ed25519 signing follows
  RFC 8032 on filippo.io/edwards25519, directly over the secmem buffer. Since Go 1.25 crypto/ed25519
  caches the expanded key under a weak pointer to the key: on mmap memory the runtime aborts, and on
  the heap the expanded key lives until garbage collection.
- GenerateSigning in c25519 reads the seed from crypto/rand straight into the secmem buffer and
  derives the public key from it by RFC 8032 (section 5.1.5) on filippo.io/edwards25519, wiping
  its own scalars and digests. crypto/ed25519.GenerateKey would leave the seed and the expanded key
  on the heap, while the node signing key lives as long as the process. The copies inside SHA-512
  and edwards25519 remain and are listed under "Known gaps". A test checks the public key and the
  signatures against ed25519.NewKeyFromSeed.

## Known gaps

secmem protects only the buffers the code manages itself. Libraries make their own copies, and
some of them live long:

| Where | What | How long |
|---|---|---|
| x/crypto chacha20poly1305 | the AEAD working key, copied into the cipher struct; in the end-to-end layer the key of a handshake message and the key mk_n of every record | for a circuit or link its whole life, never wiped; in the end-to-end layer the struct serves one Seal or Open, and the copy stays until the heap memory is reused; building the AEAD state per call from the secmem key is planned ([#39](https://github.com/jimichi-org/jimichi/issues/39)) |
| crypto/ecdh | the X25519 scalar, the node's link and onion keys and the client identity key included, and the shared secret, the static-static one (ss) included, which is the same for every session of a pair of clients before the KDF | until the freed heap memory is reused, which can be after the key itself was released |
| x/crypto hkdf, crypto/hmac | the HMAC pads (key XOR a constant) holding the PRK, the circuit secret, the link secret (ee or the MixKey output) and the MixKey chain key, in the end-to-end layer the handshake ck and the ratchet chain keys; the SHA-256 state holding the X25519 shared secret and the second secret of MixKey; the last derived block, mk_n included | until the heap memory is reused; the provider zeroes its own copy of the PRK unless zeroing is off (-keymem none or a list without zero) |
| Ed25519 generation and signing | the SHA-512 state with the seed or the nonce prefix, a copy of the scalar in edwards25519 | until the heap memory is reused; generation and signing always wipe their own scalars and digests, -keymem none included |
| gogost, Kuznyechik | the round keys in the cipher struct, the first two being the key itself | the whole life of the circuit or link; Destroy wipes them unless zeroing is off (-keymem none or a list without zero) |
| gogost, KDF | the HMAC-Streebog pads holding the VKO secret, the circuit secret, the link secret (ee or the MixKey output) and the MixKey chain key, in the end-to-end layer the handshake ck and the ratchet chain keys; the Streebog message buffer holding the second secret of MixKey; the last block Streebog computed, kept in the working buffer of the hash and in a temporary block after Sum, half of which is the output: a copy of the KEK and of every Agree, MixKey and DeriveKey output | until the heap memory is reused; the provider assembles the MixKey seed in a secmem buffer and, unless zeroing is off (-keymem none or a list without zero), zeroes the slices the library returns, not the buffers inside it |
| gogost, GOST R 34.10 and VKO | the scalar as math/big and intermediate points, the node's link and onion keys and the client identity key included | until the heap memory is reused, which can be after the key itself was released; the provider wipes the number unless zeroing is off (-keymem none or a list without zero), never the copies made inside the computation |
| gogost, GOST R 34.10 signing | the CA or node signing scalar and the one-time number k as math/big, intermediate points; k and the signature give back the key | until the heap memory is reused; the copies reappear at every signature: the request, the certificate, every descriptor refresh |
| end-to-end layer | plaintexts: the body passed to Seal and the body Receive returns (e2e zeroes its own record buffer) | with the caller, never wiped |
| -peer client and mailbox | message bodies and the records held before pinning, which the conversation driver zeroes only once the mailbox has stored a record or the conversation ends; the copies of a request with the fetch capability F that the circuit keeps after Send, while the driver zeroes its own: in client.Client the queue of the fixed schedule and the plaintext buffer wire.Circuit.Seal wraps in the layers; at the mailbox a copy of the request with F in the cell body and in the link buffer after it zeroes its own slice | until the heap memory is reused |

gogost arithmetic on math/big is not constant time. The node's link and onion keys could leak
through VKO timing to an adversary who times the node's responses; side-channel attacks are
outside the threat model.

The Go heap does not move objects, but freed memory is not wiped, and goroutine stacks are copied
when they grow. Locking and MADV_DONTDUMP do not reach these copies: only secmem pages are locked,
so key copies on the heap and on stacks can be written to swap, and with -harden=false they can
end up in a core dump. Locking all process memory is planned
([#36](https://github.com/jimichi-org/jimichi/issues/36)). Measuring how many copies remain and
how long they live is planned as block 4 of the research programme
([#24](https://github.com/jimichi-org/jimichi/issues/24)) and has not been done yet.
