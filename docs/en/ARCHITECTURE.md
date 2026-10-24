# Architecture

English | [Русский](../ru/ARCHITECTURE.md)

## What the system is

Messages travel through a chain of relay nodes under nested encryption. The client draws the
chain, three nodes by default, at random from a list of nodes. In a chain of two or more nodes no
single node sees both the client and the message: the entry knows the client's address, the exit
opens the message. A node keeps key material in process memory and writes none of it to disk, and
every cell is the same size. Two clients in -peer mode talk through a mailbox at the exit of their
chains: a message is sealed under the end-to-end layer between the clients (CRYPTO, "End-to-end
layer"), and the mailbox holds only records of a constant size that it cannot read. A client
without -peer sends its messages to an exit that echoes them back: the measurements run on that
topology.

## Components

| Component | Purpose |
|---|---|
| client | draws the chain, builds the circuit, encrypts the layers, sends payload and cover cells, receives replies; with -peer holds a conversation with one contact through a mailbox |
| relay | strips its own layer and forwards; writes nothing to disk; as the exit answers with an echo or as a mailbox (-exit) |
| noise, e2e | the end-to-end layer between clients: the contact card, the KK handshake, the hash ratchet |
| mailbox | queues of end-to-end records at the exit, in memory only |
| conversation | a client's conversation with its contact: a request on every tick, a window of puts, the rebuild of the circuit |
| crypto | CryptoProvider: two primitive suites behind one interface |
| crypto/secmem | key buffers outside the Go heap: mlock, no dumps, zeroed on release |
| wire | cell format and nested route encryption |
| vault | client container: a file of a constant size with one or two volumes under passwords of their own; a volume holds the contact card, while the identity key and F are derived from the volume password and the salt of the file at every opening (section "Client container"); the -peer client with a container is planned ([#20](https://github.com/jimichi-org/jimichi/issues/20)) |
| lab | experiment runs, the observer and metrics; cmd/lab writes the reports to artifacts/ |
| web | planned ([#21](https://github.com/jimichi-org/jimichi/issues/21)), no code yet: testbed dashboard with the network graph, what each node learns and the live attack result |

## Message flow

```
client-a -> entry A -> middle A -> mailbox (exit) <- middle B <- entry B <- client-b
```

The conversation of two -peer clients:

1. The clients are introduced: each has pinned the card of the other, which holds the mailbox
   address, a queue and a static key (subsection "The -peer client").
2. Each builds its own circuit whose exit is the mailbox (the steps below apply to each).
3. On every tick each client sends one request: a fetch from its own queue and a put of a record
   into the queue of its contact.
4. A message is sealed under the end-to-end layer into a record of 392 bytes: the KK handshake
   first, then the hash ratchet (CRYPTO, "End-to-end layer"). The mailbox keeps the record in the
   recipient's queue.
5. The recipient takes the record in the reply to one of its requests and opens it with its
   session.

A client without -peer sends its messages to the exit, and with -exit echo (the default) the exit
sends each back as the reply: this is the topology the lab harness measures. Building one circuit:

1. The client holds a list of N nodes and the length of the chain, three by default. It draws
   its entry uniformly among the N nodes, a -peer client among the N - 1 nodes other than the
   mailbox.
2. It obtains the signed bundles of the listed nodes from the entry, the only node it connects to.
   The entry may leave out up to -missing of them (1 by default). A bundle is the node's
   certificate from the CA and a descriptor with the node keys, signed by the node signing key.
3. Before the circuit setup the client checks every bundle against the trust anchor, each on its
   own (section "Node authentication"). A bundle that fails the check counts as a node the entry
   left out, within -missing. The entry's own bundle must pass, or the client refuses to build
   the circuit.
4. It draws the other nodes of the chain uniformly among the other nodes whose bundles passed the
   check, for a -peer client the middle hops with the mailbox last (section "Choice of the
   chain"), and agrees an ephemeral session key with each node of the chain separately.
5. The client wraps the message in one layer per node: the outer one for the entry, the inner one
   for the exit.
6. Each node strips exactly its own layer and learns only the next hop.
7. Session keys live until the circuit is torn down, and their buffers are then zeroed. Copies the
   libraries keep are described in CRYPTO.

## Choice of the chain

- The node list (-nodes) is static: N addresses, N not less than the length of the chain. There
  is no node discovery. The length of the chain (-hops) is 3 by default and at most what one
  setup cell carries: 4 on c25519, 3 on GOST (section "Cell format").
- The list is checked at start, before any request and before anything is drawn: an address that
  is malformed or listed twice, fewer nodes than hops, or more hops than the setup cell carries
  stop the client.
- The entry is drawn uniformly among the N nodes. The other hops are drawn once the bundles the
  entry served have been checked: uniformly and without replacement among the other nodes whose
  bundles passed the check, in the order of the chain (the first steps of a Fisher-Yates
  shuffle). When the entry serves all N nodes and all pass, every ordered chain of distinct nodes
  is equally likely, and three hops among five nodes give 60 of them. When it leaves nodes out or
  not all pass (-missing), the chain is drawn among the rest (LIMITATIONS).
- The randomness comes from the system generator (crypto/rand). A draw among m nodes reads 64
  bits, throws the value away and reads again while it is below 2^64 mod m, and only then
  reduces it modulo m: without that the low remainders would come up more often.
- The request to the entry does not depend on the rest of the chain: the client asks for the one
  mirror and checks the bundle of every listed node in it, each on its own, not only of the
  nodes it will use. A bundle that fails the check counts as a node the entry left out: the chain
  is drawn among the others, and -missing (1 by default, never more than N minus the chain
  length) bounds the missing and the failing nodes together. A mirror that lacks the entry's own
  bundle, or whose entry bundle fails the check, refuses the circuit: the client connects to the
  entry and needs a verified bundle of it. Bundles of different nodes are not compared with each
  other: the setup layer and the link of every node are bound to its identity (CRYPTO, section
  "Transcript").
- For a client without -peer any failure ends the process: an entry that does not answer, a
  mirror that lacks a verified bundle of the entry itself or more listed nodes than -missing
  allows, a setup that fails. The orchestrator restarts the client, and the new process draws a
  new entry. Within one run the client does not move on to another entry, nor does a -peer
  client.
- With a drawn chain the client does not log which nodes form it. Its log holds the name, the
  fingerprint and the certificate validity of every verified node, in the listed order (with
  -fixed-chain the descriptor validity as well), one line with the number of verified and of
  listed nodes, and one line with the number of hops and of listed nodes. A failed request to
  the entry and a failure on the circuit are logged by class only (a status code, the size
  limit, a failed handshake, a timeout, a failed connection): the error itself names the address
  of the entry.
- -fixed-chain takes the first -hops nodes of the list in the listed order, the first of them as
  the entry, and draws nothing. The bundle of every listed node the entry serves is still
  checked, but only the nodes of the chain have to be among them and pass, and errors name the
  node in full. The flag is for measurements that need a known path; no measurement uses it: the lab
  harness builds its chain itself, in a fixed order.
- With N equal to the length of the chain the chain is a random permutation of the list.

The -peer client:

- The exit is pinned to the mailbox (-mailbox, one of the listed nodes). The entry is drawn
  uniformly among the other N - 1 nodes (ChooseEntryExcept), the middle hops uniformly and
  without replacement among the nodes that are neither the entry nor the mailbox and whose bundles
  passed the check, and the mailbox comes last (ChooseRestTo). With a full mirror every ordered
  chain that ends on the mailbox is equally likely.
- A mirror is taken by the same rule and must also hold a verified bundle of the mailbox, or the
  client refuses with `the entry holds no bundle for the mailbox` (JudgeMirrorTo). So the mailbox
  is never the entry.
- -hops is at least 2: with one hop the mailbox would be the entry too. With -fixed-chain the node
  at place -hops in the list must be the mailbox.
- A -peer client logs no line per listed node; neither the path nor any node address reaches the
  log, and refusals and failures are logged by class only.
- The end of a circuit is not the end of the conversation. A rebuild always goes through the same
  entry and a fresh mirror of that entry:
  1. first the same chain: the same middle hops and the same mailbox, with keys from the new
     mirror;
  2. new middle hops are drawn only when that chain cannot be dialled: the mirror lacks one of its
     nodes, the connection to the entry fails, or two circuits in a row through it ended before
     the first reply (a setup that the entry or a middle hop did not carry on shows to the client
     only that way); this happens at most 2 times per process;
  3. after that the client dials its last drawn chain again and again. The entry, the mailbox or
     the middle hop can always stall the conversation, but none can steer the middle hops any
     further.
- A close by the far side, a reply timeout, a refused reply and a failed send all fall under the
  one rule, and none of them gives a draw beyond the bound. A mirror the client does not take
  gives neither a draw nor a setup. The bound and the chance that a rogue entry or a rogue mailbox
  gets its colluder as the middle hop are worked out in LIMITATIONS.
- The pauses between attempts and the time limit come from the conversation driver: 1 s, doubling
  up to 60 s, at most 10 min, then exit code 1; three refused replies within 10 min give code 3
  (subsection "Conversation").
- With -fixed-chain a rebuild always dials the same chain and draws nothing.

## Cell format

Every cell is 512 bytes, payload and cover cells alike.

| Field | Size | Purpose |
|---|---|---|
| version | 1 | format version |
| kind | 1 | data, control, link padding |
| circuit | 8 | circuit identifier, different on every link |
| counter | 8 | cell number on the link, the source of the nonce and of replay protection; a value of its own on every link |
| body | 494 | layers: a 16-byte tag per hop, the length prefix and the payload |

- The nonce never travels: it is derived from the direction, the circuit identifier and the
  counter. A key belongs to one hop of one circuit, so the pair never repeats under it.
- The counter takes a value of its own on every link of the circuit. At setup each node derives
  two offsets from the secret it shares with the client, one per direction, and adds its offset
  modulo 2^62 to the counter of every cell it passes on. The client knows the offsets of all
  nodes and seals the layer of each node with the value that arrives on the link into that node.
  The setup cell does not grow for it.
- The cell number stays below 2^60 in each direction, so the values of one link never repeat
  while the circuit lives.
- Every layer is an AEAD over the next layer. The associated data covers the version, the kind,
  the counter on the link into the node and the hop index, so a cell cannot be moved to another
  position in the chain and a node cannot shift the counter without breaking the layer.
- The circuit identifier is rewritten on every link and is not part of the associated data: the
  layer is bound to it through the nonce, and the hop key is derived under the setup transcript,
  which holds the identifier of the link into the node (section "Circuit setup"). Forward, a
  node finds the circuit by the identifier of the cell and builds the nonce from it. Backward, a
  node does not read the identifier of the cell that arrived and sets its own, and the client
  compares the identifier of a reply with that of its own link.
- The layer of hop i occupies the first 494 - 16 * i bytes of the body. After stripping its layer
  a node refills the body with random bytes, so every link carries the same size and the size
  does not show the position in the chain.
- Payload and cover cells share one outer kind, "data". The cover flag sits inside the innermost
  layer, in the top bit of the length field, where only the exit sees it. Nodes on the way,
  including the entry that knows the client, cannot tell a cover cell from a payload cell.
- Inside the innermost layer: two bytes of length, the data, random padding. Three hops leave 444
  bytes for a message, in both suites; four hops, on c25519 only, leave 428.
- The setup cell holds four hops on c25519 and three on GOST: a GOST public key is 64 bytes
  against 32, and every setup layer grows by the difference. This bounds the length of a chain,
  and the client checks -hops against it at start.
- Counters on every link follow strictly one after another: a node accepts a cell only if its
  counter is one above the last one accepted, modulo 2^62. Every node except the exit takes the
  first value in each direction as it comes, since it depends on the offsets of the other nodes.
  The exit expects a fixed first forward value, and the client checks the number of every reply
  (section "Return path"). A copy, a gap, a step back
  or a jump closes the circuit and the cell goes no further: forwarding a replay would hand an
  active observer a free timing mark, and a gap or a reorder would carry on to every later link.
- The exit knows the counter the first forward cell arrives with: the client puts that value in
  the exit's setup layer. Cells lost at the start of a circuit at any node reach the exit as a
  break in the order, and the exit closes the circuit.
- A node opens a forward cell first and checks its counter after. A cell that does not open is
  dropped and does not affect the order.
- The client assigns the counter when it writes the cell to the link, after the random delay, so
  cells leave in counter order.

## Link encryption

A cell never crosses a link in the clear: it travels inside an encrypted frame. Without this layer
the cell header is visible on the wire: an observer on a link would see the kind, the circuit
identifier and the counter of every cell.

- Handshake: the initiator sends a mode byte and an ephemeral public key. The responder answers
  with its own ephemeral public key and one frame: a link padding cell sealed as frame 0 of its
  direction. The secret of the two ephemeral keys gives the link forward secrecy.
- That frame confirms the keys before any cell is sent. The initiator finishes the handshake only
  once the frame has opened under the keys it derived and holds a padding cell, within the
  deadline of whoever dials. Otherwise the handshake fails, and the initiator has sent nothing but
  its hello. The responder sends the frame in both modes, and the frames of its direction go on
  from number 1. The responder's part of the handshake is its key and that one frame: 32 + 528
  bytes on c25519, 64 + 528 on GOST.
- The frame keys are bound to the transcript of the handshake: the format version, the mode
  byte, the ephemeral keys of both sides as they crossed the wire and, in the authenticated mode,
  the responder's link key and, when nodes are authenticated, the responder's identity key that
  its certificate certifies. The hash of the transcript goes into every agreement and into the
  derivation of every key (CRYPTO, section "Key derivation"). A byte of the hello or of the
  answer changed on the way is either refused outright (an unknown mode, a key the agreement
  does not accept) or gives the two sides different keys, so the confirmation frame does not
  open; in every case the handshake fails.
- In the authenticated mode the initiator makes a second agreement, of its ephemeral key with
  the responder's link key taken from a verified descriptor: the client does it for the entry
  node, a node for the next node of the circuit. The two secrets are chained (MixKey), and the
  frame keys depend on both. Every link of a circuit is therefore authenticated to the node it
  leads to: only the holder of that link key that binds the same identity derives the frame keys,
  so a responder without them cannot produce the confirmation and is sent no cell. The responder
  puts its published link key and its identity key into the transcript, and a hello in the
  authenticated mode to a responder without a link key is refused before any agreement. The
  responder does not authenticate the initiator.
- A node extends a circuit only to a node of its roster whose verified descriptor it holds
  (section "Node authentication"). A setup that names any other address is refused without a
  connection and counted (refused_extend). A next node that does not finish the handshake is
  sent no setup cell, and the failure is counted (failed_extend). In both cases the setup cell
  is counted with the dropped ones, like that of any setup that fails.
- Without node authentication (-auth=false) a node holds no verified link keys: it extends to
  any address, and its link to the next node is anonymous. An anonymous link hides headers from
  a passive observer only. This is the configuration without the measure: the lab harness runs its
  nodes this way, and no experiment block compares it with the authenticated one.
- Two keys are derived from the secret, one per direction. The nonce is the frame number in that
  direction.
- The binding takes no byte on the wire: the hello, the answer and the frame carry no field for
  it.
- A frame is the 512-byte cell plus a 16-byte tag, 528 bytes. After the handshake the wire carries
  only frames of one size: no identifiers, no counters.
- The link layer takes its primitives from the same CryptoProvider, so it works on the GOST suite
  as well.
- A link padding cell lives on one link only: the sender of the frame makes it and the receiving
  end of the link drops it before it reaches a circuit. From the outside it looks like any other
  frame.

## Sending modes

| Mode | How cells leave | What an observer sees |
|---|---|---|
| Immediate | a cell leaves as soon as there is something to send, cover is added on top | the send pattern follows the conversation |
| Constant rate | cells leave on a schedule and a payload takes a cover slot | the pattern on the link does not depend on the conversation |

The second mode is the countermeasure against flow linking. Its price is queueing: a message waits
for its slot, so latency grows at a low schedule rate and shrinks at a high one. The client's queue
holds 256 messages: when messages come faster than the schedule sends them and the queue is full,
a new message is dropped and counted, and the caller gets no error.

A -peer client requires -mode fixed but keeps a schedule of its own: the conversation driver sends
exactly one request on every tick of -rate through the immediate mode of the library while there
is a circuit, and sends no cover cells on the wire. There is a request on every tick, message or
not, so the pattern on the link does not depend on the conversation. -jitter delays each request
within its tick and must be below -rate.

A constant rate at the client is not enough: a node that forwards a cell at once carries the phase
of the client's schedule onto the next link, and it reaches the exit. So a node can send on its own
clock.

- Node parameter: the send period. Zero means forwarding at once, as without the measure.
- Each circuit and each direction gets its own queue and timer on the node. Every tick sends one
  cell from the queue, or a link padding cell when the queue is empty.
- The first tick falls at a random moment within the period. Otherwise the timer would start with
  the circuit setup, which crosses the chain almost at once, and the client's phase would match
  the node's again.
- The queue is bounded, so neither the node's memory nor the latency grows without limit when a
  client sends faster than the node's period. A cell that arrives at a full queue closes the
  circuit: a node never loses a cell of a circuit, since a loss would break the counter order on
  the later links. Such a close is counted with the closed circuits.
- There is no shuffling across circuits: every circuit runs over its own TCP connections, so
  there is nothing to mix on a link. A mixing mode with reordering across circuits is planned
  ([#82](https://github.com/jimichi-org/jimichi/issues/82)).

Entry and middle send on their own clock in both directions, the exit only backwards: it has
nothing to send forwards. The price: at each such step a cell waits half a period on average, about
two and a half periods per round trip, and the links between nodes and from the entry to the
client carry a constant stream per circuit even while the client is silent.

The measure hides the timing of data cells from an observer on a link whose sending node has it
on. The setup cell and the opening and closing of a circuit's connections do not go by the node's
clock and stay visible (LIMITATIONS). A neighbouring node removes the link encryption and tells
padding from a real cell by its kind, so the measure does not help against a node.

## Return path

A reply travels the same chain in reverse: the exit applies its layer, every relay towards the
client adds its own, and only the client strips them all. The direction enters the nonce, so a
forward and a backward cell never share one under the same key. The backward counter is separate,
and each relay checks the counter order in each direction separately. Like the forward one, it
takes a value of its own on every link: the exit and every relay on the way back add their backward
offset.

A relay cannot check a backward cell: its inner layers do not open for it. It therefore passes back
only cells of kind "data" with the next counter in turn, and any other cell closes the circuit.

The exit numbers its replies from zero, and the client knows the offsets of all nodes and recovers
the number of every reply. The client checks every reply, cover and payload alike, in this order:

| Check | What fails it |
|---|---|
| the header: the version, the kind "data", the circuit identifier of the client's link | a cell of another version or kind, another identifier; a reply that the entry relabels as link padding does not reach this check: the link drops it (link.ReadCell), and it counts as a reply that never arrived |
| every layer opens | an altered body or counter, a cell nobody sealed, a cell of another circuit, direction or position, a bad length under the last layer |
| the number of the reply is strictly the next one | a copy, a gap, a step back, a reorder of genuine replies |
| the number is below the count of cells the client has written to the link | a reply to a cell the client did not write: the exit answers every cell once |

Nothing is tolerated: the first reply that fails a check closes the circuit, and the client reads
nothing after it. A reply out of turn cannot be taken without taking a gap or a replay, and a reply
too many answers no cell of the client. A reply with a bad header or one that does not open takes no
number, and forward a node drops such a cell and keeps the circuit; the client closes the circuit
here as well: an honest chain produces no such reply, and the reply whose place such a cell took is
already lost. Of a circuit it closed the client keeps only which of the four checks the reply
failed, or that a frame on the link from the entry did not open. A reply that never arrives is not
noticed by these checks.

A reply too long for a cell is replaced by a cover reply under the same number. The length is
checked before anything is sealed, so no nonce is used twice. Any other failure to seal a reply
closes the circuit.

The exit answers every data cell with exactly one backward cell: a message with its reply, a cover
cell with a cover reply. Replies to messages only would show every node on the way back, by their
number and timing, which cells were real. The count is the same in every mode; the timing matches
only when the delivery at the exit takes constant time or the nodes send on their own clocks.

With -exit mailbox the answer to every data cell is a mailbox reply of a constant 396 bytes, and
instead of the echo the exit does bounded work per request: one hash, operations on maps and
lists, the copy of one record. That work is not constant (subsection "Store"): the difference of
microseconds shows outside the exit only when the exit forwards at once.

## End-to-end layer and mailbox

The store at the exit (package mailbox, `cmd/relay -exit mailbox`), the end-to-end layer (packages
noise and e2e, CRYPTO), the conversation driver (package conversation, subsection "Conversation")
and the client that uses them (`cmd/client -peer`, subsection "The -peer client"). On the testbed
every relay runs with -exit mailbox, and both clients keep their queues on relay-5.

The -exit flag sets what the exit does with the payload of a data cell:

| -exit | Reply |
|---|---|
| echo (the default) | the same payload |
| mailbox | a mailbox reply, always 396 bytes |
| none | a cover reply |

The cell format does not change. A mailbox request and reply are the payload of an ordinary data
cell, and wire fills the rest of the body with random bytes. The client sends one request per
tick: a fetch from its own queue and, when it has something to put, a put into the peer's queue.
A record is a ciphertext of the end-to-end layer of a constant 392 bytes, opaque to the mailbox.

| Hops | Cell capacity | Left after a 427-byte request | Left after a 396-byte reply |
|---|---|---|---|
| 2 | 460 | 33 | 64 |
| 3 | 444 | 17 | 48 |
| 4 (c25519 only) | 428 | 1 | 32 |

### Queue and fetch capability

- Fetch capability F: 16 random bytes of the queue owner, not all zero.
- Queue identifier: `QueueID(F) = NewContext(p, "mailbox/queue", F).Sum()[0:16]`. The
  transcript is 62 bytes on c25519 and 60 on GOST.
- Whoever knows F fetches; whoever knows the identifier puts. The mailbox sees F in every
  request and keeps only the identifier.

### Request, 427 bytes

| Offset | Bytes | Field |
|---|---|---|
| 0 | 1 | version, 0x01 |
| 1 | 2 | tag, u16be: the number of the request on the circuit modulo 2^16 |
| 3 | 16 | F; zeros: no fetch |
| 19 | 16 | queue identifier for a put; zeros: no put |
| 35 | 392 | record; zeros without a put |

### Reply, 396 bytes

Every data cell gets a reply, never nil.

| Offset | Bytes | Field |
|---|---|---|
| 0 | 1 | version, 0x01 |
| 1 | 2 | tag of the request; 0 when the request is shorter than 3 bytes |
| 3 | 1 | status |
| 4 | 392 | record or zeros |

| Status bits | Meaning |
|---|---|
| 0x80 | bad request: length not 427, version not 1, or an identifier other than the one bound to the circuit; the other bits 0, the record zeros |
| 0-1 | put: 00 not asked, 01 stored, 10 the queue is full or the total record limit is reached, 11 refused: no room for a new queue |
| 0x04 | the record field holds the head of the queue |
| 3-6 | always 0 |

The client matches a reply to its oldest unanswered request by position: the replies of a
circuit arrive strictly in order, and the tag is a check. A reply is bad when:

- its length is not 396, its version not 1, a bit of 3-6 is set, 0x80 comes with another bit, or
  the record is non-zero without 0x04 (ParseReply);
- the tag differs, 0x80 answers a correct request, the put bits are not 00 for a request without
  a put or 00 for a request with one, or 0x04 answers a request without F (Reply.Answers).

A bad reply does not close the circuit: the outcome of the put is unknown and the record is
dropped. The mailbox can drop everything anyway, and closing would give it one more cheap lever.

### Store

Handling one request:

1. The hash QueueID(F) is computed before any check and before the lock, on every request, for a
   zero F and for a bad request too: whether it runs does not depend on the content of the request.
2. Length not 427 or version not 1: reply 0x80.
3. Binding: a circuit (its identifier on the inbound link of the exit, unique among the live
   circuits of the node) gets its fetch queue from the first non-zero F and its put queue from the
   first non-zero put identifier. A request with another identifier in a field already set gets
   0x80 as a whole, neither put nor fetch. An honest client fetches from one queue and puts into
   one.
4. Put: the queue is full or the total record limit is reached: 10. No queue and the queue limit
   reached: the queue fetched least recently is evicted if it was not fetched within the TTL,
   otherwise 11. Then the queue is created and the record is copied with its arrival time: 01.
5. Fetch: if the queue exists, the fetch time is noted, expired records at the head are removed,
   the head is taken into the reply and 0x04 is set. A fetch never creates a queue.
6. The payload slice is zeroed and the reply is built in a new slice.

- A queue lives as long as its owner fetches. It is held while its last fetch, or its creation
  for a queue not fetched yet, is within the TTL, whether or not the circuit that did it is still
  open. Nobody evicts a held queue.
- A circuit is bound to one fetch queue and one put queue for its whole life, so it holds at most
  two. A put does not extend the hold. The cost of holding N queues depends on how long the
  circuits stay open:
  - A circuit that closes after its requests holds the queue its put created for a TTL from the
    creation and the queue it fetched for a TTL from its last fetch, after it closes as well. N
    queues take about N/2 circuit setups per TTL. Every node limits setups per source address, the
    mailbox too, where a preceding relay is one source: at 0.2 per second and a TTL of 5 min one
    source brings about 60 setups, that is about 120 held queues, and the default 1024 queues take
    about 9 sources.
  - A circuit that stays open holds its fetch queue as long as it lives: every fetch restarts the
    TTL and every request restarts the idle timeout of the circuit (-idle-timeout, 5 min; padding
    does not count), so one request per 5 min keeps both until -circuit-lifetime, 24 h. A queue
    its put created is held for a TTL from the creation and after that only by fetches. N queues
    take N open circuits with one request per TTL each, that is N setups per 24 h. At the mailbox
    every open circuit is one inbound link: at most 32 from one preceding relay and 512 in all
    (-max-links-per-source, -max-links), shared with the honest circuits.
- The binding table is bounded; when it is full, the binding seen least recently is evicted. An
  evicted honest circuit binds again to the same identifiers.
- Every 30 s the expired records, the empty queues not fetched within the TTL and the bindings
  not seen for longer than the TTL are removed.
- Removal on fetch is the acknowledgement: there is no second delivery. A node restart loses
  everything.
- A reply carries only the tag, the status and the record: no queue depth, no time, no
  identifiers.
- The array of a record is zeroed when it is fetched, when it expires, when its queue is evicted
  and when the node stops. Copies of the request remain in the cell body, in the link buffer and
  in the hash transcript on the heap, and nobody zeroes them.
- Work per request is bounded, not constant: one hash, operations on maps and lists, a copy of one
  record for a put or a fetched head, and at most -mailbox-depth removals of expired records at
  the head of the fetched queue. No request walks the queues; only the timed sweep does. The
  difference is microseconds; outside the exit it shows only when the exit forwards at once
  (-period 0).

| Limit | Flag | Default |
|---|---|---|
| TTL of a record and of a held queue | -mailbox-ttl | 5 min |
| records per queue | -mailbox-depth | 16 |
| queues | -mailbox-queues | 1024 |
| records in all | -mailbox-records | 16384, 6.1 MiB of records |
| circuit bindings | none | 4096 |

The mailbox sees both queues of every circuit, the time of each request and the outcome of each
put, so it links the two circuits of one conversation. It cannot read the records.

Counters (aggregates): mailbox_requests, mailbox_queues, mailbox_records, mailbox_bindings,
mailbox_puts, mailbox_put_full, mailbox_put_refused, mailbox_fetches, mailbox_hits,
mailbox_expired, mailbox_evicted, mailbox_bad. They appear only in /stats on loopback and only
with -exit mailbox, never in the stdout line once a minute: stdout goes to the kubelet logs on
the node's disk, and the number of queues and records would show pending messages.

### Conversation

Package conversation drives a client's conversation with one contact over a circuit that ends on
a mailbox. Package e2e runs the session (the KK handshake, the ratchet, staleness; CRYPTO, section
"End-to-end layer"), and conversation decides what to put and when. The -peer client uses it
(subsection below).

Tick:

- Every rate exactly one request while there is a circuit; no cells while it is being rebuilt.
- Every request fetches from the own queue, before the contact is pinned and after. The tag of a
  request is its number on the circuit modulo 2^16; on a new circuit the count starts from zero
  again.
- The put into the peer's queue is chosen by the first row that applies:

| Condition | Put |
|---|---|
| W requests with a put are already in flight | none |
| there is a sticky record of the current epoch | a copy of it, the same bytes |
| the session offers a handshake record (kk1 at the initiator, kk2 at the responder) | that record, which becomes sticky |
| the initiator has not yet sealed its first record after kk2 | a new record, which becomes sticky (the confirming record) |
| stall mode | a new record, which becomes sticky (the probe) |
| otherwise | a new record |

- A new record is real when there is a message and the session can seal it (the responder only
  after confirmation). Otherwise it is a dummy when cover puts (CoverPuts) are on, when the
  initiator has not yet sealed its first record after kk2, or when 30 s have passed since the
  last sealed record (keepalive). Otherwise there is no put. A stale session and a session whose
  handshake has not finished give no new record.

Window and sticky record:

- Puts are pipelined: up to W = 16 requests with a put unanswered, a new record on every tick. As
  long as W x rate exceeds the round trip of the circuit, there is a put on every tick and the
  pattern of puts does not depend on the delay.
- A refused put (10 or 11) turns stall mode on: the real body of a record that is not sticky goes
  back to its place in the outbox by the order it was sent in, a dummy that is not sticky is
  forgotten, a sticky record stays.
- In stall mode one record (the probe) is put as copies of the same bytes on every tick until
  one of the copies gets 01; then stall mode is off and the pipeline resumes. The receiver drops
  the copies by the record number.
- A handshake record is also put as copies until 01; then the session learns that the mailbox
  holds it, and from that moment the initiator waits for kk2. Copies of kk2 also stop once the
  first record of the initiator has arrived.
- The initiator's first record after kk2 (the confirming record, real or a dummy) is also put as
  copies until 01: only it lets the responder seal real messages, and without CoverPuts nothing
  else would follow it until the keepalive. In stall mode it is the probe. After 01 it is not put
  again, like any record (Rebuild).
- The outcome of a copy of a sticky record already taken off changes nothing.

Reply:

- A reply belongs to the oldest unanswered request by position, and the tag is a check; parsing
  is strict (subsection "Reply, 396 bytes").
- 01: the sticky record is taken off; a real body, of the probe, of the confirming record or of a
  record that is not sticky, counts as delivered to the mailbox and is zeroed.
- 10 and 11: stall mode; the sticky record stays and goes on being put.
- A bad reply: the outcome of the put is unknown, which is handled as 10 but without turning
  stall mode on; the circuit is not closed. A record in a reply that parsed still goes to the
  session: the mailbox has already taken it from the queue, and the session authenticates it and
  drops a repeat.
- A record in a reply is held before pinning (up to 16, the oldest pushed out) and goes to the
  session in order after pinning; after pinning it goes to the session at once.
- After pinning, a parsed reply without a record that opened is an answered fetch for the
  staleness rule; a bad reply is not.
- A message that opened goes to the caller through a queue of 256; when the queue is full it is
  dropped and counted.

Epochs:

- The epoch of the session grows with every new handshake: a restart of the initiator (no kk2
  60 s after kk1 was stored, staleness, record numbers exhausted) and the responder replacing its
  session on a fresh kk1.
- On a change of epoch the sticky record of the previous epoch is dropped, the real bodies of the
  pending requests of the previous epoch go back to the outbox at once, the outcomes of their
  puts no longer affect anything, and the handshake record of the new epoch goes first.
- A body with an unknown outcome is sent again, so a duplicate is possible; the order of messages
  is not guaranteed across refusals.

Staleness and a new handshake:

- A session goes stale after 90 s of answered fetches without a record of the peer that opened;
  the session gets it as 90 s / rate fetches, 450 at a rate of 200 ms (CRYPTO, subsection "KK
  handshake").
- An honest conversation does not go stale: with CoverPuts each side puts a record on every tick,
  without them a keepalive every 30 s.
- A gap of more than 64 records in one direction (a batch lost at the mailbox) is cleared by a new
  handshake within 2 x 90 s plus 60 s of waiting for kk2.

Rebuild:

- The end of a circuit: the far side closed it, the client refused a reply, a send failed, or the
  oldest request has waited for its reply longer than 10 s (then the driver closes the circuit
  itself).
- Unanswered requests get the outcome "unknown"; the sticky record stays.
- A record the mailbox handed out in the reply to an unanswered request is gone: the mailbox
  removes a record when it hands it out, and once a copy got 01 the sender does not put it again.
  Unless another stored copy reaches the receiver (with a round trip shorter than the rate the
  mailbox stores one), a real message is lost, a lost kk1 or kk2 costs the 60 s wait for kk2 and a
  new handshake, and without the confirming record the responder seals real messages only after
  the initiator's next record opens: with CoverPuts on the next tick, without them with the next
  message of the initiator or its keepalive 30 s after the confirming record.
- The caller's Dial builds the new circuit. For the -peer client it is the same entry, a fresh
  mirror from it, first the same chain, and new middle hops to the same mailbox only when that
  chain cannot be dialled, at most 2 times per process (section "Choice of the chain"). The
  session, the identity, the fetch capability, the pin and the outbox live for the whole
  conversation, and a rebuild leaves them alone.
- A pause of 1 s before the first attempt, and the pause doubles after each failure, up to 60 s.
  A circuit whose cell cannot carry a request is a failure.
- The conversation ends when the rebuild fails for 10 min, when three circuits ended in a reply
  refused by the client within 10 min, or when another card arrives after pinning. The circuit is
  then closed, and the session keys, the message bodies the conversation still holds and the
  records held before pinning are zeroed.
- The caller learns only the class of a circuit end: a reply refused by the client, the wait for
  a reply ran out, a failed send, or a close by the far side. No node is named.

Parameter rule:

- The round trip of a circuit of h hops, when the nodes send on their own clocks, is at most
  (2h - 1) node periods plus the network: on the testbed 5 x 190 ms = 0.95 s for 3 hops and
  1.33 s for 4; on average 2.5-2.8 periods, about 0.5 s.
- The window must cover the maximum: W x rate > (2h - 1) x node period. At W = 16 and a rate of
  200 ms that is 3.2 s.
- The reply timeout of 10 s is 7 times the maximum. Within it fewer than 256 requests are in
  flight, and that many replies fit the queue in front of the driver, so no reply is lost before
  it is matched.
- The mailbox queue depth of 16 and the ratchet window of 64 are no smaller than the honest gap of
  W + 16 = 32: refused records in flight plus records expired by the TTL.
- Without node clocks the round trip is under a millisecond and the window never fills.

| Parameter | Default |
|---|---|
| request period rate | set by the caller |
| window W | 16 |
| keepalive without CoverPuts | 30 s |
| staleness | 90 s |
| reply timeout | 10 s |
| rebuild | 1 s pause, doubling up to 60 s, at most 10 min |
| replies refused by the client | 3 within 10 min |
| outbox, records before pinning, received messages | 256, 16, 256 |

What the mailbox sees: with CoverPuts a put on every tick while fewer than W requests with a put
are in flight; without them the moment and number of real messages, the copies of the initiator's
first record after kk2 and the keepalives. The copies of a sticky record are identical bytes, so
the mailbox sees a repeat. Before pinning the requests only fetch, so the first put shows when
the contact was pinned: at once at the initiator (kk1), at the responder with kk2 once kk1 has
come.

### The -peer client

`cmd/client -peer` holds a conversation with one contact through the mailbox at the exit of its
circuits. One contact, one circuit and one queue per process.

| Flag | Default | Meaning |
|---|---|---|
| -peer | off | the conversation mode |
| -mailbox | none | the mailbox address, one of -nodes; the exit of every circuit |
| -admin | 127.0.0.1:9201 | the admin port, a loopback IP literal and a port only |
| -cover-puts | on | a put in every request, a dummy record when no message waits |
| -respond | off | answer every message of the contact with its number and text |
| -handshake-timeout | 60 s | how long the initiator waits for kk2 once the mailbox has stored kk1 |
| -rate | 200 ms | the request period |
| -interval, -count | 1 s, 1 | the period and the number of own messages; -interval 0 sends none, -count 0 without end |
| -message | | the text of own messages, at most 363 bytes |

Refused with code 2 before any network request and before the identity is made: no -mailbox or a
mailbox not among -nodes; -hops below 2; -mode other than fixed; -cover above 0; -rate below
39.22 ms (at most 255 requests, one fewer than the reply buffer of 256, may be in flight during the
10 s wait for a reply); -jitter not below -rate; -admin not a loopback IP literal; -message longer
than 363 bytes; with -fixed-chain a node at place -hops that is not the mailbox; any other error of
the flags, the node list and the anchor.

Start order:

1. The key memory policy and the dump prevention. With locked memory (-keymem all, the default)
   RLIMIT_MEMLOCK must be at least 96 KiB, or the client refuses with code 1 before any key: at its
   peak it holds about 19 locked pages (the circuit and its link about 9, the identity and F 2, a
   handshake up to 5, the ratchet up to 3). The client pods get IPC_LOCK.
2. The suite, the check of the flags, the anchor.
3. The fetch capability F, 16 random bytes drawn straight into secmem, not all zero, and the
   identity: a static agreement key from GenerateEphemeral in secmem and a card with the mailbox
   address and the queue QueueID(F).
4. Exactly one line `card_hash=<64 hex>`, before any network request. The card itself never goes
   to the log: stdout reaches the kubelet logs on the disk of the node, and whoever holds the card
   can put into the owner's queue and push out the contact's puts.
5. The first circuit to the mailbox. A refusal: the line `refusing to build the circuit: <class>`
   and code 1. Success: the line `circuit of N hops among M listed nodes to the mailbox, request
   period R`.
6. The conversation, then the admin listener and the line `admin listening on <address>`.

The contact card, binary form version 1:

```
u8 version = 1 | u8 suite | u8 address length | mailbox address | queue, 16 | static key, 32 or 64
```

- Only the canonical spelling is taken: parsing and building give the same bytes, with no tail.
  The suite equals the provider's, the address passes pki.ValidAddr, the queue is not zero.
- With the testbed address `relay-5.jimichi.svc.cluster.local:9000` a card is 89 bytes on c25519
  and 121 on GOST. The text is `<suite>:<base64 with padding>`.
- card_hash is the transcript hash of the exchange e2e/card over the card, 32 bytes, 64 hex in the
  log. There is no short fingerprint.
- `jimichi keygen-card -suite S -mailbox ADDR` prints the card of a key that is thrown away at
  once, and `jimichi card-hash <text>` prints the card_hash of a card.

The admin port (a body of at most 1 KiB, headers within 5 s):

| Request | Answer |
|---|---|
| GET /card | the text of the own card and a newline |
| PUT /contact | pins the contact's card, the body is its text |

The order of the checks of PUT /contact:

1. A body over 1 KiB: 413; not a canonical card: 400. Neither changes the state, before or after
   pinning.
2. A contact is pinned already: the same card 204; any other card that parses, including one of
   another suite or with another address, 409 and the stopped state.
3. No contact yet: the suite is the own one, the mailbox address equals the own -mailbox, the key
   and the queue are not the own ones, and the contact's key passes a trial agreement with a
   one-time pair (exchange e2e/check); otherwise 400. Then the pin in memory for the process, the
   line `contact pinned card_hash=<hash of the contact's card> role=initiator|responder` and 204.

The stopped state:

- The 409 leaves before the conversation stops. Then the conversation and the circuit are closed,
  the session keys, the identity key and F are released, and the line `contact card changed,
  refusing: pinned card_hash=<hash of the pinned card>` is logged without a byte of the new card.
- The process does not exit and answers 409 to every later request on the admin port; the
  counters line carries state=stopped.
- Only a restart by the operator ends it (scripts/introduce.sh). An exit would let the
  orchestrator restart the client with a new identity and open a new window of trust on first
  use.

Own messages:

- The body on the testbed: `u8 kind (1 message, 2 reply) | u32be number | text`.
- Once the contact is pinned the client sends a message every -interval, at most -count of them.
  After the last it goes on fetching and answering: an exit would take the identity with it.
- The first reply with the same number gives the line `e2e round trip in <time>`; repeats of a
  number are not logged. With -respond a message gets a reply of kind 2 with the same number and
  text. Neither the text nor the number reaches the log.

The log:

| Line | When |
|---|---|
| `card_hash=<hash>` | once at start |
| `circuit of N hops among M listed nodes to the mailbox, request period R` | the first circuit |
| `admin listening on <address>` | the admin port is open |
| `contact pinned card_hash=<hash> role=<role>` | the contact is pinned |
| `e2e round trip in <time>` | the reply to an own message |
| `circuit closed`, `circuit closed: <class>` | the end of a circuit: closed by the far side, a refused reply, no reply within 10 s, a failed send |
| `circuit rebuilt through the same entry` | a rebuild succeeded |
| `the chain could not be dialled again, new middle hops drawn, redraw i of 2` | new middle hops (section "Choice of the chain") |
| `circuit rebuild failed: <class>` | an attempt to rebuild failed |
| `e2e state=... requests= puts= ...` | every minute: the state (unpaired, handshaking, established, confirmed, stale, stopped) and the counters of the conversation and of the session |
| `e2e peer not reachable for <time>, pinned card_hash=<hash>` | every minute while no record of the contact has opened for more than a minute: a contact with a new identity needs a new introduction |
| `contact card changed, refusing: pinned card_hash=<hash>` | the stopped state |
| `conversation ended: <cause>` | the end of the conversation before an exit |

Card hashes appear only in the lines with card_hash. No line holds a key, a card, F, the text of a
message or a node address.

Exit codes: 0 on SIGTERM; 1 when the rebuild has failed for 10 min or on another failure; 2 when
the flags do not pass the check; 3 when three circuits within 10 min ended in a refused reply. A
changed card gives no exit.

## Circuit setup

Setup takes one control cell of the same 512 bytes, with no extra round trips.

- The client knows the addresses of the nodes and their onion keys from verified descriptors.
- For each node it generates an ephemeral pair and agrees a shared secret with that node's onion
  key. The secret is bound to the setup transcript of that hop: the format version, the hop
  index, the identifier of the link into that node, the node's onion key, the client's ephemeral
  key and, when nodes are authenticated, the node's identity key from its certificate (CRYPTO,
  section "Key derivation"). The node assembles the same transcript from the cell header, its
  onion key, the start of the layer and its own identity key, so a layer opens only at the node
  it was built for.
- Two keys are derived from the secret under the same transcript, one for the control cell and
  one for data cells, and two counter offsets, and at the node a replay tag as well.
- The binding takes no byte in the cell: a control cell carries four nodes on c25519 and three on
  GOST.
- The control cell is nested like a data cell: the layer of each node holds its ephemeral public
  key, the address of the next node, the identifier of the next link and the layer for the next
  node.
- The hop index travels in the counter field: a node must know its position before it can tell how
  much of the body belongs to its layer.
- After stripping its layer a node refills the cell to 512 bytes and forwards it.
- A node with a roster forwards the control cell only to a roster node, over a link authenticated
  with that node's link key (section "Link encryption"). A setup that names another address, or
  whose next node fails the link handshake, ends at this node, and the link it arrived on closes.
- A node remembers a tag of every control cell it opened for as long as it holds the onion key
  that opened it, and drops a copy, including after the original circuit has closed. Otherwise
  the copy would create the hop key again and the counters would restart from zero under the same
  key. The tag is derived from the shared secret under a KDF purpose of its own. A copy that
  carries another encoding of the ephemeral key (a key shifted by a point of small order, of
  which X25519 has 8 and GOST 4, or an X25519 encoding with the top bit set) does not open the
  layer: the bytes of the key are part of the transcript, and the secret comes out different.
  Only an exact copy of the layer gets the tag.
- Every onion key has a tag cache of its own, bounded by -setup-cache. A full cache refuses new
  setups under its key rather than forget tags, and under that key only: the refusal ends when
  the node publishes its next onion key. A control cell on a link that already carries a circuit
  is dropped before the key agreement and takes no tag.
- The cache protects only because the tags and the onion key go together: a released key takes
  its tags with it, and a restart clears both. The onion key therefore lives only in process
  memory, and the node writes it to no file. Memory locking covers its secmem buffer only: the
  copies the libraries leave on the Go heap (CRYPTO, known gaps) can be paged out to disk on a
  host with swap. Locking all process memory is planned
  ([#36](https://github.com/jimichi-org/jimichi/issues/36)). The node signing key only signs the
  descriptor that carries it and takes no part in the layer agreement itself.

An empty next address marks the exit node. The exit has no next link, so the field for its
identifier in the exit's layer carries the counter of the first forward cell, and the setup cell
does not grow.

Onion key epochs:

- With -onion-rotate (1 h by default and on the testbed) a node opens setup layers with an onion
  key of its own, separate from the link key, and replaces it every period: it generates a new
  pair in a secmem buffer, raises the epoch by one and signs a descriptor with the new key at
  once, without waiting for the signing timer. The link key stays the same for the life of the
  process.
- The replaced key is held for a grace period after the rotation: the descriptor lifetime plus
  the clock allowance (-descriptor-ttl + Skew, 22 min on the testbed). By then every descriptor
  that names it has expired, also for a verifier whose clock is behind by the allowance and in
  the mirror of a node that could not fetch again. The key is then released, its buffer is zeroed
  and its tags are forgotten. Apart from the copies the libraries left on the heap (LIMITATIONS;
  CRYPTO, known gaps), a setup cell recorded for it no longer opens with anything the node holds.
- A node holds at most two onion keys, and a rotation waits until the replaced key is released.
  The time between rotations is therefore -onion-rotate, or the grace period when that is
  longer: 1 h on the testbed, 1 h 2 min with the default descriptor lifetime of 1 h.
  -onion-rotate must not be shorter than -descriptor-ttl.
- While two keys are held the node tries both on every setup, in one order and to the end: two
  agreements and two attempts to open the layer whichever key the client used, so the time a
  setup takes does not show the epoch. At most one key opens the layer, and the tag goes into the
  cache of that key.
- No key is released while a setup is being opened: the release waits for it.
- The node reads its clocks once a second and takes the moment of a rotation and of a release
  twice: by the wall clock and by the running time of the host (the monotonic clock). It acts as
  soon as either says the moment has come. The running time stands still while the host sleeps,
  so after a sleep the first reading releases a key whose grace has ended by the wall clock and
  then rotates once. A wall clock set back postpones neither moment: the running time still
  brings it. A wall clock set forwards brings both early, which costs clients a refused setup and
  no secrecy. A descriptor is always signed for the key that is current at that moment.
- The published time of a descriptor never decreases within a process: Identity.Refresh takes
  published = max(now, the previous published, the floor) and expires = min(published + ttl,
  not_after). With correct clocks this changes nothing. After a wall clock set back the node's own
  /descriptors waits for its clock to reach published, as it does today, at most until the
  published of the rotation.
- The first descriptor of an epoch is published no earlier than Skew after the expiry of the last
  descriptor of the epoch before the replaced one: a rotation to e+2 that succeeds floors published
  at expires(e) + Skew. With correct clocks the release of key e comes by the wall clock ttl + Skew
  after the rotation to e+1, the floor lies below now, and nothing changes; the floor acts when the
  release came by running time or the clock was set back (section "Descriptor consistency").
- A rotation that fails, because there is no memory for the new key, its page cannot be
  locked or its key pair check (CRYPTO) does not pass, leaves the published key in place. The
  node tries again every second and counts the attempts (onion_rotate_failed). Between rotations
  it holds four key pages when memory allows and gives them back right before the next key is
  made, so that the key and its pair check find room when locked memory is used up. It takes them
  after each rotation and, if there was no room then, again once the replaced key is released.
- A circuit that is already built does not notice a rotation: its cell keys come from its setup
  and live until the circuit is torn down.
- -onion-rotate 0 is the measurement baseline: the link key opens the setup layers as well, for
  the life of the process, under epoch 0, and the node prints one WARNING line at start. The lab
  harness runs its nodes this way.
- Without node authentication a descriptor carries no lifetime. After a rotation the node serves
  an unsigned bundle with the new key and epoch, the other nodes fetch it again within a minute,
  and the replaced key is held for the same grace period.

Circuit teardown:

- A circuit is bound to the link its control cell arrived on. A cell with the same identifier on
  another link is dropped, and so is a second control cell with an identifier already in use.
- Closing a link anywhere closes the neighbouring links of the circuit in both directions, so the
  break reaches the client and the exit node.
- A node closes a circuit itself when a cell arrives out of turn, a cell of another kind or one
  it cannot wrap comes back, a cell finds no room in its queue, a cell cannot be written to either
  neighbour, or the exit cannot seal a reply. The close takes the same path as a closed link and
  is counted with the closed circuits.
- A link that has opened no circuit by the setup deadline after its handshake is closed.
- A frame that cannot be written within the write deadline is such a failed write: the peer has
  stopped reading, and a node sending on its own clock would otherwise wait for it. It is counted
  with the closed circuits and with the expired deadlines.
- A circuit that carries no cell in either direction for the idle timeout, or that reaches its
  lifetime, is torn down by closing its inbound link and counted with the expired circuits, not
  with the closed ones. Link padding does not count as traffic.
- Circuit keys are released once every goroutine using them has stopped.
- The client sees the break as its reply channel closing and exits. The orchestrator restarts
  it, and it draws a new chain. Whichever side ended the link, the client closes its own
  connection, and no cell is sealed once the end is on record: in either mode Send returns
  client.ErrCircuitClosed and queues nothing, and the constant-rate schedule stops. A send that
  was already sealing its cell finishes and fails on the closed link. After the caller's own
  Close, Send returns its own closed error instead.
- When the client closed the circuit itself over a reply or a frame, it exits with code 3 and the
  line `circuit closed: client: reply refused: <check>`, the check being one of five:
  `bad header`, `did not open`, `out of turn`, `more replies than cells written`, and
  `link: frame did not open` for a frame on the link from the entry that does not open under the
  link keys, whether it carried a reply or link padding. Anyone on the wire between the client and
  the entry can produce such a frame, so it does not implicate the entry and must not be counted
  against it. That line names neither a node nor a cell number. Any other break gives code 1 and
  the line `circuit closed`, or `send:` with the cause. Code 1 does not mean the path was honest:
  a copy, a gap or a reorder made by a node past the entry closes the circuit at the node before
  it, provided that node has already taken a backward cell, a damaged frame towards the entry or
  between nodes closes that link, and a node can simply close the connection.
  Before its first backward cell a node has nothing to compare with: every node on the way back
  takes the first backward counter as it comes, so when a node past the entry skips the first
  replies, the later reply passes every node and only the client refuses it, as `out of turn`,
  with code 3.

## Node limits

Every limit in the table below is a node parameter with a default, except the fixed 5 s towards
the next hop. A negative value turns a limit off, so its cost can be measured on its own, with two
exceptions: a burst cannot be negative and is refused at start (the rate is what turns that limit
off), and the per-address handshake cap stays on, at 4, when the shared cap is off, unless it is
set to -1 itself.

| Limit | Default | Why |
|---|---|---|
| handshake deadline, -handshake-timeout | 2 s | an initiator sends its hello at once, so a silent peer holds a slot only briefly |
| dial and handshake towards the next hop | 5 s, fixed | a silent next hop holds neither the setup nor the node shutdown |
| setup deadline, -setup-timeout | 10 s | the client and the previous node send the control cell right after the handshake |
| write deadline, -write-timeout | 4 periods and at least 1 s; 5 s without own-clock sending | a peer that stops reading does not stall the sender |
| idle circuit, -idle-timeout | 5 min | an abandoned circuit stops sending padding; the testbed client sends every 200 ms |
| circuit lifetime, -circuit-lifetime | 24 h | bounds how long one set of circuit keys lives |
| concurrent handshakes, -max-handshakes | 32 | more would only queue for the CPU |
| concurrent handshakes from one address, -max-handshakes-per-source | an eighth of -max-handshakes and at least 1, so 4; also 4 when -max-handshakes is off | one address cannot hold every handshake slot |
| open inbound links, -max-links | 512 | the memory of their circuits stays inside a 128 MiB pod |
| links from one address, -max-links-per-source | 32 | one peer cannot take every slot; a preceding relay is one address for every circuit it forwards. The client holds one circuit, one per contact is planned ([#96](https://github.com/jimichi-org/jimichi/issues/96)) |
| new links from one address, -source-link-rate, -source-link-burst | 10 per second, bursts of up to 50 | every link costs a key pair and an agreement |
| setups from one address, -source-setup-rate, -source-setup-burst | 0.2 per second, bursts of up to 10 | every setup costs an agreement with each onion key the node holds, a dial onwards and a tag kept as long as its key |

- A connection is admitted or refused when it is accepted, before any key agreement. A control
  cell is checked after the link handshake and before the agreement with the onion keys. A
  refused connection is closed without an answer.
- A full tag cache (-setup-cache) refuses setups only under the onion key it belongs to. With
  rotation the refusal ends when the next key is published, at most the time between rotations
  later (-onion-rotate, or the grace period when that is longer), provided the rotation succeeds;
  without rotation it ends at a restart.
- Every connection costs its address a token of the link rate, admitted or refused, and the limits
  of one address are checked before the shared ones: retrying against a full node spends the
  address's own allowance and leaves the shared slots to others.
- Any node can be an entry, so every node of the testbed keeps the per-address limits at their
  defaults. A node that forwards for many clients is one address at the next node, and the
  circuits it forwards share one address's allowance there (LIMITATIONS). A network policy
  (deploy/base/network.yaml) lets the pods of clients and of relays reach the cell port of every
  relay and no other pod; the info port stays open to the namespace.
- One address is an IPv4 address or an IPv6 /64 prefix. The table of addresses lives only in
  memory, holds at most 16384 of them and forgets an address once it has no open links and its
  buckets have refilled. A new address past the bound is refused and counted with the per-address
  refusals, known addresses are still served.
- Every control cell spends a setup token before it is opened, so an address whose links have
  closed stays in the table until its setup bucket refills: up to 50 s at the default rate and
  burst.
- Refusals and expired deadlines are added to the aggregated counters, without addresses or
  identifiers.
- A temporary accept error, such as running out of file descriptors, is retried with a pause from
  5 ms doubling up to 1 s. If accepting stops for good, the node exits with an error and the
  orchestrator restarts it; the health check reports ready only while the node accepts.

## Node authentication

The client takes node keys only from a bundle verified against the trust anchor, and a node takes
the link key of the next node only from such a bundle. The pki package implements the chain of
trust from the CA key to the node keys, certificate issuance and verification; cmd/relay,
cmd/client and cmd/jimichi use it. The client's check of the mirror bundles and a node's check of a
peer bundle run over pki in internal/verify, shared by cmd/client and cmd/relay. The CA key only
signs certificates and takes no part in the layer agreement.

### Chain of trust

| Link | What it binds | Signed by |
|---|---|---|
| Trust anchor | the CA public key as the string `<suite>:<base64>`; ca_id is the first 8 bytes of Hash(key) | nothing, it reaches the client as configuration (ConfigMap jimichi-ca) |
| Node certificate | suite, serial number, ca_id, validity, name, address, node signing key | the CA key |
| Node descriptor | certificate hash, link key, onion key, epoch, validity | the node signing key |
| Certificate request | a nonce chosen by the CA, name, address, node signing key | the node signing key |

- The address in the certificate is exactly the host:port the client dials or writes as the next
  node's address.
- The onion key goes into circuit setup, the link key into the link that leads to the node: from
  the client to the entry, from a node to the next node. With -onion-rotate the onion key is a
  pair of its own that changes by epochs while the link key stays (section "Circuit setup",
  onion key epochs). With -onion-rotate 0 a node publishes one agreement key in both fields.
- The node signing key the certificate certifies is the identity of the node: it goes into the
  setup transcript of the node and into the transcript of every authenticated link to it, on
  both sides (CRYPTO, section "Transcript"). A node with -auth binds it from its start; before
  its certificate it serves no descriptor and extends no circuit.
- The request is used only for issuance and is never shown to clients. It proves possession of the
  signing key, and the nonce chosen by the CA proves freshness. Request.Check accepts a request
  only if the nonce matches and the name and address match the operator roster.
- Identity.Install installs a certificate only if the signing key, suite, name, address and
  validity all match. The node does not check the CA signature: it has no anchor. Whoever issues
  the certificate must therefore verify the node's bundle against the anchor after the install,
  as pki.Verify does for a client; jimichi enroll does exactly that.
- The CA key and the node signing key are generated through the CryptoProvider straight into
  secmem buffers. Close releases them; callers defer it.

### Formats

The formats are binary: big-endian integers, variable-length fields with a one-byte length prefix
and a hard maximum, times in unix seconds (int64). The signature is the last field. What is signed
is the domain string followed by the body without the signature; the domain string itself is not
transmitted.

| Object | Body | Domain string |
|---|---|---|
| Certificate v1 | version 1, suite, serial 16, ca_id 8, not_before, not_after, name, address, signing key | `jimichi/cert/v1\x00` |
| Descriptor v1 | version 1, suite, epoch u32, published, expires, cert_hash 32, link key, onion key | `jimichi/descriptor/v1\x00` |
| Request v1 | version 1, suite, nonce 16, name, address, signing key | `jimichi/csr/v1\x00` |

- Name: 1 to 32 characters from `a-z`, `0-9` and `-`.
- Address: 1 to 64 bytes (the size of the address field in a control cell), printable ASCII
  0x21..0x7e only, parsed as host:port with a non-empty host; the port is decimal, with no sign or
  leading zero, from 1 to 65535. wire drops trailing NULs from an address, so an address with a
  NUL, a space or a byte outside ASCII could name one node and lead to another. Host and port
  have one spelling each (host names in lower case without a trailing dot, IP literals in
  canonical form, an IPv4 address only as IPv4 and not as ::ffff:a.b.c.d) because Verify compares
  addresses byte for byte. A host is an IP literal without a zone or DNS labels of a-z, 0-9 and the
  hyphen joined by dots, no label empty or starting or ending with a hyphen, the last label neither
  all digits nor starting with 0x (some resolvers read such a name as an address): an address
  carries nothing a URL would read as a path, a query, user information or another port.
- Keys and signatures are at most 128 bytes. cert_hash is the Hash of the whole certificate,
  signature included.
- Parsing rejects an unknown version (ErrVersion), an unknown suite (ErrSuite), a field over its
  maximum, trailing bytes and any input that does not re-encode to itself (ErrFormat). Every object
  has one canonical encoding. A suite other than the provider's is rejected right after parsing
  (ErrSuite).
- The node bundle for clients: JSON
  `{"v":1,"suite":"c25519","cert":"<base64>","descriptor":"<base64>"}`. Parsing accepts only the
  spelling Bundle.Marshal writes: lower-case keys in this order, no spaces, repeats, omissions or
  trailing data, base64 in its canonical form. The suite and the descriptor are not empty.
- The unsigned bundle (pki.Unsigned) is what a node started with -auth=false serves: an empty
  certificate, a zero cert_hash, an empty signature. An empty certificate is allowed only there,
  and Verify rejects such a bundle (ErrFormat).
- The roster a node receives after its certificate: JSON
  `{"anchor":"<suite>:<base64>","nodes":[{"name":"<name>","addr":"<host:port>"},...]}`. Parsing
  accepts only the spelling Roster.Marshal writes, at most 4 KiB (pki.MaxRoster); names and
  addresses are well formed, and the names and the hosts of the addresses are pairwise distinct
  (ErrFormat, ErrDuplicate). A node fetches every peer from the host of its address on the one
  -peer-info-port, so a second address on a host would reach the node of the first, and on the
  node's own host its own info port. Hosts are compared in their one spelling, and an IPv4 address
  has no IPv6 spelling, but one host under two names, or under a name and an IP address, is not
  caught.
- The descriptor mirror: JSON `[{"addr":"<host:port>","bundle":{...}},...]`, sorted strictly by
  address, every bundle in its own canonical spelling; parsing accepts only that. An item carries
  either `bundle` or `proof`: `{"addr":...,"proof":[lo,hi]}` is a proof of the node's
  inconsistency, two of its bundles, the first bytewise smaller than the second (section
  "Descriptor consistency"). Parsing rejects an item with both keys or with neither, a proof of
  other than two elements, an element that fails bundle parsing, equal or reversed elements,
  addresses out of order and any input that does not re-encode byte for byte (ErrFormat), and a
  repeated address (ErrDuplicate). A mirror without proofs encodes exactly as before. The mirror
  carries no signature of its own: each bundle in it is verified like any other, and a proof is
  verified by every reader under its own anchor, so an entry cannot forge one.
- The roster limit bounds the number of nodes: 4 KiB hold 58 nodes with names and addresses of
  the testbed form (relay-N, relay-N.jimichi.svc.cluster.local:9000) on c25519 and 57 on GOST.
  The mirror of five nodes takes about 3 KiB on c25519 and 3.6 KiB on GOST, the mirror of the
  largest roster about 35 and 41 KiB, against the 256 KiB a client accepts.

Validity:

- The clock skew allowance Skew = 2 min applies to lower bounds only (not_before, published), so no
  window is ever extended past its end.
- A certificate whose not_after is not after its not_before is rejected (ErrCertTime), as it is at
  issuance.
- A descriptor expires no later than its certificate (expires <= not_after) and lives at most 24 h.
- Identity.Refresh signs a new descriptor with published = max(now, the previous published, the
  floor) and expires = min(published + ttl, not_after) (section "Circuit setup", onion key
  epochs). Without a certificate it returns ErrNoCert, and after not_after it withdraws the bundle.
- The verification policy (pki.Policy) may set a lower bound MinLife on the lifetime: a descriptor
  that lives less is rejected (ErrDescLife) unless the certificate cut it (expires == not_after).
  A node and a client with -consistency set MinLife = pki.MinDescriptorLife, 16 min, the same as
  the least -descriptor-ttl, so an honest node never fails the bound.

### Verification order

pki.Verify checks a node bundle against the anchor, the address being dialled and the current time.
The first failure stops the check; every check after parsing has its own error:

1. the anchor suite, bundle parsing, its version and suite (ErrFormat, ErrVersion, ErrSuite): the
   suite is settled before any key is parsed as a curve point;
2. certificate parsing (ErrFormat, ErrVersion, ErrSuite);
3. ca_id (ErrUnknownCA) and the CA signature (ErrCertSignature);
4. certificate validity (ErrCertTime);
5. the certificate address equals the dialled address byte for byte (ErrWrongAddr);
6. descriptor parsing and cert_hash (ErrFormat, ErrVersion, ErrSuite, ErrCertMismatch);
7. the node signing key's signature (ErrDescSignature);
8. descriptor validity, expires <= not_after, lifetime at most 24 h (ErrDescTime);
9. the link and onion keys have the length of the suite's agreement key (ErrKeySize).

- The client, and a node for the descriptor of a peer, call pki.Verify for every bundle on its
  own.
- pki.VerifyStatement makes the same check without the clock: the anchor, both signatures,
  cert_hash, the address, the suite, not_after > not_before, expires > published, expires <=
  not_after, a lifetime at most MaxLife and at least MinLife unless cut, the key sizes. The
  certificate and descriptor windows against now are not checked, so an expired pair still
  proves. Verify and VerifyStatement are one function with a flag for the clock checks, and the
  error order of Verify stays.
- pki.Compare applies the consistency rules C0..C6 to two statements of one address (section
  "Descriptor consistency"): 0 when they are consistent, otherwise the first broken rule in the
  order identity, certificate hash, link key, then within one epoch the onion key, across epochs
  an equal onion key, then, with lo the smaller epoch, published(hi) < published(lo) and, with
  the epochs at least 2 apart, published(hi) < expires(lo) + Skew. Compare is symmetric, and Skew
  in it is the constant pki.Skew. The texts of the seven rules: `two identities at one address`,
  `two certificates for one identity`, `two link keys`, `two onion keys in one epoch`, `one onion
  key in two epochs`, `an older epoch published after a newer one`, `epochs two apart overlap`.
- pki.VerifyConflict checks both bundles of a proof with VerifyStatement at the node's address and
  returns the inconsistency Compare finds: ErrNoConflict (`pki: not a proof of inconsistency`)
  when there is none, otherwise the pki error of the first bundle that fails. Every reader of a
  proof makes this check. A refused node shows as ErrConflict (`pki: the node signed descriptors
  that contradict each other`) with the text of the rule.
- pki.VerifyChain runs this check for every node of the roster at enroll and requires addresses,
  signing keys and onion keys to be pairwise distinct (ErrDuplicate): the operator sees both
  names and can correct the roster.
- pki.Unverified reads one bundle checking only format, suite and key length, with no
  signatures, validity or addresses, and gives no identity. It is the configuration without node
  authentication, kept so that what the measure is worth can be measured; no experiment block
  makes that measurement.
- Request.Check at issuance checks the suite (ErrSuite), the nonce (ErrNonce), the name and
  address against the roster (ErrRoster) and the request signature (ErrRequestSignature).

### Client check

- Before any network request: with -auth (the default) an empty -ca is fatal, and the anchor
  suite must equal -suite.
- The client requests /descriptors from its entry, the node it drew first (with -fixed-chain the
  first node of -nodes), and from no other node: a 5 s timeout per request and a 256 KiB limit,
  up to 30 attempts 1 s apart, repeated only on a connection error or a 503 answer; decoding is
  strict. A request that fails stops the client with
  `refusing to build the circuit: the entry: <class>`, with -fixed-chain with
  `refusing to build the circuit: node <address>: <error>`.
- pki.Verify checks the bundle of every listed node the entry served on its own, in the listed
  order, whether the chain will hold the node or not. A bundle that fails the check counts as
  missing. A mirror without the entry's own bundle stops the client with
  `refusing to build the circuit: the entry: the entry holds no bundle for it`, an entry bundle
  that fails the check with `refusing to build the circuit: the entry: <class>`, more missing and
  failing listed nodes than -missing allows with `refusing to build the circuit:` and then
  `too many listed nodes left out by the entry or not passing the check: <k> of <N> listed nodes, at most <m> may be`,
  and with -fixed-chain a node of the chain whose bundle is missing or fails with
  `refusing to build the circuit: node <address>: <reason>`.
  There is no fallback to unverified keys, and with a drawn chain a list is partial only within
  -missing (section "Roster, peer descriptors and the mirror"). On success it logs one line per
  verified node: the name, the signing key fingerprint and the certificate validity, with
  -fixed-chain the descriptor validity as well (with a drawn chain it stays out: the entry's own
  descriptor is the freshest in its mirror and would point at the entry), and one line with the
  number of verified and of listed nodes.
- A mirror item may be a proof of a node's inconsistency (section "Descriptor consistency"). With
  -consistency (the default) the client verifies it itself under its own -ca (pki.VerifyConflict)
  and refuses the node: it joins no chain and is counted apart from -missing: the list is one
  node shorter, and the missing and failing nodes count against -missing among the rest
  (client.JudgeMirrorAmong); a draw never numbers a refused node. A proof that holds no
  contradiction or does not verify is a node the entry left out, within -missing. A proof about
  the entry itself refuses the circuit, as a missing entry bundle does; a proof about the mailbox
  gives a -peer client the same refusal `the entry holds no bundle for the mailbox`. With a
  refusal the line on verified nodes becomes `<n> of <N> listed nodes verified, <k> refused by
  proof`, with no address; with -fixed-chain a refused node of the chain stops the client with
  `refusing to build the circuit: node <address>: pki: the node signed descriptors that
  contradict each other: <rule>`. With -consistency=false a proof item is a node the entry left
  out, within -missing, and there is no lower bound on the descriptor lifetime.
- A -peer client differs: it logs no line per listed node, it logs refusals by class only, and a
  failure on a rebuild does not stop it (section "Choice of the chain").
- The onion key from the descriptor goes into circuit setup, the entry node's link key into
  link.Dial, and the identity key from the certificate of every node into both transcripts of
  that node. client.Dial refuses a node with an empty key or a key of the wrong size: an empty
  link key would make the link to the entry anonymous.
- With -auth=false the client takes the bundles from its entry in the same way, reads them
  through pki.Unverified and logs one WARNING line. The unverified keys of every hop then come
  from the entry alone: whoever answers for the entry chooses them. A node run with -auth=false
  serves an unsigned bundle (pki.Unsigned). Neither side has an identity, and the transcripts go
  without one; a client with -auth=false and a node with -auth agree on no key (CRYPTO, section
  "Transcript"). This is the configuration without the measure; no experiment block compares it
  with the authenticated one.

### Certificate issuance

Certificates are issued by `jimichi enroll` (cmd/jimichi) outside the cluster: on the operator's
machine or the CI runner. scripts/enroll.sh runs it for every relay of the testbed, which it
finds by the label of their deployments (app=relay).

1. The operator passes a roster: for each node the name and address for its certificate, two
   local addresses that reach the node's admin port and descriptor port, and the hash of the
   node signing key. The node prints this hash once at start, before any port serves
   (identity_hash=). scripts/enroll.sh reads it from the log of the pod's current container
   through the kube API (kubectl logs) and requires exactly one such line. Names, addresses, local
   addresses and hashes must be well formed and pairwise distinct, and so must the hosts of the
   addresses, since a node refuses a roster that names a host twice.
2. The process sets the secmem policy (-keymem, -harden). If memory locking was requested and
   does not work, issuance does not start.
3. Each node gets POST /csr with a fresh 16-byte nonce and answers with a request signed by its
   signing key. Request.Check matches the nonce, name and address against the roster, the key
   hash in the request must equal the hash from the log, and the signing keys of the nodes must
   be pairwise distinct. A node that has already taken a certificate, valid or expired, answers
   POST /csr with 409, and enroll prints the command that restarts it.
4. Only when every request has passed and the roster of the run fits the 4 KiB a node accepts
   (pki.MaxRoster) is the CA key created in a secmem buffer. The CA issues every certificate
   and its key is released at once (Close): it lives for the issuance only.
5. Each certificate goes to its node with PUT /cert. The node accepts a certificate only if it
   has taken none before, within 60 s of POST /csr (pki.InstallWindow), once per request and only
   with a not_before no earlier than the request time minus Skew; otherwise it answers 409 with
   the error class. It then installs the certificate, signs a descriptor and answers 204, or 400
   if the install is refused. Sending the installed certificate again while it is valid gets 204,
   so a retry after a lost answer goes through.
6. enroll reads /descriptor of every node and checks the whole chain with pki.VerifyChain against
   the new anchor, exactly as a client does.
7. enroll sends every node the roster with PUT /roster: the anchor and the name and address of
   every node of this run, the same bytes to each (section "Roster, peer descriptors and the
   mirror").
8. Only when every node has accepted the roster is the anchor printed on stdout. On any error
   stdout stays empty and the exit code is 1.

- A certificate is installed once per node process: an installed certificate is never replaced, not
  even an expired one, and re-enrollment needs a node restart, which brings a new identity. Install
  does not check the CA signature, so without this rule anyone who reaches the admin port could
  replace a working certificate with their own.
- Installation across the nodes is not atomic. If issuance fails after the first PUT /cert, the
  nodes that already took a certificate keep it under a discarded CA until they restart, and
  clients refuse them. enroll lists those nodes on stderr, together with the nodes whose answer
  was lost or a 5xx (may hold), and prints the `kubectl rollout restart` command for them;
  enroll.sh prints the same guidance. A roster that fails on some node is reported the same way:
  the nodes that hold or may hold a roster of the discarded CA are listed with their restart
  command. Issuance runs again after the restart.
- enroll's -timeout is at most 60 s, so the whole run fits the window in which a node waits for
  its certificate.
- The request, the certificate and the roster travel over `kubectl port-forward` to one specific
  pod, to the node's admin port 127.0.0.1:9101, the same one that serves the counters. The kube
  API lets the operator reach the pod and its log by kubeconfig and the pods/portforward and
  pods/log rights. A port-forward reaches whatever process listens on the pod's loopback, so the
  request is tied to the node by the key hash from the container log: a request under another
  key is refused and no certificate is issued. With -auth a node refuses to start unless the
  -stats address is a loopback IP. Request bodies on that port are capped at 4 KiB.
- The anchor goes into ConfigMap jimichi-ca (key anchor), from there into the JIMICHI_CA variable
  and the client's -ca flag. After a new issuance enroll.sh restarts the client.
- A Windows host has no mlock and no prctl: enroll.sh passes `-keymem zero -harden=false`, and
  enroll warns that the CA key stays in unlocked memory while it issues. The locked path runs in
  Linux: WSL2 and CI.
- `jimichi keygen-ca` prints the anchor of a key that is thrown away at once. e2e uses it to check
  that a client holding a foreign anchor refuses to build the circuit.

### Roster, peer descriptors and the mirror

- A node takes one roster per process: only after its certificate, within 60 s of installing it
  (pki.InstallWindow), and only on the admin port. A roster that does not list the node's own
  name and address is refused (400), and so is a roster under whose anchor the node's own served
  bundle does not verify (pki.Verify at its own address): the roster names the anchor of the CA
  that certified the node. Its node list is not authenticated; it only narrows the set of nodes
  that CA certified, since a peer counts only with a descriptor verified under that anchor. A
  roster before the certificate, after the window, after another roster or while the node
  serves no valid descriptor gets 409. The same bytes again get 204, so a retry after a lost
  answer goes through.
- With the roster the node keeps the descriptors of its peers: it fetches /descriptor from the
  info port of every other roster node (the host of the roster address, the port from
  -peer-info-port, 9100 by default) with a 5 s timeout, a 16 KiB limit on the body and 4 KiB on
  the status line and headers, no redirects and strict decoding, and checks the bundle with
  pki.Verify against the roster's anchor and the roster address. The cache holds public data and
  lives in memory only.
- The node fetches an entry again once its wall-clock age reaches half of its descriptor's
  lifetime: from then on the entry is due. Its timer sleeps until the nearest such moment, at
  most 1 min and at least 5 s. A pass asks every peer that is missing or due, except one paused
  after its certificate has expired (below), and no other, one after another, each with one request
  under the 5 s timeout, and while such a peer is left the next pass starts 5 s after this one
  ends. A due entry stays due until a fetch brings a descriptor signed later, so with a 5 s pause
  between passes the node keeps asking a peer that does not answer, a peer whose bundle does not
  verify and a peer that still serves the descriptor it has not signed again. The last is routine:
  it starts at the middle of the descriptor's lifetime and ends with the first pass after that peer
  has signed its descriptor again. The peer's timer does that within one period, min(ttl/4, 1 min),
  when the wall clocks of the two nodes agree, and a rotation of its onion key does it at once,
  whichever comes first (section "Key lifetime and revocation"). A descriptor whose expires is cut
  to the certificate's not_after is not due before it expires: the peer signs no descriptor that
  ends later, and it holds a replaced onion key until every descriptor naming it has expired, so
  the held one serves to its end. Once the certificate has expired the peer answers 503; when the
  fetch of a peer whose entry ended with its certificate fails, the peer is asked again after
  1 min instead of the 5 s pause, and so on while it fails: a node takes one certificate per
  process and enroll discards the CA key, so no new bundle of that peer is expected to verify
  under the roster's anchor. An entry ends at the expires of its descriptor. A bundle that cannot
  be fetched or does not verify is not taken, and the entry held so far stays until it expires. The
  log gets one line per kind of cause: no answer, the status code or the check that failed, and
  nothing the peer sent. No request and no circuit setup triggers a fetch.
- A circuit is extended from this cache alone: the next address must be a roster node with a
  valid entry, and the link to it is authenticated with the link key of that entry. A node with
  -auth extends nowhere until its roster arrives.
- GET /descriptors on the info port is the mirror: the node's own bundle and the cached
  bundles of its roster peers. It is encoded when the roster is installed, when the cache is
  refreshed and when the node signs its own descriptor. A request copies ready bytes; only the
  first request after a bundle has left the mirror or may join it encodes it again. The answer
  is 503 while the node has no roster or no descriptor of its own in service, and before its
  own bundle may be listed (below).
- A client checks the bundles on its own clock, which it reads once the mirror has arrived,
  after any retries, so the mirror lists a bundle only while a clock that differs from the
  node's within the allowance finds it valid on arrival: from the later of the descriptor's
  published time and the certificate's not_before, on the node's clock, until 2 min 6 s before
  its expires, whatever lifetime the peer signed it for. The margin is Skew, 2 min, plus the
  5 s a request may take, plus 1 s because the node compares whole seconds. A peer whose
  bundle the node does not hold, or holds outside that window, is left out of the mirror and
  counts as one of the nodes the client's -missing allows; the entry in the cache and the
  extension of circuits to that peer still last until expires. A fetched bundle that the
  mirror cannot hold yet does not displace one it holds, and the peer is asked again after the
  5 s pause.
- The node's own bundle starts the same way: a certificate may begin up to Skew after the
  node's clock, and until that clock reaches the later of published and not_before,
  /descriptors answers 503. /descriptor serves the bundle as soon as it is signed: a peer lists
  it in its mirror only from that start, and enroll checks it on the clock that set not_before.
- -descriptor-ttl is at least 16 min and at most 24 h, so a peer that signs again on time stays
  in the mirror while its clock is within Skew of the node's: its next descriptor is signed
  before the age of the held one reaches ttl/2 + 1 min and is taken on the first pass once it
  is signed and its published time has come on the node's clock (unless the held one is cut to
  not_after: that one is kept until it expires and is not replaced by a later one), while the held
  one stays in the mirror until its age reaches ttl - 2 min 6 s. With the peer's clock up to 2 min
  behind, that leaves ttl/2 - 1 min - Skew - 2 min 6 s for the 5 s pause and one pass over the
  peers: 2 min 54 s with the shortest lifetime and 4 min 54 s with the testbed's 20 min. A
  descriptor cut to the certificate's not_after leaves the mirrors of the peers 2 min 6 s before
  not_after; the node itself serves its descriptor and its own mirror, and takes circuits,
  until not_after.
- The client (-missing, 1 by default, at most the listed nodes beyond -hops) accepts a mirror that
  holds a verified bundle of the entry itself and verified bundles of all but that many listed
  nodes, verifies every bundle on its own, and draws the other hops among the nodes whose bundles
  passed. A bundle that is listed and fails the check counts as missing. A fixed chain needs
  verified bundles of its own nodes.
- A cached bundle may name an onion key its node has already replaced. The node holds that key
  until the bundle has expired (section "Circuit setup", onion key epochs), so a client that
  takes the bundle from the mirror still builds its circuit.
- The mirror makes the entry the only node a client contacts. The client trusts the entry with
  nothing: it verifies every bundle against its own anchor, so the entry can withhold bundles,
  and an altered bundle is as good as withheld.
- A node run with -auth=false takes no roster. It lists itself in /descriptors under -advertise
  together with the unsigned bundles of the nodes named in -peers, read without verification,
  and extends circuits to any address. -advertise and -peers name pairwise distinct hosts, as a
  roster does. The node keeps those bundles by passes of the same kind: an unsigned bundle
  carries no times, so an entry is due one minute after the pass that took it. A peer that is
  missing, does not answer or serves no well-formed bundle of the node's suite is asked again
  after the same 5 s pause, and the entry held so far stays, since these entries never expire:
  a peer that went away stays in the mirror with its last bundle. Without -advertise the node
  answers /descriptors with 503 and names the two flags.
- scripts/e2e.sh checks that a client asks its entry alone. It waits until two passes in a row
  show every relay with all its roster peers and unchanged counts of descriptor_requests, then
  runs the clients. Between two readings of the counters mirror_requests must have grown at one
  relay per start of a client, first client-a and client-b (their rebuilds go through the same
  entry and add nothing, and at relay-5, their mailbox, it does not grow at all) and then the
  client with the foreign anchor, and at no other relay; descriptor_requests of every relay must
  be what it was before the clients.

### Descriptor consistency

Nodes publish their descriptors themselves and there is no directory, so without a check a node
could serve each peer a validly signed onion key of its own: the key that opens a setup cell would
then name the mirror the client used, that is the entry. With -consistency (the default) nodes
therefore check each other's descriptors for consistency: every node reads the mirrors of other
roster nodes, compares every statement of every node with the others and refuses a node two of
whose descriptors break a rule. Such a pair is a proof that anyone holding the anchor verifies.

| Term | Meaning |
|---|---|
| node | one identity under one anchor at one roster address: a certificate binds the identity to a name and address, a process takes one certificate, and a restart is a new identity and a new enrollment of everything |
| statement of a node | a bundle whose certificate verifies under the anchor at that address and whose descriptor the identity signed, whatever its time window: the window says when a client may use it, the signature says the node said it |
| inconsistency | two statements of one address under one anchor that break a rule; the proof is self-contained: anyone with the anchor verifies both signatures and reads two descriptors |

The rules. a and b are two statements of one address under one anchor with the fields identity,
cert_hash, epoch, published, expires, link, onion. The rules are symmetric; C7 is about one
statement. Skew is pki.Skew, 2 min, a protocol constant.

| Rule | Statement | Why an honest node never breaks it |
|---|---|---|
| C0 one identity | a.identity == b.identity | one identity per process; a second identity at the address needs a second certificate from the CA, whose key enroll discards; a restart gives a new anchor as well |
| C1 one certificate | a.cert_hash == b.cert_hash | a node refuses a second certificate per process; enroll issues one per address per run |
| C2 one link key | a.link == b.link | the link key is set once per process and goes into every signing unchanged; no clock is involved |
| C3 one onion key per epoch | a.epoch == b.epoch implies a.onion == b.onion | a rotation makes one key per epoch, every signing reads the ring's current (epoch, key), a failed rotation changes neither; with -onion-rotate 0 epoch 0 names the static key for the life of the process; no clock is involved |
| C4 one epoch per onion key | a.onion == b.onion implies a.epoch == b.epoch | a rotation refuses a public key equal to the current one, and every key comes fresh from GenerateEphemeral (two equal keys by chance: 2^-256); no bound depends on this rule |
| C5 epochs published in order | a.epoch < b.epoch implies a.published <= b.published | the epoch only grows, and a signing of the greater epoch comes later in real time than every signing of the smaller. Equality is allowed: the timer may sign e in the second a rotation signs e+1. A wall clock set back between the two signings would decrease the field; clamp 1 rules that out |
| C6 an epoch ends Skew before the epoch after next begins | a.epoch + 2 <= b.epoch implies b.published >= a.expires + Skew | the rotation to e+2 waits for the release of key e, the grace period ttl + Skew after the rotation R1 to e+1. The last descriptor of e was signed at or before R1, so expires(e) <= R1 + ttl, and when the release comes by the wall clock, the wall at the rotation to e+2 reads at least R1 + ttl + Skew >= expires(e) + Skew. When it comes by running time, or the wall was set back since R1, clamp 2 floors published(e+2) at expires(e) + Skew. Equality is allowed |
| C7 a lifetime of at least 16 min unless cut by the certificate | expires - published >= 16 min, or expires == not_after | -descriptor-ttl is at least 16 min (pki.MinDescriptorLife); Refresh signs expires = min(published + ttl, not_after); with clamp 1 the lifetime is counted from published and stays ttl |

Why this is enough. C3 and C4 make the onion key a function of the epoch. By C5 and C6 any one
clock with the Skew allowance (a descriptor is accepted when published <= t + Skew and expires > t)
accepts at most two adjacent epochs of a node at an instant t: were e and e+k, k >= 2, both
accepted, published(e+k) >= expires(e) + Skew > t + Skew. So any one verifier accepts at most two
keys of a node at any instant. C7 bounds how often a new epoch can appear: published(e+2) >=
expires(e) + Skew >= published(e) + 16 min + Skew, so at most two new epochs per 16 min; it also
keeps a node from making its peers fetch it every minute with short descriptors. Without C6 a node
would sign e, e+1, e+2, e+3 in one second and hand each of four mirrors its own epoch, and the key
that opens a setup would name the mirror outright. Without the Skew gap in C6 a verifier with the
allowance would accept e and e+1 ending at T together with e+2 and e+3 starting at T during the
Skew before T: four keys, two bits per circuit at every boundary. Without C5 a node would sign e+1
for one peer and a fresh e for another forever, and both would stay valid. Without C7 it would
step epochs as often as the mirror margin allows and reopen the window as often. There is no rule
"epoch e+1 published at least 16 min after epoch e": it is true only against the first descriptor
of e, and a verifier of a pair cannot know which descriptor of e was first; on the testbed (ttl
20 min, rotation 1 h) the last re-signing of e comes 10 min before the rotation, and such a rule
would refuse every honest node.

Two clamps at the node, inert with correct clocks. The only honest violations of C5 and C6 come
from a wall clock set back, so published is computed with two clamps:

| Clamp | Where | Effect |
|---|---|---|
| 1. published never decreases within a process: published = max(now, the previous published, the floor), expires = min(published + ttl, not_after) | Identity.Refresh | C5 holds under a set-back of any size. Peers with correct clocks accept the bundle: published is a real past moment |
| 2. a floor at the rotation: after a rotation succeeded and before the new descriptor is published, the floor is set to the expires of the last descriptor of the replaced epoch plus Skew, and then the expires of the descriptor now in service is remembered | rotateIfDue | C6 holds under a set-back. With correct clocks the release by the wall clock gives now >= R1 + ttl + Skew >= the expires of the replaced epoch + Skew, the floor lies below now, and nothing changes. The moments of key release and rotation are untouched |

The expires of the replaced epoch is remembered only in the attempt whose rotation succeeded: a
rotation that fails and is retried every second moves neither it nor the floor. Otherwise the
attempt that succeeds would floor published(e+1) at expires(e) + Skew, up to ttl ahead of the node's
clock, and peers more than Skew behind would refuse the live bundle (ErrDescTime). The descriptor in
service at a rotation is the latest signed one; it names the current epoch, or an older one when
every signing since the previous rotation failed, and the floor then bounds every older epoch as C6
needs, since no descriptor of the skipped epoch exists.

What a set-back costs, and what of it the clamps add. After a set-back by s the node's own
/descriptors answers 503 until its clock reaches its last published again, and the re-signing
timer, which measures the age from published, fires s later; both happen today without clamp 1,
since the descriptor signed before the set-back already carries that published. Clamp 1 adds only
this: a rotation that comes by running time while the wall clock is behind signs published =
max(the previous published, the floor) instead of the wall time, so the 503 lasts until the clock
reaches that value instead of ending at the rotation. Peers drop the node from their mirrors when s
exceeds about ttl/2 minus the mirror margin minus the timer period (6 min 54 s on the testbed,
4 min 54 s at ttl 16 min), from expires minus the mirror margin of the held bundle until the late
re-signing reaches them; meanwhile they ask it every 5 s and refuse nothing. /descriptor keeps
answering throughout.

| Case | C0 C1 C2 | C3 C4 | C5 | C6 | C7 |
|---|---|---|---|---|---|
| re-signing by the timer | same | same key, same epoch | later now | n/a | ttl |
| rotation | same | new key, epoch + 1 | same or later second | floor | ttl |
| grace period, the replaced key still opening | the descriptors of e keep their fields | | | | |
| certificate truncation | same | same | n/a | expires only smaller, and e+2 is never signed under a cut e: its published would be at or past not_after, and Refresh refuses | exempt |
| failed rotation, retried every second | same | unchanged | later only | later only; the expires of the replaced epoch is untouched until the attempt that succeeds | ttl |
| host sleep | same | release, then one rotation on waking, by the wall clock | the wall clock advanced | wall clock >= R1 + grace period | ttl |
| wall clock set forwards | same | the moments come early by the wall clock | published grows | expires(e) <= R1 + ttl, the wall clock at the rotation to e+2 >= R1 + ttl + Skew | ttl |
| wall clock set back, any amount | same | same | clamp 1 | clamp 2 | lifetime from published |
| clock skew between nodes up to Skew | the fields are the signer's own clock; the rules compare the fields of one signer | | | | |
| restart and re-enrollment | a new identity, a new anchor: not the same node | | | | |
| -onion-rotate 0 | same | epoch 0, onion == link, forever | one epoch | one epoch | ttl |
| -auth=false | no identity, no statements, the check is off | | | | |

What is checked and how often:

| Party | Fetches | From | When | Limits |
|---|---|---|---|---|
| node | GET /descriptor, the peer's own bundle | every roster peer | when the entry is missing or due, as before | 5 s, 16 KiB; the bundle is also a statement fed to the peer's record under the admission rule; one not newer than the held entry is not taken |
| node | GET /descriptors/peer, the peer's mirror, the same bytes as /descriptors | k = min(4, roster peers not refused at the start of the pass), drawn uniformly without replacement (client.Choose over crypto/rand); when no such peer is left the pass ends before the draw; a drawn peer refused during the pass, by a proof read earlier in it, is skipped when its turn comes | once per -consistency-every (1 min), inside the keepPeers loop after the refresh of the entries; the first pass one period after the roster | 5 s, 256 KiB, no redirects, strict parsing, one attempt |
| client | GET /descriptors, the mirror of its entry | the entry only | at start and at every rebuild of a -peer client | as before; items may be proofs |

The node draws whom to ask, so the request itself says nothing about its records. Refused peers
are not asked. No request a node receives triggers a fetch. The refresh of the entries runs before
the pass, peer by peer with a 5 s timeout each, so a due peer that stalls delays the pass by 5 s.

The record of statements. Per roster peer X the cache keeps, besides the entry it kept before (the
bundle, relay.Peer, from, due, expires, final), a record of statements (internal/verify Record)
and, after a refusal, the inconsistency itself:

| State | Content | Bound |
|---|---|---|
| record of statements | the identity and certificate hash of the first statement; the link key and its first bundle; per epoch seen the onion key and up to three bundles: the one with the smallest published, the one with the largest published and the one with the largest expires | an epoch is forgotten once its largest expires + Skew + 8 x -consistency-every has passed: a descriptor expired for every clock opens nothing, and 8 passes let a proof against it reach every node at 58 nodes. The bound MaxEpochs = 8 is a memory guard: a ninth epoch is compared first, then the smallest epoch other than that of the held entry is dropped. Under the admission rule and the default period at most four pairwise consistent epochs are held at once (e+4 would have published >= expires(e+2) + Skew >= expires(e) + 16 min + Skew, above now + Skew while e is not forgotten), so the guard is reached only with a period above about 5 min. At most 25 bundles, about 15 KiB per peer on c25519; an honest peer holds 1 or 2 epochs |
| refusal | pki.Conflict: the rule and the canonical proof | one per peer, until the process ends: the identity cannot change under this anchor without a restart of everything |

Statements enter the record from three places: the direct fetch of X's /descriptor, X's item in any
mirror read in a pass (X's own mirror included), and both bundles of a proof item about X. Every
statement passes pki.VerifyStatement under the roster's anchor at X's roster address; what fails
gives a log class and nothing else.

The admission rule: a bundle from a mirror or from a direct fetch enters the record only when its
published <= now + Skew on the reader's clock, the lower bound pki.Verify applies to live bundles;
one published further ahead is logged under the existing class `descriptor outside its validity`
and not recorded. Without this a node could feed each reader eight pairwise consistent statements of
future epochs, push the live epoch out of the record and then serve two keys of the live epoch to
different readers unproven. Both bundles of a proof that VerifyConflict accepted enter
unconditionally: the inconsistency is already found; the bundles of a proof that holds no
contradiction are two ordinary bundles under the same rule. Record.Take compares an admitted
statement with every held bundle (at most 25 comparisons) and returns the first conflict.

Entry choice and adoption:

- The entry for X is the newest live statement: newer means greater by the pair (epoch, published)
  lexicographically, live means pki.Verify passes now. A statement not newer than the held entry is
  not taken, from a direct fetch or from a mirror; the peer stays due and is asked again after the
  pause, exactly as a re-fetched unchanged bundle is today.
- A newer statement displaces the held entry under the existing mirror rule: not while the held one
  is in the mirror and the new one cannot join it yet (its published is ahead of this node's clock).
  due and expires come from the new one, so a direct fetch of X comes later, never sooner:
  descriptor_requests does not grow because of adoption.
- A node adopts into an empty slot as well: a peer with no entry (one that never answered, or whose
  fetch failed) gets the live, mirrorable statement a mirror carries. The direct fetch still runs
  while the peer is missing or due, so startup on a testbed where every peer answers is unchanged.
- Adopting is safe: the bundle is X's own signature, verified here; the link key is the same by C2,
  so relay.Peer for X does not change; X holds the replaced onion key for the grace period, so a
  client that took the older bundle still builds its circuit.
- Adoption is also what shortens the legitimate difference between honest mirrors. Today a mirror
  that fetched e just before X rotated keeps e until it is due, ttl/2 later, and if X then fails to
  answer, until expires minus the mirror margin: up to 17 min 54 s on the testbed. With adoption the
  difference lasts at most W after the first honest mirror has listed the newer epoch.

The window W = -consistency-every + Skew + k x the fetch timeout + 1 s, counted from the first
second any honest mirror lists the newer statement, plus one fetch timeout per due peer that stalls
the direct request before the pass. On the testbed 60 + 120 + 4 x 5 + 1 = 201 s with honest peers,
206 s with one stalling peer. Skew in W is the lag of the adopting node's clock behind the
signer's that pki.Verify allows: a statement joins a mirror once the adopter's clock reaches its
published time, so a larger lag widens the window by the difference (the cmd/relay test with
clocks 238 s apart bounds it per pair). Before the first honest mirror lists the newer epoch all
honest mirrors agree on the older one: no peer fetches a node before its entry is due, half the
lifetime after published, so the newer epoch can take minutes to reach the first mirror, and that
is no window.

What happens on detection:

| Effect | Where | Detail |
|---|---|---|
| X leaves the cache | peerCache.refuse | the entry is deleted, the refusal is kept; the wait skips refused peers, since an empty entry would otherwise return the 5 s pause forever |
| no extension to X | relay.Config.Peers does not return X | relay counts RefusedExtend and refuses without dialling, as for an address outside the roster; the relay package does not change |
| X leaves the mirror, the proof enters | publish | the item becomes `{"addr":...,"proof":[lo,hi]}`; the mirror is re-encoded at once; until is computed from bundles only |
| X is not fetched again | the refresh of the entries and the draw skip refused peers | nothing X serves would be taken |
| one log line | `peer <roster addr>: refused: <rule text>` | one of seven fixed texts; never a byte X sent |
| counters | peers_refused (the current number), peer_mirror_requests (GET /descriptors/peer answered) | in /stats and in the counters line; peers does not count a refused peer |
| how long | until the process ends | the identity cannot change under this anchor without a restart of everything |

A node that reads a proof in a peer's mirror verifies both bundles itself (pki.VerifyConflict) and
feeds them into X's record; the conflict comes out of the record as if the node had fetched both, so
what it then publishes is a proof it verified, not one it copied. A proof item whose bundles do not
conflict or do not verify is logged once as `peer <addr>: mirror: not a proof of inconsistency` and
counts as X not served by that mirror; two bundles that verify still go into the record under the
admission rule. An item about the reader's own address is ignored.

Propagation and convergence:

| Question | 5 nodes (testbed) | 58 nodes |
|---|---|---|
| a holder of a divergent statement detects it | within one pass: each node reads all 4 others | a holder reads 4 of 57 per pass; with the other statement held by m of 57 a pass misses with probability about (1 - m/57)^4, 0.07 for an even split, so within 2 passes with probability 0.99 |
| every honest node holds the proof | one more pass | each of the 57 uninformed nodes draws 4 of its 57 peers without replacement: the expected uninformed share is about 0.93, 0.64, 0.08, 0.00 after the passes following detection (hypergeometric, 1, 5, 22, 53 informed), so about 4 passes, 5 as a rounded-up bound |
| every honest mirror holds the newest epoch of an honest node | W = 201 s | about 4 passes plus Skew |
| what a client sees | the proof in its entry's mirror, verified under its own -ca; the node refused and counted apart from -missing | the same |

The client verifies the evidence itself: two signatures under the anchor and a comparison of two
parsed descriptors. It fetches no second mirror and keeps no state across processes; a -peer client
keeps no record across rebuilds either: an honest entry that runs the check would have refused X
before the client could see two statements of X through it, and an entry without the check is the
mixed deployment the switch exists for.

Cost. A bundle is about 600 bytes on c25519 and 720 on GOST; a mirror of 5 nodes about 3 KiB, of 58
about 35 KiB (41 KiB on GOST).

| Nodes | Requests per minute, network | Bytes per minute (c25519 / GOST) | Per node per minute | Today's /descriptor traffic |
|---|---|---|---|---|
| 5 | 5 x 4 = 20 | 60 KiB / 72 KiB | 4 requests, 12 KiB | 5 x 4 = 20 requests per 10 min at ttl 20 min |
| 58 | 58 x 4 = 232 | 7.9 MiB / 9.3 MiB (about 135 KB/s) | 4 requests, 140 KiB | 58 x 57 = 3306 requests and about 2 MB per 10 min: each node fetches each peer every ttl/2, plus one request per 5 s per peer that is due and has not re-signed yet |

A proof is two bundles where one was: 58 proofs make a 70 KiB mirror (82 KiB on GOST), within the
256 KiB a reader takes. At 58 nodes `-consistency-every 5m` divides the traffic by five and makes W
about 7 min.

The switch:

| Flag | Where | Default | Meaning |
|---|---|---|---|
| -consistency | cmd/relay | true | read the mirrors of roster peers, keep a record of every peer's statements, refuse a peer whose descriptors contradict each other, carry the proof in /descriptors, apply pki.MinDescriptorLife to the peers' descriptors. With -auth=false one line `WARNING: -consistency needs -auth, the check is off`, and the check is off |
| -consistency-every | cmd/relay | 1m | the pass period, 30 s to 1 h (the lower bound is above k x the timeout = 20 s, so a pass never outlasts its period); refused with -consistency=false only when set explicitly |
| -consistency | cmd/client | true | verify the proofs in the entry's mirror, refuse the nodes they name, counted apart from -missing; apply pki.MinDescriptorLife. false: a proof item is a node the entry left out, within -missing; no lower bound on the lifetime |

The startup line of a node carries consistency=<value>. The baseline (nodes with
-consistency=false): no pass, no records, no proofs, mirrors as before, a node with two keys stays a
peer everywhere; /descriptors/peer still answers. The testbed manifests (deploy/base/relay.yaml)
set -consistency=true explicitly, as they set -onion-rotate. The lab harness changes nothing:
-auth=false, no rosters.

What is left to a node that breaks the rules is collected in LIMITATIONS: at most two onion keys
accepted by one verifier at any instant, and three across clients whose clocks differ, around an
epoch boundary; a two-key window of at most W and at most twice per 16 min, on the testbed at most
402 s of every 960 s; one bit about the entry per circuit set up inside the window, which a mailbox
can collect across the rebuilds of one -peer client; a refused node shrinks every client's list by
one.

scripts/e2e.sh (the bullet on the mirror above) tells the traffic of peers and of clients apart by
path: clients fetch GET /descriptors (mirror_requests), nodes fetch GET /descriptors/peer
(peer_mirror_requests), and adoption leaves descriptor_requests alone (it can only postpone a direct
fetch), so both checks it made before keep their meaning. Beyond them, after the settle loop the
script reads peer_mirror_requests and requires peers_refused to be 0 at every relay (otherwise
`a relay refuses a roster peer before the clients started`), and at the final reading of the
counters it requires peer_mirror_requests to have grown at every relay (otherwise `the consistency
check made no request at <relays>`) and peers_refused to still be 0, and prints `consistency: every
relay cross-read its peers, none refused`. The negative case, a two-key node on the kind testbed, is
not an e2e step: it needs a relay that signs two keys, which lives in the Go tests and not in the
testbed's binary.

### Key lifetime and revocation

| Key | Created by | Held in | Lives |
|---|---|---|---|
| CA key | `jimichi enroll`, pki.NewCA, after every request has passed | secmem of the enroll process | the issuance only; Close releases it on every exit path |
| Anchor | the same process | stdout, ConfigMap, client environment | until the next issuance, public |
| Node signing key | cmd/relay at start, before any port opens | secmem; a node told to lock memory does not start without the lock | until the process ends |
| Link key | cmd/relay at start, GenerateEphemeral | secmem | until the process ends; with -onion-rotate 0 it is the onion key as well |
| Onion key | cmd/relay at start and at every rotation, GenerateEphemeral | secmem; with memory locking on, a key that is not locked is not taken | with -onion-rotate one period as the published key and the grace period after it, 1 h 22 min on the testbed; a rotation that fails keeps the published key until one succeeds; released at the end of the grace period and when the process ends |
| Certificate, descriptor | CA, node | node heap, public; the bundle is kept encoded | certificate until not_after or the node restarts; descriptor 1 h by default (-descriptor-ttl), 20 min on the testbed |
| Roster, peer descriptors | enroll, the other nodes | node heap, public | the roster until the node restarts; a peer descriptor until its expires; a peer's record of statements and its refusal by a proof of inconsistency until the node restarts |

- A node restart gives a new signing key, no certificate and no roster. The node is ready
  (readiness on /healthz), but /descriptor and /descriptors answer 503, it extends no circuit,
  and clients refuse to build a circuit through it until scripts/enroll.sh runs. make deploy,
  make start and scripts/e2e.sh run it themselves.
- A new issuance needs fresh node processes. scripts/redeploy.sh restarts the nodes itself, make
  start after make stop brings them up anew, while running make deploy again, make start without
  make stop or scripts/e2e.sh on certified nodes stops with a restart hint. Certificates of the
  previous CA die when the nodes restart with new identities and the clients with the new anchor:
  revocation by forgetting. There is no other revocation.
- A peer refused by a proof of inconsistency (section "Descriptor consistency") stays refused until
  the process ends: it can change its identity under this anchor only by a restart, and the restart
  of one node needs a new issuance for all. The refusal is lifted by the same forgetting.
- The certificate lifetime comes from -cert-ttl: 72 h on the testbed, 1 h in CI.
- The descriptor is signed when the certificate is installed, at every rotation of the onion key
  and otherwise only by the timer; a /descriptor request serves the ready bundle and never
  triggers a signature. The timer fires
  every min(ttl/4, 1 min), where ttl is -descriptor-ttl, and signs again once the descriptor's
  wall-clock age reaches half of ttl or the certificate state changes. The wall clock matters
  because the timer runs on the monotonic clock, which stands still while the host sleeps.
- After the descriptor's expires or the certificate's not_after the node answers 503. A node
  whose certificate expired comes back only through a restart and a new issuance.

### CA compromise

The CA key takes no part in key agreement. Whoever holds it, that is the operator or someone who
stole the key during the issuance, can certify an identity of their own for any name and address
and, with a position in the network, substitute a node. It gives no layer keys of past circuits:
those come from the nodes' agreement keys, which the CA never sees.

## What is recorded during measurements

| Source | Data |
|---|---|
| client | on the testbed the -peer clients: the lines of subsection "The -peer client", that is the round-trip time of every own message through the mailbox, every minute the state and the counters of the conversation, ends and rebuilds of the circuit by class only, the hashes of the own and of the pinned card, with no path, address, text or key. A client without -peer (cmd/client), per message: the size of the reply and the round-trip time, or a line when no reply comes within 5 s; at the end of the circuit the line `circuit closed`, or `circuit closed: client: reply refused: <check>` with the class of the reply or frame the client refused, naming neither a node nor a cell number, or `send: <class>` with the class of a failed send (with -fixed-chain the error itself, which can name the entry address and the local port); at start the name, fingerprint and certificate validity of every listed node whose bundle it verified, in the listed order (with -fixed-chain the descriptor validity as well), how many of the listed nodes were verified, and the number of hops; with a drawn chain never which nodes form it. In the lab harness, per run: the round-trip time of every message whose echo came back, matched by flow and sequence number, the number of messages a constant-rate schedule dropped, the number left unanswered, the number of clients that refused a reply or a link frame, and per flow whether and when its circuit closed; in the block 7 set also, for every data cell, whether it carries a message, from a wrapper of the client's provider (EXPERIMENT, block 7), a labelling the relays and the observer never see |
| relay | aggregated counters on stdout once a minute and on loopback on request: accepted, forwarded, delivered, dropped, padding, closed circuits, refusals by limit, setups refused for an address outside the roster (refused_extend), setups whose next node did not finish the link handshake (failed_extend), expired deadlines, expired circuits, accept retries, state of the installed certificate (cert: none, valid, expired), roster size and peers with a valid cached descriptor (roster, peers), requests answered on the info port for the node's descriptor and for the mirror (descriptor_requests, mirror_requests), mirror requests answered to peers and peers refused by a proof of inconsistency (peer_mirror_requests, peers_refused), the epoch of the onion key and the failed attempts to rotate it (onion_epoch, onion_rotate_failed). With -exit mailbox also the mailbox counters (section "End-to-end layer and mailbox"), on loopback on request only, not on stdout. No flow identifiers or addresses. The counters are not published on the network: polled often, they would show which ticks carried a real cell. At start the fingerprint and the full hash of the signing key (identity=, identity_hash=), on certificate installation a line with the serial number and not_after, on roster installation a line with the number of nodes and ca_id, on every rotation of the onion key a line with the new epoch and no key material, on a failed rotation one line per kind of cause (pages not mapped, pages not locked, key not locked, key refused by the ring, other), a fixed class with no size and no text of the underlying error, with no new line while consecutive failures share the class and a line again for the first failure after a success, and one line per kind of cause, naming the peer by its roster address and carrying nothing the peer sent, when a peer's descriptor cannot be fetched or verified, the classes `descriptor shorter than the least lifetime` and `not a proof of inconsistency` among them; with -consistency also one line `peer <addr>: refused: <rule>` with one of the seven rule texts when a peer is refused by a proof of inconsistency, one line per kind of cause `peer <addr>: mirror: <class>` when a peer's mirror cannot be fetched or parsed or its proof does not verify, and at start with -auth=false one line `WARNING: -consistency needs -auth, the check is off` |
| network | in the lab harness only, inside its process and without a packet capture: the moment every frame crosses the client-entry link and the last link between nodes, the one into the exit, in both directions. There is no link past the exit to observe yet ([#47](https://github.com/jimichi-org/jimichi/issues/47)) |
| memory | planned: dumps of the relay process in the key extraction scenario ([#24](https://github.com/jimichi-org/jimichi/issues/24)); nothing takes a dump yet |

Only cmd/lab writes to artifacts/, as JSON reports: rows that carry the run configuration, the seeds
and the code revision (`correlation-*.json`, `paths-*.json`, `cells-cover-*.json`), the frame counts
per window and the score matrix of the first repeat (`detail-*.json`), and the medians across the
repeats in which no circuit closed and no node limit acted (`summary-*.json`; `summary-cover-*.json`
leaves out runs whose labels disagree as well), and the verdicts of the forged conversation with the
assumption and the records in hex, without a byte of a secret key (`deny-*.json`). The logs and
counters of the testbed pods are not stored: the logs stay in stdout (kubectl logs), and
scripts/stats.sh prints the counters to the terminal.

## Package layout

| Package | Purpose | Depends on |
|---|---|---|
| crypto | CryptoProvider interface, labels and the transcript of key derivation | crypto/secmem |
| crypto/gost, crypto/c25519 | primitive suites | crypto, secmem, external libraries |
| crypto/suite | picks a suite by name for entry points and the testbed | crypto/gost, crypto/c25519 |
| crypto/secmem | key memory | x/sys/unix |
| crypto/providertest | contract conformance tests | crypto |
| wire | cell format, layers, counter order | crypto, crypto/secmem |
| link | link encryption between neighbours, frames of one size | crypto, crypto/secmem, wire |
| pki | certificate, descriptor and request of a node, roster and mirror formats, issuing and checking, descriptor consistency rules and the proof of inconsistency | crypto, crypto/secmem, wire |
| internal/fetch | reading bundles and the mirror from an info port | pki |
| internal/verify | node bundle checks over pki: the client reads every bundle of its entry's mirror on its own (one that fails counts as not served), applies the mirror rule and draws the other hops among those that pass; a node takes a peer's link key and identity only from a verified bundle; the record of a node's statements, mirrors carrying proofs, refused nodes counted apart from -missing. One implementation for cmd/client and cmd/relay, against which a lab test checks the chain sampler | client, crypto, pki, relay |
| relay | relay node, sending on its own clock | crypto, crypto/secmem, link, wire |
| client | choice of the chain, send, receive, cover traffic; the mirror rule with refused nodes (JudgeMirrorAmong) | crypto, crypto/secmem, link, wire |
| noise | the Noise-shaped handshake machine over CryptoProvider, only the KK pattern today | crypto, crypto/secmem |
| e2e | the end-to-end layer: contact card, identity, KK session, hash ratchet, session recovery | crypto, crypto/secmem, noise, wire, pki |
| mailbox | queue store at the exit, request and reply format | crypto |
| conversation | a client's conversation with its contact: a request per tick, the window of puts, the sticky record, matching replies, epochs, rebuilding the circuit | crypto, crypto/secmem, e2e, mailbox |
| vault | client container: the file format, the keys from a password, the derivation of a volume's identity, the single write | crypto, crypto/secmem |
| vault/profile | the -peer client profile in a volume: the contact card, the own card from the volume's identity, the parsing rules | crypto, crypto/secmem, e2e, mailbox, noise, vault |
| lab | harness that runs one configuration in one process, the observer on two links, seeds, sampling of chains, cell labels of block 7 | client, relay, link, wire, crypto, crypto/secmem, crypto/suite |
| lab/metrics | correlation scores, AUC and its bootstrap interval, traffic multiplier and latency percentiles, share of compromised chains, cell features, discriminant, KS and TV, degrees of anonymity | standard library only |
| lab/scenario | experiments that act on the system: a recipient forging a conversation of the end-to-end layer with the production session (Genuine, Forge, Verify, a recording and injecting provider wrapper), run by `cmd/lab -set deny` | crypto, crypto/secmem, e2e, noise |
| lab/report | an empty package reserved for a report writer; today cmd/lab writes the reports | nothing yet |
| web | planned: testbed dashboard ([#21](https://github.com/jimichi-org/jimichi/issues/21)); an empty package today | nothing yet |
| cmd/relay, cmd/client, cmd/lab | entry points and configuration; cmd/client -peer with the admin port and the rebuild of the circuit | the packages above |
| cmd/jimichi | testbed CLI: certificate issuance, the card of a key that is thrown away at once, the hash of a card, creating and showing a client container (vault init, vault show) | pki, e2e, mailbox, crypto, crypto/suite, crypto/secmem, vault, vault/profile |

Rule: no package of the system knows about lab. The experiment harness depends on the system, not
the other way round, and a test of lab reads the imports of every .go file of every other package of
the module, tests included and whatever its build constraints (system, architecture, cgo, tags), and
fails on an import of lab or cmd/lab. The seams lab/scenario uses are the ones production takes as
well: a CryptoProvider and the noise.Static interface.

## Client container

Status: the packages vault and vault/profile and the commands `jimichi vault init` and `jimichi
vault show` are implemented. The -peer client with a container (-vault) and the measurement of
the property (EXPERIMENT, block 5) are planned
([#20](https://github.com/jimichi-org/jimichi/issues/20)).

The container is a client file of a constant size with one or two volumes, each under its own
password. A written volume holds the pin, that is the contact card, and nothing else. The file
holds no key material in any form, not even encrypted: the identity key and the fetch capability
F are derived from the volume key at every opening (CRYPTO, "Container"). Yet the file and a
volume password reproduce the identity key and F, so against seizure of the file together with
the password the strength is that of a key stored under a password. A volume holds no message
history ([#159](https://github.com/jimichi-org/jimichi/issues/159)).

### Format

```
file      = salt[32] | region 0 [4096] | region 1 [4096]                  exactly 8224 bytes
region    = r[32] | Seal(K_b, nonce 0, plaintext[4048], ad = th_b) [4048 + tag 16]
plaintext = u16be L | content[L] | zeroes                                  L from 0 to 4046
content   = u8 version = 1 | contact card[L-1]                             at most 339 bytes
```

| Offset | Bytes | Field |
|---|---|---|
| 0 | 32 | salt |
| 32 | 4096 | region 0 |
| 4128 | 4096 | region 1 |
| region + 0 | 32 | r |
| region + 32 | 4048 | ciphertext |
| region + 4080 | 16 | tag |
| plaintext + 0 | 2 | L |
| plaintext + 2 | L | content: version 1, then the canonical contact card |
| plaintext + 2 + L | 4046 - L | zeroes |

- The file carries no header, format version, suite, stretching cost or nonce. The size fixes the
  format: a file of another size is ErrNotVault, and another suite cannot be told from a wrong
  password.
- A region without a volume holds an empty volume: L = 0 under a key of 32 bytes from crypto/rand,
  sealed by the same code; the key is thrown away at once. The place of a volume is random:
  volume i goes to region b xor i, where b is a random bit.
- Every sealing takes a fresh r from crypto/rand, and the region key K_b is derived from the
  volume key and r, so every K_b serves one Seal and the zero nonce is safe. No nonce is stored,
  so regions are laid out the same way in both suites: the size and the look of the file do not
  give the suite away.
- vault keeps the content as opaque bytes, vault/profile knows its layout. A volume holds no own
  card: it is built from the derived public key, QueueID(F) and the mailbox address of the
  contact card.
- Another format (history, another stretching cost, another identity derivation) is another file
  size.

### Keys

```
W           = PasswordKey(password, NewContext(p, "vault/password", salt))
k_s         = DeriveKey(W, "vault/volume", NewContext(p, "vault/volume", salt, [s]), 32)   s = 0, 1
K_b         = DeriveKey(k_s, "vault/block", NewContext(p, "vault/block", [s], r), 32)
ctx_id      = NewContext(p, "vault/identity", salt, [s])
(priv, pub) = DerivePair(k_s, ctx_id)                                        identity key
F           = DeriveKey(k_s, "vault/fetch", ctx_id, 16)                      fetch capability
```

- One salt per file, shared by both volumes: Open stretches a password once, and the region
  number s separates the keys of the two regions.
- The region number and the salt enter the volume key, r enters the region key and the
  associated data: swapped regions, another salt or any changed byte of a region make the opening
  fail.
- The identity is derived from the volume key of the region that opened, and only after a
  successful opening; the volume key is released right after the pair and F are derived.
- The identity derivation belongs to file format v1: another derivation is a new format and
  another file size, otherwise earlier containers would give other identities when opened.
- Consequences: another password or a new container gives a new identity, a copy of the file
  keeps it. Changing the password changes the identity, and the pin on the peer's side is
  permanent, so a new introduction needs a new container on both sides.

### Operations

| Operation | What it does |
|---|---|
| `Prepare(p, volumes...)` | one or two volumes, each with a password and a Fill. Equal passwords: ErrSamePassword. A salt from crypto/rand and a random place of the volume. For every volume one PasswordKey, the volume key and at once the identity; Fill gets the identity and writes the content straight into a secmem buffer of MaxContent = 4046 bytes (more: ErrTooLarge; the tail past the length is zeroed). A Fill of a volume other than the first that returns 0: ErrEmpty. The volumes other than the first and the empty volume are sealed and opened back, and their keys and buffers are released. The Draft holds the salt, the sealed regions, the key of the first volume, its identity and its buffer; there is no file yet |
| `Draft.Identity()` | the identity of the first volume before the write: the own card is built from it |
| `Draft.Write(path, fill)` | fill (may be nil) edits the content of the first volume; a failed fill leaves the volume without content; L = 0: ErrEmpty, no file. A file at the path: ErrExists before any byte reaches the drive. Seal of the first volume with a fresh r, the single write (below), a reread: the same bytes, and the first region opens. A Write that linked no file (ErrExists, a write or link error) leaves the Draft fit for another attempt. From the first attempt that reached the drive the bytes of the file are fixed: every later attempt writes the same bytes, and a fill then has to give the same content, otherwise it is refused and the Draft stays as it was. Once the link succeeded, the key and the buffer of the first volume are released and the next Write gives ErrWritten; a failure after the link (removing the tmp name, the directory sync, the reread) is ErrWritten with its cause |
| `Draft.Close()` | releases whatever was not taken through Take |
| `Create(p, path, volumes...)` | Prepare and Write(path, nil) |
| `Open(p, path, password)` | a size other than 8224: ErrNotVault. The file is read whole, one PasswordKey, k_0 and k_1. Both regions are always tried, in one order, each attempt into its own secmem buffer. The identity is derived from the key of the region that opened. Open writes and removes nothing |
| `Volume.Content()`, `Volume.Identity()`, `Volume.Close()` | the content and the identity of the open volume; Close releases whatever was not taken through Take |
| `Identity` | Public: the public key; Agree: an agreement with the private key, together with Public a noise.Static; Fetch: F, borrowed; Take: moves the keys to the caller, after which Agree refuses. The private key sits under an RWMutex, as in noise.KeyPair |
| `Clean(path)` | removes `<path>.tmp`: the one a creation killed before its link left, or the one of a creation on the same path running at that moment, which then fails |

- Each attempt has a buffer of its own because on c25519 the AVX2 path zeroes its output on a
  wrong tag: a failed attempt clears its own buffer and not the other one. Both regions are
  always tried, so the work does not depend on which region opens; only a successful opening
  goes on to derive the identity.

| Error | When |
|---|---|
| ErrNotVault | the file size is not 8224, or it is not a regular file |
| ErrNoVolume | no region opens: a wrong password, no such volume, another suite, a changed salt or a changed region; one error for all of these |
| ErrCorrupt | both regions open, a length of 0 or above 4046, a nonzero tail; at opening a refused scalar sampling (crypto.ErrNoScalar) or a zero F |
| ErrExists | a file already exists at the path, before the write or at the link; it is left untouched |
| ErrSamePassword | two volumes share a password |
| ErrTooLarge | Fill returned a length above MaxContent |
| ErrWritten | a Write after this Draft has linked the file; with a cause, a Write whose link succeeded and a later step failed: the file is at the path and the Draft is spent |
| ErrEmpty | a written volume without content |

- A password that breaks the provider's rules is crypto.ErrBadPassword. ErrNoScalar and a zero F
  (about 2^-128 or rarer each) make a creation fail without a file; nothing retries, the creation
  is run again. Other provider and secmem errors, a shortage of lockable memory included, are
  returned as they are, not as ErrCorrupt: a sound container does not look corrupt.
- Both regions open only under equal passwords, which Prepare rules out.

### The single write

- The file is written exactly once, at creation, when every volume has a contact card. The API
  has no write after creation, and Open only reads. So all states of the file after creation are
  the same byte for byte, and the number and the moment of writes do not depend on the number of
  volumes.
- The write: a leftover `<path>.tmp` is removed and an existing file is refused with ErrExists
  before anything is written; a new tmp is created with O_CREATE|O_EXCL and mode 0600, gets
  8224 bytes, fsync and close; then `os.Link(tmp, path)`: if a file appeared at the path
  meanwhile, ErrExists, and that file is left untouched; tmp is removed (a tmp already gone
  counts as removed), and on Linux the directory is synced.
- The first attempt that reaches the tmp fixes the bytes of the file in the Draft: the first
  volume is sealed once, and an attempt after a failed write or link writes the same 8224 bytes.
  So the blocks a failed attempt leaves on the drive hold the version the file holds, not
  another version of this container.
- A hard link never replaces a file, so no existing container is overwritten. One creation per
  path at a time is assumed: every run starts with Clean, which removes `<path>.tmp`, so a run
  that overlaps a creation on the same path makes that creation fail, and two overlapping
  creations can both fail.
- A `<path>.tmp` left by a creation killed before its link is another container with another
  salt, not a version of this one: the next start runs a new Prepare. Clean removes it at the
  next start; removal does not wipe the blocks on the drive (LIMITATIONS).
- The cost: changing the contact means a new container, a new identity and a new introduction,
  and the contact card of a second volume is needed already at creation.

### Client profile (vault/profile)

A volume holds `u8 version = 1 | canonical contact card`, at most 339 bytes.

| Function | What it does |
|---|---|
| `New(p, mailbox, contact)` | a Fill for Prepare: builds the own card from the volume's identity (suite, mailbox, QueueID(F), public key) and checks it by a parsing round trip. A contact, if given, is checked as PUT /contact checks it (subsection "The -peer client"): the same suite and mailbox, not the own key and not the own queue, and the key takes a trial agreement (the exchange e2e/check). Writes the version and the contact card; without a contact it writes nothing, which only the first volume may do before Write |
| `WithContact(p, own, contact)` | a Fill for Draft.Write once the identity was taken: checks the contact against the own card by public values, checks its key by a trial agreement with a one-time pair (the exchange e2e/check) and writes the version and the card |
| `Parse(p, volume)` | version 1 and L above 1; the card canonical and of the provider's suite; not the own key and not the own queue. Then the keys move into the profile (Take), and the own card is built with the contact's address. Every refusal of the content is ErrCard |
| `Profile.Fit(mailbox)` | the address of the contact card equals -mailbox |
| `Profile.Identity(p)` | the end-to-end identity (e2e.Identity) over the profile's pair; the profile owns the key |
| `Profile.Close()` | releases the identity key and F |

- A zero queue (about 2^-128) is a profile error: New refuses and Prepare creates no file, and
  Parse answers ErrCard.
- The own card has the address of the contact card: the exit is pinned to the mailbox, so the
  volume stores no own address.

### Commands jimichi vault

| Command | stdin | Action |
|---|---|---|
| `jimichi vault init -suite S -mailbox ADDR -contact CARD [-contact CARD] FILE` | none | one volume per -contact, at most two; the formal checks of every card (canonical, the suite of -suite, the address of -mailbox, two cards with neither the key nor the queue in common) and the refusal of an existing file come before any password is stretched, while the key of the contact and the match with the own card are checked after the identity is derived, before the write; the command generates the passwords itself (16 bytes from crypto/rand, base32 without padding, 128 bits) and, once Create succeeds, prints them on stdout one per line in the order of -contact, once; then `created` on stderr. A creation that fails after its link removes the file: an error leaves neither a file nor a password |
| `jimichi vault init ... -stdin FILE` | passwords, one per line | the user's own passwords; a warning on stderr that the claim about the second volume is not made for them |
| `jimichi vault show -suite S FILE` | the password | the own card derived from the password, its card_hash, the mailbox address and the contact's card_hash, as the lines `card=<suite>:<base64>`, `card_hash=`, `mailbox=`, `contact_card_hash=`; neither the region number nor the number of volumes |

- The password is read from stdin straight into a secmem buffer up to \n or the end of input, a
  final \r is dropped; the byte rules are those of PasswordKey (CRYPTO, "Interface").
- Every run calls Clean first. The stretching cost is always the production one.
- -keymem and -harden are those of enroll: if locked memory is asked for and does not work, the
  command takes no password. A Windows host needs `-keymem zero -harden=false`, and the command
  warns that the password, its stretch and the keys can be paged out to pagefile.sys and written
  to hiberfil.sys; the locked path works in WSL2.
- show reports errors on stderr in the classes of a volume opening: `vault: no volume opens with
  this password`; `vault: the volume is corrupt` (ErrCorrupt and a refused content);
  `vault: not opened: memory: ...` on a secmem error and `vault: not opened: io: ...` on any
  other. A file of another size gives `vault: not a container`.
- show with one password twice gives one card, a new container with the same password another.

### The property and its check

What is claimed and under which assumptions is written in CRYPTO ("Container") and THREAT_MODEL
("Client container"), the limits in LIMITATIONS. A distinguisher of one volume from two with
controls and a trace of the file states are planned (EXPERIMENT, block 5). Statistical batteries
such as NIST STS are no evidence: they can show that a file differs from random data, not that it
is indistinguishable from it.

## Deployment

- deploy/kind: kind cluster configurations, cluster.yaml for the testbed (a control plane and two
  workers) and ci.yaml for CI (a single node). The testbed's API server listens on 127.0.0.1:16443,
  below the dynamic port range 49152-65535: Windows reserves blocks of that range after a restart,
  and a control plane whose port falls in one does not start. kind fixes the host port when it
  creates a cluster, so a change of the port takes effect only on a new cluster.
- deploy/base: the jimichi namespace, five relays (relay-1 to relay-5), each a Deployment with
  its Service and with -exit mailbox, and two -peer clients, client-a and client-b, which list all
  five, keep their queues on the mailbox of relay-5 and draw chains of three that end on it.
  client-a sends a message every 2 s, client-b answers each (-respond). The mailbox counters of
  the other relays stay at zero, which scripts/e2e.sh checks. There are no volumes, the root
  filesystem is read-only, the user is 65532, seccomp is RuntimeDefault and every capability is
  dropped; relays and clients keep only IPC_LOCK for mlock.
- The clients are deployed with the Recreate strategy and the selector `{app: client, client:
  a|b}`: every pod is a new identity, so there are never two pods of one client. The selector of a
  Deployment cannot change, so `make deploy` deletes a client-a with the old selector `{app:
  client}` before it applies the manifest, and scripts/e2e.sh deletes both clients first.
- scripts/introduce.sh introduces the clients: with RESTART=yes (the default) it restarts both,
  reads from the log of the current container of each exactly one card_hash= line, waits for the
  admin listening line, takes the cards from GET /card through port-forwards to the local ports
  19401 and 19402, checks the hash of each (`jimichi card-hash`) against the log line of the same
  container, delivers each with PUT /contact to the other client, waits 10 s for the contact pinned
  lines and checks that neither container restarted meanwhile. Any failure starts the attempt over
  with a restart, and after three it exits 1. A restart of either client is a new identity, so
  enroll, deploy, start and e2e.sh run the introduction themselves.
- The manifests hold no Secret at all: node keys are created in process memory and a node stores
  them nowhere else, in no Secret, volume or file. Only the secmem buffers are locked: the copies
  the libraries keep on the heap are not, and whether those reach swap depends on the host
  ([#36](https://github.com/jimichi-org/jimichi/issues/36)). The only thing that enters the
  cluster is the public anchor, in ConfigMap jimichi-ca.
- The CA runs outside the cluster: `jimichi enroll` (cmd/jimichi) through scripts/enroll.sh on the
  operator's machine or the CI runner.
- Nodes are deployed with the Recreate strategy, so each Deployment has exactly one live pod and
  issuance finds exactly that one. The -name and -advertise flags set the name and address in the
  certificate, and the address is the one the client knows.
- The relays run with -onion-rotate 1h and -descriptor-ttl 20m: the grace period is 22 min, so
  a node holds a single onion key for the other 38 minutes of every hour.
- deploy/base/network.yaml: a network policy lets the cell port of every relay take connections
  from the pods of clients and of relays only; the info port stays open to the namespace, and
  the port-forward that issuance and the counters use does not pass through it. The policy binds
  only where the cluster's network plugin enforces network policies: scripts/e2e.sh probes it
  from a pod that is neither a client nor a relay, fails without it in CI and only warns on a
  development host whose plugin does not enforce it, such as kindnet under WSL2.
- The scripts (enroll, e2e, stats, redeploy) take the relays from the deployments labelled
  app=relay, so the manifest alone sets how many there are. The hop label only tells the relays
  apart: any relay takes any place in a chain, and the clients of the testbed pin their exit to
  relay-5.
- Each relay Service exposes the cell port 9000 and the info port 9100. A client uses both ports
  of its entry only; nodes use the info port of every roster node for the peer descriptors and
  the cell port of the next node of a circuit.
