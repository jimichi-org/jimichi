# Glossary

English | [Русский](../ru/GLOSSARY.md)

| Term | Meaning |
|---|---|
| Cell | the unit of transmission, constant 512 bytes |
| Layer | one level of encryption, stripped by one node of the chain |
| Hop | a step between neighbouring nodes of the chain |
| Circuit | the nodes a message travels through, three by default, drawn by the client from its node list; also called the chain |
| Node list | the static list of nodes a client draws its chains from; before a chain is built every listed node whose bundle the entry serves is verified; for a random chain the entry may leave out at most -missing nodes (one by default, never more than the list holds beyond -hops), and those are not used |
| Entry, middle, exit | the places of a node in a chain: the entry is the first node and the only one the client connects to, the middle is between the entry and the exit, the exit is the last node: it opens the innermost layer and answers with an echo or as a mailbox; a -peer client pins its exit to the mailbox |
| Rogue node | a node the adversary holds: a compromised one or one inserted with a valid certificate |
| Fixed chain | the first nodes of the list in the listed order instead of a random choice, for measurements that need a known path |
| Ephemeral key | a key that lives for one session; its buffer is zeroed afterwards, while the copies the libraries made stay on the heap until that memory is reused (CRYPTO, "Known gaps") |
| UKM | the VKO factor binding an agreed secret to a session; in the GOST suite it is the first 8 bytes of the transcript hash |
| Transcript | the public data of one key exchange in an unambiguous layout: the version, the parameters of the exchange, the public keys of both sides and, when nodes are authenticated, the identity key of the node (CRYPTO, "Key derivation") |
| Key context | the transcript hash together with the suite (Context); it enters every agreement and every key derivation, and the provider derives no key without it |
| AEAD | authenticated encryption with associated data |
| Cover traffic | cells with no payload, sent to mask when a real message leaves: on top of the messages or in the empty slots of a constant-rate schedule; how much they mask is measured, not assumed (EXPERIMENT, blocks 1 and 7) |
| Link padding | a frame a node sends to its neighbour on an empty tick of its schedule; the neighbour drops it |
| Own-clock sending | a node sends one cell per tick of its own timer, not at the moment the cell arrives |
| Padding | bytes added to reach the constant cell size |
| Correlation attack | linking sender and recipient by timings and volumes |
| Unlinkability | the property that an observer cannot link sender and recipient |
| Forward secrecy | compromise of a long-term key does not expose past sessions |
| KK pattern | a handshake in which both sides know each other's static keys in advance: each of the two messages carries a fresh ephemeral key and mixes in agreements with the peer's keys; in the end-to-end layer these are the records kk1 and kk2 (CRYPTO, "End-to-end layer") |
| Hash ratchet | the key chain of one direction: every step derives a record key and the next chain key and wipes the previous one, so compromise of the current key does not expose past records; it gives no post-compromise recovery |
| KCI | key compromise impersonation: whoever knows a side's private key poses as someone else to that side; in KK this forges kk1, and the session rules reduce it to resetting a session that is absent, unconfirmed or stale |
| Offline deniability | a property of a transcript: the recipient can build one distributed like the genuine one without the sender's key, so a transcript together with the recipient's keys does not prove the sender's participation to a third party. It does not hold for a witnessed transcript, where the judge also holds an independent record of who transmitted the ciphertexts, such as a mailbox log tied to the sender's address; online deniability, against a judge acting with the recipient during the session, is not claimed (THREAT_MODEL, "Deniability") |
| End-to-end layer | encryption between two clients on top of the circuits: the KK handshake and the hash ratchet; nodes and the mailbox see only its records (CRYPTO, "End-to-end layer") |
| Mailbox | an exit that keeps queues of end-to-end records in memory and answers every request with a reply of a constant length (-exit mailbox) |
| Queue | the queue of records of one client at the mailbox; its identifier is the first 16 bytes of the hash of the fetch capability, and the first put into it creates it |
| Fetch capability (F) | 16 random bytes of the queue owner: whoever knows them takes records off the queue; the mailbox sees F in every request and keeps only the queue identifier |
| Record | an end-to-end ciphertext of a constant 392 bytes: the handshake record kk1 or kk2, or data under a ratchet key |
| Dummy record | a data record with an empty body that the client puts when no message waits; the mailbox and the nodes cannot tell it from a real one |
| Sticky record | the one record a client puts as copies of the same bytes on every tick until the mailbox answers that it stored it: a handshake record or the probe after a refused put |
| Contact card | the public data of a client for one contact: the suite, the mailbox address, the queue and the static key; the text `<suite>:<base64>`, its hash card_hash |
| Pin | the client takes a contact card once per process and afterwards refuses any other and stops |
| Client container | a client file of a constant size, 8224 bytes: the salt and two regions, each holding a volume or an empty volume. The file holds no keys, while the file and a volume password reproduce the identity key and F (ARCHITECTURE, "Client container") |
| Region | one of the two 4096-byte parts of the container file: r, the ciphertext and the tag; the region number enters the volume key |
| Volume | the content of one region under a key from a password: the version and the contact card; a container has one or two volumes, each under its own password |
| Decoy volume | the volume whose password the owner may surrender under coercion; the file in one state and this password do not show whether a second volume exists, under the assumptions of CRYPTO ("Container") and only for a generated password of the second volume |
| Empty volume | a region without a volume: empty content under a key from crypto/rand that is thrown away at once; sealed by the same code as a volume |
| Key from a password | the output of PasswordKey: the password stretched with the salt from the context at the suite's cost (Argon2id or PBKDF2 with HMAC-Streebog-512); in the container it is W |
| Volume key | k_s: the key derived from the key from a password, the salt of the file and the region number; the key of every sealing of the region, the identity key and F of the volume are derived from it |
| Pair from a secret | an agreement pair that DerivePair derives from a 32-byte secret and a context: one secret and context give one pair, others an independent one |
| File state | the bytes of the container file at one moment; the file is written once, so all states after creation are the same |
| Trust anchor | the CA public key the client trusts in advance, as the string `<suite>:<base64>` |
| Node certificate | a CA-signed record binding a node's name, address and signing key for a validity period |
| Node signing key | the node's long-term signing pair (identity key): it signs the certificate request and the descriptor and takes no part in key agreement; when nodes are authenticated its public half goes into the setup and link transcripts of the node |
| Onion key | the node key the client agrees a layer secret with during circuit setup; with rotation a node replaces it by epochs |
| Link key | the node public key (LinkPub in the descriptor) the initiator of a link to that node mixes into the handshake: the client for its entry, a node for the next node of a circuit |
| Node descriptor | a record signed by the node signing key: certificate hash, link key, onion key, epoch and a short validity |
| Onion key epoch | the number of the node's onion key in its descriptor: 0 for the first key of a process, one more after every rotation; the link key does not change with it |
| Grace period | the time a node still holds a replaced onion key: the descriptor lifetime plus the clock allowance after the rotation |
| Node bundle | the node certificate and descriptor in one JSON object, which the node serves to clients |
| Operator roster | the list of node names and addresses the operator allows certificates for |
| Node roster | the anchor with the names and addresses of the nodes of one issuance, sent to each of them; a node extends circuits only to roster nodes |
| Descriptor mirror | the node's own bundle and the bundles of the roster nodes it currently holds, served on /descriptors so that a client asks its entry alone; a roster node is left out while its bundle is missing, not yet started on the node's clock or within the mirror margin of its expiry; in place of the bundle of a refused node the mirror carries the proof of inconsistency (ARCHITECTURE) |
| Statement of a node | a bundle whose certificate verifies under the anchor at the node's address and whose descriptor its identity signed, whatever its time window: the signature says the node said it, the window says when it may be used (ARCHITECTURE, "Descriptor consistency") |
| Descriptor consistency rules | what any two statements of one node satisfy: one identity, one certificate, one link key, one onion key per epoch and one epoch per onion key, epochs published in order, an epoch ending Skew before the epoch after next begins; and one statement: a lifetime of at least 16 min unless the certificate cut it. An honest node never breaks them |
| Inconsistency proof | two signed statements of one node that break a consistency rule, in canonical order; every reader verifies it under its own anchor, the mirror carries it in place of the node's bundle, and the node is refused by nodes and clients |
| Mirror cross-check | a node with -consistency reads the mirrors of four randomly drawn roster nodes once per -consistency-every (1 min), feeds every statement of every node into that node's record, adopts a newer descriptor and refuses a node whose statements break a rule |
| Certificate issuance | the CA checks a node's signed request, carrying a nonce the CA chose, against the operator roster and signs the certificate |
| Counter order | on every link a node accepts only the counter one above the previous one, anything else closes the circuit; the client takes the numbers of replies the same way; the replay defence |
| Memory dump | a snapshot of process memory; the key extraction scenarios that will search it are planned ([#24](https://github.com/jimichi-org/jimichi/issues/24)) |
| ROC, AUC | the error curve and the area under it, the measure of success of the correlation attack and of the cell distinguisher |
| Discriminant | a linear rule that turns the features of a cell into one number, its score: w = S_t^-1 (mu1 - mu0), trained on the training runs (EXPERIMENT, "Traffic indistinguishability") |
| Cell labels | the truth "the cell carries a message" for every data cell of a client; a wrapper of the client's provider in the lab gives it, and the observer has no access to it (EXPERIMENT, block 7) |
| Rank of the true sender | for an exit flow, the number of entry flows scoring no lower than the true one, averaged over the exit flows; 1 when the true one is the only best |
| Degree of anonymity | the entropy of the adversary's distribution of the sender divided by log2 F, from 0 to 1; computed from ranks, an upper bound, and from the posterior distribution (EXPERIMENT, "Linking sender and recipient") |
| Effective anonymity set size | 2^H, the number of equally likely candidates with the same entropy H, from 1 to F |
| Bootstrap | a resampling method for confidence intervals |
