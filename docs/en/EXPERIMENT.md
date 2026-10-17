# Research programme

English | [Русский](../ru/EXPERIMENT.md)

The work answers one question: **what does resistance to traffic analysis cost in bandwidth and
latency in a three-hop chain with constant-size cells, and where does that resistance stop
working**. Everything else serves that answer.

Every run is reproducible: the configuration, the generator seed, the code version and the time
go into the report. Results live in artifacts/ and the figures are produced from those files.

Real clients start at unrelated moments, so in the lab harness each client's schedule gets a random
phase drawn from the run's seed. Clients started back to back would tick almost in phase and hand
the attack ties that a real network does not produce. The observation window also opens at a
random moment relative to the schedules; otherwise the last client to start would tick in step with
the windows.

Seeds: each repeat's seed is derived from the series' base seed, and separate streams for client
phases and for each flow's gaps are derived from it (splitmix64). Neighbouring repeats and flows
share no random sequence. The chains sampled in block 3 are drawn from a stream of their own,
derived from the seed in the same way. The seeds of the training runs of block 7 come from the base
seed through a stream of their own, and the shift and the permutation of the labels of its null
level from streams of their own of the run's seed. The phases of node clocks come from the node's
own generator, not from the seed, as in a real deployment. Every report row records the
configuration, the seeds, the code revision and the host load before and after the run.

## Adversary models

The codes are used in every results table. Measured so far: A1 with the count correlation attack
(block 1) and the choice of chains for A4 (block 3). The experiments for A3, A5 and A6 are planned,
see the status of each block; for A2 the cell distinguisher is in place (block 7) and its series is
planned.

| Code | Adversary | What it sees and can do |
|---|---|---|
| A1 | Passive on both sides | timestamps and packet sizes on the client-to-entry and exit-to-recipient links. A recipient client exists (the -peer client through a mailbox, ARCHITECTURE), but block 1 still measures the echo topology: the lab observer takes the link into the last node as the far side, and the last node echoes the message back. Measuring the topology of a conversation, two entries and the mailbox, is planned ([#47](https://github.com/jimichi-org/jimichi/issues/47)) |
| A2 | Passive on one side | the same, but only at the entry |
| A3 | Active network | delays, duplicates and drops cells, embeds a timing watermark in a flow |
| A4 | Node compromise | full access to some of the nodes, including process memory: one or two of the three nodes of a chain, k of the N nodes a client draws its chains from |
| A5 | Local on a machine | memory and disk of a node or a client during a session and after |
| A6 | Local with history | several snapshots of the container file over time |

The adversary knows the design and the source code. Security rests on keys and statistical
indistinguishability, not on the secrecy of the implementation.

## Metrics

### Linking sender and recipient

| Metric | Definition | Why it is used |
|---|---|---|
| ROC AUC | area under the error curve of the linking attack; a tie between a true and a false pair counts as half a pair | one number, comparable across configurations |
| Top-1 accuracy | share of entry flows whose highest-scoring exit flow is their own; when k exit flows tie for the highest score and the own one is among them, the flow counts 1/k | what an adversary that picks the best pair gets |
| TPR at FPR 0.01 | fraction of correctly linked pairs at a fixed false positive rate | an attack matters in the low false positive region |
| Precision at the base rate | TPR pi / (TPR pi + FPR (1 - pi)) at the operating point FPR 0.01 with the TPR there (row above): the share of true pairs among those the adversary calls linked, when a share pi of the candidate pairs is true. For linking pi = 1/F, F being the number of flows in the network the conclusion is about; the summary also gives it at the F of the testbed. It is a projection, not a measurement: the TPR and FPR measured on the testbed are taken to hold at F flows. The summary computes the TPR over the scores of all clean runs of a configuration together, with one threshold, and reports (pooled_negatives) the number of false pairs the FPR rests on. An adversary that reaches the same TPR at a lower FPR gets a higher precision. Undefined for pi outside (0, 1) and without positive decisions (TPR pi + FPR (1 - pi) = 0). Example: TPR 0.9, FPR 0.01 and pi = 1/1000 give 10/121, about 0.083 | guards against a false claim: with a thousand flows AUC 0.9 is nearly useless to the adversary |
| Rank of the true sender | for each exit flow the number of entry flows scoring at least as high as the true one (the true one included, a tie counted whole), averaged over the exit flows of a run: 1 when the true one is the single best, F when all tie. It is not a set of indistinguishable candidates: the adversary tells them apart but cannot drop any of them without risking the true one. Example: scores 0.9 for the true entry and 0.95, 0.9, 0.3 for the others give 3 | the intuitive form for the defence |
| Degree of anonymity by rank (upper bound) | r is the place of the true entry among the F entries of an exit flow by descending score; when t more entries share its score, each of the t + 1 places gets 1/(t + 1); scores are compared exactly, as for top-1 accuracy. q_r is the share of exit flows at place r over all clean runs of a configuration together, H = -sum over r of q_r log2 q_r in bits, d = H / log2 F. An adversary that knows only the order of the scores and judges each exit flow by itself gives the entry at place r probability q_r. One that sees the scores themselves knows at least as much, so against these scores the anonymity is at most d: an upper bound, not a measure of a strong adversary. An adversary that uses the fact that each entry is linked to exactly one exit and looks at the whole score matrix can know more, so against it the anonymity is no higher and d bounds it as well. A low d shows a low anonymity; a d near 1 shows only that this attack learns little. H over N exit flows is biased low, to first order by (K - 1)/(2N ln 2) bits, K being the number of places with q_r > 0, so H with the Miller-Madow correction, at most log2 F, is given beside it; its remaining bias is small and can have either sign, and near log2 F the cap leaves it slightly low; H is not taken over one run. Example: q = (1/2, 1/4, 1/4, 0) with F = 4 gives H = 1.5 and d = 0.75; with counts 20, 10, 10, 0 over all runs (N = 40) the corrected H is 1.5 + 2/(80 ln 2), about 1.536 | the formula of the degree after Díaz et al. (2002); the number belongs to this attack |
| Degree of anonymity by posterior | pair scores are calibrated on the other runs of the same configuration by isotonic regression of the pair truth on the score (equal scores in one block), with one true pair added below all scores and one false pair above all, so every block holds a true and a false pair and the calibrated probability c lies strictly between 0 and 1; a score between training scores takes the block of the nearest training score not above it, a score below all the lowest block. For an exit flow of the held-out run the probability of an entry is proportional to c/(1 - c): the posterior under equal prior probabilities and entry scores independent given the sender. d is the mean entropy of the posterior over exit flows, divided by log2 F; it holds only when the calibration holds for the held-out run, and by itself it is neither an upper nor a lower bound. The mean -log2 of the probability of the true sender (the cross-entropy) is given beside it: with the calibration taken from other runs its expectation is at least the entropy of the sender given the entry scores of that exit flow, without the independence assumption, so it bounds from above the anonymity against the strongest adversary that judges by these scores. An adversary that uses the fact that each entry is linked to exactly one exit and looks at the whole score matrix can know more; against it the anonymity is no higher, and the cross-entropy bounds it as well. When the cross-entropy is below the mean entropy, the posterior is underconfident and d overstates the anonymity: against that adversary the degree is at most the cross-entropy divided by log2 F. When it is above, the posterior is miscalibrated for the held-out run and d is unreliable, while the cross-entropy still bounds the anonymity from above. Numbers are planned on the data of the full series ([#23](https://github.com/jimichi-org/jimichi/issues/23)). Example: calibrated c = 1/3, 1/2 and 2/3 for three entries give odds 1/2, 1 and 2 and the posterior (1/7, 2/7, 4/7) | a measure against an adversary that uses the score values |
| Effective anonymity set size | 2^H, the number of equally likely candidates with the same entropy, from 1 to F; Serjantov and Danezis (2002) call H itself, in bits, the effective size. By rank 2^H for H without and with the correction, by posterior 2 to the mean entropy. In the rank example 2 sqrt 2, about 2.83 | the intuitive form for the defence |

Every report row carries ROC AUC, top-1 accuracy, TPR at FPR 0.01, the rank of the true sender
(true_rank) and the places of the true entry (rank_counts). The summary over the clean runs of a
line gives the median rank, the precision at the base rate at the F of the testbed and at a pi fixed
before the series (-base, 1/1000 by default), with the TPR over the scores of all runs together and
the number of wrong pairs, the degree of anonymity by ranks and the effective set size, plain and
with the Miller-Madow correction, given two clean runs or more (with one those fields are null).
The posterior degree is in lab/metrics and checked by tests with hand-computed answers; its numbers
are planned on the data of the full series ([#23](https://github.com/jimichi-org/jimichi/issues/23)).

### Compromised chains

| Metric | Definition |
|---|---|
| Share of chains with a rogue entry and exit | share of the chains whose first and last node are both rogue, that is held by the adversary, who then links the two ends of the circuit; a chain of one node counts when that node is rogue. A uniform choice of h distinct nodes among N, k of them rogue, gives k(k-1)/(N(N-1)), and k/N for h = 1 |
| Share of chains with a rogue node | share of the chains that hold at least one rogue node; a uniform choice gives 1 - C(N-k,h)/C(N,h) |
| Share of refused attempts | share of the attempts to build a chain whose entry serves a mirror the client refuses, one that lacks more than min(-missing, N - h) listed nodes or lacks a verified bundle of the entry itself; a listed bundle that fails the check counts as lacking |
| Share of attempts failed at setup | share of the attempts in which the client chooses a chain the nodes do not set up: an honest node extends a circuit only to a node whose verified descriptor it holds, so a chain with an honest node directly before a node that withholds its descriptor fails. The two shares of chains above are taken over the chains that come up |
| Share of the route recovered | R, the share of route positions whose occupant the adversary names right. Positions for echo: the client, then the nodes of the chain in order. For a -peer client the mailbox of the testbed is known to everyone and is not a position: a side is the client, the entry and the middle hop. A rogue node that follows the protocol knows the position before it (the client for the entry), its own and the next. The views of rogue nodes are joined only when the adversary has linked their circuits (linked pair below); a linked view that names some position otherwise than the views already joined is not added, so the result depends on the order of joining. The R of a chain is taken over one linked component of its rogue views and one order of joining the views of that component, those under which the most positions of the chain are named right; unlinked views are not joined. The harness, not the adversary, picks the component and the order by the truth, so R is an upper bound on what the adversary can claim by such joining. An order that starts with the chain's own views keeps all they know, so the R of a chain is at least the R of each of its views alone and, when all of them are in one component, at least the R of its views joined; when each echo chain has its own client and a -peer process keeps its entry, no joining at three hops names right more positions of the chain than its views know together, and when all its views share a component, R is exactly that. A position the adversary does not name, or names wrong, does not count. With three hops R is 3/4 for the echo entry, 3/4 for the middle and 2/4 for the exit; for a -peer side R is 1 for the entry, 2/3 for the middle and 1/3 for the mailbox. The attack in which a node hands its neighbours different onion keys is not part of it (THREAT_MODEL) |
| Model of the share of the route recovered | the distribution of the number of known positions when the chain is drawn uniformly from full mirrors and the views of the rogue nodes of a chain are joined. The exit is drawn with the chain (echo) or pinned to an honest or a rogue node (the mailbox of a -peer client). It is summed over the positions of the chain, each holding a rogue or an honest node drawn without replacement, and gives the mean and the standard deviation of R, the share of chains with a rogue exit and the shares of chains with a rogue entry and exit and with a rogue node. In a chain longer than three nodes a middle does not know its index, so there the model is an upper bound |
| Share of chains with content revealed | the share of chains at least one message of which was found byte for byte inside anything the rogue nodes recorded, among the chains that sent at least one message; the number of the others is given. In the compromise scenarios (planned, block 3) the messages are filled with random bytes after the flow and message numbers, since a containment search would otherwise find, for example, a message of zeros in any record that holds zeros; the metric refuses a message whose bytes are all equal. The unit is the chain, not the message: the messages of one chain are revealed together, and a binomial error over the messages would be too small. Model: the share of chains with a rogue exit for echo (k/N for a uniform choice); 0 for a -peer client, since the mailbox holds only end-to-end records. Over the revealed chains the share of messages found is given as well; it is close to 1, messages that had not reached the exit when the run ended are not found |
| Lag score of a pair | two colluding nodes record on one clock one event of each of their circuits, setup or close: a_i at the first node and b_j at the second. When either event was not recorded the score is undefined. Setup: 1/(1 + (b_j - a_i) in seconds) when b_j is not before a_i; when it is, the order of events rules the pair out (the second node gets a setup only after the first has extended it), and the pair scores below the undefined score: a ruled-out pair is certainly false, while an undefined one only lacks a record. A close travels both ways along the circuit, and the exit may close it before the entry (idle time, age, a break further on), so the order of closes rules no pair out and the score is symmetric, 1/(1 + \|b_j - a_i\|). The score is bounded, so no lag drops an admissible pair below a ruled-out one. ROC AUC and TPR at FPR 0.01 are taken over all pairs, top-1 accuracy over the circuits of the first node that pass the second, as for linking sender and recipient |
| Shared link score of a pair | for adjacent rogue nodes: 1 when the outgoing link of one and the incoming link of the other are one link (the address and port of each end match crosswise; an IPv4 address in IPv6 form equals the IPv4 address), 0 when not, undefined when the link was not recorded. A link carries one circuit, so as long as no address pair of a link repeats within a run (the block 3 scenario checks this in every run, planned), ROC AUC and top-1 are 1 here by construction |
| Linked pair | the adversary links a circuit of the first node to a circuit of the second when the score of the pair is above 0 and the single highest both among the pairs of that circuit of the first node and among the pairs of that circuit of the second: a circuit passes each node once, so the link is mutual. When several pairs share the highest score (exact equality) there is no link: a pick between equals is not a link. A circuit of the first node that does not pass the second can link to another one; the share of false links among those made is given separately. The views of linked pairs are joined for the share of the route recovered |
| Time to link | the smallest observation window of a grid set before the series from which on top-1 accuracy over the circuits that pass both nodes is 1 at that window and at every larger window of the grid; null when it is below 1 at the largest window. A single tie keeps top-1 below 1. The top-1 at every window is given next to it. The setup lag score does not depend on the window: the time is 0 when its top-1 is 1, and null otherwise. Over runs the median is given in which runs that never linked rank above every window of the grid (null when such a run falls in the middle), with the number of such runs |
| Joining of conversations at the mailbox | the mailbox joins two circuits when one puts into the queue the other fetches from; one direction is enough. The share is the number of conversations at least two circuits of which are joined, over the number of conversations of the run; pairs of circuits of different conversations are counted separately as false |
| Request feature at the mailbox | the ROC AUC of a feature of a request, such as "the request carries a put", against the truth "the request's record holds a message", over the requests sent while the sender's session is established and not stale: before the session is established a put carries only the handshake record until the mailbox has stored it, and while the session is stale no new record is sealed, so there the put follows the handshake, not the messages or the cover, even with -cover-puts. A message always rides a put, so the AUC of the put feature is 0.5 + q/2, q being the share of requests without a message that carry no put either. With -cover-puts a request lacks a put only on a tick where the window of puts is full, and the AUC is exactly 0.5 only when there was no such tick; the number of requests without a put is given, and equality with guessing is claimed only by equivalence. The requests of the two circuits of one conversation and of a rebuilt circuit are dependent, so the bootstrap runs over conversations and gives an interval inside one run; the unit of comparison is the run |
| Standard error of a share | sqrt(p(1-p)/n) for a share of n independent draws at the value p the model gives; n is the number of chains that came up, and the number of attempts for the refused and the failed shares; for the mean share of the route recovered over n chains (over n processes for -peer clients) it is sigma/sqrt(n), sigma being the standard deviation of R the model gives: R takes several values, and the binomial formula does not apply to it |

### Traffic indistinguishability

Status: implemented, no numbers yet. The distinguisher separates payload cells from cover cells on
the client-entry link by the moments of the cells of a flow and of the replies to them (adversary
A2); the set `cmd/lab -set cover`, the labelling of cells, the features and the report are described
in block 7. The flow distinguisher is planned.

| Metric | Definition |
|---|---|
| Cell distinguisher AUC | a linear discriminant over the features of a cell: w = S_t^-1 (mu1 - mu0), mu1 and mu0 being the feature means of payload and cover cells and S_t the sum of (x - mu)(x - mu)^T over all training cells, mu their mean. For two classes S_t = S_w + (n1 n0 / n)(mu1 - mu0)(mu1 - mu0)^T, S_w being the within-class scatter, so when S_w is invertible w points as Fisher's discriminant S_w^-1 (mu1 - mu0); it is also the least-squares direction for the class label (Hastie, Tibshirani, Friedman, 2009). When a combination of features is constant within each training class and differs between the classes, S_w is singular and w follows that combination: dropping it would hide the strongest leak. A feature constant over the training cells or a linear function of the features before it (1 - R^2 at most 1e-9) is not used; this rule also loses a combination whose spread is below about 1e-4 of the feature standard deviation, so the feature set is built without exact linear relations and the features left out are printed. A cell scores w·(x - (mu1 + mu0)/2) / (w·(mu1 - mu0)): the training class means score +1/2 and -1/2, so, while no feature is left out by the rule above, the scores do not depend on the units of the features and all runs of the series share one scale. AUC against the truth "the cell carries a message", the interval within a run by a bootstrap over flows. Training uses the cells of separate training runs of the same configuration, run before the series with seeds from a stream of their own and not part of it; every run of the series is a test run. The direction is fixed before the series and is the same for all of its runs, so the per-run AUCs of the series are independent given it, an AUC below 0.5 is not replaced by 1 - AUC, and under indistinguishability it is 0.5 on average, with no upward shift. Undefined (NaN, null in the report) when the test run lacks cells of one class (in the immediate mode without -cover there are no cover cells); when the training gives no direction (it lacks cells of one class, no feature is left, or the class means agree on every feature left), the AUC is undefined for the whole configuration. Such a run stays out of the medians and is counted separately in the summary, with the reason; a configuration without a direction makes no indistinguishability claim by AUC, and its D and TV are given as usual. Example: training (2, 0), (4, 0) with a message against (0, 1), (0, 3) gives S_t = [[11, -6], [-6, 6]] and w = (1/5, -2/15), that is 2/15 of Fisher's w (3/2, -1); the test (3, 1), (1, 1) against (1, 0), (0, 2) scores 9/26 and -3/26 against 1/26 and -1/2 and orders 3 pairs of 4 right, AUC 0.75 |
| AUC of a feature | the same distinguisher on one feature: the direction by the sign of the difference of the class means over the training runs, AUC on a run of the series without folding; undefined when the feature is constant in training or the class means are equal. Shows which feature separates the classes |
| Kolmogorov-Smirnov distance | D = max over x of \|F_a(x) - F_b(x)\| between the empirical distribution functions of a feature of payload cells (a) and of cover cells (b) of one run; equal values by the rule of section "Comparisons" make one step. When D and AUC take values as equal by one rule, \|AUC - 0.5\| <= D for the feature itself as a score on the same sample. No p is given within a run: the values of one flow are dependent, and even for independent values the asymptotic formula is not exact at these sizes (8 and 8 values, D = 1/2: 0.188 against the exact 1819/6435, about 0.283). Beside it the null level: D of the same run after a random circular shift of the label sequence of each flow, one draw of the shift per run. The shift keeps the group sizes, on which D depends, and the clustering of messages in time, and breaks only the link between labels and features; the null level holds when, without a leak, the labels do not depend on the features and the processes within the run are stationary. A random permutation of the cell labels keeps the sizes but not the clustering: with clustered labels and slowly changing features its D is too low. Runs are compared by D and the null level, section "Comparisons". Example: a = {1, 2, 3, 4} and b = {3, 4, 5, 6} give D = 1/2 |
| Total variation over bins | TV = 1/2 sum over k of \|p_k - q_k\| for B = 16 bins of equal frequency of the pooled sample of N values of both groups: a group of equal values whose smallest place in ascending order is r (from 0) goes whole into bin floor(B r / N); the bins are built without the labels. (1 + TV)/2 is the accuracy of the best rule that judges the group by the bin of one value at equal group shares. Bins coarsen the distributions (for the interleaved samples 1, 3, ..., 31 and 2, 4, ..., 32, TV over 16 bins is 0 although they share no value), and for small groups the sample TV is biased up even for one distribution, so it is neither an upper nor a lower bound; the null level is given beside it, as for D. Example with three bins: a = {1, 3} and b = {2, 4, 5, 6} give p = (1/2, 1/2, 0), q = (1/4, 1/4, 1/2), TV = 1/2 |
| Precision at the base rate | as for linking, over the scores of the cell distinguisher of all runs of the series together: they share one direction, so one threshold over them is meaningful; pi is the share of payload cells in the network the conclusion is about; the summary of block 7 gives it at the share of payload cells in the clean runs of the series with a defined AUC, with the number of cover cells the FPR rests on |
| Flow distinguisher (planned) | D and TV of the inter-arrival gaps of flows that carry messages against flows that send only cover cells; the null level: the same distances after a random split of all flows of the run into groups of the same sizes. Needs a testbed mode in which some clients send no messages |

### The price of protection

| Metric | Definition |
|---|---|
| Bandwidth multiplier | frames on a link within the observation window over messages handed to the clients. Reported separately for the client-entry link and for the observed link between nodes, in each direction. The window opens when the flows start sending, once the setup of every flow has crossed every observed link: circuit setup and anything sent before it are excluded. Clients send only while the window is open. A frame at the moment the window opens counts, a frame at the moment it closes does not. A message handed over just before the window closes can cross a link, or come back, after it closes, so a single run without protection can read one frame per such message below x1 there; such runs are rare, and the median of a series without protection stays at x1 |
| Goodput (planned, [#118](https://github.com/jimichi-org/jimichi/issues/118)) | payload bytes per second per client |
| Latency | median, 95th and 99th percentile. The lab harness measures the round trip: from handing a message to the client to the exit's echo coming back, matched to its message by sequence number, not by order |
| Cost per cell | nanoseconds of CPU and allocations to strip a layer |
| Cost per session | nanoseconds to agree a key, per suite |

### Key material hygiene

Status: planned, not implemented ([#24](https://github.com/jimichi-org/jimichi/issues/24)). The
lab takes no memory dumps and records no setup cells yet. That a replaced onion key stops opening
setups after its release is covered by the tests of the node; the fraction against the age of a
cell is not measured.

| Metric | Definition |
|---|---|
| Extraction success rate | in what fraction of N attempts the key is found in a dump |
| Key lifetime window | time from the end of a session until the key no longer appears in memory |
| Decrypted fraction after a node key theft | forward secrecy check: zero for a wire capture (links run on ephemeral keys); for a neighbour that kept the setup cells, the fraction of them whose layer opens with the keys in node memory, by the age of the cell at the moment of the theft. With onion key rotation it is expected to be one while the key of the cell is held and zero past the rotation period plus the descriptor lifetime plus the clock allowance; without rotation one for the whole time the node ran |

### Client container

Status: the container is implemented (ARCHITECTURE, "Client container"), its metrics are planned
([#20](https://github.com/jimichi-org/jimichi/issues/20)). NIST STS and entropy can show only
that the ciphertext has no statistical structure; they do not show that a second volume is
deniable. That is the task of the volume distinguisher.

| Metric | Definition |
|---|---|
| NIST STS pass rate | out of the 15 tests, over at least 100 containers |
| Entropy per byte | estimated from the sample, close to eight expected |
| Volume distinguisher AUC | a classifier separates one-volume from two-volume containers; 0.5 expected |
| Brute force cost | Argon2id parameters, time to open, cost estimate for a password of a given entropy |

## Experiment blocks

### Block 1. Flow linking, adversary A1

Status: partly implemented. The lab runs the baseline attack over the series with cover traffic,
a constant rate at the client and nodes on their own clocks; the rest of this block is planned.

Baseline attack, implemented: Pearson correlation of cell counts per window on the client-entry
link and on the link into the last node, every entry flow against every exit flow. Stronger
attack, planned: gradient boosting over window features (cell count, variance of intervals, gap
lengths, autocorrelation), trained on one sample and evaluated on another, split by time. A
deep-learning correlator as the strongest adversary is planned as well
([#67](https://github.com/jimichi-org/jimichi/issues/67)).

| Factor | Levels |
|---|---|
| Cover traffic | none, 0.5 of payload, 1.0, 2.0 |
| Client schedule | at once, constant rate where a payload takes the slot of a cover cell |
| Cell size | constant; a variable size is not implemented: the cell has one size and no switch, so this factor is not measured. Message size classes are planned ([#68](https://github.com/jimichi-org/jimichi/issues/68)) |
| Node delay | none, sending on the node's own clock; uniform, exponential and batching by k cells are planned ([#45](https://github.com/jimichi-org/jimichi/issues/45), [#82](https://github.com/jimichi-org/jimichi/issues/82)) |
| Concurrent flows | 2, 5, 10, 20 |
| Primitive suite | GOST, X25519 |

Plan: one factor at a time against the baseline, then a full factorial over the subset where cover
traffic and delay are expected to interact. The headline result is the curve of bandwidth
multiplier against attack AUC; confidence intervals across runs are planned with the full series
([#23](https://github.com/jimichi-org/jimichi/issues/23)).

### Block 2. Active adversary A3, timing watermark

Status: planned, not implemented ([#116](https://github.com/jimichi-org/jimichi/issues/116)). The
lab has no active adversary and no watermark detector, and batching at nodes, which this block
will test, is planned as well ([#82](https://github.com/jimichi-org/jimichi/issues/82)). Of the
table below only the flow_closed and flow_closed_after fields of the report rows exist; the lab
has no series over the ratio of periods.

The adversary will delay cells at the entry following a pattern and look for that pattern at the
exit. This is stronger than passive correlation and will test whether batching helps.

| Measured | Metric |
|---|---|
| Watermark detectability | AUC of the watermark detector at the exit |
| Resistance threshold | batching parameters at which the watermark stops being detected |
| Price of resistance | added delivery latency that buys it |
| Circuit survival | share of circuits still open at the end of a run and time to the first closed circuit, against the ratio of the node period to the client's, from the flow_closed and flow_closed_after fields of the report rows; one lost or reordered cell closes a circuit |

### Block 3. Node compromise, adversary A4

Status: partly implemented. The choice of the chain is measured (`cmd/lab -set paths`). The trust
boundary of the testbed is checked by a lab test with real nodes and a client in one process: a
node certified by a second CA joins no chain of a client without -peer (below). The metrics of the
scenarios with rogue nodes (section "Compromised chains") and the procedures of agreement with a
model (section "Comparisons") are implemented in lab/metrics and checked by tests with
hand-computed answers. The view of a node, that is what the testbed's nodes see and link, is not
measured in this revision: what a node that follows the protocol knows is given by the model
derived from the protocol ([#117](https://github.com/jimichi-org/jimichi/issues/117)). The lab
has no scenario in which nodes record what they see, and replay and tampering are covered by the
tests of the node and of the client, not measured as a share.

| Scenario | Metric |
|---|---|
| One node of three | what the node holds: its neighbours and one layer, and at the echo exit also the messages and the cover flag; share of the route recovered and share of chains with content revealed, against the model |
| Entry and exit nodes | ROC AUC, top-1 accuracy and TPR at FPR 0.01 by the lag of setup and of close and by the cell counts on their inbound links, time to link, share of false links; share of the route recovered with the views joined over linked pairs |
| Middle and one edge node | linking by the shared link, exact by construction; share of the route recovered |
| Inserted node with a valid certificate | for echo and for -peer clients, for a certificate of a second CA and of the compromised CA: shares of chains with a rogue node and with a rogue entry and exit, share of chains with content revealed, share of refused attempts; for echo and one node of a second CA among five, chains of three and -missing 1, the shares of chains, the failures and the share refused are checked by the trust boundary test (below) |
| Rogue mailbox (-peer clients) | joining of conversations, request feature, share of the route recovered per side |
| Choice of the chain with k rogue nodes among N | share of chains with a rogue entry and exit and share of chains with a rogue node, over the chains that come up among those drawn with the client's own choice, against the values the model gives: with full mirrors, with rogue entries that leave honest nodes out of their mirrors, and with rogue nodes that withhold their descriptors |
| Ordered pairs of nodes kept busy from one address (planned, [#125](https://github.com/jimichi-org/jimichi/issues/125)) | share of the surviving chains with a rogue entry and exit and with a rogue node, against the addresses and circuits the adversary spends (LIMITATIONS, node limits) |
| Replay and tampering | share of replayed, reordered or altered cells that go no further than the first party able to check them: forward that is the first node that sees them (a cell out of turn closes the circuit, an altered one is dropped); backward the first node checks the order, and the altered body of a reply is checked only by the client, which closes the circuit; one hundred percent expected |

The block is to conclude which share of the chain must be compromised to destroy the property,
and whether that matches the theoretical probability of picking a compromised chain.

The choice of the chain is measured without traffic and without nodes. `cmd/lab -set paths` makes
-samples attempts to draw a chain of -hops nodes among -nodes the way the client does, with the
client's own functions for the entry, for taking or refusing its mirror and for the rest of the
chain, on a stream derived from -seed in place of the system generator: the entry among all the
nodes, a refusal when its mirror lacks more than min(-missing, N - h) of them (the bound) or a
verified bundle of the entry itself, the
other hops among the nodes the mirror holds. A chosen chain then comes up when every node on it
extends the circuit to the next one, and here the lab applies the rule of the node: an honest
node extends only to a node whose descriptor it holds, a rogue node to any node. The first
-rogue nodes are rogue and act together:

| Flag | What the rogue nodes do | What it does to the chains |
|---|---|---|
| -leftout o | as an entry each leaves o honest nodes out of its mirror | the exit of a rogue entry is drawn among N - o - 1 nodes, k - 1 of them rogue |
| -withhold w | w of them keep their descriptors from the honest nodes | the mirror of an honest entry lacks w nodes: within the bound its chain is drawn among the N - w nodes the mirror holds, beyond it the attempt is refused. No honest node extends a circuit to a withholding node, so a chain chosen through a rogue entry fails at setup when an honest node stands directly before one |

With both at 0, the default, every mirror is full, every chain comes up and the choice is the
uniform one. An attempt ends in one of three ways: it is refused, its chain fails at setup, or
its chain comes up. The report gives the shares of refused and of failed attempts and, over the
chains that came up, the two shares of chains, each next to the value the model gives and the
standard error of a share at that value, and the values of a uniform choice next to them. A
configuration in which no attempt gives a chain that comes up is turned away: there is no chain
to take a share of. The report row carries nodes, hops, rogue_nodes, missing, left_out,
withheld, samples, seed and rev, so the same sample can be drawn again. The report file is named
after all of these but rev and after the second it is written in, so two runs within one second
overwrite each other only when they differ in nothing but rev.

Rows drawn at one seed read the same stream: while no attempt is refused they draw the same
entries, and an honest entry with a full mirror draws the same chain. Such rows are not
independent samples, and their shares can coincide to the last digit: with -leftout within the
bound and no -withhold the sampled share of chains with a rogue node is that of full mirrors at
the same seed. Rows meant as independent samples take different seeds.

The values the model gives are computed exactly, the chains of a rogue entry by summing over
the kind of node in each position, and are checked in the tests of the metric against every
chain the client can choose, taken one by one. A sampled share differs from its value by about
the standard error. Where the value is 0 or 1 the share is exact by construction: every draw
gives the same answer, the sampled share equals the value for any seed and any number of
samples, the standard error is 0, and the row says nothing about the choice. The common cases:

| Row | Exact share |
|---|---|
| no rogue node, or every node rogue | both shares of chains, 0 or 1 |
| one rogue node, chains of two nodes or more | a rogue entry and exit, 0 |
| two rogue nodes, both withholding, chains of three nodes or more | a rogue entry and exit, 0: an honest node stands before the exit and does not extend to it |
| fewer honest nodes than hops | a rogue node, 1 |
| the mirrors of the honest entries are refused (-withhold above the bound) | a rogue node, 1 |
| the mirrors of the rogue entries are refused (-leftout above the bound) | a rogue entry and exit, 0 |
| no mirror lacks more than the bound | refused attempts, 0 |
| no node withholds, or chains of one or two nodes | attempts failed at setup, 0 |

The printed row gives four decimals. A value they would round to 0 or 1 is printed to two
significant digits of its distance from it, so a printed 0.0000 or 1.0000 is exactly 0 or 1. A
sampled share can be exactly 0 or 1 too: a share is exact by construction only when its bracket
also reads 0.0000 or 1.0000 +- 0.0000.

For N = 5, k = 2 and h = 3 there are 5 * 4 * 3 = 60 ordered chains. Six have rogue nodes at both
ends (2 choices of the entry, the other rogue node as the exit, any of the 3 honest nodes
between them): 6/60 = 0.1 = k(k-1)/(N(N-1)). Six hold no rogue node (the three honest nodes in
any order), so 54/60 = 0.9 = 1 - C(3,3)/C(5,3) hold one. The test of the metric enumerates the
60 chains and requires exactly these values.

With -leftout 1 in the same configuration a rogue entry serves four nodes and draws its two
further hops among the three others: 3 * 2 = 6 chains, two of them ending at the other rogue
node. An honest entry serves all five: 4 * 3 = 12 chains, ten of them with a rogue node. The
entry is any node with 1/5, so both ends are rogue with 2/5 * 2/6 = 2/15 against 0.1 for full
mirrors, and a rogue node is in 2/5 + 3/5 * 10/12 = 0.9 of the chains, as before. No node
withholds its descriptor here, so every chain comes up.

With -withhold 2 and -missing 1 the mirrors of the three honest nodes lack two nodes and are
refused, 3/5 of the attempts. Every chain the client chooses enters through a rogue node, which
serves all five: 12 chains. In three of them an honest node stands before the other rogue node,
whose descriptor it does not hold, and the chain fails at setup: 2/5 * 3/12 = 1/10 of the
attempts. The other nine come up, 3/10 of the attempts, and each ends at an honest node. So of
the chains that come up every one holds a rogue node and none has a rogue entry and exit, where
the choice alone, before setup, gives 3/12 = 1/4: by withholding, the two nodes take every entry
and lose the exit. With -withhold 1 nothing is refused, 1/20 of the attempts fail at setup, and
of the chains that come up 1/19 have a rogue entry and exit and 15/19 a rogue node. The tests
enumerate the chains of these cases as well.

A -peer client draws its chain otherwise: the exit is pinned to the mailbox, the entry is drawn
among the other N - 1 nodes and the middle hops among the rest (ARCHITECTURE, "Choice of the
chain"). The paths set models a random exit, so for a pinned exit the values are worked out by
hand, for N = 5, k = 2, h = 3 and full mirrors:

| Mailbox | Both ends rogue | At least one rogue node |
|---|---|---|
| honest | 0: the exit is honest | 1 - 2/4 x 1/3 = 5/6: both the entry (2 of 4) and the middle hop (1 of 3) honest |
| rogue | (k - 1)/(N - 1) = 1/4: the entry is the other rogue node | 1 |

A rogue entry that leaves one honest middle hop out of its mirror and closes the circuits with an
honest middle hop gets its colluder as the middle hop with probability 7/8 under an honest
mailbox: a -peer client draws its middle hops at most three times per process (LIMITATIONS). A
rogue mailbox that leaves the requests through an honest middle hop unanswered gets its colluder
as the middle hop with probability 19/27 under an honest entry, and so learns the entry. These
cases are not measured in the lab: nodes that close circuits or leave requests unanswered are not
part of the block; the values 7/8 and 19/27 are checked by enumerating every outcome of the draws
(cmd/client tests, LIMITATIONS).

The share of the route recovered by the model for N = 5, h = 3 and full mirrors. The echo route
has four positions (for echo exactly one known position never occurs: a rogue node knows at least
itself and a neighbour):

| Configuration | Shares of chains with 0, 2, 3 and 4 known positions | E[R] | sigma(R) |
|---|---|---|---|
| echo, k = 1 | 2/5, 1/5, 2/5, 0 | 2/5 | sqrt(23/200), 0.339 |
| echo, k = 2 | 1/10, 1/5, 1/2, 1/5 | 27/40 | 11/40 |

A side of a -peer client has three positions (the client, the entry, the middle hop; the mailbox
is known to everyone):

| Configuration | Shares of sides with 0, 1, 2 and 3 known positions | E[R] | sigma(R) |
|---|---|---|---|
| honest mailbox, k = 1 | 1/2, 0, 1/4, 1/4 | 5/12 | sqrt(3)/4, 0.433 |
| honest mailbox, k = 2 | 1/6, 0, 1/3, 1/2 | 13/18 | sqrt(41)/18, 0.356 |
| rogue mailbox, k = 1 | 0, 1, 0, 0 | 1/3 | 0 |
| rogue mailbox and one more node, k = 2 | 0, 1/2, 1/4, 1/4 | 7/12 | sqrt(11)/12, 0.276 |

Echo, k = 1: the rogue node is the entry, the middle and the exit of 12 of the 60 chains each and
knows 3, 3 and 2 positions, and it is absent from the other 24: E[R] = (3/4 + 3/4 + 2/4)/5 = 2/5,
E[R^2] = 2/5 x 9/16 + 1/5 x 1/4 = 11/40, sigma^2 = 11/40 - 4/25 = 23/200. The binomial value
sqrt(p(1-p)) at p = 0.4 would be 0.490, 1.44 times larger. Echo, k = 2: exactly one rogue node
on 36 chains (12 per position), both on 18 (entry and middle know all four positions, middle and
exit three, entry and exit four with the views joined), none on 6:
E[R] = 36/60 x 2/3 + 18/60 x (1 + 3/4 + 1)/3 = 27/40. One side of a -peer client with an honest
mailbox and k = 1: the entry is rogue with probability 1/4 and names the client, itself and the
middle hop, R = 1; the middle hop is rogue with probability 3/4 x 1/3 = 1/4 and names the entry
and itself, R = 2/3; E[R] = 1/4 + 1/6 = 5/12. A rogue mailbox names the middle hop, 1/3 of each
side, exactly by construction. The tests of the metric enumerate all 60 and 12 chains and every
configuration of up to six nodes and four hops.

The model joins the views as if the rogue nodes of a chain had linked their circuits. Adjacent nodes
link them by the shared link, exactly. Entry and exit link them by the setup lag: when circuits are
set up one at a time and the next starts only once the setup of the previous one has reached its
last node, the first exit event after an entry event belongs to the same circuit, top-1 accuracy
over the circuits that pass both nodes is 1 by construction, and each such link is mutual. ROC AUC
can still be below 1, since it compares pairs of different circuits: entries at 0, 310 and 320 ms
and exits at 300, 315 and 325 ms give top-1 1 and AUC 17/18 (the true pair of the first circuit,
1/1.3, is below the false pair of the second entry and the third exit, 1/1.015). A circuit of the
rogue entry with an honest exit can then link to a circuit of an honest entry that passed the rogue
exit; when every chain has its own client, such a false link neither raises nor lowers R: the view
of the other chain names the positions of this one wrong or as its own view does, and a joining that
starts with its own view keeps all that view knows. The measurement comes from setting up several circuits at once: there linking can
miss, tie or fail to be mutual, and the R of a chain falls below its R with the views joined only
when the chain passes both nodes and its circuit is left unlinked or linked to a wrong partner. The
gap is measured for one linker, the mutual best without tie-breaking: a linker that breaks ties at
random or matches the circuits one to one over all pairs can link circuits this one leaves unlinked,
so the gap describes this linker and is not a property of the system. A score of minus the lag with
the undefined score -2 for ruled-out pairs would put a true pair with a lag over 2 s below the
ruled-out ones: entries at 0, 1 and 3 s with exits at 0.5, 1.2 and 5.5 s would give top-1 2/3 and
AUC 7/9 instead of 1 and 17/18.

The bundle of a node with a certificate of a second CA fails the check against the anchor. Such a
node is in no mirror, honest nodes do not extend to it, and the mirror it serves as an entry is
refused: it lacks a verified bundle of the entry itself. An honest mirror then lacks k nodes. When
k is at most min(-missing, N - h), the chains of honest entries come up without these nodes: the
shares of chains with a rogue node and with rogue ends are 0, failures 0, refusals k/N for echo
and k/(N - 1) for a -peer client with an honest mailbox, which draws its entry among the N - 1
nodes other than the mailbox; otherwise every attempt is refused. When the mailbox itself is of
the second CA, it is in no mirror, and every attempt of a -peer client is refused. With N = 5,
h = 3 and k = 1 that is 1/5 refused for echo and 1/4 for -peer at -missing 1 and 2, and every
attempt refused at -missing 0. For echo and k < h these are the shares the mirror model gives
with -leftout N - k and -withhold k: N - k exceeds the bound at any -missing, and the rogue entry
is refused. For k of at least h and -missing of at least N - k that -leftout falls within the
bound and would let the rogue entry through, so the model of a second CA is stated on its own;
the tests enumerate every chain of up to six nodes with a drawn and a pinned exit. A node of the
compromised CA is chosen like any other: for echo the shares of the uniform choice, 0 and 3/5 for
k = 1, 1/10 and 9/10 for k = 2; for -peer the shares of the pinned exit (the table with the
Mailbox column above).

The trust boundary is checked by a lab test with real nodes: five nodes of the relay package in
one process over loopback, enrolled the way enroll does it, four under the CA of the testbed and
one under a second CA, each with an onion key of its own, peer checks and an echo exit. The test
assembles each node's peer table and mirror by the rule of cmd/relay: a node takes a peer's keys
with the node's function verify.Peer against the anchor of its own CA (the one its roster would
name), and its mirror holds its own bundle and the bundles of the peers it took. The test has no
roster and no descriptors or mirrors over HTTP (the cmd/relay tests and e2e cover them); the
per-address limits are off as in the harness, the nodes forward at once rather than on their own
clock, and no onion key rotates during the test. The client holds the anchor of the testbed's CA,
node authentication (-auth, the default), -missing 1, chains of three nodes and a drawn exit,
without -peer.

| Check | Expected |
|---|---|
| verify.Peer at every node | 12 ordered pairs of nodes of the testbed's CA taken; the 8 ordered pairs where one of the two is the node of the second CA refused as a certificate from an unknown CA |
| the mirror of an honest entry at the client | no bundle of the node of the second CA, one node not served: refused at -missing 0, taken at -missing 1 and 2; the same bundle added to the mirror fails the check and changes nothing |
| the mirror of the entry of the second CA at the client | its own bundle fails the check: refused at any -missing |
| the 24 chains the client can draw | each comes up and returns its echo; none holds the node of the second CA, and no link to it is opened |
| 36 chains holding the node of the second CA, put together past the client's choice | the honest node before it refuses to extend without trying to connect, 24 of 24; the node itself, following the protocol with a roster under its own CA, extends to no honest node, 12 of 12 |
| 3000 attempts of the choice on the stream of a seed | the chains and refusals are those that the sampling function of the paths set, lab.SampleMirrorPaths, gives on the masks of the mirrors the client read at the same seed; only the entry of the second CA is refused; every chain drawn comes up, failures 0; chains with the node of the second CA 0, and no link to it is opened; the share refused agrees with the model value 1/5: the Wilson interval at level 0.95 inside [0.15, 0.25] |

Every row but the share refused is exact by construction and checked without an interval. A
refusal happens exactly when the entry drawn is the node of the second CA, so the interval checks
the choice of the entry, and the boundary itself is checked by the exact rows. The share refused
is the one claim of the test, m = 1, margin 0.05; it is not among the claims of the block's
series. 3000 attempts give it an exact power of 0.999998 at the model share, while the 673
attempts the size formula below gives at m = 1 give 0.80: the test would then fail at about one
seed in five. A client that draws the node of the second CA as its entry asks it for its mirror;
the test reads the mirror without HTTP and does not model that request. An honest node accepts an
inbound link from any address, as it does from a client, so the node of the second CA extends to
no honest node only because it follows the protocol: one that departs from it can extend to
honest nodes, though only as the entry of a chain a client composes past its own choice. A -peer
client with a pinned mailbox is not covered by this test: its shares are derived above. On the
GOST suite every row but the sample is checked.

Exact by construction, not tested in the series and not counted among the claims: R given the
role (for echo entry 3/4, middle 3/4, exit 2/4; for a -peer side entry 1, middle 2/3, mailbox
1/3); content revealed for -peer, 0; linking of adjacent nodes by the shared link, AUC and top-1
1, as long as no address pair of a link repeats within the run; top-1 by setup lag over the
circuits that pass both nodes when circuits are set up one at a time; the cover flag: 1 at the
echo exit, 0 at the entry and the middle, while -peer has no cover cells at the node level and
the mailbox tells only requests apart (request feature); joining of conversations at the mailbox
with honest clients that make requests, 1 and no false pairs; model shares of 0 or 1, among them
a node of a second CA in the chains that come up, 0 (checked exactly by the trust boundary test
above). The AUC of the put feature with -cover-puts is not among them: it is 0.5 only when every
tick carries a request with a put (row "Request feature at the mailbox").

Agreement with the model in block 3. The shares and the mean R are compared with the model by
equivalence (section "Comparisons"): the margin delta is set before the series, 0.05 by default
as for AUC; m is the number of claims of the block without those exact by construction; the
interval is taken at level 1 - 0.05/m, the Wilson interval for a share and the normal one for the
mean R. For echo the unit is the chain. For a -peer client the unit is the process: the entry is
drawn once per process, a rebuild dials the same chain, and the middle hops are drawn anew at
most twice, so the R of a side is taken from the first chain of the process, rebuilds do not
enter it, and the processes that drew new middle hops are given separately; a configuration has
as many sides as processes, twice as many as conversations. The mean R is claimed only where
linking is exact by construction: one rogue node in the chain, adjacent rogue nodes, or setup one
at a time. With circuits set up at once the mean R is given against the model as the linking
gap: there the unit is the run (the mean R of a run, the median over clean runs, next to it the
shares of the circuits that pass both nodes left unlinked and linked to a wrong partner), and it
is not counted among the claims. The number of chains per configuration is the largest over its
claims of max(30, ceil((sigma (z_{1-0.025/m} + z_{0.9}) / delta)^2)), sigma being the model's
standard deviation of one observation, sqrt(p(1-p)) for a share and sigma(R) for R: then a claim
passes with probability about 0.8 when the model is exact. At m = 14 and delta = 0.05 a share
near 0.6 needs 1690 chains, a share of 0.2 needs 1127, the mean R of echo at k = 1 needs 810, the
mean R of a -peer side with an honest mailbox and k = 1 needs 1321 processes, that is 661
conversations. The deviation in standard errors of the model is given next to it as a consistency
check. The list of configurations, delta, m and the number of chains are set before the series.

A worked example of the arithmetic: echo, k = 1, 1800 chains, each of which sent at least one
message, m = 14 claims, z = 2.914 at level 1 - 0.05/14. 711 chains without a rogue node, 378 with
it at the exit, 711 at the entry or in the middle. The mean R = (378 x 2/4 + 711 x 3/4)/1800 =
0.40125, the sample variance 204.635/1799 = 0.1137, the standard error 0.00795, the interval
[0.378, 0.424] inside [0.35, 0.45]: agreement is claimed. The deviation 0.00125 is 0.16 standard
errors of the model, sqrt(0.115/1800) = 0.00799. Chains revealed 378 of 1800, exactly those with
the rogue node at the exit, 0.21: the Wilson interval [0.183, 0.239] inside [0.15, 0.25]. Chains
with a rogue node 1089, 0.605: the interval [0.571, 0.638] inside [0.55, 0.65].

The correlation series of block 1 run with as many nodes as hops, in an order the harness sets
itself: the choice of the chain does not enter them. The harness starts the nodes and the clients
inside one process and connects them over loopback, not in the cluster, so there is no network
delay between them. Its nodes run without certificates, with anonymous links between nodes,
without onion key rotation and with the per-address limits off, and the last node echoes every
message.

### Block 4. Key material, adversary A5

Status: planned, not implemented ([#24](https://github.com/jimichi-org/jimichi/issues/24)). The
measures are switched by the -keymem and -harden flags of the node and the client; the scenarios
with memory dumps, the search on disk and the recording of setup cells do not exist yet. The
client container exists ([#20](https://github.com/jimichi-org/jimichi/issues/20)); its row is
planned with the other scenarios.

| Scenario | Metric |
|---|---|
| Memory dump of a node during a session | extraction success rate, a run without the measures (-keymem none, -harden=false) against a run with mlock and dumps disabled |
| Dump after the session | key lifetime window in seconds |
| Search on disk and in the image | found or not |
| Node key theft at a given age of the recorded setup cells | fraction of recorded setups whose layer opens, against the time from the recording to the theft, with and without onion key rotation |
| Memory dump of a -peer client during a conversation | extraction success rate of the identity key, the ratchet chains and the fetch capability F, with and without the measures |
| Dump of a -peer client after the keys moved on | whether a record key is found after its record opened and a previous chain key after a ratchet step |
| Client | whether the volume key is still in memory after the container is closed |

### Block 5. Client container, adversaries A5 and A6

Status: the container is implemented, the measurement is planned
([#20](https://github.com/jimichi-org/jimichi/issues/20)).

| Scenario | Metric |
|---|---|
| Ciphertext statistics | NIST STS, entropy, chi-square; no evidence about a hidden volume |
| One volume against two | classifier AUC over a sample of containers |
| Several snapshots over time | fraction of cases where the changes reveal the hidden volume |
| Integrity | fraction of modifications detected, one hundred percent expected |
| Cost to open | time at the chosen Argon2id parameters on the target hardware |

NIST STS, entropy and chi-square are no evidence about a hidden volume: they can show that a file
differs from random data, not that one volume cannot be told from two.

For A6 the file is written once (ARCHITECTURE, "The single write"), so its snapshots are expected
to be the same byte for byte; what the filesystem and the drive keep beyond the file is a
boundary (LIMITATIONS). The result will be reported as measured.

### Block 6. Performance and primitive cost

Status: partly implemented. go test -bench covers key generation, key agreement, signing,
verification, one AEAD layer of a cell, the transcript hash, the derivation of the hop keys and
the chaining of two agreements, the key from a password and the pair from a secret on both
suites (crypto/suite), sealing a cell and layer stripping on c25519 (wire), and the KK
handshake and one record of the hash ratchet on both suites (e2e). The lab reports round-trip latency for chains of two and more nodes. Planned
([#118](https://github.com/jimichi-org/jimichi/issues/118)): the setup benchmark
at a node with one and two onion keys, node throughput at saturation, goodput per client, latency
for a chain of one node (the lab takes no fewer than two hops) and the cost of memory locking (the
lab and the benchmarks have no switch for the key-memory measures).

| Measured | How |
|---|---|
| Key agreement | go test -bench, nanoseconds per operation, GOST against X25519 |
| Setup during the grace period | nanoseconds per setup at a node holding one and two onion keys, GOST against X25519: the second key costs a second agreement, paid only during the grace period, 22 minutes of every hour on the testbed |
| Layer stripping | nanoseconds and allocations per cell |
| Node throughput | cells per second at saturation, on 1, 2 and 4 cores |
| Latency by hop count | one, two, three nodes; p50, p95, p99 |
| Cost of mlock | the same metrics with memory locking on and off |
| End-to-end layer | go test -bench, nanoseconds per KK handshake of both sides and per record of the hash ratchet, GOST against X25519 |
| Key from a password | go test -bench (BenchmarkPasswordKey), wall and processor time per call, Argon2id against PBKDF2 with Streebog-512 |
| Pair from a secret | go test -bench (BenchmarkDerivePair), wall and processor time per call, GOST against X25519 |

The end-to-end layer has two benchmarks in e2e. BenchmarkKK times one handshake of both sides:
two sessions with their card checks, kk1 and kk2. BenchmarkRatchetStep times one record with a
368-byte body: a step and a Seal at the sender, a step and an Open at the receiver. No
measurement of either is recorded yet, and there is no earlier one to compare with: the layer is
new. Their numbers are a planned measurement and will be published only from a recorded run.

The binding of every derived key to the transcript, the suite and the scheme version has no
switch, like the setup replay tag and the link confirmation frame: a build without it would be a
second key schedule, that is, a downgrade path. No block measures its contribution. The
benchmarks of crypto/suite time its parts apart: the hash of the setup transcript of an
authenticated node, with its identity key (BenchmarkNewContext; a client makes one per hop, a
node one per onion key it holds; a link
handshake hashes a transcript of its own, of another length, which is not timed apart), the
agreement under a context (BenchmarkAgree), the five values a hop
derives after the agreement: the setup key, the cell key, the replay tag and the two counter
offsets (BenchmarkDeriveHopKeys), and the chaining of two agreements on an authenticated link
(BenchmarkMixKey). Release v0.2.0, the last one without the binding, has only the agreement
benchmark to compare with.

The cost of the key from a password is two numbers per call: the wall time and the processor
time of the whole process (core-seconds, user + sys from getrusage; the wall time alone on
systems without getrusage). Argon2id runs four lanes in goroutines of their own, so its processor
time is about four times its wall time, while PBKDF2 runs on one thread. The iteration count
C_GOST of the GOST suite comes from a one-off measurement on the testbed host, chosen so that the
core-seconds per guess match Argon2id within 0.8-1.25. This equates the cost on our code in the
Linux containers of the testbed, not for an adversary: the same code outside a container, an
optimised Streebog and above all GPUs and dedicated hardware, where PBKDF2 needs no memory,
compute a guess faster, and that cost has not been measured. The number of candidates of
DerivePair in the GOST suite depends on the secret, so the benchmark cycles through 64 secrets and
gives the mean; the worst case, 128 refused candidates, is timed by a separate benchmark in
crypto/gost. No measurement is recorded yet, and the numbers are published only from a recorded
run.

### Block 7. Cell indistinguishability, adversary A2

Status: implemented, the series is planned
([#23](https://github.com/jimichi-org/jimichi/issues/23)). The set `cmd/lab -set cover` runs the
cell distinguisher (section "Traffic indistinguishability") on the client-entry link; there are no
numbers yet.

The observer sees the moments of the frames on the client-entry link in both directions and tells a
payload cell from a cover cell by the moments of the cells of a flow and of the replies to them. The
entry of the chain sees the same moments on this link and does not see the cover flag, which sits
inside the innermost layer (ARCHITECTURE, "Cell format"), so the same distinguisher is open to it,
and a distinguishability found here holds for the entry too; what the entry can learn beyond these
features the block does not measure.

| Factor | Levels |
|---|---|
| Client mode | add-1x: immediate, a cover cell every 200 ms; fixed-2x: constant rate, a slot every 100 ms. At a mean message gap of 200 ms both levels send about ten cells per second per flow, half of them payload: one bandwidth price and close group sizes. The immediate mode without cover is not a level: it has no cover cells, and the AUC is undefined |
| Primitive suite | c25519 at three hops; GOST at two and three, the GOST setup layer holds no more |
| Client | without -peer only (LIMITATIONS) |
| Relays | forward at once, without own-clock sending (the kind testbed relays send on their own clocks): r_idx is defined, and the exit answers a payload cell after handling it and a cover cell at once (LIMITATIONS) |

Labelling of cells:

- The lab wraps the provider of every client; the relays get the provider without the wrapper. The
  wrapper remembers the last cell key the client derives at circuit setup, the exit's key, and
  labels only Seal on the AEAD instance made on that key, and only with the associated data of a
  data cell at the exit's position (11 bytes: version, kind, counter, hop index). The label is the
  top bit of the length field inside the innermost layer, the cover flag. Payload and cover cells
  take one path through the wrapper.
- Labelling by length is not possible: on c25519 at three hops the plaintext of the entry's setup
  layer and of the innermost layer of a data cell have one length, 446 bytes (494 - 32 - 16 and 494
  - 3 · 16), and the first byte of the setup layer would read as a payload cell. Setup layers are
  sealed under setup keys and never reach the labelled instance; the test of the wrapper checks this
  case explicitly.
- A second instance on the exit's key, or a Seal on it with other associated data, makes the labels
  of the flow inconsistent.
- The forward frames are [setup, data cells...]: frame k + 1 carries label k. A cell is labelled
  before it is written to the link, so there are as many labels as data frames, or one more when the
  last write failed as the client closed; the extra label at the end is not used.
- In every run the labels are checked against the frames of every flow, and the number of payload
  labels against the number of messages handed to the clients minus those the schedule dropped
  (messages - dropped). A run that disagrees is marked label_mismatch and enters no training, median
  or comparison; the summary counts such runs (label_mismatch_runs), and in the summary of block 7
  clean_runs leaves them out as well.

Cell features, in seconds, in this order:

| Feature | Definition |
|---|---|
| g_prev | the gap since the previous data cell of the flow |
| g_next | the gap to the next data cell of the flow |
| dev | \|g_prev - m\|, m being the median g_prev of the cells of the flow in the window; each flow has its own median, computed without labels |
| r_next | from the cell to the first backward frame strictly after it |
| r_idx | from the cell to the k-th backward frame when it is the k-th data cell of the flow: the exit answers every data cell with one cell, the client accepts replies strictly by number, and without relays sending on their own clocks only replies travel back to the client. With relay clocks the feature is left out |

- The cells of the distinguisher are the data frames in the observation window; neighbouring frames
  and replies are taken outside the window as well. A cell lacking any feature (the first and the
  last data cell of a flow, no backward frame after it, no k-th backward frame) enters neither
  training nor test nor D and TV; the row counts them (undefined_cells).
- By definition the features have no linear relation: dev is an absolute deviation, not g_prev minus
  a constant of the flow. r_next and r_idx are defined differently but agree when the reply to a
  cell is marked strictly after it and no other backward frame lies between them; if they agree on
  every training cell, the rule of the distinguisher leaves r_idx out, the level line in the output
  of the set prints it, and the report row carries it (unused_features).
- A reply on loopback comes some tens of microseconds after its cell, so before the runs the set
  measures the step of the host's monotonic clock and does not start at a step above 10 µs: on a
  coarser clock the reply would be marked at the reading of its cell (LIMITATIONS). Every row and
  the summary carry the step (clock_step).
- At a constant rate the schedule, not the messages, sets the moments of the cells, so chance level
  is expected for g_prev, g_next and dev. r_next and r_idx also carry the moment of the exit's
  reply, which depends on the kind of cell for relays without own-clock sending: an AUC above 0.5 at
  a constant rate can come from it rather than from the moment of sending. feature_auc shows which
  feature separates the classes.

Training, test and null levels:

- Each level first runs -train training runs (5 by default), then the -repeats runs of the series.
  The seeds of the training runs come from -seed through a stream of their own and never equal a
  repeat seed of the series: training runs share no message gaps and no client phases with the
  series. The repeat of a training row is the number of the training run, and it pairs with no row
  of the series.
- The distinguisher is trained once, on the cells of the clean training runs of the level without a
  label mismatch, together; every run of the series is a test run. A training row carries the AUC
  with that run left out of training. The pilot is the set with -repeats 0: s and the number of runs
  are set from the AUCs of its training runs before the series.
- Only the constant-rate level claims equivalence: the series asks whether a constant rate hides the
  moment of sending with relays that forward at once (the set does not measure the setting
  THREAT_MODEL claims, with relays sending on their own clocks), while add-1x is expected to
  separate, and its summary has neither the quantile bounds for the corridor nor a verdict. Each
  invocation of the set thus makes one claim, and m (-claims) is the number of invocations of the
  series of block 7 whose verdict is read (for example c25519 at three hops and GOST at two and
  three give m = 3); m is set before the series by the claim plan, not from the pilot.
- D and TV are taken on g_prev of payload cells against cover cells: g_prev does not depend on
  training, so a level without a direction has them as well. The null level: a circular shift of the
  labels of each flow by a number uniform from 1 to n - 1 (n cells of the flow), from a seed stream
  of the run, one draw per run; a flow of one cell is not shifted. Beside it, for comparison, a
  permutation of the labels of all cells of the run (ks_permuted, tv_permuted).

| Where | What |
|---|---|
| run row, cells-cover-*.json | role (training or claim); configuration, seeds, revision and host load as in block 1, and the clock step (clock_step); messages, dropped, cells, bandwidth_multiplier, payload_labels, label_mismatch; payload_cells, cover_cells, undefined_cells; lda_auc with the BCa interval over flows, feature_auc for every feature, unused_features, degenerate (missing_class for a run lacking one class, training_missing_class, training_no_feature, training_equal_means for a run without a training direction); ks_distance, ks_null, ks_permuted, tv, tv_null, tv_permuted; circuit closures and node limits as in block 1. The BCa interval is descriptive: its coverage on null runs is not checked and no conclusion rests on it; the conclusions rest on the distribution of the per-run AUC and on the corridor |
| summary, summary-cover-*.json | for the set the clock step, s and m; for each level: whether it claims equivalence (equivalence_claim); training runs, run and used, the reason for no direction and the features left out; runs, broken_runs, limited_runs, label_mismatch_runs, clean_runs, degenerate_runs; medians over the clean runs of the series: lda_auc, ks_distance, ks_null, tv and tv_null with the interval by order statistics at level 0.95, the AUC minimum and maximum, medians of the per-feature AUCs; the runs the AUC median and the D and TV medians rest on (lda_auc_runs, ks_runs): a degenerate run gives no AUC, a run without one of the classes no D or TV either, and the printed summary marks a median of one run; at the constant-rate level the lower bound of the s-quantile and the upper bound of the (1 - s)-quantile of the per-run AUC of the series at level 1 - 0.05/m (auc_corridor_low, auc_corridor_high) at s (-corridor, 0.2 by default) and m (-claims, 1 by default), and the verdict whether they lie in the corridor [0.45, 0.55] (section "Comparisons"); the precision at the base rate with the TPR and the number of cover cells; the median bandwidth multiplier |
| comparisons in the summary | the family against the null level: Wilcoxon of D against D_0 and of TV against TV_0 at each level; the family of modes: Wilcoxon by repeat number of AUC, D - D_0 and TV - TV_0 of the two levels; Holm within each family over the comparisons that are neither degenerate nor undefined, with the numbers of pairs and of dropped pairs |

## Statistics

- Target for the full series ([#23](https://github.com/jimichi-org/jimichi/issues/23)): at least 30
  clean repetitions per point (runs with no closed circuit and no node limit acting, clean_runs
  in the report). The series published so far is preliminary and has fewer runs per point. The
  observation window opens when the flows start sending, so circuit setup falls outside it; no
  further warm-up is discarded.
- Series run with the kind cluster stopped and no build on the host: concurrent load disturbs
  timing and lowers the AUC of individual runs. Tables report the median.
- Within a run the AUC carries a 95 percent confidence interval: BCa bootstrap over flows, 10000
  resamples. Across repeats the summary gives the median, the minimum and the maximum; the summary
  of block 7 adds the interval by order statistics at level 0.95 to its medians of the AUC, D, TV
  and the null levels of D and TV (section "Comparisons"), the summaries of block 1 will add it with
  the full series ([#23](https://github.com/jimichi-org/jimichi/issues/23)).
- Configurations and attacks are compared under one convention, section "Comparisons" below.
- The linking attack of block 1 has no training step. The cell distinguisher (section "Traffic
  indistinguishability") is trained on separate training runs of the same configuration, run before
  the series with seeds from a stream of their own and not part of it, and evaluated on every run of
  the series. The calibration of the degree of anonymity by posterior is trained on the other clean
  runs of the same configuration and evaluated on the held-out run; the training never holds a run
  with the same repeat seed as the held-out one (such runs share the message gaps, section
  "Comparisons"). A learned linking attack, once added, will be trained and evaluated on separate
  samples, split by time, with no feature leakage.
- A relay closes a circuit when a counter breaks the order (a copy, a gap, a step back, a jump, or
  at the exit a first forward counter other than the one in its setup layer), a cell finds no room
  in a queue in either direction, a backward cell of another kind or one it cannot wrap arrives,
  the exit cannot seal a reply for any reason other than its length (a reply too long for a cell
  goes back as cover under the same number), or a cell cannot be written to the next node or back
  towards the client. A write on a link the node closed itself while closing a circuit is not
  counted again. A client closes its circuit on a reply with a bad header, a reply that does not
  open, a reply out of turn, a reply beyond the number of cells it wrote, or a frame on the link
  from the entry that does not open. Anyone on the wire between the client and the entry can
  produce such a frame, so a refused frame does not implicate the entry. The flow then stops
  before the run ends and its traces are shorter. A flow whose circuit ended hands no more
  messages to its client, so messages, drop_rate and unanswered of a broken run count only up to
  its closure.
- A report row carries relay_broken_circuits (the sum of the closures each relay noticed, so one
  circuit can be counted by several relays), broken_flows (clients that refused a reply or a link
  frame) and, per flow, flow_closed and flow_closed_after: whether the circuit closed before the
  run was read, as the client saw it and whatever the cause, and how long after the flows started
  ("" for one that stayed open). Of the client fields, a circuit ended by a relay or by the far
  side shows in flow_closed and not in broken_flows.
- A row also carries relay_timed_out (handshake, setup and write deadlines that ran out),
  relay_expired (circuits closed for idleness or age) and relay_refused (connections and setups
  the relays turned away), summed over the relays. A run is limited when any of them is non-zero:
  what it lost, it lost to a node limit and not to the configuration under test. A write deadline
  that ran out closes its circuit, so it shows in relay_timed_out and in relay_broken_circuits.
- A run is broken when any of the closure fields is non-zero. In the summary, runs counts every
  run, broken_runs the broken ones, limited_runs the limited ones (a run can be both) and
  clean_runs those that are neither; medians, ranges and ci_degenerate_runs rest on the clean
  runs. With none left those fields are null, and the latency median is null as well when the
  clean runs have no latency sample. A line resting on a single clean run gives that run's
  values, not a median, and the printed summary marks it.
- relay_dropped_cells counts cells the relays dropped: cells whose layer did not open, cells with
  an unparseable header, cells for an unknown circuit, control cells of a failed or refused setup
  (a layer that does not open, a copy of a setup seen before, a full tag cache, an identifier in
  use, a link that already carries a circuit, an unreachable next node), replies too long for a
  cell (a cover reply goes back under the same number), cells still waiting in the queue of a
  circuit that closed and, when a node forwards at once, cells towards the next node and replies
  of the exit whose write met a link that node had already closed itself. A write that fails for
  any other reason closes the circuit and is counted in relay_broken_circuits, not here.

### Comparisons

One convention for the full series of block 1
([#23](https://github.com/jimichi-org/jimichi/issues/23)), blocks 2
([#116](https://github.com/jimichi-org/jimichi/issues/116)), 3
([#117](https://github.com/jimichi-org/jimichi/issues/117)) and 7. The procedures are implemented
once in lab/metrics (stats.go) and checked by tests with hand-computed answers; the summary of block
7 calls them (Wilcoxon, Holm, the quantile interval, equivalence), the summaries of the other blocks
will call them with their series.

Procedures:

- Equal values: a and b count as equal when |a - b| is at most 1e-9 max(|a|, |b|), because the
  same number reached by different arithmetic differs in the last bits. The rule holds for ties
  and zero differences in the Mann-Whitney and Wilcoxon tests, the effect sizes, the
  Kolmogorov-Smirnov distance and the bins of the total variation, and for constant features and
  equal class means in the cell distinguisher. The scores of the linking attack (ROC AUC, top-1
  accuracy, the places of the true entry, the calibration) are compared exactly: they are rounded
  to 1e-9 when computed. The scores of the cell distinguisher are compared exactly too, without
  rounding: equal feature rows give bit-equal scores. The rule is not transitive, so a group of
  equal values starts at its smallest value and takes every value within 1e-9 of it. Values with
  a large offset (absolute timestamps, counters) are not passed to the procedures: by this rule
  1e10 + 5 and 1e10 are equal. The intervals and the equivalence verdict compare values exactly.
- Mann-Whitney U test, two independent samples: x of n values and y of m. U is the number of
  pairs where the x value is larger than the y value, plus half the pairs with equal values, over
  all nm pairs; U/(nm) reads as an AUC. The two-sided p is the share of splits of the pooled
  sample into groups of n and m values whose |U - nm/2| is at least the observed one; equal values
  get the midrank. While min(n, m)(n+m) is at most 5000 (which includes up to 50 values in each
  group), p is exact: the distribution of U over all C(n+m, n) splits is obtained by counting rank
  sums. Above the bound, the normal approximation with tie and continuity corrections:
  z = max(|U - nm/2| - 0.5, 0) / sqrt(nm/12 (n+m+1 - S / ((n+m)(n+m-1)))), where S is the sum of
  t^3 - t over groups of t equal values, and p = 2(1 - F(z)), F the standard normal distribution
  function. With large tie groups the approximation gives too small a p (seven values of 0 and 1
  in each group: 0.045 against the exact 0.103), and a growing sample does not cure it when the
  ties form rare minority values. So conclusions rest only on the exact p: if a series goes past
  the bound, the bound is raised before the analysis (the counting grows as the square of
  min(n, m)(n+m)).
- Wilcoxon signed-rank test, pairs (x_i, y_i). Pairs with equal x_i and y_i are dropped, leaving
  n' differences d_i = x_i - y_i; their absolute values are ranked with midranks, and W is the
  rank sum of the positive differences. The two-sided p is the share of the 2^n' sign assignments
  whose |W - n'(n'+1)/4| is at least the observed one: exact, by counting rank sums, when n' is at
  most 100, otherwise
  z = max(|W - n'(n'+1)/4| - 0.5, 0) / sqrt(n'(n'+1)(2n'+1)/24 - S/48), with S the same sum over
  groups of equal absolute values, and p = 2(1 - F(z)).
- Effect size, from -1 to 1. For Mann-Whitney it is Cliff's delta: (pairs with x > y minus pairs
  with x < y) / (nm), that is 2U/(nm) - 1. For Wilcoxon the matched-pairs rank-biserial
  correlation (Kerby, 2014): (W - W') / (W + W'), where W' is the rank sum of the negative
  differences; its sign is always on the side W departs to, and for independent samples the same
  measure is Cliff's delta. Cliff's delta on paired data would describe the overlap of two
  distributions and could point the opposite way to the test. Magnitude for both measures by the
  thresholds of Romano et al. (2006): an absolute value below 0.147 is negligible, below 0.33
  small, below 0.474 medium, otherwise large.
- Holm's correction for a family of k comparisons: the p-values are sorted ascending,
  p(1) <= ... <= p(k); the adjusted p(j) is the largest (k - i + 1) p(i) over i <= j, capped at 1.
  A hypothesis is rejected when its adjusted p is at most 0.05.
- Interval of a share: x of n draws, p = x/n, z the standard normal quantile of level 1 - alpha/2
  for an interval of level 1 - alpha. The Wilson interval:
  (p + z^2/(2n) -+ z sqrt(p(1-p)/n + z^2/(4n^2))) / (1 + z^2/n); at x = 0 the lower bound is 0,
  at x = n the upper bound 1. Unlike p -+ z sqrt(p(1-p)/n) it does not shrink to a point at
  x = 0 and x = n and stays inside [0, 1] (Brown, Cai, DasGupta, 2001). Example: 600 of 1000 at
  level 0.95 give [0.5693, 0.6299].
- Interval of a mean: x̄ -+ z s/sqrt(n), s the sample standard deviation with divisor n - 1;
  when all values are equal the interval is that value. The quantile is normal, not Student's: at
  the block 3 sizes (533 chains and more) t is wider by under half a percent (0.45 percent at
  n = 533 and 0.24 percent at n = 1000 at the level for 14 claims); it does not suit the 30 runs
  of a point, where t is wider by 8.8 percent at the same level and 4.4 percent at level 0.95.
- Interval of a quantile by order statistics, with no assumption on the distribution:
  n independent values of one distribution, x_(1) <= ... <= x_(n), K ~ Binom(n, q), interval
  level 1 - alpha. The lower bound is x_(l) with the largest l such that P(K <= l - 1) <= alpha/2,
  the upper bound x_(u) with the smallest u such that P(K >= u) <= alpha/2; the coverage
  1 - P(K <= l - 1) - P(K >= u) is at least 1 - alpha, with ties as well. When no such index
  exists the bound is undefined: with five runs there is no 0.95 interval for the median
  (P(K = 0) = 1/32). The point is the quantile with linear interpolation, the usual median for the
  median. Example: 20 runs, the median, level 0.95: x_(6) and x_(15), coverage
  1 - 2·21700/2^20, about 0.9586. The bounds of two quantiles bound the share of runs: the lower
  bound of the s-quantile and the upper bound of the (1 - s)-quantile, both at level 1 - alpha,
  hold together with probability at least 1 - alpha, and when both lie inside the corridor, the
  share of runs below it and the share above are at most s each. At level 0.95 and s = 0.2 these
  are x_(1) and x_(n) from 17 to 25 runs (0.8^17 about 0.0225, 0.8^16 about 0.0281) and x_(2) and
  x_(n - 1) from 26 to 33; for s = 0.1 neither bound exists below 36 runs (0.9^n > 0.025).
- Equivalence verdict: "equivalent" when the interval lies entirely inside the model value plus or
  minus the margin (edges included), "not shown" otherwise; an undefined interval and an infinite
  margin give no verdict. "Not shown" does not mean the value differs from the model.
- Size for an equivalence claim: with the model's standard deviation sigma of one observation,
  margin delta, m claims and power pi,
  n = max(30, ceil((sigma (z_{1-0.025/m} + z_{(1+pi)/2}) / delta)^2)); below 30 the normal
  approximation does not hold. A claim passes when the deviation of the estimate from the model
  is at most delta - z_{1-0.025/m} SE, which for an exact model and a normal estimate happens with
  probability 2F(delta/SE - z_{1-0.025/m}) - 1. This is a normal approximation: for a share near
  0 or 1 the exact power of the Wilson interval is a few points lower (0.74 instead of 0.8 for a
  share of 0.1 at 634 chains). Example: sigma = 0.5, delta = 0.05, m = 1, pi = 0.8 give 1051.

Rules:

- Tests are two-sided at 0.05 per family after Holm's correction. A family is the set of
  comparisons that answer one question of a block, for example every level of one factor against
  the baseline configuration.
- Per-run metrics (AUC and the like) are bounded, not normally distributed and often sit at the
  edge: a run's AUC is often exactly 1. So the tests are rank tests with no assumption on the
  distribution, and p is exact: if a series goes past the bound of either test, that bound is
  raised before the analysis.
- Runs are paired when they share random streams. cmd/lab derives the seed of repeat r from -seed
  and r alone (the training runs of block 7 take their seeds from a stream of their own and pair
  with nothing), so runs with the same -seed and repeat number, from one set or from separate
  invocations, share the stream of message gaps and the stream of client phases. A phase is the
  remainder of a shared random number divided by the schedule of the level, so levels with the same
  schedule get the same phases, levels with different schedules share them for only part of the
  flows, and a level without a schedule has no phases; relay clock phases are each run's own. Such
  runs are compared as pairs by repeat number, by Wilcoxon's test, over the pairs where both runs
  are clean; the number of dropped pairs is reported alongside, since a pair stays only when both
  levels survived. A pair shares random numbers, not time: the levels of a set run one after
  another, and a pair does not cancel drift in host load. Two quantities of one run are compared as
  pairs in the same way: two attacks on the same links, a watermark and the null level of the
  detector. Runs with different -seed values are independent and are compared by Mann-Whitney's
  test.
- A p-value is reported only together with the effect size, and a significant but negligible
  difference is called negligible.
- A Holm family holds only comparisons where rejecting the null hypothesis is the result. A
  comparison whose outcome is exact by construction (for Mann-Whitney the same value in every run
  of both groups, for Wilcoxon equal values in every pair; the procedure marks it as degenerate)
  and an undefined comparison (an empty group) are not tested and do not enter the family.
- Agreement with a model and equality with guessing are not inferred from a non-significant p: with
  few runs a non-significant p shows nothing, and Holm's correction would only make such a claim
  easier. A proportion inside +-2 SE of the model is the same non-rejection, so the deviation in SE
  is reported as a consistency check, not as agreement. Agreement is claimed as equivalence: before
  the series the block sets a margin and claims agreement only when the 95 percent interval for the
  measured quantity lies entirely inside the model value plus or minus the margin; with m such
  claims in a block the intervals are taken at level 1 - 0.05/m. For AUC the default margin is 0.05,
  the corridor [0.45, 0.55]. Under exact guessing the quantity a block compares with the corridor
  must lie well inside it: the folded per-run AUC max(AUC, 1 - AUC) is pushed upward by noise and
  with few flows can lie above 0.55 at any number of runs. It must also bound the share of runs that
  separate, not only the centre: a mix of runs at AUC 0.2 and 0.8, and 22 runs at AUC 0.5 next to 8
  at 0.8, both have a median of 0.5 but are not guessing. The block sets the quantity, its interval,
  the margin and the number of runs, given the step of the quantity itself, before the series; the
  share of runs that separate is bounded by the intervals of quantiles (procedures above); the
  summary of block 7 gives these quantile bounds at the s and m set by its flags and the verdict for
  the constant-rate level; in the summaries of the other blocks they are planned with the series
  ([#23](https://github.com/jimichi-org/jimichi/issues/23)).
- The degrees of anonymity and the effective set size are reported descriptively: no difference
  or equality is claimed for them until an interval for them is defined. The degree by rank is
  taken over all runs of a configuration together and has no interval over runs, and the values
  of the degree by posterior over held-out runs depend on each other through shared training.
- In block 3 the intervals are those above: Wilson for shares, normal for the mean R, the margin
  set before the series (0.05 by default), size by the rule for equivalence at power 0.8 (block 3,
  "Agreement with the model in block 3"). m is the number of equivalence claims of the block; in
  block 3 the letter k is taken by the number of rogue nodes. Equivalence claims do not enter a
  Holm family: their multiplicity is in the level 1 - 0.05/m. Goodness-of-fit tests (chi-square,
  exact binomial) do not show agreement and are not used in block 3: a deviation from the model
  shows in the deviation in SE, and the view of each chain is checked against its route
  directly.
- The smallest exact p that can be reached is 2/2^n' for Wilcoxon and 2/C(n+m, n) for
  Mann-Whitney with equal groups or without ties; with unequal groups and ties the null
  distribution can be asymmetric and the floor drops to 1/C(n+m, n). With five runs per group
  that is 2/252, about 0.0079, so in a family of more than six comparisons no difference passes
  Holm's first threshold 0.05/k. With five pairs it is 2/32 = 0.0625, so a paired comparison is
  not significant even alone; zero differences lower n' and raise the floor. A pilot of five runs
  per point therefore serves only to size the series, and conclusions rest on the series.
- Series size, planned ([#23](https://github.com/jimichi-org/jimichi/issues/23)): before a series,
  a pilot of five runs per point on the same code revision. Power is computed by resampling the
  pilot runs with one group shifted by 0.05 AUC away from the nearer end of [0, 1], by the same
  exact test the series will use, at
  Holm's first threshold, and for paired comparisons on the number of nonzero differences. The
  size is the smallest number of runs with power 0.8; a series point takes the larger of 30 and
  that size, and pilot runs do not enter the series.

| Block | Unit of observation | What is compared | Procedure | Why |
|---|---|---|---|---|
| 1, full series ([#23](https://github.com/jimichi-org/jimichi/issues/23)) | clean run | attack AUC at each level of a factor against the baseline configuration of the same set | Wilcoxon by repeat number with the rank-biserial correlation, Holm over the levels of one factor; between sets with different seeds Mann-Whitney with Cliff's delta | repeat r of every level of a set is derived from one seed, so these are pairs |
| 2 ([#116](https://github.com/jimichi-org/jimichi/issues/116)) | clean run | watermark detector AUC against its null level in the same run; configurations of the block against each other | against the null level Wilcoxon; configurations by the pairing rule above; Holm over the configurations; resistance threshold by equivalence | the null level is the same detector on unmarked flows of the same run |
| 3 ([#117](https://github.com/jimichi-org/jimichi/issues/117)) | established echo chain and -peer client process (its first chain) for shares and the mean R; clean run for AUC, the request feature and the mean R with circuits set up at once | shares of chains and the mean share of the route recovered against the model; residual linking AUC from the vantage point of the rogue nodes against the A1 AUC on the same runs; scenarios of the block against each other | shares: Wilson interval, mean R: normal interval; agreement by equivalence with a margin set before the series at level 1 - 0.05/m, for the mean R only where linking is exact by construction; deviation in SE of the model as a consistency check; AUC: Wilcoxon for a claimed difference, "not lower" only as non-inferiority by an interval of the paired differences with a margin set before the series; Holm over non-degenerate comparisons | the model proportion is known exactly, so the question is agreement, not rejection; both attacks watch the same links of one run |
| 7, series planned ([#23](https://github.com/jimichi-org/jimichi/issues/23)) | clean run of the series | AUC of the cell distinguisher on the run (unfolded), D and TV against the null level of the same run; the immediate mode with cover traffic against the constant rate by the per-run AUC and by the excess D - D_0 and TV - TV_0 over the null level, not by D and TV themselves: they depend on the group sizes, and the share of payload cells agrees between runs and modes only on average | a difference: D and TV against the null level by Wilcoxon over runs, the modes by the pairing rule above, Holm over the non-degenerate comparisons; equality with guessing: equivalence in which the lower bound of the s-quantile and the upper bound of the (1 - s)-quantile of the per-run AUC at level 1 - 0.05/m lie in the corridor [0.45, 0.55], at the constant-rate level only; the per-run AUCs of the series are independent since the direction comes from training runs outside it; s and the number of runs are set before the series from the pilot, m by the claim plan of the block | indistinguishability is claimed by equivalence of the AUC, not by a non-significant p, and bounds the share of runs that separate, not only the centre; D and TV serve only claims of a difference |

## Threats to validity

| Type | Threat | What is done |
|---|---|---|
| Internal | the adversary sees ideal timestamps, unlike a real network | planned: a separate series with network noise and jitter ([#46](https://github.com/jimichi-org/jimichi/issues/46)); until then the lab observer has ideal timestamps |
| Internal | synthetic load is too regular | messages leave with exponential gaps, one profile; a heavy-tailed model and several activity profiles are planned |
| Internal | the labels of block 7 are wrong, and the distinguisher is trained and tested against the wrong truth | the wrapper of the client's provider labels a cell by the AEAD instance of the innermost layer and the associated data of a data cell, not by length (a test with equal lengths on c25519 at three hops); in every run the labels are checked against the forward frames and the number of payload labels against the number of messages minus those dropped; a run that disagrees is left out and counted (label_mismatch) |
| External | the testbed runs on one machine and the series in one process over loopback, network delays are not modelled | absolute latency figures belong to loopback and do not carry over to a network; network emulation profiles are planned ([#46](https://github.com/jimichi-org/jimichi/issues/46)) |
| Construct | AUC alone does not imply a practical attack | TPR at FPR 0.01 and top-1 accuracy are reported alongside; the precision at the base rate is in the summary: for linking at the F of the testbed and at a pi fixed before the series, for cells at the share of payload cells on the testbed |
| Reproducibility | randomness across runs | fixed seeds, configuration and code version in every report |
| Survival bias | medians without broken and limited runs describe the runs where every circuit survived; when closures depend on the configuration, such as a node period close to the client's, its medians describe the luckier runs | runs, broken_runs, limited_runs and clean_runs, and in block 7 label_mismatch_runs as well, stand next to every median, and every row records which circuits closed and when (flow_closed, flow_closed_after); a survival series over the ratio of periods is planned (block 2) |

## Comparison with existing systems

Planned: a table over the same features for Tor, Session, SimpleX, Briar and this work. Features:
constant cell size, cover traffic, state kept on a node, deniability, primitive suite, published
latency figures. Of the deniability properties this work has today deniability of sending at a
constant rate with relays sending on their own clocks, nothing to surrender after a session and
offline deniable authentication between clients, shown by a forgery and not measured
(THREAT_MODEL); the client container
([#20](https://github.com/jimichi-org/jimichi/issues/20)) is implemented, and the measurement of
its property is planned (block 5). Numbers for other systems
will come from their documentation and papers, ours will be measured. No direct performance
comparison will be made: the conditions differ, and that will be stated.

## What the defence shows

1. A live message through three nodes. The panel of what each node learns is planned with the
   dashboard ([#21](https://github.com/jimichi-org/jimichi/issues/21)).
2. The observer: the linking attack runs without protection and with each measure in turn. Cover
   traffic on top of the payload is not expected to lower its AUC: in the preliminary series it
   stayed at 1.000 with cover, and nodes sending on their own clocks lowered it to medians of
   0.44-0.67 against 0.94-1.00 in the other rows of the README table; these runs cannot show that
   it is at chance ([README](../../README.md)). A live view of the attack result is planned with
   the dashboard ([#21](https://github.com/jimichi-org/jimichi/issues/21)).
3. The bandwidth multiplier against AUC curve. The published figure has no intervals; confidence
   intervals across runs are planned with the full series
   ([#23](https://github.com/jimichi-org/jimichi/issues/23)).
4. Planned ([#24](https://github.com/jimichi-org/jimichi/issues/24)): the search for key bytes in
   memory dumps with and without the key-memory measures. The measured result will be shown as
   it is; copies of keys that libraries keep on the heap are listed in [CRYPTO](CRYPTO.md),
   "Known gaps".
5. The container ([#20](https://github.com/jimichi-org/jimichi/issues/20)): `jimichi vault
   init` and `jimichi vault show`, one password opens the decoy volume and another the second
   volume; the distinguisher of block 5 is planned. NIST STS results are no evidence about a
   hidden volume: they show only that the ciphertext has no statistical structure.
6. The cost table: GOST against X25519 from the benchmarks and round-trip latency for chains of
   two and three nodes; the rest of block 6 is planned
   ([#118](https://github.com/jimichi-org/jimichi/issues/118)).
7. A forged conversation: `cmd/lab -set deny` on both suites. Holding only its own keys, the
   recipient builds a transcript that passes the same check as the genuine one, while a forgery
   made with a fresh key in place of the recipient's fails it. Shown with its limits: offline
   only, no witnessed transcript, no metadata ([CRYPTO](CRYPTO.md), "Deniability").
