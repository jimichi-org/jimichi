//go:build linux && amd64

package nodeview

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/jimichi-org/jimichi/conversation"
	"golang.org/x/sys/unix"
)

const witnessVersion = 1
const relayWitnessValues = 25
const clientWitnessValues = 14

type childWitness struct {
	role   byte
	values [relayWitnessValues]uint64
}

func witnessValues(role byte) int {
	switch role {
	case roleRelay:
		return relayWitnessValues
	case roleClient:
		return clientWitnessValues
	}
	return 0
}

func encodeChildWitness(w *encoder, cw childWitness) {
	n := witnessValues(cw.role)
	if n == 0 {
		w.bad = true
		return
	}
	w.u8(witnessVersion)
	w.u8(cw.role)
	for _, v := range cw.values[:n] {
		w.u64(v)
	}
}

func decodeChildWitness(r *decoder, role byte) (childWitness, error) {
	cw := childWitness{role: role}
	n := witnessValues(role)
	version, got := r.u8(), r.u8()
	for i := range n {
		cw.values[i] = r.u64()
	}
	if r.bad || n == 0 || version != witnessVersion || got != role || cw.values[0] >= uint64(len(reasons)) {
		return childWitness{}, fail(ReasonIPC)
	}
	latch := cw.values[1:9]
	phase := cw.values[2]
	if role == roleClient {
		latch, phase = cw.values[1:3], cw.values[1]
		if cw.values[10] > 3 {
			return childWitness{}, fail(ReasonIPC)
		}
	} else if cw.values[1] > uint64(siteLast) {
		return childWitness{}, fail(ReasonIPC)
	}
	if phase > uint64(phaseLast) {
		return childWitness{}, fail(ReasonIPC)
	}
	if cw.values[0] == 0 {
		for _, v := range latch {
			if v != 0 {
				return childWitness{}, fail(ReasonIPC)
			}
		}
	}
	return cw, nil
}

func selfCPU() uint64 {
	var u unix.Rusage
	if unix.Getrusage(unix.RUSAGE_SELF, &u) != nil {
		return 0
	}
	return uint64(u.Utime.Nano() + u.Stime.Nano())
}

func waitCPU(state *os.ProcessState) uint64 {
	if state == nil {
		return 0
	}
	return uint64(state.UserTime() + state.SystemTime())
}

// window figures are taken after freeze, latch fields were written once at the first failure
func relayTail(col *collector, cpuWindowNS, wallWindowNS uint64) childWitness {
	cw := childWitness{role: roleRelay}
	v := &cw.values
	if col.latch.set {
		l := col.latch
		v[0], v[1], v[2] = uint64(reasonByte(col.err)), uint64(l.site), uint64(l.phase)
		if l.phase != phaseBeforeBegin {
			v[3] = latchOffset(l.at, col.start)
		}
		v[4], v[5], v[6], v[7], v[8] = l.connections, l.pending, l.contexts, l.cells, l.closedAgeNS
	}
	v[9], v[10] = cpuWindowNS, wallWindowNS
	copy(v[11:17], col.visits[:])
	v[17] = uint64(col.arena.freeHigh)
	v[18], v[19], v[20] = residenceCounts(col.view.cells, col.measured)
	v[21], v[22], v[23], v[24] = deliverThirds(col.view.mailbox, col.start, col.cutoff)
	return cw
}

type clientTimeline struct {
	beginAt, epoch, cutoff, stopAt int64
}

func (t clientTimeline) latch(p *privateCapture) (reason, phase, offset uint64) {
	if p.err == ReasonNone {
		return 0, 0, 0
	}
	begun := t.beginAt != 0 && p.latchAt >= t.beginAt
	ph := latchPhase(p.latchAt, begun, t.epoch, t.cutoff, t.stopAt != 0 && p.latchAt >= t.stopAt)
	if ph != phaseBeforeBegin {
		offset = latchOffset(p.latchAt, t.epoch)
	}
	return uint64(reasonByte(p.err)), uint64(ph), offset
}

type conversationSnapshot struct {
	finish, refusals                        uint64
	unansweredThroughDrain, unansweredTotal uint64
}

func finishClass(e error) uint64 {
	switch {
	case e == nil:
		return 0
	case errors.Is(e, conversation.ErrRebuild):
		return 1
	case errors.Is(e, conversation.ErrRefused):
		return 2
	}
	return 3
}

func clientTail(p *privateCapture, b *boundaryClientState, t clientTimeline, conv conversationSnapshot) childWitness {
	cw := childWitness{role: roleClient}
	v := &cw.values
	v[0], v[1], v[2] = t.latch(p)
	b.mu.Lock()
	v[3], v[4], v[5], v[6] = b.ends.replyTimeout, b.ends.sendFailed, b.ends.refused, b.ends.farClose
	v[7] = b.ends.after
	v[8], v[9] = b.dials.attempts, b.dials.failures
	b.mu.Unlock()
	v[10], v[11], v[12], v[13] = conv.finish, conv.refusals, conv.unansweredThroughDrain, conv.unansweredTotal
	return cw
}

type relayWitness struct {
	selected bool
	reason   Reason
	flags    []Reason
	summary  [24]uint64
	tail     childWitness
	cpuNS    uint64
	maxRSS   uint64
}
type clientWitness struct {
	reason  Reason
	flags   []Reason
	rebuilt uint64
	tail    childWitness
	cpuNS   uint64
}
type hostStat struct {
	busy, steal, total uint64
	ok                 bool
}
type taskWitness struct {
	routes           [][3]uint8
	relays           [5]relayWitness
	relayCount       int
	clients          []clientWitness
	unanswered       uint64
	recorded         bool
	marked           bool
	startNS, endNS   int64
	startCPU, endCPU uint64
	host             [2]hostStat
	cgroup           [2]uint64
	cgroupOK         bool
	cpu              cpuCgroup
}

type taskWitnessKey struct{}

func withTaskWitness(ctx context.Context, w *taskWitness) context.Context {
	return context.WithValue(ctx, taskWitnessKey{}, w)
}

func taskWitnessFrom(ctx context.Context) *taskWitness {
	w, _ := ctx.Value(taskWitnessKey{}).(*taskWitness)
	return w
}

type cpuCgroup struct {
	dir         string
	limitMillis uint64
	limitKnown  bool
}

func processCPUCgroup() cpuCgroup {
	membership, e1 := os.ReadFile("/proc/self/cgroup")
	mounts, e2 := os.ReadFile("/proc/self/mountinfo")
	if e1 != nil || e2 != nil {
		return cpuCgroup{}
	}
	return resolveCPUCgroup(membership, mounts, os.ReadFile)
}

// a quota on any visible ancestor caps the process, so the limit is the minimum from leaf to mount
func resolveCPUCgroup(membership, mounts []byte, read func(string) ([]byte, error)) cpuCgroup {
	_, group, err := parseMemoryMembership(membership)
	if err != nil || group.version != 2 {
		return cpuCgroup{}
	}
	resolved, err := resolveMemoryMounts(mounts, group)
	if err != nil {
		return cpuCgroup{}
	}
	group = resolved[0]
	leaf, err := memoryCgroupDirectory(group)
	if err != nil {
		return cpuCgroup{}
	}
	unknown := cpuCgroup{dir: leaf}
	// without cpu in the unified hierarchy a quota may live in a v1 hierarchy this walk cannot see
	controllers, err := read(path.Join(group.mount, "cgroup.controllers"))
	if err != nil || !slices.Contains(strings.Fields(string(controllers)), "cpu") {
		return unknown
	}
	out := cpuCgroup{dir: leaf, limitKnown: true}
	for dir := leaf; ; dir = path.Dir(dir) {
		b, err := read(path.Join(dir, "cpu.max"))
		if err == nil {
			millis, limited, ok := parseCPULimit(string(b))
			if !ok {
				return unknown
			}
			if limited && (out.limitMillis == 0 || millis < out.limitMillis) {
				out.limitMillis = millis
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return unknown
		}
		if dir == group.mount {
			return out
		}
	}
}

func cgroupUsage(dir string) (uint64, bool) {
	if dir == "" {
		return 0, false
	}
	b, e := os.ReadFile(path.Join(dir, "cpu.stat"))
	if e != nil {
		return 0, false
	}
	return parseCgroupUsage(string(b))
}

func parseCgroupUsage(text string) (uint64, bool) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "usage_usec" {
			v, e := strconv.ParseUint(f[1], 10, 64)
			return v, e == nil
		}
	}
	return 0, false
}

func (w *taskWitness) mark() {
	w.marked = true
	w.startNS, w.startCPU = monotonicNS(), selfCPU()
	w.host[0] = readHostStat()
	w.cpu = processCPUCgroup()
	w.cgroup[0], w.cgroupOK = cgroupUsage(w.cpu.dir)
}

func recordTaskWitness(ctx context.Context, f *fixture, clients []*ownedChild, routes [][3]uint8, row RunResult) {
	w := taskWitnessFrom(ctx)
	if w == nil || !w.marked {
		return
	}
	w.endNS, w.endCPU = monotonicNS(), selfCPU()
	w.host[1] = readHostStat()
	var ok bool
	w.cgroup[1], ok = cgroupUsage(w.cpu.dir)
	w.cgroupOK = w.cgroupOK && ok
	w.routes = append(w.routes[:0], routes...)
	w.relayCount = min(len(f.relays), len(w.relays))
	for i, ch := range f.relays[:w.relayCount] {
		w.relays[i] = relayWitness{selected: ch.selected, reason: ch.reason, flags: append([]Reason(nil), ch.flags...), summary: ch.processSummary.values, tail: ch.witness, cpuNS: ch.cpuNS, maxRSS: ch.maxRSS}
	}
	w.clients = w.clients[:0]
	for _, ch := range clients {
		w.clients = append(w.clients, clientWitness{reason: ch.reason, flags: append([]Reason(nil), ch.flags...), rebuilt: ch.counts.Rebuilt, tail: ch.witness, cpuNS: ch.cpuNS})
	}
	w.unanswered = row.Counts.Unanswered
	w.recorded = true
}

func readHostStat() hostStat {
	b, e := os.ReadFile("/proc/stat")
	if e != nil {
		return hostStat{}
	}
	return parseHostStat(string(b))
}

// the first line sums every cpu; guest time is already inside user and nice
func parseHostStat(text string) hostStat {
	line, _, _ := strings.Cut(text, "\n")
	f := strings.Fields(line)
	if len(f) < 9 || f[0] != "cpu" {
		return hostStat{}
	}
	var v [8]uint64
	for i := range v {
		x, e := strconv.ParseUint(f[i+1], 10, 64)
		if e != nil {
			return hostStat{}
		}
		v[i] = x
	}
	var total uint64
	for _, x := range v {
		total += x
	}
	return hostStat{busy: total - v[3] - v[4], steal: v[7], total: total, ok: true}
}

func parseCPULimit(text string) (millis uint64, limited, ok bool) {
	f := strings.Fields(text)
	if len(f) != 2 {
		return 0, false, false
	}
	period, e := strconv.ParseUint(f[1], 10, 64)
	if e != nil || period == 0 {
		return 0, false, false
	}
	if f[0] == "max" {
		return 0, false, true
	}
	quota, e := strconv.ParseUint(f[0], 10, 64)
	if e != nil || quota > math.MaxUint64/1000 || quota*1000/period == 0 {
		return 0, false, false
	}
	return quota * 1000 / period, true, true
}

func stealPPM(h [2]hostStat) (uint64, bool) {
	if !h[0].ok || !h[1].ok || h[1].total <= h[0].total || h[1].steal < h[0].steal {
		return 0, false
	}
	return uint64(float64(h[1].steal-h[0].steal) * 1e6 / float64(h[1].total-h[0].total)), true
}

func utilizationPPM(cpuNS uint64, wallNS int64, nproc int, cpuLimitMillis uint64) uint64 {
	capacity := uint64(nproc) * 1000
	if cpuLimitMillis != 0 {
		capacity = min(capacity, cpuLimitMillis)
	}
	if wallNS <= 0 || capacity == 0 {
		return 0
	}
	return uint64(float64(cpuNS) * 1e6 * 1000 / (float64(wallNS) * float64(capacity)))
}

func ms(ns uint64) uint64 { return ns / 1000000 }

func signedMS(v uint64) string { return fmt.Sprintf("%+d", int64(v)/1000000) }

func optional(v uint64, ok bool) string {
	if !ok {
		return "none"
	}
	return strconv.FormatUint(v, 10)
}

func (w *taskWitness) lines(suite, name, exec, outcome string, nproc, gomaxprocs int) []string {
	head := fmt.Sprintf("nodeview-witness v1 suite=%s case=%s exec=%s outcome=%s", suite, name, exec, outcome)
	if !w.recorded {
		return []string{head + " witness absent"}
	}
	var children uint64
	for _, r := range w.relays[:w.relayCount] {
		children += r.cpuNS
	}
	var clientsCPU uint64
	for _, c := range w.clients {
		clientsCPU += c.cpuNS
	}
	children += clientsCPU
	wall := w.endNS - w.startNS
	controller := w.endCPU - w.startCPU
	steal, stealOK := stealPPM(w.host)
	var rebuilt, rebuiltMax, rebuiltNonzero uint64
	perClient := make([]uint64, len(w.clients))
	for i, c := range w.clients {
		perClient[i] = c.rebuilt
		rebuilt += c.rebuilt
		rebuiltMax = max(rebuiltMax, c.rebuilt)
		if c.rebuilt != 0 {
			rebuiltNonzero++
		}
	}
	limit, utilization := "unknown", "none"
	if w.cpu.limitKnown {
		limit = "none"
		if w.cpu.limitMillis != 0 {
			limit = strconv.FormatUint(w.cpu.limitMillis, 10)
		}
		utilization = strconv.FormatUint(utilizationPPM(children+controller, wall, nproc, w.cpu.limitMillis), 10)
	}
	cgroup := "none"
	if w.cgroupOK && w.cgroup[1] >= w.cgroup[0] {
		cgroup = strconv.FormatUint((w.cgroup[1]-w.cgroup[0])/1000, 10)
	}
	out := []string{fmt.Sprintf("%s rebuilt_total=%d unanswered=%d wall_ms=%d nproc=%d cpu_limit_millis=%s gomaxprocs=%d children_cpu_ms=%d controller_cpu_ms=%d utilization_ppm=%s host_steal_ppm=%s cgroup_cpu_ms=%s", head, rebuilt, w.unanswered, max(wall, 0)/1000000, nproc, limit, gomaxprocs, ms(children), ms(controller), utilization, optional(steal, stealOK), cgroup)}
	base, baseOK := routeConnections(w.routes, make([]uint64, len(w.routes)))
	predicted, predictedOK := routeConnections(w.routes, perClient)
	for i, r := range w.relays[:w.relayCount] {
		s, v := r.summary, r.tail.values
		baseText, predictedText, unattributed := "n/a", "n/a", "n/a"
		if baseOK {
			baseText = strconv.FormatUint(base[i], 10)
		}
		if predictedOK {
			predictedText = strconv.FormatUint(predicted[i], 10)
			unattributed = strconv.FormatInt(int64(s[19])-int64(predicted[i]), 10)
		}
		latch := "none"
		if v[0] != 0 {
			latch = fmt.Sprintf("%s@%s%s inv=%d/%d/%d/%d closed_age_ms=%d", latchSite(v[1]), phaseName(v[2]), signedMS(v[3]), v[4], v[5], v[6], v[7], ms(v[8]))
		}
		out = append(out, fmt.Sprintf("nodeview-witness v1 suite=%s relay=%d selected=%d reason=%s flags=%v conns=%d base=%s predicted=%s unattributed=%s pending_hw=%d cells_hw=%d contexts_hw=%d arena_hw=%d free_spans_hw=%d calls=%d callback_ms=%d cpu_ms=%d cpu_window_ms=%d wall_window_ms=%d visits=setup_out:%d,setup_hop:%d,history:%d,pair:%d,deliver:%d,pending:%d queue_ge_3500ms=%d queue_ge_7s=%d queue_max_ms=%d deliver_early=calls:%d,us:%d deliver_late=calls:%d,us:%d stats=accepted:%d,forwarded:%d,delivered:%d,dropped:%d,broken:%d,accept_retries:%d,refused_links:%d,refused_busy:%d,failed_extend:%d,timed_out:%d,expired:%d latch=%s",
			suite, i, boolInt(r.selected), reasonText(r.reason), r.flags, s[19], baseText, predictedText, unattributed, s[20], s[22], s[21], s[18], v[17], s[16], ms(s[17]), ms(r.cpuNS), ms(v[9]), ms(v[10]), v[11], v[12], v[13], v[14], v[15], v[16], v[18], v[19], ms(v[20]), v[21], v[22]/1000, v[23], v[24]/1000,
			s[0], s[1], s[2], s[3], s[5], s[6], s[7], s[8], s[13], s[14], s[15], latch))
	}
	var ends [5]uint64
	var dials [2]uint64
	var finish [4]uint64
	var refusals, window, total uint64
	var latches []string
	for i, c := range w.clients {
		v := c.tail.values
		for j := range ends {
			ends[j] += v[3+j]
		}
		dials[0] += v[8]
		dials[1] += v[9]
		finish[min(v[10], 3)]++
		refusals += v[11]
		window += v[12]
		total += v[13]
		if v[0] != 0 {
			latches = append(latches, fmt.Sprintf("%d:%s%s", i, phaseName(v[1]), signedMS(v[2])))
		}
	}
	out = append(out, fmt.Sprintf("nodeview-witness v1 suite=%s clients n=%d rebuilt_sum=%d rebuilt_max=%d rebuilt_nonzero=%d ends=reply_timeout:%d,send_failed:%d,refused:%d,far_close:%d,after:%d dial=attempts:%d,failures:%d finish=none:%d,rebuild:%d,refused:%d,other:%d refusals=%d conv_unanswered=through_drain:%d,total:%d clients_cpu_ms=%d latches=[%s]",
		suite, len(w.clients), rebuilt, rebuiltMax, rebuiltNonzero, ends[0], ends[1], ends[2], ends[3], ends[4], dials[0], dials[1], finish[0], finish[1], finish[2], finish[3], refusals, window, total, ms(clientsCPU), strings.Join(latches, ",")))
	return out
}

func reasonText(r Reason) string {
	if r == ReasonNone {
		return "none"
	}
	return string(r)
}
