package nodeview

import (
	"math"
	"reflect"
	"strings"
	"unicode/utf8"
)

type outputTaskBound struct {
	First, Second, MailboxRows, MailboxGroups int
}

type outputMemoryPlan struct {
	RetainedBytes    uint64
	EmitterBytes     uint64
	TotalBytes       uint64
	ReportLimitBytes uint64
	LegacyTotalBytes uint64
}

type outputSize struct {
	backing, json, longest, custom, depth uint64
}

type outputArithmetic struct{ err error }

func (a *outputArithmetic) add(values ...uint64) uint64 {
	if a.err != nil {
		return 0
	}
	var total uint64
	for _, value := range values {
		if value > math.MaxUint64-total {
			a.err = fail(ReasonLimit)
			return 0
		}
		total += value
	}
	return total
}

func (a *outputArithmetic) mul(first, second uint64) uint64 {
	if a.err != nil {
		return 0
	}
	if first != 0 && second > math.MaxUint64/first {
		a.err = fail(ReasonLimit)
		return 0
	}
	return first * second
}

func (a *outputArithmetic) merge(first, second outputSize) outputSize {
	return outputSize{a.add(first.backing, second.backing), a.add(first.json, second.json), max(first.longest, second.longest), a.add(first.custom, second.custom), max(first.depth, second.depth)}
}

type outputEmitterParts struct {
	plan, manifest, models, modelFamily, differenceFamily, planning outputSize
	runMarshal, auditMarshal, modelMarshal, runJSONL, auditJSONL    uint64
	descriptions, keys                                              uint64
	counts                                                          outputMethodCounts
	planCounts                                                      outputMethodCounts
	selectedPlan                                                    outputSize
	canonicalModels                                                 uint64
	headerVisits, rowBoxes                                          uint64
}

// bounds describe owned public backing, not allocator, runtime or process RSS
func plannedOutputMemory(p Plan, tasks []outputTaskBound) (outputMemoryPlan, error) {
	a := &outputArithmetic{}
	shape := outputShape{strings: 128, methods: 16, flags: 128}
	if p.Phase == Pilot && p.Suite == "c25519" {
		if p.Set == Collude {
			shape.planning, shape.powers = 9, 9
		} else if p.Set == Mailbox {
			shape.planning, shape.powers = 4, 4
		}
	}
	if p.Phase == Train || p.TrainingReady {
		shape.models = 8
	}
	if p.Phase == Train {
		shape.references = 8
	}
	retained := plannedOutputType(reflect.TypeFor[Report](), shape, a)
	currentPlan := actualOutputValue(reflect.ValueOf(p), a)
	retained = a.merge(retained, currentPlan)
	parts := outputEmitterParts{
		plan:             a.merge(plannedOutputType(reflect.TypeFor[Plan](), shape, a), currentPlan),
		manifest:         plannedOutputType(reflect.TypeFor[Manifest](), shape, a),
		models:           plannedOutputSlice(reflect.TypeFor[[]FrozenModel](), shape.models, shape, a),
		modelFamily:      plannedOutputSlice(reflect.TypeFor[[]Inference](), nodeFamilySize, shape, a),
		differenceFamily: plannedOutputSlice(reflect.TypeFor[[]Inference](), nodeFamilySize, shape, a),
		planning:         plannedOutputSlice(reflect.TypeFor[[]PlanningResult](), shape.planning, shape, a),
	}
	parts.counts = outputPlannedMethods(reflect.TypeFor[Report](), shape, a)
	parts.planCounts = outputActualMethods(reflect.ValueOf(&p).Elem(), a)
	parts.selectedPlan = currentPlan
	parts.counts = outputMergeMethods(parts.counts, parts.planCounts, a)
	model := plannedOutputType(reflect.TypeFor[FrozenModel](), shape, a)
	parts.canonicalModels = a.mul(shape.models, outputCanonicalAllocation(model, reflect.TypeFor[FrozenModel](), outputPlannedMethods(reflect.TypeFor[FrozenModel](), shape, a), a))
	parts.modelMarshal = a.mul(shape.models, outputMarshalAllocation(model, uint64(reflect.TypeFor[FrozenModel]().Size()), a))
	var runs, audits outputSize
	var auditCount, groupCount uint64
	for _, task := range tasks {
		if task.First < 0 || task.First > 128 || task.Second < 0 || task.Second > 128 || task.MailboxRows < 0 || task.MailboxRows > maxTruthRecords || task.MailboxGroups < 0 || task.MailboxGroups > maxClients/2 || task.MailboxRows > 0 && task.MailboxGroups == 0 {
			return outputMemoryPlan{}, ErrInvalid
		}
		run := plannedOutputType(reflect.TypeFor[RunResult](), shape, a)
		parts.counts = outputMergeMethods(parts.counts, outputPlannedMethods(reflect.TypeFor[RunResult](), shape, a), a)
		runs = a.merge(runs, run)
		parts.runMarshal = a.add(parts.runMarshal, outputMarshalAllocation(run, uint64(reflect.TypeFor[RunResult]().Size()), a))
		parts.runJSONL = a.add(parts.runJSONL, run.json, 1)
		link := shape
		link.groups = uint64(task.First)
		link.buckets = a.mul(uint64(task.First), uint64(task.Second))
		link.top = link.groups
		mail := shape
		mail.groups, mail.buckets = uint64(task.MailboxGroups), uint64(task.MailboxRows)
		for _, part := range []struct {
			count uint64
			shape outputShape
		}{{14, link}, {2, mail}} {
			row := plannedOutputType(reflect.TypeFor[RankAudit](), part.shape, a)
			audits = a.merge(audits, outputSize{a.mul(part.count, row.backing), a.mul(part.count, row.json), row.longest, a.mul(part.count, row.custom), row.depth})
			parts.auditMarshal = a.add(parts.auditMarshal, a.mul(part.count, outputMarshalAllocation(row, uint64(reflect.TypeFor[RankAudit]().Size()), a)))
			parts.auditJSONL = a.add(parts.auditJSONL, a.mul(part.count, a.add(row.json, 1)))
			auditCount = a.add(auditCount, part.count)
			groupCount = a.add(groupCount, a.mul(part.count, part.shape.groups))
		}
	}
	runCount := uint64(len(tasks))
	retained = addOutputRows(retained, runs, runCount, reflect.TypeFor[RunResult](), a)
	retained = addOutputRows(retained, audits, auditCount, reflect.TypeFor[RankAudit](), a)
	parts.keys = min(a.mul(runCount, 16), a.mul(uint64(len(p.Configurations)), 16))
	parts.descriptions = a.add(parts.keys, min(a.mul(runCount, 2), a.mul(uint64(len(p.Configurations)), 2)))
	hp := outputPlanHeaders(&p, a)
	hr := a.add(hp, 6, a.mul(3, outputCapacityUpper(shape.planning, a)), a.mul(4, outputCapacityUpper(runCount, a)), a.mul(2, outputCapacityUpper(auditCount, a)), a.add(a.mul(groupCount, 5), 1)/2, a.mul(4, auditCount), a.mul(6, outputCapacityUpper(shape.models, a)))
	parts.headerVisits = a.add(hp, a.mul(6, hr))
	parts.rowBoxes = a.mul(2, outputRowBytes(runCount, auditCount, shape.models, a))
	return finishOutputMemory(retained, a.mul(runCount, 16), runCount, uint64(len(p.Configurations)), shape, parts, a)
}

// source admission establishes public ownership and bounded, cloned variable strings
func actualOutputMemory(r Report) (outputMemoryPlan, error) {
	a := &outputArithmetic{}
	retained := actualOutputValue(reflect.ValueOf(r), a)
	parts := outputEmitterParts{
		plan:             actualOutputValue(reflect.ValueOf(r.Plan), a),
		manifest:         actualOutputValue(reflect.ValueOf(r.Manifest), a),
		models:           actualOutputValue(reflect.ValueOf(r.Models), a),
		modelFamily:      actualOutputValue(reflect.ValueOf(r.ModelInference), a),
		differenceFamily: actualOutputValue(reflect.ValueOf(r.DifferenceInference), a),
		planning:         actualOutputValue(reflect.ValueOf(r.Planning), a),
	}
	parts.counts = outputActualMethods(reflect.ValueOf(&r).Elem(), a)
	parts.planCounts = outputActualMethods(reflect.ValueOf(&r.Plan).Elem(), a)
	parts.selectedPlan = parts.plan
	var methods uint64
	for _, run := range r.Runs {
		methods = a.add(methods, uint64(len(run.Methods)))
		size := actualOutputValue(reflect.ValueOf(run), a)
		parts.runMarshal = a.add(parts.runMarshal, outputMarshalAllocation(size, uint64(reflect.TypeFor[RunResult]().Size()), a))
		parts.runJSONL = a.add(parts.runJSONL, size.json, 1)
	}
	for _, row := range r.Audit {
		size := actualOutputValue(reflect.ValueOf(row), a)
		parts.auditMarshal = a.add(parts.auditMarshal, outputMarshalAllocation(size, uint64(reflect.TypeFor[RankAudit]().Size()), a))
		parts.auditJSONL = a.add(parts.auditJSONL, size.json, 1)
	}
	for _, model := range r.Models {
		size := actualOutputValue(reflect.ValueOf(model), a)
		parts.canonicalModels = a.add(parts.canonicalModels, outputCanonicalAllocation(size, reflect.TypeFor[FrozenModel](), outputActualMethods(reflect.ValueOf(&model).Elem(), a), a))
		parts.modelMarshal = a.add(parts.modelMarshal, outputMarshalAllocation(size, uint64(reflect.TypeFor[FrozenModel]().Size()), a))
	}
	parts.descriptions, parts.keys = outputDescriptiveCounts(r, a)
	parts.headerVisits = a.add(outputPlanHeaders(&r.Plan, a), a.mul(6, outputReportHeaders(&r, a)))
	parts.rowBoxes = a.mul(2, outputRowBytes(uint64(len(r.Runs)), uint64(len(r.Audit)), uint64(len(r.Models)), a))
	shape := outputShape{strings: max(uint64(128), retained.longest), planning: uint64(len(r.Planning)), models: uint64(len(r.Models))}
	return finishOutputMemory(retained, methods, uint64(len(r.Runs)), uint64(len(r.Plan.Configurations)), shape, parts, a)
}

func checkOutputHost(p outputMemoryPlan, available, overlapping uint64) error {
	a := &outputArithmetic{}
	if p.TotalBytes != a.add(p.RetainedBytes, p.EmitterBytes) || a.err != nil {
		return ErrInvalid
	}
	required := a.add(p.TotalBytes, overlapping)
	if a.err != nil || required > available {
		return fail(ReasonLimit)
	}
	return nil
}

type outputShape struct {
	strings, methods, flags, groups, buckets, top, planning, models, powers, references uint64
	catalog                                                                             bool
	source                                                                              bool
	configurations                                                                      uint64
}

func outputStringLimit(t reflect.Type, shape outputShape) uint64 {
	if t == reflect.TypeFor[Reason]() {
		var longest int
		for _, reason := range reasons {
			longest = max(longest, len(reason))
		}
		return uint64(longest)
	}
	return shape.strings
}

func (s outputShape) count(parent reflect.Type, name string) (uint64, bool) {
	if parent == reflect.TypeFor[RankAudit]() && name == "TopOne" {
		return s.top, true
	}
	if s.source {
		return outputSourceCount(parent, name, s.configurations)
	}
	switch parent.Name() + "." + name {
	case "Report.Runs", "Report.Audit", "Plan.Configurations", "Plan.WindowsNS", "Plan.Samples", "Plan.PowerSearch":
		return 0, true
	case "Family.IDs":
		if s.catalog {
			return nodeFamilySize, true
		}
		return 0, true
	case "Coordinate.Controlled", "Coordinate.ForeignPositions":
		if s.catalog {
			return 3, true
		}
		return 0, true
	case "Report.Planning":
		return s.planning, true
	case "Report.Models":
		return s.models, true
	case "Report.ModelInference", "Report.DifferenceInference":
		return nodeFamilySize, true
	case "Plan.Powers":
		return s.powers, true
	case "Plan.FrozenModels":
		return s.references, true
	case "RunResult.Flags":
		return s.flags, true
	case "RunResult.RouteHistogram":
		return 5, true
	case "RunResult.Methods":
		return s.methods, true
	case "RunResult.LinkingTimes":
		return 2, true
	case "RankAudit.TopOne":
		return s.top, true
	case "PlanningResult.PilotX", "PlanningResult.PilotY", "PowerCalculation.PilotX", "PowerCalculation.PilotY":
		return 5, true
	case "PairedPowerPlan.Search":
		return nodeMaxPairs - 29, true
	case "MailboxFitWitness.Kept", "MailboxFitWitness.Unused", "Discriminant.Weights", "Discriminant.Center", "Discriminant.Kept", "Discriminant.Unused":
		return mailboxFeatureCount, true
	}
	return 0, false
}

// Go 1.27.3 and 1.27.4 nextslicecap is at most 2n; size-class rounding is at most 2x for public elements >=8 bytes
func outputSliceBacking(n uint64, element reflect.Type, a *outputArithmetic) uint64 {
	return a.mul(a.mul(n, uint64(element.Size())), 8)
}

func plannedOutputType(t reflect.Type, s outputShape, a *outputArithmetic) outputSize {
	out := outputSize{backing: uint64(t.Size())}
	switch t.Kind() {
	case reflect.Struct:
		out.json = 2
		out.depth = 1
		for index := 0; index < t.NumField(); index++ {
			field := t.Field(index)
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if field.PkgPath != "" || name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			var child outputSize
			if t == reflect.TypeFor[RankAudit]() && field.Name == "Groups" {
				child = plannedOutputGroups(s, a)
			} else if field.Type.Kind() == reflect.Slice {
				n, ok := s.count(t, field.Name)
				if !ok {
					a.err = ErrInvalid
					return outputSize{}
				}
				child = plannedOutputSlice(field.Type, n, s, a)
			} else {
				child = plannedOutputType(field.Type, s, a)
			}
			if t == reflect.TypeFor[RankBucket]() {
				child.json = outputDigits(s.buckets)
				if field.Name == "Category" {
					child.json = 2
				}
			}
			if field.Type.Kind() == reflect.String && field.Type != reflect.TypeFor[Reason]() {
				limit, ascii := outputFieldString(field.Name, s)
				child.backing, child.longest = a.add(uint64(field.Type.Size()), limit), limit
				child.json = a.add(2, a.mul(limit, 6))
				if ascii {
					child.json = a.add(2, limit)
				}
			}
			out.backing = a.add(out.backing, child.backing-uint64(field.Type.Size()))
			out.json = a.add(out.json, outputJSONString(name, a), 2, child.json)
			out.longest = max(out.longest, child.longest)
			out.custom = a.add(out.custom, child.custom)
			out.depth = max(out.depth, a.add(child.depth, 1))
		}
	case reflect.Array:
		child := plannedOutputType(t.Elem(), s, a)
		n := uint64(t.Len())
		out.backing = a.add(out.backing, a.mul(n, child.backing-uint64(t.Elem().Size())))
		out.json = a.add(2, a.mul(n, a.add(child.json, 1)))
		out.longest = child.longest
		out.custom = a.mul(n, child.custom)
		out.depth = a.add(child.depth, 1)
	case reflect.Pointer:
		child := plannedOutputType(t.Elem(), s, a)
		out.backing = a.add(out.backing, child.backing)
		out.json, out.longest = max(uint64(4), child.json), child.longest
		out.custom = child.custom
		out.depth = child.depth
	case reflect.String:
		out.longest = outputStringLimit(t, s)
		out.backing = a.add(out.backing, out.longest)
		out.json = a.add(2, a.mul(out.longest, 6))
		if t == reflect.TypeFor[Reason]() {
			out.json = a.add(2, out.longest)
		}
	case reflect.Bool:
		out.json = 5
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		out.json = 20
	case reflect.Float32, reflect.Float64:
		out.json = 25
	default:
		a.err = ErrInvalid
	}
	return outputCustomAllocation(t, out, a)
}

func plannedOutputSlice(t reflect.Type, n uint64, s outputShape, a *outputArithmetic) outputSize {
	child := plannedOutputType(t.Elem(), s, a)
	return outputSize{
		backing: a.add(uint64(t.Size()), outputSliceBacking(n, t.Elem(), a), a.mul(n, child.backing-uint64(t.Elem().Size()))),
		json:    max(uint64(4), a.add(2, a.mul(n, a.add(child.json, 1)))),
		longest: child.longest,
		custom:  a.mul(n, child.custom),
		depth:   a.add(child.depth, 1),
	}
}

func plannedOutputGroups(s outputShape, a *outputArithmetic) outputSize {
	t := reflect.TypeFor[[][]RankBucket]()
	bucket := plannedOutputType(reflect.TypeFor[RankBucket](), s, a)
	return outputSize{
		backing: a.add(uint64(t.Size()), outputSliceBacking(s.groups, t.Elem(), a), outputSliceBacking(s.buckets, t.Elem().Elem(), a)),
		json:    max(uint64(4), a.add(2, a.mul(s.groups, 5), a.mul(s.buckets, a.add(bucket.json, 1)))),
		depth:   3,
	}
}

func addOutputRows(out, rows outputSize, n uint64, t reflect.Type, a *outputArithmetic) outputSize {
	out.backing = a.add(out.backing, outputSliceBacking(n, t, a), rows.backing-a.mul(n, uint64(t.Size())))
	out.json = a.add(out.json, rows.json, n)
	out.longest = max(out.longest, rows.longest)
	out.custom = a.add(out.custom, rows.custom)
	out.depth = max(out.depth, a.add(rows.depth, 2))
	return out
}

func actualOutputValue(v reflect.Value, a *outputArithmetic) outputSize {
	t := v.Type()
	out := outputSize{backing: uint64(t.Size())}
	switch v.Kind() {
	case reflect.Struct:
		out.json = 2
		out.depth = 1
		for index := 0; index < v.NumField(); index++ {
			field := t.Field(index)
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if field.PkgPath != "" || name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			child := actualOutputValue(v.Field(index), a)
			out.backing = a.add(out.backing, child.backing-uint64(field.Type.Size()))
			out.json = a.add(out.json, outputJSONString(name, a), 2, child.json)
			out.longest = max(out.longest, child.longest)
			out.custom = a.add(out.custom, child.custom)
			out.depth = max(out.depth, a.add(child.depth, 1))
		}
	case reflect.Array, reflect.Slice:
		out.json = 2
		out.depth = 1
		capacity := v.Len()
		if v.Kind() == reflect.Slice {
			capacity = v.Cap()
			out.backing = a.add(out.backing, a.mul(a.mul(uint64(capacity), uint64(t.Elem().Size())), 2))
			if v.IsNil() {
				out.json = 4
			}
		}
		all := v
		if v.Kind() == reflect.Slice {
			all = v.Slice(0, capacity)
		}
		for index := 0; index < capacity; index++ {
			child := actualOutputValue(all.Index(index), a)
			out.backing = a.add(out.backing, child.backing-uint64(t.Elem().Size()))
			out.longest = max(out.longest, child.longest)
			if index < v.Len() {
				out.json = a.add(out.json, child.json, 1)
				out.custom = a.add(out.custom, child.custom)
				out.depth = max(out.depth, a.add(child.depth, 1))
			}
		}
	case reflect.Pointer:
		out.json = 4
		if !v.IsNil() {
			child := actualOutputValue(v.Elem(), a)
			out.backing = a.add(out.backing, child.backing)
			out.json, out.longest = child.json, child.longest
			out.custom = child.custom
			out.depth = child.depth
		}
	case reflect.String:
		out.longest = uint64(v.Len())
		out.backing = a.add(out.backing, out.longest)
		out.json = outputJSONString(v.String(), a)
	case reflect.Bool:
		out.json = 5
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value := v.Int()
		out.json = outputDigits(uint64(value))
		if value < 0 {
			out.json = outputDigits(uint64(-(value+1))+1) + 1
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		out.json = outputDigits(v.Uint())
	case reflect.Float32, reflect.Float64:
		if math.IsNaN(v.Float()) || math.IsInf(v.Float(), 0) {
			a.err = ErrInvalid
		}
		out.json = 25
	default:
		a.err = ErrInvalid
	}
	return outputCustomAllocation(t, out, a)
}

func outputMapBytes(entries, keyBytes, valueBytes uint64, a *outputArithmetic) uint64 {
	// swiss groups, directory slack and old/new table overlap stay below sixteen slots per live entry
	return a.add(256, a.mul(a.add(entries, 1), a.mul(16, a.add(keyBytes, valueBytes, 16))))
}

func outputDigits(value uint64) uint64 {
	digits := uint64(1)
	for value >= 10 {
		value /= 10
		digits++
	}
	return digits
}

func outputFieldString(name string, s outputShape) (uint64, bool) {
	if s.source && (name == "Features" || name == "FeatureVersion") {
		return s.strings, false
	}
	switch name {
	case "Revision", "Tree", "TrainRevision":
		return 40, true
	case "Digest", "ParentDigest", "MainSeedCommitment", "BinarySHA256", "TransformDigest":
		return 64, true
	case "Method":
		return 11, true
	case "Features", "FeatureVersion":
		return uint64(len(featureVersion)), true
	}
	return s.strings, false
}

func outputJSONString(value string, a *outputArithmetic) uint64 {
	n := uint64(2)
	for index := 0; index < len(value); {
		c := value[index]
		if c < utf8.RuneSelf {
			width := uint64(1)
			switch c {
			case '\\', '"', '\n', '\r', '\t', '\b', '\f':
				width = 2
			case '<', '>', '&':
				width = 6
			default:
				if c < 0x20 {
					width = 6
				}
			}
			n = a.add(n, width)
			index++
			continue
		}
		r, width := utf8.DecodeRuneInString(value[index:])
		if r == utf8.RuneError && width == 1 || r == '\u2028' || r == '\u2029' {
			n = a.add(n, 6)
		} else {
			n = a.add(n, uint64(width))
		}
		index += width
	}
	return n
}

func outputRoundBytes(n uint64, a *outputArithmetic) uint64 {
	// Go 1.27.3 and 1.27.4 noscan size classes and the 8192-byte heap page
	classes := [...]uint64{0, 8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256, 288, 320, 352, 384, 416, 448, 480, 512, 576, 640, 704, 768, 896, 1024, 1152, 1280, 1408, 1536, 1792, 2048, 2304, 2688, 3072, 3200, 3456, 4096, 4864, 5376, 6144, 6528, 6784, 6912, 8192, 9472, 9728, 10240, 10880, 12288, 13568, 14336, 16384, 18432, 19072, 20480, 21760, 24576, 27264, 28672, 32768}
	for _, size := range classes {
		if n <= size {
			return size
		}
	}
	return a.add(n, 8191) &^ 8191
}

func outputRoundObject(n uint64, a *outputArithmetic) uint64 {
	if n > 512 {
		n = a.add(n, 8)
	}
	return outputRoundBytes(n, a)
}

func outputMarshalAllocation(size outputSize, inline uint64, a *outputArithmetic) uint64 {
	// five capacities cover append growth; the sixth prepays a later initializer based on this call's prevLen
	buffer := outputRoundBytes(max(uint64(64), a.mul(size.json, 2)), a)
	// this also covers legacy Buffer doubling; neither bound assumes reuse of pooled state
	return a.add(a.mul(buffer, 6), outputRoundBytes(size.json, a), a.mul(outputRoundObject(inline, a), 2), outputEncoderMetadata(size.depth, a), size.custom)
}

type outputEncoderLayout struct {
	tokens struct {
		stack []uint64
		last  uint64
	}
	names struct {
		offsets []int
		text    []byte
	}
	namespaces []any
	buffer     struct {
		bytes      []byte
		offset     int64
		writer     any
		maximum    int
		available  []byte
		statistics [2]int
	}
	options struct {
		flags           [2]uint64
		indent, prefix  string
		byteLimit       int64
		depthLimit      int
		marshal, decode any
		format          string
	}
	seen map[any]struct{}
}

func outputEncoderMetadata(depth uint64, a *outputArithmetic) uint64 {
	// jsontext.Encoder is 320 bytes; two 112-byte option copies also cover legacy state and its empty map
	out := a.add(outputRoundBytes(uint64(reflect.TypeFor[outputEncoderLayout]().Size()), a), 2*112)
	for capacity := uint64(1); capacity <= depth; {
		out = a.add(out, a.mul(outputRoundBytes(a.mul(capacity, 8), a), 2))
		if capacity >= depth {
			break
		}
		next := a.mul(capacity, 2)
		if a.err != nil {
			return 0
		}
		capacity = next
		if capacity > depth {
			out = a.add(out, a.mul(outputRoundBytes(a.mul(capacity, 8), a), 2))
		}
	}
	return out
}

func outputCustomAllocation(t reflect.Type, out outputSize, a *outputArithmetic) outputSize {
	if t == reflect.TypeFor[Reason]() {
		// Reason marshals a plain string; appendCompact uses a scanner with no container stack
		out.custom = a.add(out.custom, outputMarshalAllocation(outputSize{json: out.json}, 16, a), 64, 16)
	} else if t == reflect.TypeFor[MailboxTraining]() {
		// released training has at most four JSON container levels; scanner stack capacities sum to 1+2+4
		out.custom = a.add(outputMarshalAllocation(outputSize{json: out.json, custom: out.custom, depth: out.depth}, uint64(t.Size()), a), uint64(t.Size()), 64, 7*8, 256)
	}
	return out
}

func outputBodyAllocation(length uint64, a *outputArithmetic) uint64 {
	if length == 0 {
		return 0
	}
	// growslice grows by at least 5/4, so all old/new JSONL capacities sum to at most five final capacities
	return a.mul(outputRoundBytes(a.mul(length, 2), a), 5)
}

func outputNewlineAllocation(length uint64, a *outputArithmetic) uint64 {
	return outputRoundBytes(a.mul(a.add(length, 1), 2), a)
}

func outputCumulativeSlice(n, element, arrays uint64, a *outputArithmetic) uint64 {
	// five final capacities, nextslicecap <=2n and rounded bytes <=5n/4+32 including scan headers
	return a.add(a.add(a.mul(a.mul(n, element), 25), 1)/2, a.mul(arrays, 160))
}

func outputMapFamily(entries, maps, key, value uint64, a *outputArithmetic) uint64 {
	return a.add(a.mul(maps, outputMapBytes(0, key, value, a)), a.mul(entries, a.mul(16, a.add(key, value, 16))))
}

func outputCodecMetadata(t reflect.Type, a *outputArithmetic) uint64 {
	out := a.add(outputMapBytes(1, 16, 8, a), 128)
	switch t.Kind() {
	case reflect.Struct:
		fields := uint64(t.NumField())
		// both field arrays, three name indexes and per-field option maps from jsonv2.makeStructFields
		out = a.add(out, a.mul(outputCumulativeSlice(fields, 256, 1, a), 2), a.mul(outputMapFamily(fields, 1, 16, 8, a), 2), outputMapFamily(fields, 1, 16, 24, a))
		out = a.add(out, a.mul(fields, outputMapBytes(2, 16, 1, a)))
		for index := 0; index < t.NumField(); index++ {
			field := t.Field(index)
			out = a.add(out, uint64(len(field.Name)+len(field.Tag))*4, 8, 64, outputCodecMetadata(field.Type, a))
		}
	case reflect.Array, reflect.Slice, reflect.Pointer:
		out = a.add(out, outputCodecMetadata(t.Elem(), a))
	}
	return out
}

type outputSummaryLayout struct {
	Schema              string
	Status              Reason
	Models, Differences []Inference
	Planning            PowerEstimate
	Search              []PlanningResult
	Descriptive         []DescriptiveSummary
}

type outputPlanningEstimateLayout struct {
	Schema   string        `json:"schema"`
	Set      Set           `json:"set"`
	Phase    Phase         `json:"phase"`
	Estimate PowerEstimate `json:"maximum_paired_planning"`
}

func outputSummarySize(parts outputEmitterParts, s outputShape, a *outputArithmetic) (outputSize, outputSize) {
	descriptive := plannedOutputSlice(reflect.TypeFor[[]DescriptiveSummary](), parts.descriptions, s, a)
	out := outputSize{json: 2, depth: 1}
	for _, field := range []struct {
		name string
		size outputSize
	}{
		{"schema", outputSize{json: a.add(2, a.mul(s.strings, 6))}},
		{"status", plannedOutputType(reflect.TypeFor[Reason](), s, a)},
		{"model_family", parts.modelFamily}, {"difference_family", parts.differenceFamily},
		{"planning_estimate", plannedOutputType(reflect.TypeFor[PowerEstimate](), s, a)},
		{"power_search", parts.planning}, {"descriptive", descriptive},
	} {
		out.json = a.add(out.json, outputJSONString(field.name, a), 2, field.size.json)
		out.custom = a.add(out.custom, field.size.custom)
		out.depth = max(out.depth, a.add(field.size.depth, 1))
	}
	return out, descriptive
}

func outputDescriptiveCounts(r Report, a *outputArithmetic) (uint64, uint64) {
	var descriptions, totalKeys uint64
	for _, coordinate := range r.Plan.Configurations {
		requested := false
		for _, run := range r.Runs {
			if run.Configuration == coordinate.ID {
				requested = true
				break
			}
		}
		if !requested {
			continue
		}
		_, count := requestedSummaryMethods(r.Plan, coordinate)
		totalKeys = a.add(totalKeys, uint64(count))
		descriptions = a.add(descriptions, uint64(count))
		if len(coordinate.Controlled) == 2 {
			descriptions = a.add(descriptions, 2)
		}
	}
	return descriptions, totalKeys
}

func finishOutputMemory(retained outputSize, methods, runs, configurations uint64, s outputShape, parts outputEmitterParts, a *outputArithmetic) (outputMemoryPlan, error) {
	out, err := finishLegacyOutputMemory(retained, methods, runs, configurations, s, parts, a)
	if err != nil {
		return outputMemoryPlan{}, err
	}
	out.ReportLimitBytes, out.LegacyTotalBytes = out.EmitterBytes, out.TotalBytes
	if !outputSelectedBackend() {
		return out, nil
	}
	out.EmitterBytes = outputSelectedEmitter(retained, methods, runs, configurations, s, parts, a)
	out.TotalBytes = a.add(out.RetainedBytes, out.EmitterBytes)
	if a.err != nil {
		return outputMemoryPlan{}, a.err
	}
	return out, nil
}

func finishLegacyOutputMemory(retained outputSize, methods, runs, configurations uint64, s outputShape, parts outputEmitterParts, a *outputArithmetic) (outputMemoryPlan, error) {
	summary, descriptive := outputSummarySize(parts, s, a)
	// PublishReport followed by WriteReport: three whole reports, two validated plan copies, six files
	marshal := a.mul(outputMarshalAllocation(retained, uint64(reflect.TypeFor[Report]().Size()), a), 3)
	marshal = a.add(marshal, a.mul(outputMarshalAllocation(parts.plan, uint64(reflect.TypeFor[Plan]().Size()), a), 3))
	marshal = a.add(marshal, outputMarshalAllocation(parts.manifest, uint64(reflect.TypeFor[Manifest]().Size()), a))
	marshal = a.add(marshal, outputMarshalAllocation(parts.models, uint64(reflect.TypeFor[[]FrozenModel]().Size()), a), a.mul(parts.modelMarshal, 2))
	marshal = a.add(marshal, parts.runMarshal, parts.auditMarshal, outputMarshalAllocation(summary, uint64(reflect.TypeFor[outputSummaryLayout]().Size()), a))
	marshal = a.add(marshal, outputBodyAllocation(parts.runJSONL, a), outputBodyAllocation(parts.auditJSONL, a))
	// load/prepare/validate/final plan encodes and one training/load model pass bound prior owned pool history
	marshal = a.add(marshal, a.mul(outputMarshalAllocation(parts.plan, uint64(reflect.TypeFor[Plan]().Size()), a), 5), parts.modelMarshal)
	// cmd/lab emits this fixed planning record before Run on the pilot and primary paths
	estimate := plannedOutputType(reflect.TypeFor[outputPlanningEstimateLayout](), s, a)
	marshal = a.add(marshal, outputMarshalAllocation(estimate, uint64(reflect.TypeFor[outputPlanningEstimateLayout]().Size()), a), outputNewlineAllocation(estimate.json, a))
	for _, length := range []uint64{retained.json, parts.plan.json, parts.manifest.json, parts.models.json, summary.json} {
		marshal = a.add(marshal, outputNewlineAllocation(length, a))
	}
	keySize := uint64(reflect.TypeFor[struct {
		method string
		window int64
	}]().Size())
	scratch := outputMapFamily(parts.keys, configurations, keySize, 24, a)
	scratch = a.add(scratch, a.mul(outputMapFamily(parts.keys, configurations, keySize, 8, a), 2))
	values := a.add(methods, a.mul(runs, 2))
	scratch = a.add(scratch, outputCumulativeSlice(values, 8, parts.descriptions, a), outputCumulativeSlice(parts.keys, keySize, configurations, a))
	// QuantileInterval, CensoredMedian and Median copies contain no more than all method/link input values
	scratch = a.add(scratch, a.mul(values, 3*8), a.mul(parts.descriptions, 64), outputCumulativeSlice(parts.descriptions, uint64(reflect.TypeFor[DescriptiveSummary]().Size()), 1, a), descriptive.backing)
	// two validations: allowlists, model keys and reflect.DeepEqual's per-coordinate visited maps
	scratch = a.add(scratch, outputMapFamily(a.mul(configurations, 4), a.mul(configurations, 2), 24, 1, a), outputMapFamily(4*nodeFamilySize, 4, 16, 1, a), outputMapFamily(a.mul(s.models, 4), 4, 16, 1, a))
	catalog := s
	catalog.catalog = true
	coordinate := plannedOutputType(reflect.TypeFor[Coordinate](), catalog, a)
	catalogRows := a.mul(max(configurations, uint64(27)), 4)
	scratch = a.add(scratch, outputCumulativeSlice(catalogRows, uint64(reflect.TypeFor[Coordinate]().Size()), 4, a), a.mul(catalogRows, coordinate.backing-uint64(reflect.TypeFor[Coordinate]().Size())))
	scratch = a.add(scratch, a.mul(a.add(a.mul(s.models, 2), 6), 512), a.mul(s.models, 2*256))
	// cold caches include the distinct released-training and summary struct types; repeated types overcount safely
	scratch = a.add(scratch, a.mul(outputCodecMetadata(reflect.TypeFor[Report](), a), 2), outputCodecMetadata(reflect.TypeFor[outputSummaryLayout](), a), outputCodecMetadata(reflect.TypeFor[outputPlanningEstimateLayout](), a))
	out := outputMemoryPlan{RetainedBytes: retained.backing, EmitterBytes: a.add(marshal, scratch)}
	out.TotalBytes = a.add(out.RetainedBytes, out.EmitterBytes)
	if a.err != nil {
		return outputMemoryPlan{}, a.err
	}
	return out, nil
}

type outputMethodCounts struct {
	reasons, training, trainingJSON, trainingPayload uint64
}

type outputPublicSummary = struct {
	Schema      string               `json:"schema"`
	Status      Reason               `json:"status"`
	Models      []Inference          `json:"model_family"`
	Differences []Inference          `json:"difference_family"`
	Planning    PowerEstimate        `json:"planning_estimate"`
	Search      []PlanningResult     `json:"power_search"`
	Descriptive []DescriptiveSummary `json:"descriptive"`
}

func outputMergeMethods(x, y outputMethodCounts, a *outputArithmetic) outputMethodCounts {
	return outputMethodCounts{a.add(x.reasons, y.reasons), a.add(x.training, y.training), max(x.trainingJSON, y.trainingJSON), max(x.trainingPayload, y.trainingPayload)}
}

func outputPlannedMethods(t reflect.Type, s outputShape, a *outputArithmetic) outputMethodCounts {
	if t == reflect.TypeFor[Reason]() {
		return outputMethodCounts{reasons: 1}
	}
	if t == reflect.TypeFor[MailboxTraining]() {
		v := plannedOutputType(t, s, a)
		return outputMethodCounts{training: 1, trainingJSON: v.json, trainingPayload: v.custom}
	}
	if t == reflect.TypeFor[RankAudit]() {
		return outputMethodCounts{}
	}
	var out outputMethodCounts
	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			var child outputMethodCounts
			if f.Type.Kind() == reflect.Slice {
				n, ok := s.count(t, f.Name)
				if !ok {
					a.err = ErrInvalid
					return out
				}
				child = outputPlannedMethods(f.Type.Elem(), s, a)
				child.reasons, child.training = a.mul(n, child.reasons), a.mul(n, child.training)
			} else {
				child = outputPlannedMethods(f.Type, s, a)
			}
			out = outputMergeMethods(out, child, a)
		}
	case reflect.Array:
		out = outputPlannedMethods(t.Elem(), s, a)
		out.reasons, out.training = a.mul(uint64(t.Len()), out.reasons), a.mul(uint64(t.Len()), out.training)
	case reflect.Pointer:
		out = outputPlannedMethods(t.Elem(), s, a)
	}
	return out
}

func outputActualMethods(v reflect.Value, a *outputArithmetic) outputMethodCounts {
	if v.Type() == reflect.TypeFor[Reason]() {
		return outputMethodCounts{reasons: 1}
	}
	if v.Type() == reflect.TypeFor[MailboxTraining]() {
		s := outputSerializedSize(v, a)
		return outputMethodCounts{training: 1, trainingJSON: s.json, trainingPayload: s.custom}
	}
	var out outputMethodCounts
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			out = outputMergeMethods(out, outputActualMethods(v.Field(i), a), a)
		}
	case reflect.Array, reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			out = outputMergeMethods(out, outputActualMethods(v.Index(i), a), a)
		}
	case reflect.Pointer:
		if !v.IsNil() {
			out = outputActualMethods(v.Elem(), a)
		}
	case reflect.Float32, reflect.Float64:
		if math.IsNaN(v.Float()) || math.IsInf(v.Float(), 0) {
			a.err = ErrInvalid
		}
	}
	return out
}

func outputSerializedSize(v reflect.Value, a *outputArithmetic) outputSize {
	out := outputSize{}
	switch v.Kind() {
	case reflect.Struct:
		out.json, out.depth = 2, 1
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if f.PkgPath != "" || name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			c := outputSerializedSize(v.Field(i), a)
			out.json = a.add(out.json, outputJSONString(name, a), 2, c.json)
			out.custom = a.add(out.custom, c.custom)
			out.longest = max(out.longest, c.longest)
			out.depth = max(out.depth, a.add(c.depth, 1))
		}
	case reflect.Array, reflect.Slice:
		out.json, out.depth = 2, 1
		if v.Kind() == reflect.Slice && v.IsNil() {
			out.json = 4
		}
		for i := 0; i < v.Len(); i++ {
			c := outputSerializedSize(v.Index(i), a)
			out.json = a.add(out.json, c.json, 1)
			out.custom = a.add(out.custom, c.custom)
			out.longest = max(out.longest, c.longest)
			out.depth = max(out.depth, a.add(c.depth, 1))
		}
	case reflect.Pointer:
		out.json = 4
		if !v.IsNil() {
			out = outputSerializedSize(v.Elem(), a)
		}
	case reflect.String:
		out.json = outputJSONString(v.String(), a)
		out.longest = uint64(v.Len())
	case reflect.Bool:
		out.json = 5
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		x := v.Int()
		if x < 0 {
			out.json = a.add(outputDigits(uint64(-(x+1))+1), 1)
		} else {
			out.json = outputDigits(uint64(x))
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		out.json = outputDigits(v.Uint())
	case reflect.Float32, reflect.Float64:
		out.json = 25
		if math.IsNaN(v.Float()) || math.IsInf(v.Float(), 0) {
			a.err = ErrInvalid
		}
	default:
		a.err = ErrInvalid
	}
	return outputCustomAllocation(v.Type(), out, a)
}

func outputTypeBounds(t reflect.Type, a *outputArithmetic) (uint64, uint64, uint64) {
	var path, key uint64
	depth := uint64(1)
	switch t.Kind() {
	case reflect.Array, reflect.Slice, reflect.Pointer:
		path, key, depth = outputTypeBounds(t.Elem(), a)
		depth = a.add(depth, 1)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" {
				name = f.Name
			}
			p, k, d := outputTypeBounds(f.Type, a)
			path = max(path, a.add(uint64(len(name)), p))
			key = max(key, uint64(len(name)), k)
			depth = max(depth, a.add(d, 1))
		}
	}
	return path, key, depth
}

func outputAux(t reflect.Type, a *outputArithmetic) uint64 {
	_, _, d := outputTypeBounds(t, a)
	return a.add(512, a.mul(360, d), a.mul(2, outputRoundObject(uint64(t.Size()), a)))
}
func outputPrefix(t reflect.Type, a *outputArithmetic) uint64 {
	_, _, d := outputTypeBounds(t, a)
	return a.add(512, a.mul(360, d))
}
func outputTrie(n uint64, a *outputArithmetic) uint64 {
	return a.add(a.mul(a.add(1, a.mul(16, n)), 160), a.mul(48, n))
}
func outputPools(n, p uint64, a *outputArithmetic) uint64 {
	if p < 2 || p > 64 {
		a.err = ErrUnsupported
		return 0
	}
	return a.mul(n, a.add(a.mul(2, outputRoundObject(a.mul(128, p), a)), 4112))
}

func outputTypeOccurrences(t reflect.Type, marshal bool, a *outputArithmetic) uint64 {
	if marshal && (t == reflect.TypeFor[Reason]() || t == reflect.TypeFor[MailboxTraining]()) {
		return 1
	}
	n := uint64(1)
	switch t.Kind() {
	case reflect.Array, reflect.Slice, reflect.Pointer:
		n = a.add(n, outputTypeOccurrences(t.Elem(), marshal, a))
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			n = a.add(n, outputTypeOccurrences(t.Field(i).Type, marshal, a))
		}
	}
	return n
}

func outputCache(t reflect.Type, marshal bool, a *outputArithmetic) uint64 {
	n := outputTypeOccurrences(t, marshal, a)
	out := a.add(outputTrie(n, a), a.mul(1024, n))
	if t == reflect.TypeFor[string]() {
		return out
	}
	module := a.add(outputRoundObject(a.mul(8, (1<<20)/96), a), outputMapBytes(1, 8, 24, a), outputCumulativeSlice(4096, 8, 1, a))
	query := a.add(1024, outputRoundBytes(4097, a), outputRoundBytes(4108, a), outputRoundObject(56, a), outputCumulativeSlice(8, 8, 1, a))
	return a.add(out, outputTrie(n, a), module, a.mul(2, outputMapBytes(320, 8, 8, a)), a.mul(n, query))
}

func outputFields(t reflect.Type, a *outputArithmetic) uint64 {
	switch t.Kind() {
	case reflect.Array, reflect.Slice, reflect.Pointer:
		return outputFields(t.Elem(), a)
	case reflect.Struct:
		n := uint64(t.NumField())
		out := a.add(outputCumulativeSlice(n, 136, 1, a), outputMapBytes(n, 16, 8, a), 256, a.mul(a.add(n, 1), 4*40), 256, a.mul(a.add(n, 1), 4*56), 8192)
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			out = a.add(out, a.mul(uint64(len(f.Name)+len(f.Tag)), 4), 200, outputFields(f.Type, a))
		}
		return out
	}
	return 0
}

func outputPath(n uint64, a *outputArithmetic) uint64 {
	return a.add(outputCumulativeSlice(n, 1, 1, a), a.mul(2, outputRoundBytes(n, a)))
}
func outputNames(t reflect.Type, a *outputArithmetic) uint64 {
	p, k, d := outputTypeBounds(t, a)
	if t == reflect.TypeFor[string]() {
		p, k, d = 0, 0, 0
	}
	return a.add(outputCumulativeSlice(a.add(p, a.mul(5, k), 2), 1, 1, a), outputPath(a.add(a.mul(2, p), a.mul(21, d)), a), 192)
}

func outputCanonicalAllocation(size outputSize, t reflect.Type, c outputMethodCounts, a *outputArithmetic) uint64 {
	scalar, released := reflect.TypeFor[string](), reflect.TypeFor[MailboxTraining]()
	return a.add(outputMarshalAllocation(size, uint64(t.Size()), a), outputCodecMetadata(t, a), outputAux(t, a), 528, outputCache(t, true, a), outputNames(t, a), a.mul(c.reasons, a.add(outputCache(scalar, true, a), outputAux(scalar, a), outputNames(scalar, a))), a.mul(c.training, a.add(outputFields(released, a), outputCache(released, false, a), outputAux(released, a), outputNames(released, a))), outputPools(a.add(1, c.reasons, c.training), 64, a))
}

type outputStreamParts struct{ buffers, encoder, copies, metadata, aux, cache, names, override, constructors, reasons, training uint64 }

func outputStreamAllocation(size outputSize, c outputMethodCounts, a *outputArithmetic) uint64 {
	p := outputStreamComponents(size, c, a)
	return a.add(p.buffers, p.encoder, p.copies, p.metadata, p.aux, p.cache, p.names, p.override, p.constructors, p.reasons, p.training)
}

func outputStreamComponents(size outputSize, c outputMethodCounts, a *outputArithmetic) outputStreamParts {
	return outputStreamComponentsRoot(size, c, nil, a)
}

func outputRootStreamAllocation(size outputSize, c outputMethodCounts, root reflect.Type, a *outputArithmetic) uint64 {
	p := outputStreamComponentsRoot(size, c, root, a)
	return a.add(p.buffers, p.encoder, p.copies, p.metadata, p.aux, p.cache, p.names, p.override, p.constructors, p.reasons, p.training)
}

func outputStreamComponentsRoot(size outputSize, c outputMethodCounts, root reflect.Type, a *outputArithmetic) outputStreamParts {
	var f, aux, cache, names, occurrences, inline uint64
	for _, t := range [...]reflect.Type{reflect.TypeFor[Report](), reflect.TypeFor[Plan](), reflect.TypeFor[Manifest](), reflect.TypeFor[FrozenModel](), reflect.TypeFor[RunResult](), reflect.TypeFor[RankAudit](), reflect.TypeFor[outputPublicSummary]()} {
		if root != nil && root != t {
			continue
		}
		f = max(f, outputCodecMetadata(t, a))
		aux = max(aux, outputAux(t, a))
		cache = max(cache, outputCache(t, true, a))
		names = max(names, outputNames(t, a))
		occurrences = max(occurrences, outputTypeOccurrences(t, true, a))
		inline = max(inline, uint64(t.Size()))
	}
	token := a.add(8192, a.mul(4, a.add(max(a.add(a.mul(6, size.longest), 2), c.trainingJSON), 24472)), 64*10)
	released := reflect.TypeFor[MailboxTraining]()
	training := a.add(c.trainingPayload, 128, outputFields(released, a), outputCache(released, false, a), outputAux(released, a), outputNames(released, a), outputPools(1, 64, a))
	return outputStreamParts{a.mul(6, outputRoundBytes(a.mul(2, token), a)), outputEncoderMetadata(9, a), a.mul(2, outputRoundObject(inline, a)), f, aux, cache, names, a.add(outputTrie(occurrences, a), a.mul(4096, occurrences)), 4096, a.mul(64, c.reasons), a.mul(c.training, training)}
}

func outputCoordinateConstruction(n uint64, a *outputArithmetic) uint64 {
	t := reflect.TypeFor[Coordinate]()
	return a.add(a.mul(2, outputCumulativeSlice(n, uint64(t.Size()), 1, a)), a.mul(n, outputSourceGraph(t, n, a)), a.mul(2048, n), 4096)
}

func outputDefaultConstruction(n uint64, a *outputArithmetic) uint64 {
	ids := a.add(outputCumulativeSlice(13, 16, 1, a), a.mul(13, outputRoundBytes(128, a)))
	return a.add(uint64(reflect.TypeFor[Plan]().Size()), outputCoordinateConstruction(n, a), a.mul(2, ids), outputCumulativeSlice(5, 8, 1, a), a.mul(16, outputRoundBytes(128, a)), outputRoundBytes(uint64(len(transformDescription)), a), 528, 4096)
}

func outputPlanNoncodec(n uint64, a *outputArithmetic) uint64 {
	ids := a.add(outputCumulativeSlice(13, 16, 1, a), a.mul(13, outputRoundBytes(128, a)))
	boxes := a.add(a.mul(2, outputRoundObject(uint64(reflect.TypeFor[Plan]().Size()), a)), a.mul(2, a.add(a.mul(2, outputRoundObject(uint64(reflect.TypeFor[Family]().Size()), a)), outputRoundObject(24, a), a.mul(n, outputRoundObject(uint64(reflect.TypeFor[Coordinate]().Size()), a)))))
	return a.add(outputDefaultConstruction(n, a), a.mul(8, outputCoordinateConstruction(21, a)), outputMapBytes(n, 16, 1, a), outputMapBytes(8, 16, 1, a), a.mul(8, outputRoundBytes(257, a)), a.mul(a.add(n, 3), outputMapBytes(4, 32, 1, a)), boxes, a.mul(13, ids), 4096)
}

func outputSelectedEmitter(retained outputSize, methods, runs, configurations uint64, s outputShape, parts outputEmitterParts, a *outputArithmetic) uint64 {
	rows := outputSelectedOwners(retained, methods, runs, configurations, s, parts, a)
	var total uint64
	for _, n := range rows {
		total = a.add(total, n)
	}
	return total
}

func outputSelectedOwners(retained outputSize, methods, runs, configurations uint64, s outputShape, parts outputEmitterParts, a *outputArithmetic) [17]uint64 {
	var out [17]uint64
	_, descriptive := outputSummarySize(parts, s, a)
	out[0] = a.mul(15, outputStreamAllocation(retained, parts.counts, a))
	out[1] = a.mul(8, outputCanonicalAllocation(parts.selectedPlan, reflect.TypeFor[Plan](), parts.planCounts, a))
	out[2] = a.mul(8, outputPlanNoncodec(configurations, a))
	out[3] = a.mul(3, parts.canonicalModels)
	estimate := plannedOutputType(reflect.TypeFor[outputPlanningEstimateLayout](), s, a)
	out[4] = a.add(outputCanonicalAllocation(estimate, reflect.TypeFor[outputPlanningEstimateLayout](), outputMethodCounts{}, a), outputNewlineAllocation(estimate.json, a), 65536)
	keys, descriptions := parts.keys, parts.descriptions
	values := a.add(methods, a.mul(2, runs))
	out[5] = a.add(outputMapFamily(keys, configurations, 24, 24, a), a.mul(2, outputMapFamily(keys, configurations, 24, 8, a)))
	out[6] = a.add(outputCumulativeSlice(values, 8, descriptions, a), outputCumulativeSlice(keys, 24, configurations, a))
	out[7] = a.add(a.mul(24, values), a.mul(64, descriptions), outputCumulativeSlice(descriptions, uint64(reflect.TypeFor[DescriptiveSummary]().Size()), 1, a), descriptive.backing)
	out[8] = a.add(outputMapFamily(a.mul(4, configurations), a.mul(2, configurations), 24, 1, a), outputMapFamily(52, 4, 16, 1, a), outputMapFamily(32, 4, 16, 1, a))
	catalog := s
	catalog.catalog = true
	coordinate := plannedOutputType(reflect.TypeFor[Coordinate](), catalog, a)
	rows := a.mul(4, max(configurations, uint64(27)))
	out[9] = a.add(outputCumulativeSlice(rows, uint64(reflect.TypeFor[Coordinate]().Size()), 4, a), a.mul(rows, coordinate.backing-uint64(reflect.TypeFor[Coordinate]().Size())))
	out[10] = 22*512 + 8*512
	out[11] = a.add(a.mul(2, outputCodecMetadata(reflect.TypeFor[Report](), a)), outputCodecMetadata(reflect.TypeFor[outputPublicSummary](), a), outputCodecMetadata(reflect.TypeFor[outputPlanningEstimateLayout](), a))
	out[12] = 3 * 65536
	out[13] = a.mul(18, outputPrefix(reflect.TypeFor[Report](), a))
	out[14] = a.mul(24, parts.headerVisits)
	out[15] = parts.rowBoxes
	out[16] = 4800
	return out
}

func outputCapacityUpper(n uint64, a *outputArithmetic) uint64 {
	if n == 0 {
		return 0
	}
	return a.add(a.add(a.mul(5, n), 1)/2, 4)
}

func outputAdmit(need uint64) error {
	available, err := availableHostMemory()
	if err != nil {
		return err
	}
	if need > available {
		return fail(ReasonLimit)
	}
	return nil
}

func outputEarlyEntry() error {
	if !outputSelectedBackend() {
		return nil
	}
	if err := outputAdmit(65536); err != nil {
		return err
	}
	return outputSupportedProfile()
}

func outputPlanHeaders(p *Plan, a *outputArithmetic) uint64 {
	return a.add(8, a.mul(2, uint64(cap(p.Configurations))), a.mul(2, uint64(cap(p.Powers))), uint64(cap(p.PowerSearch)))
}
func outputModelHeaders(m *FrozenModel, a *outputArithmetic) uint64 {
	var n uint64
	if m.Training.Model != nil {
		n = a.add(n, 4)
	}
	if m.Training.Witness != nil {
		n = a.add(n, 2)
	}
	return n
}
func outputReportHeaders(r *Report, a *outputArithmetic) uint64 {
	n := a.add(outputPlanHeaders(&r.Plan, a), 6, a.mul(3, uint64(cap(r.Planning))), a.mul(4, uint64(cap(r.Runs))))
	allAudit, allModels := r.Audit[:cap(r.Audit)], r.Models[:cap(r.Models)]
	for i := range allAudit {
		n = a.add(n, 2, uint64(cap(allAudit[i].Groups)))
	}
	for i := range allModels {
		n = a.add(n, outputModelHeaders(&allModels[i], a))
	}
	return n
}

func outputRowBytes(runs, audits, models uint64, a *outputArithmetic) uint64 {
	if a.err != nil {
		return 0
	}
	total := a.mul(outputRoundObject(uint64(reflect.TypeFor[RunResult]().Size()), a), runs)
	if a.err != nil {
		return 0
	}
	part := a.mul(outputRoundObject(uint64(reflect.TypeFor[RankAudit]().Size()), a), audits)
	if a.err != nil {
		return 0
	}
	total = a.add(total, part)
	if a.err != nil {
		return 0
	}
	part = a.mul(outputRoundObject(uint64(reflect.TypeFor[FrozenModel]().Size()), a), models)
	if a.err != nil {
		return 0
	}
	return a.add(total, part)
}

func outputPlanPreparation(p *Plan) error {
	return outputPlanPreparationCore(p, outputAdmit, nil)
}

func outputPlanPreparationCore(p *Plan, admit func(uint64) error, beforeSizing func()) error {
	if admit == nil {
		return ErrInvalid
	}
	if !outputSelectedBackend() {
		return nil
	}
	if err := admit(65536); err != nil {
		return err
	}
	a := &outputArithmetic{}
	controls := a.add(65536, 320, a.mul(24, outputPlanHeaders(p, a)), outputAux(reflect.TypeFor[Plan](), a), outputPrefix(reflect.TypeFor[Plan](), a))
	if a.err != nil {
		return a.err
	}
	if err := admit(controls); err != nil {
		return err
	}
	if beforeSizing != nil {
		beforeSizing()
	}
	size := actualOutputValue(reflect.ValueOf(p).Elem(), a)
	methods := outputActualMethods(reflect.ValueOf(p).Elem(), a)
	price := a.add(controls, outputCanonicalAllocation(size, reflect.TypeFor[Plan](), methods, a), outputPlanNoncodec(max(uint64(len(p.Configurations)), outputCanonicalCount(p.Set)), a))
	if a.err != nil {
		return a.err
	}
	return admit(price)
}

func CheckPlanningEstimateResources() error {
	if err := outputEarlyEntry(); err != nil {
		return err
	}
	return checkPlanningEstimateResources(outputAdmit, nil)
}

func checkPlanningEstimateResources(admit func(uint64) error, beforeMarshal func()) error {
	if admit == nil {
		return ErrInvalid
	}
	if !outputSelectedBackend() {
		return nil
	}
	if err := admit(65536); err != nil {
		return err
	}
	a := &outputArithmetic{}
	s := plannedOutputType(reflect.TypeFor[outputPlanningEstimateLayout](), outputShape{strings: 128}, a)
	price := a.add(65536, outputCanonicalAllocation(s, reflect.TypeFor[outputPlanningEstimateLayout](), outputMethodCounts{}, a), outputNewlineAllocation(s.json, a))
	if a.err != nil {
		return a.err
	}
	if err := admit(price); err != nil {
		return err
	}
	if beforeMarshal != nil {
		beforeMarshal()
	}
	return nil
}

func outputSourceCount(parent reflect.Type, name string, c uint64) (uint64, bool) {
	switch parent.Name() + "." + name {
	case "Plan.Configurations":
		return c, true
	case "Family.IDs", "Plan.Samples", "Plan.Powers", "Plan.PowerSearch", "Report.Planning", "Report.ModelInference", "Report.DifferenceInference":
		return 13, true
	case "Coordinate.Controlled", "Coordinate.ForeignPositions":
		return 3, true
	case "Plan.WindowsNS":
		return 5, true
	case "Plan.FrozenModels", "Report.Models":
		return 8, true
	case "RunResult.Flags":
		return 128, true
	case "RunResult.RouteHistogram":
		return 5, true
	case "RunResult.Methods":
		return 16, true
	case "RunResult.LinkingTimes":
		return 2, true
	case "PowerCalculation.PilotX", "PowerCalculation.PilotY", "PlanningResult.PilotX", "PlanningResult.PilotY":
		return 5, true
	case "PairedPowerPlan.Search":
		return 483, true
	case "Discriminant.Weights", "Discriminant.Center", "Discriminant.Kept", "Discriminant.Unused", "MailboxFitWitness.Kept", "MailboxFitWitness.Unused":
		return 18, true
	case "Report.Runs", "Report.Audit":
		return 0, true
	}
	return 0, false
}

func outputSourceGraph(t reflect.Type, c uint64, a *outputArithmetic) uint64 {
	if t == reflect.TypeFor[Reason]() {
		return outputRoundBytes(outputStringLimit(t, outputShape{}), a)
	}
	switch t.Kind() {
	case reflect.Pointer:
		return a.add(outputRoundObject(uint64(t.Elem().Size()), a), outputSourceGraph(t.Elem(), c, a))
	case reflect.Array:
		return a.mul(uint64(t.Len()), outputSourceGraph(t.Elem(), c, a))
	case reflect.Struct:
		var out uint64
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if t == reflect.TypeFor[DescriptiveSummary]() && f.Name == "Method" {
				out = a.add(out, outputRoundBytes(11, a))
				continue
			}
			if f.Type.Kind() == reflect.Slice {
				n, ok := outputSourceCount(t, f.Name, c)
				if !ok {
					a.err = ErrInvalid
					return 0
				}
				out = a.add(out, outputCumulativeSlice(n, uint64(f.Type.Elem().Size()), 1, a), a.mul(n, outputSourceGraph(f.Type.Elem(), c, a)))
			} else {
				out = a.add(out, outputSourceGraph(f.Type, c, a))
			}
		}
		return out
	case reflect.String:
		return outputRoundBytes(128, a)
	}
	return 0
}

func outputPrivateScratch(c, models, methods, runs uint64, a *outputArithmetic) uint64 {
	keys := min(a.mul(runs, methods), a.mul(c, methods))
	descriptions := a.add(keys, min(a.mul(2, runs), a.mul(2, c)))
	values := a.mul(runs, a.add(methods, 2))
	mapRows := a.mul(c, a.add(outputMapBytes(keys, 24, 24, a), a.mul(2, outputMapBytes(keys, 24, 8, a))))
	valuesRows := a.add(outputCumulativeSlice(values, 8, descriptions, a), outputCumulativeSlice(keys, 24, c, a), a.mul(values, 24), a.mul(descriptions, 64), outputCumulativeSlice(descriptions, uint64(reflect.TypeFor[DescriptiveSummary]().Size()), 1, a), a.mul(descriptions, outputSourceGraph(reflect.TypeFor[DescriptiveSummary](), c, a)))
	catalog := a.mul(4, max(c, uint64(27)))
	return a.add(mapRows, valuesRows, outputMapFamily(a.mul(c, 4), a.mul(c, 2), 24, 1, a), outputMapFamily(52, 4, 16, 1, a), outputMapFamily(a.mul(models, 4), 4, 16, 1, a), outputCumulativeSlice(catalog, uint64(reflect.TypeFor[Coordinate]().Size()), 4, a), a.mul(catalog, outputSourceGraph(reflect.TypeFor[Coordinate](), c, a)), a.mul(a.add(a.mul(2, models), 6), 512), a.mul(models, 512), a.mul(2, outputCodecMetadata(reflect.TypeFor[Report](), a)), outputCodecMetadata(reflect.TypeFor[Plan](), a))
}

func outputCanonicalCount(set Set) uint64 {
	switch set {
	case Compromise:
		return 25
	case Collude:
		return 27
	case Mailbox:
		return 21
	}
	return 0
}

func outputCloneGraph(v reflect.Value, a *outputArithmetic) uint64 {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			return a.add(outputRoundObject(uint64(v.Type().Elem().Size()), a), outputCloneGraph(v.Elem(), a))
		}
	case reflect.Array, reflect.Slice:
		var out uint64
		if v.Kind() == reflect.Slice {
			out = outputCumulativeSlice(uint64(v.Len()), uint64(v.Type().Elem().Size()), 1, a)
		}
		for i := 0; i < v.Len(); i++ {
			out = a.add(out, outputCloneGraph(v.Index(i), a))
		}
		return out
	case reflect.Struct:
		var out uint64
		for i := 0; i < v.NumField(); i++ {
			out = a.add(out, outputCloneGraph(v.Field(i), a))
		}
		return out
	case reflect.String:
		return outputRoundBytes(uint64(v.Len()), a)
	}
	return 0
}

type outputSourceLexical struct{ strings, numbers, escaped, numeric, objects uint64 }
type outputSourceLink struct{ tasks, side uint64 }
type outputSourceEnvelope struct {
	outputMemoryPlan
	earlier, preflight uint64
	owners             [17]uint64
	inputs             [10]uint64
}

func outputSourceLexMerge(x, y outputSourceLexical, a *outputArithmetic) outputSourceLexical {
	return outputSourceLexical{a.add(x.strings, y.strings), a.add(x.numbers, y.numbers), a.add(x.escaped, y.escaped), a.add(x.numeric, y.numeric), a.add(x.objects, y.objects)}
}

func outputSourceLexRepeat(x outputSourceLexical, n uint64, a *outputArithmetic) outputSourceLexical {
	return outputSourceLexical{a.mul(x.strings, n), a.mul(x.numbers, n), a.mul(x.escaped, n), a.mul(x.numeric, n), a.mul(x.objects, n)}
}

func outputSourceString(n uint64, a *outputArithmetic) outputSourceLexical {
	return outputSourceLexical{strings: 1, escaped: a.add(outputRoundBytes(a.add(a.mul(6, n), 2), a), a.mul(2, outputRoundBytes(n, a)))}
}

func outputSourceLex(t reflect.Type, s outputShape, a *outputArithmetic) outputSourceLexical {
	if t == reflect.TypeFor[Reason]() {
		return outputSourceString(outputStringLimit(t, s), a)
	}
	if t == reflect.TypeFor[RankBucket]() {
		return outputSourceLexical{4, 4, 64, 4 * 6 * 24, 1}
	}
	switch t.Kind() {
	case reflect.Pointer:
		return outputSourceLex(t.Elem(), s, a)
	case reflect.Array:
		return outputSourceLexRepeat(outputSourceLex(t.Elem(), s, a), uint64(t.Len()), a)
	case reflect.Struct:
		out := outputSourceLexical{objects: 1}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" {
				name = f.Name
			}
			var child outputSourceLexical
			if t == reflect.TypeFor[RankAudit]() && f.Name == "Groups" {
				child = outputSourceLexRepeat(outputSourceLex(reflect.TypeFor[RankBucket](), s, a), s.buckets, a)
			} else if f.Type.Kind() == reflect.Slice {
				n, ok := s.count(t, f.Name)
				if !ok {
					a.err = ErrInvalid
					return out
				}
				child = outputSourceLexRepeat(outputSourceLex(f.Type.Elem(), s, a), n, a)
			} else if f.Type.Kind() == reflect.String && f.Type != reflect.TypeFor[Reason]() {
				n, _ := outputFieldString(f.Name, s)
				child = outputSourceString(n, a)
			} else {
				child = outputSourceLex(f.Type, s, a)
			}
			out = outputSourceLexMerge(out, child, a)
			out.strings = a.add(out.strings, 1)
			out.escaped = a.add(out.escaped, a.mul(2, outputRoundBytes(uint64(len(name)), a)))
		}
		return out
	case reflect.String:
		return outputSourceString(s.strings, a)
	case reflect.Bool:
		return outputSourceLexical{}
	case reflect.Float32, reflect.Float64:
		return outputSourceLexical{numbers: 1, numeric: 6 * 48}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return outputSourceLexical{numbers: 1, numeric: 6 * 48}
	}
	a.err = ErrInvalid
	return outputSourceLexical{}
}

func outputSourceDecoderHistory(length uint64, a *outputArithmetic) uint64 {
	target := a.add(a.mul(length/3, 4), (length%3)*4/3, 1)
	capacity := uint64(64)
	total := outputRoundBytes(capacity, a)
	for capacity < target && a.err == nil {
		capacity = a.mul(capacity, 2)
		total = a.add(total, outputRoundBytes(capacity, a))
	}
	return total
}

func outputSourceMaxFields(t reflect.Type) uint64 {
	switch t.Kind() {
	case reflect.Array, reflect.Slice, reflect.Pointer:
		return outputSourceMaxFields(t.Elem())
	case reflect.Struct:
		n := uint64(t.NumField())
		for i := 0; i < t.NumField(); i++ {
			n = max(n, outputSourceMaxFields(t.Field(i).Type))
		}
		return n
	}
	return 0
}

type outputSourceInput struct{ read, codec, graph uint64 }

func outputSourceSmall(size outputSize, x outputSourceLexical, t reflect.Type, c uint64, a *outputArithmetic) outputSourceInput {
	p, _, d := outputTypeBounds(t, a)
	w := a.add(a.mul(6, p), 898, a.mul(32, a.add(d, 1)))
	v := a.add(a.mul(2, w), a.mul(21, a.add(d, 1)))
	codec := a.add(a.mul(4, outputCodecMetadata(t, a)), a.mul(9, outputCumulativeSlice(a.add(d, 1), 8, 1, a)), a.mul(3, outputCumulativeSlice(a.add(d, 1), 16, 1, a)), a.mul(3, outputRoundObject(40, a)), outputSourceDecoderHistory(size.json, a), a.mul(2, outputSourceDecoderHistory(4096, a)), a.mul(3, a.add(outputRoundObject(48, a), outputRoundObject(40, a))), a.mul(32, a.add(x.strings, x.numbers)), a.mul(3, x.escaped), x.numeric/2, a.mul(3, outputCumulativeSlice(w, 1, 1, a)), a.mul(3, outputPath(v, a)), 280, outputRoundObject(48, a), 32, 16, 14016, 6768, outputCache(t, false, a), outputPools(1, 64, a), 120, a.mul(312, d), 1024, 160, outputBodyAllocation(a.add(size.json, 512), a), outputCumulativeSlice(a.add(1, size.json/240), 24, 1, a), a.mul(x.objects, outputMapBytes(outputSourceMaxFields(t), 16, 1, a)))
	graphConfigurations := c
	if t == reflect.TypeFor[Plan]() {
		graphConfigurations = max(c, uint64(27))
	}
	graph := a.add(uint64(t.Size()), outputSourceGraph(t, graphConfigurations, a))
	if t.Kind() == reflect.Slice && t.Elem() == reflect.TypeFor[FrozenModel]() {
		graph = a.add(uint64(t.Size()), outputCumulativeSlice(8, uint64(t.Elem().Size()), 1, a), a.mul(8, outputSourceGraph(t.Elem(), c, a)))
	}
	return outputSourceInput{a.add(outputRoundBytes(size.json, a), 528, 65536), codec, graph}
}

func outputDefaultSourceEnvelope(tasks, configurations, mailbox uint64, links []outputSourceLink) (outputSourceEnvelope, error) {
	if !outputSelectedBackend() {
		return outputSourceEnvelope{}, ErrUnsupported
	}
	a := &outputArithmetic{}
	s := outputShape{strings: 128, models: 8, planning: 13, powers: 13, references: 8, methods: 16, flags: 128, source: true, configurations: configurations}
	p := plannedOutputType(reflect.TypeFor[Plan](), s, a)
	model := plannedOutputType(reflect.TypeFor[FrozenModel](), s, a)
	run := plannedOutputType(reflect.TypeFor[RunResult](), s, a)
	r := plannedOutputType(reflect.TypeFor[Report](), s, a)
	if a.err != nil {
		return outputSourceEnvelope{}, a.err
	}
	if r.json < 8 {
		return outputSourceEnvelope{}, ErrInvalid
	}
	r.json -= 8
	parts := outputEmitterParts{plan: p, selectedPlan: p, manifest: plannedOutputType(reflect.TypeFor[Manifest](), s, a), models: plannedOutputSlice(reflect.TypeFor[[]FrozenModel](), 8, s, a), modelFamily: plannedOutputSlice(reflect.TypeFor[[]Inference](), 13, s, a), differenceFamily: plannedOutputSlice(reflect.TypeFor[[]Inference](), 13, s, a), planning: plannedOutputSlice(reflect.TypeFor[[]PlanningResult](), 13, s, a)}
	parts.planCounts = outputPlannedMethods(reflect.TypeFor[Plan](), s, a)
	parts.counts = outputMergeMethods(outputPlannedMethods(reflect.TypeFor[Report](), s, a), parts.planCounts, a)
	parts.counts = outputMergeMethods(parts.counts, outputMethodCounts{reasons: a.mul(tasks, outputPlannedMethods(reflect.TypeFor[RunResult](), s, a).reasons)}, a)
	parts.canonicalModels = a.mul(8, outputCanonicalAllocation(model, reflect.TypeFor[FrozenModel](), outputPlannedMethods(reflect.TypeFor[FrozenModel](), s, a), a))
	parts.modelMarshal = a.mul(8, outputMarshalAllocation(model, uint64(reflect.TypeFor[FrozenModel]().Size()), a))
	parts.runMarshal = a.mul(tasks, outputMarshalAllocation(run, uint64(reflect.TypeFor[RunResult]().Size()), a))
	parts.runJSONL = a.mul(tasks, a.add(run.json, 1))
	runRows := outputSize{a.mul(tasks, run.backing), a.mul(tasks, run.json), run.longest, a.mul(tasks, run.custom), run.depth}
	r = addOutputRows(r, runRows, tasks, reflect.TypeFor[RunResult](), a)
	var auditRows outputSize
	var linkTasks, groups uint64
	addAudit := func(n uint64, shape outputShape) {
		row := plannedOutputType(reflect.TypeFor[RankAudit](), shape, a)
		auditRows = a.merge(auditRows, outputSize{a.mul(n, row.backing), a.mul(n, row.json), row.longest, a.mul(n, row.custom), row.depth})
		parts.auditMarshal = a.add(parts.auditMarshal, a.mul(n, outputMarshalAllocation(row, uint64(reflect.TypeFor[RankAudit]().Size()), a)))
		parts.auditJSONL = a.add(parts.auditJSONL, a.mul(n, a.add(row.json, 1)))
		groups = a.add(groups, a.mul(n, shape.groups))
	}
	for _, link := range links {
		linkTasks = a.add(linkTasks, link.tasks)
		row := s
		row.groups, row.top = link.side, link.side
		row.buckets = a.mul(link.side, link.side)
		addAudit(a.mul(14, link.tasks), row)
	}
	if a.err != nil {
		return outputSourceEnvelope{}, a.err
	}
	if linkTasks > tasks || mailbox > tasks {
		return outputSourceEnvelope{}, ErrInvalid
	}
	addAudit(a.mul(14, tasks-linkTasks), s)
	mail := s
	mail.groups, mail.top, mail.buckets = 16, 16, 32768
	addAudit(a.mul(2, mailbox), mail)
	addAudit(a.mul(2, tasks-mailbox), s)
	audits := a.mul(16, tasks)
	r = addOutputRows(r, auditRows, audits, reflect.TypeFor[RankAudit](), a)
	r = a.merge(r, p)
	parts.keys = min(a.mul(tasks, 16), a.mul(configurations, 16))
	parts.descriptions = a.add(parts.keys, min(a.mul(tasks, 2), a.mul(configurations, 2)))
	hp := a.add(8, a.mul(2, outputCapacityUpper(configurations, a)), a.mul(3, outputCapacityUpper(13, a)))
	hr := a.add(hp, 6, a.mul(3, outputCapacityUpper(13, a)), a.mul(4, outputCapacityUpper(tasks, a)), a.mul(6, outputCapacityUpper(8, a)), a.mul(2, outputCapacityUpper(audits, a)), a.add(a.mul(5, groups), 1)/2, a.mul(4, audits))
	parts.headerVisits = a.add(hp, a.mul(6, hr))
	parts.rowBoxes = a.mul(2, outputRowBytes(tasks, audits, 8, a))
	price, err := finishOutputMemory(r, a.mul(16, tasks), tasks, configurations, s, parts, a)
	if err != nil {
		return outputSourceEnvelope{}, err
	}
	out := outputSourceEnvelope{outputMemoryPlan: price, owners: outputSelectedOwners(r, a.mul(16, tasks), tasks, configurations, s, parts, a)}
	planLex := outputSourceLex(reflect.TypeFor[Plan](), s, a)
	bundleLex := outputSourceLexRepeat(outputSourceLex(reflect.TypeFor[FrozenModel](), s, a), 8, a)
	planInput := outputSourceSmall(p, planLex, reflect.TypeFor[Plan](), configurations, a)
	modelInput := outputSourceSmall(parts.models, bundleLex, reflect.TypeFor[[]FrozenModel](), configurations, a)
	out.inputs[0], out.inputs[1], out.inputs[2] = planInput.read, planInput.codec, planInput.graph
	out.inputs[3], out.inputs[4], out.inputs[5] = modelInput.read, modelInput.codec, modelInput.graph
	out.inputs[6] = a.mul(2, outputCanonicalAllocation(p, reflect.TypeFor[Plan](), parts.planCounts, a))
	out.inputs[7] = a.mul(2, outputPlanNoncodec(configurations, a))
	out.inputs[8] = a.add(320, a.mul(24, a.add(a.mul(3, hp), 3*8*6)))
	out.inputs[9] = a.add(a.mul(3, outputAux(reflect.TypeFor[Plan](), a)), a.mul(8, outputAux(reflect.TypeFor[FrozenModel](), a)), 65536)
	for _, n := range out.inputs {
		out.earlier = a.add(out.earlier, n)
	}
	out.preflight = a.add(price.TotalBytes, out.earlier, 64<<20, 320<<20, 32*1875968)
	if a.err != nil {
		return outputSourceEnvelope{}, a.err
	}
	return out, nil
}
