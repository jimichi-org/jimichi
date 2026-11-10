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
	RetainedBytes uint64
	EmitterBytes  uint64
	TotalBytes    uint64
}

type outputSize struct {
	backing, json, longest, custom, depth uint64
}

type outputArithmetic struct{ err error }

func (a *outputArithmetic) add(values ...uint64) uint64 {
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
	model := plannedOutputType(reflect.TypeFor[FrozenModel](), shape, a)
	parts.modelMarshal = a.mul(shape.models, outputMarshalAllocation(model, uint64(reflect.TypeFor[FrozenModel]().Size()), a))
	var runs, audits outputSize
	var auditCount uint64
	for _, task := range tasks {
		if task.First < 0 || task.First > 128 || task.Second < 0 || task.Second > 128 || task.MailboxRows < 0 || task.MailboxRows > maxTruthRecords || task.MailboxGroups < 0 || task.MailboxGroups > maxClients/2 || task.MailboxRows > 0 && task.MailboxGroups == 0 {
			return outputMemoryPlan{}, ErrInvalid
		}
		run := plannedOutputType(reflect.TypeFor[RunResult](), shape, a)
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
		}
	}
	runCount := uint64(len(tasks))
	retained = addOutputRows(retained, runs, runCount, reflect.TypeFor[RunResult](), a)
	retained = addOutputRows(retained, audits, auditCount, reflect.TypeFor[RankAudit](), a)
	parts.keys = min(a.mul(runCount, 16), a.mul(uint64(len(p.Configurations)), 16))
	parts.descriptions = a.add(parts.keys, min(a.mul(runCount, 2), a.mul(uint64(len(p.Configurations)), 2)))
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
		parts.modelMarshal = a.add(parts.modelMarshal, outputMarshalAllocation(size, uint64(reflect.TypeFor[FrozenModel]().Size()), a))
	}
	parts.descriptions, parts.keys = outputDescriptiveCounts(r, a)
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

// Go 1.27.3 nextslicecap is at most 2n; size-class rounding is at most 2x for public elements >=8 bytes
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
	// Go 1.27.3 noscan size classes and the 8192-byte heap page
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
