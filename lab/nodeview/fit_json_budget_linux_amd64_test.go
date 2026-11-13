//go:build linux && amd64

package nodeview

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"runtime"
	"strings"
	"unsafe"

	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	fitV2ControlReservation = uint64(6 << 20)
	fitV2PoolReservation    = uint64(1 << 20)
	fitV2FrozenPoolPairs    = uint64(72 + 49 + 10)
	fitV2ParentPoolPairs    = fitV2FrozenPoolPairs + 2
	fitV2ProcessPoolPuts    = 2 * fitV2ParentPoolPairs
)

func fitV2ColdControlHistory(a *outputArithmetic) uint64 {
	return a.add(a.mul(92, 36864), a.mul(19, 69632), a.mul(19, 19184), a.mul(128, 512), a.mul(96, 4096), 65536, 65536)
}

func fitV2ColdPoolHistory(a *outputArithmetic) uint64 {
	// every codec pin pays a whole global backing, including copied unrelated pool pointers
	list := a.mul(a.mul(2, fitV2ParentPoolPairs), outputRoundObject(2*64*8, a))
	queue := a.add(a.mul(fitV2ProcessPoolPuts, outputRoundObject(48, a)), outputCumulativeSlice(a.mul(8, fitV2ProcessPoolPuts), 16, fitV2ProcessPoolPuts, a))
	return a.add(list, queue)
}

func fitV2ColdEarlyBudget() (uint64, error) {
	a := &outputArithmetic{}
	controls, pools := fitV2ColdControlHistory(a), fitV2ColdPoolHistory(a)
	if a.err != nil {
		return 0, a.err
	}
	if controls > fitV2ControlReservation || pools > fitV2PoolReservation {
		return 0, fail(ReasonUnsupported)
	}
	return a.add(fitV2ControlReservation, fitV2PoolReservation), a.err
}

type fitJSONLexical struct {
	data                            []byte
	at                              int
	tokens, objects, depth, maximum uint64
	strings, numbers                uint64
	arithmetic                      outputArithmetic
}

func fitJSONHex(data []byte) (rune, bool) {
	if len(data) < 4 {
		return 0, false
	}
	var value rune
	for _, c := range data[:4] {
		value *= 16
		switch {
		case c >= '0' && c <= '9':
			value += rune(c - '0')
		case c >= 'a' && c <= 'f':
			value += rune(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			value += rune(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return value, true
}

func fitJSONUnquoteHistory(encoded, decoded uint64, a *outputArithmetic) uint64 {
	initial := a.add(encoded, 2)
	if decoded <= initial {
		return outputRoundBytes(initial, a)
	}
	return outputCumulativeSlice(max(initial, decoded), 1, 1, a)
}

func (l *fitJSONLexical) quoted() error {
	l.at++
	start := l.at
	var decoded uint64
	unusual := false
	for l.at < len(l.data) {
		c := l.data[l.at]
		if c == '"' {
			encoded := uint64(l.at - start)
			l.at++
			unquote := uint64(0)
			if unusual {
				unquote = fitJSONUnquoteHistory(encoded, decoded, &l.arithmetic)
			}
			l.strings = l.arithmetic.add(l.strings, unquote, l.arithmetic.mul(outputRoundBytes(decoded, &l.arithmetic), 2))
			return l.arithmetic.err
		}
		if c < 0x20 {
			return ErrInvalid
		}
		if c == '\\' {
			unusual = true
			l.at++
			if l.at >= len(l.data) {
				return ErrInvalid
			}
			switch l.data[l.at] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				l.at++
				decoded = l.arithmetic.add(decoded, 1)
			case 'u':
				value, ok := fitJSONHex(l.data[l.at+1:])
				if !ok {
					return ErrInvalid
				}
				l.at += 5
				if utf16.IsSurrogate(value) {
					if l.at+6 <= len(l.data) && l.data[l.at] == '\\' && l.data[l.at+1] == 'u' {
						next, ok := fitJSONHex(l.data[l.at+2:])
						if ok {
							if pair := utf16.DecodeRune(value, next); pair != utf8.RuneError {
								value = pair
								l.at += 6
							} else {
								value = utf8.RuneError
							}
						} else {
							value = utf8.RuneError
						}
					} else {
						value = utf8.RuneError
					}
				}
				decoded = l.arithmetic.add(decoded, uint64(utf8.RuneLen(value)))
			default:
				return ErrInvalid
			}
			continue
		}
		value, width := utf8.DecodeRune(l.data[l.at:])
		if value == utf8.RuneError && width == 1 {
			unusual = true
			decoded = l.arithmetic.add(decoded, 3)
		} else {
			decoded = l.arithmetic.add(decoded, uint64(width))
		}
		l.at += width
	}
	return ErrInvalid
}

func (l *fitJSONLexical) word(word string) bool {
	if len(l.data)-l.at < len(word) {
		return false
	}
	for i := range len(word) {
		if l.data[l.at+i] != word[i] {
			return false
		}
	}
	l.at += len(word)
	return true
}

func (l *fitJSONLexical) number() error {
	start := l.at
	if l.data[l.at] == '-' {
		l.at++
	}
	if l.at >= len(l.data) {
		return ErrInvalid
	}
	if l.data[l.at] == '0' {
		l.at++
	} else {
		if l.data[l.at] < '1' || l.data[l.at] > '9' {
			return ErrInvalid
		}
		for l.at < len(l.data) && l.data[l.at] >= '0' && l.data[l.at] <= '9' {
			l.at++
		}
	}
	if l.at < len(l.data) && l.data[l.at] == '.' {
		l.at++
		begin := l.at
		for l.at < len(l.data) && l.data[l.at] >= '0' && l.data[l.at] <= '9' {
			l.at++
		}
		if begin == l.at {
			return ErrInvalid
		}
	}
	if l.at < len(l.data) && (l.data[l.at] == 'e' || l.data[l.at] == 'E') {
		l.at++
		if l.at < len(l.data) && (l.data[l.at] == '+' || l.data[l.at] == '-') {
			l.at++
		}
		begin := l.at
		for l.at < len(l.data) && l.data[l.at] >= '0' && l.data[l.at] <= '9' {
			l.at++
		}
		if begin == l.at {
			return ErrInvalid
		}
	}
	l.numbers = l.arithmetic.add(l.numbers, l.arithmetic.mul(outputRoundBytes(l.arithmetic.add(uint64(l.at-start), 16), &l.arithmetic), 6))
	return l.arithmetic.err
}

func fitJSONLex(data []byte) (fitJSONLexical, error) {
	l := fitJSONLexical{data: data}
	for l.at < len(data) {
		c := data[l.at]
		switch c {
		case ' ', '\n', '\r', '\t', ':', ',':
			l.at++
			continue
		case '{', '[':
			l.depth = l.arithmetic.add(l.depth, 1)
			l.maximum = max(l.maximum, l.depth)
			if c == '{' {
				l.objects = l.arithmetic.add(l.objects, 1)
			}
			l.at++
		case '}', ']':
			if l.depth == 0 {
				return l, ErrInvalid
			}
			l.depth--
			l.at++
		case '"':
			if l.quoted() != nil {
				return l, ErrInvalid
			}
		case 't':
			if !l.word("true") {
				return l, ErrInvalid
			}
		case 'f':
			if !l.word("false") {
				return l, ErrInvalid
			}
		case 'n':
			if !l.word("null") {
				return l, ErrInvalid
			}
		default:
			if (c != '-' && (c < '0' || c > '9')) || l.number() != nil {
				return l, ErrInvalid
			}
		}
		l.tokens = l.arithmetic.add(l.tokens, 1)
		if l.arithmetic.err != nil {
			return l, l.arithmetic.err
		}
	}
	if l.depth != 0 {
		return l, ErrInvalid
	}
	return l, nil
}

func fitJSONMaxFields(typ reflect.Type) uint64 {
	switch typ.Kind() {
	case reflect.Pointer, reflect.Array, reflect.Slice:
		return fitJSONMaxFields(typ.Elem())
	case reflect.Struct:
		maximum := uint64(typ.NumField())
		for i := range typ.NumField() {
			maximum = max(maximum, fitJSONMaxFields(typ.Field(i).Type))
		}
		return maximum
	}
	return 0
}

func fitJSONDecoderHistory(length uint64, a *outputArithmetic) uint64 {
	target := a.add(a.mul(length, 4)/3, 1)
	capacity, total := uint64(64), uint64(0)
	for a.err == nil {
		total = a.add(total, outputRoundBytes(capacity, a))
		if capacity >= target {
			break
		}
		capacity = a.mul(capacity, 2)
	}
	return total
}

type fitJSONErrorContext struct {
	Structure reflect.Type
	Fields    []string
}

type fitJSONHashLayout struct {
	State  [8]uint32
	Block  [64]byte
	Used   int
	Length uint64
	Short  bool
}

func fitJSONHashBudget(a *outputArithmetic) uint64 {
	return a.add(a.mul(outputRoundObject(uint64(reflect.TypeFor[fitJSONHashLayout]().Size()), a), 2), outputRoundObject(uint64(reflect.TypeFor[uintptr]().Size()), a), outputRoundObject(uint64(reflect.TypeFor[[]byte]().Size()), a), outputRoundObject(uint64(reflect.TypeFor[any]().Size()), a), a.mul(outputRoundBytes(32, a), 3), a.mul(outputRoundBytes(64, a), 2))
}

func fitJSONStackBudget(maximum uint64, a *outputArithmetic) uint64 {
	depth := a.add(maximum, 1)
	return a.add(a.mul(outputCumulativeSlice(depth, 8, 1, a), 9), a.mul(outputCumulativeSlice(depth, 16, 1, a), 3), a.mul(outputRoundObject(uint64(reflect.TypeFor[fitJSONErrorContext]().Size()), a), 3))
}

func fitJSONCodecBudget(data []byte, typ reflect.Type) (uint64, error) {
	l, err := fitJSONLex(data)
	if err != nil {
		return 0, err
	}
	a := &l.arithmetic
	var boxes uint64
	for _, size := range [...]uintptr{reflect.TypeFor[any]().Size(), reflect.TypeFor[any]().Size(), reflect.TypeFor[string]().Size(), reflect.TypeFor[string]().Size(), reflect.TypeFor[json.Number]().Size(), reflect.TypeFor[float64]().Size(), reflect.TypeFor[reflect.Value]().Size(), reflect.TypeFor[json.UnmarshalTypeError]().Size(), reflect.TypeFor[json.SyntaxError]().Size(), reflect.TypeFor[strconv.NumError]().Size()} {
		boxes = a.add(boxes, outputRoundObject(uint64(size), a))
	}
	metadata := a.mul(fitV2ColdDecodeMetadata(typ, a), 4)
	maps := a.mul(l.objects, outputMapBytes(fitJSONMaxFields(typ), 16, 1, a))
	path, key := fitV2ColdNameBounds(typ, a)
	nameBytes := a.add(path, a.mul(key, 5), 2)
	stacks := a.add(a.mul(outputCumulativeSlice(a.add(l.maximum, 1), 8, 1, a), 9), a.mul(outputCumulativeSlice(nameBytes, 1, 1, a), 3), a.mul(outputRoundObject(uint64(reflect.TypeFor[fitJSONErrorContext]().Size()), a), 3))
	decoders := a.mul(a.add(fitJSONDecoderHistory(uint64(len(data)), a), outputRoundObject(uint64(reflect.TypeFor[json.Decoder]().Size()), a), outputRoundObject(uint64(reflect.TypeFor[bytes.Reader]().Size()), a)), 3)
	readAll := a.add(outputBodyAllocation(a.add(uint64(len(data)), 512), a), outputCumulativeSlice(a.add(uint64(len(data))/240, 1), 24, 1, a))
	budget := a.add(metadata, stacks, decoders, readAll, a.mul(a.mul(l.tokens, boxes), 3), a.mul(maps, 2), a.mul(l.strings, 3), l.numbers)
	pointer := a.add(a.mul(path, 2), a.mul(l.maximum, 21))
	fixedErrors := a.add(14016, a.mul(3, a.add(outputCumulativeSlice(pointer, 1, 1, a), a.mul(outputRoundBytes(pointer, a), 2))))
	budget = a.add(budget, 6768, fixedErrors, fitV2ColdPoolLocals(1, a))
	return budget, a.err
}

type fitJSONShape struct {
	jsonShapeValidator
	arithmetic outputArithmetic
	backing    uint64
}

func (s *fitJSONShape) token(d *json.Decoder) (json.Token, error) {
	token, err := d.Token()
	if err != nil {
		return nil, ErrInvalid
	}
	return token, nil
}

func (s *fitJSONShape) value(d *json.Decoder, typ reflect.Type) error {
	token, err := s.token(d)
	if err != nil {
		return ErrInvalid
	}
	if token == nil {
		if typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			return nil
		}
		return ErrInvalid
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
		s.backing = s.arithmetic.add(s.backing, outputRoundObject(uint64(typ.Size()), &s.arithmetic))
	}
	switch typ.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return ErrInvalid
		}
		fields, err := s.objectFields(typ)
		if err != nil {
			return ErrInvalid
		}
		seen := make(map[string]bool, len(fields))
		for d.More() {
			key, err := s.token(d)
			name, ok := key.(string)
			field, known := fields[name]
			if err != nil || !ok || !known || seen[name] {
				return ErrInvalid
			}
			seen[name] = true
			if s.value(d, field.typ) != nil {
				return ErrInvalid
			}
		}
		for name, field := range fields {
			if !field.optional && !seen[name] {
				return ErrInvalid
			}
		}
		if end, err := s.token(d); err != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	case reflect.Array, reflect.Slice:
		if token != json.Delim('[') {
			return ErrInvalid
		}
		var count uint64
		for d.More() {
			if typ.Kind() == reflect.Array && count >= uint64(typ.Len()) || s.value(d, typ.Elem()) != nil {
				return ErrInvalid
			}
			count = s.arithmetic.add(count, 1)
		}
		if typ.Kind() == reflect.Array && count != uint64(typ.Len()) {
			return ErrInvalid
		}
		if typ.Kind() == reflect.Slice {
			s.backing = s.arithmetic.add(s.backing, outputCumulativeSlice(count, uint64(typ.Elem().Size()), 1, &s.arithmetic))
		}
		if end, err := s.token(d); err != nil || end != json.Delim(']') {
			return ErrInvalid
		}
	case reflect.String:
		value, ok := token.(string)
		if !ok {
			return ErrInvalid
		}
		s.backing = s.arithmetic.add(s.backing, outputRoundBytes(uint64(len(value)), &s.arithmetic))
	case reflect.Bool:
		if _, ok := token.(bool); !ok {
			return ErrInvalid
		}
	default:
		if _, ok := token.(json.Number); !ok {
			return ErrInvalid
		}
	}
	return s.arithmetic.err
}

func fitJSONShapeBound(data []byte, typ reflect.Type) (uint64, error) {
	shape := fitJSONShape{jsonShapeValidator: jsonShapeValidator{fields: make(map[reflect.Type]map[string]jsonShapeField)}, backing: uint64(typ.Size())}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if shape.value(d, typ) != nil {
		return 0, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return 0, ErrInvalid
	}
	return shape.backing, shape.arithmetic.err
}

type fitV2ColdOptions struct {
	name, quotedName                         string
	hasName, nameNeedEscape                  bool
	casing                                   int8
	embed, omitzero, omitempty, stringOption bool
	format                                   string
}

type fitV2ColdField struct {
	id, index0      int
	index           []int
	typ             reflect.Type
	fncs            unsafe.Pointer
	isZero, isEmpty func()
	options         fitV2ColdOptions
}

func fitV2ColdProcessors() uint64 {
	return uint64(max(2, runtime.NumCPU(), runtime.GOMAXPROCS(0)))
}

func fitV2ColdProfile() bool {
	return runtime.Version() == "go1.27.4" && runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && fitV2ColdProcessors() <= 64 && unsafe.Sizeof(fitV2ColdOptions{}) == 56 && unsafe.Sizeof(fitV2ColdField{}) == 136 && unsafe.Sizeof(json.Decoder{}) == 48 && unsafe.Sizeof(Coordinate{}) == 424 && unsafe.Sizeof(Settings{}) == 192 && unsafe.Sizeof(Plan{}) == 760
}

func fitV2ColdBackendProfile() bool {
	return fitV2ColdDecoderType(reflect.TypeFor[json.Decoder]())
}

func fitV2ColdDecoderType(typ reflect.Type) bool {
	if typ == nil || typ.Kind() != reflect.Struct || typ.NumField() == 0 {
		return false
	}
	field := typ.Field(0)
	if field.Name != "dec" || field.Offset != 0 || field.Type.Kind() != reflect.Pointer {
		return false
	}
	backend := field.Type.Elem()
	return backend.Kind() == reflect.Struct && backend.Name() == "Decoder" && backend.PkgPath() == "encoding/json/jsontext" && backend.Size() == 312
}

func fitV2ColdCacheBudget(types, fallbacks uint64, a *outputArithmetic) uint64 {
	trie := func(n uint64) uint64 {
		return a.add(a.mul(a.add(1, a.mul(16, n)), 160), a.mul(n, 48))
	}
	budget := a.add(trie(types), a.mul(types, 1024))
	if fallbacks != 0 {
		budget = a.add(budget, trie(fallbacks), a.mul(fallbacks, 1024), 21760, 1792, 34304)
	}
	return budget
}

func fitV2ColdFieldHistory(n uint64, a *outputArithmetic) uint64 {
	if n > 35 {
		a.err = fail(ReasonUnsupported)
		return 0
	}
	var capacity, history uint64
	for capacity < n && a.err == nil {
		logical := a.mul(max(uint64(1), a.mul(capacity, 2)), 136)
		physical := outputRoundObject(logical, a)
		header := uint64(0)
		if logical > 512 {
			header = 8
		}
		if physical < header || (physical-header)/136 <= capacity {
			a.err = fail(ReasonUnsupported)
			return 0
		}
		capacity = (physical - header) / 136
		history = a.add(history, physical)
	}
	return history
}

func fitV2ColdHintMap(n, key, value uint64, a *outputArithmetic) uint64 {
	return a.add(256, a.mul(a.mul(a.add(n, 1), 4), a.add(key, value, 16)))
}

func fitV2ColdFields(t reflect.Type, stopCustom bool, a *outputArithmetic) uint64 {
	if stopCustom && (t == reflect.TypeFor[MailboxTraining]() || t == reflect.TypeFor[Reason]()) {
		return 0
	}
	var out uint64
	switch t.Kind() {
	case reflect.Struct:
		n := uint64(t.NumField())
		// 8192 owns local metadata positions; transitive physical sort stacks retain runtime scope
		out = a.add(fitV2ColdFieldHistory(n, a), outputMapFamily(n, 1, 16, 8, a), fitV2ColdHintMap(n, 16, 8, a), fitV2ColdHintMap(n, 16, 24, a), 8192)
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			_, options, _ := strings.Cut(f.Tag.Get("json"), ",")
			if f.Anonymous || f.PkgPath != "" || options != "" && options != "omitempty" {
				a.err = fail(ReasonUnsupported)
				return 0
			}
			out = a.add(out, uint64(len(f.Name)+len(f.Tag))*4, 200, fitV2ColdFields(f.Type, stopCustom, a))
		}
	case reflect.Array, reflect.Slice, reflect.Pointer:
		out = fitV2ColdFields(t.Elem(), stopCustom, a)
	}
	return out
}

func fitV2ColdCounts(v reflect.Value) (training, reasons uint64) {
	if v.Type() == reflect.TypeFor[MailboxTraining]() {
		return 1, 0
	}
	if v.Type() == reflect.TypeFor[Reason]() {
		return 0, 1
	}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			t, r := fitV2ColdCounts(v.Field(i))
			training, reasons = training+t, reasons+r
		}
	case reflect.Array, reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			t, r := fitV2ColdCounts(v.Index(i))
			training, reasons = training+t, reasons+r
		}
	case reflect.Pointer:
		if !v.IsNil() {
			return fitV2ColdCounts(v.Elem())
		}
	}
	return training, reasons
}

func fitV2ColdMarshalMetadata(v reflect.Value, a *outputArithmetic) (uint64, uint64) {
	t := v.Type()
	training, reasons := fitV2ColdCounts(v)
	var cache uint64
	switch t {
	case reflect.TypeFor[Plan]():
		cache = 256 << 10
		if training != 0 || reasons != 0 {
			a.err = fail(ReasonUnsupported)
		}
	case reflect.TypeFor[FrozenModel]():
		cache = 16 << 10
		if training != 1 || reasons != 0 {
			a.err = fail(ReasonUnsupported)
		}
	case reflect.TypeFor[[]FrozenModel]():
		cache = 96 << 10
		if v.Len() != 8 || training != 8 || reasons != 0 {
			a.err = fail(ReasonUnsupported)
		}
	default:
		a.err = fail(ReasonUnsupported)
	}
	out := a.add(fitV2ColdFields(t, true, a), cache)
	if training != 0 {
		// eager default records are in the outer cache; each invoked released alias remains cold
		nested := a.add(fitV2ColdFields(reflect.TypeFor[MailboxTraining](), false, a), 192<<10)
		out = a.add(out, a.mul(training, nested))
	}
	return out, a.add(training, 1)
}

func fitV2ColdDecodeMetadata(t reflect.Type, a *outputArithmetic) uint64 {
	cache := uint64(192 << 10)
	switch t {
	case reflect.TypeFor[Plan]():
		cache = 256 << 10
	case reflect.TypeFor[FrozenModel](), reflect.TypeFor[[]FrozenModel]():
	default:
		a.err = fail(ReasonUnsupported)
	}
	return a.add(fitV2ColdFields(t, false, a), cache)
}

func fitV2ColdPoolLocals(pairs uint64, a *outputArithmetic) uint64 {
	p := fitV2ColdProcessors()
	if p > 64 {
		a.err = fail(ReasonUnsupported)
		return 0
	}
	return a.mul(a.mul(pairs, 2), outputRoundObject(a.mul(128, p), a))
}

func fitV2ColdNameBounds(t reflect.Type, a *outputArithmetic) (path, key uint64) {
	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" {
				name = f.Name
			}
			p, k := fitV2ColdNameBounds(f.Type, a)
			path, key = max(path, a.add(uint64(len(name)), p)), max(key, uint64(len(name)), k)
		}
	case reflect.Array, reflect.Slice, reflect.Pointer:
		return fitV2ColdNameBounds(t.Elem(), a)
	}
	return path, key
}

func fitV2ColdMetadataProfile() bool {
	a := &outputArithmetic{}
	for _, family := range [...][3]uint64{{33, 11, 262144}, {3, 0, 16384}, {4, 0, 98304}, {21, 11, 196608}, {22, 11, 196608}, {23, 11, 196608}} {
		if fitV2ColdCacheBudget(family[0], family[1], a) > family[2] || a.err != nil {
			return false
		}
	}
	return fitV2ColdFields(reflect.TypeFor[Plan](), true, a)+262144 == 638368 &&
		fitV2ColdFields(reflect.TypeFor[FrozenModel](), true, a)+16384 == 42820 &&
		fitV2ColdFields(reflect.TypeFor[[]FrozenModel](), true, a)+98304 == 124740 &&
		fitV2ColdFields(reflect.TypeFor[MailboxTraining](), false, a)+196608 == 289556 &&
		fitV2ColdDecodeMetadata(reflect.TypeFor[FrozenModel](), a) == 315992 &&
		fitV2ColdDecodeMetadata(reflect.TypeFor[[]FrozenModel](), a) == 315992 && a.err == nil
}
