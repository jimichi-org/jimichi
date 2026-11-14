//go:build linux && amd64 && goexperiment.jsonv2

package nodeview

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"os"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

type outputInputLexical struct {
	data                                        []byte
	at                                          int
	tokens, objects, depth, maximum             uint64
	strings, numbers                            uint64
	stringCount, numberCount, material, decoded uint64
	q, m                                        uint64
	arithmetic                                  outputArithmetic
}

func outputInputHex(data []byte) (rune, bool) {
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

func outputInputUnquoteHistory(encoded, decoded uint64, a *outputArithmetic) uint64 {
	quoted := a.add(encoded, 2)
	if decoded <= quoted {
		return outputRoundBytes(quoted, a)
	}
	return outputCumulativeSlice(max(quoted, decoded), 1, 1, a)
}

func (l *outputInputLexical) quoted() error {
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
				unquote = outputInputUnquoteHistory(encoded, decoded, &l.arithmetic)
			}
			l.strings = l.arithmetic.add(l.strings, unquote, l.arithmetic.mul(outputRoundBytes(decoded, &l.arithmetic), 2))
			l.stringCount = l.arithmetic.add(l.stringCount, 1)
			l.material = l.arithmetic.add(l.material, encoded, 2, decoded)
			l.q = max(l.q, l.arithmetic.add(encoded, 2, decoded))
			l.decoded = l.arithmetic.add(l.decoded, decoded)
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
				value, ok := outputInputHex(l.data[l.at+1:])
				if !ok {
					return ErrInvalid
				}
				l.at += 5
				if utf16.IsSurrogate(value) {
					if len(l.data)-l.at >= 6 && l.data[l.at] == '\\' && l.data[l.at+1] == 'u' {
						next, ok := outputInputHex(l.data[l.at+2:])
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

func (l *outputInputLexical) word(word string) bool {
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

func (l *outputInputLexical) number() error {
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
	l.numberCount = l.arithmetic.add(l.numberCount, 1)
	l.m = max(l.m, uint64(l.at-start))
	return l.arithmetic.err
}

func outputInputLex(data []byte) (outputInputLexical, error) {
	l := outputInputLexical{data: data}
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

func outputInputMaxFields(t reflect.Type) uint64 {
	switch t.Kind() {
	case reflect.Array, reflect.Slice, reflect.Pointer:
		return outputInputMaxFields(t.Elem())
	case reflect.Struct:
		n := uint64(t.NumField())
		for i := 0; i < t.NumField(); i++ {
			n = max(n, outputInputMaxFields(t.Field(i).Type))
		}
		return n
	}
	return 0
}

func outputInputSchema(t reflect.Type, depth uint64) error {
	if t == nil || depth >= 9 {
		return ErrInvalid
	}
	switch t.Kind() {
	case reflect.Array, reflect.Slice, reflect.Pointer:
		if t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8 {
			return ErrInvalid
		}
		return outputInputSchema(t.Elem(), depth+1)
	case reflect.Struct:
		if t.NumField() > 35 {
			return ErrInvalid
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, opt, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" {
				name = f.Name
			}
			if f.Anonymous || f.PkgPath != "" || name == "-" || opt != "" && opt != "omitempty" || outputInputSchema(f.Type, depth+1) != nil {
				return ErrInvalid
			}
		}
	case reflect.String, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
	default:
		return ErrInvalid
	}
	return nil
}

func outputInputDecoderHistory(length uint64, a *outputArithmetic) uint64 {
	target := a.add(a.mul(length/3, 4), (length%3)*4/3, 1)
	capacity := uint64(64)
	total := outputRoundBytes(capacity, a)
	for capacity < target && a.err == nil {
		capacity = a.mul(capacity, 2)
		total = a.add(total, outputRoundBytes(capacity, a))
	}
	return total
}

func outputInputCodec(data []byte, t reflect.Type, small bool) (uint64, error) {
	l, err := outputInputLex(data)
	if err != nil {
		return 0, err
	}
	if outputInputSchema(t, 0) != nil {
		return 0, ErrInvalid
	}
	a := &l.arithmetic
	p, _, depth := outputTypeBounds(t, a)
	w := a.add(a.mul(6, p), l.q, a.mul(32, a.add(depth, 1)))
	v := a.add(a.mul(2, w), a.mul(21, a.add(depth, 1)))
	stacks := a.add(a.mul(9, outputCumulativeSlice(a.add(l.maximum, 1), 8, 1, a)), a.mul(3, outputCumulativeSlice(a.add(l.maximum, 1), 16, 1, a)), a.mul(3, outputRoundObject(40, a)))
	scalar := max(uint64(4096), l.q, l.m)
	price := a.add(a.mul(4, outputCodecMetadata(t, a)), stacks, outputInputDecoderHistory(uint64(len(data)), a), outputInputDecoderHistory(scalar, a), a.mul(2, a.add(outputRoundObject(48, a), outputRoundObject(40, a))), a.mul(16, a.add(l.stringCount, l.numberCount)), a.mul(2, l.strings), l.numbers/3, a.mul(3, outputCumulativeSlice(w, 1, 1, a)), a.mul(3, outputPath(v, a)), 280, outputRoundObject(48, a), outputRoundBytes(l.m, a), 16, 14016, 6768, outputCache(t, false, a), outputPools(1, 64, a), 120, a.mul(312, depth), 1024, 160)
	if small {
		price = a.add(price, outputInputDecoderHistory(scalar, a), outputRoundObject(48, a), outputRoundObject(40, a), outputBodyAllocation(a.add(uint64(len(data)), 512), a), outputCumulativeSlice(a.add(uint64(len(data))/240, 1), 24, 1, a), a.mul(16, a.add(l.stringCount, l.numberCount)), l.strings, l.numbers/6, a.mul(l.objects, outputMapBytes(outputInputMaxFields(t), 16, 1, a)))
	}
	return price, a.err
}

func outputInputBucketHistory(n uint64, a *outputArithmetic) uint64 {
	var capacity, total uint64
	for capacity < n && a.err == nil {
		length := a.add(capacity, 1)
		doubled := a.mul(capacity, 2)
		next := capacity
		if a.err != nil {
			return 0
		}
		if length > doubled {
			next = length
		} else if capacity < 256 {
			next = doubled
		} else {
			for next < length && a.err == nil {
				next = a.add(next, a.add(next, 3*256)>>2)
			}
		}
		bytes := outputRoundBytes(a.mul(next, 32), a)
		if a.err != nil || bytes/32 > uint64(math.MaxInt) {
			a.err = fail(ReasonLimit)
			return 0
		}
		capacity = bytes / 32
		total = a.add(total, bytes)
	}
	return total
}

type outputInputShape struct {
	arithmetic outputArithmetic
	backing    uint64
	ranges     bool
}

func outputInputMask(t reflect.Type) (uint64, uint64, error) {
	if t.Kind() != reflect.Struct || t.NumField() > 35 {
		return 0, 0, ErrInvalid
	}
	var required, all uint64
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		_, opt, _ := strings.Cut(f.Tag.Get("json"), ",")
		bit := uint64(1) << uint(i)
		all |= bit
		if opt != "omitempty" {
			required |= bit
		}
	}
	return required, all, nil
}

func outputInputNumber(raw string, t reflect.Type) error {
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if _, err := strconv.ParseInt(raw, 10, t.Bits()); err != nil {
			return ErrInvalid
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if _, err := strconv.ParseUint(raw, 10, t.Bits()); err != nil {
			return ErrInvalid
		}
	case reflect.Float32, reflect.Float64:
		v, err := strconv.ParseFloat(raw, t.Bits())
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (s *outputInputShape) value(d *json.Decoder, t reflect.Type) error {
	token, err := d.Token()
	if err != nil {
		return ErrInvalid
	}
	if token == nil {
		if t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
			return nil
		}
		return ErrInvalid
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
		s.backing = s.arithmetic.add(s.backing, outputRoundObject(uint64(t.Size()), &s.arithmetic))
	}
	switch t.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') || t.NumField() > 35 {
			return ErrInvalid
		}
		var seen uint64
		required, _, maskErr := outputInputMask(t)
		if maskErr != nil {
			return maskErr
		}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return ErrInvalid
			}
			index := -1
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				expected, _, _ := strings.Cut(f.Tag.Get("json"), ",")
				if expected == "" {
					expected = f.Name
				}
				if name == expected {
					index = i
					break
				}
			}
			if index < 0 {
				return ErrInvalid
			}
			bit := uint64(1) << uint(index)
			if seen&bit != 0 {
				return ErrInvalid
			}
			seen |= bit
			if err := s.value(d, t.Field(index).Type); err != nil {
				return err
			}
		}
		if seen&required != required {
			return ErrInvalid
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	case reflect.Array, reflect.Slice:
		if token != json.Delim('[') {
			return ErrInvalid
		}
		var count uint64
		for d.More() {
			if t.Kind() == reflect.Array && count >= uint64(t.Len()) {
				return ErrInvalid
			}
			if err := s.value(d, t.Elem()); err != nil {
				return err
			}
			count = s.arithmetic.add(count, 1)
			if s.arithmetic.err != nil {
				return s.arithmetic.err
			}
		}
		if t.Kind() == reflect.Array && count != uint64(t.Len()) {
			return ErrInvalid
		}
		if t.Kind() == reflect.Slice {
			if t.Elem() == reflect.TypeFor[RankBucket]() {
				s.backing = s.arithmetic.add(s.backing, outputInputBucketHistory(count, &s.arithmetic))
			} else {
				s.backing = s.arithmetic.add(s.backing, outputCumulativeSlice(count, uint64(t.Elem().Size()), 1, &s.arithmetic))
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalid
		}
	case reflect.String:
		v, ok := token.(string)
		if !ok {
			return ErrInvalid
		}
		s.backing = s.arithmetic.add(s.backing, outputRoundBytes(uint64(len(v)), &s.arithmetic))
	case reflect.Bool:
		if _, ok := token.(bool); !ok {
			return ErrInvalid
		}
	default:
		v, ok := token.(json.Number)
		if !ok {
			return ErrInvalid
		}
		if s.ranges && outputInputNumber(string(v), t) != nil {
			return ErrInvalid
		}
	}
	return s.arithmetic.err
}

func outputInputShapeBound(data []byte, t reflect.Type, ranges bool) (uint64, error) {
	if outputInputSchema(t, 0) != nil {
		return 0, ErrInvalid
	}
	s := outputInputShape{backing: uint64(t.Size()), ranges: ranges}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := s.value(d, t); err != nil {
		return 0, err
	}
	if _, err := d.Token(); err != io.EOF {
		return 0, ErrInvalid
	}
	return s.backing, s.arithmetic.err
}

func outputInputInspect(data []byte, t reflect.Type) error {
	return outputInputInspectCore(data, t, outputAdmit, nil, nil)
}

func outputInputInspectCore(data []byte, t reflect.Type, admit func(uint64) error, beforeShape, beforeDecode func()) error {
	if admit == nil {
		return ErrInvalid
	}
	if err := admit(65536); err != nil {
		return err
	}
	codec, err := outputInputCodec(data, t, true)
	if err != nil {
		return err
	}
	a := &outputArithmetic{}
	need := a.add(65536, codec)
	if a.err != nil {
		return a.err
	}
	if err := admit(need); err != nil {
		return err
	}
	if beforeShape != nil {
		beforeShape()
	}
	graph, err := outputInputShapeBound(data, t, true)
	if err != nil {
		return err
	}
	need = a.add(need, graph)
	if a.err != nil {
		return a.err
	}
	if err := admit(need); err != nil {
		return err
	}
	if beforeDecode != nil {
		beforeDecode()
	}
	return nil
}

func outputReadExact(path string, maximum int64, startup bool) ([]byte, error) {
	return outputReadExactCore(path, maximum, startup, outputAdmit, nil)
}

func outputReadExactCore(path string, maximum int64, startup bool, admit func(uint64) error, beforeRead func()) ([]byte, error) {
	if admit == nil {
		return nil, ErrInvalid
	}
	if err := admit(65536); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalid
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > int64(math.MaxInt) || maximum > 0 && before.Size() >= maximum {
		return nil, ErrInvalid
	}
	a := &outputArithmetic{}
	need := a.add(65536, outputRoundBytes(uint64(before.Size()), a), 528)
	if startup {
		need = a.add(need, outputDefaultConstruction(27, a))
	}
	if a.err != nil {
		return nil, a.err
	}
	if err := admit(need); err != nil {
		return nil, err
	}
	if beforeRead != nil {
		beforeRead()
	}
	data := make([]byte, int(before.Size()))
	_, err = io.ReadFull(f, data)
	var extra [1]byte
	n, endErr := f.Read(extra[:])
	after, statErr := f.Stat()
	current, pathErr := os.Stat(path)
	if err != nil || n != 0 || endErr != io.EOF || statErr != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(before, current) || before.Size() != after.Size() || before.Size() != current.Size() || before.ModTime() != after.ModTime() || before.ModTime() != current.ModTime() {
		return nil, ErrInvalid
	}
	return data, nil
}

func outputLoadInput(path string, destination any, regular bool) error {
	t := reflect.TypeOf(destination)
	if t == nil || t.Kind() != reflect.Pointer || reflect.ValueOf(destination).IsNil() {
		return ErrInvalid
	}
	data, err := outputReadExact(path, 8<<20, false)
	if err != nil {
		return err
	}
	if err := outputInputInspect(data, t.Elem()); err != nil {
		return err
	}
	return strictJSON(bytes.NewReader(data), destination)
}

func outputExecutableBytes(path string) ([]byte, error) { return outputReadExact(path, 0, true) }
