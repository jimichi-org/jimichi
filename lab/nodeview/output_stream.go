//go:build linux && amd64 && goexperiment.jsonv2

package nodeview

import (
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"io"
	"reflect"
	"runtime"
)

func outputSelectedBackend() bool { return true }

func outputSupportedProfile() error {
	if runtime.Version() != "go1.27.4" || max(2, runtime.NumCPU(), runtime.GOMAXPROCS(0)) > 64 {
		return ErrUnsupported
	}
	t := reflect.TypeFor[json.Decoder]()
	if t.Kind() != reflect.Struct || t.Size() != 48 || t.NumField() == 0 {
		return ErrUnsupported
	}
	f := t.Field(0)
	if f.Name != "dec" || f.Offset != 0 || f.Type.Kind() != reflect.Pointer {
		return ErrUnsupported
	}
	e := f.Type.Elem()
	if e.Kind() != reflect.Struct || e.Name() != "Decoder" || e.PkgPath() != "encoding/json/jsontext" || e.Size() != 312 || reflect.TypeFor[jsontext.Encoder]().Size() != 320 {
		return ErrUnsupported
	}
	if reflect.TypeFor[*string]().Elem() != reflect.TypeFor[string]() {
		return ErrUnsupported
	}
	return nil
}

type outputStreamWriter struct {
	destination io.Writer
	failed      bool
}

func (w *outputStreamWriter) Write(data []byte) (int, error) {
	if err := writePublic(w.destination, data); err != nil {
		w.failed = true
		return 0, fail(ReasonIncomplete)
	}
	return len(data), nil
}

func outputReasonToken(enc *jsontext.Encoder, r Reason) error {
	if !validReason(r) {
		return ErrInvalid
	}
	return enc.WriteToken(jsontext.String(string(r)))
}

func outputMethodSet(t reflect.Type, depth uint64) error {
	if t == nil || depth >= 9 {
		return ErrInvalid
	}
	marshaler := reflect.TypeFor[json.Marshaler]()
	if t == reflect.TypeFor[Reason]() {
		return nil
	}
	allowed := t == reflect.TypeFor[MailboxTraining]()
	if t.Implements(marshaler) && !allowed {
		if t.Kind() != reflect.Pointer || t.Elem() != reflect.TypeFor[Reason]() && t.Elem() != reflect.TypeFor[MailboxTraining]() {
			return ErrInvalid
		}
	}
	if t.Kind() != reflect.Pointer && !allowed && reflect.PointerTo(t).Implements(marshaler) {
		return ErrInvalid
	}
	switch t.Kind() {
	case reflect.Pointer:
		return outputMethodSet(t.Elem(), depth)
	case reflect.Array, reflect.Slice:
		return outputMethodSet(t.Elem(), depth+1)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if err := outputMethodSet(t.Field(i).Type, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func outputStream(w io.Writer, value any, jsonl bool) error {
	return outputStreamWithAdmission(w, value, jsonl, outputAdmit, nil)
}

func outputStreamWithAdmission(w io.Writer, value any, jsonl bool, admit func(uint64) error, beforeMarshal func()) error {
	if jsonl {
		switch rows := value.(type) {
		case []RunResult:
			if len(rows) == 0 {
				return nil
			}
		case []RankAudit:
			if len(rows) == 0 {
				return nil
			}
		default:
			return ErrInvalid
		}
	}
	if admit == nil {
		return ErrInvalid
	}
	a := &outputArithmetic{}
	prefix := outputPrefix(reflect.TypeFor[Report](), a)
	if a.err != nil {
		return a.err
	}
	if err := admit(prefix); err != nil {
		return err
	}
	v := reflect.ValueOf(value)
	if !v.IsValid() {
		return ErrInvalid
	}
	price := a.add(prefix, outputStreamAllocation(outputSerializedSize(v, a), outputActualMethods(v, a), a))
	if a.err != nil {
		return a.err
	}
	if err := admit(price); err != nil {
		return err
	}
	if beforeMarshal != nil {
		beforeMarshal()
	}
	if outputMethodSet(reflect.TypeOf(value), 0) != nil {
		return ErrInvalid
	}
	adapter := outputStreamWriter{destination: w}
	override := jsonv2.MarshalToFunc(outputReasonToken)
	encoder := jsontext.NewEncoder(&adapter, json.DefaultOptionsV1(), jsonv2.WithMarshalers(override))
	write := func(value any) error {
		err := jsonv2.MarshalEncode(encoder, value)
		if adapter.failed {
			return fail(ReasonIncomplete)
		}
		if err != nil {
			return ErrInvalid
		}
		return nil
	}
	if !jsonl {
		return write(value)
	}
	switch rows := value.(type) {
	case []RunResult:
		for i := range rows {
			if err := write(&rows[i]); err != nil {
				return err
			}
		}
	case []RankAudit:
		for i := range rows {
			if err := write(&rows[i]); err != nil {
				return err
			}
		}
	default:
		return ErrInvalid
	}
	return nil
}
