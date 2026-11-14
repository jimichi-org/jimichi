//go:build !linux || !amd64 || !goexperiment.jsonv2

package nodeview

import (
	"encoding/json"
	"io"
)

func outputSelectedBackend() bool { return false }

func outputSupportedProfile() error { return nil }

func outputStreamWithAdmission(w io.Writer, value any, jsonl bool, admit func(uint64) error, beforeMarshal func()) error {
	if beforeMarshal != nil {
		beforeMarshal()
	}
	return outputStream(w, value, jsonl)
}

func outputStream(w io.Writer, value any, jsonl bool) error {
	write := func(v any) error {
		data, err := json.Marshal(v)
		if err != nil {
			return ErrInvalid
		}
		return writePublic(w, append(data, '\n'))
	}
	if !jsonl {
		return write(value)
	}
	switch rows := value.(type) {
	case []RunResult:
		for i := range rows {
			if err := write(rows[i]); err != nil {
				return err
			}
		}
	case []RankAudit:
		for i := range rows {
			if err := write(rows[i]); err != nil {
				return err
			}
		}
	default:
		return ErrInvalid
	}
	return nil
}
