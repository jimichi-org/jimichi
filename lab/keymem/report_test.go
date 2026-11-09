package keymem

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReportAggregateOnlyExclusiveFiles(t *testing.T) {
	r := newReport(validTestConfig())
	for i := range r.Trials {
		r.Trials[i].terminal("not_started")
	}
	r.Trials[0] = aggregateTestRow("evaluated", true, [3]uint64{1, 0, 0})
	_ = r.finish()
	dir, e := r.Write(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
		info, e := entry.Info()
		if e != nil {
			t.Fatal(e)
		}
		if info.Mode().Perm()&0077 != 0 && os.PathSeparator == '/' {
			t.Fatal("report file permissions")
		}
		b, e := os.ReadFile(filepath.Join(dir, entry.Name()))
		if e != nil {
			t.Fatal(e)
		}
		for _, value := range []byte{0x11, 0x22, 0x33, 0x44, 0x55} {
			secret := bytes.Repeat([]byte{value}, 32)
			for _, pattern := range [][]byte{secret, []byte(hex.EncodeToString(secret)), []byte(base64.StdEncoding.EncodeToString(secret))} {
				if bytes.Contains(b, pattern) {
					t.Fatal("synthetic secret/control representation reached report")
				}
			}
		}
		for _, forbidden := range [][]byte{[]byte(`"marker_address"`), []byte(`"bundle"`), []byte(`"anchor"`), []byte(`"nonce"`), []byte(`"object_address"`), []byte(`"pattern"`)} {
			if bytes.Contains(b, forbidden) {
				t.Fatal("transient metadata reached report")
			}
		}
	}
	if !reflect.DeepEqual(names, []string{"manifest.json", "summary.json", "trials.jsonl"}) {
		t.Fatal("unexpected output artifact")
	}
	b, e := os.ReadFile(filepath.Join(dir, "summary.json"))
	if e != nil {
		t.Fatal(e)
	}
	var summary map[string]ConditionSummary
	if json.Unmarshal(b, &summary) != nil || !reflect.DeepEqual(summary, r.Summary) {
		t.Fatal("serialized summary mismatch")
	}
	other, e := r.Write(filepath.Dir(dir))
	if e != nil || other == dir {
		t.Fatal("preceding run was reused")
	}
}

func TestReportWriteFailureIsFixed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if e := os.WriteFile(path, nil, 0600); e != nil {
		t.Fatal(e)
	}
	r := newReport(validTestConfig())
	if _, e := r.Write(path); e != errControllerFailed {
		t.Fatal("report write failure not sanitized")
	}
}
