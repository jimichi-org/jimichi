package nodeview

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testNodeviewReport() Report {
	p := testNodeviewPlan(Collude)
	body, _ := json.Marshal(p)
	p.Digest = publicHash(body)
	r := Report{Schema: reportSchema, Plan: p, Status: ReasonIncomplete,
		Manifest: Manifest{Resources: ResourcePoint{Scope: resourceScope, Reason: ReasonIncomplete}, Revision: p.Revision, Tree: p.Tree, BinarySHA256: p.BinarySHA256, Suite: p.Suite, Runtime: "go1.27.3", Kernel: "linux-test", Protection: "protected", Clock: p.Clock, LoadBefore: "unavailable", LoadAfter: "unavailable", LoopbackExemptions: [4]int{-1, -1, -1, -1}, ExemptionReason: p.ExemptionReason}}
	missing := Number{Reason: ReasonIncomplete}
	for _, id := range p.ModelFamily.IDs {
		r.ModelInference = append(r.ModelInference, Inference{ID: id, Reason: ReasonIncomplete, Point: missing, Low: missing, High: missing, P: missing, AdjustedP: missing, Effect: missing, MedianDelta: missing})
	}
	for _, id := range p.DifferenceFamily.IDs {
		r.DifferenceInference = append(r.DifferenceInference, Inference{ID: id, Reason: ReasonIncomplete, Point: missing, Low: missing, High: missing, P: missing, AdjustedP: missing, Effect: missing, MedianDelta: missing})
	}
	return r
}

func TestReportRequiresSealedPlanAndCompleteCleanResourcePoint(t *testing.T) {
	for _, name := range []string{"unsealed", "scope", "clean-unknown", "defined-reason"} {
		t.Run(name, func(t *testing.T) {
			r := testNodeviewReport()
			switch name {
			case "unsealed":
				r.Plan.Digest = ""
			case "scope":
				r.Manifest.Resources.Scope = "other"
			case "clean-unknown":
				r.Status = ReasonNone
			case "defined-reason":
				value := uint64(4096)
				r.Manifest.Resources.MaxRSS = &value
			}
			if err := r.validate(); err == nil {
				t.Fatal("invalid emitted plan or resource coverage accepted")
			}
		})
	}
}

type segmentedPublicWriter struct {
	bytes.Buffer
}

func (w *segmentedPublicWriter) Write(p []byte) (int, error) {
	return w.Buffer.Write(p[:min(len(p), 7)])
}

type stoppedPublicWriter struct{ err error }

func (w stoppedPublicWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWriteReportHandlesShortAndFailedWrites(t *testing.T) {
	r := testNodeviewReport()
	var full bytes.Buffer
	if err := WriteReport(&full, r); err != nil || !json.Valid(full.Bytes()) {
		t.Fatalf("valid report: %v", err)
	}
	var partial segmentedPublicWriter
	if err := WriteReport(&partial, r); err != nil || !bytes.Equal(partial.Bytes(), full.Bytes()) {
		t.Fatalf("short writes silently lost report bytes: %v", err)
	}
	for _, w := range []stoppedPublicWriter{{}, {errors.New("private-writer-sentinel")}} {
		err := WriteReport(w, r)
		if err == nil || strings.Contains(err.Error(), "private-writer-sentinel") {
			t.Fatalf("failed writer returned unsafe success/error: %v", err)
		}
	}
}

func TestReportRejectsUnknownReleaseFieldsBeforeWrite(t *testing.T) {
	const secret = "private-release-sentinel"
	for name, mutate := range map[string]func(*Report){
		"status":        func(r *Report) { r.Status = secret },
		"configuration": func(r *Report) { r.Runs = []RunResult{{Configuration: secret}} },
		"run-phase":     func(r *Report) { r.Runs = []RunResult{{Configuration: r.Plan.Configurations[0].ID, Phase: secret}} },
		"reason": func(r *Report) {
			r.Runs = []RunResult{{Configuration: r.Plan.Configurations[0].ID, Flags: []Reason{secret}}}
		},
		"method": func(r *Report) {
			r.Runs = []RunResult{{Configuration: r.Plan.Configurations[0].ID, Methods: []MethodResult{{Method: secret}}}}
		},
		"audit-configuration": func(r *Report) { r.Audit = []RankAudit{{Configuration: secret, Method: "cells"}} },
		"audit-method":        func(r *Report) { r.Audit = []RankAudit{{Configuration: r.Plan.Configurations[0].ID, Method: secret}} },
		"model-id":            func(r *Report) { r.ModelInference[0].ID = secret },
		"difference-reason":   func(r *Report) { r.DifferenceInference[0].Reason = secret },
		"verdict":             func(r *Report) { r.DifferenceInference[0].Verdict = secret },
	} {
		t.Run(name, func(t *testing.T) {
			r := testNodeviewReport()
			mutate(&r)
			var out bytes.Buffer
			if err := WriteReport(&out, r); err == nil || out.Len() != 0 {
				t.Fatal("unregistered release field reached output")
			}
			root := filepath.Join(t.TempDir(), "not-created")
			if _, err := PublishReport(root, r); err == nil {
				t.Fatal("unregistered release field reached disk")
			}
			if _, err := os.Stat(root); !os.IsNotExist(err) {
				t.Fatal("invalid report touched output root")
			}
		})
	}
}

func TestNonfiniteReportDoesNotCreatePartialPublication(t *testing.T) {
	r := testNodeviewReport()
	invalid := math.NaN()
	r.DifferenceInference[0].Point = Number{Value: &invalid}
	var out bytes.Buffer
	if err := WriteReport(&out, r); err == nil || out.Len() != 0 {
		t.Fatal("nonfinite output accepted")
	}
	root := filepath.Join(t.TempDir(), "not-created")
	if _, err := PublishReport(root, r); err == nil {
		t.Fatal("nonfinite publication accepted")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("nonfinite report created a partial publication")
	}
}

func TestPrivateObservationSerializationAndFormattingDenied(t *testing.T) {
	for _, value := range []any{privateTruth{}, nodeView{}, viewSet{}, predictions{}, mailboxObservation{}, rawMailboxFeatures{}, encodedMailboxRow{}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatalf("private type %T can be serialized", value)
		}
		if fmt.Sprint(value) != "nodeview: private" || fmt.Sprintf("%#v", value) != "nodeview: private" {
			t.Fatalf("private type %T has a revealing formatter", value)
		}
	}
}

func TestPublishReportCreatesExclusiveSanitizedFiles(t *testing.T) {
	r := testNodeviewReport()
	root := t.TempDir()
	first, err := PublishReport(root, r)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(first, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := PublishReport(root, r)
	if err != nil || first == second || filepath.Dir(first) != root || filepath.Dir(second) != root {
		t.Fatalf("publication not exclusive: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(first, "plan.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("later publication changed an existing file")
	}
	want := map[string]bool{"plan.json": true, "manifest.json": true, "runs.jsonl": true, "summary.json": true, "audit.jsonl": true, "frozen-models.json": true}
	entries, err := os.ReadDir(first)
	if err != nil || len(entries) != len(want) {
		t.Fatalf("unexpected report file set: %v", err)
	}
	for _, entry := range entries {
		if !want[entry.Name()] || entry.IsDir() {
			t.Fatal("unexpected public file")
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			t.Fatal("publication is not a regular file")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			t.Fatal("public artifact file mode is not 0600")
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(first)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatal("public artifact directory mode is not 0700")
		}
	}
}

func TestPublishReportRejectsSymlinkRoot(t *testing.T) {
	outside, parent := t.TempDir(), t.TempDir()
	link := filepath.Join(parent, "linked-output")
	if err := os.Symlink(outside, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symlink privilege unavailable")
		}
		t.Fatal(err)
	}
	if _, err := PublishReport(link, testNodeviewReport()); err == nil {
		t.Fatal("publication followed a symlink root")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("symlink target was changed")
	}
}
