package nodeview

import (
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
)

type FrozenModel struct {
	Schema          string          `json:"schema"`
	Features        string          `json:"features"`
	Population      string          `json:"population"`
	Configuration   string          `json:"configuration"`
	Suite           string          `json:"suite"`
	TrainRevision   string          `json:"train_revision"`
	TransformDigest string          `json:"transform_digest"`
	Digest          string          `json:"digest,omitempty"`
	Training        MailboxTraining `json:"training"`
}

type Inference struct {
	Method      string `json:"method,omitempty"`
	ID          string `json:"id"`
	Defined     bool   `json:"defined"`
	Reason      Reason `json:"reason,omitempty"`
	Planned     int    `json:"planned"`
	Usable      int    `json:"usable"`
	Failures    int    `json:"failures"`
	Point       Number `json:"point"`
	Low         Number `json:"low"`
	High        Number `json:"high"`
	P           Number `json:"p"`
	AdjustedP   Number `json:"adjusted_p"`
	Effect      Number `json:"effect"`
	MedianDelta Number `json:"median_delta"`
	Verdict     string `json:"verdict"`
}

func (r Report) validate() error {
	if r.Schema != reportSchema || ValidatePlan(r.Plan) != nil || r.Manifest.Revision != r.Plan.Revision || r.Manifest.Tree != r.Plan.Tree || r.Manifest.BinarySHA256 != r.Plan.BinarySHA256 || r.Manifest.Suite != r.Plan.Suite {
		return ErrInvalid
	}
	if r.Plan.Phase == Primary {
		commitment, err := mainSeedCommitment(r.Plan, r.Manifest.BaseSeed)
		if err != nil || r.Plan.MainSeedCommitment != commitment {
			return ErrInvalid
		}
	}
	if !validReason(r.Status) {
		return ErrInvalid
	}
	if r.Plan.Digest == "" || !validResourcePoint(r.Manifest.Resources) || r.Status == ReasonNone && r.Manifest.Resources.MaxRSS == nil {
		return ErrInvalid
	}
	allowed := map[string]bool{}
	for _, c := range r.Plan.Configurations {
		allowed[c.ID] = true
	}
	for _, run := range r.Runs {
		if !allowed[run.Configuration] || run.Repeat < 0 || run.Repeat > 1048576 || run.Phase != Structural && run.Phase != Train && run.Phase != Pilot && run.Phase != Primary {
			return ErrInvalid
		}
		for _, reason := range run.Flags {
			if !validReason(reason) {
				return ErrInvalid
			}
		}
		for _, v := range []Number{run.QueueJoined, run.PutQ, run.PutBaseline, run.RequestLDA, run.RecordLDA} {
			if !validNumber(v) {
				return ErrInvalid
			}
		}
		for i, m := range run.Methods {
			for _, earlier := range run.Methods[:i] {
				if earlier.Method == m.Method && earlier.WindowNS == m.WindowNS {
					return ErrInvalid
				}
			}
			if !knownMethod(m.Method) {
				return ErrInvalid
			}
			for _, v := range []Number{m.AUC, m.TopOne, m.TPR, m.BootstrapLow, m.BootstrapHigh} {
				if !validNumber(v) {
					return ErrInvalid
				}
			}
		}
		for i, link := range run.LinkingTimes {
			if !validLinkingTime(link) {
				return ErrInvalid
			}
			for _, earlier := range run.LinkingTimes[:i] {
				if earlier.Method == link.Method {
					return ErrInvalid
				}
			}
		}
	}
	for _, a := range r.Audit {
		if !allowed[a.Configuration] || !knownMethod(a.Method) || a.Repeat < 0 {
			return ErrInvalid
		}
	}
	for family, rows := range [][]Inference{r.ModelInference, r.DifferenceInference} {
		ids := modelIDs()
		if family == 1 {
			ids = differenceIDs()
		}
		seen := map[string]bool{}
		for _, row := range rows {
			for _, v := range []Number{row.Point, row.Low, row.High, row.P, row.AdjustedP, row.Effect, row.MedianDelta} {
				if !validNumber(v) {
					return ErrInvalid
				}
			}
			if family == 0 && row.Method != "" && row.Method != "normal" && row.Method != "wilson" || family == 1 && row.Method != "" && row.Method != "exact" && row.Method != "degenerate" {
				return ErrInvalid
			}
			known := false
			for _, id := range ids {
				if row.ID == id {
					known = true
				}
			}
			if !known || seen[row.ID] || !validReason(row.Reason) {
				return ErrInvalid
			}
			seen[row.ID] = true
			switch row.Verdict {
			case "", "equivalent", "not shown", "rejected", "not rejected", "degenerate":
			default:
				return ErrInvalid
			}
		}
	}
	for _, planning := range r.Planning {
		known := false
		for _, id := range differenceIDs() {
			if planning.ID == id {
				known = true
			}
		}
		if !known || len(planning.PilotX) != 5 || len(planning.PilotY) != 5 || !validReason(planning.Power.Reason) {
			return ErrInvalid
		}
	}
	modelCoordinates := map[string]bool{}
	for _, coordinate := range canonicalCoordinates(Mailbox) {
		if coordinate.Population == "classifier" {
			modelCoordinates[coordinate.ID] = true
		}
	}
	modelKeys := map[string]bool{}
	for _, m := range r.Models {
		key := m.Configuration + "/" + m.Population
		if modelKeys[key] || m.Schema != "jimichi-nodeview-model-v1" || m.Features != featureVersion || m.TransformDigest != r.Plan.TransformDigest || m.TrainRevision != r.Plan.Revision || m.Suite != r.Plan.Suite || !modelCoordinates[m.Configuration] || m.Population != "request" && m.Population != "record" || !validateMailboxTraining(m.Training) {
			return ErrInvalid
		}
		modelKeys[key] = true
		if m.Training.Releasable {
			copyModel := m
			copyModel.Digest = ""
			b, e := json.Marshal(copyModel)
			if e != nil || m.Digest != publicHash(b) {
				return ErrInvalid
			}
		} else if m.Digest != "" {
			return ErrInvalid
		}
	}
	if r.Plan.TrainingReady {
		if len(r.Models) != 8 {
			return ErrInvalid
		}
		for _, ref := range r.Plan.FrozenModels {
			found := false
			for _, model := range r.Models {
				if model.Configuration == ref.Configuration && model.Population == ref.Population && model.Digest == ref.Digest && model.Training.Releasable {
					found = true
				}
			}
			if !found {
				return ErrInvalid
			}
		}
	}
	if err := guardReportEmission(r); err != nil {
		return err
	}
	if _, e := json.Marshal(r); e != nil {
		return ErrInvalid
	}
	return nil
}

func validNumber(v Number) bool {
	return validReason(v.Reason) && (v.Value == nil || !math.IsNaN(*v.Value) && !math.IsInf(*v.Value, 0))
}
func knownMethod(s string) bool {
	for _, v := range []string{"setup", "close", "shared", "mixed", "cells", "frames", "request", "record", "put"} {
		if s == v {
			return true
		}
	}
	return false
}
func validReason(r Reason) bool {
	for _, v := range reasons {
		if v == r {
			return true
		}
	}
	return false
}

func WriteReport(w io.Writer, r Report) error {
	if e := r.validate(); e != nil {
		return e
	}
	b, e := json.Marshal(r)
	if e != nil {
		return ErrInvalid
	}
	b = append(b, '\n')
	return writePublic(w, b)
}

func PublishReport(root string, r Report) (string, error) {
	if e := r.validate(); e != nil {
		return "", e
	}
	base, e := filepath.Abs(root)
	if e != nil || root == "" {
		return "", ErrInvalid
	}
	if e = rejectSymlinks(base); e != nil {
		return "", e
	}
	if os.MkdirAll(base, 0700) != nil {
		return "", fail(ReasonIncomplete)
	}
	suffix := reportNonce()
	if suffix == "" {
		return "", fail(ReasonIncomplete)
	}
	dir := filepath.Join(base, "nodeview-"+string(r.Plan.Set)+"-"+string(r.Plan.Phase)+"-"+suffix)
	if filepath.Dir(dir) != base || os.Mkdir(dir, 0700) != nil {
		return "", fail(ReasonIncomplete)
	}
	write := func(name string, value any, jsonl bool) error {
		var body []byte
		if jsonl {
			switch rows := value.(type) {
			case []RunResult:
				for _, row := range rows {
					b, e := json.Marshal(row)
					if e != nil {
						return ErrInvalid
					}
					body = append(body, b...)
					body = append(body, '\n')
				}
			case []RankAudit:
				for _, row := range rows {
					b, e := json.Marshal(row)
					if e != nil {
						return ErrInvalid
					}
					body = append(body, b...)
					body = append(body, '\n')
				}
			default:
				return ErrInvalid
			}
		} else {
			var e error
			body, e = json.Marshal(value)
			if e != nil {
				return ErrInvalid
			}
			body = append(body, '\n')
		}
		temp := filepath.Join(dir, "."+name+"."+suffix)
		file, e := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return fail(ReasonIncomplete)
		}
		ok := false
		defer func() {
			file.Close()
			if !ok {
				os.Remove(temp)
			}
		}()
		if e = writePublic(file, body); e != nil {
			return e
		}
		if file.Sync() != nil || file.Close() != nil {
			return fail(ReasonIncomplete)
		}
		target := filepath.Join(dir, name)
		if _, e = os.Lstat(target); !os.IsNotExist(e) {
			return fail(ReasonIncomplete)
		}
		if os.Rename(temp, target) != nil {
			return fail(ReasonIncomplete)
		}
		ok = true
		return nil
	}
	if e = write("plan.json", r.Plan, false); e != nil {
		return dir, e
	}
	if e = write("manifest.json", r.Manifest, false); e != nil {
		return dir, e
	}
	if e = write("runs.jsonl", r.Runs, true); e != nil {
		return dir, e
	}
	if e = write("summary.json", struct {
		Schema      string               `json:"schema"`
		Status      Reason               `json:"status"`
		Models      []Inference          `json:"model_family"`
		Differences []Inference          `json:"difference_family"`
		Planning    PowerEstimate        `json:"planning_estimate"`
		Search      []PlanningResult     `json:"power_search"`
		Descriptive []DescriptiveSummary `json:"descriptive"`
	}{r.Schema, r.Status, r.ModelInference, r.DifferenceInference, PairedPowerEstimate(), r.Planning, descriptiveSummaries(r)}, false); e != nil {
		return dir, e
	}
	if e = write("audit.jsonl", r.Audit, true); e != nil {
		return dir, e
	}
	if e = write("frozen-models.json", r.Models, false); e != nil {
		return dir, e
	}
	return dir, nil
}

func writePublic(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if n < 0 || n > len(b) {
			return fail(ReasonIncomplete)
		}
		b = b[n:]
		if e != nil || n == 0 {
			return fail(ReasonIncomplete)
		}
	}
	return nil
}
func rejectSymlinks(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e == nil && st.Mode()&os.ModeSymlink != 0 {
			return ErrInvalid
		}
		if e != nil && !os.IsNotExist(e) {
			return ErrInvalid
		}
		parent := filepath.Dir(p)
		if p == parent {
			break
		}
	}
	return nil
}

func loadFrozen(path string, p Plan) ([]FrozenModel, error) {
	if ValidatePlan(p) != nil || !p.TrainingReady || len(p.FrozenModels) != 8 {
		return nil, ErrInvalid
	}
	file, e := adjacentFile(path, "frozen-models.json")
	if e != nil {
		return nil, e
	}
	f, e := os.Open(file)
	if e != nil {
		return nil, ErrInvalid
	}
	defer f.Close()
	var models []FrozenModel
	if strictJSON(f, &models) != nil {
		for i := range models {
			wipeMailboxTraining(&models[i].Training)
		}
		return nil, ErrInvalid
	}
	if validateFrozenModels(models, &p) != nil {
		for i := range models {
			wipeMailboxTraining(&models[i].Training)
		}
		return nil, ErrInvalid
	}
	return models, nil
}

func frozenModelMetadataValid(m *FrozenModel, p *Plan) bool {
	if m == nil || p == nil || m.Schema != "jimichi-nodeview-model-v1" || !m.Training.Releasable || m.TrainRevision != p.Revision || m.Suite != p.Suite || m.Features != featureVersion || m.TransformDigest != p.TransformDigest || !digestPattern.MatchString(m.Digest) || m.Population != "request" && m.Population != "record" {
		return false
	}
	known := false
	for _, coordinate := range p.Configurations {
		if coordinate.Population == "classifier" && coordinate.ID == m.Configuration {
			known = true
		}
	}
	if !known {
		return false
	}
	matched := 0
	for _, ref := range p.FrozenModels {
		if ref.Configuration == m.Configuration && ref.Population == m.Population && ref.Digest == m.Digest {
			matched++
		}
	}
	return matched == 1
}

func validateFrozenModel(m *FrozenModel, p *Plan) error {
	if !frozenModelMetadataValid(m, p) || !validateMailboxTraining(m.Training) {
		return ErrInvalid
	}
	preimage := *m
	preimage.Digest = ""
	b, err := json.Marshal(preimage)
	defer clear(b[:cap(b)])
	if err != nil || publicHash(b) != m.Digest {
		return ErrInvalid
	}
	return nil
}

func validateFrozenModels(models []FrozenModel, p *Plan) error {
	if p == nil || ValidatePlan(*p) != nil || !p.TrainingReady || len(p.FrozenModels) != 8 || len(models) != 8 {
		return ErrInvalid
	}
	for i := range models {
		for j := 0; j < i; j++ {
			if models[i].Configuration == models[j].Configuration && models[i].Population == models[j].Population {
				return ErrInvalid
			}
		}
		if !frozenModelMetadataValid(&models[i], p) {
			return ErrInvalid
		}
	}
	for i := range models {
		if validateFrozenModel(&models[i], p) != nil {
			return ErrInvalid
		}
	}
	return nil
}

func safeLoad() string {
	b, e := os.ReadFile("/proc/loadavg")
	if e != nil {
		return "unavailable"
	}
	parts := strings.Fields(string(b))
	if len(parts) < 3 {
		return "unavailable"
	}
	s := strings.Join(parts[:3], " ")
	if len(s) > 128 {
		return "unavailable"
	}
	return strings.Clone(s)
}
