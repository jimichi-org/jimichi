package nodeview

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

type shapeTestSettings struct {
	ControlProfile uint8 `json:"control_profile"`
}

type shapeTestDocument struct {
	Schema   string            `json:"schema"`
	Settings shapeTestSettings `json:"settings"`
	Segments [2]int64          `json:"segments"`
	Optional string            `json:"optional,omitempty"`
}

func TestStrictJSONRejectsTypedAliasesAndDiscardedArrayValues(t *testing.T) {
	for _, raw := range []string{
		`{"schema":"v1","Schema":"v1","settings":{"control_profile":0},"segments":[1,0]}`,
		`{"Schema":"v1","settings":{"control_profile":0},"segments":[1,0]}`,
		`{"schema":"v1","settings":{},"segments":[1,0]}`,
		`{"schema":"v1","settings":{"control_profile":null},"segments":[1,0]}`,
		`{"schema":"v1","settings":{"control_profile":0},"segments":[1,0,999]}`,
		`{"schema":"v1","settings":{"control_profile":0},"segments":[1]}`,
		`{"schema":"v1","settings":{"control_profile":0},"segments":null}`,
	} {
		var document shapeTestDocument
		if err := strictJSON(strings.NewReader(raw), &document); err == nil {
			t.Errorf("noncanonical typed shape accepted: %s", raw)
		}
	}
}

func TestStrictJSONRequiresExplicitZeroProfileInPlan(t *testing.T) {
	p := testNodeviewPlan(Mailbox)
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	var coordinates []map[string]json.RawMessage
	var settings map[string]json.RawMessage
	if json.Unmarshal(body, &document) != nil || json.Unmarshal(document["configurations"], &coordinates) != nil || json.Unmarshal(coordinates[0]["settings"], &settings) != nil {
		t.Fatal("could not read the canonical test plan")
	}
	delete(settings, "control_profile")
	coordinates[0]["settings"], err = json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	document["configurations"], err = json.Marshal(coordinates)
	if err != nil {
		t.Fatal(err)
	}
	body, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Plan
	if err := strictJSON(strings.NewReader(string(body)), &decoded); err == nil {
		t.Fatal("omitted zero control profile was accepted")
	}
}

func TestStrictJSONPreservesCanonicalPublicSchemas(t *testing.T) {
	for _, set := range []Set{Compromise, Collude, Mailbox} {
		input := testNodeviewPlan(set)
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		var output Plan
		if err := strictJSON(strings.NewReader(string(body)), &output); err != nil || !reflect.DeepEqual(output, input) {
			t.Fatal("canonical public plan did not round trip")
		}
	}
	training := trainMailbox(mailboxTrainingFixture(), featureVersion, true, true)
	if !training.Releasable {
		t.Fatal("canonical model fixture is unavailable")
	}
	plan := testNodeviewPlan(Mailbox)
	input := []FrozenModel{{Schema: "jimichi-nodeview-model-v1", Features: featureVersion, Population: "request", Configuration: plan.Configurations[0].ID, Suite: plan.Suite, TrainRevision: plan.Revision, TransformDigest: plan.TransformDigest, Training: training}}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var output []FrozenModel
	if err := strictJSON(strings.NewReader(string(body)), &output); err != nil || !reflect.DeepEqual(output, input) {
		t.Fatal("canonical released model did not round trip")
	}
}
