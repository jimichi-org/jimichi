package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/jimichi-org/jimichi/crypto/suite"
	"github.com/jimichi-org/jimichi/lab/nodeview"
)

type nodeviewFlags struct {
	set, phase, plan, suite, revision, out string
	peer                                   bool
	seed                                   int64
	explicit                               map[string]bool
	positional                             int
}

func isNodeviewSet(name string) bool {
	return name == string(nodeview.Compromise) || name == string(nodeview.Collude) || name == string(nodeview.Mailbox)
}

func nodeviewRequested(args []string) bool {
	for i, arg := range args {
		if (arg == "-set" || arg == "--set") && i+1 < len(args) && isNodeviewSet(args[i+1]) {
			return true
		}
		for _, prefix := range []string{"-set=", "--set="} {
			if strings.HasPrefix(arg, prefix) && isNodeviewSet(strings.TrimPrefix(arg, prefix)) {
				return true
			}
		}
	}
	return false
}

func nodeviewConfig(f nodeviewFlags) (nodeview.Config, error) {
	allowed := map[string]bool{"set": true, "suite": true, "seed": true, "rev": true, "out": true, "node-phase": true, "node-plan": true, "peer": true}
	for name := range f.explicit {
		if !allowed[name] {
			return nodeview.Config{}, nodeview.ErrInvalid
		}
	}
	s, err := suite.Parse(f.suite)
	if err != nil || !isNodeviewSet(f.set) || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(f.revision) || f.positional != 0 || f.out == "" {
		return nodeview.Config{}, nodeview.ErrInvalid
	}
	phase := nodeview.Phase(f.phase)
	switch phase {
	case nodeview.Structural:
	case nodeview.Train:
		if f.set != string(nodeview.Mailbox) || f.plan == "" {
			return nodeview.Config{}, nodeview.ErrInvalid
		}
	case nodeview.Pilot, nodeview.Primary:
		if f.plan == "" {
			return nodeview.Config{}, nodeview.ErrInvalid
		}
	default:
		return nodeview.Config{}, nodeview.ErrInvalid
	}
	if (f.peer || f.explicit["peer"]) && (f.set != string(nodeview.Compromise) || phase != nodeview.Structural) {
		return nodeview.Config{}, nodeview.ErrInvalid
	}
	return nodeview.Config{Set: nodeview.Set(f.set), Phase: phase, Suite: s, Seed: f.seed, Revision: f.revision, PlanPath: f.plan, Peer: f.peer}, nil
}

func nodeviewExit(report nodeview.Report, err error) int {
	switch {
	case errors.Is(err, nodeview.ErrInvalid):
		return 2
	case errors.Is(err, nodeview.ErrUnsupported), report.Status == nodeview.ReasonUnsupported:
		return 3
	case report.Status == nodeview.ReasonCancelled:
		return 130
	case err != nil || report.Status != nodeview.ReasonNone:
		return 1
	default:
		return 0
	}
}

func nodeviewCommand(f nodeviewFlags, stdout, stderr io.Writer) int {
	c, err := nodeviewConfig(f)
	if err != nil {
		fmt.Fprintln(stderr, "nodeview: invalid_config")
		return 2
	}
	if err := nodeviewPlanningEstimate(stderr, c); err != nil {
		fmt.Fprintln(stderr, "nodeview: report_failed")
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	report, runErr := nodeview.Run(ctx, c)
	code := nodeviewExit(report, runErr)
	if report.Schema != "" {
		if _, err := nodeview.PublishReport(f.out, report); err != nil {
			fmt.Fprintln(stderr, "nodeview: report_failed")
			return 1
		}
		if err := nodeview.WriteReport(stdout, report); err != nil {
			fmt.Fprintln(stderr, "nodeview: report_failed")
			return 1
		}
	} else if code == 0 {
		code = 1
	}
	switch code {
	case 1:
		fmt.Fprintln(stderr, "nodeview: series_unavailable")
	case 2:
		fmt.Fprintln(stderr, "nodeview: invalid_config")
	case 3:
		fmt.Fprintln(stderr, "nodeview: unsupported")
	case 130:
		fmt.Fprintln(stderr, "nodeview: cancelled")
	}
	return code
}

func nodeviewPlanningEstimate(w io.Writer, c nodeview.Config) error {
	if c.Suite.String() != "c25519" || c.Phase != nodeview.Pilot && c.Phase != nodeview.Primary {
		return nil
	}
	if err := nodeview.CheckPlanningEstimateResources(); err != nil {
		return err
	}
	record := struct {
		Schema   string                 `json:"schema"`
		Set      nodeview.Set           `json:"set"`
		Phase    nodeview.Phase         `json:"phase"`
		Estimate nodeview.PowerEstimate `json:"maximum_paired_planning"`
	}{"jimichi-nodeview-planning-estimate-v1", c.Set, c.Phase, nodeview.PairedPowerEstimate()}
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, bytes.NewReader(append(body, '\n')))
	return err
}
