// Package corpus enforces the spec's two CI gates: every attack sample is
// caught by its expected detectors, and no benign sample produces any
// finding. This corpus is the company's accumulating asset (spec §6.1).
package corpus

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"interceptor/internal/detect"
	"interceptor/internal/scan"
)

type corpusCase struct {
	Expect   []string        `json:"expect"`
	Manifest detect.Manifest `json:"manifest"`
}

func loadCases(t *testing.T, dir string) map[string]corpusCase {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no corpus files in %s", dir)
	}
	out := map[string]corpusCase{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var c corpusCase
		if err := json.Unmarshal(data, &c); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out[filepath.Base(f)] = c
	}
	return out
}

func TestAttackCorpusCaught(t *testing.T) {
	for name, c := range loadCases(t, "attacks") {
		t.Run(name, func(t *testing.T) {
			if len(c.Expect) == 0 {
				t.Fatal("attack case must declare expected detectors")
			}
			r := scan.Manifests([]detect.Manifest{c.Manifest})
			fired := map[string]bool{}
			for _, f := range r.Findings {
				fired[f.Detector] = true
			}
			for _, want := range c.Expect {
				if !fired[want] {
					t.Errorf("detector %q did not fire (fired: %v)", want, fired)
				}
			}
		})
	}
}

func TestBenignCorpusClean(t *testing.T) {
	for name, c := range loadCases(t, "benign") {
		t.Run(name, func(t *testing.T) {
			r := scan.Manifests([]detect.Manifest{c.Manifest})
			if len(r.Findings) != 0 {
				t.Errorf("false positive(s) on benign manifest: %+v", r.Findings)
			}
		})
	}
}
