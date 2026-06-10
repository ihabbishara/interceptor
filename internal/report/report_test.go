package report

import (
	"strings"
	"testing"

	"interceptor/internal/detect"
	"interceptor/internal/scan"
)

func TestTerminalCleanReport(t *testing.T) {
	out := Terminal(&scan.Report{ScannedManifests: 2, ScannedTools: 5})
	if !strings.Contains(out, "2 manifest(s)") || !strings.Contains(out, "No findings") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestTerminalWithFindings(t *testing.T) {
	out := Terminal(&scan.Report{ScannedManifests: 1, ScannedTools: 1, Findings: []detect.Finding{
		{Detector: "tool-description-poisoning", Severity: detect.SeverityCritical,
			Title: "Instruction override", Server: "evil", Tool: "t", Evidence: "ignore previous instructions"},
	}})
	for _, want := range []string{"CRITICAL", "Instruction override", "evil", "ignore previous instructions"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestTerminalEscapesControlCharacters(t *testing.T) {
	out := Terminal(&scan.Report{ScannedManifests: 1, ScannedTools: 1, Findings: []detect.Finding{
		{Detector: "d", Severity: detect.SeverityHigh, Title: "T",
			Server: "evil\x1b[2K\x1b[1Aserver", Tool: "t\x1b[31m", Evidence: "e"},
	}})
	if strings.Contains(out, "\x1b") {
		t.Fatalf("raw escape byte leaked into terminal output:\n%q", out)
	}
}

func TestBadgeURL(t *testing.T) {
	if !strings.Contains(BadgeURL(0), "clean-brightgreen") {
		t.Fatalf("clean badge wrong: %s", BadgeURL(0))
	}
	if !strings.Contains(BadgeURL(3), "3%20findings-red") {
		t.Fatalf("findings badge wrong: %s", BadgeURL(3))
	}
}
