// Package report renders scan results for humans, CI, and READMEs.
package report

import (
	"fmt"
	"strings"

	"interceptor/internal/scan"
)

func Terminal(r *scan.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Scanned %d manifest(s), %d tool(s)\n", r.ScannedManifests, r.ScannedTools)
	if len(r.Findings) == 0 {
		b.WriteString("No findings. Clean.\n")
		return b.String()
	}
	counts := map[string]int{}
	for _, f := range r.Findings {
		counts[string(f.Severity)]++
	}
	fmt.Fprintf(&b, "%d finding(s):", len(r.Findings))
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if counts[sev] > 0 {
			fmt.Fprintf(&b, " %d %s", counts[sev], sev)
		}
	}
	b.WriteString("\n\n")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "[%s] %s\n  server=%q tool=%q detector=%s\n  evidence: %q\n\n",
			strings.ToUpper(string(f.Severity)), f.Title, f.Server, f.Tool, f.Detector, f.Evidence)
	}
	return b.String()
}

func BadgeURL(findingCount int) string {
	if findingCount == 0 {
		return "https://img.shields.io/badge/MCP%20scan-clean-brightgreen"
	}
	return fmt.Sprintf("https://img.shields.io/badge/MCP%%20scan-%d%%20findings-red", findingCount)
}
