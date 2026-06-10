package detect

import (
	"encoding/json"
	"regexp"
)

var secretPatterns = []struct {
	re    *regexp.Regexp
	title string
}{
	{regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`), "OpenAI-style API key"},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "AWS access key ID"},
	{regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`), "GitHub personal access token"},
	{regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), "Slack token"},
	{regexp.MustCompile(`(?i)\b(api[_-]?key|secret|password)\b\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}`), "Hardcoded credential assignment"},
}

type SecretsDetector struct{}

func (SecretsDetector) Name() string { return "embedded-secrets" }

func (d SecretsDetector) ScanManifest(m Manifest) []Finding {
	var out []Finding
	for _, t := range m.Tools {
		schemaJSON, _ := json.Marshal(t.InputSchema)
		text := t.Description + " " + string(schemaJSON)
		for _, p := range secretPatterns {
			if match := p.re.FindString(text); match != "" {
				out = append(out, Finding{
					Detector: d.Name(), Severity: SeverityCritical,
					Title:  p.title + " embedded in tool definition",
					Server: m.Server, Tool: t.Name, Evidence: match,
				})
			}
		}
	}
	return out
}
