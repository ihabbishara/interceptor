package detect

import "regexp"

type poisonPattern struct {
	re       *regexp.Regexp
	title    string
	severity Severity
}

var poisonPatterns = []poisonPattern{
	{regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|messages|context)`),
		"Instruction override in tool description", SeverityCritical},
	{regexp.MustCompile(`(?i)do\s+not\s+(tell|inform|mention|reveal|show)\b`),
		"Concealment instruction in tool description", SeverityCritical},
	{regexp.MustCompile(`(?i)<\s*(important|system|secret|instructions?)\s*>`),
		"Hidden instruction block in tool description", SeverityHigh},
	{regexp.MustCompile(`(?i)before\s+(using|invoking|calling)\s+(this|any)\s+tool`),
		"Behavioral precondition targeting the model", SeverityHigh},
	{regexp.MustCompile(`(?i)(read|cat|open|send|upload|forward|email)[^.]{0,60}(\.ssh|id_rsa|\.env\b|credentials|/etc/passwd|conversation)`),
		"Sensitive-data exfiltration cue in tool description", SeverityCritical},
	{regexp.MustCompile(`(?i)\binstead\s*,?\s+(use|call|invoke|route)\b`),
		"Tool redirection instruction", SeverityMedium},
}

type PoisoningDetector struct{}

func (PoisoningDetector) Name() string { return "tool-description-poisoning" }

func (d PoisoningDetector) ScanManifest(m Manifest) []Finding {
	var out []Finding
	for _, t := range m.Tools {
		for _, p := range poisonPatterns {
			if match := p.re.FindString(t.Description); match != "" {
				out = append(out, Finding{
					Detector: d.Name(), Severity: p.severity, Title: p.title,
					Server: m.Server, Tool: t.Name, Evidence: match,
				})
			}
		}
	}
	return out
}
