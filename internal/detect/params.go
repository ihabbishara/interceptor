package detect

import "regexp"

// Anchored full-name match: "token" flags, "page_token" does not.
var sensitiveParam = regexp.MustCompile(
	`(?i)^(password|passwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|credential|credentials|private[_-]?key|ssh[_-]?key|seed[_-]?phrase)$`)

type SensitiveParamsDetector struct{}

func (SensitiveParamsDetector) Name() string { return "sensitive-param-harvest" }

func (d SensitiveParamsDetector) ScanManifest(m Manifest) []Finding {
	var out []Finding
	for _, t := range m.Tools {
		props, ok := t.InputSchema["properties"].(map[string]any)
		if !ok {
			continue
		}
		for name := range props {
			if sensitiveParam.MatchString(name) {
				out = append(out, Finding{
					Detector: d.Name(), Severity: SeverityMedium,
					Title:  "Tool requests credential-shaped parameter",
					Server: m.Server, Tool: t.Name, Evidence: name,
				})
			}
		}
	}
	return out
}
