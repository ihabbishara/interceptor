package detect

import "fmt"

var invisibleRanges = []struct {
	lo, hi   rune
	label    string
	severity Severity
}{
	{0x200B, 0x200F, "zero-width or directional mark", SeverityHigh},
	{0x202A, 0x202E, "bidi control character", SeverityHigh},
	{0x2060, 0x2064, "invisible operator", SeverityHigh},
	{0x2066, 0x2069, "bidi isolate", SeverityHigh},
	{0xFEFF, 0xFEFF, "zero-width no-break space", SeverityHigh},
	{0xE0000, 0xE007F, "unicode tag character (ASCII smuggling)", SeverityCritical},
}

type UnicodeDetector struct{}

func (UnicodeDetector) Name() string { return "unicode-smuggling" }

func (d UnicodeDetector) ScanManifest(m Manifest) []Finding {
	var out []Finding
	for _, t := range m.Tools {
		out = append(out, d.scanField(m.Server, t.Name, "name", t.Name)...)
		out = append(out, d.scanField(m.Server, t.Name, "description", t.Description)...)
	}
	return out
}

func (d UnicodeDetector) scanField(server, tool, field, text string) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, r := range text {
		for _, rg := range invisibleRanges {
			if r >= rg.lo && r <= rg.hi && !seen[rg.label] {
				seen[rg.label] = true
				out = append(out, Finding{
					Detector: d.Name(), Severity: rg.severity,
					Title:    "Invisible unicode in tool " + field + ": " + rg.label,
					Server:   server, Tool: tool,
					Evidence: fmt.Sprintf("U+%04X", r),
				})
			}
		}
	}
	return out
}
