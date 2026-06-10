// Package detect holds the detection core shared by the scanner (static
// manifests) and, later, the runtime proxy. Detectors are pure functions:
// same input manifest, same findings. No I/O, no global state.
package detect

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Rank orders severities for threshold comparison and sorting.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// ToolDef mirrors the MCP tools/list entry shape.
type ToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// Manifest is one MCP server's advertised tool set.
type Manifest struct {
	Server string    `json:"server"`
	Tools  []ToolDef `json:"tools"`
}

type Finding struct {
	Detector string   `json:"detector"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Server   string   `json:"server"`
	Tool     string   `json:"tool"`
	Evidence string   `json:"evidence"`
}

// Detector scans a manifest statically. The runtime proxy will add an
// event-scanning interface later; manifest scanning stays shared.
type Detector interface {
	Name() string
	ScanManifest(m Manifest) []Finding
}
