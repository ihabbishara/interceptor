// Package scan runs every registered detector over a set of manifests.
package scan

import (
	"sort"

	"interceptor/internal/detect"
	"interceptor/internal/mcp"
)

type Report struct {
	ScannedManifests int              `json:"scanned_manifests"`
	ScannedTools     int              `json:"scanned_tools"`
	Findings         []detect.Finding `json:"findings"`
}

func Manifests(ms []detect.Manifest) *Report {
	r := &Report{ScannedManifests: len(ms), Findings: []detect.Finding{}}
	for _, m := range ms {
		r.ScannedTools += len(m.Tools)
		for _, d := range detect.All() {
			r.Findings = append(r.Findings, d.ScanManifest(m)...)
		}
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return r.Findings[i].Severity.Rank() > r.Findings[j].Severity.Rank()
	})
	return r
}

func Path(path string) (*Report, error) {
	ms, err := mcp.LoadPath(path)
	if err != nil {
		return nil, err
	}
	return Manifests(ms), nil
}
