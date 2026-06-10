// Package mcp handles MCP server I/O: manifest files and the stdio protocol.
package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"interceptor/internal/detect"
)

// ParseManifest accepts either {"server":..,"tools":[..]} or a bare tool
// array. Real-world tools/list dumps come in both shapes.
func ParseManifest(data []byte, name string) (detect.Manifest, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return detect.Manifest{}, fmt.Errorf("%s: empty manifest", name)
	}
	var m detect.Manifest
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &m.Tools); err != nil {
			return m, fmt.Errorf("%s: %w", name, err)
		}
	} else {
		if err := json.Unmarshal(trimmed, &m); err != nil {
			return m, fmt.Errorf("%s: %w", name, err)
		}
	}
	if m.Server == "" {
		m.Server = name
	}
	return m, nil
}

// LoadPath loads one manifest file, or every *.json file in a directory.
func LoadPath(path string) ([]detect.Manifest, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	files := []string{path}
	if info.IsDir() {
		files, err = filepath.Glob(filepath.Join(path, "*.json"))
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("no .json manifests found in %s", path)
		}
	}
	var out []detect.Manifest
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		m, err := ParseManifest(data, filepath.Base(f))
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}
