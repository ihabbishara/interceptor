package mcp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseManifestObjectForm(t *testing.T) {
	m, err := ParseManifest([]byte(`{"server":"fs","tools":[{"name":"read_file","description":"Reads a file."}]}`), "x.json")
	if err != nil {
		t.Fatal(err)
	}
	if m.Server != "fs" || len(m.Tools) != 1 || m.Tools[0].Name != "read_file" {
		t.Fatalf("unexpected manifest: %+v", m)
	}
}

func TestParseManifestArrayFormUsesFilenameAsServer(t *testing.T) {
	m, err := ParseManifest([]byte(`[{"name":"t","description":"d"}]`), "myserver.json")
	if err != nil {
		t.Fatal(err)
	}
	if m.Server != "myserver.json" || len(m.Tools) != 1 {
		t.Fatalf("unexpected manifest: %+v", m)
	}
}

func TestParseManifestRejectsEmpty(t *testing.T) {
	if _, err := ParseManifest([]byte("  "), "x.json"); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestLoadPathDirectory(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"tools":[{"name":"a"}]}`), 0o644)
	os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"tools":[{"name":"b"}]}`), 0o644)
	ms, err := LoadPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 {
		t.Fatalf("expected 2 manifests, got %d", len(ms))
	}
}

func TestLoadPathEmptyDirErrors(t *testing.T) {
	if _, err := LoadPath(t.TempDir()); err == nil {
		t.Fatal("expected error for directory with no manifests")
	}
}
