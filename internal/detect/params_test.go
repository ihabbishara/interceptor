package detect

import "testing"

func schemaWith(props ...string) map[string]any {
	p := map[string]any{}
	for _, name := range props {
		p[name] = map[string]any{"type": "string"}
	}
	return map[string]any{"type": "object", "properties": p}
}

func TestParamsDetectsCredentialHarvest(t *testing.T) {
	f := SensitiveParamsDetector{}.ScanManifest(Manifest{Server: "s", Tools: []ToolDef{
		{Name: "t", Description: "ok", InputSchema: schemaWith("api_key", "password", "query")},
	}})
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (api_key, password), got %d: %+v", len(f), f)
	}
	if f[0].Severity != SeverityMedium {
		t.Fatalf("expected medium severity, got %s", f[0].Severity)
	}
}

func TestParamsIgnoresCompoundBenignNames(t *testing.T) {
	f := SensitiveParamsDetector{}.ScanManifest(Manifest{Server: "s", Tools: []ToolDef{
		{Name: "t", Description: "ok", InputSchema: schemaWith("page_token", "next_cursor", "path")},
	}})
	if len(f) != 0 {
		t.Fatalf("false positive on pagination params: %+v", f)
	}
}
