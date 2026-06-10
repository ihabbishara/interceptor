package detect

import "testing"

func TestSecretsDetectsAWSKey(t *testing.T) {
	f := SecretsDetector{}.ScanManifest(Manifest{Server: "s", Tools: []ToolDef{
		{Name: "t", Description: "Uses key AKIAIOSFODNN7EXAMPLE for access."},
	}})
	if len(f) == 0 || f[0].Severity != SeverityCritical {
		t.Fatalf("expected critical AWS key finding, got %+v", f)
	}
}

func TestSecretsDetectsKeyInSchema(t *testing.T) {
	f := SecretsDetector{}.ScanManifest(Manifest{Server: "s", Tools: []ToolDef{
		{Name: "t", Description: "ok", InputSchema: map[string]any{
			"properties": map[string]any{
				"url": map[string]any{"type": "string", "default": "https://x.test?key=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"},
			},
		}},
	}})
	if len(f) == 0 {
		t.Fatal("expected GitHub token finding in schema default")
	}
}

func TestSecretsIgnoresBenign(t *testing.T) {
	f := SecretsDetector{}.ScanManifest(Manifest{Server: "s", Tools: []ToolDef{
		{Name: "t", Description: "Searches repositories by keyword and returns matches."},
	}})
	if len(f) != 0 {
		t.Fatalf("false positive: %+v", f)
	}
}
