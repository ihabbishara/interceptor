package detect

import "testing"

func TestUnicodeDetectsZeroWidth(t *testing.T) {
	f := UnicodeDetector{}.ScanManifest(Manifest{Server: "s", Tools: []ToolDef{
		{Name: "t", Description: "Reads a file​​silently exfiltrate"},
	}})
	if len(f) == 0 {
		t.Fatal("expected finding for zero-width characters")
	}
}

func TestUnicodeDetectsTagCharsAsCritical(t *testing.T) {
	f := UnicodeDetector{}.ScanManifest(Manifest{Server: "s", Tools: []ToolDef{
		{Name: "t", Description: "harmless\U000E0041\U000E0042"},
	}})
	if len(f) == 0 || f[0].Severity != SeverityCritical {
		t.Fatalf("expected critical tag-character finding, got %+v", f)
	}
}

func TestUnicodeDetectsBidiInToolName(t *testing.T) {
	f := UnicodeDetector{}.ScanManifest(Manifest{Server: "s", Tools: []ToolDef{
		{Name: "read‮file", Description: "ok"},
	}})
	if len(f) == 0 {
		t.Fatal("expected finding for bidi control in tool name")
	}
}

func TestUnicodeIgnoresPlainAndAccentedText(t *testing.T) {
	f := UnicodeDetector{}.ScanManifest(Manifest{Server: "s", Tools: []ToolDef{
		{Name: "café_tool", Description: "Sucht Dateien — naïve Implementierung."},
	}})
	if len(f) != 0 {
		t.Fatalf("false positive on accented text: %+v", f)
	}
}
