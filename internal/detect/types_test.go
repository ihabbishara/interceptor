package detect

import "testing"

func TestSeverityRankOrdering(t *testing.T) {
	if !(SeverityCritical.Rank() > SeverityHigh.Rank() &&
		SeverityHigh.Rank() > SeverityMedium.Rank() &&
		SeverityMedium.Rank() > SeverityLow.Rank()) {
		t.Fatalf("severity ranks not strictly ordered")
	}
}

func TestRegistryReturnsDetectors(t *testing.T) {
	// Grows as detector tasks land; at minimum it must not be nil.
	if All() == nil {
		t.Fatal("All() returned nil")
	}
}
