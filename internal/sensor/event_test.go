package sensor

import "testing"

func TestDirectionString(t *testing.T) {
	if Outbound.String() != "out" || Inbound.String() != "in" {
		t.Fatalf("unexpected direction strings: %s %s", Outbound, Inbound)
	}
}

func TestRawEventStreamKeyDistinguishesDirection(t *testing.T) {
	out := RawEvent{PID: 10, FD: 3, Direction: Outbound}
	in := RawEvent{PID: 10, FD: 3, Direction: Inbound}
	if out.StreamKey() == in.StreamKey() {
		t.Fatal("request and response on the same fd must be different streams")
	}
}

func TestRawEventStreamKeySamePidFdDirGroups(t *testing.T) {
	a := RawEvent{PID: 10, FD: 3, Direction: Outbound, Seq: 1}
	b := RawEvent{PID: 10, FD: 3, Direction: Outbound, Seq: 2}
	if a.StreamKey() != b.StreamKey() {
		t.Fatal("same pid+fd+direction must share a stream key")
	}
}
