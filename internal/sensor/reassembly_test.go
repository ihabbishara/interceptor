package sensor

import (
	"bytes"
	"testing"
)

func TestReassemblerOrdersBySeq(t *testing.T) {
	r := NewReassembler()
	r.Add(RawEvent{PID: 1, FD: 3, Direction: Outbound, Seq: 2, Data: []byte("world")})
	r.Add(RawEvent{PID: 1, FD: 3, Direction: Outbound, Seq: 1, Data: []byte("hello ")})
	got := r.Bytes(RawEvent{PID: 1, FD: 3, Direction: Outbound}.StreamKey())
	if !bytes.Equal(got, []byte("hello world")) {
		t.Fatalf("got %q", got)
	}
}

func TestReassemblerSeparatesStreams(t *testing.T) {
	r := NewReassembler()
	r.Add(RawEvent{PID: 1, FD: 3, Direction: Outbound, Seq: 1, Data: []byte("req")})
	r.Add(RawEvent{PID: 1, FD: 3, Direction: Inbound, Seq: 1, Data: []byte("resp")})
	out := r.Bytes(RawEvent{PID: 1, FD: 3, Direction: Outbound}.StreamKey())
	in := r.Bytes(RawEvent{PID: 1, FD: 3, Direction: Inbound}.StreamKey())
	if string(out) != "req" || string(in) != "resp" {
		t.Fatalf("streams crossed: out=%q in=%q", out, in)
	}
}

func TestReassemblerHandlesDuplicateSeqIdempotently(t *testing.T) {
	r := NewReassembler()
	e := RawEvent{PID: 1, FD: 3, Direction: Outbound, Seq: 1, Data: []byte("x")}
	r.Add(e)
	r.Add(e) // duplicate delivery (perf buffer can repeat under load)
	if got := r.Bytes(e.StreamKey()); string(got) != "x" {
		t.Fatalf("duplicate seq not deduped: %q", got)
	}
}
