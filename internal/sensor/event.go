// Package sensor holds the userspace side of the live runtime sensor.
// RawEvent is the seam between kernel capture (eBPF, Linux-only) and all
// userspace processing (parsers, correlator, detectors). Everything above
// this type is ordinary Go and testable without a kernel.
package sensor

import "fmt"

// Direction is the data direction relative to the agent process.
type Direction uint8

const (
	// Outbound is data the agent wrote (e.g. an LLM request body) —
	// captured at SSL_write before encryption.
	Outbound Direction = iota
	// Inbound is data the agent read (e.g. an LLM response body) —
	// captured at SSL_read after decryption.
	Inbound
)

func (d Direction) String() string {
	if d == Inbound {
		return "in"
	}
	return "out"
}

// RawEvent is one captured chunk of plaintext from one TLS call. The kernel
// produces these; userspace consumes them. A single logical HTTP message is
// reassembled from many RawEvents sharing a StreamKey, ordered by Seq.
type RawEvent struct {
	PID uint32 // process that made the TLS call
	// FD is the kernel fd; always >= 0. A negative value is invalid and
	// callers must drop the event rather than construct a RawEvent with it.
	FD        int32
	Direction Direction // out = request (SSL_write), in = response (SSL_read)
	Seq       uint64    // monotonic per (pid,fd,direction); orders chunks
	TimeNs    uint64    // kernel timestamp (ktime), for cross-wire ordering
	// Data is the plaintext chunk. It may alias a reused ring-buffer backing
	// array; consumers that retain it past the read callback MUST copy it.
	Data []byte
}

// StreamKey groups chunks belonging to one direction of one fd of one
// process. Request and response on the same fd are deliberately distinct.
func (e RawEvent) StreamKey() string {
	return fmt.Sprintf("%d:%d:%s", e.PID, e.FD, e.Direction)
}
