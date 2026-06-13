//go:build linux && spike

// Loads ssl.bpf.o, attaches the SSL_write uprobe to the libssl CPython uses,
// reads the ring buffer, and prints each capture as an internal/sensor.RawEvent.
// This closes the kernel->RawEvent seam end to end.
//
// Build (on the Linux VM, after `go generate` compiles the C):
//
//	go run github.com/cilium/ebpf/cmd/bpf2go -cc clang ssl ../bpf/ssl.c
//	sudo go run .
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang ssl ../bpf/ssl.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"interceptor/internal/sensor"
)

// mirrors struct event in ssl.c — field order is descending-by-alignment so
// there is no interior padding; binary.Read (packed) matches the C layout.
type rawCapture struct {
	TimeNs    uint64
	PID       uint32
	Len       uint32
	Direction uint8
	Data      [1024]byte
}

// libsslPath returns the libssl the running python loaded. The spike runbook
// explains how to confirm it; this default fits Ubuntu 22.04.
func libsslPath() string {
	for _, p := range []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/lib/x86_64-linux-gnu/libssl.so.3",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintln(os.Stderr, "removing memlock:", err)
		os.Exit(1)
	}

	objs := sslObjects{}
	if err := loadSslObjects(&objs, nil); err != nil {
		fmt.Fprintln(os.Stderr, "loading bpf objects:", err)
		os.Exit(1)
	}
	defer objs.Close()

	path := libsslPath()
	if path == "" {
		fmt.Fprintln(os.Stderr, "could not find libssl.so.3 — see spike/README.md")
		os.Exit(1)
	}
	ex, err := link.OpenExecutable(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open libssl:", err)
		os.Exit(1)
	}
	up, err := ex.Uprobe("SSL_write", objs.ProbeSslWrite, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "attach SSL_write uprobe:", err)
		os.Exit(1)
	}
	defer up.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open ringbuf:", err)
		os.Exit(1)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; rd.Close() }()

	fmt.Println("listening on SSL_write uprobe; run the python target now...")
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		var c rawCapture
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &c); err != nil {
			continue
		}
		if c.Len > uint32(len(c.Data)) {
			continue
		}
		ev := sensor.RawEvent{
			PID:       c.PID,
			FD:        -1, // not resolved in spike
			Direction: sensor.Direction(c.Direction),
			TimeNs:    c.TimeNs,
			Data:      c.Data[:c.Len],
		}
		fmt.Printf("RawEvent pid=%d dir=%s len=%d marker=%v\n",
			ev.PID, ev.Direction, len(ev.Data),
			bytes.Contains(ev.Data, []byte("SPIKE_MARKER_REQUEST_BODY")))
	}
}
