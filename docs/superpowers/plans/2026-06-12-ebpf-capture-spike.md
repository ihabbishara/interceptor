# eBPF Capture Spike + RawEvent Seam Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the riskiest Phase-2 assumption — that an eBPF uprobe on Python's OpenSSL can capture the plaintext of a real LLM API call before encryption — and lock the `RawEvent` seam contract that all userspace code will consume, so the kernel risk is retired before the userspace stack is built.

**Architecture:** A Linux-only spike. An eBPF uprobe attaches to `SSL_write`/`SSL_read` in the libssl that CPython loads, copies the plaintext buffer into a perf/ring buffer tagged with PID+fd+direction, and a Go userspace loader reads those events and emits `RawEvent` structs. The `RawEvent` type and a kernel-independent reassembly helper are defined as ordinary Go (macOS-testable). The spike's success criterion is empirical: run a real `openai`-shaped HTTPS call from Python and see its JSON body surface as `RawEvent`s.

**Tech Stack:** Go 1.22 (userspace loader, matches Phase-1 module), `github.com/cilium/ebpf` (CO-RE loader, pure-Go, no libbpf cgo), C for the eBPF program (compiled with clang/LLVM to BPF), Python 3 + `requests` (the captured target), Linux kernel ≥ 5.8 (ring buffer + CAP_BPF). Vagrant or a cloud Linux box for the kernel-bound parts.

**Critical constraint:** the developer's primary machine is macOS. eBPF cannot run there. Tasks are explicitly tagged **[mac-ok]** (ordinary Go, runs/tests anywhere) or **[linux-only]** (needs the Linux box). Do the [mac-ok] tasks first so the seam is locked before touching the kernel.

**Spike disposition:** this is exploratory de-risking, NOT production code. It lives under `spike/` and `internal/sensor/`. If the spike fails (no plaintext captured, or overhead untenable), that is a SUCCESS of the spike — it saved months. Report the finding either way; do not paper over a failure.

---

## File Structure

```
internal/sensor/event.go            — RawEvent type + Direction enum (the seam contract) [mac-ok]
internal/sensor/event_test.go
internal/sensor/reassembly.go       — per-(pid,fd) byte-stream reassembler [mac-ok]
internal/sensor/reassembly_test.go
internal/sensor/httpparse.go        — minimal HTTP/1.1 request+response splitter over a reassembled stream [mac-ok]
internal/sensor/httpparse_test.go
spike/README.md                     — how to run the spike on a Linux box, what success looks like
spike/bpf/ssl.c                     — eBPF C: uprobe SSL_write/SSL_read → ring buffer [linux-only]
spike/loader/main.go                — Go: load bpf, attach to libssl, read ring buffer → print RawEvent [linux-only]
spike/target/llm_call.py            — the Python program whose TLS we capture [linux-only to run]
spike/Vagrantfile                   — reproducible Linux kernel env [linux-only]
spike/findings.md                   — empirical result written at the end (the actual deliverable)
```

The `internal/sensor` package is real (it survives into v1). The `spike/` tree is throwaway scaffolding to get an empirical answer.

---

### Task 1: RawEvent seam contract [mac-ok]

**Files:**
- Create: `internal/sensor/event.go`
- Test: `internal/sensor/event_test.go`

This is the most important artifact in the plan — every userspace unit consumes it. Lock it before any kernel work.

- [ ] **Step 1: Write the failing test**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sensor/ -run TestRawEvent -v` and `go test ./internal/sensor/ -run TestDirection -v`
Expected: FAIL — `undefined: Outbound`, `undefined: RawEvent`

- [ ] **Step 3: Write the type**

`internal/sensor/event.go`:

```go
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
	PID       uint32    // process that made the TLS call
	FD        int32     // file descriptor of the TLS socket
	Direction Direction // out = request (SSL_write), in = response (SSL_read)
	Seq       uint64    // monotonic per (pid,fd,direction); orders chunks
	TimeNs    uint64    // kernel timestamp (ktime), for cross-wire ordering
	Data      []byte    // the plaintext chunk
}

// StreamKey groups chunks belonging to one direction of one fd of one
// process. Request and response on the same fd are deliberately distinct.
func (e RawEvent) StreamKey() string {
	return fmt.Sprintf("%d:%d:%s", e.PID, e.FD, e.Direction)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sensor/ -v`
Expected: PASS (all 3)

- [ ] **Step 5: Commit**

```bash
git add internal/sensor/event.go internal/sensor/event_test.go
git commit -m "feat: define RawEvent kernel/userspace seam contract"
```

---

### Task 2: Per-stream reassembler [mac-ok]

**Files:**
- Create: `internal/sensor/reassembly.go`
- Test: `internal/sensor/reassembly_test.go`

`SSL_write`/`SSL_read` deliver arbitrary slices; a logical message spans many chunks, possibly out of order. The reassembler buffers chunks per `StreamKey` and yields ordered bytes. Pure Go — the gnarly part the spec calls out, tested without a kernel.

- [ ] **Step 1: Write the failing test**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sensor/ -run TestReassembler -v`
Expected: FAIL — `undefined: NewReassembler`

- [ ] **Step 3: Write the reassembler**

`internal/sensor/reassembly.go`:

```go
package sensor

import "sort"

// Reassembler buffers RawEvent chunks per stream and reconstructs the
// ordered byte sequence for each. Chunks may arrive out of order or be
// delivered more than once; reassembly is by Seq and is idempotent.
type Reassembler struct {
	streams map[string]map[uint64][]byte // streamKey -> seq -> data
}

func NewReassembler() *Reassembler {
	return &Reassembler{streams: map[string]map[uint64][]byte{}}
}

// Add records one chunk. Duplicate (streamKey, seq) pairs are ignored.
func (r *Reassembler) Add(e RawEvent) {
	key := e.StreamKey()
	s, ok := r.streams[key]
	if !ok {
		s = map[uint64][]byte{}
		r.streams[key] = s
	}
	if _, dup := s[e.Seq]; dup {
		return
	}
	cp := make([]byte, len(e.Data))
	copy(cp, e.Data)
	s[e.Seq] = cp
}

// Bytes returns the ordered, concatenated payload for one stream.
func (r *Reassembler) Bytes(streamKey string) []byte {
	s := r.streams[streamKey]
	if len(s) == 0 {
		return nil
	}
	seqs := make([]uint64, 0, len(s))
	for seq := range s {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	var out []byte
	for _, seq := range seqs {
		out = append(out, s[seq]...)
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sensor/ -v`
Expected: PASS (all)

- [ ] **Step 5: Commit**

```bash
git add internal/sensor/reassembly.go internal/sensor/reassembly_test.go
git commit -m "feat: add per-stream chunk reassembler"
```

---

### Task 3: Minimal HTTP message split over a reassembled stream [mac-ok]

**Files:**
- Create: `internal/sensor/httpparse.go`
- Test: `internal/sensor/httpparse.go` test → `internal/sensor/httpparse_test.go`

The spike's success check is "did we capture the LLM request JSON body?" That means finding the body after the HTTP headers in the outbound stream. This is a deliberately minimal splitter — NOT a full HTTP parser (YAGNI for a spike). It finds the `\r\n\r\n` header/body boundary and returns the body. Tested with fixture bytes, no kernel.

- [ ] **Step 1: Write the failing test**

```go
package sensor

import "testing"

func TestSplitBodyAfterHeaders(t *testing.T) {
	raw := []byte("POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\n\r\n{\"model\":\"gpt-4\"}")
	headers, body, ok := SplitHTTPBody(raw)
	if !ok {
		t.Fatal("expected to find header/body boundary")
	}
	if string(body) != `{"model":"gpt-4"}` {
		t.Fatalf("body = %q", body)
	}
	if len(headers) == 0 || string(body) == string(headers) {
		t.Fatal("headers not separated from body")
	}
}

func TestSplitBodyNoBoundaryReturnsFalse(t *testing.T) {
	if _, _, ok := SplitHTTPBody([]byte("partial headers only")); ok {
		t.Fatal("expected ok=false when no boundary present")
	}
}

func TestSplitBodyEmptyBody(t *testing.T) {
	_, body, ok := SplitHTTPBody([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if !ok || len(body) != 0 {
		t.Fatalf("expected ok with empty body, got ok=%v body=%q", ok, body)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sensor/ -run TestSplit -v`
Expected: FAIL — `undefined: SplitHTTPBody`

- [ ] **Step 3: Write the splitter**

`internal/sensor/httpparse.go`:

```go
package sensor

import "bytes"

// SplitHTTPBody splits a reassembled HTTP/1.1 message at the first blank
// line (CRLFCRLF), returning headers and body. This is intentionally
// minimal — enough to extract an LLM request/response body for the capture
// spike, not a conforming HTTP parser. Chunked/SSE decoding is a later,
// separate concern (see spec testing §5.1).
func SplitHTTPBody(raw []byte) (headers, body []byte, ok bool) {
	sep := []byte("\r\n\r\n")
	i := bytes.Index(raw, sep)
	if i < 0 {
		return nil, nil, false
	}
	return raw[:i], raw[i+len(sep):], true
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sensor/ -v`
Expected: PASS (all sensor tests)

- [ ] **Step 5: Commit**

```bash
git add internal/sensor/httpparse.go internal/sensor/httpparse_test.go
git commit -m "feat: add minimal HTTP header/body splitter for capture spike"
```

---

### Task 4: Spike scaffolding — Linux env + target program [linux-only to run, files mac-ok]

**Files:**
- Create: `spike/README.md`
- Create: `spike/Vagrantfile`
- Create: `spike/target/llm_call.py`

The files can be written on macOS; running requires the Linux box. This task only creates and documents them; capture happens in Task 6.

- [ ] **Step 1: Write the Linux env definition**

`spike/Vagrantfile`:

```ruby
# Reproducible Linux kernel for the eBPF capture spike.
# `vagrant up` then `vagrant ssh`. Kernel 5.15 ships ring buffer + CAP_BPF.
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"   # Ubuntu 22.04, kernel 5.15
  config.vm.provider "virtualbox" do |vb|
    vb.memory = 2048
    vb.cpus = 2
  end
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) \
                       golang-go python3 python3-pip bpftool
    pip3 install requests
  SHELL
end
```

- [ ] **Step 2: Write the capture target**

`spike/target/llm_call.py`:

```python
"""Target program for the eBPF capture spike. Makes one HTTPS POST shaped
like an OpenAI chat-completions call. We do NOT need a real API key or a
real response — we only need genuine TLS traffic whose plaintext request
body the eBPF uprobe should surface. httpbin echoes the body back, giving
us a real TLS response to capture on SSL_read too.
"""
import json
import requests

PAYLOAD = {
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "SPIKE_MARKER_REQUEST_BODY"}],
}

resp = requests.post("https://httpbin.org/post", json=PAYLOAD, timeout=30)
print("status:", resp.status_code)
print("echoed marker present:", "SPIKE_MARKER_REQUEST_BODY" in resp.text)
print(json.dumps(resp.json().get("json", {}), indent=2))
```

- [ ] **Step 3: Write the runbook**

`spike/README.md`:

```markdown
# eBPF Capture Spike

Goal: prove an eBPF uprobe can read the plaintext of a Python HTTPS request
body before OpenSSL encrypts it, and surface it as RawEvents.

## Run

1. `cd spike && vagrant up && vagrant ssh`
2. Inside the VM: `cd /vagrant`
3. Build the loader: `go build ./spike/loader` (after Task 5)
4. Terminal A: `sudo ./loader`   # attaches uprobes, prints RawEvents
5. Terminal B: `python3 spike/target/llm_call.py`

## Success criterion

The loader prints a RawEvent (direction=out) whose Data contains
`SPIKE_MARKER_REQUEST_BODY`, captured from PID of the python process —
proving plaintext capture before encryption with no code change to the
target and no TLS interception.

## Failure is a valid result

If no plaintext surfaces (static linking, symbol mismatch, kernel/perms),
record exactly what failed in findings.md. A clean negative saves the
months the full sensor would cost on a broken foundation.

## Which libssl?

Find the lib CPython actually loads:
`python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"` and
`cat /proc/$(pgrep -n python3)/maps | grep -i ssl` while the target sleeps,
to confirm the uprobe target path.
```

- [ ] **Step 4: Sanity-check the files compile/parse where possible [mac-ok]**

Run: `ruby -c spike/Vagrantfile` (if ruby present) and `python3 -m py_compile spike/target/llm_call.py`
Expected: `Syntax OK` / no output (compiles). If ruby absent, skip the Vagrantfile check — it's declarative.

- [ ] **Step 5: Commit**

```bash
git add spike/README.md spike/Vagrantfile spike/target/llm_call.py
git commit -m "chore: add eBPF spike Linux env, target, and runbook"
```

---

### Task 5: eBPF program + Go loader [linux-only]

**Files:**
- Create: `spike/bpf/ssl.c`
- Create: `spike/loader/main.go`

Written on any machine; **builds and runs only on the Linux VM**. The loader bridges kernel events to the `internal/sensor.RawEvent` type from Task 1 — closing the seam.

- [ ] **Step 1: Write the eBPF program**

`spike/bpf/ssl.c`:

```c
// uprobe on SSL_write / SSL_read. On entry we see the plaintext buffer and
// length (args to the libssl call). Copy a bounded slice into a ring buffer
// event tagged with pid, a synthetic fd placeholder, direction, and ktime.
// SPIKE SCOPE: fd is not resolved here (it needs the SSL* -> fd map); the
// spike only needs to prove plaintext capture. fd resolution is a v1 task.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_DATA 1024  // bounded copy; spike only needs to see the marker

struct event {
    __u32 pid;
    __u8  direction; // 0 = out (write), 1 = in (read)
    __u32 len;
    __u64 time_ns;
    __u8  data[MAX_DATA];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int emit(void *buf, int num, __u8 dir) {
    if (num <= 0) return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->direction = dir;
    e->time_ns = bpf_ktime_get_ns();
    __u32 n = num;
    if (n > MAX_DATA) n = MAX_DATA;
    e->len = n;
    bpf_probe_read_user(&e->data, n, buf);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uprobe/SSL_write")
int BPF_UPROBE(probe_ssl_write, void *ssl, void *buf, int num) {
    return emit(buf, num, 0);
}

// int SSL_read(SSL *ssl, void *buf, int num);
// NOTE: at uprobe entry of SSL_read, buf is not yet filled. For the spike we
// capture writes (request body) as the primary proof; reads require a uretprobe.
// A uretprobe variant is added only if write-capture succeeds (see findings).
SEC("uprobe/SSL_read")
int BPF_UPROBE(probe_ssl_read, void *ssl, void *buf, int num) {
    return 0; // placeholder; request-body capture is the spike's bar
}

char LICENSE[] SEC("license") = "GPL";
```

- [ ] **Step 2: Write the Go loader**

`spike/loader/main.go`:

```go
// Loads ssl.bpf.o, attaches the SSL_write uprobe to the libssl CPython uses,
// reads the ring buffer, and prints each capture as an internal/sensor.RawEvent.
// This closes the kernel->RawEvent seam end to end.
//
// Build (on the Linux VM, after `go generate` compiles the C):
//   go run github.com/cilium/ebpf/cmd/bpf2go -cc clang ssl ../bpf/ssl.c
//   sudo go run .
package main

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

// mirrors struct event in ssl.c
type rawCapture struct {
	PID       uint32
	Direction uint8
	Len       uint32
	TimeNs    uint64
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
```

- [ ] **Step 3: Note the build dependency**

The loader imports `github.com/cilium/ebpf`. On the Linux VM, add it:
```bash
go get github.com/cilium/ebpf@latest
go generate ./spike/loader/   # runs bpf2go, produces ssl_bpfel.go etc.
```
Do NOT commit the generated `*_bpfel.go`/`*.o` artifacts from macOS — they are Linux-arch objects. Commit only hand-written source; generated files are produced on the VM. Add to `.gitignore`:
```
spike/loader/ssl_bpf*.go
spike/loader/*.o
```

- [ ] **Step 4: Verify the Go source compiles in isolation where possible [mac-ok]**

The loader cannot fully build on macOS (Linux-only ebpf package + generated objects). Confirm only that the non-generated Go is syntactically valid:
Run: `gofmt -l spike/loader/main.go`
Expected: no output (file is well-formatted; a parse error would print the name). Full build is verified in Task 6 on the VM.

- [ ] **Step 5: Commit**

```bash
git add spike/bpf/ssl.c spike/loader/main.go .gitignore
git commit -m "feat: add eBPF SSL_write uprobe and Go ring-buffer loader"
```

---

### Task 6: Run the spike, record the empirical finding [linux-only]

**Files:**
- Create: `spike/findings.md`

This is the actual deliverable — the answer to "does the foundation hold?" No new product code; it runs the spike on the VM and writes down what happened.

- [ ] **Step 1: Bring up the VM and confirm the toolchain**

On the Linux VM (`cd spike && vagrant up && vagrant ssh`, then `cd /vagrant`):
Run: `clang --version && go version && python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"`
Expected: clang ≥ 12, go ≥ 1.22, an OpenSSL 3.x version string. Record the exact versions for findings.md.

- [ ] **Step 2: Build the loader on the VM**

Run:
```bash
go get github.com/cilium/ebpf@latest
go generate ./spike/loader/
go build -o /tmp/loader ./spike/loader
```
Expected: a `/tmp/loader` binary. If the BPF C fails to compile (missing `vmlinux.h`), generate it: `bpftool btf dump file /sys/kernel/btf/vmlinux format c > spike/bpf/vmlinux.h`. Record any fixups in findings.md.

- [ ] **Step 3: Run the capture**

Terminal A: `sudo /tmp/loader`
Terminal B: `python3 spike/target/llm_call.py`
Expected (the success bar): Terminal A prints a line `RawEvent pid=<py pid> dir=out len=<n> marker=true`.

- [ ] **Step 4: Record the finding honestly**

Write `spike/findings.md` with the ACTUAL result. Template (fill with real observations, not assumptions):

```markdown
# eBPF Capture Spike — Findings

**Date:** <run date>
**Env:** Ubuntu <ver>, kernel <uname -r>, clang <ver>, go <ver>, OpenSSL <ver>

## Result: <CAPTURED | NOT CAPTURED | PARTIAL>

## What was observed
- SSL_write uprobe attached: <yes/no, any errors>
- Marker `SPIKE_MARKER_REQUEST_BODY` surfaced in a RawEvent: <yes/no>
- PID attribution correct (matched the python process): <yes/no>
- Chunks per request body: <count> (informs reassembly need)

## Fixups required to get here
- <e.g. generated vmlinux.h, adjusted libssl path, kernel flag> — or "none"

## Implications for v1
- TLS write capture for Python/OpenSSL: <viable / blocked because ...>
- SSL_read (response) capture: <attempted? uretprobe needed? deferred>
- fd resolution (SSL* -> socket fd): <noted as v1 work>
- Overhead anecdote (if measured): <ballpark>

## Verdict
<One paragraph: does the Phase-2 sensor foundation hold for Python, and
what is the single biggest remaining unknown before committing to the v1
userspace build?>
```

- [ ] **Step 5: Commit the finding**

```bash
git add spike/findings.md
git commit -m "docs: record eBPF capture spike empirical findings"
```

---

## Self-Review notes

- **Spec coverage:** This plan covers spec §2 unit 1 (eBPF probes — spike subset), the §5 `RawEvent` seam + reassembly testing approach (Tasks 1–3), and the §3 capture-path/chunking realities (Tasks 2, 5). It deliberately does NOT cover correlator, LLM/MCP parsers beyond the minimal splitter, detectors, usage extractor, exporter, or redaction — those are the post-spike v1 plan, gated on Task 6's verdict. This matches the agreed "spike + seam only" scope.
- **macOS reality:** Tasks 1–3 are full TDD and run on the dev machine. Task 4 files are authored on macOS, run on the VM. Tasks 5–6 are Linux-only; their "tests" are the empirical capture, not Go unit tests, which is correct for a kernel spike.
- **Honest-failure path:** Task 6 explicitly treats NOT CAPTURED as a valid, valuable outcome. The plan must not be "made to pass."

---

## Out of Scope (this plan)

Per spec §7 and the spike framing: SSL_read/response capture (only attempted if write-capture works), fd resolution, the correlator/spine, provider JSON parsing, cross-wire detectors, usage/cost extraction, exporter, redaction, multi-runtime support, overhead-budget enforcement, any cloud/dashboard work, and production hardening of the eBPF program. All gated behind a positive Task-6 verdict.
