# eBPF Capture Spike

Goal: prove an eBPF uprobe can read the plaintext of a Python HTTPS request
body before OpenSSL encrypts it, and surface it as RawEvents.

## Run

1. `cd spike && vagrant up && vagrant ssh`
2. Inside the VM: `cd /vagrant`
3. Generate + build the loader (after Task 5):
   - `go generate -tags spike ./spike/loader`   # bpf2go compiles ssl.c
   - The loader sits behind the `spike` build tag (and `linux`), so the
     default `go build ./...` / `go test ./...` surface excludes it.
4. Terminal A: `sudo go run -tags spike ./spike/loader`   # attaches uprobes, prints RawEvents
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
