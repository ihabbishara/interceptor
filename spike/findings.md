# eBPF Capture Spike — Findings

**Date:** 2026-06-14
**Env:** Docker Desktop (macOS arm64 host), privileged `ubuntu:22.04` container,
kernel `5.10.104-linuxkit aarch64`, clang 14, Go 1.23→1.25 (toolchain auto),
OpenSSL 3.0.2, CPython 3.10, cilium/ebpf v0.21.0.

## Result: CAPTURED

The eBPF uprobe read the **plaintext of a Python HTTPS request before
encryption** and surfaced it as `internal/sensor.RawEvent`s. The marker
planted in the request body appeared in cleartext:

```
RawEvent pid=82103 dir=out len=199 marker=false   # TLS chunk (request line + headers)
RawEvent pid=82103 dir=out len=90  marker=true    # request body chunk — SPIKE_MARKER_REQUEST_BODY present
```

No code change to the target, no MITM, no proxy redirect, no TLS cert. Pure
passive uprobe on the userspace TLS library.

## What was observed
- SSL write uprobe attached: **yes** (via `SSL_write_ex`, see below).
- Marker `SPIKE_MARKER_REQUEST_BODY` surfaced in a RawEvent: **yes** (dir=out).
- PID attribution: **yes** — events tagged with the python process PID (82103).
- Chunks per request: **2** (headers chunk + body chunk) — confirms the
  reassembler (Task 2) is needed: one logical request arrives as multiple
  `SSL_write_ex` calls.

## The decisive finding: SSL_write vs SSL_write_ex
Hooking `SSL_write` alone captured **nothing**. CPython 3.10 with OpenSSL 3.x
calls **`SSL_write_ex`**, not `SSL_write`. Capture only succeeded once the
probe attached to `SSL_write_ex`. **v1 implication:** the sensor must hook the
full TLS write/read family per library/version (`SSL_write`, `SSL_write_ex`,
and the read equivalents), not assume one symbol.

## Fixups required to get here (all toolchain/environment, none "eBPF can't do it")
1. **No kernel BTF** on Docker Desktop's linuxkit kernel (`/sys/kernel/btf/vmlinux`
   absent). Solved by making the BPF program **BTF-less**: dropped `vmlinux.h`,
   used `<linux/bpf.h>` + `<asm/ptrace.h>` (the latter supplies
   `struct user_pt_regs` that `bpf_tracing.h`'s PT_REGS macros need on arm64).
2. **Old libbpf (0.5)** in Ubuntu 22.04 has no `BPF_UPROBE` macro → used
   `BPF_KPROBE` (identical pt_regs arg extraction; valid for uprobes).
3. **eBPF verifier** rejected `bpf_probe_read_user` size as possibly-negative.
   A clamp got elided by clang; the robust fix is a power-of-2 **mask only**
   (`n = num & (MAX_DATA-1)`) so the bound is provable and not optimized away.
4. **cilium/ebpf `OpenExecutable`** requires the lib's +x bit; Ubuntu ships
   `libssl.so.3` as 0644 → `chmod +x` (v1: handle libs without +x).
5. **Toolchain**: Ubuntu's Go 1.18 is too old for cilium/ebpf (needs ≥1.24);
   installed Go from tarball. arm64 libssl lives at
   `/usr/lib/aarch64-linux-gnu/libssl.so.3` (loader path list updated).

## Deferred / not yet proven (out of spike scope)
- **SSL_read (response) capture** — needs a uretprobe (buffer is filled on
  return, not entry). Not attempted; the write path was the spike's bar.
- **fd resolution** (SSL* → socket fd) — loader emits FD=-1. v1 task; needed
  for per-connection stream separation.
- **The MCP-anchor → PID correlation** across both wires — spike proved
  single-wire capture only.
- **A BTF-enabled kernel** would have avoided fixups 1–2 entirely. Production
  sensor should target BTF kernels (most cloud/distro kernels post-2021 ship
  BTF); the BTF-less path is a useful fallback for minimal kernels.

## Verdict
**The Phase-2 sensor foundation holds.** Plaintext LLM-style traffic is
capturable from a userspace TLS library via eBPF uprobe with zero target
instrumentation, deterministic PID attribution, and the chunked delivery the
reassembler already handles. The single biggest v1 unknown now retired is "can
we read the bytes at all" — yes. The biggest *remaining* v1 unknown is
**per-runtime TLS symbol coverage** (the SSL_write_ex lesson): each language/
OpenSSL/BoringSSL/Go-crypto-tls combination needs its own probe set and symbol
discovery. That, plus uretprobe-based response capture and fd resolution, is
the next milestone — and it is engineering, not research risk.
