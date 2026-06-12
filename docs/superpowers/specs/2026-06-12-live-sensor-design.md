# Live Sensor — Design Spec (Phase 2)

**Date:** 2026-06-12
**Status:** Approved (brainstorm complete)
**Scope:** v1 thin vertical slice — eBPF runtime sensor correlating the LLM wire and the MCP wire by process identity, producing cross-wire attack-chain findings and exact token/cost accounting, exported to a cloud dashboard.

Builds on Phase 1 (the MCP manifest scanner, `docs/superpowers/specs/2026-06-10-mcp-interceptor-design.md`). Reuses `internal/detect` (pure-function detectors) and the scanner's MCP JSON-RPC parsing.

---

## 1. Strategic Context

### Vision
A live runtime sensor for agentic systems: observe what an agent actually does at runtime — across the LLM wire and the tool/MCP wire — and surface attacks, anomalies, stuck agents, errors, and cost, then drive customer recommendations from one correlated picture.

### The wedge (v1)
The **cross-wire correlation spine** — one session that threads `LLM call → reasoning → tool action → cost → outcome`, keyed by process identity. This is the only genuinely new IP. Observability tools (Langfuse, Datadog, Helicone) own the LLM wire and ship token/error dashboards. The Phase-1 scanner owns the MCP wire. **Nobody stitches them into a causal chain.** That chain is the moat.

### Decisions locked during brainstorm
- **Both wires, unified — but sequenced, not simultaneous.** Build the correlation spine first, light up wires/signals onto it incrementally. End state unified; build order disciplined. (Avoids the "all the above" trap that recurred twice in Phase 1.)
- **Correlation key = process identity (PID), NOT an injected trace ID.** Rejected: OpenTelemetry (unwanted dependency), customer SDK (unwanted code change), traffic-redirect proxy (trust burden), heuristic stitching (probabilistic/weak). One process makes both calls; the kernel already attributes both flows to that PID. The MCP foothold yields the anchor PID (`SO_PEERCRED` / child-process parentage); the sensor then attributes that PID's LLM sockets. No injection, ever.
- **Payload-deep via eBPF** — uprobe TLS-library symbols (`SSL_write`/`SSL_read`, Go `crypto/tls`) to read plaintext LLM payloads before encryption / after decryption. No MITM, no cert, no proxy redirect. Passive observation: a sensor failure cannot break customer traffic.
- **v1 hero = cross-wire attack chain + token/cost rider.** Attack chain (injection on LLM wire → malicious MCP tool-call) is the unique demo and sells the meeting. Exact token/cost falls out of the same payload pipeline for near-free (LLM response carries a `usage` object) and justifies the PO.
- **First slice = one runtime + Linux/K8s deploy target.** Not all runtimes, not portable-everywhere.

### Risks accepted (explicit)
- **Re-introduces the enterprise-security-review buyer.** A privileged node sensor decrypting LLM traffic is the hardest artifact to clear a security team. Different buyer from Phase 1's AI-native startups; the scanner and sensor may not sell to the same person.
- **Data-sensitivity blast radius.** Decrypted prompts/completions are customers' most sensitive data. Mitigated by the local-only detection model (§4) — only derived findings leave the node.
- **Self dev-loop friction.** eBPF is Linux-kernel; primary dev machine is macOS. Mitigated by isolating kernel code behind a `RawEvent` seam (§5) so ~80% of the build tests natively.
- **Incumbent proximity.** eBPF L7 vendors (Pixie, Cilium→Cisco, Groundcover, Odigos, Coroot) could add LLM-payload parsing onto mature pipes. Edge is the correlation + detection, not the pipe.
- **Sensor is a high-value tap.** See §6.

This is a multi-month infrastructure build, not a weekend project. This spec's first implementation plan covers ONLY the thin vertical slice, not the full sensor.

---

## 2. Architecture

```
   AGENT PROCESS (pid N)                          interceptor sensor (privileged, per-node)
  ┌──────────────────────┐                       ┌────────────────────────────────────────┐
  │  agent / orchestrator │                       │  ┌──────────────┐                       │
  │                       │   TLS write/read      │  │ eBPF probes  │ uprobe SSL_write/read │
  │  LLM SDK ──────────────┼──(api.openai.com)───▶│  │ (kernel)     │ kprobe connect/sendmsg│
  │                       │                       │  └──────┬───────┘                       │
  │  MCP client ───────────┼──(stdio/HTTP)────────▶│        │ raw events {pid, fd, bytes}    │
  └──────────┬────────────┘                       │  ┌──────▼───────┐                       │
             │ peer PID (SO_PEERCRED / child)      │  │ correlator   │ pid → session spine    │
             └────────────────────────────────────┼─▶│ (userspace)  │ stitches both wires    │
                                                   │  └──────┬───────┘                       │
                                                   │  ┌──────▼───────┐  ┌─────────────────┐   │
                                                   │  │ detectors    │  │ usage extractor │   │
                                                   │  │ (reused +    │  │ tokens/cost     │   │
                                                   │  │  cross-wire) │  └────────┬────────┘   │
                                                   │  └──────┬───────┘           │            │
                                                   │         └──────┬────────────┘            │
                                                   │          ┌─────▼──────┐                  │
                                                   │          │ exporter   │──▶ cloud:        │
                                                   │          └────────────┘   dashboard,     │
                                                   └────────────────────────────recommendations┘
```

Seven units, each one purpose, independently testable:

1. **eBPF probes (kernel)** — uprobes on TLS lib symbols capture plaintext LLM payloads before encryption; kprobes on socket syscalls give connection metadata. Emit `RawEvent` tagged with PID + fd. One runtime's TLS symbols for v1. The only kernel-bound unit.
2. **Correlator (userspace)** — the spine. Maps PID → session; uses the MCP peer-PID anchor to bind the agent's LLM sockets and MCP connection into one ordered session timeline. The moat unit — guard hardest.
3. **LLM parser** — reassembles request/response from captured TLS chunks (incl. streaming SSE), parses provider JSON (OpenAI/Anthropic shape).
4. **MCP parser** — Phase-1 scanner's manifest/JSON-RPC parsing, fed live events instead of a spawned server.
5. **Detectors** — Phase-1 pure-function detectors reused, plus **cross-wire detectors** taking a correlated session (injection event + subsequent tool-call) → finding.
6. **Usage extractor** — pulls `usage` token counts, maps to provider pricing → exact cost. The token/cost rider.
7. **Exporter** — batches session timelines + findings to cloud; enforces redaction (§4).

Key design decisions:
- Units 3–6 are ordinary userspace Go, testable on macOS with recorded fixtures. Only unit 1 needs a kernel. Isolating eBPF to one unit keeps most of the build in the native dev loop.
- The correlator is the only novel IP. Copied detectors still can't produce the cross-wire finding without the PID spine.

---

## 3. Data Flow

### Capture path (per agent process)
1. Agent `pid N` starts. Node-wide eBPF already attached — no per-process setup.
2. **MCP anchor fires first.** Agent connects to an MCP server interceptor fronts → sensor reads peer PID (`SO_PEERCRED` on unix socket; for stdio the server is a child, so parentage is direct). Session opened for pid N.
3. **LLM wire attaches by PID.** uprobe on `SSL_write` copies the plaintext HTTP request buffer for pid N before OpenSSL encrypts it; `SSL_read` captures response plaintext after decryption. Tagged `{pid N, fd, direction, bytes}`.
4. **Correlator stitches by PID + time.** All pid-N events (LLM + MCP) land on one ordered session timeline. The spine.
5. **Parsers reconstruct.** TLS chunks → reassembled HTTP → provider JSON (request: messages/tools; response: completion + `usage`). MCP events → tool calls/results.
6. **Detectors run on the correlated session**, not single events. Cross-wire detector sees: LLM response carried an injection-shaped instruction → a subsequent MCP tool-call matched it. Usage extractor reads token counts → cost.
7. **Exporter** ships session timeline + findings (redacted per §4).

### TLS capture realities (named, not hidden)
- **Chunking & reassembly.** `SSL_write` is called with arbitrary buffer slices; one request spans many calls, and streaming responses (SSE, the LLM default) arrive token-by-token across hundreds of `SSL_read` calls. The parser reassembles per-fd byte streams and handles chunked/SSE framing. Gnarliest userspace code — testable on macOS with recorded byte-chunk fixtures.
- **Symbol resolution per runtime.** uprobe needs the TLS-write symbol address. Dynamically-linked runtimes (Python, Node) resolve from the shared libssl — manageable. **Go statically links its own `crypto/tls`** — no libssl symbol; uprobe `crypto/tls.(*Conn).Write`, whose offset shifts per Go version and may be inlined. v1 picks ONE runtime; Go is hardest — start there only if the design partner is Go.

### Degradation
Capture failure = degrade, never block. Unsupported TLS lib or unresolved symbols → the LLM wire falls back to **metadata-only** for that process (connection count, byte volume, errors via kprobes — no payload). Loop/error/volume signals survive; exact tokens + injection-content lost for that process. The sensor never crashes the agent — passive observation, not in-path.

### Session lifecycle
Session closes when pid N exits or after an idle window. Closed timelines flush to exporter. Live sessions stream incrementally to the dashboard.

---

## 4. Trust, Privacy & Redaction

Privacy is architecture here, not policy. The sensor decrypts customer LLM traffic; the design must make that safe or no one grants node access.

**Core principle:** the sensitive payload never leaves the customer's node by default. Detection runs locally in the sensor (userspace, on their machine). Only **derived findings + metadata** ship to cloud — never raw prompts/completions unless explicitly opted in per-stream.

What crosses the network boundary:

| Data | Default | Opt-in |
|---|---|---|
| Token counts, cost, latency, error codes | exported | — |
| Finding records (detector, severity, which tool, session shape) | exported | — |
| Redacted evidence snippet (secrets/PII masked) | exported | — |
| Raw prompt/completion text | stays local | explicit per-stream |

**Redaction happens in-sensor, before export, deterministically.** The Phase-1 secrets/PII detectors gain a second job: not just flag secrets but mask them in any evidence snippet before it leaves the node. Same `internal/detect` regexes — find for the customer, hide from yourself.

**Hard guarantees baked into the design:**
- **Local-only detection** — full payload analysis on-node; cloud receives structured findings, not text.
- **Redaction non-optional on the default path** — no code path exports raw payload without an explicit per-stream opt-in flag. Enforced in the exporter, tested as a hard gate (§5.4).
- **Memory hygiene** — captured plaintext lives in a bounded buffer, zeroed after parsing, never written to disk unless opt-in. No payload in logs (evidence fields use `%q`-style escaping + masking).
- **Customer-held / self-host mode** — a fully on-prem deployment (sensor + local dashboard, nothing exported) is the regulated-vertical answer. Spec'd as a deployment mode; build later.

**Compliance posture:** because raw sensitive data doesn't move, the blast radius is findings metadata, not prompts. SOC2 scope and GDPR data-processor burden shrink. Doesn't eliminate review of a privileged node sensor, but makes "what do you do with our prompts?" answerable with "nothing leaves your node."

---

## 5. Testing Strategy

The eBPF boundary is an event stream; everything above it tests without a kernel. Define one interface — `RawEvent{pid, fd, direction, ts, bytes}` — that eBPF *produces* and userspace *consumes*. Above the line is ordinary Go (TDD, fixtures, macOS/Linux CI). Below is the only kernel-dependent code.

1. **Capture fixtures (no kernel).** Record real `SSL_write`/`SSL_read` byte-chunk sequences from real LLM calls (streaming SSE + non-streaming) once; save as fixtures; replay through the parser in CI. Covers reassembly/SSE-framing deterministically. Crown-jewel suite, analogous to Phase 1's attack corpus.
2. **Correlation tests (no kernel).** Synthetic `RawEvent` streams with interleaved PIDs/sessions, including concurrency (overlapping agents) → assert the spine stitches each PID's LLM+MCP events into the right session and never cross-contaminates. The determinism guarantee lives or dies here.
3. **Cross-wire detection corpus.** Each case = a full correlated session (LLM injection event + the tool-call it caused) with `expect: [cross-wire-detector]`, plus benign correlated sessions that must stay silent. CI gate, same model as Phase 1.
4. **Redaction gate (no kernel).** Property test: payloads containing secrets/PII through the exporter → assert no raw payload and no unmasked secret ever appears in exported output on the default path. A regression here is a breach; hard CI gate.
5. **eBPF integration (real kernel, separate CI lane).** A Linux CI job runs the probes against a fixture agent (tiny program making one OpenAI-shaped TLS call + one MCP call) and asserts events surface for the v1 runtime. Slower, Linux-only, isolated from the fast suite. Also tests symbol-resolution breakage across runtime versions.

**Overhead gate:** a benchmark asserts eBPF capture overhead stays under budget (e.g. <5% CPU on a hot agent); regression fails CI. Passive observation must stay cheap or it gets ripped out.

---

## 6. Security Hardening (deferred past v1)

**Residual risk:** the sensor sees everything in-memory on the node. A compromised sensor = a compromised tap. The sensor binary becomes a high-value target — signing, attestation, and minimal attack surface matter more here than in the scanner.

**Disposition:** flag for the security-hardening workstream. Do NOT solve in v1. Revisit binary signing / attestation / attack-surface minimization before any enterprise or regulated deployment. (Recorded in project memory: `sensor-compromise-residual-risk`.)

---

## 7. Out of Scope for v1

- Additional runtimes beyond the first (multi-runtime TLS symbol support).
- Non-Linux deployment (macOS/Windows sensors).
- Stuck-agent/loop detection, full anomaly suite, multi-signal dashboard — light up onto the spine after v1.
- Prompt-layer guardrails as a standalone product, agent identity/IAM.
- Self-host/on-prem deployment mode (spec'd in §4, built later).
- Sensor binary signing/attestation (§6).
- Auto-remediation / blocking on the LLM wire — v1 is observe + report + recommend; the liability fork toward auto-remediation is a later, explicit decision.

---

## 8. Open Questions (deferred, not blocking)

- Which runtime is the v1 target (decided by first design partner: Python or Node likely; Go only if partner is Go).
- eBPF toolchain: libbpf + CO-RE vs a higher-level framework — decided at implementation planning.
- Cloud/dashboard stack — out of the sensor's critical path; decided when the dashboard phase starts.
- Provider coverage for usage/pricing (OpenAI + Anthropic first; pricing table maintenance owner TBD).
