# MCP Interceptor — Design Spec

**Date:** 2026-06-10
**Status:** Approved (brainstorm complete)
**Scope:** v1 product — open-source MCP security proxy + scanner, with paid cloud tier

---

## 1. Strategic Context

### Vision
Agentic runtime security platform: detect and block attacks across the
agent/tool ecosystem — MCP tool calls, multi-agent delegation chains,
agent identity, and data exfiltration.

### Wedge (v1)
The MCP / tool-call layer. All four target surfaces share one data spine —
the tool-call/action stream. Instrumenting the action layer once makes the
other detections (delegation chains, identity, exfil) features on the same
pipe rather than new products.

Explicitly rejected entry strategies:
- Launching on all four surfaces at once (no wedge, loses to focused
  competitors on every axis).
- Passive network sniffing (TLS makes it impossible without MITM; "listen
  to network segments" in practice means proxy, SDK, or eBPF — we chose
  proxy deliberately).
- ML/anomaly detection at launch (requires baseline traffic data that does
  not exist yet; shipping FP-prone models day one destroys trust).

### Positioning
- **Deployment:** in-line MCP proxy (sees everything, can BLOCK — security
  buyers pay for prevention, not dashboards).
- **First buyer:** AI-native startups/scaleups shipping agents in
  production today. Fast sales, design partners, telemetry. $10–50k
  contracts initially.
- **Business model:** open core. Proxy + scanner + deterministic
  detections + policy engine = OSS. Cloud dashboard, fleet management,
  cross-org threat intel, ML detections = paid.
- **Competitive landscape (known, accepted):** AI gateways
  (Portkey/LiteLLM/Cloudflare), LLM observability (Langfuse/LangSmith/
  Datadog), AI runtime security (Lakera→CheckPoint, Robust→Cisco,
  Aim→Cato, Zenity, Noma). The MCP/action layer is the least-saturated
  surface; session-state detection from proxy position is the technical
  differentiator per-request guardrails structurally cannot match.

---

## 2. Architecture

```
                       ┌─────────────────────────────┐
  Agent (any client)   │         INTERCEPTOR          │      MCP servers / tools
  Claude, LangChain,   │  ┌────────┐    ┌──────────┐ │
  CrewAI, custom ──────┼─▶│ Proxy   │──▶│ Detection│ │────▶  filesystem, GitHub,
       MCP/stdio+HTTP  │  │ core    │    │ pipeline │ │       DBs, APIs, ...
                       │  └────────┘    └────┬─────┘ │
                       │       │             │       │
                       │  ┌────▼─────┐  ┌────▼─────┐ │
                       │  │ Policy   │  │ Telemetry│ │
                       │  │ engine   │  │ exporter │─┼────▶ Cloud (paid):
                       │  └──────────┘  └──────────┘ │      dashboard, fleet,
                       │  + Scanner (CLI, offline)    │      ML detections later
                       └─────────────────────────────┘
```

Five units, each with one purpose, independently testable:

1. **Proxy core** — speaks MCP in both directions (stdio + streamable
   HTTP). Transparent pass-through; agent configs point at the interceptor
   instead of the real server (one-line config change). Language: **Go**
   (single static binary, easy install, good concurrency; chosen over Rust
   for iteration speed against the 8–12 week launch target).
2. **Detection pipeline** — ordered chain of detectors. Each detector is a
   pure function `(event, context) → findings`. New detectors plug in
   without touching the proxy.
3. **Policy engine** — YAML rules: `allow` / `block` / `require-approval`
   per tool, per server, per agent. Combines findings + policy → verdict.
   Block returns a proper MCP error to the agent; everything is logged.
4. **Scanner** — the same detector code run statically over MCP server
   manifests/registries/source. CLI: `interceptor scan`. Zero-friction
   first touch and launch-marketing weapon.
5. **Telemetry exporter** — structured events, OTel-compatible. Local
   JSONL always; opt-in anonymized cloud export. Schema designed from day
   one to double as ML training data (the "plumbing" for future anomaly
   models).

**OSS boundary:** units 1–4 + local telemetry. **Paid cloud:** dashboard,
fleet management, cross-org threat intel, ML detections (later).

Key design decisions:
- Detector-as-pure-function → testable against attack corpus in CI, and
  the same detection codebase runs in both scanner (static) and proxy
  (runtime).
- OTel compatibility → integrates with the observability stack buyers
  already run (Langfuse, Datadog) instead of competing with it.

---

## 3. Data Flow

### Runtime path (hot — every tool call)
1. Agent sends MCP request → proxy parses → normalized
   `Event{session, agent_id, server, tool, args, ts}`.
2. **Pre-flight detectors** (before forwarding): poisoning check on
   new/changed tool definitions, exfil scan on args, policy lookup.
3. Verdict:
   - `allow` → forward to real MCP server.
   - `block` → MCP error back to agent with finding ID.
   - `approve` → hold call, push notification to a human, allow/deny
     click; timeout (default 60s) = deny, agent receives clean MCP error.
4. Server response → **post-flight detectors**: response-injection scan
   (instructions embedded in tool results), rug-pull diff vs cached tool
   definitions.
5. Every event + finding → local JSONL; async batched export to cloud if
   opted in.

**Latency budget:** ~1–5 ms added per call. Detection runs inline;
telemetry export is async. Blocking verdicts must never wait on network.

### Session context (the moat detail)
Detectors receive rolling session state, not just single events: call
sequences, cumulative data volume per server, cross-server flows. This
catches attack chains that per-request guardrails structurally cannot —
e.g., *read SSH key via filesystem server, then POST-shaped call to a web
server* = an exfil chain spanning two servers, invisible per-request.

### Scanner path (cold)
Same detectors minus session-dependent ones, run over server manifests and
source where available. Output: terminal report + JSON + shareable badge.

---

## 4. v1 Detector Set

| Detector | Method | FP risk | Block default? | Notes |
|---|---|---|---|---|
| Tool-description poisoning | Pattern + heuristics on manifests (hidden instructions, unicode tricks) | Low | Yes | Known attack class; demos well |
| Rug-pull / definition drift | Hash + diff vs first-seen tool defs | ~Zero | Yes | Pure determinism; unique to proxy position |
| Secrets in args | Regex (keys, tokens) + entropy | Low–med | Yes | Immediate "saved you" moments |
| PII in args | Pattern library | Med | No (alert) | Tunable; block opt-in |
| Response injection | Heuristics for instruction-shaped content in tool results | Med–high | No (alert) | Hardest; never block-by-default |
| Cross-server exfil chain | Session-state rules | Med | No (alert) | The differentiator demo |

**Trust rule baked into defaults:** deterministic detectors may block;
heuristic detectors are alert-only until the customer opts in.

---

## 5. Error Handling & Failure Modes

The dominating question for an in-path security proxy: what happens when
the interceptor itself breaks?

- **Fail-open vs fail-closed:** customer's explicit choice, per-policy.
  **Default fail-open** (proxy crash → traffic passes + loud alert).
  Rationale: a proxy that breaks a dev's agent demo gets uninstalled
  forever; adoption beats theoretical purity at this stage. Fail-closed
  available in config; tradeoff documented honestly.
- **Detector crash isolation:** each detector wrapped in recover. One bad
  detector logs + skips; never kills the call. Per-detector timeout budget
  (~5 ms) enforced; over budget → skip + telemetry flag. Worst case is a
  missed detection, never a broken customer.
- **Malformed MCP traffic:** real-world agents/servers violate spec
  constantly. Parser falls back to opaque pass-through + "unparseable"
  event rather than rejecting. Log-everything beats break-anything.
- **Approval-flow timeout:** pending approvals default-deny after a
  configurable window (60 s); the agent receives a clean MCP error it can
  relay.
- **Cloud unreachable:** zero runtime dependency on cloud. Telemetry
  buffers to disk and ships later. The OSS binary is fully functional
  offline forever (also the trust story: traffic never *needs* to leave).

---

## 6. Testing & Validation

1. **Attack corpus as crown-jewel test suite.** Repo of real MCP attack
   samples: poisoned tool descriptions, rug-pull sequences,
   response-injection payloads, exfil chains. Every detector PR runs
   against the corpus with required catch-rate and max-FP-rate gates in
   CI. The corpus grows with every published attack and, later, customer
   incidents. This corpus is the company's accumulating asset.
2. **FP corpus equally weighted.** Recorded benign traffic from popular
   real MCP servers (filesystem, GitHub, Slack, …). A detector that flags
   benign traffic fails CI. Low FP = trust, enforced mechanically.
3. **Replay harness.** Real sessions captured to JSONL (telemetry format
   doubles as fixture format) and replayed through the proxy in tests. The
   same harness later replays customer incidents for debugging. One
   schema, three jobs: telemetry, fixtures, incident replay.
4. **Conformance.** Proxy tested against the official MCP SDK
   client/server matrix (stdio + HTTP) plus chaos cases: huge payloads,
   slow servers, mid-stream disconnects.
5. **Latency regression gate.** p99 added-latency benchmark in CI; budget
   breach fails the build.

---

## 7. Launch Sequencing

| Phase | Timeline | Deliverable | Goal |
|---|---|---|---|
| Scanner | Weeks 1–3 | Scanner CLI, OSS | Launch blog: scan public MCP registry, publish aggregate findings (responsible disclosure to vendors first — no zero-day dumping). HN/X. Stars + waitlist; validate attention before proxy is fully built. |
| Proxy GA | Weeks 4–10 | Proxy + v1 detectors + policy + approval flow | Scanner users = warm funnel ("you scanned, now protect runtime"). |
| Cloud beta | Weeks 8–14 | Dashboard private beta | 5–10 design partners from the funnel. First revenue conversations. Telemetry opt-in starts accruing ML training data. |
| ML tier | Months 4–6 | Anomaly detections beta (paid), threat-intel feed | Fleet-wide network effect: every customer's rug-pull alert hardens everyone's defaults. This becomes the real moat. |

### Explicitly out of scope for v1
- Non-MCP tool calling (raw OpenAI function-calling interception)
- Prompt-layer guardrails (jailbreak/injection scoring on prompts)
- Agent identity / IAM
- eBPF / network-agent deployment
- SOC2 (begins ~month 6 when enterprise demand appears)

### Platform seeds intentionally planted in v1
- Approval flow = start of the human-in-the-loop agent-authorization
  story (identity surface) without building IAM.
- Telemetry schema = ML training pipeline (anomaly surface).
- Session-state engine = delegation-chain detection substrate
  (multi-agent surface).

---

## 8. Open Questions (deferred, not blocking)

- Name/brand for the OSS project.
- Exact OSS license (Apache-2.0 vs BSL-style protective license) — decide
  before scanner launch.
- Cloud stack choices (deferred to implementation planning for the cloud
  phase; irrelevant to scanner/proxy).
