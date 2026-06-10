# interceptor

Security scanner for MCP (Model Context Protocol) servers. Detects
tool-description poisoning, invisible-unicode smuggling, embedded
secrets, and credential-harvesting parameters in MCP tool manifests —
before your agent ever calls them.

## Install

    go install ./cmd/interceptor

## Usage

Scan a saved tool manifest (a `tools/list` result, object or array form):

    interceptor scan path/to/manifest.json

Scan a directory of manifests:

    interceptor scan path/to/manifests/

Scan a live MCP stdio server:

    interceptor scan --stdio "npx -y @modelcontextprotocol/server-filesystem /tmp"

CI mode — exit 1 if findings at or above a severity:

    interceptor scan --json --fail-on medium manifests/

## Detectors

| Detector | What it catches | Severity |
|---|---|---|
| tool-description-poisoning | Hidden instructions to the model: overrides, concealment, exfiltration cues | medium–critical |
| unicode-smuggling | Zero-width, bidi, and tag characters hiding instructions | high–critical |
| embedded-secrets | API keys and tokens baked into tool definitions | critical |
| sensitive-param-harvest | Tools asking the agent to pass passwords/keys as parameters | medium |

## Corpus

`corpus/attacks/` holds real attack patterns; `corpus/benign/` holds
real-world manifests that must never trigger a finding. Both are CI
gates: detectors must catch every attack and stay silent on everything
benign. Contributions of new attack samples are welcome.

## Status

Early. The scanner is phase 1 of a runtime MCP security proxy — same
detectors, in-line, with blocking. See `docs/superpowers/specs/`.
