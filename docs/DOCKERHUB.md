# mcpdef — MCP gateway & governance plane

A fast, self-hostable, **single-binary MCP gateway** in Rust. It sits *in the data path*
between agents and **MCP (Model Context Protocol)** servers: multiplexes transports
(stdio · Streamable HTTP · legacy HTTP+SSE), enforces a deny-by-default tool allowlist,
guards egress (SSRF/cloud-metadata block + DNS pinning), pins tool definitions to catch
**rug-pulls**, and writes a **tamper-evident, hash-linked audit ledger** of every tool call.

## Where it fits

`mcpd` is the **governance choke-point** between agents and their tools: it sits
*in the data path*, multiplexes the transports agents speak, and gates every
`tools/call` before it reaches an MCP server. It governs the **MCP/tool wire**
only — a separate LLM gateway owns model traffic; `mcpd` never sits between an
agent and a model provider.

```
   CALLERS                 MCPD                       GOVERNANCE          UPSTREAMS
   (agents / clients)      (this image)               (per tools/call)    (MCP servers it fronts)

 ┌──────────────┐
 │ Coding agent │  stdio (child proc) ───────┐
 │ / IDE        │                            │
 └──────────────┘                            │
 ┌──────────────┐                            │      ┌─────────────┐    ┌──────────────────┐
 │ App / service│  Streamable HTTP ──────────┼────▶ │ allowlist   │    │ stdio server     │
 │ (MCP client) │                            │      │ RBAC · pins │───▶│ HTTP + SSE server│
 └──────────────┘                            │      │ egress guard│    │ WASM sandbox     │
 ┌──────────────┐        ┌───────────────┐   │      └─────────────┘    │ (in-proc         │
 │ Automation / │  ────▶ │     mcpd      │ ◀─┘             │           │  Wasmtime)       │
 │ CI · scripts │        │ govern · mux  │                 ▼           └──────────────────┘
 └──────────────┘        └───────┬───────┘        deny → MCP tool-execution error (audited)
                                 │
                                 └──▶ every tools/call appended to a tamper-evident, hash-linked
                                      ledger (SIEM-exportable: OCSF / CEF / syslog)
```

- **Upstream** — the agents and MCP clients that call tools: a coding agent/IDE
  over stdio, an app or service over Streamable HTTP, a CI job or script. `mcpd`
  is in the data path — every call goes through it, not around it.
- **mcpd** — multiplexes the transport, then runs each `tools/call` through the
  deny-by-default allowlist, RBAC, tool-def pins (rug-pull detection), rate
  limits, and the egress/SSRF guard before forwarding.
- **Downstream** — the MCP servers it fronts: local stdio children, remote
  Streamable HTTP / legacy HTTP+SSE servers, or an untrusted server sandboxed
  in-process under Wasmtime. A denied call never reaches them.
- **Audit** — every governed call (allow or deny) is appended to a hash-linked,
  tamper-evident ledger, verifiable offline and exportable to a SIEM.

## Tags

- `vX.Y.Z` — a specific release (multi-arch: `linux/amd64`, `linux/arm64`).
- `latest` — the newest GA release.

Images are **distroless** (`gcr.io/distroless/static-debian12:nonroot`), **cosign-signed**
(keyless), and carry **SLSA build provenance**.

## Run

```bash
# print version
docker run --rm mancube/mcpdef:latest version

# front your MCP servers (mount a config + an audit dir)
# The image runs as the distroless `nonroot` user (uid 65532), so the mounted
# audit dir must be writable by it — pre-create and chown it on the host first
# (or use a named volume):
mkdir -p "$PWD/mcpdef-audit" && sudo chown 65532:65532 "$PWD/mcpdef-audit"
docker run --rm \
  -v "$PWD/mcpdef.toml:/mcpdef.toml:ro" \
  -v "$PWD/mcpdef-audit:/mcpdef-audit" \
  mancube/mcpdef:latest run --config /mcpdef.toml
```

## Verify the image

```bash
cosign verify mancube/mcpdef:latest \
  --certificate-identity-regexp '^https://github\.com/lucheeseng827/mcpdef/\.github/workflows/release\.yml@refs/tags/v.+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Links

- Source, docs, and the audit-chain verifier (`mcpdef audit verify`): the project repo.
- Licensed **Apache-2.0** (OSS engine). Safety and audit are never paywalled.
