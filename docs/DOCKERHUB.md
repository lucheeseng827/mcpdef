# mcpdef — MCP gateway & governance plane

A fast, self-hostable, **single-binary MCP gateway** in Rust. It sits *in the data path*
between agents and **MCP (Model Context Protocol)** servers: multiplexes transports
(stdio · Streamable HTTP · legacy HTTP+SSE), enforces a deny-by-default tool allowlist,
guards egress (SSRF/cloud-metadata block + DNS pinning), pins tool definitions to catch
**rug-pulls**, and writes a **tamper-evident, hash-linked audit ledger** of every tool call.

## Where it fits

`mcpdef` is the **governance choke-point** between agents and their tools: it sits
*in the data path*, multiplexes the transports agents speak, and gates every
`tools/call` before it reaches an MCP server. It governs the **MCP/tool wire**
only — a separate LLM gateway owns model traffic; `mcpdef` never sits between an
agent and a model provider.

```
   CALLERS                 MCPDEF                     GOVERNANCE          UPSTREAMS
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
 │ Automation / │  ────▶ │    mcpdef     │ ◀─┘             │           │  Wasmtime)       │
 │ CI · scripts │        │ govern · mux  │                 ▼           └──────────────────┘
 └──────────────┘        └───────┬───────┘        deny → MCP tool-execution error (audited)
                                 │
                                 └──▶ every tools/call appended to a tamper-evident, hash-linked
                                      ledger (SIEM-exportable: OCSF / CEF / syslog)
```

- **Upstream** — the agents and MCP clients that call tools: a coding agent/IDE
  over stdio, an app or service over Streamable HTTP, a CI job or script. `mcpdef`
  is in the data path — every call goes through it, not around it.
- **mcpdef** — multiplexes the transport, then runs each `tools/call` through the
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

# front your MCP servers over Streamable HTTP: mcpdef.toml declares them, and
# the project's deploy/compose/mcpdef.example.toml is one to start from (it
# listens on 0.0.0.0:7878 and keeps the ledger at /var/lib/mcpdef/audit.log).
# /var/lib/mcpdef belongs to the user the image runs as (the distroless
# `nonroot`, uid 65532), and so does a new named volume mounted there:
docker run -d --name mcpdef -p 7878:7878 \
  -v "$PWD/mcpdef.toml:/etc/mcpdef/mcpdef.toml:ro" \
  -v mcpdef-audit:/var/lib/mcpdef \
  mancube/mcpdef:latest run --http --config /etc/mcpdef/mcpdef.toml

# or keep the ledger in a directory on the host, given to that user first:
mkdir -p mcpdef-audit && sudo chown 65532:65532 mcpdef-audit
# ... and mount it in place of the volume: -v "$PWD/mcpdef-audit:/var/lib/mcpdef"
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
