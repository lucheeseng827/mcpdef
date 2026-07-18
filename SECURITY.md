# Security Policy

MCPdef is an infrastructure component that sits **in the data path** between agents
and their MCP tool servers — it brokers credentials, enforces allow/deny, and
writes the audit record of every tool call. A vulnerability here can be
high-impact, so we treat security reports with priority and coordinate
disclosure.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Report privately through GitHub's **private vulnerability reporting** ("Report a
vulnerability" under the repository's *Security* tab).

*(A dedicated `security@` email address will be published at public launch; until
then, GitHub private vulnerability reporting is the supported channel.)*

Include, where you can:

- the affected component (`mcpdef-transport`, `mcpdef-policy`, `mcpdef-audit`, the
  `mcpdef` binary, …) and version / commit,
- a description of the issue and its impact (e.g. allowlist bypass, audit-chain
  forgery, SSRF via an upstream URL, credential leakage, denial of service),
- reproduction steps or a proof of concept,
- any suggested remediation.

## What to expect

- **Acknowledgement** within a few business days.
- A **coordinated, embargoed** fix: we will work with you on a timeline, prepare
  a patch, and credit you (opt-in) in the advisory and `CHANGELOG.md`.
- Public disclosure only **after** a fix is available, via a GitHub Security
  Advisory.

## Scope

In scope — the OSS engine and the `ee/` plane in this repository, specifically:

- **Allowlist / policy bypass** — getting a denied `tools/call` (or a non-allowed
  server/tool/resource) through the gateway.
- **Audit integrity** — forging, truncating, or silently editing the hash-linked
  ledger without detection by `mcpdef audit verify` / `verify_against`.
- **Credential exposure** — leaking brokered upstream credentials, or passing a
  client token upstream (token passthrough is forbidden by the MCP spec).
- **SSRF / egress** — reaching private/reserved ranges or cloud metadata via an
  upstream URL or (later) the sandbox egress path.
- **Transport / protocol** — desync, smuggling, or resource exhaustion in the
  stdio / Streamable HTTP / legacy SSE bridge.
- **Sandbox escape** (once the Phase-4 WASM sandbox lands).

Out of scope — issues in third-party MCP servers MCPdef merely fronts, and reports
that require an already-compromised host or operator-level access.

## Supported versions

MCPdef is pre-1.0 and fast-moving; security fixes target the latest `main` and the
most recent tagged release. Pin a release tag and watch `CHANGELOG.md` for
security-relevant entries.
