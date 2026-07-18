# mcpdef-auth

An OAuth 2.1 Resource Server — per-request bearer JWT validation against a JWKS, with RFC 9728 Protected Resource Metadata.

Part of **[MCPdef](https://github.com/lucheeseng827/mcpdef)** — a fast, self-hostable,
single-binary MCP gateway & governance plane. This crate is one of the engine
crates; most users want the `mcpdef` binary, not this library directly.

## What it does

- Validates a bearer JWT per request against a JWKS (asymmetric-only, algorithm-confusion-safe).
- Checks RFC 8707 / 9068 audience along with `iss` / `exp`.
- Serves the RFC 9728 Protected Resource Metadata document and emits a `WWW-Authenticate` challenge on 401.

## Usage

This library is consumed by the `mcpdef` binary (which wires it into the HTTP
listener) and its sibling engine crates; it has no CLI of its own. If you want it
standalone:

```sh
cargo add mcpdef-auth
```

## License

Apache-2.0. See the [workspace root](https://github.com/lucheeseng827/mcpdef) for the full project, docs, and the `ee/` governance-plane boundary.
