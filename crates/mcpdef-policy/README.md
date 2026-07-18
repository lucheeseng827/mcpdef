# mcpdef-policy

The deny-by-default tool allowlist, the RBAC role model, and the policy-as-code rule engine for the MCPdef gateway.

Part of **[MCPdef](https://github.com/lucheeseng827/mcpdef)** — a fast, self-hostable,
single-binary MCP gateway & governance plane. This crate is one of the engine
crates; most users want the `mcpdef` binary, not this library directly.

## What it does

- Enforces a deny-by-default tool allowlist with glob allow/deny and reusable named profiles (deny wins over allow).
- Models RBAC as a role→grant mapping keyed on the caller's scopes/roles.
- Runs the policy-as-code rule engine — per-agent / per-argument allow/deny (`[[policy]]`) layered over the allowlist.

## Usage

This library is consumed by the `mcpdef` binary and its sibling engine crates; it
has no CLI of its own. If you want it standalone:

```sh
cargo add mcpdef-policy
```

## License

Apache-2.0. See the [workspace root](https://github.com/lucheeseng827/mcpdef) for the full project, docs, and the `ee/` governance-plane boundary.
