# mcpdef-ratelimit

Token-bucket rate limiting for the gateway's `tools/call`, `resources/read`, `prompts/get` and `completion/complete` hot paths — per server's tool, per server's reads, prompt gets and completions, and global.

Part of **[MCPdef](https://github.com/lucheeseng827/mcpdef)** — a fast, self-hostable,
single-binary MCP gateway & governance plane. This crate is one of the engine
crates; most users want the `mcpdef` binary, not this library directly.

## What it does

- Applies token-bucket rate limits on the `tools/call`, `resources/read`, `prompts/get` and `completion/complete` hot paths.
- Enforces a bucket per tool of each server, so two servers' tools of one name spend apart, and per server a bucket for its resource reads, one for its prompt gets and one for its completions (each at the per-tool rate), and a global bucket that all of them spend from.
- Feeds a `rate-limited` decision into the audit ledger when a call, a read or a get is throttled, defending gateway availability.

## Usage

This library is consumed by the `mcpdef` binary and its sibling engine crates; it
has no CLI of its own. If you want it standalone:

```sh
cargo add mcpdef-ratelimit
```

## License

Apache-2.0. See the [workspace root](https://github.com/lucheeseng827/mcpdef) for the full project, docs, and the `ee/` governance-plane boundary.
