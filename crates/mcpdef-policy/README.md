# mcpdef-policy

The deny-by-default tool allowlist, the RBAC role model, and the policy-as-code rule engine for the MCPdef gateway.

Part of **[MCPdef](https://github.com/lucheeseng827/mcpdef)** — a fast, self-hostable,
single-binary MCP gateway & governance plane. This crate is one of the engine
crates; most users want the `mcpdef` binary, not this library directly.

## What it does

- Enforces a deny-by-default tool allowlist with glob allow/deny and reusable named profiles (deny wins over allow).
- Models RBAC as a role→grant mapping keyed on the caller's scopes/roles: grants of tools, of resource URIs (`Rbac::decide_resource`) and of prompts (`Rbac::decide_prompt`), each kind granting nothing of another. A client certificate's roles come from its identity (`Rbac::map_certificates`, `Rbac::certificate_roles`), exact or by glob, and an identity no mapping matches holds none.
- Runs the policy-as-code rule engine — per-agent / per-argument allow/deny (`[[policy]]`) layered over the allowlist. The same rules judge a resource read by its URI (`uris`) and a prompt get by its name (`prompts`) and arguments; what a request is about is its `Target`.
- Rewrites a tool call's arguments with `transform` rules (`set`, `default`, `remove`, `clamp`), in a pass before admission whose output the allow/deny rules judge (`PolicyRules::transform`). A rule that cannot apply denies under its own name, or is skipped.
- Edits a result, a tool call's or a read's, with the same rules' `ResultEdit`s (`Redact`, `Mask`, `Remove`, `Truncate`), in a pass once the upstream answers (`PolicyRules::transform_result`): on JSON values, never serialized text, rewriting a `structuredContent`'s text mirror from the edited structure and keeping to the tool's `outputSchema`. `redact_result` is the same redaction for a caller that refuses what is no secret, as inspect's redact mode does. The secrets come from a detector the caller gives (`PolicyRules::with_secrets`), so the crate depends on no scanner.
- Holds each server's resource allowlist (`ResourcePolicy`) and prompt allowlist, and decides a read of a URI (`Policy::decide_resource`), a get of a prompt (`Policy::decide_prompt`) or a completion of a resource template (`Policy::decide_template`) against them: with none, a server exposes no resource and no prompt.
- Matches names and resource URIs with one glob engine (`glob`). In a name, `*` matches any run of characters. In a URI, `*` matches within one path segment and a `**` segment matches any number of them, after `uri::normalize` has put the URI in normal form (RFC 3986) and refused anything two readers could take two ways.

## Usage

This library is consumed by the `mcpdef` binary and its sibling engine crates; it
has no CLI of its own. If you want it standalone:

```sh
cargo add mcpdef-policy
```

## License

Apache-2.0. See the [workspace root](https://github.com/lucheeseng827/mcpdef) for the full project, docs, and the `ee/` governance-plane boundary.
