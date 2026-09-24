# Wire models — what MCPdef speaks

MCP has two eras. MCPdef fronts both, but not yet to the same depth, and this
page says exactly which is which so nobody has to read the source to find out.

| Era | Revisions | Shape |
|---|---|---|
| **Legacy** | `2025-11-25` and earlier | An `initialize` handshake establishes a session; later requests inherit version, identity and capabilities from it |
| **Modern** | `2026-07-28` | No handshake and no session. Every request carries its own version, identity and capabilities in `params._meta`, and on HTTP mirrors its routing facts into headers |

The terms are the specification's own
([Versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#terminology)).

## Status

**Downstream, MCPdef serves whichever eras you ask for.** `[gateway] wire` takes
`legacy` (the default), `dual`, or `modern`:

```toml
[gateway]
wire = "dual"   # serve 2025-11-25 and 2026-07-28 on the one endpoint
```

The default is `legacy`, so upgrading MCPdef never changes what an existing
deployment accepts. For an in-path enforcer, a surprise in what the wire takes is
a surprise in what gets governed.

On `dual` or `modern`, a request's era is read off the message — modern `_meta`
means modern, `initialize` means legacy — and a modern request gets the full
treatment: the mirrored headers are reconciled with the body before anything
routes, an unserved revision is refused with `-32022` naming what *is* served, and
`server/discover` answers with the same list. **The governance path is identical
either way**: the allowlist, the argument policy, the tool-definition pin, the
rate limit and the ledger do not know which wire carried the call.

Two things MCPdef already did turn out to be what `2026-07-28` requires of a
modern-only server, because the listener was built stateless from the start:

- a client `Mcp-Session-Id` is ignored, never minted or echoed;
- `GET` on the MCP endpoint returns `405 Method Not Allowed`.

**Upstream, each server says what it speaks.** `[[server]] spec` takes
`"2025-11-25"` (the default) or `"2026-07-28"`:

```toml
[[server]]
id   = "weather"
spec = "2026-07-28"     # no `initialize`; opened with `server/discover`
```

A legacy upstream gets the `initialize` handshake it expects. A modern one gets
no handshake — the revision removed it — so MCPdef opens with `server/discover`,
checks the revision the config claims is one the server actually lists, and then
puts the protocol version, its own identity and its capabilities on **every**
request it sends. On HTTP the mirrored `Mcp-Method` / `Mcp-Name` headers go with
them, derived from the message being sent so that a request and its headers
cannot disagree.

`spec` is a fact about the server, not a preference. Set it wrong and MCPdef says
so at startup, naming the knob, rather than coming up with an empty tool list.

**So one gateway fronts both eras at once**, in either direction: a `2026-07-28`
client can reach a `2025-11-25` server through it, and the reverse. The
allowlist, the argument policy, the pin, the rate limit and the ledger do not
know which wire either side used.

**`spec = "auto"` probes.** MCPdef asks `server/discover` and reads the answer:

| The upstream replies | Conclusion |
|---|---|
| a result | modern — and its `supportedVersions` picks the revision |
| `-32022` unsupported version, or `-32020` header mismatch | modern; only a modern server has a rule for either |
| `-32601` method not found | **legacy** — every modern server must implement `server/discover`, so not having it dates the server |
| any other error, a closed pipe, or silence | legacy |

The last row matters more than it looks. JSON-RPC requires `-32601` for an
unknown method and plenty of servers never send it, so the probe carries its own
five-second bound rather than relying on `upstream_timeout`, which defaults to
waiting forever. The two answer different questions: "how long until I conclude
this server is legacy" is not "how long may a tool call take".

Which is also why the probe's five seconds are **added to** `upstream_timeout_ms`
when opening an `auto` upstream, not taken out of it. A per-call bound shorter
than the probe would otherwise fire before the fallback in the last row could
run, failing startup on a server that opens fine pinned — and carving the probe
out of that knob would let it decide which era a slow server is judged to speak.
The opening is still bounded, at `upstream_timeout_ms` + 5s; a pinned upstream is
unaffected, because it does not probe.

The `-32601` row is the subtle one, and the two cases pull opposite ways. On
HTTP, `404` + `-32601` *identifies* a modern server — that JSON-RPC body is what
distinguishes a modern endpoint from a legacy server with no such route. In reply
to `server/discover` specifically, the same code proves the opposite. MCPdef
keeps the two as separate predicates for that reason.

The era is a property of the server, not of a request, so it is resolved once
when the upstream is opened and kept for the life of the connection.

**`auto` is stdio-only today**, and a config that asks for it elsewhere is
refused by name at startup. On stdio the probe is free — the pipe carries
whatever it carries. On an HTTP upstream it is not: `HttpClient`'s first send
also selects the *transport* (Streamable HTTP versus the deprecated 2024-11-05
SSE bridge), and that negotiation is one-shot. The probe would consume it, and
could leave the client failed before the real opening request ever went out. Two
negotiations, one first message. Pin `spec` on an HTTP upstream until they are
untangled.

Also not implemented, and worth knowing before you point a strict client at it:

| Not yet | Why it matters |
|---|---|
| `Mcp-Param-{Name}` validation | Needs the upstream tool's `inputSchema` to know which parameters carry an `x-mcp-header` annotation. **The listener drops these headers**: it hands the gateway a parsed message, and the upstream request is rebuilt from that message alone, so an inbound `Mcp-Param-*` reaches neither the check nor the upstream. A tool relying on one will not see it |
| SSE responses | The listener answers a request with a single JSON object. Legal (`application/json` is one of the two allowed content types), but it means no `notifications/progress` during a long tool call |
| `subscriptions/listen` | No long-lived change-notification stream |
| MRTR (`InputRequiredResult`) | Sampling, elicitation and roots do not round-trip through the gateway |
| `ttlMs` / `cacheScope` on list results | Nothing is advertised as cacheable. `server/discover` deliberately omits them: a gateway's tool surface moves when a pin drifts or a description trips the injection scanner, and promising a lifetime we cannot honour is worse than promising none |

## What 2026-07-28 changed

Sources: the
[release post](https://blog.modelcontextprotocol.io/posts/2026-07-28/),
[Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
and
[Versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning).

- **`initialize`/`initialized` removed** (SEP-2575) and **`Mcp-Session-Id`
  removed** (SEP-2567). There is no negotiation handshake at all: every request
  declares its version and the server accepts or rejects it independently.
- **Per-request `_meta`**, in `params`, under a reverse-DNS namespace:
  `io.modelcontextprotocol/protocolVersion`,
  `io.modelcontextprotocol/clientInfo`,
  `io.modelcontextprotocol/clientCapabilities`.
- **Mirrored headers.** `MCP-Protocol-Version` on every POST; `Mcp-Method` on
  every request; `Mcp-Name` on `tools/call`, `resources/read` and `prompts/get`,
  carrying `params.name` or `params.uri`. A server **MAY** additionally mirror
  annotated tool parameters as `Mcp-Param-{Name}` via an `x-mcp-header`
  extension in the tool's `inputSchema`.
- **Values that cannot sit in a header** — non-ASCII, control characters,
  leading or trailing whitespace — are carried as `=?base64?{value}?=`. A server
  **MUST** decode before comparing.
- **Header/body validation is mandatory.** A server that reads the body **MUST**
  reject a request whose headers disagree with it, with `400` and JSON-RPC
  `-32020 HeaderMismatch`.
- **New error codes.** `-32020` header mismatch, `-32022` unsupported protocol
  version (carrying `data.supported`), and `-32601` method-not-found paired with
  HTTP `404`.
- **`server/discover` is mandatory** for servers; clients may use it to learn
  supported versions before sending anything else.
- **The standalone `GET` SSE stream is gone**, along with `Last-Event-ID`
  resumption and `DELETE` session termination. Long-lived notification streams
  come from a `subscriptions/listen` request instead.
- **Servers no longer send JSON-RPC requests.** Sampling, elicitation and roots
  are embedded in results as `InputRequiredResult` and the client retries
  (MRTR, SEP-2322).
- **`ttlMs` / `cacheScope`** on `tools/list`, `prompts/list`, `resources/list`
  and `resources/read` results, so clients can cache.

## Why a gateway cannot trust the mirrored headers

The headers exist so an intermediary can route without parsing the body. MCPdef
parses the body anyway — the allowlist, the pin and the rate limit all key on the
tool name — so for MCPdef the headers are something to **check**, never a source
of truth. The specification says as much to intermediaries directly:

> Intermediaries that enforce policy based on mirrored headers **SHOULD** verify
> that the `MCP-Protocol-Version` header indicates a version that requires
> header–body validation. If the version is older or the header is absent, the
> intermediary **SHOULD** reject the request rather than trusting unvalidated
> header values.

The failure this prevents is concrete: a client sends `Mcp-Name: safe_tool` with
a body calling `dangerous_tool`; a gateway that allow-lists on the header lets it
through and the upstream runs the body. `mcpdef-core::wire` makes that shape hard
to write — the trusted facts come back from `validate_headers`, built from the
body, and there is no other way to get them.

## Era detection

A dual-era server picks its behaviour **per request**. MCPdef's listener keeps
no connection or session state, so nothing carries over between requests and a
client must not rely on connection affinity:

- a request carrying `_meta.io.modelcontextprotocol/protocolVersion` is modern;
- an `initialize` request is legacy;
- anything else is ambiguous. `WireModel::of` returns `None`, and `wire_check`
  then treats it as legacy where the configured mode serves legacy, and rejects
  it in `modern` mode.

A legacy `tools/call` and a modern one differ only by the `_meta`, which is why
the ambiguous case returns `None` rather than a default — the fallback is the
listener's decision, made against its configured mode, not a guess inside the
classifier.
