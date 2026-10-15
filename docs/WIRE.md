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

A request for a method MCPdef does not serve is refused with `404` and
`-32601`, as the revision requires, so the body tells it from a server with no
MCP endpoint there. On the legacy wire it is the same error with `200`.

**The lists MCPdef answers itself carry caching hints**, because the revision
requires them
([Caching](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching)):

> Servers MUST include caching hints on results with `resultType: "complete"`
> returned by the following operations: `server/discover`, `tools/list`,
> `prompts/list`, `resources/list`, `resources/templates/list`, `resources/read`.

MCPdef answers all six itself. `server/discover` always carries the hints,
because it has no legacy form. A `tools/list`, `prompts/list`, `resources/list`,
`resources/templates/list` or `resources/read` sent on the modern wire carries
them along with the `resultType` every modern result must have
([Result Responses](https://modelcontextprotocol.io/specification/2026-07-28/basic/index#result-responses)).
A legacy one is answered exactly as before, because `2025-11-25` defines none of
the three:

| Request | `tools/list` result |
|---|---|
| modern | `{ "resultType": "complete", "tools": [ … ], "ttlMs": 0, "cacheScope": "private" }` |
| legacy | `{ "tools": [ … ] }` |

`ttlMs: 0` meets the requirement without promising a lifetime. In the revision's
words, "If `ttlMs` is `0`, the response **SHOULD** be considered immediately
stale." A gateway cannot promise a lifetime. Its tool surface moves when a pin
drifts, a description trips the injection scanner or an upstream goes away, and a
client still holding a list MCPdef no longer offers would be acting on a surface
that is gone.

`cacheScope` is `"private"` because what is offered is governance state, and
filtering it per caller is planned. A `"public"` list could then reach another
caller through a shared cache. `"private"` is never wrong about privacy, and at
`ttlMs: 0` a shared cache has no fresh hits to lose.

**A stdio client is told when the tools change.** Over stdio, `initialize` is
answered with `capabilities.tools.listChanged: true`. Once the client sends
`notifications/initialized`, MCPdef sends it
`notifications/tools/list_changed` each time what `tools/list` shows changes:

- an upstream said its tools changed, and MCPdef listed them again;
- a reload changed an allowlist, a prefix or the servers;
- an upstream that started again lists other tools.

A burst of word from an upstream is one re-list, and so one notification. A
client that has not yet said it is initialized is told nothing: its first
`tools/list` shows the change anyway.

**An HTTP client is told nothing.** The listener answers each request with one
JSON object and offers no stream (`GET` is `405`). So its `initialize` offers
no `listChanged`, and it sees a change on its next `tools/list`.

Nor is a 2026-07-28 client, on either transport. That revision sends
notifications on a `subscriptions/listen` stream, which MCPdef does not serve,
so `server/discover` offers no `listChanged` either. Its `tools/list` carries
`ttlMs: 0`, which already tells it to ask again rather than keep the list.

**Upstream, MCPdef hears `notifications/tools/list_changed`** from:

- a stdio server;
- a 2024-11-05 SSE bridge, on its stream;
- a Streamable HTTP server, in its answer to a request.

It hears it while an upstream opens too, including in the answer to the
opening's `tools/list`, whether the word comes before the tools or after them.
What it then does is in
[OPERATIONS.md § When an upstream's tools change](./OPERATIONS.md#when-an-upstreams-tools-change).

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
cannot disagree. A legacy upstream is sent neither header. Both belong to the
modern wire, where the server checks them against the body; a 2025-11-25 server
does no such check, so there they would be unvalidated claims about the body —
the shape the revision tells a policy-enforcing intermediary to
[reject](#why-a-gateway-cannot-trust-the-mirrored-headers). A call relayed from
a 2026-07-28 client is no exception: MCPdef takes that client's version,
identity and capabilities out of `_meta` first, so the upstream sees what a
2025-11-25 client would have sent rather than a claim to a revision it does not
speak.

What a legacy upstream over Streamable HTTP *is* sent, on every request after
`initialize`, is the `MCP-Protocol-Version` header 2025-11-25 itself requires of
a client
([Protocol Version Header](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#protocol-version-header)).
It names the revision the handshake settled on: the server's answer, which need
not be the `2025-11-25` MCPdef asks for. Without it, a server that cannot tell
otherwise is told to assume `2025-03-26`. `initialize` itself carries none, and
the 2024-11-05 HTTP+SSE bridge, which predates the header, is sent none.

`spec` is a fact about the server, not a preference. Set it wrong and MCPdef says
so at startup, naming the knob, rather than coming up with an empty tool list.

**So one gateway fronts both eras at once**, in either direction: a `2026-07-28`
client can reach a `2025-11-25` server through it, and the reverse. The
allowlist, the argument policy, the pin, the rate limit and the ledger do not
know which wire either side used.

**Tool parameters a server asks to see as headers (`x-mcp-header`).** A server
may annotate a parameter in a tool's `inputSchema` so its value goes in an
`Mcp-Param-{Name}` header too, `{Name}` being the annotation's value
([Custom Headers from Tool Parameters](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#custom-headers-from-tool-parameters)):

```json
"region": { "type": "string", "x-mcp-header": "Region" }
```

A `tools/call` with `"region": "us-west1"` then carries
`Mcp-Param-Region: us-west1`. MCPdef honours this on both of its sides:

- **Upstream, it mirrors.** A modern `tools/call` to a Streamable-HTTP server
  carries a header for each annotated argument, made from the call as it is
  sent, after its `transform` rules, so the header says what the body does. A
  value a header cannot carry as it is goes in the `=?base64?…?=` sentinel; an
  absent or `null` one sends no header. A legacy upstream is sent none.
- **Downstream, it checks.** A modern `tools/call`'s `Mcp-Param-*` headers are
  reconciled with its arguments, by its tool's annotations, before anything
  routes. A header that disagrees, one missing for an argument the body
  carries, one for an argument the body does not carry, and one a header cannot
  carry are each refused with `400` and `-32020`. A number is compared as a
  number, so `42.0` and `42` agree. An object or an array where a tool asks
  for a string, integer or boolean is taken for no value, as no header can
  carry it: the tool's server refuses it by its schema. A header no annotation
  of the tool names is ignored. Only a tool `tools/list` shows is checked: a
  call to one the allowlist hides is refused as the call, so a mismatch never
  tells a caller what a hidden tool's annotations are. A legacy request is not
  checked: 2025-11-25 has no such headers.
- **A tool whose annotations break the revision's rules is not served.** The
  revision has a client exclude such a tool from `tools/list`: an empty name,
  one that is not an HTTP token (a CR or LF in it would be a header injection),
  two alike but for case, a parameter that is not a `string`, `integer` or
  `boolean`, or one reached other than through `properties` alone (under
  `items`, `oneOf`, `$defs` and the like). MCPdef hides it, refuses a call to
  it (audited under `x-mcp-header`) and logs why, one tool at a time: the rest
  of its server's tools are served. The revision lets a stdio client ignore
  annotations; MCPdef applies the rules whatever the upstream's transport,
  because what it takes from any upstream it serves to clients over HTTP.

Each follows a tool's annotations as its server lists them *now*. They are
judged with the tools, at an opening, a restart and a reload, and again each
time the server says its tools changed, and the listener asks for them as each
request arrives rather than keeping a copy.

**`spec = "auto"` probes.** MCPdef asks for `initialize` and reads the answer:

| The upstream replies | Conclusion |
|---|---|
| a result | **legacy** — and the handshake is already done |
| `-32601` method not found | modern — `2026-07-28` removed `initialize` (SEP-2575) |
| `-32022` unsupported version, or `-32020` header mismatch | modern; only a modern server has a rule for either, and a bare `initialize` carries no `_meta` to satisfy one |
| any other error | legacy — an ordinary rejection is not evidence of an era |
| silence | **neither.** Every revision implements `initialize`, so a server that says nothing is not telling you it is old; it is failing to answer. MCPdef says so and names `spec` |

`initialize` is the right question to ask because it is the only message that is
legal-first in *every* era, and its **absence** is what defines the modern one.
Asking for it is therefore the most direct form of the question — and it sends a
2024-11-05 server nothing it would consider out of order, which a `server/discover`
probe could not claim.

It also means the probe costs nothing on the legacy path. The message it sends is
the message the handshake needed anyway, so a legacy upstream opens in the same
number of round trips as a pinned one. MCPdef carries that reply forward rather
than sending a second `initialize`, which an already-initialized 2025-11-25
session would reject.

**This is what lets `auto` work on HTTP**, where it was once refused by name. An
`HttpClient`'s first send also selects the *binding* — Streamable HTTP versus the
deprecated 2024-11-05 HTTP+SSE bridge — and that negotiation is one-shot. A probe
sent ahead of the opening request would consume it. Probing with `initialize`
removes the conflict rather than working around it, because the probe **is** the
opening request:

| Upstream | Answers the probe | Binding | Era |
|---|---|---|---|
| `2026-07-28` Streamable | `404` + a modern JSON-RPC error | Streamable | modern |
| `2025-11-25` Streamable | `200` + a result | Streamable | legacy |
| 2024-11-05 HTTP+SSE | `404`, no MCP body at all | the bridge | legacy |
| down or unauthorized | `503`, `401` | — | neither; the status is reported |

The probe carries its own five-second bound rather than relying on
`upstream_timeout`, which defaults to waiting forever. The two answer different
questions: "how long until I give up determining the wire" is not "how long may a
tool call take".

Which is also why the probe's five seconds are **added to** `upstream_timeout_ms`
when opening an `auto` upstream, not taken out of it. A per-call bound shorter
than the probe would otherwise fire first, so the operator would be told their
upstream missed a deadline they set for something else, with no mention of the
probe that actually ran out. The opening is still bounded, at
`upstream_timeout_ms` + 5s; a pinned upstream is unaffected, because it does not
probe.

`-32601` is the subtle code, because it means opposite things depending on what
was asked, and MCPdef keeps a separate predicate for each:

| Asked | `-32601` means |
|---|---|
| `initialize` | **modern** — the revision removed the method |
| `server/discover` | **legacy** — every modern server must implement it |
| some other method, over HTTP | **modern** — the body proves the endpoint exists at all |

The era is a property of the server, not of a request, so it is resolved once
when the upstream is opened and kept for the life of the connection.

**A 2026-07-28 server may ask the client for something first, and MCPdef
passes that on**
([Multi Round-Trip Requests](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr),
SEP-2322). Such a server answers a `tools/call`, `resources/read` or
`prompts/get` with an `InputRequiredResult` (`resultType: "input_required"`):
its `inputRequests` name an elicitation, a sampling or the roots, and its
`requestState` is for the client to echo. The client asks again, under a new
id, with its `inputResponses` and that state.

- **What the upstream is told.** A request from a 2026-07-28 client goes up
  with the `elicitation`, `sampling` and `roots` capabilities that client
  declares, as it declares them, and no others. A server may ask only under
  what the client declares, and what it asks comes back to that client. Any
  other request carries `clientCapabilities: {}`, as before: one from a
  2025-11-25 client, and each that MCPdef sends of its own.
- **The interim result goes back as it came**, to a 2026-07-28 client that can
  answer it, after the scanner has read it: what a server asks the user, or
  the client's model, is text it wrote, as a tool result is. No caching hints
  are added: they belong on a complete result. The ledger records the request
  as allowed, with `rule = "input-required"`.
- **It is refused**, audited as a deny under `input-required`, when:
  - the client speaks 2025-11-25, and could not read it, even one that holds
    only `requestState`;
  - it asks for something the client did not declare, such as a sampling from
    a client that declared only `elicitation`, or an elicitation in URL mode
    from one that did not declare `elicitation.url`;
  - it breaks the revision's rules for one: a request that is none of the
    three, `inputRequests` that is not an object, a `requestState` that is
    not a string, or neither of the two.

  A `tools/call` gets the tool error `MCPdef denied: tool '<t>' on '<s>' asked
  for input …`. A read or a prompt get gets JSON-RPC error `-32000` with the
  same text.
- **The retry is a request of its own.** It is routed by the name or URI it
  names, as any other, and meets every gate again: the allowlist, the rules,
  RBAC and the rate limit, where it spends a token of its own. Its
  `inputResponses` and `requestState` go upstream as the client sent them, and
  the ledger holds a second record, for the completed call.
- **The state is the upstream's to check.** The revision tells a server to bind
  `requestState` to the principal that asked. Behind MCPdef, every client
  reaches the upstream with MCPdef's own credentials, so the principal it can
  bind to is MCPdef. A server that relies on the binding cannot tell MCPdef's
  clients apart.

**A 2025-11-25 server's own requests are answered at once.** Such a server
asks its client for an elicitation, a sampling or its roots with a JSON-RPC
request of its own, and waits for the answer. MCPdef relays none of them, so it
answers each with `-32601`:

> MCPdef does not relay `elicitation/create` to its clients: through it, a server
> asks for input in its result, on the 2026-07-28 wire

It answers a `ping` with `{}`. It answers on stdio, on a 2024-11-05 SSE
bridge's stream, and in the middle of a Streamable HTTP answer, which it reads
as it comes for that reason: the server goes on only once it has the answer.
The log names the upstream and what it asked. MCPdef used to drop these
requests, and the call the server was making waited until
`upstream_timeout_ms`, or for good.

Also not implemented, and worth knowing before you point a strict client at it:

| Not yet | Why it matters |
|---|---|
| Forwarding an unrecognized `Mcp-Param-*` | The revision has an intermediary forward a `Mcp-Param-{Name}` it does not recognize. MCPdef ignores one, but does not forward it: the upstream request is made from the message alone, and a client's own headers never go upstream. One a tool's annotations name is checked, and made again for the upstream from the body, so only a header no annotation of the tool names is lost, and that is one its server did not ask for either |
| SSE responses | The listener answers a request with a single JSON object. Legal (`application/json` is one of the two allowed content types), but it means no `notifications/progress` during a long tool call |
| `subscriptions/listen` | No long-lived change-notification stream: a request for one is refused, `404` and `-32601`. A modern client sees a change to the tools on its next `tools/list` |
| An upstream's own notification stream | MCPdef opens no standalone `GET` stream to a Streamable HTTP upstream, and sends no `subscriptions/listen` to a 2026-07-28 one. `notifications/tools/list_changed` sent only there is not heard, and that server's tools are listed again when it next opens |
| A 2025-11-25 server's requests to its client | Sampling, elicitation and roots from a 2025-11-25 server are refused with `-32601`, not relayed. They reach the client only as a 2026-07-28 server's `InputRequiredResult`, and only to a 2026-07-28 client |
| `resultType` beyond MCPdef's own lists | Every modern result must carry one. A result relayed from a `2025-11-25` upstream has none, and neither do the `tools/call` errors MCPdef writes itself: a denial, a blocked result, a timeout. A modern client must read a missing `resultType` as `complete`, which is right for all of them, but the field is required |

## What 2026-07-28 changed

Sources: the
[release post](https://blog.modelcontextprotocol.io/posts/2026-07-28/),
[Key Changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog),
[Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http),
[Versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
and
[Caching](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching).

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
- **`resultType` on every result**: `"complete"`, or `"input_required"` for an
  MRTR interim result. A client **MUST** read a missing one as `"complete"`, for
  servers that predate it.
- **Caching hints are mandatory.** A complete result of `server/discover`,
  `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list` or
  `resources/read` **MUST** carry `ttlMs`, a freshness hint that is `>= 0`, and
  `cacheScope`: `"public"`, or `"private"` for a result that must not be shared
  across authorization contexts.

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

With `[gateway] tool_namespace = "prefix"` the name a client calls is the
prefixed one, `gh__create_issue`, so that is what its `Mcp-Name` carries and is
checked against. MCPdef sends the upstream the name the upstream knows,
`create_issue`, in the body and in the `Mcp-Name` it derives from it.

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
