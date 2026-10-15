// SPDX-License-Identifier: Apache-2.0
//! The two MCP wire models MCPdef fronts, and the rules that separate them.
//!
//! MCP revision **2026-07-28** removed the `initialize` handshake (SEP-2575) and
//! the `Mcp-Session-Id` header (SEP-2567). A request no longer inherits its
//! protocol version, client identity and capabilities from a session: it carries
//! them itself, in `params._meta`, and on Streamable HTTP it *also* mirrors its
//! routing facts into HTTP headers so an intermediary can act without parsing the
//! body. Everything from **2025-11-25** back is the older, session-establishing
//! shape. The spec calls these two eras *modern* and *legacy*; so does
//! [`WireModel`].
//!
//! ## Why this lives in `mcpdef-core`
//!
//! MCPdef is one of the intermediaries the mirroring exists for — and the spec
//! has a warning aimed squarely at it:
//!
//! > Intermediaries that enforce policy based on mirrored headers **SHOULD**
//! > verify that the `MCP-Protocol-Version` header indicates a version that
//! > requires header–body validation. If the version is older or the header is
//! > absent, the intermediary **SHOULD** reject the request rather than trusting
//! > unvalidated header values.
//!
//! MCPdef's allowlist, pin and rate limit all key on the tool name. Reading that
//! name from `Mcp-Name` without checking it against `params.name` would be a
//! policy bypass: a client sends `Mcp-Name: safe_tool` with a body calling
//! `dangerous_tool`, the gateway allows on the header and the upstream executes
//! the body. So the trusted facts are not reachable except through
//! [`validate_headers`], which returns a [`Routing`] built **from the body** —
//! the headers are only ever an input to the check, never a source of truth.
//!
//! ## What is here and what is not
//!
//! Here: the era split, the `_meta` keys, the mirrored standard headers, the
//! header/body validation rule, the `=?base64?…?=` sentinel codec, and the error
//! shapes the revision defines. This module is the seam both ends are built on:
//! the listener validates incoming requests against it, and the upstream
//! connector stamps outgoing ones with it.
//!
//! `Mcp-Param-{Name}` is here as rules, not as state: reading a tool's
//! `x-mcp-header` annotations ([`param_headers`]), mirroring a call's arguments
//! by them ([`param_header_values`]) and checking a request's headers against
//! them ([`validate_param_headers`]). *Which* annotations a call is judged by
//! is a fact about the tool it names, as its server lists it now, so that stays
//! with the gateway's tools: an upstream lists them again when they change.
//!
//! Every rule below is from the published 2026-07-28 specification
//! (`/basic/transports/streamable-http` and `/basic/versioning`), not from a
//! summary of it.

use std::borrow::Cow;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json::Value;

use crate::{method, Id, Message, JSONRPC_VERSION};

/// The last session-establishing revision. What MCPdef speaks today.
pub const SPEC_2025_11_25: &str = "2025-11-25";
/// The first stateless revision: no `initialize`, no session id, `_meta` on
/// every request.
pub const SPEC_2026_07_28: &str = "2026-07-28";

/// Every revision this build knows how to speak, newest first.
///
/// Not the same thing as what a given listener *serves*: that is a deployment's
/// choice (`[gateway] wire`), and it is the narrower list that must appear in an
/// [`WireError::UnsupportedProtocolVersion`], because a client retries against
/// it. Passing this constant where the served list belongs is how a gateway ends
/// up advertising a revision it will then refuse.
pub const KNOWN_SPEC_VERSIONS: &[&str] = &[SPEC_2026_07_28, SPEC_2025_11_25];

/// The `_meta` keys the modern revision defines, in its reverse-DNS namespace.
pub mod meta_key {
    pub const PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
    pub const CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
    pub const CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
    /// Result-side: where a modern response carries the server's identity.
    pub const SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";
}

/// Mirrored HTTP header names, lower-cased.
///
/// Field names are case-insensitive per RFC 9110 and every comparison here is
/// too; these constants are lower-case so they can be compared directly against
/// a normalized header map.
pub mod header {
    pub const PROTOCOL_VERSION: &str = "mcp-protocol-version";
    pub const METHOD: &str = "mcp-method";
    pub const NAME: &str = "mcp-name";
    /// Prefix of a tool parameter mirrored by an `x-mcp-header` annotation.
    pub const PARAM_PREFIX: &str = "mcp-param-";
}

/// JSON-RPC error codes this revision allocates.
pub mod error_code {
    /// Standard JSON-RPC. Paired with HTTP 404 on the modern transport, whose
    /// JSON-RPC body is what tells a client this endpoint is a modern MCP server
    /// with no such method, rather than a legacy server with no MCP endpoint.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// Standard JSON-RPC: the method exists, and its parameters are wrong.
    pub const INVALID_PARAMS: i64 = -32602;
    /// Headers do not match the body, or a required one is missing/malformed.
    pub const HEADER_MISMATCH: i64 = -32020;
    /// The requested protocol version is not served; `data.supported` lists what is.
    pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;
}

/// The sentinel wrapping a Base64-encoded header value: `=?base64?…?=`.
const SENTINEL_OPEN: &str = "=?base64?";
const SENTINEL_CLOSE: &str = "?=";

/// Which era a message belongs to.
///
/// The spec's own terms. A dual-era server picks its behaviour from how the
/// client opens — modern `_meta` means stateless, `initialize` means legacy —
/// and [`WireModel::of`] is that decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireModel {
    /// 2025-11-25 and earlier: an `initialize` handshake establishes a session
    /// that later requests inherit from.
    Legacy,
    /// 2026-07-28 and later: every request carries its own version, identity and
    /// capabilities, and nothing is remembered between them.
    Modern,
}

/// Which eras a listener serves, from `[gateway] wire`.
///
/// The default is [`WireMode::Legacy`], so upgrading MCPdef changes nothing
/// about what an existing deployment answers: the stateless model is reachable
/// only by asking for it. That is deliberate for an in-path enforcer, where a
/// surprise in what the wire accepts is a surprise in what gets governed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WireMode {
    /// 2025-11-25 only. An `initialize` opens a session; a modern request is
    /// refused with what is served.
    #[default]
    Legacy,
    /// Both eras on the one endpoint, chosen per request by how the client
    /// opens — the revision's own rule for a dual-era server.
    Dual,
    /// 2026-07-28 only. `initialize` is refused, naming what is served, because
    /// a legacy client has no other way to learn it.
    Modern,
}

/// Which revision a *particular upstream* speaks — the resolved answer.
///
/// Spelled as the revision itself rather than as an era, because that is what an
/// operator reads off the server they are pointing at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UpstreamSpec {
    #[default]
    V20251125,
    V20260728,
}

/// What a server's `spec` knob was set to — which may be "work it out".
///
/// A separate type from [`UpstreamSpec`] on purpose: `auto` is a question, not an
/// answer, and the difference matters everywhere downstream. Nothing can ask an
/// `Auto` which era it is, because until the probe runs nobody knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
pub enum SpecSetting {
    /// Probe the upstream and use what it turns out to speak.
    #[serde(rename = "auto")]
    Auto,
    /// Pinned. Defaults here: an upstream's era is a fact about that server, and
    /// assuming the newer one would break every existing config on upgrade.
    #[serde(rename = "2025-11-25")]
    #[default]
    V20251125,
    #[serde(rename = "2026-07-28")]
    V20260728,
}

impl SpecSetting {
    /// The revision this setting pins, or `None` for `auto`.
    pub fn pinned(self) -> Option<UpstreamSpec> {
        match self {
            SpecSetting::Auto => None,
            SpecSetting::V20251125 => Some(UpstreamSpec::V20251125),
            SpecSetting::V20260728 => Some(UpstreamSpec::V20260728),
        }
    }
}

impl UpstreamSpec {
    /// Which era this revision belongs to — what decides whether a request needs
    /// its own `_meta` or inherits one from a handshake.
    pub fn era(self) -> WireModel {
        match self {
            UpstreamSpec::V20251125 => WireModel::Legacy,
            UpstreamSpec::V20260728 => WireModel::Modern,
        }
    }

    /// The revision string to declare to a peer speaking it.
    pub fn version(self) -> &'static str {
        match self {
            UpstreamSpec::V20251125 => SPEC_2025_11_25,
            UpstreamSpec::V20260728 => SPEC_2026_07_28,
        }
    }
}

impl WireMode {
    /// The revisions this mode answers for, newest first.
    ///
    /// This is the list that reaches a client in an
    /// [`WireError::UnsupportedProtocolVersion`], so it must be what the
    /// listener will actually serve — never [`KNOWN_SPEC_VERSIONS`], which is
    /// only what the build can speak.
    pub fn served(self) -> &'static [&'static str] {
        match self {
            WireMode::Legacy => &[SPEC_2025_11_25],
            WireMode::Dual => KNOWN_SPEC_VERSIONS,
            WireMode::Modern => &[SPEC_2026_07_28],
        }
    }

    /// Does this mode answer an `initialize` handshake?
    pub fn serves_legacy(self) -> bool {
        matches!(self, WireMode::Legacy | WireMode::Dual)
    }

    /// Does this mode answer a request carrying its own `_meta`?
    pub fn serves_modern(self) -> bool {
        matches!(self, WireMode::Dual | WireMode::Modern)
    }
}

impl WireModel {
    /// Classify one request.
    ///
    /// `Modern` when it carries `_meta.io.modelcontextprotocol/protocolVersion`,
    /// which is exactly what the revision requires of every request and what a
    /// legacy client has no reason to send. `Legacy` for an `initialize`, which
    /// the modern revision does not define at all. `None` for anything else —
    /// an era-ambiguous request, which the caller resolves from how the
    /// connection opened rather than by guessing per message.
    pub fn of(msg: &Message) -> Option<Self> {
        if protocol_version(msg).is_some() {
            return Some(WireModel::Modern);
        }
        if msg.method() == Some(method::INITIALIZE) {
            return Some(WireModel::Legacy);
        }
        None
    }

    /// The revision string this era's newest revision is named by.
    pub fn spec_version(self) -> &'static str {
        match self {
            WireModel::Legacy => SPEC_2025_11_25,
            WireModel::Modern => SPEC_2026_07_28,
        }
    }
}

/// `params._meta`, if the message has one.
fn meta(msg: &Message) -> Option<&Value> {
    msg.params.as_ref()?.get("_meta")
}

/// The protocol version a modern request declares, from its `_meta`.
pub fn protocol_version(msg: &Message) -> Option<&str> {
    meta(msg)?.get(meta_key::PROTOCOL_VERSION)?.as_str()
}

/// The client identity a modern request declares. Self-asserted, exactly as
/// `initialize`'s `clientInfo` was — it names an audit subject, it does not
/// authenticate one.
pub fn client_info(msg: &Message) -> Option<&Value> {
    meta(msg)?.get(meta_key::CLIENT_INFO)
}

/// The capabilities a modern request declares.
pub fn client_capabilities(msg: &Message) -> Option<&Value> {
    meta(msg)?.get(meta_key::CLIENT_CAPABILITIES)
}

/// Which `params` field `Mcp-Name` mirrors for a given method, if any.
///
/// The revision's table: `params.name` for `tools/call` and `prompts/get`,
/// `params.uri` for `resources/read`. Every other method has no `Mcp-Name`.
pub fn name_field(method_name: &str) -> Option<&'static str> {
    match method_name {
        method::TOOLS_CALL | method::PROMPTS_GET => Some("name"),
        method::RESOURCES_READ => Some("uri"),
        _ => None,
    }
}

/// The `Mcp-Name` source value from the body, unencoded.
pub fn name_value(msg: &Message) -> Option<&str> {
    let field = name_field(msg.method()?)?;
    msg.params.as_ref()?.get(field)?.as_str()
}

/// The standard headers a conforming client must send for this request.
///
/// Emitted when MCPdef is itself the client — it calls an upstream, and a
/// modern upstream rejects a request whose headers are missing. Values are
/// sentinel-encoded where they have to be.
///
/// Empty for a legacy message — one that declares no protocol version in its
/// `_meta`. The mirrored headers belong to the 2026-07-28 wire, where the server
/// checks them against the body; a 2025-11-25 server does no such check, so on
/// that wire they would be unvalidated claims about the body — the shape the
/// revision tells a policy-enforcing intermediary to reject — sent to a server
/// that never asked for them.
pub fn mirrored_headers(msg: &Message) -> Vec<(&'static str, String)> {
    let Some(version) = protocol_version(msg) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(3);
    out.push((header::PROTOCOL_VERSION, version.to_string()));
    if let Some(m) = msg.method() {
        out.push((header::METHOD, m.to_string()));
        if name_field(m).is_some() {
            if let Some(n) = name_value(msg) {
                out.push((header::NAME, encode_header_value(n).into_owned()));
            }
        }
    }
    out
}

/// Put onto a request the per-request metadata a modern server requires.
///
/// A modern server has no handshake to have learned any of this from, so every
/// request carries it: the revision being spoken, who is speaking, and what the
/// speaker can do. `client` is the `clientInfo` object — name and version.
///
/// Capabilities go out as `{}`: MCPdef is a proxy, and the capabilities that
/// matter to an upstream are the downstream client's, which the gateway does not
/// speak for. Declaring someone else's would be a claim it cannot keep. The one
/// exception is [`stamp_request_offering`]'s, for a request relayed from a
/// client that can answer what the upstream asks back.
///
/// Idempotent. Re-stamping replaces the fields rather than nesting them.
///
/// Only *requests* are stamped. The revision requires this metadata on every
/// request and says nothing about notifications — it defines no client-to-server
/// notification over Streamable HTTP at all, and the one that exists on stdio,
/// `notifications/cancelled`, carries no version. Stamping one would be
/// inventing a rule, and handing a peer a `_meta` it has no reason to expect.
pub fn stamp_request(msg: &mut Message, version: &str, client: &Value) {
    stamp_request_offering(msg, version, client, &Value::Object(Default::default()));
}

/// [`stamp_request`], declaring `capabilities` as the client's.
///
/// For a request MCPdef relays from a modern client: [`input_capabilities`]
/// of that request. MCPdef can keep those claims, because what the upstream
/// asks for under them comes back in an `InputRequiredResult` that goes to
/// the client, who answers it on its retry.
pub fn stamp_request_offering(
    msg: &mut Message,
    version: &str,
    client: &Value,
    capabilities: &Value,
) {
    if !msg.is_request() {
        return;
    }
    let params = msg
        .params
        .get_or_insert_with(|| Value::Object(Default::default()));
    let Some(obj) = params.as_object_mut() else {
        return;
    };
    let meta = obj
        .entry("_meta")
        .or_insert_with(|| Value::Object(Default::default()));
    let Some(meta) = meta.as_object_mut() else {
        return;
    };
    meta.insert(
        meta_key::PROTOCOL_VERSION.to_string(),
        Value::String(version.to_string()),
    );
    meta.insert(meta_key::CLIENT_INFO.to_string(), client.clone());
    meta.insert(
        meta_key::CLIENT_CAPABILITIES.to_string(),
        capabilities.clone(),
    );
}

/// The `resultType` values the revision defines. A client reads a result with
/// none as `complete`, as it must for a server that predates the field.
pub mod result_type {
    pub const COMPLETE: &str = "complete";
    /// A multi round-trip request's interim result (SEP-2322): the server
    /// needs more from the client before it can answer, and the client asks
    /// again with it.
    pub const INPUT_REQUIRED: &str = "input_required";
}

/// The capabilities under which a server may ask a client for input, in an
/// `InputRequiredResult`: one for each kind of request it may make there.
const INPUT_CAPABILITIES: [&str; 3] = ["elicitation", "sampling", "roots"];

/// Whether `result` is an interim `InputRequiredResult`, not an answer.
///
/// Only `tools/call`, `resources/read` and `prompts/get` may be answered with
/// one. The client asks again, under a new id, with `inputResponses` for the
/// server's `inputRequests` and the `requestState` it was given.
pub fn input_required(result: &Value) -> bool {
    result.get("resultType").and_then(Value::as_str) == Some(result_type::INPUT_REQUIRED)
}

/// What a modern request's client can be asked for in an
/// `InputRequiredResult`: the `elicitation`, `sampling` and `roots` it
/// declares, as it declares them. `{}` for a legacy request, which could not
/// read such a result.
///
/// The capabilities MCPdef declares to an upstream for that request
/// ([`stamp_request_offering`]). Nothing else the client declares goes: the
/// gateway would have to keep those claims itself.
pub fn input_capabilities(msg: &Message) -> Value {
    let mut offered = serde_json::Map::new();
    if protocol_version(msg).is_some() {
        if let Some(declared) = client_capabilities(msg).and_then(Value::as_object) {
            for key in INPUT_CAPABILITIES {
                if let Some(value) = declared.get(key) {
                    offered.insert(key.to_string(), value.clone());
                }
            }
        }
    }
    Value::Object(offered)
}

/// Why a client that declared `capabilities` could not answer the interim
/// `result`, or `None` when it could.
///
/// The revision's rules for the result: `inputRequests` is an object whose
/// every value is an `elicitation/create`, a `sampling/createMessage` or a
/// `roots/list`, and asks only for what the client declared; `requestState`
/// is a string; and at least one of the two is there. A form elicitation needs
/// `elicitation` (an empty one means forms), and one in URL mode needs
/// `elicitation.url`.
pub fn unanswerable_input(result: &Value, capabilities: &Value) -> Option<String> {
    let state = result.get("requestState");
    if state.is_some_and(|state| !state.is_string()) {
        return Some("its `requestState` is not a string".into());
    }
    let Some(requests) = result.get("inputRequests") else {
        return state
            .is_none()
            .then(|| "it holds neither `inputRequests` nor `requestState`".into());
    };
    let Some(requests) = requests.as_object() else {
        return Some("its `inputRequests` is not an object".into());
    };
    for (key, request) in requests {
        let declared = match request.get("method").and_then(Value::as_str) {
            Some(method::ELICITATION_CREATE) => {
                let url = request
                    .get("params")
                    .and_then(|params| params.get("mode"))
                    .and_then(Value::as_str)
                    == Some("url");
                match capabilities.get("elicitation") {
                    None => false,
                    Some(modes) if url => modes.get("url").is_some(),
                    Some(modes) => modes.get("form").is_some() || modes.get("url").is_none(),
                }
            }
            Some(method::SAMPLING_CREATE_MESSAGE) => capabilities.get("sampling").is_some(),
            Some(method::ROOTS_LIST) => capabilities.get("roots").is_some(),
            Some(other) => {
                return Some(format!(
                    "its input request '{key}' is `{other}`, which no server may send"
                ))
            }
            None => return Some(format!("its input request '{key}' names no method")),
        };
        if !declared {
            let method = request["method"].as_str().unwrap_or_default();
            let mode = if method == method::ELICITATION_CREATE
                && request["params"]["mode"].as_str() == Some("url")
            {
                " in URL mode"
            } else {
                ""
            };
            return Some(format!(
                "its input request '{key}' is `{method}`{mode}, which the client did not \
                 declare it can answer"
            ));
        }
    }
    None
}

/// Take off a request the per-request metadata only a modern server reads.
///
/// The counterpart of [`stamp_request`], for a request bound for a *legacy*
/// upstream. A request relayed from a 2026-07-28 client carries that client's
/// revision, identity and capabilities in `_meta`. Passed on as-is it would
/// claim a revision the upstream does not speak — mirrored into an
/// `MCP-Protocol-Version` header over HTTP, which a 2025-11-25 server must
/// refuse — and speak for the downstream client's capabilities, which a proxy
/// does not.
///
/// Only those three keys go. Anything else in `_meta` (a `progressToken`, say)
/// stays, and a `_meta` left empty is removed, so the upstream gets what a
/// 2025-11-25 client would have sent.
pub fn strip_modern_meta(msg: &mut Message) {
    let Some(params) = msg.params.as_mut().and_then(Value::as_object_mut) else {
        return;
    };
    let Some(meta) = params.get_mut("_meta").and_then(Value::as_object_mut) else {
        return;
    };
    for key in [
        meta_key::PROTOCOL_VERSION,
        meta_key::CLIENT_INFO,
        meta_key::CLIENT_CAPABILITIES,
    ] {
        meta.remove(key);
    }
    if meta.is_empty() {
        params.remove("_meta");
    }
}

/// Does this reply identify its sender as a *modern* server?
///
/// The revision's own rule for telling the two eras apart, and it is not
/// cosmetic. A modern server answers an unsupported version, a header mismatch
/// or an unknown method with `400`/`404` **and a JSON-RPC error body**; a legacy
/// HTTP+SSE server answers the same statuses with no MCP body at all, because it
/// does not host the endpoint. So the body, not the status, is the signal:
///
/// > On `400 Bad Request`, the client **SHOULD** inspect the response body
/// > before falling back … If the body contains a recognized modern JSON-RPC
/// > error, the server speaks a modern version of MCP — retry using the
/// > advertised `supported` versions or correct the request, rather than falling
/// > back.
///
/// Treating a bare status as the signal is how a modern server gets mistaken for
/// a 2024-11-05 one and dragged onto the deprecated SSE bridge.
///
/// [`initialize_proves_modern`] asks the same question of an `initialize` reply,
/// where the answer decides an upstream's *era* rather than its transport.
pub fn is_modern_error(msg: &Message) -> bool {
    let Some(err) = msg.error.as_ref() else {
        return false;
    };
    matches!(
        err.get("code").and_then(Value::as_i64),
        Some(error_code::HEADER_MISMATCH)
            | Some(error_code::UNSUPPORTED_PROTOCOL_VERSION)
            | Some(error_code::METHOD_NOT_FOUND)
    )
}

/// Does this reply to `initialize` prove its sender is a modern server?
///
/// The same codes as [`is_modern_error`], asked of a different question — and
/// the **opposite** conclusion from [`discover_proves_modern`] on the same
/// `-32601`. The three are deliberately separate because that is the part which
/// is easy to get wrong:
///
/// | Asked | `-32601` means |
/// |---|---|
/// | `initialize` | **modern** — 2026-07-28 removed the method (SEP-2575) |
/// | `server/discover` | **legacy** — every modern server must implement it |
/// | some other method, over HTTP | **modern** — the body proves the endpoint exists |
///
/// `initialize` is the probe worth sending first, on any transport. It is the
/// only message that is legal-first in every era, and its absence is what
/// *defines* the modern one, so asking for it is the most direct form of the
/// question. On HTTP that matters twice over: `HttpClient`'s first send also
/// selects the binding, and this way the era probe *is* the opening request
/// rather than a second negotiation competing for it.
///
/// A modern server may refuse it with any of three codes, depending on what it
/// checks first — method-not-found, or a header/`_meta` mismatch, or an
/// unsupported version — so all three count. A legacy server answers with a
/// result, and any other error (bad params, say) is not evidence of an era.
pub fn initialize_proves_modern(reply: &Message) -> bool {
    is_modern_error(reply)
}

/// Does this reply to `server/discover` prove its sender is a modern server?
///
/// Narrower than [`is_modern_error`], and deliberately so — they answer different
/// questions and the difference is easy to get wrong.
///
/// `-32601` identifies a modern server when it answers *some other* method: the
/// revision has a modern server return method-not-found with a `404`, and that
/// JSON-RPC body is exactly what tells a client the MCP endpoint exists at all
/// rather than being a legacy server with no such route. But in reply to
/// `server/discover` the same code proves the opposite. Every modern server
/// **MUST** implement `server/discover`, so a method-not-found *for it* is a
/// server that predates the method.
///
/// What does prove modern here: a result, or an error only a modern server
/// produces — an unsupported version, or a header mismatch, neither of which a
/// 2025-11-25 server has any rule for.
pub fn discover_proves_modern(reply: &Message) -> bool {
    if reply.error.is_none() {
        return true;
    }
    matches!(
        reply
            .error
            .as_ref()
            .and_then(|e| e.get("code"))
            .and_then(Value::as_i64),
        Some(error_code::UNSUPPORTED_PROTOCOL_VERSION) | Some(error_code::HEADER_MISMATCH)
    )
}

/// The revisions a server named in an `UnsupportedProtocolVersionError`, or in a
/// `server/discover` result. Empty when it said nothing useful.
pub fn advertised_versions(msg: &Message) -> Vec<String> {
    let from_error = msg
        .error
        .as_ref()
        .and_then(|e| e.get("data"))
        .and_then(|d| d.get("supported"));
    let from_result = msg.result.as_ref().and_then(|r| r.get("supportedVersions"));
    from_error
        .or(from_result)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The routing facts a gateway may act on.
///
/// Reachable only from [`validate_headers`], and every field is read from the
/// **body**. That is the point: the headers exist so an intermediary need not
/// parse the body, and MCPdef parses it anyway, so for MCPdef the headers are
/// something to check rather than something to trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routing<'a> {
    /// The declared protocol version, from `_meta`.
    pub protocol_version: &'a str,
    /// The JSON-RPC method, from `method`.
    pub method: &'a str,
    /// The tool name, prompt name or resource URI this call targets, from
    /// `params`. `None` for a method that has no such field.
    pub name: Option<&'a str>,
}

/// A rejection this revision names.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// HTTP 400 + `-32020`. A required header is missing, malformed, or
    /// disagrees with the body.
    #[error("{0}")]
    HeaderMismatch(String),
    /// HTTP 400 + `-32022`, carrying what this gateway does serve so the client
    /// can retry against it rather than guess.
    #[error("unsupported protocol version {requested:?}; this gateway serves {supported:?}")]
    UnsupportedProtocolVersion {
        requested: String,
        supported: Vec<String>,
    },
}

impl WireError {
    /// The JSON-RPC error code the revision allocates for this rejection.
    pub fn code(&self) -> i64 {
        match self {
            WireError::HeaderMismatch(_) => error_code::HEADER_MISMATCH,
            WireError::UnsupportedProtocolVersion { .. } => {
                error_code::UNSUPPORTED_PROTOCOL_VERSION
            }
        }
    }

    /// Both of these are `400 Bad Request`. Kept as a method rather than a
    /// constant because the listener should ask rather than assume.
    pub fn http_status(&self) -> u16 {
        400
    }

    /// The JSON-RPC error response to send back.
    ///
    /// `id` is `None` when the request could not be parsed far enough to have
    /// one; the revision allows an error response with no `id` for exactly that
    /// case.
    pub fn to_message(&self, id: Option<Id>) -> Message {
        let mut error = serde_json::json!({
            "code": self.code(),
            "message": self.to_string(),
        });
        if let WireError::UnsupportedProtocolVersion {
            requested,
            supported,
        } = self
        {
            error["data"] = serde_json::json!({
                "supported": supported,
                "requested": requested,
            });
        }
        Message {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            method: None,
            params: None,
            result: None,
            error: Some(error),
        }
    }
}

/// Check the mirrored headers against the body and return what may be trusted.
///
/// `get` looks a header up by its **lower-case** name and returns the value as
/// sent; header names are compared case-insensitively and values are not.
///
/// The revision's failure conditions, in order:
///
/// * a required standard header (`MCP-Protocol-Version`, `Mcp-Method`,
///   `Mcp-Name`) is missing;
/// * a header value does not match the body's, after decoding the sentinel;
/// * a header value contains characters a header field value cannot carry.
///
/// An `Mcp-Name` on a method that has no name field is ignored rather than
/// rejected: there is no body value for it to disagree with, and RFC 9110 tells
/// an intermediary to forward what it does not recognize.
///
/// `served` is the revisions *this listener* answers for — not
/// [`KNOWN_SPEC_VERSIONS`]. A request declaring anything else is refused with
/// that list attached, which is what a client retries against.
pub fn validate_headers<'a, F>(
    msg: &'a Message,
    get: F,
    served: &[&str],
) -> Result<Routing<'a>, WireError>
where
    F: Fn(&str) -> Option<&'a str>,
{
    let body_version = protocol_version(msg).ok_or_else(|| {
        WireError::HeaderMismatch(format!(
            "the request body carries no {} in params._meta",
            meta_key::PROTOCOL_VERSION
        ))
    })?;
    let header_version = required(&get, header::PROTOCOL_VERSION)?;
    if header_version != body_version {
        return Err(mismatch(
            header::PROTOCOL_VERSION,
            header_version,
            body_version,
        ));
    }
    if !served.contains(&body_version) {
        return Err(WireError::UnsupportedProtocolVersion {
            requested: body_version.to_string(),
            supported: served.iter().map(|v| v.to_string()).collect(),
        });
    }

    let body_method = msg.method().ok_or_else(|| {
        WireError::HeaderMismatch("the request body carries no method".to_string())
    })?;
    let header_method = required(&get, header::METHOD)?;
    if header_method != body_method {
        return Err(mismatch(header::METHOD, header_method, body_method));
    }

    let name = match name_field(body_method) {
        None => None,
        Some(field) => {
            let body_name = msg
                .params
                .as_ref()
                .and_then(|p| p.get(field))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    WireError::HeaderMismatch(format!(
                        "a {body_method} request must carry params.{field}"
                    ))
                })?;
            let raw = required(&get, header::NAME)?;
            let decoded = decode_header_value(raw)?;
            if decoded != body_name {
                return Err(mismatch(header::NAME, &decoded, body_name));
            }
            Some(body_name)
        }
    };

    Ok(Routing {
        protocol_version: body_version,
        method: body_method,
        name,
    })
}

/// Read a header that must be present, and refuse a value a header field
/// cannot carry before anything tries to compare it.
fn required<'a, F>(get: &F, name: &str) -> Result<&'a str, WireError>
where
    F: Fn(&str) -> Option<&'a str>,
{
    let v = get(name)
        .ok_or_else(|| WireError::HeaderMismatch(format!("required header {name} is missing")))?;
    if !is_header_safe(v) {
        return Err(WireError::HeaderMismatch(format!(
            "header {name} contains characters a header value cannot carry"
        )));
    }
    Ok(v)
}

/// The rejection for a header that disagrees with the body, naming both sides —
/// a reader needs to know which one was wrong, not just that they differed.
fn mismatch(name: &str, header_value: &str, body_value: &str) -> WireError {
    WireError::HeaderMismatch(format!(
        "header {name} value {header_value:?} does not match body value {body_value:?}"
    ))
}

/// Every byte a header field value may carry: visible ASCII, space, or tab.
fn is_header_safe(v: &str) -> bool {
    v.bytes().all(|b| (0x20..=0x7e).contains(&b) || b == 0x09)
}

/// Can this value go into a header as itself?
///
/// It must be carriable at all, must not lead or trail with whitespace (which an
/// intermediary is free to strip), and must not look like the sentinel — a plain
/// value that does would decode into something else on the way back.
fn needs_encoding(v: &str) -> bool {
    !is_header_safe(v)
        || v.starts_with([' ', '\t'])
        || v.ends_with([' ', '\t'])
        || (v.starts_with(SENTINEL_OPEN) && v.ends_with(SENTINEL_CLOSE))
}

/// Render a value for a header, wrapping it in the sentinel only when it has to
/// be. Plain values stay readable, which is the whole reason an intermediary
/// wanted them in a header.
pub fn encode_header_value(v: &str) -> Cow<'_, str> {
    if needs_encoding(v) {
        Cow::Owned(format!(
            "{SENTINEL_OPEN}{}{SENTINEL_CLOSE}",
            BASE64.encode(v)
        ))
    } else {
        Cow::Borrowed(v)
    }
}

/// Read a header value, unwrapping the sentinel if it is there.
///
/// The markers are case-sensitive and must appear exactly, so a value that
/// merely resembles them is returned untouched. A malformed payload inside real
/// markers is a rejection, not a pass-through: the alternative is comparing a
/// corrupted name against the body and calling the difference a mismatch, which
/// sends the reader somewhere useless.
pub fn decode_header_value(v: &str) -> Result<Cow<'_, str>, WireError> {
    let Some(inner) = v
        .strip_prefix(SENTINEL_OPEN)
        .and_then(|r| r.strip_suffix(SENTINEL_CLOSE))
    else {
        return Ok(Cow::Borrowed(v));
    };
    let bytes = BASE64.decode(inner).map_err(|e| {
        WireError::HeaderMismatch(format!(
            "a {SENTINEL_OPEN} header value is not valid Base64: {e}"
        ))
    })?;
    let text = String::from_utf8(bytes).map_err(|_| {
        WireError::HeaderMismatch(format!("a {SENTINEL_OPEN} header value is not valid UTF-8"))
    })?;
    Ok(Cow::Owned(text))
}

// ---------------------------------------------------------------------------
// `x-mcp-header`: tool parameters a server asks to see mirrored into headers.
// ---------------------------------------------------------------------------

/// One `x-mcp-header` annotation, lifted out of a tool's `inputSchema`.
///
/// The name is the *annotation's value*, not the parameter's: a property
/// `region` carrying `"x-mcp-header": "Region"` is mirrored as
/// `Mcp-Param-Region`. Getting that backwards produces a header the upstream
/// does not recognize, which it must then reject as a mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamHeader {
    /// The `{Name}` in `Mcp-Param-{Name}`, exactly as the schema spelled it.
    pub name: String,
    /// The chain of `properties` keys from the schema root to the annotated
    /// property. For a `tools/call` the root is `params.arguments`, so
    /// `["a", "b"]` means `params.arguments.a.b`.
    pub path: Vec<String>,
}

impl ParamHeader {
    /// The header name to send or look up, lower-cased: field names are
    /// case-insensitive, and everything in [`header`] is stored folded.
    pub fn header_name(&self) -> String {
        format!("{}{}", header::PARAM_PREFIX, self.name.to_ascii_lowercase())
    }

    /// The value at this annotation's path in a `tools/call`'s arguments.
    ///
    /// `None` when nothing is there, `null` included, which the revision makes
    /// a legal state rather than an error: "If no value is present at that path
    /// in the call arguments, the header is omitted."
    pub fn value_in<'a>(&self, arguments: &'a Value) -> Option<&'a Value> {
        let mut at = arguments;
        for step in &self.path {
            at = at.get(step)?;
        }
        (!at.is_null()).then_some(at)
    }

    /// `value` as it goes in a header, before the sentinel codec: a string as
    /// it is, a boolean lower-cased, an integer in decimal.
    ///
    /// The revision converts only those three, and its schema rule lets no
    /// other type carry an annotation. A number that is not an integer can
    /// still turn up, from a client that broke the tool's schema: it goes as
    /// its JSON text, so the header says what the body does and the upstream's
    /// own schema check is what refuses it. An integral one (`42.0`) goes as
    /// the integer it is. An object or an array cannot go in a header: `None`.
    pub fn wire_value(value: &Value) -> Option<String> {
        match value {
            Value::String(s) => Some(s.clone()),
            Value::Bool(b) => Some(b.to_string()),
            Value::Number(n) if n.is_i64() || n.is_u64() => Some(n.to_string()),
            Value::Number(n) => Some(match n.as_f64() {
                Some(f) if f.fract() == 0.0 && f.abs() <= MAX_SAFE_INTEGER => {
                    format!("{}", f as i64)
                }
                _ => n.to_string(),
            }),
            _ => None,
        }
    }
}

/// The largest integer an IEEE 754 double holds exactly, `2^53 - 1`: the
/// revision's bound on an annotated integer's value.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// Why a tool definition cannot be served at all.
///
/// The revision is blunt about the consequence: a client "**MUST** reject tool
/// definitions where any `x-mcp-header` value violates these constraints", and
/// rejection means excluding that tool from `tools/list`. An `x-mcp-header`
/// carrying a CR or LF is a header-injection primitive handed to whoever wrote
/// the tool definition, and MCPdef puts these headers on requests it sends.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaError {
    #[error("`x-mcp-header` at {path} must be a non-empty string")]
    NotAName { path: String },
    #[error("`x-mcp-header: {name:?}` at {path} is not an HTTP field name (an RFC 9110 token)")]
    NotAToken { path: String, name: String },
    #[error("`x-mcp-header: {name:?}` is used more than once; names must be unique ignoring case")]
    Duplicate { name: String },
    #[error(
        "`x-mcp-header: {name:?}` at {path} annotates a {found} parameter; only `string`, \
         `integer` and `boolean` may be mirrored into a header"
    )]
    NotPrimitive {
        path: String,
        name: String,
        found: String,
    },
    #[error(
        "`x-mcp-header: {name:?}` at {path} is not on a parameter reachable from the schema \
         root through `properties` alone"
    )]
    NotStaticallyReachable { path: String, name: String },
}

/// Every `x-mcp-header` annotation in one tool's `inputSchema`.
///
/// `Err` means the whole tool is unusable: see [`SchemaError`]. The revision
/// puts every one of these constraints on the *client*, which is what MCPdef is
/// to its upstreams, and makes the failure excluding the tool rather than
/// dropping the annotation. Half-using a definition found to be malformed is
/// how a CR in a header name becomes a request MCPdef sends.
///
/// The walk covers the whole schema, not just the `properties` chain. An
/// annotation somewhere unreachable (under `items`, `oneOf`, `if`, `$defs`)
/// is not skipped: it invalidates the tool, because its server asked for a
/// mirroring no client can perform, and quietly not performing it would leave
/// the two sides disagreeing about what a request said. Keywords whose values
/// are instances rather than schemas (`const`, `default`, `enum`, `examples`)
/// are not walked: an `x-mcp-header` key in an example value is data.
pub fn param_headers(input_schema: &Value) -> Result<Vec<ParamHeader>, SchemaError> {
    let mut found = Vec::new();
    walk_schema(input_schema, &mut Vec::new(), true, &mut found)?;

    // Unique ignoring case, because that is how the headers they become are
    // compared: `Region` and `region` would be one header and a silent
    // disagreement about whose value it carried.
    let mut seen: Vec<String> = Vec::with_capacity(found.len());
    for h in &found {
        let folded = h.name.to_ascii_lowercase();
        if seen.contains(&folded) {
            return Err(SchemaError::Duplicate {
                name: h.name.clone(),
            });
        }
        seen.push(folded);
    }
    Ok(found)
}

/// Keywords whose values are data, not subschemas: JSON instances, or the
/// names of properties (`dependentRequired`).
const INSTANCE_KEYWORDS: &[&str] = &["const", "default", "enum", "examples", "dependentRequired"];

/// Keywords whose values map names to subschemas, besides `properties`: a name
/// in one is a key, never an annotation.
const SCHEMA_MAP_KEYWORDS: &[&str] = &[
    "$defs",
    "definitions",
    "patternProperties",
    "dependentSchemas",
];

/// Recurse, tracking whether this position is still statically reachable.
///
/// Reachable means every step from the root has been a `properties` key. Once
/// the walk goes through anything else (an array keyword, a composition or
/// conditional keyword, `$defs`), it goes on inside the schema but marks what
/// it finds as unreachable, so an annotation there is reported, not ignored.
fn walk_schema(
    schema: &Value,
    path: &mut Vec<String>,
    reachable: bool,
    out: &mut Vec<ParamHeader>,
) -> Result<(), SchemaError> {
    let Some(obj) = schema.as_object() else {
        return Ok(());
    };

    if let Some(raw) = obj.get("x-mcp-header") {
        let at = if path.is_empty() {
            "the schema root".to_string()
        } else {
            path.join(".")
        };
        let name = raw
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SchemaError::NotAName { path: at.clone() })?;
        if !is_field_token(name) {
            return Err(SchemaError::NotAToken {
                path: at,
                name: name.to_string(),
            });
        }
        // The root is the arguments object, not a parameter in it.
        if !reachable || path.is_empty() {
            return Err(SchemaError::NotStaticallyReachable {
                path: at,
                name: name.to_string(),
            });
        }
        // A list of one type is that type; JSON Schema reads them the same.
        let declared = match obj.get("type") {
            Some(Value::Array(types)) if types.len() == 1 => types[0].as_str(),
            other => other.and_then(Value::as_str),
        };
        match declared {
            Some("string" | "integer" | "boolean") => {}
            // `number` is ruled out by name, and anything else (absent, a list
            // of several types) is not *known* to be one of the three. A header
            // is a string, and guessing what to put in one is how a client and
            // its server end up disagreeing.
            other => {
                return Err(SchemaError::NotPrimitive {
                    path: at,
                    name: name.to_string(),
                    found: other.unwrap_or("untyped").to_string(),
                })
            }
        }
        out.push(ParamHeader {
            name: name.to_string(),
            path: path.clone(),
        });
    }

    for (key, child) in obj {
        if INSTANCE_KEYWORDS.contains(&key.as_str()) {
            continue;
        }
        if key == "properties" {
            if let Some(props) = child.as_object() {
                for (prop, sub) in props {
                    path.push(prop.clone());
                    let walked = walk_schema(sub, path, reachable, out);
                    path.pop();
                    walked?;
                }
            }
            continue;
        }
        // Every other keyword is walked too, but nothing under it is
        // statically reachable.
        if SCHEMA_MAP_KEYWORDS.contains(&key.as_str()) {
            for sub in child.as_object().into_iter().flat_map(|m| m.values()) {
                walk_schema(sub, path, false, out)?;
            }
            continue;
        }
        match child {
            Value::Object(_) => walk_schema(child, path, false, out)?,
            Value::Array(items) => {
                for item in items {
                    walk_schema(item, path, false, out)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// RFC 9110 §5.1 `token`: `1*tchar`. Control characters, CR and LF among them,
/// are excluded by construction rather than by a check of their own.
fn is_field_token(v: &str) -> bool {
    !v.is_empty()
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// The `Mcp-Param-{Name}` headers one request should carry, by `annotations`,
/// the ones its tool declared ([`param_headers`]).
///
/// Only a modern `tools/call` carries any, as with [`mirrored_headers`]: on the
/// 2025-11-25 wire a server has no rule for them. A value that is absent or
/// `null` omits its header, which the revision makes a legal state: the server
/// "MUST NOT expect the header". A value goes out through the same sentinel
/// codec as `Mcp-Name`, so one that cannot sit in a header travels as
/// `=?base64?…?=` rather than being dropped or cut short into a disagreement
/// with the body.
pub fn param_header_values(msg: &Message, annotations: &[ParamHeader]) -> Vec<(String, String)> {
    if annotations.is_empty()
        || msg.method() != Some(method::TOOLS_CALL)
        || protocol_version(msg).is_none()
    {
        return Vec::new();
    }
    let Some(args) = msg.params.as_ref().and_then(|p| p.get("arguments")) else {
        return Vec::new();
    };
    annotations
        .iter()
        .filter_map(|a| {
            let text = ParamHeader::wire_value(a.value_in(args)?)?;
            Some((a.header_name(), encode_header_value(&text).into_owned()))
        })
        .collect()
}

/// Reconcile a `tools/call`'s `Mcp-Param-{Name}` headers with its body, by
/// `annotations`, the ones its tool declared.
///
/// The revision requires this of anything that reads the body: "Any server
/// that processes the message body **MUST** validate that encoded header
/// values, after decoding if Base64-encoded, match the corresponding values in
/// the request body." MCPdef reads the body on every call. `get` looks a header
/// up by its lower-case name, as for [`validate_headers`].
///
/// Only **recognized** headers are checked: ones naming an annotation this tool
/// declared. One it did not is the revision's to forward and otherwise ignore.
/// For a recognized one, each way the two sides can disagree is refused:
///
/// * the body carries the annotated argument and no header does: the
///   revision's own "Client omits header but value is in body", which a
///   server MUST reject;
/// * both carry it, and they differ. A number is compared as a number, as the
///   revision advises, so `42.0` and `42` agree;
/// * the header carries characters a header value cannot, or a sentinel that
///   does not decode;
/// * the header claims a value the body does not carry. The revision says only
///   that a server must not *expect* the header then, but a header asserting
///   what the body never said is the disagreement this check exists to stop.
///
/// An object or an array at an annotated path is taken for no value, as
/// [`param_header_values`] takes it: no header can carry one, so no client can
/// send one, and refusing the call for its absence would answer a schema error
/// as a header mismatch. The tool's schema, at its server, is what refuses it.
pub fn validate_param_headers<'a, F>(
    msg: &Message,
    get: F,
    annotations: &[ParamHeader],
) -> Result<(), WireError>
where
    F: Fn(&str) -> Option<&'a str>,
{
    if annotations.is_empty() {
        return Ok(());
    }
    let args = msg
        .params
        .as_ref()
        .and_then(|p| p.get("arguments"))
        .unwrap_or(&Value::Null);
    for a in annotations {
        let name = a.header_name();
        let argument = a.path.join(".");
        let sent = match get(&name) {
            Some(raw) if !is_header_safe(raw) => {
                return Err(WireError::HeaderMismatch(format!(
                    "header {name} contains characters a header value cannot carry"
                )))
            }
            Some(raw) => Some(decode_header_value(raw)?),
            None => None,
        };
        let carried = a
            .value_in(args)
            .filter(|v| ParamHeader::wire_value(v).is_some());
        match (carried, sent) {
            (None, None) => {}
            (Some(body), Some(header)) => {
                if !same_value(&header, body) {
                    let said = ParamHeader::wire_value(body).unwrap_or_default();
                    return Err(mismatch(&name, &header, &said));
                }
            }
            (Some(body), None) => {
                return Err(WireError::HeaderMismatch(format!(
                    "the body carries the annotated argument {argument:?} as {body}, so a \
                     matching {name} header is required"
                )))
            }
            (None, Some(header)) => {
                return Err(WireError::HeaderMismatch(format!(
                    "header {name} claims {header:?}, but the body carries no {argument:?} \
                     argument a header can carry"
                )))
            }
        }
    }
    Ok(())
}

/// Whether a decoded header value says what `body` does.
fn same_value(header: &str, body: &Value) -> bool {
    match body {
        Value::Number(n) => same_number(header, n),
        _ => ParamHeader::wire_value(body).is_some_and(|text| text == header),
    }
}

/// Whether `header` is the number `n`. An integer is compared exactly with an
/// integer, and with a double (`42.0`) only where a double holds every integer
/// exactly, so two past that precision are never taken for each other.
/// Anything else is compared as doubles.
fn same_number(header: &str, n: &serde_json::Number) -> bool {
    let exact = n
        .as_i64()
        .map(i128::from)
        .or_else(|| n.as_u64().map(i128::from));
    if let Some(body) = exact {
        if let Ok(header) = header.parse::<i128>() {
            return body == header;
        }
        let safe = body.unsigned_abs() <= MAX_SAFE_INTEGER as u128;
        return safe && header.parse::<f64>().is_ok_and(|h| h == body as f64);
    }
    match (n.as_f64(), header.parse::<f64>()) {
        (Some(body), Ok(header)) => header.is_finite() && body == header,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// What a listener in these tests serves: everything this build speaks.
    const SERVED: &[&str] = KNOWN_SPEC_VERSIONS;

    /// The revision's own `tools/call` example, verbatim.
    fn spec_tools_call() -> Message {
        Message::request(
            Id::Num(1),
            method::TOOLS_CALL,
            Some(json!({
                "name": "get_weather",
                "arguments": { "location": "Seattle, WA" },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "ExampleClient",
                        "version": "1.0.0"
                    },
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            })),
        )
    }

    /// The revision's own `resources/read` example, verbatim.
    fn spec_resources_read() -> Message {
        Message::request(
            Id::Num(2),
            method::RESOURCES_READ,
            Some(json!({
                "uri": "file:///projects/myapp/config.json",
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "ExampleClient",
                        "version": "1.0.0"
                    },
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            })),
        )
    }

    /// Look headers up from a slice, the way a normalized header map would.
    fn from<'a>(pairs: &'a [(&str, &str)]) -> impl Fn(&str) -> Option<&'a str> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| *v)
        }
    }

    #[test]
    fn a_request_carrying_meta_is_modern_and_an_initialize_is_legacy() {
        assert_eq!(WireModel::of(&spec_tools_call()), Some(WireModel::Modern));

        let init = Message::request(Id::Num(1), method::INITIALIZE, Some(json!({})));
        assert_eq!(WireModel::of(&init), Some(WireModel::Legacy));

        // A legacy `tools/call` names neither era: after `initialize` it is
        // legacy, but the message alone cannot say so.
        let bare = Message::request(Id::Num(1), method::TOOLS_CALL, Some(json!({"name": "t"})));
        assert_eq!(
            WireModel::of(&bare),
            None,
            "era comes from how the connection opened, never from a guess"
        );
    }

    #[test]
    fn the_specs_own_examples_read_back_field_for_field() {
        let m = spec_tools_call();
        assert_eq!(protocol_version(&m), Some("2026-07-28"));
        assert_eq!(client_info(&m).unwrap()["name"], "ExampleClient");
        assert_eq!(client_capabilities(&m), Some(&json!({})));
        assert_eq!(name_value(&m), Some("get_weather"));

        let r = spec_resources_read();
        assert_eq!(
            name_value(&r),
            Some("file:///projects/myapp/config.json"),
            "resources/read mirrors params.uri, not params.name"
        );
    }

    #[test]
    fn the_mirrored_headers_are_the_ones_the_spec_example_shows() {
        assert_eq!(
            mirrored_headers(&spec_tools_call()),
            vec![
                (header::PROTOCOL_VERSION, "2026-07-28".to_string()),
                (header::METHOD, "tools/call".to_string()),
                (header::NAME, "get_weather".to_string()),
            ]
        );

        // A method with no name field emits no `Mcp-Name`.
        let list = Message::request(
            Id::Num(3),
            method::TOOLS_LIST,
            Some(json!({ "_meta": { meta_key::PROTOCOL_VERSION: SPEC_2026_07_28 } })),
        );
        let names: Vec<_> = mirrored_headers(&list)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert!(!names.contains(&header::NAME), "got: {names:?}");
    }

    /// A legacy message mirrors nothing — not even `Mcp-Method`.
    ///
    /// The mirrored headers are a 2026-07-28 construct, safe to act on only
    /// because a modern server must check them against the body. A message
    /// that declares no revision has no such check behind it, so headers on it
    /// would be unvalidated claims about the body, sent to a server that never
    /// asked for them. `_meta` alone is not the signal: a 2025-11-25 request
    /// may carry one (a `progressToken`, say), and only a declared protocol
    /// version makes a message modern.
    #[test]
    fn a_legacy_message_mirrors_no_headers() {
        let legacy = [
            Message::request(
                Id::Num(1),
                method::INITIALIZE,
                Some(json!({ "protocolVersion": SPEC_2025_11_25 })),
            ),
            Message::notification(method::INITIALIZED, None),
            Message::request(Id::Num(2), method::TOOLS_LIST, None),
            Message::request(
                Id::Num(3),
                method::TOOLS_CALL,
                Some(json!({ "name": "echo", "arguments": {} })),
            ),
            Message::request(
                Id::Num(4),
                method::TOOLS_CALL,
                Some(json!({ "name": "echo", "_meta": { "progressToken": 7 } })),
            ),
            Message::request(
                Id::Num(5),
                method::RESOURCES_READ,
                Some(json!({ "uri": "file:///projects/myapp/config.json" })),
            ),
        ];
        for m in &legacy {
            let headers = mirrored_headers(m);
            assert!(
                headers.is_empty(),
                "a legacy {:?} must mirror nothing, got {headers:?}",
                m.method()
            );
        }
    }

    #[test]
    fn a_conforming_request_validates_and_the_routing_comes_from_the_body() {
        let m = spec_tools_call();
        let routing = validate_headers(
            &m,
            from(&[
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "tools/call"),
                ("Mcp-Name", "get_weather"),
            ]),
            SERVED,
        )
        .unwrap();
        assert_eq!(
            routing,
            Routing {
                protocol_version: "2026-07-28",
                method: "tools/call",
                name: Some("get_weather"),
            }
        );
    }

    /// The bypass this whole module exists to prevent: allow-list on the header,
    /// execute the body.
    #[test]
    fn a_name_header_that_disagrees_with_the_body_is_rejected_not_preferred() {
        let mut m = spec_tools_call();
        m.params.as_mut().unwrap()["name"] = json!("dangerous_tool");

        let e = validate_headers(
            &m,
            from(&[
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/call"),
                ("mcp-name", "get_weather"),
            ]),
            SERVED,
        )
        .unwrap_err();

        assert_eq!(e.code(), error_code::HEADER_MISMATCH);
        assert_eq!(e.http_status(), 400);
        let msg = e.to_string();
        assert!(
            msg.contains("get_weather") && msg.contains("dangerous_tool"),
            "got: {msg}"
        );
    }

    #[test]
    fn every_required_header_is_required_by_name() {
        let m = spec_tools_call();
        for missing in [header::PROTOCOL_VERSION, header::METHOD, header::NAME] {
            let all = [
                (header::PROTOCOL_VERSION, "2026-07-28"),
                (header::METHOD, "tools/call"),
                (header::NAME, "get_weather"),
            ];
            let kept: Vec<_> = all.iter().copied().filter(|(k, _)| *k != missing).collect();
            let e = validate_headers(&m, from(&kept), SERVED).unwrap_err();
            assert!(
                e.to_string().contains(missing),
                "dropping {missing} must say so: {e}"
            );
            assert_eq!(e.code(), error_code::HEADER_MISMATCH);
        }
    }

    #[test]
    fn header_names_compare_case_insensitively_and_values_do_not() {
        let m = spec_tools_call();
        assert!(validate_headers(
            &m,
            from(&[
                ("mCp-PrOtOcOl-VeRsIoN", "2026-07-28"),
                ("MCP-METHOD", "tools/call"),
                ("mcp-name", "get_weather"),
            ]),
            SERVED,
        )
        .is_ok());

        let e = validate_headers(
            &m,
            from(&[
                (header::PROTOCOL_VERSION, "2026-07-28"),
                (header::METHOD, "tools/call"),
                (header::NAME, "GET_WEATHER"),
            ]),
            SERVED,
        )
        .unwrap_err();
        assert_eq!(
            e.code(),
            error_code::HEADER_MISMATCH,
            "a tool name is case-sensitive: {e}"
        );
    }

    #[test]
    fn an_unserved_revision_is_reported_with_what_is_served() {
        let mut m = spec_tools_call();
        m.params.as_mut().unwrap()["_meta"][meta_key::PROTOCOL_VERSION] = json!("1900-01-01");

        let e = validate_headers(
            &m,
            from(&[
                (header::PROTOCOL_VERSION, "1900-01-01"),
                (header::METHOD, "tools/call"),
                (header::NAME, "get_weather"),
            ]),
            SERVED,
        )
        .unwrap_err();

        assert_eq!(e.code(), error_code::UNSUPPORTED_PROTOCOL_VERSION);
        let body = e.to_message(Some(Id::Num(1)));
        let err = body.error.unwrap();
        assert_eq!(err["code"], -32022);
        assert_eq!(err["data"]["requested"], "1900-01-01");
        assert_eq!(
            err["data"]["supported"],
            json!(["2026-07-28", "2025-11-25"])
        );
    }

    /// The encoding table from the revision, value for value.
    #[test]
    fn the_sentinel_codec_matches_the_specs_table() {
        for (plain, encoded) in [
            ("us-west1", "us-west1"),
            ("Hello, 世界", "=?base64?SGVsbG8sIOS4lueVjA==?="),
            (" padded ", "=?base64?IHBhZGRlZCA=?="),
            ("line1\nline2", "=?base64?bGluZTEKbGluZTI=?="),
            ("=?base64?literal?=", "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="),
        ] {
            assert_eq!(encode_header_value(plain), encoded, "encoding {plain:?}");
            assert_eq!(
                decode_header_value(encoded).unwrap(),
                plain,
                "decoding {encoded:?}"
            );
        }
    }

    #[test]
    fn a_name_that_needs_encoding_survives_the_round_trip_through_validation() {
        let mut m = spec_tools_call();
        m.params.as_mut().unwrap()["name"] = json!("搜索");

        let routing = validate_headers(
            &m,
            from(&[
                (header::PROTOCOL_VERSION, "2026-07-28"),
                (header::METHOD, "tools/call"),
                (header::NAME, "=?base64?5pCc57Si?="),
            ]),
            SERVED,
        )
        .unwrap();
        assert_eq!(
            routing.name,
            Some("搜索"),
            "the decoded header must match, and the body wins"
        );
    }

    #[test]
    fn a_broken_sentinel_payload_is_a_rejection_rather_than_a_confusing_mismatch() {
        let e = decode_header_value("=?base64?not base64!?=").unwrap_err();
        assert!(e.to_string().contains("Base64"), "got: {e}");
        assert_eq!(e.code(), error_code::HEADER_MISMATCH);

        // Real markers, valid Base64, not UTF-8.
        let e = decode_header_value("=?base64?/w==?=").unwrap_err();
        assert!(e.to_string().contains("UTF-8"), "got: {e}");

        // Something that only looks like the markers is left alone.
        assert_eq!(decode_header_value("=?BASE64?x?=").unwrap(), "=?BASE64?x?=");
    }

    #[test]
    fn a_header_value_carrying_a_newline_is_refused_before_it_is_compared() {
        let m = spec_tools_call();
        let e = validate_headers(
            &m,
            from(&[
                (header::PROTOCOL_VERSION, "2026-07-28"),
                (header::METHOD, "tools/call\r\nX-Admin: 1"),
                (header::NAME, "get_weather"),
            ]),
            SERVED,
        )
        .unwrap_err();
        assert!(e.to_string().contains("cannot carry"), "got: {e}");
    }

    /// A listener configured for one era must advertise only that era.
    /// Reporting `KNOWN_SPEC_VERSIONS` here would send a client to retry with a
    /// revision this deployment then refuses — a loop, not a negotiation.
    #[test]
    fn the_supported_list_is_what_the_caller_serves_not_what_the_build_knows() {
        let m = spec_tools_call();
        let headers = [
            (header::PROTOCOL_VERSION, "2026-07-28"),
            (header::METHOD, "tools/call"),
            (header::NAME, "get_weather"),
        ];

        let e = validate_headers(&m, from(&headers), &[SPEC_2025_11_25]).unwrap_err();
        assert_eq!(e.code(), error_code::UNSUPPORTED_PROTOCOL_VERSION);
        let err = e.to_message(Some(Id::Num(1))).error.unwrap();
        assert_eq!(err["data"]["supported"], json!(["2025-11-25"]));
        assert_eq!(err["data"]["requested"], "2026-07-28");

        // The same request, on a listener that does serve it.
        assert!(validate_headers(&m, from(&headers), &[SPEC_2026_07_28]).is_ok());
    }

    /// What MCPdef puts on a request it sends to a modern upstream. The headers
    /// a conforming client mirrors are derived from the same message, so a
    /// stamped request and its headers cannot disagree by construction.
    #[test]
    fn a_stamped_request_carries_what_a_modern_server_requires_and_validates() {
        let client = json!({ "name": "mcpdef", "version": "0.2.0" });
        let mut m = Message::request(
            Id::Num(1),
            method::TOOLS_CALL,
            Some(json!({ "name": "echo", "arguments": { "msg": "hi" } })),
        );
        stamp_request(&mut m, SPEC_2026_07_28, &client);

        assert_eq!(WireModel::of(&m), Some(WireModel::Modern));
        assert_eq!(protocol_version(&m), Some(SPEC_2026_07_28));
        assert_eq!(client_info(&m), Some(&client));
        assert_eq!(client_capabilities(&m), Some(&json!({})));
        assert_eq!(
            m.params.as_ref().unwrap()["arguments"]["msg"],
            "hi",
            "stamping must not disturb the call itself"
        );

        // The headers a client mirrors come off the same message, so the request
        // validates against its own headers with nothing to reconcile.
        let headers = mirrored_headers(&m);
        let routing = validate_headers(
            &m,
            |name| {
                headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.as_str())
            },
            SERVED,
        )
        .expect("a stamped request validates against its own mirrored headers");
        assert_eq!(routing.name, Some("echo"));

        // Re-stamping replaces rather than nesting.
        stamp_request(&mut m, SPEC_2026_07_28, &client);
        assert_eq!(protocol_version(&m), Some(SPEC_2026_07_28));

        // A notification is left exactly as it was: the revision asks for this
        // metadata on requests, and inventing a rule for anything else is how a
        // peer ends up with a `_meta` it has no reason to expect.
        let before = Message::notification("notifications/cancelled", Some(json!({ "x": 1 })));
        let mut n = before.clone();
        stamp_request(&mut n, SPEC_2026_07_28, &client);
        assert_eq!(n, before, "a notification must not be stamped");

        // Nor is a response, which has no params to stamp onto.
        let before = Message::result(Id::Num(9), json!({ "ok": true }));
        let mut r = before.clone();
        stamp_request(&mut r, SPEC_2026_07_28, &client);
        assert_eq!(r, before, "a response must not be stamped");
    }

    /// A 2026-07-28 client's request, relayed to a legacy upstream, reaches it as
    /// a 2025-11-25 client would have sent it: no declared revision, nothing to
    /// mirror, and the rest of its `_meta` untouched.
    #[test]
    fn stripping_leaves_what_a_legacy_client_would_have_sent() {
        let mut m = spec_tools_call();
        m.params.as_mut().unwrap()["_meta"]["progressToken"] = json!(7);
        strip_modern_meta(&mut m);

        assert_eq!(WireModel::of(&m), None, "it no longer declares a revision");
        assert!(mirrored_headers(&m).is_empty(), "so nothing is mirrored");
        let params = m.params.as_ref().unwrap();
        assert_eq!(
            params["_meta"],
            json!({ "progressToken": 7 }),
            "unrelated `_meta` stays"
        );
        assert_eq!(
            params["name"], "get_weather",
            "the call itself is untouched"
        );

        // A `_meta` that held nothing else goes entirely.
        let mut m = spec_tools_call();
        strip_modern_meta(&mut m);
        assert!(m.params.as_ref().unwrap().get("_meta").is_none());

        // A request with nothing to strip is left exactly as it was.
        let before = Message::request(Id::Num(3), method::TOOLS_LIST, None);
        let mut m = before.clone();
        strip_modern_meta(&mut m);
        assert_eq!(m, before);
    }

    /// The knob an operator sets per server. Exercised here through serde (the
    /// renames are format-agnostic); `config.rs` covers the real TOML path.
    #[test]
    fn a_spec_setting_is_named_by_its_revision_or_by_auto() {
        let d = |v: &str| -> Result<SpecSetting, serde_json::Error> {
            serde_json::from_str(&format!("\"{v}\""))
        };
        assert_eq!(
            SpecSetting::default(),
            SpecSetting::V20251125,
            "an unset knob must keep speaking the old wire"
        );
        assert_eq!(
            d("2025-11-25").unwrap().pinned(),
            Some(UpstreamSpec::V20251125)
        );
        assert_eq!(
            d("2026-07-28").unwrap().pinned(),
            Some(UpstreamSpec::V20260728)
        );
        assert_eq!(
            d("auto").unwrap().pinned(),
            None,
            "auto is a question, not an answer"
        );

        let e = d("2024-11-05").unwrap_err().to_string();
        assert!(e.contains("2026-07-28") && e.contains("auto"), "got: {e}");
    }

    /// The era split, and the revision each side declares.
    #[test]
    fn a_resolved_spec_maps_to_its_era_and_revision() {
        assert_eq!(UpstreamSpec::V20251125.era(), WireModel::Legacy);
        assert_eq!(UpstreamSpec::V20260728.era(), WireModel::Modern);
        assert_eq!(UpstreamSpec::V20260728.version(), SPEC_2026_07_28);
    }

    /// The discriminator the probe and the transport both turn on. It is the
    /// body, never the status — a legacy HTTP+SSE server answers the same 400s
    /// and 404s with no MCP body at all.
    #[test]
    fn a_modern_server_is_identified_by_its_error_body_not_its_status() {
        let err = |code: i64| {
            let mut m = Message::error(Id::Num(1), code, "x");
            m.id = Some(Id::Num(1));
            m
        };
        for code in [
            error_code::HEADER_MISMATCH,
            error_code::UNSUPPORTED_PROTOCOL_VERSION,
            error_code::METHOD_NOT_FOUND,
        ] {
            assert!(
                is_modern_error(&err(code)),
                "{code} identifies a modern server"
            );
        }
        assert!(
            !is_modern_error(&err(-32603)),
            "an internal error says nothing about era"
        );

        // The probe asks a narrower question, and `-32601` answers it the other
        // way: a modern server MUST implement `server/discover`, so a
        // method-not-found *for that method* is a server older than it.
        assert!(
            !discover_proves_modern(&err(error_code::METHOD_NOT_FOUND)),
            "no such method `server/discover` means the server predates it"
        );
        assert!(discover_proves_modern(&err(
            error_code::UNSUPPORTED_PROTOCOL_VERSION
        )));
        assert!(discover_proves_modern(&err(error_code::HEADER_MISMATCH)));
        assert!(discover_proves_modern(&Message::result(
            Id::Num(1),
            json!({})
        )));
        assert!(
            !is_modern_error(&Message::result(Id::Num(1), json!({}))),
            "a result is not an error"
        );

        // And what a server said it speaks, from either shape.
        let mut unsupported =
            Message::error(Id::Num(1), error_code::UNSUPPORTED_PROTOCOL_VERSION, "no");
        unsupported.error.as_mut().unwrap()["data"] = json!({ "supported": ["2026-07-28"] });
        assert_eq!(advertised_versions(&unsupported), vec!["2026-07-28"]);

        let discovered =
            Message::result(Id::Num(1), json!({ "supportedVersions": ["2026-07-28"] }));
        assert_eq!(advertised_versions(&discovered), vec!["2026-07-28"]);
        assert!(advertised_versions(&Message::result(Id::Num(1), json!({}))).is_empty());
    }

    #[test]
    fn a_body_with_no_meta_never_validates_as_modern() {
        let m = Message::request(Id::Num(1), method::TOOLS_CALL, Some(json!({"name": "t"})));
        let e = validate_headers(
            &m,
            from(&[
                (header::PROTOCOL_VERSION, "2026-07-28"),
                (header::METHOD, "tools/call"),
                (header::NAME, "t"),
            ]),
            SERVED,
        )
        .unwrap_err();
        assert!(
            e.to_string().contains(meta_key::PROTOCOL_VERSION),
            "got: {e}"
        );
    }

    /// A modern `tools/call` whose client declares `capabilities`.
    fn call_declaring(capabilities: Value) -> Message {
        let mut m = spec_tools_call();
        m.params.as_mut().unwrap()["_meta"][meta_key::CLIENT_CAPABILITIES] = capabilities;
        m
    }

    #[test]
    fn only_the_capabilities_a_server_may_ask_under_are_offered_on() {
        let m = call_declaring(json!({
            "elicitation": { "form": {}, "url": {} },
            "sampling": { "tools": {} },
            "roots": {},
            "experimental": { "x": {} },
            "extensions": { "io.example/ext": {} },
        }));
        assert_eq!(
            input_capabilities(&m),
            json!({
                "elicitation": { "form": {}, "url": {} },
                "sampling": { "tools": {} },
                "roots": {},
            })
        );
        assert_eq!(
            input_capabilities(&call_declaring(json!({ "elicitation": {} }))),
            json!({ "elicitation": {} })
        );
        // A legacy request's client could not read an input-required result,
        // whatever it says.
        let mut legacy = m.clone();
        strip_modern_meta(&mut legacy);
        legacy.params.as_mut().unwrap()["_meta"] =
            json!({ meta_key::CLIENT_CAPABILITIES: { "elicitation": {} } });
        assert_eq!(input_capabilities(&legacy), json!({}));
        assert_eq!(input_capabilities(&call_declaring(json!(null))), json!({}));
    }

    #[test]
    fn stamping_offers_what_it_is_given_and_otherwise_nothing() {
        let client = json!({ "name": "mcpdef", "version": "0" });
        let mut plain = call_declaring(json!({ "elicitation": {} }));
        stamp_request(&mut plain, SPEC_2026_07_28, &client);
        assert_eq!(client_capabilities(&plain), Some(&json!({})));

        let mut relayed = call_declaring(json!({ "elicitation": {}, "experimental": {} }));
        let offered = input_capabilities(&relayed);
        stamp_request_offering(&mut relayed, SPEC_2026_07_28, &client, &offered);
        assert_eq!(
            client_capabilities(&relayed),
            Some(&json!({ "elicitation": {} }))
        );
        assert_eq!(client_info(&relayed), Some(&client));
    }

    /// The revision's own `InputRequiredResult` example, verbatim.
    fn spec_input_required() -> Value {
        json!({
            "resultType": "input_required",
            "inputRequests": {
                "github_login": {
                    "method": "elicitation/create",
                    "params": {
                        "mode": "form",
                        "message": "Please provide your GitHub username",
                        "requestedSchema": {
                            "type": "object",
                            "properties": { "name": { "type": "string" } },
                            "required": ["name"]
                        }
                    }
                },
                "capital_of_france": {
                    "method": "sampling/createMessage",
                    "params": {
                        "messages": [{
                            "role": "user",
                            "content": { "type": "text", "text": "What is the capital of France?" }
                        }],
                        "maxTokens": 100
                    }
                }
            },
            "requestState": "eyJsb2NhdGlvbiI6Ik5ldyBZb3JrIn0"
        })
    }

    #[test]
    fn an_interim_result_is_told_by_its_result_type_alone() {
        assert!(input_required(&spec_input_required()));
        assert!(input_required(&json!({ "resultType": "input_required" })));
        assert!(!input_required(
            &json!({ "resultType": "complete", "content": [] })
        ));
        // A server that predates the field answered in full.
        assert!(!input_required(&json!({ "content": [] })));
        assert!(!input_required(&json!({ "resultType": "later" })));
    }

    #[test]
    fn a_client_can_answer_only_what_it_declared() {
        let result = spec_input_required();
        let both = json!({ "elicitation": {}, "sampling": {} });
        assert_eq!(unanswerable_input(&result, &both), None);
        assert_eq!(
            unanswerable_input(&result, &json!({ "elicitation": {} })).as_deref(),
            Some(
                "its input request 'capital_of_france' is `sampling/createMessage`, which the \
                 client did not declare it can answer"
            )
        );
        assert!(unanswerable_input(&result, &json!({})).is_some());

        let roots = json!({ "inputRequests": { "r": { "method": "roots/list" } } });
        assert_eq!(unanswerable_input(&roots, &json!({ "roots": {} })), None);
        assert!(unanswerable_input(&roots, &json!({ "sampling": {} })).is_some());
    }

    #[test]
    fn an_elicitation_needs_the_mode_it_asks_in() {
        let asking = |mode: Option<&str>| {
            let mut params = json!({ "message": "m" });
            if let Some(mode) = mode {
                params["mode"] = json!(mode);
            }
            json!({ "inputRequests": { "e": { "method": "elicitation/create", "params": params } } })
        };
        let (form, url, unsaid) = (asking(Some("form")), asking(Some("url")), asking(None));
        // An empty `elicitation` means forms.
        for declared in [
            json!({}),
            json!({ "form": {} }),
            json!({ "form": {}, "url": {} }),
        ] {
            let capabilities = json!({ "elicitation": declared });
            assert_eq!(
                unanswerable_input(&form, &capabilities),
                None,
                "{capabilities}"
            );
            assert_eq!(
                unanswerable_input(&unsaid, &capabilities),
                None,
                "{capabilities}"
            );
        }
        assert_eq!(
            unanswerable_input(&url, &json!({ "elicitation": {} })).as_deref(),
            Some(
                "its input request 'e' is `elicitation/create` in URL mode, which the client \
                 did not declare it can answer"
            )
        );
        assert!(unanswerable_input(&url, &json!({ "elicitation": { "form": {} } })).is_some());
        assert_eq!(
            unanswerable_input(&url, &json!({ "elicitation": { "url": {} } })),
            None
        );
        // Declared URL mode alone takes no forms.
        let only_url = json!({ "elicitation": { "url": {} } });
        assert!(unanswerable_input(&form, &only_url).is_some());
    }

    #[test]
    fn an_interim_result_the_revision_does_not_allow_cannot_be_answered() {
        let any = json!({ "elicitation": { "form": {}, "url": {} }, "sampling": {}, "roots": {} });
        let why = |result: Value| unanswerable_input(&result, &any);
        // State alone asks the client to try again, as a busy server may.
        assert_eq!(
            why(json!({ "resultType": "input_required", "requestState": "s" })),
            None
        );
        assert_eq!(
            why(json!({ "resultType": "input_required" })).as_deref(),
            Some("it holds neither `inputRequests` nor `requestState`")
        );
        assert_eq!(
            why(json!({ "requestState": 7 })).as_deref(),
            Some("its `requestState` is not a string")
        );
        assert_eq!(
            why(json!({ "inputRequests": ["elicitation/create"] })).as_deref(),
            Some("its `inputRequests` is not an object")
        );
        assert_eq!(
            why(json!({ "inputRequests": { "p": { "method": "ping" } } })).as_deref(),
            Some("its input request 'p' is `ping`, which no server may send")
        );
        assert_eq!(
            why(json!({ "inputRequests": { "n": { "params": {} } } })).as_deref(),
            Some("its input request 'n' names no method")
        );
    }

    // ------------------------------------------------------------ x-mcp-header

    /// The revision's `execute_sql` example, as a schema.
    fn execute_sql_schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "region": {
                    "type": "string",
                    "description": "The region to execute the query in",
                    "x-mcp-header": "Region"
                },
                "query": { "type": "string", "description": "The SQL query to execute" }
            },
            "required": ["region", "query"]
        })
    }

    /// A modern `tools/call` of `execute_sql` with `arguments`.
    fn execute_sql(arguments: Value) -> Message {
        let mut m = spec_tools_call();
        let params = m.params.as_mut().unwrap();
        params["name"] = json!("execute_sql");
        params["arguments"] = arguments;
        m
    }

    /// The revision's own worked example, field for field.
    #[test]
    fn the_specs_x_mcp_header_example_reads_back_exactly() {
        let found = param_headers(&execute_sql_schema()).unwrap();
        assert_eq!(
            found,
            vec![ParamHeader {
                // The annotation's value, not the property's name.
                name: "Region".into(),
                path: vec!["region".into()],
            }]
        );
        assert_eq!(found[0].header_name(), "mcp-param-region");

        let call = execute_sql(json!({ "region": "us-west1", "query": "SELECT * FROM users" }));
        assert_eq!(
            param_header_values(&call, &found),
            vec![("mcp-param-region".to_string(), "us-west1".to_string())]
        );
    }

    /// Nested object properties are allowed, as long as every step is `properties`.
    #[test]
    fn a_nested_properties_chain_is_statically_reachable() {
        let schema = json!({
            "type": "object",
            "properties": { "outer": { "type": "object", "properties": {
                "inner": { "type": "integer", "x-mcp-header": "Inner" }
            }}}
        });
        let found = param_headers(&schema).unwrap();
        assert_eq!(found[0].path, ["outer", "inner"]);
        let args = json!({ "outer": { "inner": 42 } });
        let v = found[0].value_in(&args).unwrap();
        assert_eq!(ParamHeader::wire_value(v).unwrap(), "42");
    }

    /// Every keyword the revision names as breaking the chain, each on its own.
    /// The tool is refused, not stripped of the annotation.
    #[test]
    fn an_annotation_off_the_properties_chain_invalidates_the_tool() {
        let x = || json!({ "type": "string", "x-mcp-header": "X" });
        let cases = [
            (
                "items",
                json!({ "properties": { "xs": { "type": "array", "items": x() } } }),
            ),
            ("prefixItems", json!({ "prefixItems": [x()] })),
            ("oneOf", json!({ "oneOf": [x()] })),
            ("anyOf", json!({ "anyOf": [x()] })),
            ("allOf", json!({ "allOf": [x()] })),
            ("not", json!({ "not": x() })),
            ("if", json!({ "if": x() })),
            ("then", json!({ "then": x() })),
            ("else", json!({ "else": x() })),
            ("$defs", json!({ "$defs": { "d": x() } })),
            (
                "additionalProperties",
                json!({ "additionalProperties": x() }),
            ),
            (
                "patternProperties",
                json!({ "patternProperties": { "^a": x() } }),
            ),
            // A `properties` chain *below* a broken link is still broken: it
            // has to be unbroken from the root, not merely end well.
            (
                "properties under items",
                json!({ "properties": { "xs": {
                    "type": "array", "items": { "type": "object", "properties": {
                        "p": x() } } } } }),
            ),
            // The root is the arguments object, not a parameter in it.
            ("the root", json!({ "type": "string", "x-mcp-header": "X" })),
        ];
        for (keyword, schema) in cases {
            let e = param_headers(&schema).unwrap_err();
            assert!(
                matches!(e, SchemaError::NotStaticallyReachable { .. }),
                "an annotation under `{keyword}` must invalidate the tool, got: {e}"
            );
        }
    }

    /// `x-mcp-header` inside an example, a default or an enum value is data,
    /// not an annotation, and so is a property of that name in
    /// `dependentRequired`: those keywords hold data, not schemas.
    #[test]
    fn an_x_mcp_header_key_in_instance_data_is_not_an_annotation() {
        let data = json!({ "x-mcp-header": "line\nbreak" });
        for keyword in ["const", "default", "enum", "examples", "dependentRequired"] {
            let value = match keyword {
                "enum" | "examples" => json!([data]),
                _ => data.clone(),
            };
            let schema = json!({ "type": "object", "properties": {
                "p": { "type": "object", keyword: value } } });
            assert_eq!(param_headers(&schema), Ok(vec![]), "under `{keyword}`");
        }
    }

    /// A name in a map of subschemas is a key: a definition or a pattern
    /// called `x-mcp-header` is not an annotation. One inside them still is.
    #[test]
    fn a_subschema_named_x_mcp_header_is_not_an_annotation() {
        let named = json!({ "type": "object" });
        for keyword in [
            "$defs",
            "definitions",
            "patternProperties",
            "dependentSchemas",
        ] {
            let schema = json!({ "type": "object", keyword: { "x-mcp-header": named } });
            assert_eq!(param_headers(&schema), Ok(vec![]), "under `{keyword}`");
            let inside = json!({ keyword: { "d": { "type": "string", "x-mcp-header": "X" } } });
            assert!(
                matches!(
                    param_headers(&inside),
                    Err(SchemaError::NotStaticallyReachable { .. })
                ),
                "inside `{keyword}`"
            );
        }
    }

    /// `number` is refused by name; so is anything not known to be primitive.
    #[test]
    fn only_string_integer_and_boolean_may_be_mirrored() {
        for ok in ["string", "integer", "boolean"] {
            let schema = json!({ "properties": { "p": { "type": ok, "x-mcp-header": "P" } } });
            assert!(param_headers(&schema).is_ok(), "{ok} must be allowed");
            // A list of one type is that type.
            let schema = json!({ "properties": { "p": { "type": [ok], "x-mcp-header": "P" } } });
            assert!(param_headers(&schema).is_ok(), "[{ok}] must be allowed");
        }
        for refused in [
            json!({ "type": "number", "x-mcp-header": "P" }),
            json!({ "type": "object", "x-mcp-header": "P" }),
            json!({ "type": ["string", "null"], "x-mcp-header": "P" }),
            json!({ "x-mcp-header": "P" }),
        ] {
            let schema = json!({ "properties": { "p": refused } });
            assert!(
                matches!(
                    param_headers(&schema),
                    Err(SchemaError::NotPrimitive { .. })
                ),
                "{schema} must be refused"
            );
        }
    }

    /// A CR or LF in the name is why this check is not advisory: MCPdef puts
    /// these on requests it sends.
    #[test]
    fn a_name_that_is_not_an_http_token_is_refused() {
        for bad in [
            json!(""),
            json!("has space"),
            json!("new\nline"),
            json!("carriage\rreturn"),
            json!("colon:"),
            json!("quote\""),
            json!("ünïcode"),
            json!(7),
            json!(null),
        ] {
            let schema =
                json!({ "properties": { "p": { "type": "string", "x-mcp-header": bad } } });
            let e = param_headers(&schema).unwrap_err();
            assert!(
                matches!(
                    e,
                    SchemaError::NotAName { .. } | SchemaError::NotAToken { .. }
                ),
                "{bad} must be refused, got: {e}"
            );
        }
    }

    /// Unique ignoring case, because the headers they become are compared that way.
    #[test]
    fn two_annotations_differing_only_in_case_are_refused() {
        let schema = json!({ "properties": {
            "a": { "type": "string", "x-mcp-header": "Region" },
            "b": { "type": "string", "x-mcp-header": "region" }
        }});
        assert!(matches!(
            param_headers(&schema),
            Err(SchemaError::Duplicate { .. })
        ));
    }

    /// A schema with no annotations, the common case, is not an error.
    #[test]
    fn an_unannotated_schema_yields_nothing() {
        let schema = json!({ "type": "object", "properties": { "q": { "type": "string" } } });
        assert_eq!(param_headers(&schema), Ok(vec![]));
        assert_eq!(param_headers(&json!({ "type": "object" })), Ok(vec![]));
        assert_eq!(param_headers(&json!(true)), Ok(vec![]));
    }

    /// The revision's type conversion, including the booleans it lower-cases.
    #[test]
    fn wire_values_convert_the_way_the_revision_says() {
        let v = |value: Value| ParamHeader::wire_value(&value);
        assert_eq!(v(json!("us-west1")).unwrap(), "us-west1");
        assert_eq!(v(json!(42)).unwrap(), "42");
        assert_eq!(v(json!(-7)).unwrap(), "-7");
        assert_eq!(v(json!(true)).unwrap(), "true");
        assert_eq!(v(json!(false)).unwrap(), "false");
        // An integral number is the integer it is.
        assert_eq!(v(json!(42.0)).unwrap(), "42");
        // A fractional one says what the body does; the upstream's schema
        // check is what refuses it.
        assert_eq!(v(json!(1.5)).unwrap(), "1.5");
        assert_eq!(v(json!({ "a": 1 })), None);
        assert_eq!(v(json!([1])), None);
    }

    /// Absent and `null` omit the header; a value that cannot sit in a header
    /// as it is goes in the sentinel; a legacy request or another method
    /// carries none at all.
    #[test]
    fn mirroring_omits_what_is_absent_and_encodes_what_must_be() {
        let found = param_headers(&execute_sql_schema()).unwrap();
        assert_eq!(
            param_header_values(&execute_sql(json!({ "query": "q" })), &found),
            vec![]
        );
        assert_eq!(
            param_header_values(&execute_sql(json!({ "region": null })), &found),
            vec![]
        );
        assert_eq!(
            param_header_values(&execute_sql(json!({ "region": "亞太-1" })), &found),
            vec![(
                "mcp-param-region".to_string(),
                encode_header_value("亞太-1").into_owned()
            )]
        );

        let mut legacy = execute_sql(json!({ "region": "us-west1" }));
        strip_modern_meta(&mut legacy);
        assert_eq!(param_header_values(&legacy, &found), vec![]);

        let mut read = execute_sql(json!({ "region": "us-west1" }));
        read.method = Some(method::PROMPTS_GET.into());
        assert_eq!(param_header_values(&read, &found), vec![]);
    }

    /// Whatever is mirrored validates: the two halves of the rule agree.
    #[test]
    fn what_mirroring_sends_validation_accepts() {
        let found = param_headers(&execute_sql_schema()).unwrap();
        // An object or an array breaks the tool's schema, and sends no
        // header: validation takes it for no value, as mirroring does.
        for region in [
            json!("us-west1"),
            json!(" padded "),
            json!("=?base64?x?="),
            json!(""),
            json!(42),
            json!(true),
            json!({ "k": 1 }),
            json!([1, 2]),
        ] {
            let call = execute_sql(json!({ "region": region }));
            let sent = param_header_values(&call, &found);
            let pairs: Vec<(&str, &str)> =
                sent.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            assert_eq!(
                validate_param_headers(&call, from(&pairs), &found),
                Ok(()),
                "{region}"
            );
        }
    }

    /// Each way a recognized header and the body can disagree is refused, as
    /// `400` + `-32020`.
    #[test]
    fn a_param_header_that_disagrees_with_the_body_is_refused() {
        let found = param_headers(&execute_sql_schema()).unwrap();
        let with = execute_sql(json!({ "region": "us-west1" }));
        let without = execute_sql(json!({ "query": "q" }));
        let refused = |msg: &Message, pairs: &[(&str, &str)]| {
            let e = validate_param_headers(msg, from(pairs), &found).unwrap_err();
            assert_eq!(
                (e.code(), e.http_status()),
                (error_code::HEADER_MISMATCH, 400)
            );
            e.to_string()
        };
        // It disagrees.
        let e = refused(&with, &[("Mcp-Param-Region", "eu-central1")]);
        assert!(e.contains("eu-central1") && e.contains("us-west1"), "{e}");
        // The body carries it and no header does.
        let e = refused(&with, &[]);
        assert!(e.contains("mcp-param-region"), "{e}");
        // The header claims what the body does not carry.
        let e = refused(&without, &[("mcp-param-region", "us-west1")]);
        assert!(e.contains("carries no"), "{e}");
        // Characters a header value cannot carry.
        let e = refused(&with, &[("mcp-param-region", "us-west1\n")]);
        assert!(e.contains("cannot carry"), "{e}");
        // A sentinel that does not decode.
        refused(&with, &[("mcp-param-region", "=?base64?%%%?=")]);
        // A header beside a value no header can carry.
        let e = refused(
            &execute_sql(json!({ "region": { "k": 1 } })),
            &[("mcp-param-region", "{}")],
        );
        assert!(e.contains("a header can carry"), "{e}");
    }

    /// Agreement, the "omit" state, an unrecognized header, a sentinel and a
    /// number written another way are all accepted.
    #[test]
    fn a_param_header_that_agrees_with_the_body_is_accepted() {
        let found = param_headers(&execute_sql_schema()).unwrap();
        let ok = |msg: &Message, pairs: &[(&str, &str)]| {
            assert_eq!(validate_param_headers(msg, from(pairs), &found), Ok(()));
        };
        ok(
            &execute_sql(json!({ "region": "us-west1" })),
            &[("MCP-PARAM-REGION", "us-west1")],
        );
        ok(&execute_sql(json!({ "query": "q" })), &[]);
        ok(&execute_sql(json!({ "region": null })), &[]);
        // Forwarded and otherwise ignored, per the revision.
        ok(
            &execute_sql(json!({ "region": "us-west1" })),
            &[
                ("mcp-param-region", "us-west1"),
                ("mcp-param-tenant", "acme"),
            ],
        );
        let encoded = encode_header_value("亞太-1").into_owned();
        ok(
            &execute_sql(json!({ "region": "亞太-1" })),
            &[("mcp-param-region", encoded.as_str())],
        );
        // Nothing to check against: no annotations.
        assert_eq!(
            validate_param_headers(&execute_sql(json!({ "region": "x" })), from(&[]), &[]),
            Ok(())
        );
    }

    /// Integers compare as numbers, as the revision advises: `42.0` and `42`
    /// agree. Two integers past a double's precision do not.
    #[test]
    fn an_integer_header_is_compared_as_a_number() {
        let found = param_headers(&json!({ "properties": {
            "n": { "type": "integer", "x-mcp-header": "N" },
            "b": { "type": "boolean", "x-mcp-header": "B" } } }))
        .unwrap();
        let check = |args: Value, pairs: &[(&str, &str)]| {
            validate_param_headers(&execute_sql(args), from(pairs), &found)
        };
        assert_eq!(check(json!({ "n": 42 }), &[("mcp-param-n", "42")]), Ok(()));
        assert_eq!(
            check(json!({ "n": 42 }), &[("mcp-param-n", "42.0")]),
            Ok(())
        );
        assert_eq!(
            check(json!({ "n": 42.0 }), &[("mcp-param-n", "42")]),
            Ok(())
        );
        assert!(check(json!({ "n": 42 }), &[("mcp-param-n", "43")]).is_err());
        assert!(check(json!({ "n": 42 }), &[("mcp-param-n", "forty-two")]).is_err());
        assert!(check(
            json!({ "n": 9_007_199_254_740_993_u64 }),
            &[("mcp-param-n", "9007199254740992")]
        )
        .is_err());
        // Nor written as a double, which holds neither exactly.
        assert!(check(
            json!({ "n": 9_007_199_254_740_993_u64 }),
            &[("mcp-param-n", "9007199254740992.0")]
        )
        .is_err());
        assert_eq!(
            check(json!({ "n": -7 }), &[("mcp-param-n", "-7.0")]),
            Ok(())
        );
        assert_eq!(
            check(json!({ "b": true }), &[("mcp-param-b", "true")]),
            Ok(())
        );
        // Values are case-sensitive, a boolean's too.
        assert!(check(json!({ "b": true }), &[("mcp-param-b", "True")]).is_err());
    }
}
