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
//! shapes the revision defines. Not here, deliberately: `Mcp-Param-{Name}`
//! validation, which needs the upstream tool's `inputSchema` to know which
//! parameters are annotated with `x-mcp-header`, and therefore belongs with the
//! gateway's tool cache rather than with the envelope. This module is the seam
//! both ends are built on: the listener validates incoming requests against it,
//! and the upstream connector stamps outgoing ones with it.
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
pub fn mirrored_headers(msg: &Message) -> Vec<(&'static str, String)> {
    let mut out = Vec::with_capacity(3);
    if let Some(v) = protocol_version(msg) {
        out.push((header::PROTOCOL_VERSION, v.to_string()));
    }
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
/// speak for. Declaring someone else's would be a claim it cannot keep.
///
/// Idempotent. Re-stamping replaces the fields rather than nesting them.
///
/// Only *requests* are stamped. The revision requires this metadata on every
/// request and says nothing about notifications — it defines no client-to-server
/// notification over Streamable HTTP at all, and the one that exists on stdio,
/// `notifications/cancelled`, carries no version. Stamping one would be
/// inventing a rule, and handing a peer a `_meta` it has no reason to expect.
pub fn stamp_request(msg: &mut Message, version: &str, client: &Value) {
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
        Value::Object(Default::default()),
    );
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
}
