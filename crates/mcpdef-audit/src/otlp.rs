// SPDX-License-Identifier: Apache-2.0
//! The ledger's records as OpenTelemetry spans, in OTLP/JSON.
//!
//! [`request`] makes an `ExportTraceServiceRequest`: the body an OTLP/HTTP
//! receiver takes at `/v1/traces` with `Content-Type: application/json`, and,
//! one per line, what the OTLP file exporter writes and the Collector's
//! `otlpjsonfile` receiver reads.
//!
//! Each governed request is one span, named and described as the
//! OpenTelemetry semantic conventions for MCP describe a server's span
//! (`{mcp.method.name} {target}`, kind `SERVER`, `gen_ai.operation.name =
//! execute_tool` on a tool call), with MCPdef's own members under `mcpdef.`.
//! The span is made from the record alone, so the same ledger always gives
//! the same spans, with the same ids:
//!
//! - **The trace:** the one the caller's `traceparent` named, when the record
//!   keeps one, under the caller's span. Without one, a trace of its own.
//! - **The span's id:** from the record's hash, so a span sent twice, once as
//!   the gateway wrote it and once from an export of the ledger, is one span.
//!
//! The records the gateway writes of itself are no agent's request, and
//! become no span: [`span`] gives `None` for one of another `kind` than a call
//! (`admin`, `reload`, `upstream`), or whose `agent` is the gateway's own,
//! such as a finding at an upstream's connection.

use crate::{Kind, Record};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

/// The instrumentation scope every span is under.
pub const SCOPE: &str = "mcpdef";

/// The `service.name` spans carry when the gateway is given none.
pub const SERVICE: &str = "mcpdef";

/// The method of a tool call: its span is a tool's execution.
const TOOLS_CALL: &str = "tools/call";

/// The method whose `tool` member names a prompt.
const PROMPTS_GET: &str = "prompts/get";

/// The rule a call to a tool no server lists is refused under. The name in
/// such a call is the caller's to choose, so it is kept out of the span's name.
const UNKNOWN_TOOL: &str = "unknown-tool";

/// `records` as one `ExportTraceServiceRequest`, each that is a governed
/// request as a span of the service named `service`. `None` when none is.
pub fn request<'r>(records: impl IntoIterator<Item = &'r Record>, service: &str) -> Option<Value> {
    let spans: Vec<Value> = records.into_iter().filter_map(span).collect();
    if spans.is_empty() {
        return None;
    }
    Some(json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    string("service.name", service),
                    string("service.version", env!("CARGO_PKG_VERSION")),
                ],
            },
            "scopeSpans": [{
                "scope": { "name": SCOPE, "version": env!("CARGO_PKG_VERSION") },
                "spans": spans,
            }],
        }],
    }))
}

/// The span `rec` is: `None` for a record the gateway wrote of itself, which
/// no agent's request made.
pub fn span(rec: &Record) -> Option<Value> {
    let call = rec.kind.as_deref().is_none_or(|k| k == Kind::Call.as_str());
    if !call || rec.agent == crate::GATEWAY_AGENT {
        return None;
    }
    let method = rec.method.as_deref().unwrap_or_default();
    let ids = Ids::of(rec);
    let end = rec.ts_unix_ms.saturating_mul(1_000_000);
    let start = rec
        .ts_unix_ms
        .saturating_sub(rec.latency_ms)
        .saturating_mul(1_000_000);

    let mut attributes = Vec::new();
    if !method.is_empty() {
        attributes.push(string("mcp.method.name", method));
    }
    let target = match (method, rec.tool.as_deref()) {
        (TOOLS_CALL, tool) => {
            attributes.push(string("gen_ai.operation.name", "execute_tool"));
            if let Some(tool) = tool {
                attributes.push(string("gen_ai.tool.name", tool));
            }
            tool.filter(|_| rec.rule.as_deref() != Some(UNKNOWN_TOOL))
        }
        (PROMPTS_GET, Some(prompt)) => {
            attributes.push(string("gen_ai.prompt.name", prompt));
            Some(prompt)
        }
        _ => None,
    };
    if let Some(uri) = &rec.uri {
        attributes.push(string("mcp.resource.uri", uri));
    }
    let denied = rec.decision == "deny";
    if denied {
        attributes.push(string(
            "error.type",
            rec.rule.as_deref().unwrap_or("denied"),
        ));
    }
    if let Some(peer) = &rec.peer {
        match crate::parse_peer(peer) {
            Some((ip, port)) => {
                attributes.push(string("client.address", &ip.to_string()));
                if let Some(port) = port {
                    attributes.push(int("client.port", port.into()));
                }
            }
            None => attributes.push(string("client.address", peer)),
        }
    }
    attributes.push(string("mcpdef.agent", &rec.agent));
    attributes.push(string("mcpdef.server", &rec.server));
    attributes.push(string("mcpdef.decision", &rec.decision));
    if let Some(rule) = &rec.rule {
        attributes.push(string("mcpdef.rule", rule));
    }
    attributes.push(int("mcpdef.seq", rec.seq.try_into().unwrap_or(i64::MAX)));
    if let Some(digest) = &rec.tool_digest {
        attributes.push(string("mcpdef.tool_digest", digest));
    }
    if let Some(actor) = &rec.actor {
        attributes.push(string("mcpdef.actor", actor));
    }
    if let Some(hook) = &rec.hook {
        attributes.push(string("mcpdef.hook", hook));
    }
    if let Some(transforms) = &rec.transforms {
        attributes.push(strings("mcpdef.transforms", transforms));
    }

    let name = match target {
        Some(target) if !method.is_empty() => format!("{method} {target}"),
        _ if !method.is_empty() => method.to_string(),
        _ => "mcpdef".to_string(),
    };
    let mut span = json!({
        "traceId": ids.trace,
        "spanId": ids.span,
        "name": name,
        // SPAN_KIND_SERVER: the gateway serves the request a client sent it.
        "kind": 2,
        "startTimeUnixNano": start.to_string(),
        "endTimeUnixNano": end.to_string(),
        "attributes": attributes,
    });
    if let Some(parent) = ids.parent {
        span["parentSpanId"] = Value::String(parent);
    }
    if denied {
        // STATUS_CODE_ERROR, described by the rule that refused it: the
        // reason is free text the ledger does not keep.
        span["status"] = json!({
            "code": 2,
            "message": rec.rule.as_deref().unwrap_or("denied"),
        });
    }
    Some(span)
}

/// A span's trace, its own id and its parent's, as OTLP/JSON writes them:
/// lowercase hex.
struct Ids {
    trace: String,
    span: String,
    parent: Option<String>,
}

impl Ids {
    /// The caller's trace and span when the record names a valid one, and an
    /// id of the span's own from the record's hash. A record with no trace,
    /// or one that does not read, is a trace of its own, from the same hash.
    fn of(rec: &Record) -> Ids {
        let derived = Sha256::digest(rec.hash.as_bytes());
        let span = hex::encode(&derived[16..24]);
        match rec.trace_id.as_deref().filter(|id| is_id(id, 32)) {
            Some(trace) => Ids {
                trace: trace.to_string(),
                span,
                parent: rec
                    .parent_id
                    .as_deref()
                    .filter(|id| is_id(id, 16))
                    .map(str::to_string),
            },
            None => Ids {
                trace: hex::encode(&derived[..16]),
                span,
                parent: None,
            },
        }
    }
}

/// Whether `id` is a W3C trace or span id of `len` characters: lowercase hex,
/// not all zeros, which the specification makes invalid.
pub fn is_id(id: &str, len: usize) -> bool {
    id.len() == len
        && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        && id.bytes().any(|b| b != b'0')
}

/// What a W3C `traceparent` names: its trace and the caller's span, or `None`
/// for one that does not read, which the specification says to ignore.
///
/// Version `00` is exactly four fields. A later version may add fields after
/// them, and is read for the four it starts with; `ff` is never valid.
pub fn traceparent(value: &str) -> Option<(String, String)> {
    let mut fields = value.trim().splitn(5, '-');
    let version = fields.next()?;
    let trace = fields.next()?;
    let parent = fields.next()?;
    let flags = fields.next()?;
    let rest = fields.next();
    let hex = |s: &str, len: usize| {
        s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    let readable = hex(version, 2)
        && version != "ff"
        && (version != "00" || rest.is_none())
        && hex(flags, 2)
        && is_id(trace, 32)
        && is_id(parent, 16);
    readable.then(|| (trace.to_string(), parent.to_string()))
}

fn string(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}

/// An integer attribute. OTLP/JSON writes a 64-bit integer as a decimal
/// string, as the protobuf JSON mapping does.
fn int(key: &str, value: i64) -> Value {
    json!({ "key": key, "value": { "intValue": value.to_string() } })
}

fn strings(key: &str, values: &[String]) -> Value {
    let values: Vec<Value> = values.iter().map(|v| json!({ "stringValue": v })).collect();
    json!({ "key": key, "value": { "arrayValue": { "values": values } } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Attrs, Entry, Ledger};
    use mcpdef_core::Decision;

    fn call(tool: &str, decision: Decision, attrs: Attrs) -> Entry {
        Entry {
            agent: "sub:alice".into(),
            server: "github".into(),
            method: Some(TOOLS_CALL.into()),
            tool: Some(tool.into()),
            decision,
            latency_ms: 12,
            attrs,
        }
    }

    fn written(entries: Vec<Entry>) -> Vec<Record> {
        let dir = tempfile::tempdir().unwrap();
        let mut led = Ledger::open(dir.path().join("audit.log")).unwrap();
        entries
            .into_iter()
            .map(|e| led.append(e).unwrap())
            .collect()
    }

    fn attr<'v>(span: &'v Value, key: &str) -> Option<&'v Value> {
        span["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["key"] == key)
            .map(|a| &a["value"])
    }

    const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const PARENT: &str = "00f067aa0ba902b7";

    #[test]
    fn an_allowed_tool_call_is_a_server_span_in_its_callers_trace() {
        let recs = written(vec![call(
            "list_issues",
            Decision::Allow,
            Attrs {
                trace_id: Some(TRACE.into()),
                parent_id: Some(PARENT.into()),
                tool_digest: Some(format!("sha256:{}", "ab".repeat(32))),
                peer: Some("10.1.2.80:65123".into()),
                ..Attrs::default()
            },
        )]);
        let span = span(&recs[0]).unwrap();
        assert_eq!(span["name"], "tools/call list_issues");
        assert_eq!(span["kind"], 2);
        assert_eq!(span["traceId"], TRACE);
        assert_eq!(span["parentSpanId"], PARENT);
        assert!(is_id(span["spanId"].as_str().unwrap(), 16));
        assert!(
            span.get("status").is_none(),
            "an allowed call is left unset"
        );
        let end: u64 = span["endTimeUnixNano"].as_str().unwrap().parse().unwrap();
        let start: u64 = span["startTimeUnixNano"].as_str().unwrap().parse().unwrap();
        assert_eq!(end, recs[0].ts_unix_ms * 1_000_000);
        assert_eq!(end - start, 12_000_000, "the call's latency");
        assert_eq!(
            attr(&span, "mcp.method.name").unwrap()["stringValue"],
            "tools/call"
        );
        assert_eq!(
            attr(&span, "gen_ai.operation.name").unwrap()["stringValue"],
            "execute_tool"
        );
        assert_eq!(
            attr(&span, "gen_ai.tool.name").unwrap()["stringValue"],
            "list_issues"
        );
        assert_eq!(
            attr(&span, "client.address").unwrap()["stringValue"],
            "10.1.2.80"
        );
        assert_eq!(attr(&span, "client.port").unwrap()["intValue"], "65123");
        assert_eq!(
            attr(&span, "mcpdef.server").unwrap()["stringValue"],
            "github"
        );
        assert_eq!(
            attr(&span, "mcpdef.decision").unwrap()["stringValue"],
            "allow"
        );
        assert_eq!(attr(&span, "mcpdef.seq").unwrap()["intValue"], "0");
        assert!(attr(&span, "mcpdef.tool_digest").unwrap()["stringValue"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert!(attr(&span, "error.type").is_none());
    }

    #[test]
    fn a_refused_call_is_an_error_named_by_its_rule() {
        let deny = Decision::Deny {
            rule: "tools.deny".into(),
            reason: "not on the list".into(),
        };
        let recs = written(vec![call("delete_repo", deny, Attrs::default())]);
        let span = span(&recs[0]).unwrap();
        assert_eq!(span["status"]["code"], 2);
        assert_eq!(span["status"]["message"], "tools.deny");
        assert_eq!(
            attr(&span, "error.type").unwrap()["stringValue"],
            "tools.deny"
        );
        assert_eq!(
            attr(&span, "mcpdef.rule").unwrap()["stringValue"],
            "tools.deny"
        );
        let text = span.to_string();
        assert!(!text.contains("not on the list"), "the reason is not kept");
    }

    #[test]
    fn a_made_up_tool_name_stays_out_of_the_spans_name() {
        let deny = Decision::Deny {
            rule: UNKNOWN_TOOL.into(),
            reason: String::new(),
        };
        let recs = written(vec![call("x-1f9a", deny, Attrs::default())]);
        let span = span(&recs[0]).unwrap();
        assert_eq!(span["name"], "tools/call");
        assert_eq!(
            attr(&span, "gen_ai.tool.name").unwrap()["stringValue"],
            "x-1f9a"
        );
    }

    #[test]
    fn a_record_with_no_trace_is_a_trace_of_its_own_and_the_same_every_time() {
        let recs = written(vec![
            call("a", Decision::Allow, Attrs::default()),
            call(
                "b",
                Decision::Allow,
                Attrs {
                    // Not a trace: all zeros.
                    trace_id: Some("0".repeat(32)),
                    parent_id: Some(PARENT.into()),
                    ..Attrs::default()
                },
            ),
        ]);
        let (a, b) = (span(&recs[0]).unwrap(), span(&recs[1]).unwrap());
        for s in [&a, &b] {
            assert!(is_id(s["traceId"].as_str().unwrap(), 32));
            assert!(s.get("parentSpanId").is_none());
        }
        assert_ne!(a["traceId"], b["traceId"]);
        assert_ne!(a["spanId"], b["spanId"]);
        assert_eq!(span(&recs[0]).unwrap(), a, "a function of the record");
    }

    #[test]
    fn other_requests_name_their_method_and_target() {
        let mut read = call("x", Decision::Allow, Attrs::default());
        (read.method, read.tool) = (Some("resources/read".into()), None);
        read.attrs.uri = Some("file:///srv/docs/a.md".into());
        let mut prompt = call("review", Decision::Allow, Attrs::default());
        prompt.method = Some(PROMPTS_GET.into());
        let recs = written(vec![read, prompt]);

        let read = span(&recs[0]).unwrap();
        assert_eq!(read["name"], "resources/read");
        assert_eq!(
            attr(&read, "mcp.resource.uri").unwrap()["stringValue"],
            "file:///srv/docs/a.md"
        );
        assert!(attr(&read, "gen_ai.operation.name").is_none());

        let prompt = span(&recs[1]).unwrap();
        assert_eq!(prompt["name"], "prompts/get review");
        assert_eq!(
            attr(&prompt, "gen_ai.prompt.name").unwrap()["stringValue"],
            "review"
        );
    }

    #[test]
    fn the_gateways_own_records_are_no_span() {
        let mut admin = call("x", Decision::Allow, Attrs::default());
        admin.attrs.kind = Kind::Admin;
        let mut reload = call("x", Decision::Allow, Attrs::default());
        reload.attrs.kind = Kind::Reload;
        // A finding at an upstream's connection: a call by its kind, but the
        // gateway's own.
        let finding = Decision::Deny {
            rule: "injection".into(),
            reason: String::new(),
        };
        let mut finding = call("poisoned", finding, Attrs::default());
        finding.agent = crate::GATEWAY_AGENT.into();
        finding.method = Some("connect".into());
        let recs = written(vec![admin, reload, finding]);
        assert!(recs.iter().all(|r| span(r).is_none()));
        assert!(request(&recs, SERVICE).is_none());
    }

    #[test]
    fn a_request_holds_the_resource_and_scope_once() {
        let recs = written(vec![
            call("a", Decision::Allow, Attrs::default()),
            call("b", Decision::Allow, Attrs::default()),
        ]);
        let body = request(&recs, "gateway-eu").unwrap();
        let rs = &body["resourceSpans"][0];
        assert_eq!(
            rs["resource"]["attributes"][0],
            json!({ "key": "service.name", "value": { "stringValue": "gateway-eu" } })
        );
        assert_eq!(rs["scopeSpans"][0]["scope"]["name"], SCOPE);
        assert_eq!(rs["scopeSpans"][0]["spans"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn a_traceparent_reads_as_the_w3c_specification_says() {
        let tp = format!("00-{TRACE}-{PARENT}-01");
        assert_eq!(traceparent(&tp), Some((TRACE.into(), PARENT.into())));
        // A later version is read for the fields it starts with.
        assert_eq!(
            traceparent(&format!("01-{TRACE}-{PARENT}-00-more")),
            Some((TRACE.into(), PARENT.into()))
        );
        let refused = [
            format!("00-{TRACE}-{PARENT}-01-more"),
            format!("ff-{TRACE}-{PARENT}-01"),
            format!("00-{}-{PARENT}-01", "0".repeat(32)),
            format!("00-{TRACE}-{}-01", "0".repeat(16)),
            format!("00-{}-{PARENT}-01", TRACE.to_uppercase()),
            format!("00-{TRACE}-{PARENT}"),
            format!("00-{TRACE}-{PARENT}-1"),
            String::new(),
        ];
        for tp in refused {
            assert_eq!(traceparent(&tp), None, "{tp}");
        }
    }
}
