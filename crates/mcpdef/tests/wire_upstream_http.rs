// SPDX-License-Identifier: Apache-2.0
//! `spec = "auto"` against an upstream reached over **HTTP**.
//!
//! This is the case the knob used to refuse by name. The reason was real: an
//! `HttpClient`'s first send also selects its *binding* — Streamable HTTP versus
//! the deprecated 2024-11-05 HTTP+SSE bridge — and that negotiation is one-shot.
//! An era probe that sent `server/discover` first would consume it.
//!
//! Probing with `initialize` dissolves the conflict rather than working around
//! it. It is the only message legal-first in every era, and its *absence* is
//! what defines the modern one, so the probe **is** the opening request. Each
//! test below is one row of that argument, against a server that behaves the way
//! the row claims:
//!
//! | Upstream | Answers `initialize` | Binding | Era |
//! |---|---|---|---|
//! | 2026-07-28 Streamable | `404` + `-32601` | Streamable | modern |
//! | 2025-11-25 Streamable | `200` + a result | Streamable | legacy |
//! | 2024-11-05 SSE bridge | `404`, no MCP body | bridge | legacy |
//! | down / unauthorized | `503` | — | neither: say so |
//!
//! The modern stand-in refuses any request arriving without its own `_meta`, or
//! with mirrored headers that are missing or disagree with it, so a passing test
//! here is evidence MCPdef really sent what the revision asks for rather than
//! evidence the mock was lenient.

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use futures_util::{stream, Stream, StreamExt};
use mcpdef::Gateway;
use mcpdef_audit::Ledger;
use mcpdef_core::wire::{
    error_code, header, meta_key, validate_headers, SpecSetting, SPEC_2025_11_25, SPEC_2026_07_28,
};
use mcpdef_core::{method, Id, Message};
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_transport::HttpClient;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

// ---------------------------------------------------------------- the upstreams

/// A 2026-07-28 server: no `initialize`, `server/discover` implemented, and
/// every request required to carry its own `_meta` and the mirrored headers
/// that agree with it.
async fn modern(headers: HeaderMap, body: String) -> Response {
    let Ok(msg) = Message::from_json_line(&body) else {
        return (StatusCode::BAD_REQUEST, "not JSON-RPC").into_response();
    };
    let Some(id) = msg.id.clone() else {
        return StatusCode::ACCEPTED.into_response();
    };

    // The `_meta` gate, before anything else — the point of the mock.
    let declared = msg
        .params
        .as_ref()
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(meta_key::PROTOCOL_VERSION))
        .and_then(Value::as_str);
    match declared {
        Some(SPEC_2026_07_28) => {}
        // A bare `initialize` reaches here: no handshake exists to have carried
        // a version, which is exactly why refusing it proves the era.
        _ => {
            return json_rpc(
                StatusCode::BAD_REQUEST,
                Message::error(
                    id,
                    error_code::HEADER_MISMATCH,
                    "every request must carry its own protocolVersion",
                ),
            )
        }
    }

    // Then the mirrored headers, which a 2026-07-28 server MUST check against
    // the body — so a pass is evidence MCPdef sent them, and sent them right,
    // rather than only stamping the body.
    if let Err(e) = validate_headers(
        &msg,
        |name| headers.get(name).and_then(|v| v.to_str().ok()),
        &[SPEC_2026_07_28],
    ) {
        return json_rpc(StatusCode::BAD_REQUEST, e.to_message(Some(id)));
    }

    match msg.method() {
        Some(method::INITIALIZE) => json_rpc(
            StatusCode::NOT_FOUND,
            Message::error(
                id,
                error_code::METHOD_NOT_FOUND,
                format!("this server speaks {SPEC_2026_07_28}, which has no `initialize`"),
            ),
        ),
        Some(method::SERVER_DISCOVER) => json_rpc(
            StatusCode::OK,
            Message::result(
                id,
                json!({
                    "resultType": "complete",
                    "supportedVersions": [SPEC_2026_07_28],
                    "capabilities": { "tools": {} },
                }),
            ),
        ),
        Some(method::TOOLS_LIST) => json_rpc(
            StatusCode::OK,
            Message::result(id, json!({ "tools": [{ "name": "echo_v2" }] })),
        ),
        Some(method::TOOLS_CALL) => json_rpc(
            StatusCode::OK,
            Message::result(
                id,
                json!({ "content": [{ "type": "text", "text": "v2" }], "isError": false }),
            ),
        ),
        _ => json_rpc(
            StatusCode::NOT_FOUND,
            Message::error(id, error_code::METHOD_NOT_FOUND, "no such method"),
        ),
    }
}

/// A 2025-11-25 server over Streamable HTTP: the handshake exists, and an
/// unknown method is a `-32601` in a `200` body, the way that revision does it.
async fn legacy_streamable(body: String) -> Response {
    legacy_streamable_settling_on(SPEC_2025_11_25, body).await
}

/// The same server, answering `initialize` with `version`. That need not be the
/// revision the client asked for: the server's answer is what the handshake
/// settles on.
async fn legacy_streamable_settling_on(version: &str, body: String) -> Response {
    let Ok(msg) = Message::from_json_line(&body) else {
        return (StatusCode::BAD_REQUEST, "not JSON-RPC").into_response();
    };
    match (msg.method(), msg.id.clone()) {
        (Some(method::INITIALIZED), _) | (_, None) => StatusCode::ACCEPTED.into_response(),
        (Some(method::INITIALIZE), Some(id)) => json_rpc(
            StatusCode::OK,
            Message::result(
                id,
                json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "mock", "version": "0" }
                }),
            ),
        ),
        (Some(method::TOOLS_LIST), Some(id)) => json_rpc(
            StatusCode::OK,
            Message::result(id, json!({ "tools": [{ "name": "echo" }] })),
        ),
        (Some(method::TOOLS_CALL), Some(id)) => json_rpc(
            StatusCode::OK,
            Message::result(
                id,
                json!({ "content": [{ "type": "text", "text": "v1" }], "isError": false }),
            ),
        ),
        (_, Some(id)) => json_rpc(
            StatusCode::OK,
            Message::error(id, error_code::METHOD_NOT_FOUND, "no such method"),
        ),
    }
}

/// The session the `/session` stand-in hands out.
const SESSION: &str = "mcpdef-test-session";

/// A 2025-11-25 Streamable server that hands out a session on `initialize` and
/// refuses any later request that does not bring it back: `400` without one,
/// `404` with another, as that revision has it.
async fn with_session(headers: HeaderMap, body: String) -> Response {
    let opening =
        Message::from_json_line(&body).is_ok_and(|m| m.method() == Some(method::INITIALIZE));
    if opening {
        let mut r = legacy_streamable(body).await;
        r.headers_mut()
            .insert("mcp-session-id", HeaderValue::from_static(SESSION));
        return r;
    }
    match headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        None => StatusCode::BAD_REQUEST.into_response(),
        Some(SESSION) => legacy_streamable(body).await,
        Some(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

fn json_rpc(status: StatusCode, msg: Message) -> Response {
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        msg.to_json_line(),
    )
        .into_response()
}

#[derive(Clone)]
struct Bridge {
    tx: tokio::sync::broadcast::Sender<String>,
}

/// The 2024-11-05 bridge's `GET`: an SSE stream that names the POST URL in its
/// first `endpoint` event, then stays open to carry replies.
async fn bridge_sse(
    State(st): State<Arc<Bridge>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = tokio_stream::wrappers::BroadcastStream::new(st.tx.subscribe());
    let first = stream::once(async { Ok(Event::default().event("endpoint").data("/bridge/post")) });
    Sse::new(first.chain(
        rx.filter_map(|m| async move { m.ok().map(|data| Ok(Event::default().data(data))) }),
    ))
}

/// The 2024-11-05 bridge's POST: accept, answer over the stream.
async fn bridge_post(State(st): State<Arc<Bridge>>, body: String) -> Response {
    if let Ok(msg) = Message::from_json_line(&body) {
        // Same logic as the Streamable 2025-11-25 server, delivered the other way.
        let reply = match (msg.method(), msg.id.clone()) {
            (Some(method::INITIALIZE), Some(id)) => Some(Message::result(
                id,
                json!({
                    "protocolVersion": SPEC_2025_11_25,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "bridge", "version": "0" }
                }),
            )),
            (Some(method::TOOLS_LIST), Some(id)) => Some(Message::result(
                id,
                json!({ "tools": [{ "name": "echo" }] }),
            )),
            (Some(method::TOOLS_CALL), Some(id)) => Some(Message::result(
                id,
                json!({ "content": [{ "type": "text", "text": "bridged" }], "isError": false }),
            )),
            _ => None,
        };
        if let Some(reply) = reply {
            let _ = st.tx.send(reply.to_json_line());
        }
    }
    StatusCode::ACCEPTED.into_response()
}

/// Start every stand-in on one ephemeral loopback port; returns the base URL.
async fn upstreams() -> String {
    let (tx, _) = tokio::sync::broadcast::channel(16);
    let app = Router::new()
        .route("/modern", post(modern))
        .route("/v1", post(legacy_streamable))
        .route("/session", post(with_session))
        // A POST to the bridge's SSE URL is what a framework 404s with HTML —
        // no MCP body at all, which is what says "this is not a Streamable
        // endpoint" and sends the client to the bridge.
        .route(
            "/bridge/sse",
            get(bridge_sse).post(|| async {
                (
                    StatusCode::NOT_FOUND,
                    [(axum::http::header::CONTENT_TYPE, "text/html")],
                    "<!DOCTYPE html><html><body>Cannot POST /bridge/sse</body></html>",
                )
                    .into_response()
            }),
        )
        .route("/bridge/post", post(bridge_post))
        .route("/down", post(|| async { StatusCode::SERVICE_UNAVAILABLE }))
        // Accepts the connection and then says nothing, ever — the shape a
        // wedged or half-deployed upstream actually has.
        .route(
            "/silent",
            post(|| async {
                std::future::pending::<()>().await;
                StatusCode::OK
            })
            .get(|| async {
                std::future::pending::<()>().await;
                StatusCode::OK
            }),
        )
        .with_state(Arc::new(Bridge { tx }));

    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}")
}

/// A header that exists only on the 2026-07-28 wire. `MCP-Protocol-Version` is
/// not one: 2025-11-25 defines it too, for every request after `initialize`.
fn modern_only(name: &str) -> bool {
    name == header::METHOD || name == header::NAME || name.starts_with(header::PARAM_PREFIX)
}

/// One POST as a recording upstream received it.
struct Received {
    method: Option<String>,
    /// Every [`modern_only`] header it came with, as `(name, value)`.
    modern_headers: Vec<(String, String)>,
    /// The `MCP-Protocol-Version` header, if one came.
    protocol_version: Option<String>,
    /// The body's `params._meta`, if it had one.
    meta: Option<Value>,
}

/// The 2025-11-25 stand-in on its own port, settling `initialize` on
/// `settles_on` and keeping a record of every POST.
///
/// A 2025-11-25 server ignores headers it does not know, so whether MCPdef sent
/// one cannot be read off whether the call worked — only by looking.
async fn recording_legacy_upstream(
    settles_on: &'static str,
) -> (String, Arc<Mutex<Vec<Received>>>) {
    let received: Arc<Mutex<Vec<Received>>> = Arc::default();
    let log = Arc::clone(&received);
    let app = Router::new().route(
        "/mcp",
        post(move |headers: HeaderMap, body: String| {
            let log = Arc::clone(&log);
            async move {
                let msg = Message::from_json_line(&body).ok();
                let seen = Received {
                    method: msg.as_ref().and_then(|m| m.method().map(str::to_string)),
                    modern_headers: headers
                        .iter()
                        .filter(|(name, _)| modern_only(name.as_str()))
                        .map(|(name, value)| {
                            let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
                            (name.as_str().to_string(), value)
                        })
                        .collect(),
                    protocol_version: headers
                        .get(header::PROTOCOL_VERSION)
                        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned()),
                    meta: msg
                        .as_ref()
                        .and_then(|m| m.params.as_ref())
                        .and_then(|p| p.get("_meta"))
                        .cloned(),
                };
                log.lock().unwrap().push(seen);
                legacy_streamable_settling_on(settles_on, body).await
            }
        }),
    );

    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (format!("http://{addr}/mcp"), received)
}

// ---------------------------------------------------------------- the harness

fn gateway(dir: &tempfile::TempDir) -> Gateway {
    let mut p = Policy::new();
    for (server, safe) in [("remote", "echo"), ("remote", "echo_v2")] {
        p.insert(
            server,
            ServerPolicy {
                allow_tools: Some(vec![safe.into(), "echo".into(), "echo_v2".into()]),
                deny: vec![],
            },
        );
    }
    let ledger = Ledger::open(dir.path().join("audit.log")).unwrap();
    Gateway::new(p, ledger, "agent:test")
}

fn streamable(url: String) -> Box<HttpClient> {
    Box::new(HttpClient::streamable(url).unwrap())
}

async fn call(gw: &mut Gateway, id: i64, tool: &str) -> Value {
    let req = Message::request(
        Id::Num(id),
        method::TOOLS_CALL,
        Some(json!({ "name": tool, "arguments": { "msg": "hi" } })),
    );
    gw.handle(req).await.unwrap().unwrap().result.unwrap()
}

// ---------------------------------------------------------------- the cases

/// Row 1: a 2026-07-28 Streamable upstream, reached with `auto` over HTTP.
///
/// The probe's `initialize` is refused the way only a modern server refuses it,
/// which settles both questions at once — the binding is Streamable (the JSON-RPC
/// body proves the endpoint exists) and the era is modern. The upstream then
/// rejects any request without `_meta` or with headers that disagree with it, so
/// a green assertion here is evidence MCPdef stamped and mirrored every one.
#[tokio::test]
async fn auto_reaches_a_modern_upstream_over_http() {
    let base = upstreams().await;
    let dir = tempfile::tempdir().unwrap();
    let mut gw = gateway(&dir);

    gw.add_upstream_speaking(
        "remote",
        streamable(format!("{base}/modern")),
        SpecSetting::Auto,
    )
    .await
    .expect("`auto` must resolve a modern Streamable upstream");

    assert_eq!(call(&mut gw, 1, "echo_v2").await["isError"], false);
}

/// Row 2: a 2025-11-25 Streamable upstream.
///
/// The probe's `initialize` is *answered*, so the era is legacy — and the
/// handshake is already done. That reply has to travel forward rather than be
/// re-sent: a second `initialize` on an initialized session is an error in this
/// revision's implementations.
#[tokio::test]
async fn auto_reaches_a_legacy_streamable_upstream_over_http() {
    let base = upstreams().await;
    let dir = tempfile::tempdir().unwrap();
    let mut gw = gateway(&dir);

    gw.add_upstream_speaking(
        "remote",
        streamable(format!("{base}/v1")),
        SpecSetting::Auto,
    )
    .await
    .expect("`auto` must resolve a 2025-11-25 Streamable upstream");

    assert_eq!(call(&mut gw, 1, "echo").await["isError"], false);
}

/// A session handed out at the opening is carried on every call after it,
/// which since calls post concurrently means from a shared session rather than
/// one owned by a single task.
#[tokio::test]
async fn a_streamable_session_is_carried_on_every_call() {
    let base = upstreams().await;
    let dir = tempfile::tempdir().unwrap();
    let mut gw = gateway(&dir);

    gw.add_upstream_speaking(
        "remote",
        streamable(format!("{base}/session")),
        SpecSetting::Auto,
    )
    .await
    .expect("the opening sets up the session");

    for id in 1..=3 {
        assert_eq!(call(&mut gw, id, "echo").await["isError"], false);
    }
}

/// Row 3: the 2024-11-05 HTTP+SSE bridge — the case the restriction was about.
///
/// The probe POSTs `initialize` to the SSE URL, gets a framework `404` with no
/// MCP body, and that is what sends `HttpClient` to the bridge: `GET`, read the
/// `endpoint` event, re-POST there. One message resolved the binding *and* the
/// era, and the message it sent was `initialize` — legal first for this
/// revision, which `server/discover` would not have been.
#[tokio::test]
async fn auto_reaches_a_2024_sse_bridge_over_http() {
    let base = upstreams().await;
    let dir = tempfile::tempdir().unwrap();
    let mut gw = gateway(&dir);

    gw.add_upstream_speaking(
        "remote",
        streamable(format!("{base}/bridge/sse")),
        SpecSetting::Auto,
    )
    .await
    .expect("`auto` must fall back to the 2024-11-05 bridge and open it");

    assert_eq!(call(&mut gw, 1, "echo").await["isError"], false);
}

/// Row 4: an upstream that is simply down.
///
/// `503` is neither era. It used to become `State::Failed` inside the transport
/// and then, one send later, a bare `Closed` — the operator told their upstream
/// was shut when what happened was a `503`. The probe reports the status it got.
#[tokio::test]
async fn auto_reports_the_status_when_an_http_upstream_is_not_answering() {
    let base = upstreams().await;
    let dir = tempfile::tempdir().unwrap();
    let mut gw = gateway(&dir);

    let e = gw
        .add_upstream_speaking(
            "remote",
            streamable(format!("{base}/down")),
            SpecSetting::Auto,
        )
        .await
        .expect_err("a 503 is not an era");
    // The whole chain, which is what an operator sees: `main` prints the error
    // with anyhow's `{:?}`, so a cause is not lost the way `{}` alone loses it.
    let chain = format!("{e:#}");

    assert!(
        chain.contains("503"),
        "the operator must be told what the upstream actually said: {chain}"
    );
    assert!(
        chain.contains("initialize"),
        "and which request got it: {chain}"
    );
}

/// `transport = "sse"` + `spec = "auto"`: a combination the config only started
/// accepting with this change, so it gets evidence rather than an assumption.
///
/// Here the binding is *pinned* by the operator — `HttpKind::Legacy` skips the
/// Streamable attempt entirely and opens the bridge directly — so only the era
/// is in question. The probe's `initialize` rides the bridge like any other
/// request and is answered over the stream.
#[tokio::test]
async fn auto_resolves_the_era_on_a_transport_pinned_to_the_2024_bridge() {
    let base = upstreams().await;
    let dir = tempfile::tempdir().unwrap();
    let mut gw = gateway(&dir);

    let sse = Box::new(HttpClient::legacy_sse(format!("{base}/bridge/sse")).unwrap());
    gw.add_upstream_speaking("remote", sse, SpecSetting::Auto)
        .await
        .expect("`auto` must resolve the era on a transport already pinned to the bridge");

    assert_eq!(call(&mut gw, 1, "echo").await["isError"], false);
}

/// And the exit condition, over HTTP: one gateway, both eras, neither pinned.
#[tokio::test]
async fn auto_fronts_both_http_eras_at_once_without_being_told_which_is_which() {
    let base = upstreams().await;
    let dir = tempfile::tempdir().unwrap();
    let mut p = Policy::new();
    for id in ["old", "new"] {
        p.insert(
            id,
            ServerPolicy {
                allow_tools: Some(vec!["echo".into(), "echo_v2".into()]),
                deny: vec![],
            },
        );
    }
    let ledger = Ledger::open(dir.path().join("audit.log")).unwrap();
    let mut gw = Gateway::new(p, ledger, "agent:test");

    gw.add_upstream_speaking("old", streamable(format!("{base}/v1")), SpecSetting::Auto)
        .await
        .unwrap();
    gw.add_upstream_speaking(
        "new",
        streamable(format!("{base}/modern")),
        SpecSetting::Auto,
    )
    .await
    .unwrap();

    assert_eq!(call(&mut gw, 1, "echo").await["isError"], false);
    assert_eq!(call(&mut gw, 2, "echo_v2").await["isError"], false);
}

/// What a 2025-11-25 upstream is sent in the headers, looked at directly.
///
/// `Mcp-Method`, `Mcp-Name` and `Mcp-Param-*` belong to the 2026-07-28 wire,
/// where the server checks them against the body — the check that makes them
/// safe to act on. A 2025-11-25 upstream has no such check, so it is sent none of
/// them: not on the opening, the handshake's notification, the tool list or a
/// call, whether its `spec` is pinned or probed. Sent anyway, they are
/// unvalidated claims about the body, which is the shape the revision tells a
/// policy-enforcing intermediary to reject.
///
/// That holds for a call relayed from a 2026-07-28 client too. It arrives with
/// the client's own revision, identity and capabilities in `_meta`, and passed
/// on as-is it would be mirrored into all three headers — including
/// `MCP-Protocol-Version: 2026-07-28`, which a 2025-11-25 server must refuse.
/// So the upstream gets it without them, and with the rest of its `_meta`.
#[tokio::test]
async fn a_legacy_streamable_upstream_is_sent_no_mirrored_headers() {
    let modern_keys = [
        meta_key::PROTOCOL_VERSION,
        meta_key::CLIENT_INFO,
        meta_key::CLIENT_CAPABILITIES,
    ];
    for spec in [SpecSetting::V20251125, SpecSetting::Auto] {
        let (url, received) = recording_legacy_upstream(SPEC_2025_11_25).await;
        let dir = tempfile::tempdir().unwrap();
        let mut gw = gateway(&dir);

        gw.add_upstream_speaking("remote", streamable(url), spec)
            .await
            .unwrap_or_else(|e| panic!("{spec:?}: {e:#}"));
        assert_eq!(call(&mut gw, 1, "echo").await["isError"], false);

        // The same call from a 2026-07-28 client, as the listener hands it over.
        let relayed = Message::request(
            Id::Num(2),
            method::TOOLS_CALL,
            Some(json!({
                "name": "echo",
                "arguments": { "msg": "hi" },
                "_meta": {
                    meta_key::PROTOCOL_VERSION: SPEC_2026_07_28,
                    meta_key::CLIENT_INFO: { "name": "modern-client", "version": "1" },
                    meta_key::CLIENT_CAPABILITIES: {},
                    "progressToken": 7,
                },
            })),
        );
        let reply = gw.handle(relayed).await.unwrap().unwrap();
        assert_eq!(reply.result.unwrap()["isError"], false, "{spec:?}");

        let received = received.lock().unwrap();
        // Every kind of request the opening and a call send, so the checks below
        // cannot pass by looking at nothing.
        let methods: Vec<_> = received
            .iter()
            .filter_map(|r| r.method.as_deref())
            .collect();
        for sent in [
            method::INITIALIZE,
            method::INITIALIZED,
            method::TOOLS_LIST,
            method::TOOLS_CALL,
        ] {
            assert!(
                methods.contains(&sent),
                "{spec:?}: expected a {sent} POST, saw {methods:?}"
            );
        }
        for r in received.iter() {
            assert!(
                r.modern_headers.is_empty(),
                "{spec:?}: a 2025-11-25 upstream was sent {:?} with {:?}",
                r.modern_headers,
                r.method
            );
            assert_ne!(
                r.protocol_version.as_deref(),
                Some(SPEC_2026_07_28),
                "{spec:?}: a 2025-11-25 upstream was told it speaks 2026-07-28 on {:?}",
                r.method
            );
            for key in modern_keys {
                assert!(
                    r.meta.as_ref().and_then(|m| m.get(key)).is_none(),
                    "{spec:?}: a 2025-11-25 upstream was sent `_meta.{key}` on {:?}",
                    r.method
                );
            }
        }
        // Only those keys go: the relayed call keeps the rest of its `_meta`.
        let last = received.last().expect("the relayed call was received");
        assert_eq!(last.method.as_deref(), Some(method::TOOLS_CALL));
        assert_eq!(last.meta, Some(json!({ "progressToken": 7 })), "{spec:?}");
    }
}

/// What 2025-11-25 does require of a client over HTTP: every request after
/// `initialize` carries `MCP-Protocol-Version`, set to the revision the
/// handshake settled on. Without it, that revision tells the server to assume
/// `2025-03-26` unless it can identify the version some other way.
///
/// The stand-in settles on `2025-06-18`, not the `2025-11-25` MCPdef asks for,
/// so a pass is evidence the header carries the server's answer rather than
/// MCPdef's own request. `initialize` itself carries none: nothing has been
/// negotiated yet.
#[tokio::test]
async fn a_legacy_streamable_upstream_is_sent_the_negotiated_protocol_version() {
    const SETTLED: &str = "2025-06-18";
    for spec in [SpecSetting::V20251125, SpecSetting::Auto] {
        let (url, received) = recording_legacy_upstream(SETTLED).await;
        let dir = tempfile::tempdir().unwrap();
        let mut gw = gateway(&dir);

        gw.add_upstream_speaking("remote", streamable(url), spec)
            .await
            .unwrap_or_else(|e| panic!("{spec:?}: {e:#}"));
        assert_eq!(call(&mut gw, 1, "echo").await["isError"], false);

        let received = received.lock().unwrap();
        let (opening, later) = received.split_first().expect("the upstream was reached");
        assert_eq!(
            opening.method.as_deref(),
            Some(method::INITIALIZE),
            "{spec:?}"
        );
        assert_eq!(
            opening.protocol_version, None,
            "{spec:?}: `initialize` has nothing negotiated to send yet"
        );
        // The rest of the opening and a call, so the check below cannot pass by
        // looking at nothing.
        let methods: Vec<_> = later.iter().filter_map(|r| r.method.as_deref()).collect();
        for sent in [method::INITIALIZED, method::TOOLS_LIST, method::TOOLS_CALL] {
            assert!(
                methods.contains(&sent),
                "{spec:?}: expected a {sent} POST, saw {methods:?}"
            );
        }
        for r in later {
            assert_eq!(
                r.protocol_version.as_deref(),
                Some(SETTLED),
                "{spec:?}: {:?} went without the negotiated revision",
                r.method
            );
        }
    }
}

/// An HTTP upstream that accepts the connection and never answers must not hang
/// startup — the probe's own five-second bound is what `docs/WIRE.md` promises.
///
/// The bound has to cover the **send**, not just the wait for a reply. On stdio
/// a send is a pipe write; on HTTP it is where the silence actually lands, since
/// the first send is what POSTs and, on a bodyless 400/404/405, then waits for
/// the SSE `endpoint` event. Neither carries a deadline of its own, so bounding
/// only the receive promises a five-second probe and delivers a hang.
#[tokio::test]
async fn a_silent_http_upstream_cannot_hang_startup() {
    let base = upstreams().await;
    let dir = tempfile::tempdir().unwrap();
    let mut gw = gateway(&dir);

    // Generously more than the probe's bound, so a pass means the probe
    // returned on its own rather than this deadline masking a hang.
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        gw.add_upstream_speaking(
            "remote",
            streamable(format!("{base}/silent")),
            SpecSetting::Auto,
        ),
    )
    .await;

    let e = outcome
        .expect("the probe must give up on its own, not hang startup")
        .expect_err("a silent upstream has no era")
        .to_string();
    assert!(e.contains("initialize"), "name the request: {e}");
}
