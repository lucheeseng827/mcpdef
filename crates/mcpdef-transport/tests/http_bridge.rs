// SPDX-License-Identifier: Apache-2.0
//! HTTP transport integration tests (ROADMAP Phase 1 Streamable HTTP + Phase 1.5
//! legacy HTTP+SSE bridge). A small axum app mocks both wire formats so we can
//! exercise `HttpClient` end-to-end: modern request/response, the legacy
//! GET-SSE → `endpoint` → POST flow, the dual-transport probe that falls back to
//! legacy on a 405, and `Last-Event-ID` resumption across a dropped stream.

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use futures_util::{stream, Stream, StreamExt};
use mcpdef_core::{Id, Message};
use mcpdef_transport::{HttpClient, Transport};
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;

#[derive(Clone)]
struct AppState {
    tx: tokio::sync::broadcast::Sender<String>,
    seq: Arc<AtomicU64>,
}

/// The MCP server logic shared by both wire formats: echoes the request id and
/// exposes `echo` + `delete_repo` tools (matching the stdio mock).
fn respond(req: &Message) -> Option<Message> {
    let id = req.id.clone();
    match req.method() {
        Some("initialize") => Some(Message::result(
            id?,
            serde_json::json!({
                "protocolVersion": "2025-11-25",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mock", "version": "0" }
            }),
        )),
        Some("notifications/initialized") => None,
        Some("tools/list") => Some(Message::result(
            id?,
            serde_json::json!({ "tools": [{ "name": "echo" }, { "name": "delete_repo" }] }),
        )),
        Some("tools/call") => {
            let name = req.tool_name().unwrap_or_default();
            Some(Message::result(
                id?,
                serde_json::json!({
                    "content": [{ "type": "text", "text": name }],
                    "isError": false
                }),
            ))
        }
        Some("ping") => Some(Message::result(id?, serde_json::json!({}))),
        _ => id.map(|i| Message::error(i, -32601, "method not found")),
    }
}

fn notif(n: u64) -> String {
    format!(r#"{{"jsonrpc":"2.0","method":"notifications/message","params":{{"n":{n}}}}}"#)
}

// ── Streamable HTTP (modern): POST returns a single JSON response ──
async fn modern_mcp(body: String) -> Response {
    let Ok(msg) = Message::from_json_line(body.trim()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match respond(&msg) {
        Some(resp) => {
            let mut r = (
                [(header::CONTENT_TYPE, "application/json")],
                resp.to_json_line(),
            )
                .into_response();
            if msg.method() == Some("initialize") {
                r.headers_mut()
                    .insert("mcp-session-id", HeaderValue::from_static("sess-123"));
            }
            r
        }
        None => StatusCode::ACCEPTED.into_response(),
    }
}

// ── Legacy HTTP+SSE: GET opens the stream and emits `endpoint`, then forwards
//    broadcast messages; POST publishes the response onto the broadcast. ──
async fn legacy_sse(
    State(st): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = st.tx.subscribe();
    let seq = st.seq.clone();
    let endpoint =
        stream::once(async { Ok(Event::default().event("endpoint").data("/legacy/messages")) });
    let messages = BroadcastStream::new(rx).map(move |item| {
        let payload = item.unwrap_or_default();
        let id = seq.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(Event::default()
            .event("message")
            .id(id.to_string())
            .data(payload))
    });
    Sse::new(endpoint.chain(messages))
}

async fn legacy_post(State(st): State<AppState>, body: String) -> StatusCode {
    if let Ok(msg) = Message::from_json_line(body.trim()) {
        if let Some(resp) = respond(&msg) {
            let _ = st.tx.send(resp.to_json_line());
        }
    }
    StatusCode::ACCEPTED
}

// ── Resumption probe: first GET emits one message then closes; the reconnect
//    (carrying Last-Event-ID) emits the next message. ──
async fn resume_sse(headers: HeaderMap) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let leid = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let mut evs: Vec<Result<Event, Infallible>> = vec![Ok(Event::default()
        .event("endpoint")
        .data("/resume/messages"))];
    match leid.as_deref() {
        None => evs.push(Ok(Event::default().event("message").id("1").data(notif(1)))),
        Some("1") => evs.push(Ok(Event::default().event("message").id("2").data(notif(2)))),
        _ => {}
    }
    Sse::new(stream::iter(evs))
}

fn build_app() -> Router {
    let (tx, _rx) = tokio::sync::broadcast::channel::<String>(64);
    let state = AppState {
        tx,
        seq: Arc::new(AtomicU64::new(0)),
    };
    Router::new()
        .route("/mcp", post(modern_mcp))
        .route("/legacy", get(legacy_sse))
        .route("/legacy/messages", post(legacy_post))
        // The same legacy bridge, but answering an unexpected POST the way a
        // real framework does rather than the way axum's router does: a body,
        // and not a JSON one. Express sends exactly this for `Cannot POST /sse`.
        // A modern (2026-07-28) endpoint: it answers `initialize` normally, and
        // answers anything else the way the revision requires — `404` carrying a
        // JSON-RPC `-32601`. One route exercises both the opening probe and a
        // request sent after the wire is resolved.
        .route(
            "/modern-404",
            post(|body: String| async move {
                let msg = Message::from_json_line(body.trim()).ok();
                let id = msg
                    .as_ref()
                    .and_then(|m| m.id.clone())
                    .unwrap_or(Id::Num(0));
                match msg.as_ref().and_then(|m| m.method()) {
                    Some("initialize") => (
                        StatusCode::OK,
                        Message::result(
                            id,
                            serde_json::json!({
                                "protocolVersion": "2026-07-28",
                                "capabilities": { "tools": {} },
                                "serverInfo": { "name": "mock", "version": "0" }
                            }),
                        )
                        .to_json_line(),
                    ),
                    _ => (
                        StatusCode::NOT_FOUND,
                        Message::error(id, -32601, "no such method here").to_json_line(),
                    ),
                }
            }),
        )
        // One that refuses even the opening request, with a modern error body.
        .route(
            "/modern-refuses",
            post(|body: String| async move {
                let id = Message::from_json_line(body.trim())
                    .ok()
                    .and_then(|m| m.id)
                    .unwrap_or(Id::Num(0));
                let mut err = Message::error(id, -32022, "unsupported protocol version");
                err.error.as_mut().unwrap()["data"] =
                    serde_json::json!({ "supported": ["2026-07-28"] });
                (StatusCode::BAD_REQUEST, err.to_json_line())
            }),
        )
        .route(
            "/framework",
            get(legacy_sse).post(|| async {
                (
                    StatusCode::NOT_FOUND,
                    "<!DOCTYPE html>\n<html><body>Cannot POST /framework</body></html>",
                )
            }),
        )
        .route("/resume", get(resume_sse))
        .route("/resume/messages", post(|| async { StatusCode::ACCEPTED }))
        .with_state(state)
}

async fn spawn_app() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, build_app()).await.unwrap();
    });
    format!("http://{addr}")
}

async fn recv_msg(c: &mut HttpClient) -> Message {
    tokio::time::timeout(Duration::from_secs(5), c.recv())
        .await
        .expect("recv timed out")
        .expect("transport error")
        .expect("stream closed unexpectedly")
}

fn init() -> Message {
    Message::request(
        Id::Num(1),
        "initialize",
        Some(serde_json::json!({ "clientInfo": { "name": "t" } })),
    )
}

#[tokio::test]
async fn streamable_http_request_response() {
    let base = spawn_app().await;
    let mut c = HttpClient::streamable(format!("{base}/mcp")).unwrap();

    c.send(init()).await.unwrap();
    let resp = recv_msg(&mut c).await;
    assert!(resp.is_response());
    assert_eq!(resp.result.unwrap()["serverInfo"]["name"], "mock");

    c.send(Message::notification("notifications/initialized", None))
        .await
        .unwrap();
    c.send(Message::request(
        Id::Num(2),
        "tools/call",
        Some(serde_json::json!({ "name": "echo", "arguments": { "x": 1 } })),
    ))
    .await
    .unwrap();
    let r = recv_msg(&mut c).await;
    assert_eq!(r.id, Some(Id::Num(2)));
    assert_eq!(r.result.unwrap()["isError"], serde_json::json!(false));
}

#[tokio::test]
async fn legacy_sse_bridge_request_response() {
    let base = spawn_app().await;
    let mut c = HttpClient::legacy_sse(format!("{base}/legacy")).unwrap();

    // send() connects the SSE stream, reads `endpoint`, and POSTs the request;
    // the response arrives back over the held-open SSE stream.
    c.send(init()).await.unwrap();
    let resp = recv_msg(&mut c).await;
    assert!(resp.is_response());
    assert_eq!(resp.result.unwrap()["serverInfo"]["name"], "mock");
}

#[tokio::test]
async fn streamable_probe_falls_back_to_legacy() {
    let base = spawn_app().await;
    // Point the *streamable* client at the legacy endpoint: the POST probe gets a
    // 405, so it must fall back to the GET-SSE legacy bridge automatically.
    let mut c = HttpClient::streamable(format!("{base}/legacy")).unwrap();

    c.send(init()).await.unwrap();
    let resp = recv_msg(&mut c).await;
    assert!(
        resp.is_response(),
        "fallback should deliver the response via the legacy SSE stream"
    );
    assert_eq!(resp.result.unwrap()["serverInfo"]["name"], "mock");
}

/// The same fallback, against a server that answers the probe with a body.
///
/// `streamable_probe_falls_back_to_legacy` above gets axum's own `405`, which
/// carries nothing — so it passed even while the fallback was broken for real
/// servers. A framework-generated `404` or `405` carries HTML, and decoding that
/// strictly returned `Err` from the probe before the fallback branch was ever
/// reached. The body of an error status is only interesting when it is JSON-RPC.
#[tokio::test]
async fn streamable_probe_falls_back_when_the_error_page_is_not_json() {
    let base = spawn_app().await;
    let mut c = HttpClient::streamable(format!("{base}/framework")).unwrap();

    c.send(init()).await.unwrap();
    let resp = recv_msg(&mut c).await;
    assert!(
        resp.is_response(),
        "an HTML error page must not stop the legacy fallback"
    );
    assert_eq!(resp.result.unwrap()["serverInfo"]["name"], "mock");
}

#[tokio::test]
async fn legacy_sse_resumes_with_last_event_id() {
    let base = spawn_app().await;
    let mut c = HttpClient::legacy_sse(format!("{base}/resume")).unwrap();

    // First send connects (endpoint + message id:1, then the server closes).
    c.send(init()).await.unwrap();
    let m1 = recv_msg(&mut c).await;
    assert_eq!(m1.params.unwrap()["n"], serde_json::json!(1));

    // The reader reconnects with Last-Event-ID:1; the server replays message id:2.
    let m2 = recv_msg(&mut c).await;
    assert_eq!(m2.params.unwrap()["n"], serde_json::json!(2));

    // After id:2 the server replays nothing on further reconnects; the reader
    // exhausts its bounded retries and surfaces a terminal signal rather than
    // blocking recv() forever.
    let terminal = tokio::time::timeout(Duration::from_secs(5), c.recv())
        .await
        .expect("third recv timed out — give-up must not hang");
    assert!(
        matches!(terminal, Err(_) | Ok(None)),
        "expected a terminal close after retries, got {terminal:?}"
    );
}

// ── SSRF / egress guard (end-to-end through HttpClient::send) ────────────────

use mcpdef_transport::{EgressPolicy, TransportError};

#[tokio::test]
async fn ssrf_blocks_cloud_metadata_upstream() {
    // The single highest-value SSRF target is always blocked, before any connect,
    // even under the permissive default policy.
    let mut c = HttpClient::streamable("http://169.254.169.254/mcp").unwrap();
    let err = c.send(init()).await.unwrap_err();
    assert!(
        matches!(err, TransportError::Egress(_)),
        "metadata upstream must be blocked, got {err:?}"
    );
}

#[tokio::test]
async fn ssrf_blocks_plaintext_public_upstream() {
    // A public IP over plain HTTP leaks creds — refused by default.
    let mut c = HttpClient::streamable("http://8.8.8.8/mcp").unwrap();
    let err = c.send(init()).await.unwrap_err();
    assert!(matches!(err, TransportError::Egress(_)), "got {err:?}");
}

#[tokio::test]
async fn ssrf_hardened_policy_blocks_loopback_upstream() {
    // A real loopback mock is up, but the hardened policy refuses private/loopback
    // destinations — so the guard, not the server, terminates the call.
    let base = spawn_app().await;
    let mut c = HttpClient::streamable(format!("{base}/mcp"))
        .unwrap()
        .with_egress(EgressPolicy::hardened());
    let err = c.send(init()).await.unwrap_err();
    assert!(
        matches!(err, TransportError::Egress(_)),
        "hardened policy must block loopback, got {err:?}"
    );
}

#[tokio::test]
async fn default_policy_allows_loopback_upstream() {
    // The default policy permits loopback so MCPdef can front local MCP servers —
    // this is the same flow the other tests rely on, asserted explicitly.
    let base = spawn_app().await;
    let mut c = HttpClient::streamable(format!("{base}/mcp")).unwrap();
    assert!(c.send(init()).await.is_ok());
}

/// A modern upstream's JSON-RPC error is the answer to the request, not a
/// transport failure.
///
/// The revision has a modern server return `404` with a `-32601` body for a
/// method it does not implement, and `400` with `-32022` or `-32020` for an
/// unsupported version or a header mismatch. Dropping those bodies for a
/// `TransportError` means the gateway can only report "gateway error", and the
/// reason the upstream stated never reaches whoever could act on it.
#[tokio::test]
async fn a_modern_error_body_reaches_the_caller_instead_of_a_transport_failure() {
    let base = spawn_app().await;
    let mut c = HttpClient::streamable(format!("{base}/modern-404")).unwrap();

    // The opening request succeeds, so the wire resolves to Streamable HTTP.
    c.send(init()).await.unwrap();
    let resp = recv_msg(&mut c).await;
    assert_eq!(resp.result.unwrap()["serverInfo"]["name"], "mock");

    // A later method the upstream does not implement: `404` + `-32601`. That is
    // its answer, and it has to survive the hop.
    c.send(Message::request(Id::Num(2), "prompts/list", None))
        .await
        .expect("a 404 carrying JSON-RPC is an answer, not a send failure");
    let resp = recv_msg(&mut c).await;
    assert!(resp.is_response(), "got: {resp:?}");
    assert_eq!(
        resp.error.as_ref().and_then(|e| e["code"].as_i64()),
        Some(-32601),
        "the upstream's own error must survive the hop: {resp:?}"
    );
}

/// The same, on the *opening* request. An error only a modern server produces
/// settles the transport question — it is a Streamable-HTTP endpoint that did
/// not like this request — so the client is left able to retry with a version
/// the upstream named, rather than holding a failed transport.
#[tokio::test]
async fn a_probe_refused_with_a_modern_error_resolves_rather_than_failing() {
    let base = spawn_app().await;
    let mut c = HttpClient::streamable(format!("{base}/modern-refuses")).unwrap();

    c.send(init())
        .await
        .expect("a modern refusal is an answer, not a dead transport");
    let resp = recv_msg(&mut c).await;

    assert_eq!(
        resp.error.as_ref().and_then(|e| e["code"].as_i64()),
        Some(-32022)
    );
    assert_eq!(
        resp.error.as_ref().unwrap()["data"]["supported"],
        serde_json::json!(["2026-07-28"]),
        "the versions it does serve are the useful half: {resp:?}"
    );
}
