// SPDX-License-Identifier: Apache-2.0
//! The concurrent Streamable-HTTP path: once opened, calls POST straight to the
//! endpoint from every caller's task, sharing the session, the redirect policy
//! and the request decorator (the auth seam) the opening used.

use async_trait::async_trait;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use futures_util::{stream, Stream, StreamExt};
use mcpdef_core::{Id, Message};
use mcpdef_transport::{
    CallError, HandleOptions, HttpClient, RequestAuth, Transport, TransportError, UpstreamHandle,
};
use serde_json::json;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_stream::wrappers::BroadcastStream;

const SESSION: &str = "s-1";
const TOKEN: &str = "Bearer t0k3n";

/// What the mock upstream saw.
#[derive(Default)]
struct Seen {
    running: AtomicUsize,
    most_at_once: AtomicUsize,
    /// The headers of every request after `initialize`.
    headers: Mutex<Vec<HeaderMap>>,
    /// The ids `slow` calls arrived under.
    slow_ids: Mutex<Vec<Id>>,
    /// Requests that reached the route a redirect points at.
    redirected: AtomicUsize,
    /// Whether every request must carry [`TOKEN`].
    requires_token: bool,
}

/// Counts a slow call as running until it is dropped, finished or not.
struct Running<'a>(&'a Seen);

impl<'a> Running<'a> {
    fn start(seen: &'a Seen) -> Self {
        let now = seen.running.fetch_add(1, Ordering::SeqCst) + 1;
        seen.most_at_once.fetch_max(now, Ordering::SeqCst);
        Running(seen)
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.running.fetch_sub(1, Ordering::SeqCst);
    }
}

fn json(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// A 2025-11-25 Streamable endpoint that hands out a session on `initialize`
/// and refuses anything after it that does not carry the session back.
async fn mcp(State(seen): State<Arc<Seen>>, headers: HeaderMap, body: String) -> Response {
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(TOKEN);
    if seen.requires_token && !authorized {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(msg) = Message::from_json_line(body.trim()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if msg.method() == Some("initialize") {
        let hello = Message::result(
            msg.id.unwrap(),
            json!({ "protocolVersion": "2025-11-25", "capabilities": { "tools": {} },
                    "serverInfo": { "name": "concurrent", "version": "0" } }),
        );
        let mut r = json(StatusCode::OK, hello.to_json_line());
        r.headers_mut()
            .insert("mcp-session-id", HeaderValue::from_static(SESSION));
        return r;
    }
    if headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) != Some(SESSION) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    seen.headers.lock().unwrap().push(headers.clone());
    let Some(id) = msg.id.clone() else {
        return StatusCode::ACCEPTED.into_response();
    };
    let args = msg
        .params
        .as_ref()
        .map(|p| p["arguments"].clone())
        .unwrap_or_default();
    match msg.tool_name() {
        Some("slow") => {
            seen.slow_ids.lock().unwrap().push(id.clone());
            let _running = Running::start(&seen);
            let delay = args["delay_ms"].as_u64().unwrap_or(0);
            tokio::time::sleep(Duration::from_millis(delay)).await;
            json(
                StatusCode::OK,
                Message::result(id, json!({ "tag": args["tag"] })).to_json_line(),
            )
        }
        // An answer streamed as SSE: a stray reply to some other request, a
        // notification, then the reply.
        Some("notify") => {
            let stray = Message::result(Id::Str("elsewhere".into()), json!({ "tag": "stray" }));
            let note = Message::notification("notifications/progress", Some(json!({ "n": 1 })));
            let reply = Message::result(id, json!({ "tag": "notify" }));
            let body: String = [stray, note, reply]
                .iter()
                .map(|m| format!("event: message\ndata: {}\n\n", m.to_json_line()))
                .collect();
            ([(header::CONTENT_TYPE, "text/event-stream")], body).into_response()
        }
        // A server that could not read the request's id answers with a null one.
        Some("null-id") => json(
            StatusCode::BAD_REQUEST,
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"invalid request"}}"#
                .to_string(),
        ),
        Some("accepted") => StatusCode::ACCEPTED.into_response(),
        // What a server says once it has ended the session: a `404`, often with
        // a JSON-RPC error under a null id.
        Some("expired") => json(
            StatusCode::NOT_FOUND,
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"Session not found"}}"#
                .to_string(),
        ),
        Some("broken") => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Some("redirect") => (
            StatusCode::TEMPORARY_REDIRECT,
            [(header::LOCATION, "/elsewhere")],
        )
            .into_response(),
        _ => json(
            StatusCode::OK,
            Message::result(id, json!({})).to_json_line(),
        ),
    }
}

/// Where the redirect points. Never to be reached.
async fn elsewhere(State(seen): State<Arc<Seen>>, body: String) -> Response {
    seen.redirected.fetch_add(1, Ordering::SeqCst);
    let id = Message::from_json_line(body.trim())
        .ok()
        .and_then(|m| m.id)
        .unwrap_or(Id::Num(0));
    json(
        StatusCode::OK,
        Message::result(id, json!({ "tag": "followed" })).to_json_line(),
    )
}

async fn serve(seen: Arc<Seen>) -> String {
    let app = Router::new()
        .route("/mcp", post(mcp))
        .route("/elsewhere", post(elsewhere))
        .with_state(seen);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// Run the opening on the raw transport, as the gateway does, then hand the
/// client to a handle.
async fn open(client: HttpClient, max_inflight: usize) -> Result<UpstreamHandle, TransportError> {
    let options = HandleOptions {
        max_inflight,
        ..HandleOptions::default()
    };
    open_with(client, options).await
}

async fn open_with(
    mut client: HttpClient,
    options: HandleOptions,
) -> Result<UpstreamHandle, TransportError> {
    assert!(
        client.concurrent().is_none(),
        "nothing to share before the opening"
    );
    client
        .send(Message::request(
            Id::Num(0),
            "initialize",
            Some(json!({ "capabilities": {} })),
        ))
        .await?;
    let hello = client.recv().await?.expect("an initialize reply");
    assert!(hello.result.is_some(), "{hello:?}");
    client
        .send(Message::notification("notifications/initialized", None))
        .await?;
    assert!(
        client.concurrent().is_some(),
        "Streamable HTTP takes concurrent requests"
    );
    Ok(UpstreamHandle::spawn_with(
        "http",
        Box::new(client),
        options,
    ))
}

async fn upstream(max_inflight: usize) -> (UpstreamHandle, Arc<Seen>) {
    let seen = Arc::new(Seen::default());
    let base = serve(Arc::clone(&seen)).await;
    let client = HttpClient::streamable(format!("{base}/mcp")).unwrap();
    (open(client, max_inflight).await.unwrap(), seen)
}

fn call(id: i64, tool: &str, arguments: serde_json::Value) -> Message {
    Message::request(
        Id::Num(id),
        "tools/call",
        Some(json!({ "name": tool, "arguments": arguments })),
    )
}

fn slow(id: i64, tag: &str, delay_ms: u64) -> Message {
    call(id, "slow", json!({ "tag": tag, "delay_ms": delay_ms }))
}

fn tag(reply: &Message) -> &str {
    reply.result.as_ref().unwrap()["tag"].as_str().unwrap()
}

#[tokio::test]
async fn two_slow_calls_to_one_upstream_overlap() {
    let (up, seen) = upstream(16).await;
    let started = Instant::now();
    let (a, b) = tokio::join!(
        up.call(slow(1, "a", 400), None),
        up.call(slow(1, "b", 400), None)
    );
    let took = started.elapsed();
    assert_eq!((tag(&a.unwrap()), tag(&b.unwrap())), ("a", "b"));
    assert_eq!(seen.most_at_once.load(Ordering::SeqCst), 2);
    assert!(
        took < Duration::from_millis(700),
        "about one call's time, not two: {took:?}"
    );
}

#[tokio::test]
async fn the_in_flight_cap_still_bounds_direct_calls() {
    let (up, seen) = upstream(1).await;
    let started = Instant::now();
    let (a, b) = tokio::join!(
        up.call(slow(1, "a", 300), None),
        up.call(slow(2, "b", 300), None)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(seen.most_at_once.load(Ordering::SeqCst), 1);
    assert!(started.elapsed() >= Duration::from_millis(600));
    assert_eq!(up.inflight(), 0);
}

#[tokio::test]
async fn every_concurrent_call_carries_the_session_back() {
    let (up, seen) = upstream(16).await;
    let calls: Vec<_> = (0..8)
        .map(|n| {
            let up = up.clone();
            tokio::spawn(async move { up.call(slow(n, &format!("c{n}"), 50), None).await })
        })
        .collect();
    for (n, call) in calls.into_iter().enumerate() {
        let reply = call.await.unwrap().unwrap();
        assert_eq!(
            (tag(&reply), reply.id.clone()),
            (format!("c{n}").as_str(), Some(Id::Num(n as i64)))
        );
    }
    // The mock refuses a call without the session, so all eight carried it.
    let headers = seen.headers.lock().unwrap();
    assert!(headers.len() >= 8);
    assert!(headers.iter().all(|h| h["mcp-session-id"] == SESSION));
}

#[tokio::test]
async fn private_ids_keep_concurrent_requests_apart() {
    let (up, seen) = upstream(16).await;
    // Both callers use id 7, but one session must never see an id twice.
    let (a, b) = tokio::join!(
        up.call(slow(7, "a", 100), None),
        up.call(slow(7, "b", 100), None)
    );
    assert_eq!(
        (a.unwrap().id, b.unwrap().id),
        (Some(Id::Num(7)), Some(Id::Num(7)))
    );
    let ids = seen.slow_ids.lock().unwrap();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
    assert!(!ids.contains(&Id::Num(7)));
}

#[tokio::test]
async fn a_redirect_is_refused_not_followed() {
    let (up, seen) = upstream(16).await;
    let err = up
        .call(call(1, "redirect", json!({})), None)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, CallError::Failed(why) if why.contains("307")),
        "{err:?}"
    );
    assert_eq!(seen.redirected.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn notifications_in_an_answer_reach_subscribers() {
    let (up, _seen) = upstream(16).await;
    let mut notes = up.subscribe();
    let reply = up.call(call(1, "notify", json!({})), None).await.unwrap();
    assert_eq!(tag(&reply), "notify");
    let note = notes
        .try_recv()
        .expect("the notification came with the answer");
    assert_eq!(note.method(), Some("notifications/progress"));
}

#[tokio::test]
async fn an_error_under_a_null_id_is_the_reply() {
    let (up, _seen) = upstream(16).await;
    let reply = up.call(call(9, "null-id", json!({})), None).await.unwrap();
    assert_eq!(reply.id, Some(Id::Num(9)));
    assert_eq!(reply.error.unwrap()["code"], -32600);
}

#[tokio::test]
async fn an_answer_with_no_reply_fails_at_once() {
    let (up, _seen) = upstream(16).await;
    assert_eq!(
        up.call(call(1, "accepted", json!({})), None).await,
        Err(CallError::Failed(
            "the upstream's answer held no reply".into()
        ))
    );
}

#[tokio::test]
async fn a_timed_out_call_gives_its_slot_back() {
    let (up, _seen) = upstream(1).await;
    let limit = Duration::from_millis(50);
    assert_eq!(
        up.call(slow(1, "abandoned", 2_000), Some(limit)).await,
        Err(CallError::Timeout(limit))
    );
    assert_eq!(up.inflight(), 0);
    let started = Instant::now();
    assert_eq!(
        tag(&up.call(slow(2, "next", 0), None).await.unwrap()),
        "next"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "not queued behind the abandoned call"
    );
}

/// Adds the token, and tries to overwrite the headers the transport owns.
struct Token {
    applied: AtomicUsize,
}

#[async_trait]
impl RequestAuth for Token {
    async fn apply(&self, headers: &mut HeaderMap) -> Result<(), TransportError> {
        self.applied.fetch_add(1, Ordering::SeqCst);
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static(TOKEN));
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        headers.insert("mcp-session-id", HeaderValue::from_static("forged"));
        Ok(())
    }
}

#[tokio::test]
async fn the_auth_seam_signs_every_request_but_cannot_override_the_protocol() {
    let seen = Arc::new(Seen {
        requires_token: true,
        ..Seen::default()
    });
    let base = serve(Arc::clone(&seen)).await;

    // Without credentials the upstream refuses the opening itself.
    let bare = HttpClient::streamable(format!("{base}/mcp")).unwrap();
    assert!(open(bare, 16).await.is_err());

    let auth = Arc::new(Token {
        applied: AtomicUsize::new(0),
    });
    let client = HttpClient::streamable(format!("{base}/mcp"))
        .unwrap()
        .with_auth(auth.clone());
    let up = open(client, 16).await.unwrap();
    let (a, b) = tokio::join!(
        up.call(slow(1, "a", 20), None),
        up.call(slow(2, "b", 20), None)
    );
    assert_eq!((tag(&a.unwrap()), tag(&b.unwrap())), ("a", "b"));

    // initialize, initialized, and the two calls.
    assert_eq!(auth.applied.load(Ordering::SeqCst), 4);
    for h in seen.headers.lock().unwrap().iter() {
        assert_eq!(h[header::AUTHORIZATION], TOKEN);
        assert_eq!(h[header::CONTENT_TYPE], "application/json");
        assert_eq!(h[header::ACCEPT], "application/json, text/event-stream");
        assert_eq!(h["mcp-session-id"], SESSION);
        assert_eq!(h.get_all("mcp-session-id").iter().count(), 1);
    }
}

// ── The legacy HTTP+SSE bridge, behind a token: it stays on the actor, and its
//    stream and its posts both carry the credentials. ──

#[derive(Clone)]
struct Bridge {
    tx: tokio::sync::broadcast::Sender<String>,
    refused: Arc<AtomicUsize>,
}

fn has_token(headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(TOKEN)
}

async fn bridge_sse(
    State(st): State<Bridge>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    if !has_token(&headers) {
        st.refused.fetch_add(1, Ordering::SeqCst);
        return Err(StatusCode::UNAUTHORIZED);
    }
    let endpoint =
        stream::once(async { Ok(Event::default().event("endpoint").data("/bridge/messages")) });
    let messages = BroadcastStream::new(st.tx.subscribe()).map(|m| {
        Ok(Event::default()
            .event("message")
            .data(m.unwrap_or_default()))
    });
    Ok(Sse::new(endpoint.chain(messages)))
}

async fn bridge_post(State(st): State<Bridge>, headers: HeaderMap, body: String) -> StatusCode {
    if !has_token(&headers) {
        st.refused.fetch_add(1, Ordering::SeqCst);
        return StatusCode::UNAUTHORIZED;
    }
    if let Ok(msg) = Message::from_json_line(body.trim()) {
        if let Some(id) = msg.id.clone() {
            let _ = st
                .tx
                .send(Message::result(id, json!({ "tag": "bridged" })).to_json_line());
        }
    }
    StatusCode::ACCEPTED
}

#[tokio::test]
async fn the_legacy_bridge_carries_the_credentials_and_keeps_its_actor() {
    let (tx, _) = tokio::sync::broadcast::channel(16);
    let bridge = Bridge {
        tx,
        refused: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new()
        .route("/bridge/sse", get(bridge_sse))
        .route("/bridge/messages", post(bridge_post))
        .with_state(bridge.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let auth = Arc::new(Token {
        applied: AtomicUsize::new(0),
    });
    let mut client = HttpClient::legacy_sse(format!("http://{addr}/bridge/sse"))
        .unwrap()
        .with_auth(auth);
    client
        .send(Message::request(Id::Num(0), "initialize", None))
        .await
        .unwrap();
    let hello = tokio::time::timeout(Duration::from_secs(5), client.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(hello.id, Some(Id::Num(0)));
    assert!(
        client.concurrent().is_none(),
        "one shared stream: the bridge keeps its actor"
    );

    let up = UpstreamHandle::spawn("bridge", Box::new(client), 16);
    let reply = up
        .call(call(3, "anything", json!({})), Some(Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(
        (tag(&reply), reply.id.clone()),
        ("bridged", Some(Id::Num(3)))
    );
    assert_eq!(bridge.refused.load(Ordering::SeqCst), 0);
}

/// How many requests after `initialize` reached the upstream.
fn reached(seen: &Seen) -> usize {
    seen.headers.lock().unwrap().len()
}

#[tokio::test]
async fn a_404_on_the_session_takes_the_upstream_down() {
    let (up, seen) = upstream(16).await;
    let watch = up.watch();
    let ended = "the upstream ended its session (HTTP 404 for its Mcp-Session-Id)";
    // Not the upstream's answer to this call, whatever its body says: the
    // session it was sent on is gone.
    assert_eq!(
        up.call(call(1, "expired", json!({})), None).await,
        Err(CallError::Down(ended.into()))
    );
    assert_eq!(&*watch.down().await, ended);
    let before = reached(&seen);
    assert_eq!(
        up.call(slow(2, "after", 0), None).await,
        Err(CallError::Down(ended.into()))
    );
    assert_eq!(reached(&seen), before, "a later call is not sent at all");
}

#[tokio::test]
async fn failed_calls_in_a_row_take_a_direct_upstream_down_at_the_limit() {
    let seen = Arc::new(Seen::default());
    let base = serve(Arc::clone(&seen)).await;
    let client = HttpClient::streamable(format!("{base}/mcp")).unwrap();
    let options = HandleOptions {
        max_inflight: 16,
        trip_after: Some(3),
    };
    let up = open_with(client, options).await.unwrap();

    // A reply ends a run, an error reply included.
    for n in 0..2 {
        assert!(matches!(
            up.call(call(n, "broken", json!({})), None).await,
            Err(CallError::Failed(_))
        ));
    }
    assert_eq!(up.failures(), 2);
    up.call(call(3, "null-id", json!({})), None).await.unwrap();
    assert_eq!(up.failures(), 0);

    for n in 4..6 {
        assert!(matches!(
            up.call(call(n, "broken", json!({})), None).await,
            Err(CallError::Failed(_))
        ));
    }
    assert_eq!(up.down_reason(), None, "two in a row is under the limit");
    let third = up.call(call(6, "broken", json!({})), None).await;
    assert!(matches!(third, Err(CallError::Failed(_))), "{third:?}");
    let reason = up.down_reason().expect("down at the limit");
    assert!(
        reason.starts_with("3 calls in a row failed; the last: http: Streamable HTTP POST to"),
        "{reason}"
    );
    let before = reached(&seen);
    assert_eq!(
        up.call(slow(7, "after", 0), None).await,
        Err(CallError::Down(reason))
    );
    assert_eq!(reached(&seen), before, "a later call is not sent at all");
}

#[tokio::test]
async fn a_refused_connection_says_why() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut client = HttpClient::streamable(format!("http://127.0.0.1:{port}/mcp")).unwrap();
    let err = client
        .send(Message::request(Id::Num(0), "initialize", None))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.starts_with("http: error sending request for url"),
        "{err}"
    );
    assert!(
        err.contains("Connection refused"),
        "the cause is kept: {err}"
    );
}
