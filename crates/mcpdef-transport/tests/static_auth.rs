// SPDX-License-Identifier: Apache-2.0
//! Credentials that stay the same from one request to the next
//! ([`StaticAuth`]): the header each kind sends, the headers none may, and
//! what an upstream's `401` does. The secret is read again, once however many
//! requests were refused, and a request goes once more only when that changed
//! it; then a second `401` fails it closed.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use futures_util::{stream, Stream, StreamExt};
use mcpdef_core::{Id, Message};
use mcpdef_secrets::{SecretRef, SecretString};
use mcpdef_transport::{
    CallError, Credential, HttpClient, RequestAuth, StaticAuth, Transport, TransportError,
    UpstreamHandle,
};
use serde_json::json;
use std::convert::Infallible;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;

fn literal(value: &str) -> SecretRef {
    SecretRef::Literal(SecretString::from(value))
}

/// The headers `auth` adds to a request.
async fn applied(auth: &StaticAuth) -> HeaderMap {
    let mut headers = HeaderMap::new();
    auth.apply(&mut headers).await.unwrap();
    headers
}

#[tokio::test]
async fn each_kind_sends_its_header_marked_sensitive() {
    let bearer = StaticAuth::read(Credential::Bearer(literal("t0k3n")))
        .await
        .unwrap();
    let headers = applied(&bearer).await;
    assert_eq!(headers[header::AUTHORIZATION], "Bearer t0k3n");
    assert!(headers[header::AUTHORIZATION].is_sensitive());
    assert!(!format!("{headers:?}").contains("t0k3n"), "{headers:?}");

    let key = Credential::header("X-Api-Key", literal("k3y")).unwrap();
    let headers = applied(&StaticAuth::read(key).await.unwrap()).await;
    assert_eq!(headers["x-api-key"], "k3y");
    assert!(headers["x-api-key"].is_sensitive());
    assert_eq!(headers.len(), 1);

    let basic = Credential::basic("mcpdef", literal("pa55")).unwrap();
    let headers = applied(&StaticAuth::read(basic).await.unwrap()).await;
    assert_eq!(headers[header::AUTHORIZATION], "Basic bWNwZGVmOnBhNTU=");
    assert!(headers[header::AUTHORIZATION].is_sensitive());
}

#[test]
fn a_header_http_mcp_or_a_proxy_sets_is_refused() {
    for name in [
        "Host",
        "Accept",
        "Content-Type",
        "content-length",
        "Transfer-Encoding",
        "Connection",
        "Mcp-Session-Id",
        "MCP-Protocol-Version",
        "Last-Event-ID",
        "Proxy-Authorization",
    ] {
        let refused = Credential::header(name, literal("v")).unwrap_err();
        assert!(
            refused.ends_with(
                "is a header HTTP, MCP's transport or a proxy sets: send the \
                               credential in another"
            ),
            "{name}: {refused}"
        );
    }
    for name in [
        "X-Api-Key",
        "Authorization",
        "Cookie",
        "Contentious",
        "Mcpish",
    ] {
        assert!(Credential::header(name, literal("v")).is_ok(), "{name}");
    }
    assert_eq!(
        Credential::header("bad name", literal("v")).unwrap_err(),
        "\"bad name\" is not a header name"
    );
    assert!(Credential::basic("a:b", literal("p")).is_err());
    assert!(Credential::basic("a\nb", literal("p")).is_err());
}

#[tokio::test]
async fn a_secret_that_cannot_be_used_says_where_it_is_and_not_what() {
    let missing = Credential::Bearer(SecretRef::File("/nonexistent/token".into()));
    let error = StaticAuth::read(missing).await.err().unwrap().to_string();
    assert!(
        error.starts_with("credentials: token /nonexistent/token: "),
        "{error}"
    );
    let broken = Credential::Bearer(literal("s3cret\nline"));
    let error = StaticAuth::read(broken).await.err().unwrap().to_string();
    assert_eq!(
        error,
        "credentials: token (literal): holds a character no HTTP header can"
    );
    // Nor does the credential's own Debug.
    let credential = Credential::Bearer(literal("s3cret"));
    assert_eq!(format!("{credential:?}"), "authorization token (literal)");
}

// ── An upstream that takes one credential at a time, which the test changes.

#[derive(Default)]
struct Gate {
    /// The `Authorization` value it takes.
    wants: Mutex<String>,
    /// What each request carried, in order.
    seen: Mutex<Vec<String>>,
    /// For the bridge: where replies go out, on its stream.
    stream: Mutex<Option<tokio::sync::broadcast::Sender<String>>>,
}

impl Gate {
    fn wants(&self, value: &str) {
        *self.wants.lock().unwrap() = format!("Bearer {value}");
    }

    /// Whether `headers` carry what it takes. Every request is counted.
    fn lets(&self, headers: &HeaderMap) -> bool {
        let given = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let ok = given == *self.wants.lock().unwrap();
        self.seen.lock().unwrap().push(given);
        ok
    }

    /// What the requests since the last look carried, as the tokens alone.
    fn seen(&self) -> Vec<String> {
        let seen = std::mem::take(&mut *self.seen.lock().unwrap());
        seen.into_iter()
            .map(|v| v.trim_start_matches("Bearer ").to_string())
            .collect()
    }
}

fn answer(message: &Message) -> Message {
    let result = match message.method() {
        Some("initialize") => json!({
            "protocolVersion": "2025-11-25",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "gate", "version": "0" }
        }),
        _ => json!({ "content": [{ "type": "text", "text": "done" }], "isError": false }),
    };
    Message::result(message.id.clone().unwrap_or(Id::Num(0)), result)
}

async fn streamable(State(gate): State<Arc<Gate>>, headers: HeaderMap, body: String) -> Response {
    if !gate.lets(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let message = Message::from_json_line(body.trim()).unwrap();
    if message.id.is_none() {
        return StatusCode::ACCEPTED.into_response();
    }
    (
        [(header::CONTENT_TYPE, "application/json")],
        answer(&message).to_json_line(),
    )
        .into_response()
}

async fn bridge_stream(
    State(gate): State<Arc<Gate>>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    if !gate.lets(&headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let (tx, rx) = tokio::sync::broadcast::channel(16);
    *gate.stream.lock().unwrap() = Some(tx);
    let endpoint = stream::once(async { Ok(Event::default().event("endpoint").data("/messages")) });
    let replies = BroadcastStream::new(rx).map(|m| {
        Ok(Event::default()
            .event("message")
            .data(m.unwrap_or_default()))
    });
    Ok(Sse::new(endpoint.chain(replies)))
}

async fn bridge_post(
    State(gate): State<Arc<Gate>>,
    headers: HeaderMap,
    body: String,
) -> StatusCode {
    if !gate.lets(&headers) {
        return StatusCode::UNAUTHORIZED;
    }
    let message = Message::from_json_line(body.trim()).unwrap();
    if message.id.is_some() {
        if let Some(tx) = &*gate.stream.lock().unwrap() {
            let _ = tx.send(answer(&message).to_json_line());
        }
    }
    StatusCode::ACCEPTED
}

async fn serve(gate: Arc<Gate>) -> String {
    let app = Router::new()
        .route("/mcp", post(streamable))
        .route("/sse", get(bridge_stream))
        .route("/messages", post(bridge_post))
        .with_state(gate);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// A bearer token read from `path`.
async fn from_file(path: &Path) -> Arc<StaticAuth> {
    let token = Credential::Bearer(SecretRef::File(path.to_owned()));
    Arc::new(StaticAuth::read(token).await.unwrap())
}

/// Open `client` as the gateway does, and hand it to a handle.
async fn open(mut client: HttpClient) -> Result<UpstreamHandle, TransportError> {
    client
        .send(Message::request(Id::Num(0), "initialize", Some(json!({}))))
        .await?;
    client.recv().await?.expect("an initialize reply");
    client
        .send(Message::notification("notifications/initialized", None))
        .await?;
    Ok(UpstreamHandle::spawn("gate", Box::new(client), 16))
}

fn call(id: i64) -> Message {
    Message::request(
        Id::Num(id),
        "tools/call",
        Some(json!({ "name": "t", "arguments": {} })),
    )
}

const WAIT: Option<Duration> = Some(Duration::from_secs(5));

#[tokio::test]
async fn a_refused_request_goes_once_more_when_the_secret_read_again_changed() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, "t1").unwrap();
    let gate = Arc::new(Gate::default());
    gate.wants("t1");
    let base = serve(Arc::clone(&gate)).await;
    let client = HttpClient::streamable(format!("{base}/mcp"))
        .unwrap()
        .with_auth(from_file(&token).await);
    let up = open(client).await.unwrap();
    up.call(call(1), WAIT).await.unwrap();
    assert_eq!(gate.seen(), ["t1", "t1", "t1"]);

    // Rotated: refused, read again, and sent once more.
    gate.wants("t2");
    std::fs::write(&token, "t2\n").unwrap();
    up.call(call(2), WAIT).await.unwrap();
    assert_eq!(gate.seen(), ["t1", "t2"]);

    // Refused, and the file says the same: no second try.
    gate.wants("t3");
    let refused = up.call(call(3), WAIT).await.unwrap_err();
    assert!(matches!(refused, CallError::Unauthorized(_)), "{refused:?}");
    assert_eq!(
        refused.to_string(),
        format!("{base}/mcp answered 401 Unauthorized")
    );
    assert_eq!(gate.seen(), ["t2"]);

    // Refused again after one more try with what it says now: closed.
    std::fs::write(&token, "t4").unwrap();
    let refused = up.call(call(4), WAIT).await.unwrap_err();
    assert!(matches!(refused, CallError::Unauthorized(_)), "{refused:?}");
    assert_eq!(gate.seen(), ["t2", "t4"]);
}

/// Requests refused at once read the secret again once between them, and all
/// go once more.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_refused_requests_read_the_secret_again_once() {
    let dir = tempfile::tempdir().unwrap();
    let (token, reads) = (dir.path().join("token"), dir.path().join("reads"));
    std::fs::write(&token, "t1").unwrap();
    let counting = SecretRef::Exec {
        program: "sh".into(),
        args: vec![
            "-c".into(),
            format!(
                "echo read >> '{}'; cat '{}'",
                reads.display(),
                token.display()
            ),
        ],
    };
    let auth = Arc::new(
        StaticAuth::read(Credential::Bearer(counting))
            .await
            .unwrap(),
    );
    let gate = Arc::new(Gate::default());
    gate.wants("t1");
    let base = serve(Arc::clone(&gate)).await;
    let client = HttpClient::streamable(format!("{base}/mcp"))
        .unwrap()
        .with_auth(auth);
    let up = open(client).await.unwrap();

    gate.wants("t2");
    std::fs::write(&token, "t2").unwrap();
    let calls = (1..=8).map(|id| up.call(call(id), WAIT));
    for answer in futures_util::future::join_all(calls).await {
        answer.unwrap();
    }
    let reads = std::fs::read_to_string(&reads).unwrap();
    assert_eq!(
        reads.lines().count(),
        2,
        "read once to open, once for all 8"
    );
}

/// The legacy bridge's stream and its posts go once more too.
#[tokio::test]
async fn the_bridge_s_stream_and_posts_go_once_more_too() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, "t1").unwrap();
    let auth = from_file(&token).await;
    let gate = Arc::new(Gate::default());
    let base = serve(Arc::clone(&gate)).await;

    // Rotated before the stream opens: the stream is refused once.
    gate.wants("t2");
    std::fs::write(&token, "t2").unwrap();
    let client = HttpClient::legacy_sse(format!("{base}/sse"))
        .unwrap()
        .with_auth(auth);
    let up = open(client).await.unwrap();
    assert_eq!(gate.seen(), ["t1", "t2", "t2", "t2"]);

    // Rotated while it is open: a post is refused once.
    gate.wants("t3");
    std::fs::write(&token, "t3").unwrap();
    up.call(call(1), WAIT).await.unwrap();
    assert_eq!(gate.seen(), ["t2", "t3"]);
}
