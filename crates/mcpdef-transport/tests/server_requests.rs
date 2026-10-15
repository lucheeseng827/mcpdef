// SPDX-License-Identifier: Apache-2.0
//! A request of the upstream's own. A 2025-11-25 server asks its client for
//! something (an elicitation, a sampling, its roots, a ping) and waits for the
//! answer. MCPdef passes none of them on, so it answers each at once: `-32601`,
//! saying so, or `{}` for a ping. It used to drop them, and the call the server
//! was making waited for good.

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use mcpdef_core::{Id, Message};
use mcpdef_transport::{
    duplex_pair, Duplex, HttpClient, Transport, TransportError, UpstreamHandle,
};
use serde_json::json;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;

/// Long enough for any answer on a slow machine: a regression fails the test
/// rather than hanging it.
const PATIENCE: Duration = Duration::from_secs(10);

/// What MCPdef answers a request for `asked` it does not pass on.
fn refusal(id: Id, asked: &str) -> Message {
    Message::error(
        id,
        -32601,
        format!(
            "MCPdef does not relay `{asked}` to its clients: through it, a server asks for \
             input in its result, on the 2026-07-28 wire"
        ),
    )
}

/// What the far end of a pipe is sent next.
async fn next(far: &mut Duplex) -> Message {
    tokio::time::timeout(PATIENCE, far.recv())
        .await
        .expect("an answer")
        .unwrap()
        .unwrap()
}

fn call() -> Message {
    Message::request(Id::Num(1), "tools/call", Some(json!({ "name": "ask" })))
}

#[tokio::test]
async fn over_a_pipe_each_request_is_answered_and_the_call_goes_on() {
    let (near, mut far) = duplex_pair();
    let up = UpstreamHandle::spawn("pipe", Box::new(near), 4);
    let calling = tokio::spawn({
        let up = up.clone();
        async move { up.call(call(), Some(PATIENCE)).await }
    });
    let sent = far.recv().await.unwrap().unwrap();
    for (id, asked) in [
        ("e", "elicitation/create"),
        ("s", "sampling/createMessage"),
        ("r", "roots/list"),
    ] {
        let id = Id::Str(id.into());
        let ask = Message::request(id.clone(), asked, Some(json!({})));
        far.send(ask).await.unwrap();
        assert_eq!(next(&mut far).await, refusal(id, asked));
    }
    // Numbered as a call of the handle's own is: still a request, not a reply.
    let ping = Message::request(sent.id.clone().unwrap(), "ping", None);
    far.send(ping).await.unwrap();
    assert_eq!(
        next(&mut far).await,
        Message::result(sent.id.clone().unwrap(), json!({}))
    );

    let answer = Message::result(sent.id.clone().unwrap(), json!({ "content": [] }));
    far.send(answer).await.unwrap();
    let reply = calling.await.unwrap().unwrap();
    assert_eq!(reply.id, Some(Id::Num(1)));
    assert_eq!(reply.result, Some(json!({ "content": [] })));
}

/// Like the in-process sandboxes: each reply is produced by the `send` that
/// carries its request. This one asks for an elicitation before it answers.
#[derive(Default)]
struct AsksInline {
    sent: Arc<Mutex<Vec<Message>>>,
    inbox: VecDeque<Message>,
}

#[async_trait]
impl Transport for AsksInline {
    async fn send(&mut self, msg: Message) -> Result<(), TransportError> {
        self.sent.lock().unwrap().push(msg.clone());
        if let Some(id) = msg.id.clone().filter(|_| msg.is_request()) {
            let ask = Message::request(Id::Str("e".into()), "elicitation/create", None);
            self.inbox.push_back(ask);
            self.inbox.push_back(Message::result(id, json!({})));
        }
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<Message>, TransportError> {
        Ok(self.inbox.pop_front())
    }

    fn replies_inline(&self) -> bool {
        true
    }
}

/// The call that made the request has run to its end by the time it is read,
/// so there is nothing to answer it for.
#[tokio::test]
async fn an_inline_peers_request_is_not_answered() {
    let inline = AsksInline::default();
    let sent = Arc::clone(&inline.sent);
    let up = UpstreamHandle::spawn("inline", Box::new(inline), 1);
    let reply = up.call(call(), Some(PATIENCE)).await.unwrap();
    assert_eq!(reply.result, Some(json!({})));
    let methods: Vec<Option<String>> = sent
        .lock()
        .unwrap()
        .iter()
        .map(|m| m.method.clone())
        .collect();
    assert_eq!(methods, [Some("tools/call".to_string())]);
}

const SESSION: &str = "s-1";

/// A 2025-11-25 Streamable HTTP server whose `tools/call` answer is an SSE
/// stream: it sends a request of its own on it, waits for the client to POST
/// the answer, then sends the call's result, which says what it was answered
/// and under which session and revision.
#[derive(Default)]
struct Asking {
    answer: Mutex<Option<oneshot::Sender<(Message, HeaderMap)>>>,
}

async fn mcp(State(asking): State<Arc<Asking>>, headers: HeaderMap, body: String) -> Response {
    let msg = Message::from_json_line(body.trim()).unwrap();
    if msg.is_response() {
        if let Some(waiting) = asking.answer.lock().unwrap().take() {
            let _ = waiting.send((msg, headers));
        }
        return StatusCode::ACCEPTED.into_response();
    }
    let Some(id) = msg.id.clone() else {
        return StatusCode::ACCEPTED.into_response();
    };
    if msg.method() == Some("initialize") {
        let hello = Message::result(
            id,
            json!({ "protocolVersion": "2025-11-25", "capabilities": { "tools": {} },
                    "serverInfo": { "name": "asking", "version": "0" } }),
        );
        let mut response = (
            [(header::CONTENT_TYPE, "application/json")],
            hello.to_json_line(),
        )
            .into_response();
        response
            .headers_mut()
            .insert("mcp-session-id", HeaderValue::from_static(SESSION));
        return response;
    }
    let (waiting, answered) = oneshot::channel();
    *asking.answer.lock().unwrap() = Some(waiting);
    let (events, stream) = mpsc::channel::<Result<String, Infallible>>(4);
    tokio::spawn(async move {
        let event = |m: &Message| Ok(format!("event: message\ndata: {}\n\n", m.to_json_line()));
        let ask = Message::request(
            Id::Str("e1".into()),
            "elicitation/create",
            Some(json!({ "message": "What is your name?" })),
        );
        events.send(event(&ask)).await.unwrap();
        let Ok((answer, headers)) = answered.await else {
            return;
        };
        let said = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("-")
                .to_string()
        };
        let text = format!(
            "{} under {} at {}",
            answer.to_json_line(),
            said("mcp-session-id"),
            said("mcp-protocol-version")
        );
        let reply = Message::result(id, json!({ "content": [{ "type": "text", "text": text }] }));
        let _ = events.send(event(&reply)).await;
    });
    Response::builder()
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(ReceiverStream::new(stream)))
        .unwrap()
}

/// Over Streamable HTTP the request comes in the middle of the answer to a
/// call, and the server goes on only once it has the answer: it is POSTed at
/// once, under the call's session and revision, and the call's result follows.
#[tokio::test]
async fn over_streamable_http_a_request_mid_answer_is_answered_at_once() {
    mcpdef_transport::install_crypto_provider();
    let app = Router::new()
        .route("/mcp", post(mcp))
        .with_state(Arc::new(Asking::default()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mut client = HttpClient::streamable(format!("http://{addr}/mcp")).unwrap();
    client
        .send(Message::request(
            Id::Num(0),
            "initialize",
            Some(json!({ "protocolVersion": "2025-11-25", "capabilities": {} })),
        ))
        .await
        .unwrap();
    assert!(client.recv().await.unwrap().unwrap().result.is_some());
    assert!(
        client.concurrent().is_some(),
        "calls go straight to the endpoint"
    );
    let up = UpstreamHandle::spawn("http", Box::new(client), 4);

    let reply = up.call(call(), Some(PATIENCE)).await.unwrap();
    let text = reply.result.unwrap()["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string();
    let answered = refusal(Id::Str("e1".into()), "elicitation/create");
    assert_eq!(
        text,
        format!("{} under {SESSION} at 2025-11-25", answered.to_json_line())
    );
}
