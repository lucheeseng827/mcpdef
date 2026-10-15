// SPDX-License-Identifier: Apache-2.0
//! `UpstreamHandle`: many calls over one upstream connection.
//!
//! Most tests drive the upstream by hand through the far end of a duplex pair,
//! so they choose exactly when each reply goes out.

use async_trait::async_trait;
use mcpdef_core::{Id, Message};
use mcpdef_transport::{
    duplex_pair, CallError, Duplex, Exchange, HandleOptions, Transport, TransportError,
    UpstreamHandle,
};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

fn upstream(max_inflight: usize) -> (UpstreamHandle, Duplex) {
    let (near, far) = duplex_pair();
    (
        UpstreamHandle::spawn("mock", Box::new(near), max_inflight),
        far,
    )
}

/// A request from a caller using `id`, tagged so its reply can be recognised.
fn req(id: i64, tag: &str) -> Message {
    Message::request(Id::Num(id), "tools/call", Some(json!({ "tag": tag })))
}

/// The upstream's reply to `request`: same id, echoing its tag.
fn echo(request: &Message) -> Message {
    let tag = request.params.as_ref().unwrap()["tag"].clone();
    Message::result(request.id.clone().unwrap(), json!({ "tag": tag }))
}

fn tag(reply: &Message) -> &str {
    reply.result.as_ref().unwrap()["tag"].as_str().unwrap()
}

async fn next(far: &mut Duplex) -> Message {
    far.recv().await.unwrap().expect("a request")
}

fn spawn_call(
    up: &UpstreamHandle,
    request: Message,
    timeout: Option<Duration>,
) -> tokio::task::JoinHandle<Result<Message, CallError>> {
    let up = up.clone();
    tokio::spawn(async move { up.call(request, timeout).await })
}

#[tokio::test]
async fn replies_in_any_order_reach_their_own_callers() {
    let (up, mut far) = upstream(16);
    // Both callers use id 1, as two downstream clients would.
    let a = spawn_call(&up, req(1, "a"), None);
    let b = spawn_call(&up, req(1, "b"), None);
    let first = next(&mut far).await;
    let second = next(&mut far).await;
    assert_ne!(
        first.id, second.id,
        "each request goes out under its own id"
    );
    assert!(matches!(first.id, Some(Id::Num(n)) if n >= 100));

    far.send(echo(&second)).await.unwrap();
    far.send(echo(&first)).await.unwrap();
    let (a, b) = (a.await.unwrap().unwrap(), b.await.unwrap().unwrap());
    assert_eq!((tag(&a), a.id.clone()), ("a", Some(Id::Num(1))));
    assert_eq!((tag(&b), b.id.clone()), ("b", Some(Id::Num(1))));
    assert_eq!(up.inflight(), 0);
}

#[tokio::test]
async fn an_error_reply_is_a_reply() {
    let (up, mut far) = upstream(16);
    let call = spawn_call(
        &up,
        Message::request(Id::Str("s".into()), "nope", None),
        None,
    );
    let sent = next(&mut far).await;
    far.send(Message::error(sent.id.unwrap(), -32601, "method not found"))
        .await
        .unwrap();
    let reply = call.await.unwrap().unwrap();
    assert_eq!(reply.id, Some(Id::Str("s".into())));
    assert_eq!(reply.error.unwrap()["code"], -32601);
}

#[tokio::test(start_paused = true)]
async fn a_reply_after_its_timeout_is_dropped_not_misrouted() {
    let (up, mut far) = upstream(16);
    let limit = Duration::from_millis(50);
    assert_eq!(
        up.call(req(7, "late"), Some(limit)).await,
        Err(CallError::Timeout(limit))
    );
    let stale = next(&mut far).await;

    let waiting = spawn_call(&up, req(7, "next"), None);
    let fresh = next(&mut far).await;
    // The late reply arrives while the next call, with the same caller id, waits.
    far.send(echo(&stale)).await.unwrap();
    far.send(echo(&fresh)).await.unwrap();
    let got = waiting.await.unwrap().unwrap();
    assert_eq!((tag(&got), got.id.clone()), ("next", Some(Id::Num(7))));
    assert_eq!(up.inflight(), 0);
}

#[tokio::test]
async fn requests_from_the_upstream_are_not_taken_for_replies() {
    let (up, mut far) = upstream(16);
    let call = spawn_call(&up, req(1, "a"), None);
    let sent = next(&mut far).await;
    // A server-to-client request that happens to reuse the call's id, and stray
    // replies to ids nobody sent.
    far.send(Message::request(
        sent.id.clone().unwrap(),
        "sampling/createMessage",
        None,
    ))
    .await
    .unwrap();
    for stray in [Id::Num(-1), Id::Num(0), Id::Num(99), Id::Str("100".into())] {
        far.send(Message::result(stray, json!({ "tag": "stray" })))
            .await
            .unwrap();
    }
    far.send(echo(&sent)).await.unwrap();
    assert_eq!(tag(&call.await.unwrap().unwrap()), "a");
}

#[tokio::test]
async fn notifications_reach_every_subscriber_in_order() {
    let (up, mut far) = upstream(16);
    let mut subscribers = [up.subscribe(), up.subscribe()];
    let call = spawn_call(&up, req(1, "a"), None);
    let sent = next(&mut far).await;
    for n in 0..3 {
        far.send(Message::notification(
            "notifications/progress",
            Some(json!({ "n": n })),
        ))
        .await
        .unwrap();
    }
    far.send(echo(&sent)).await.unwrap();
    assert_eq!(tag(&call.await.unwrap().unwrap()), "a");
    for sub in &mut subscribers {
        for n in 0..3 {
            let note = sub.recv().await.unwrap();
            assert_eq!(note.method(), Some("notifications/progress"));
            assert_eq!(note.params.unwrap()["n"], n);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn calls_beyond_the_cap_wait_for_a_slot() {
    let (up, mut far) = upstream(2);
    let calls: Vec<_> = ["a", "b", "c"]
        .iter()
        .map(|t| spawn_call(&up, req(1, t), None))
        .collect();
    let first = next(&mut far).await;
    let second = next(&mut far).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), far.recv())
            .await
            .is_err(),
        "a third request must wait while two are unanswered"
    );
    assert_eq!(up.inflight(), 2);
    far.send(echo(&first)).await.unwrap();
    let third = next(&mut far).await;
    far.send(echo(&second)).await.unwrap();
    far.send(echo(&third)).await.unwrap();
    let mut tags: Vec<String> = Vec::new();
    for call in calls {
        tags.push(tag(&call.await.unwrap().unwrap()).to_string());
    }
    assert_eq!(tags, ["a", "b", "c"]);
    assert_eq!(up.inflight(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_caller_that_stops_waiting_gives_its_slot_back() {
    let (up, mut far) = upstream(1);
    let limit = Duration::from_millis(50);
    assert_eq!(
        up.call(req(1, "abandoned"), Some(limit)).await,
        Err(CallError::Timeout(limit))
    );
    let _never_answered = next(&mut far).await;
    // The only slot is free again, so the next call goes out.
    let call = spawn_call(&up, req(2, "next"), None);
    let sent = next(&mut far).await;
    far.send(echo(&sent)).await.unwrap();
    assert_eq!(tag(&call.await.unwrap().unwrap()), "next");

    // Dropping a call's future mid-wait gives its slot back too.
    let dropped = spawn_call(&up, req(3, "dropped"), None);
    let _sent = next(&mut far).await;
    dropped.abort();
    assert!(dropped.await.unwrap_err().is_cancelled());
    let call = spawn_call(&up, req(4, "after"), None);
    let sent = next(&mut far).await;
    far.send(echo(&sent)).await.unwrap();
    assert_eq!(tag(&call.await.unwrap().unwrap()), "after");
    assert_eq!(up.inflight(), 0);
}

#[tokio::test]
async fn a_closed_connection_fails_waiting_and_later_calls_as_down() {
    let (up, mut far) = upstream(16);
    let call = spawn_call(&up, req(1, "a"), None);
    let _sent = next(&mut far).await;
    drop(far);
    let reason = "the upstream closed the connection";
    assert_eq!(call.await.unwrap(), Err(CallError::Down(reason.into())));
    // Later calls fail at once, with no timeout to wait out.
    assert_eq!(
        up.call(req(2, "b"), None).await,
        Err(CallError::Down(reason.into()))
    );
    assert_eq!(up.down_reason().as_deref(), Some(reason));
    assert_eq!(up.inflight(), 0);
}

/// A notification already waiting when the handle takes the transport over
/// reaches a receiver made with the handle, and the receiver closes with the
/// last handle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listening_handle_hears_what_was_waiting_and_closes_with_the_last_handle() {
    let (near, mut far) = duplex_pair();
    far.send(Message::notification(
        "notifications/tools/list_changed",
        None,
    ))
    .await
    .unwrap();
    let (up, mut notices) =
        UpstreamHandle::spawn_listening("mock", Box::new(near), HandleOptions::default());
    let note = notices.recv().await.unwrap();
    assert_eq!(note.method(), Some("notifications/tools/list_changed"));
    let other = up.clone();
    drop(up);
    far.send(Message::notification("notifications/progress", None))
        .await
        .unwrap();
    assert_eq!(
        notices.recv().await.unwrap().method(),
        Some("notifications/progress")
    );
    drop(other);
    assert!(matches!(
        notices.recv().await,
        Err(tokio::sync::broadcast::error::RecvError::Closed)
    ));
}

/// A transport with a concurrent side, holding what came before the handle
/// took it over, as a Streamable HTTP client holds the rest of the answer to
/// the opening's last request. Nothing more ever comes on it.
struct Held(VecDeque<Message>);

#[async_trait]
impl Transport for Held {
    async fn send(&mut self, _: Message) -> Result<(), TransportError> {
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<Message>, TransportError> {
        match self.0.pop_front() {
            Some(message) => Ok(Some(message)),
            None => std::future::pending().await,
        }
    }

    fn concurrent(&self) -> Option<Arc<dyn Exchange>> {
        Some(Arc::new(Echoes))
    }
}

/// A concurrent side that echoes each request.
struct Echoes;

#[async_trait]
impl Exchange for Echoes {
    async fn exchange(&self, request: &Message) -> Result<Vec<Message>, TransportError> {
        Ok(vec![echo(request)])
    }
}

/// A handle that calls a transport's concurrent side never reads the transport
/// itself, so it hands the notifications the transport already holds to a
/// receiver made with it as it takes it over. What else it holds is dropped.
#[tokio::test]
async fn a_direct_handle_hands_on_the_notifications_its_transport_held() {
    let note = Message::notification("notifications/tools/list_changed", None);
    let stray = Message::result(Id::Num(1), json!({}));
    let held = Held(VecDeque::from([stray, note.clone()]));
    let (up, mut notices) =
        UpstreamHandle::spawn_listening("mock", Box::new(held), HandleOptions::default());
    assert_eq!(notices.try_recv().unwrap(), note);
    assert!(notices.try_recv().is_err(), "a reply is no notification");
    let reply = up.call(req(7, "direct"), None).await.unwrap();
    assert_eq!(tag(&reply), "direct");
}

#[tokio::test]
async fn dropping_the_last_handle_closes_the_transport() {
    let (up, mut far) = upstream(16);
    let other = up.clone();
    drop(up);
    let call = spawn_call(&other, req(1, "a"), None);
    let sent = next(&mut far).await;
    far.send(echo(&sent)).await.unwrap();
    call.await.unwrap().unwrap();
    drop(other);
    assert!(far.recv().await.unwrap().is_none());
}

#[tokio::test]
async fn a_notification_cannot_be_called() {
    let (up, _far) = upstream(16);
    let err = up
        .call(
            Message::notification("notifications/initialized", None),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, CallError::Failed(_)), "{err:?}");
    assert_eq!(up.inflight(), 0);
}

/// A duplex end whose sends wait for a permit, and which can fail a send or
/// turn a marked message into an unreadable one.
struct Scripted {
    inner: Duplex,
    gate: Arc<Semaphore>,
}

#[async_trait]
impl Transport for Scripted {
    async fn send(&mut self, msg: Message) -> Result<(), TransportError> {
        self.gate.acquire().await.unwrap().forget();
        if msg.params.as_ref().is_some_and(|p| p["tag"] == "boom") {
            return Err(TransportError::Http("POST returned 500".into()));
        }
        self.inner.send(msg).await
    }

    async fn recv(&mut self) -> Result<Option<Message>, TransportError> {
        match self.inner.recv().await? {
            Some(m) if m.method() == Some("test/garbage") => {
                Err(TransportError::Decode("expected value at line 1".into()))
            }
            other => Ok(other),
        }
    }
}

fn scripted(max_inflight: usize, permits: usize) -> (UpstreamHandle, Duplex, Arc<Semaphore>) {
    let (near, far) = duplex_pair();
    let gate = Arc::new(Semaphore::new(permits));
    let transport = Scripted {
        inner: near,
        gate: Arc::clone(&gate),
    };
    (
        UpstreamHandle::spawn("scripted", Box::new(transport), max_inflight),
        far,
        gate,
    )
}

#[tokio::test(start_paused = true)]
async fn a_call_abandoned_before_its_turn_is_never_sent() {
    let (up, mut far, gate) = scripted(16, 0);
    // The actor is stuck sending the first request, so the second waits behind it.
    let first = spawn_call(&up, req(1, "first"), None);
    tokio::task::yield_now().await;
    let limit = Duration::from_millis(50);
    assert_eq!(
        up.call(req(2, "abandoned"), Some(limit)).await,
        Err(CallError::Timeout(limit))
    );
    gate.add_permits(2);
    let sent = next(&mut far).await;
    assert_eq!(sent.params.as_ref().unwrap()["tag"], "first");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), far.recv())
            .await
            .is_err(),
        "the abandoned request must not be sent"
    );
    far.send(echo(&sent)).await.unwrap();
    assert_eq!(tag(&first.await.unwrap().unwrap()), "first");
    assert_eq!(up.inflight(), 0);
}

#[tokio::test]
async fn a_failed_send_fails_only_that_call() {
    let (up, mut far, _gate) = scripted(16, 100);
    assert_eq!(
        up.call(req(1, "boom"), None).await,
        Err(CallError::Failed("http: POST returned 500".into()))
    );
    let call = spawn_call(&up, req(2, "fine"), None);
    let sent = next(&mut far).await;
    far.send(echo(&sent)).await.unwrap();
    assert_eq!(tag(&call.await.unwrap().unwrap()), "fine");
    assert_eq!(up.down_reason(), None);
}

#[tokio::test]
async fn an_unreadable_message_is_skipped() {
    let (up, mut far, _gate) = scripted(16, 100);
    let call = spawn_call(&up, req(1, "a"), None);
    let sent = next(&mut far).await;
    far.send(Message::notification("test/garbage", None))
        .await
        .unwrap();
    far.send(echo(&sent)).await.unwrap();
    assert_eq!(tag(&call.await.unwrap().unwrap()), "a");
    assert_eq!(up.down_reason(), None);
}

/// Like the in-process sandboxes: each reply is produced by the `send` that
/// carries its request, and `recv` returns `None` once nothing is queued.
#[derive(Default)]
struct Inline {
    inbox: VecDeque<Message>,
    running: Arc<Mutex<usize>>,
}

#[async_trait]
impl Transport for Inline {
    async fn send(&mut self, msg: Message) -> Result<(), TransportError> {
        *self.running.lock().unwrap() += 1;
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(*self.running.lock().unwrap(), 1, "one request at a time");
        *self.running.lock().unwrap() -= 1;
        match msg.params.as_ref().map(|p| p["tag"].clone()) {
            Some(t) if t == "trap" => Err(TransportError::Sandbox("all fuel consumed".into())),
            Some(t) if t == "silent" => Ok(()),
            _ => {
                self.inbox.push_back(echo(&msg));
                Ok(())
            }
        }
    }

    async fn recv(&mut self) -> Result<Option<Message>, TransportError> {
        Ok(self.inbox.pop_front())
    }

    fn replies_inline(&self) -> bool {
        true
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_inline_transport_answers_every_caller_and_fails_only_its_own() {
    let up = UpstreamHandle::spawn("inline", Box::new(Inline::default()), 1);
    let calls: Vec<_> = (0..8)
        .map(|n| spawn_call(&up, req(n, &format!("call-{n}")), None))
        .collect();
    for (n, call) in calls.into_iter().enumerate() {
        let reply = call.await.unwrap().unwrap();
        assert_eq!(tag(&reply), format!("call-{n}"));
        assert_eq!(reply.id, Some(Id::Num(n as i64)));
    }
    // A request that produces no reply fails at once rather than waiting forever.
    assert_eq!(
        up.call(req(1, "silent"), None).await,
        Err(CallError::Failed("the upstream returned no reply".into()))
    );
    assert_eq!(
        up.call(req(1, "trap"), None).await,
        Err(CallError::Failed("sandbox: all fuel consumed".into()))
    );
    // Neither took the upstream down.
    assert_eq!(tag(&up.call(req(1, "after"), None).await.unwrap()), "after");
    assert_eq!(up.down_reason(), None);
    assert_eq!(up.inflight(), 0);
}

/// A send that finds the connection closed takes the upstream down, and the
/// call it was sending fails as down, not as a one-off failure. Replies and
/// notifications the upstream sent before it went still reach their callers.
#[tokio::test(start_paused = true)]
async fn a_send_that_finds_the_connection_gone_still_delivers_what_came_before() {
    let (up, mut far, gate) = scripted(16, 1);
    let mut notes = up.subscribe();
    let answered = spawn_call(&up, req(1, "answered"), None);
    let sent = next(&mut far).await;
    // The actor is now stuck sending the next request.
    let stuck = spawn_call(&up, req(2, "stuck"), None);
    tokio::task::yield_now().await;
    // The upstream answers the first call, says one more thing, and hangs up.
    far.send(echo(&sent)).await.unwrap();
    far.send(Message::notification("notifications/message", None))
        .await
        .unwrap();
    drop(far);
    gate.add_permits(1);

    assert_eq!(
        stuck.await.unwrap(),
        Err(CallError::Down("transport closed".into()))
    );
    assert_eq!(tag(&answered.await.unwrap().unwrap()), "answered");
    assert_eq!(
        notes.recv().await.unwrap().method(),
        Some("notifications/message")
    );
    assert_eq!(up.down_reason().as_deref(), Some("transport closed"));
    assert_eq!(
        up.call(req(3, "later"), None).await,
        Err(CallError::Down("transport closed".into()))
    );
    assert_eq!(up.inflight(), 0);
}

#[tokio::test]
async fn a_watch_wakes_when_the_upstream_goes_down() {
    let (up, far) = upstream(16);
    let watch = up.watch();
    let waiting = tokio::spawn({
        let watch = watch.clone();
        async move { watch.down().await }
    });
    tokio::task::yield_now().await;
    assert!(!waiting.is_finished());
    assert_eq!(watch.reason(), None);
    drop(far);
    let reason = "the upstream closed the connection";
    assert_eq!(&*waiting.await.unwrap(), reason);
    // A watch made after the fact answers at once.
    assert_eq!(&*up.watch().down().await, reason);
    assert_eq!(watch.reason().as_deref(), Some(reason));
}

#[tokio::test]
async fn a_watch_does_not_keep_the_connection_open() {
    let (up, mut far) = upstream(16);
    let watch = up.watch();
    drop(up);
    assert!(
        far.recv().await.unwrap().is_none(),
        "the last handle is gone, so the transport closes"
    );
    // Closing because nobody holds a handle is not going down.
    assert_eq!(watch.reason(), None);
}

#[tokio::test(start_paused = true)]
async fn failures_in_a_row_are_counted_until_a_reply() {
    let (up, mut far, _gate) = scripted(16, 100);
    assert_eq!(up.failures(), 0);
    assert!(matches!(
        up.call(req(1, "boom"), None).await,
        Err(CallError::Failed(_))
    ));
    let limit = Duration::from_millis(50);
    assert_eq!(
        up.call(req(2, "unanswered"), Some(limit)).await,
        Err(CallError::Timeout(limit))
    );
    let _unanswered = next(&mut far).await;
    assert_eq!(up.failures(), 2, "a timeout counts as a failure");
    assert_eq!(up.down_reason(), None, "with no limit, never down");

    let call = spawn_call(&up, req(3, "fine"), None);
    let sent = next(&mut far).await;
    far.send(echo(&sent)).await.unwrap();
    call.await.unwrap().unwrap();
    assert_eq!(up.failures(), 0);
}

#[tokio::test]
async fn a_run_reaching_its_limit_takes_the_upstream_down() {
    let (near, _far) = duplex_pair();
    let gate = Arc::new(Semaphore::new(100));
    let transport = Scripted { inner: near, gate };
    let options = HandleOptions {
        max_inflight: 16,
        trip_after: Some(2),
    };
    let up = UpstreamHandle::spawn_with("scripted", Box::new(transport), options);
    let watch = up.watch();
    for n in 0..2 {
        assert_eq!(
            up.call(req(n, "boom"), None).await,
            Err(CallError::Failed("http: POST returned 500".into()))
        );
    }
    let reason = "2 calls in a row failed; the last: http: POST returned 500";
    assert_eq!(&*watch.down().await, reason);
    assert_eq!(
        up.call(req(3, "fine"), None).await,
        Err(CallError::Down(reason.into()))
    );
}
