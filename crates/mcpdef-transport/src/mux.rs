// SPDX-License-Identifier: Apache-2.0
//! `mux` — many concurrent calls over one upstream connection. See
//! [`UpstreamHandle`].

use crate::{answer_request, note_refused, Exchange, Transport, TransportError};
use futures_util::FutureExt;
use mcpdef_core::{Id, Message};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot, Notify, OwnedSemaphorePermit, Semaphore};

/// How many calls may wait on one upstream at once, unless configured otherwise.
pub const DEFAULT_MAX_INFLIGHT: usize = 16;

/// The first private id. Past the ids the opening uses, `0` and one for each
/// page of `tools/list` it reads, so a stray reply to the opening is never
/// taken for a call's.
const FIRST_ID: i64 = 100;

/// How many notifications a subscriber may fall behind by before it misses some.
const NOTIFICATION_BUFFER: usize = 64;

/// How an [`UpstreamHandle`] treats its upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleOptions {
    /// The most calls that may wait on the upstream at once. At least 1.
    pub max_inflight: usize,
    /// Declare the upstream down once this many calls in a row have failed or
    /// timed out. `None` never does. For a peer with no connection to lose, such
    /// as a Streamable-HTTP endpoint, this is the only way it goes down.
    pub trip_after: Option<u32>,
}

impl Default for HandleOptions {
    fn default() -> Self {
        HandleOptions {
            max_inflight: DEFAULT_MAX_INFLIGHT,
            trip_after: None,
        }
    }
}

/// Why [`UpstreamHandle::call`] returned no reply.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CallError {
    /// No reply within the call's timeout. The upstream may still answer; that
    /// reply is dropped.
    #[error("no reply within {}ms", .0.as_millis())]
    Timeout(Duration),
    /// The upstream's connection closed or failed, or too many calls in a row
    /// failed (see [`HandleOptions::trip_after`]). This call failed, and every
    /// later call on the handle fails at once.
    #[error("the upstream is down: {0}")]
    Down(Arc<str>),
    /// This call failed, but the upstream is still up: sending its request
    /// failed for that request alone, or the upstream answered it with nothing.
    /// The message is the transport's.
    #[error("{0}")]
    Failed(Arc<str>),
    /// The upstream refused the credentials the call's request carried
    /// ([`TransportError::Unauthorized`]), and fresh ones changed nothing. It
    /// counts as a failure, like [`Failed`](Self::Failed).
    #[error("{0}")]
    Unauthorized(Arc<str>),
    /// The call's request was not sent: there were no credentials to send
    /// with it ([`TransportError::Credentials`]), since a secret could not be
    /// read or a token endpoint gave no token. The message says why. It counts
    /// as a failure, like [`Failed`](Self::Failed).
    #[error("{0}")]
    NoCredentials(Arc<str>),
}

/// The error for a call whose request could not be sent or answered, while
/// the upstream stays up.
fn failed(error: TransportError) -> CallError {
    match error {
        TransportError::Unauthorized(_) => CallError::Unauthorized(error.to_string().into()),
        TransportError::Credentials(why) => CallError::NoCredentials(why.into()),
        error => CallError::Failed(error.to_string().into()),
    }
}

/// Hand each notification `transport` already holds to `notifications`'
/// subscribers, without waiting for more. Anything else it holds is dropped:
/// no caller is waiting for it.
fn publish_held(transport: &mut dyn Transport, notifications: &Notifications) {
    // Unconstrained: a task out of its scheduling budget would find even a
    // message already queued not ready.
    while let Some(Ok(Some(message))) = tokio::task::unconstrained(transport.recv()).now_or_never()
    {
        if message.is_notification() {
            if let Some(subscribers) = notifications.get() {
                let _ = subscribers.send(message);
            }
        }
    }
}

/// A cloneable handle to one upstream connection, shared by every call to it.
///
/// The handle fronts a task, the *actor*, that owns the upstream's
/// [`Transport`]. Callers hand it requests; it writes them to the transport one
/// at a time and routes each reply back to whoever sent the request.
///
/// A transport with a [concurrent side](Transport::concurrent), such as a
/// Streamable-HTTP endpoint, needs no actor: each call goes straight to it from
/// its caller's task, and many run at once. Private ids, the in-flight cap and
/// notifications work the same either way.
///
/// - **Private ids.** A request goes out under an id from the handle's own
///   counter, and its reply comes back under the caller's id. Two callers may use
///   the same id (two downstream clients both sending `id: 1` is the normal
///   case), and neither sees the other's reply.
/// - **Routing by id.** Replies are matched to requests through a map, so they
///   may arrive in any order. A reply that matches no waiting call, such as one
///   that arrives after its call timed out, is dropped. It is never handed to
///   another call.
/// - **Notifications** from the upstream reach every receiver made by
///   [`subscribe`](Self::subscribe). Requests from the upstream (sampling,
///   roots, elicitation) are not relayed yet, and are dropped as before.
/// - **An in-flight cap.** At most `max_inflight` calls wait on the upstream at
///   once. Further calls queue for a slot, and the queueing counts against their
///   timeout. A call gives its slot back when its caller stops waiting.
/// - **Down.** Once the connection closes or fails, every waiting call fails
///   with [`CallError::Down`], and so does every later one, at once. A send that
///   fails because the connection is gone counts; one that fails only its own
///   request, such as an HTTP error status or a sandbox trap, does not. A
///   Streamable-HTTP session the upstream no longer knows counts too.
///   [`watch`](Self::watch) waits for this.
/// - **A run of failures.** The handle counts the calls in a row that failed or
///   timed out ([`failures`](Self::failures)). With
///   [`HandleOptions::trip_after`] set, reaching it takes the upstream down.
///
/// The actor writes one request at a time and does not read while it writes.
/// On stdio that could deadlock only if both directions filled their pipes at
/// once: a request larger than the pipe buffer, sent while the upstream is
/// itself blocked writing a large reply instead of reading.
///
/// Dropping the last handle stops the actor and closes the transport.
#[derive(Clone)]
pub struct UpstreamHandle {
    shared: Arc<Shared>,
}

struct Shared {
    /// The upstream's id, for diagnostics.
    name: Arc<str>,
    route: Route,
    slots: Arc<Semaphore>,
    max_inflight: usize,
    next_id: AtomicI64,
    notifications: Notifications,
    /// Why the upstream is down, once it is.
    down: Arc<DownSignal>,
    /// Calls in a row that failed or timed out.
    failures: AtomicU64,
    trip_after: Option<u32>,
}

/// Why an upstream is down, once it is, and a way to wait for that.
#[derive(Default)]
struct DownSignal {
    reason: OnceLock<Arc<str>>,
    changed: Notify,
}

impl DownSignal {
    /// Record why the upstream went down, unless a reason is already recorded,
    /// and return the one that stands.
    fn set(&self, reason: impl Into<Arc<str>>) -> Arc<str> {
        let mut first = false;
        let reason = Arc::clone(self.reason.get_or_init(|| {
            first = true;
            reason.into()
        }));
        if first {
            self.changed.notify_waiters();
        }
        reason
    }

    fn get(&self) -> Option<&Arc<str>> {
        self.reason.get()
    }

    async fn wait(&self) -> Arc<str> {
        loop {
            // Register before looking, so a reason set in between still wakes us.
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(reason) = self.get() {
                return Arc::clone(reason);
            }
            changed.await;
        }
    }
}

/// Waits for an upstream to go down, without keeping its connection open the way
/// a handle does. Made by [`UpstreamHandle::watch`].
#[derive(Clone)]
pub struct DownWatch(Arc<DownSignal>);

impl DownWatch {
    /// Resolves once the upstream is down, with why. Never resolves if the last
    /// handle is dropped first: that closes the connection without it failing.
    pub async fn down(&self) -> Arc<str> {
        self.0.wait().await
    }

    /// Why the upstream is down, if it is.
    pub fn reason(&self) -> Option<Arc<str>> {
        self.0.get().cloned()
    }
}

/// Where a call goes.
enum Route {
    /// To the actor that owns the transport.
    Actor(mpsc::UnboundedSender<Command>),
    /// Straight to a peer that takes concurrent requests.
    Direct(Arc<dyn Exchange>),
}

/// The notification channel, made on the first [`UpstreamHandle::subscribe`]:
/// an upstream nobody listens to keeps no buffer.
type Notifications = Arc<OnceLock<broadcast::Sender<Message>>>;

enum Command {
    /// Send `request` (already under its private `id`) and reply to `reply`.
    ///
    /// The request is boxed because the queue allocates its slots in blocks, and
    /// every idle upstream holds one.
    Call {
        id: i64,
        request: Box<Message>,
        reply: oneshot::Sender<Result<Message, CallError>>,
        slot: OwnedSemaphorePermit,
    },
    /// The caller of `id` stopped waiting.
    Forget(i64),
}

impl UpstreamHandle {
    /// Take over an open `transport` and return the first handle to it: its
    /// concurrent side if it has one, or else a new actor that owns it.
    ///
    /// Open means the connect handshake has already run on it. `max_inflight` is
    /// at least 1. Must be called within a Tokio runtime.
    pub fn spawn(
        name: impl Into<String>,
        transport: Box<dyn Transport>,
        max_inflight: usize,
    ) -> UpstreamHandle {
        let options = HandleOptions {
            max_inflight,
            ..HandleOptions::default()
        };
        Self::spawn_with(name, transport, options)
    }

    /// [`spawn`](Self::spawn), with every option.
    pub fn spawn_with(
        name: impl Into<String>,
        transport: Box<dyn Transport>,
        options: HandleOptions,
    ) -> UpstreamHandle {
        Self::start(name, transport, options, Notifications::default())
    }

    /// [`spawn_with`](Self::spawn_with), subscribed from the start: the
    /// receiver gets every notification the upstream sends once it is handed
    /// over, including one already waiting on the transport. A
    /// [`subscribe`](Self::subscribe) after spawning misses whatever the actor
    /// reads first.
    pub fn spawn_listening(
        name: impl Into<String>,
        transport: Box<dyn Transport>,
        options: HandleOptions,
    ) -> (UpstreamHandle, broadcast::Receiver<Message>) {
        let (sender, receiver) = broadcast::channel(NOTIFICATION_BUFFER);
        let notifications = Notifications::new(OnceLock::from(sender));
        (
            Self::start(name, transport, options, notifications),
            receiver,
        )
    }

    /// Take `transport` over, handing the notifications it carries to
    /// `notifications`' subscribers.
    ///
    /// A transport with a concurrent side is called through that, and nothing
    /// reads the transport itself again. What it already holds, which can be
    /// the rest of the answer to the opening's last request, goes to
    /// subscribers now, as the notifications in a call's answer do.
    fn start(
        name: impl Into<String>,
        mut transport: Box<dyn Transport>,
        options: HandleOptions,
        notifications: Notifications,
    ) -> UpstreamHandle {
        let max_inflight = options.max_inflight.clamp(1, Semaphore::MAX_PERMITS);
        let down = Arc::new(DownSignal::default());
        let name: Arc<str> = name.into().into();
        let route = match transport.concurrent() {
            Some(peer) => {
                publish_held(&mut *transport, &notifications);
                Route::Direct(peer)
            }
            None => {
                let (commands, queue) = mpsc::unbounded_channel();
                let actor = Actor {
                    name: Arc::clone(&name),
                    inline: transport.replies_inline(),
                    transport,
                    queue,
                    waiting: HashMap::new(),
                    notifications: Arc::clone(&notifications),
                    down: Arc::clone(&down),
                };
                tokio::spawn(actor.run());
                Route::Actor(commands)
            }
        };
        UpstreamHandle {
            shared: Arc::new(Shared {
                name,
                route,
                slots: Arc::new(Semaphore::new(max_inflight)),
                max_inflight,
                next_id: AtomicI64::new(FIRST_ID),
                notifications,
                down,
                failures: AtomicU64::new(0),
                trip_after: options.trip_after,
            }),
        }
    }

    /// Send `request` and wait for its reply, for at most `timeout` if one is
    /// given.
    ///
    /// The request's id is swapped for a private one on the way out and put back
    /// on the reply, so any id will do. The timeout covers the whole call:
    /// waiting for a slot, sending, and waiting for the reply. A caller that
    /// stops waiting, whether by timing out or by dropping this future, gives
    /// its slot back, and a reply that arrives after that is dropped.
    pub async fn call(
        &self,
        mut request: Message,
        timeout: Option<Duration>,
    ) -> Result<Message, CallError> {
        let Some(caller_id) = request.id.take() else {
            return Err(CallError::Failed(
                "only a request, which has an id, gets a reply".into(),
            ));
        };
        let round_trip = self.round_trip(request);
        let outcome = match timeout {
            Some(limit) => tokio::time::timeout(limit, round_trip)
                .await
                .unwrap_or(Err(CallError::Timeout(limit))),
            None => round_trip.await,
        };
        self.tally(&outcome);
        let mut reply = outcome?;
        reply.id = Some(caller_id);
        Ok(reply)
    }

    /// Count a call's outcome toward the run of failures, and declare the
    /// upstream down once the run reaches [`HandleOptions::trip_after`].
    fn tally(&self, outcome: &Result<Message, CallError>) {
        let shared = &*self.shared;
        let failure = match outcome {
            // Any reply ends the run, an error reply included: the upstream
            // answered. Most calls find it at zero, so they only read it.
            Ok(_) => {
                if shared.failures.load(Ordering::Relaxed) != 0 {
                    shared.failures.store(0, Ordering::Relaxed);
                }
                return;
            }
            Err(CallError::Down(_)) => return,
            Err(failure) => failure,
        };
        let run = shared.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(limit) = shared.trip_after {
            if run >= u64::from(limit) {
                shared
                    .down
                    .set(format!("{run} calls in a row failed; the last: {failure}"));
            }
        }
    }

    async fn round_trip(&self, mut request: Message) -> Result<Message, CallError> {
        let shared = &*self.shared;
        if let Some(reason) = shared.down.get() {
            return Err(CallError::Down(Arc::clone(reason)));
        }
        let slot = Arc::clone(&shared.slots)
            .acquire_owned()
            .await
            .map_err(|_| self.down_error())?;
        let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
        request.id = Some(Id::Num(id));
        let commands = match &shared.route {
            Route::Direct(peer) => {
                let answer = peer.exchange(&request).await;
                drop(slot);
                return match answer {
                    Ok(answer) => self.reply_among(id, answer),
                    // The peer is there, but this connection to it is not:
                    // every later call would fail the same way.
                    Err(e @ (TransportError::SessionExpired | TransportError::Closed)) => {
                        Err(CallError::Down(shared.down.set(e.to_string())))
                    }
                    Err(e) => Err(failed(e)),
                };
            }
            Route::Actor(commands) => commands,
        };
        let (reply, answer) = oneshot::channel();
        commands
            .send(Command::Call {
                id,
                request: Box::new(request),
                reply,
                slot,
            })
            .map_err(|_| self.down_error())?;
        // From here the actor may be holding the call, so a caller that stops
        // waiting must say so. Otherwise its slot waits for a reply that may
        // never come.
        let mut waiting = Waiting {
            commands,
            id,
            armed: true,
        };
        let answer = answer.await;
        waiting.armed = false;
        answer.unwrap_or_else(|_| Err(self.down_error()))
    }

    /// The reply to call `id` among what a direct exchange brought back.
    /// Notifications go to subscribers on the way.
    ///
    /// An exchange carries only this request, so the reply is the response under
    /// its id or under none: a peer that could not read the id answers with a
    /// null one (a JSON-RPC parse or invalid-request error).
    fn reply_among(&self, id: i64, answer: Vec<Message>) -> Result<Message, CallError> {
        let mut reply = None;
        for message in answer {
            if message.is_response() {
                let ours = match &message.id {
                    Some(Id::Num(n)) => *n == id,
                    None => true,
                    Some(Id::Str(_)) => false,
                };
                if ours && reply.is_none() {
                    reply = Some(message);
                }
            } else if message.is_notification() {
                if let Some(subscribers) = self.shared.notifications.get() {
                    let _ = subscribers.send(message);
                }
            } else if message.is_request() {
                // The exchange answered it while the peer waited.
                note_refused(&self.shared.name, &message);
            }
        }
        reply.ok_or_else(|| CallError::Failed("the upstream's answer held no reply".into()))
    }

    /// Receive the upstream's notifications from now on.
    ///
    /// A subscriber that falls more than 64 behind misses the oldest, and its
    /// next `recv` says how many.
    pub fn subscribe(&self) -> broadcast::Receiver<Message> {
        self.shared
            .notifications
            .get_or_init(|| broadcast::channel(NOTIFICATION_BUFFER).0)
            .subscribe()
    }

    /// Why the upstream is down, once it is.
    pub fn down_reason(&self) -> Option<Arc<str>> {
        self.shared.down.get().cloned()
    }

    /// A way to wait for this upstream to go down that does not keep its
    /// connection open.
    pub fn watch(&self) -> DownWatch {
        DownWatch(Arc::clone(&self.shared.down))
    }

    /// How many calls in a row have failed or timed out since the last one
    /// that got a reply.
    pub fn failures(&self) -> u64 {
        self.shared.failures.load(Ordering::Relaxed)
    }

    /// The most calls that may wait on this upstream at once.
    pub fn max_inflight(&self) -> usize {
        self.shared.max_inflight
    }

    /// How many calls hold a slot now: sent or about to be, and still awaited.
    pub fn inflight(&self) -> usize {
        self.shared.max_inflight - self.shared.slots.available_permits()
    }

    fn down_error(&self) -> CallError {
        CallError::Down(
            self.shared
                .down
                .get()
                .cloned()
                .unwrap_or_else(|| "its connection task stopped".into()),
        )
    }
}

/// Tells the actor to forget a call whose caller stopped waiting.
struct Waiting<'a> {
    commands: &'a mpsc::UnboundedSender<Command>,
    id: i64,
    armed: bool,
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.commands.send(Command::Forget(self.id));
        }
    }
}

/// The task that owns the transport.
struct Actor {
    /// The upstream's id, for diagnostics.
    name: Arc<str>,
    transport: Box<dyn Transport>,
    /// See [`Transport::replies_inline`].
    inline: bool,
    queue: mpsc::UnboundedReceiver<Command>,
    /// Calls sent and not yet answered, by private id.
    waiting: HashMap<i64, Waiter>,
    notifications: Notifications,
    down: Arc<DownSignal>,
}

struct Waiter {
    reply: oneshot::Sender<Result<Message, CallError>>,
    /// Given back when the call is answered, fails or is forgotten.
    slot: OwnedSemaphorePermit,
}

impl Waiter {
    /// Give the slot back, then the result, so a caller holding its result
    /// never sees its own call still counted in [`UpstreamHandle::inflight`].
    fn finish(self, result: Result<Message, CallError>) {
        let Waiter { reply, slot } = self;
        drop(slot);
        let _ = reply.send(result);
    }
}

impl Actor {
    async fn run(mut self) {
        let closed: Option<Arc<str>> = loop {
            tokio::select! {
                inbound = self.transport.recv(), if !self.inline => match inbound {
                    Ok(Some(message)) => {
                        if let Some(answer) = self.route(message) {
                            // A failed send means the connection is going, and
                            // the next read says so.
                            let _ = self.transport.send(answer).await;
                        }
                    }
                    Ok(None) => break Some("the upstream closed the connection".into()),
                    // One unreadable message does not end the connection. It may
                    // have been a reply; that call then waits for its timeout.
                    Err(TransportError::Decode(e)) => eprintln!(
                        "mcpdef: upstream '{}': dropping a message that is not JSON-RPC: {e}",
                        self.name
                    ),
                    Err(e) => break Some(e.to_string().into()),
                },
                command = self.queue.recv() => match command {
                    Some(Command::Call { id, request, reply, slot }) => {
                        let gone = self.send(id, *request, Waiter { reply, slot }).await;
                        if let (Err(reason), true) = (gone, self.inline) {
                            // Nothing more can arrive from an inline transport.
                            break Some(reason);
                        }
                    }
                    Some(Command::Forget(id)) => {
                        self.waiting.remove(&id);
                    }
                    // Every handle is gone, so nobody is waiting.
                    None => break None,
                },
            }
        };
        if let Some(closed) = closed {
            // The first reason recorded wins: a failed send may have found the
            // connection gone before the end of its stream was read.
            let reason = self.down.set(closed);
            self.queue.close();
            for (_, waiter) in self.waiting.drain() {
                waiter.finish(Err(CallError::Down(Arc::clone(&reason))));
            }
        }
        let _ = self.transport.close().await;
    }

    /// Write one call's request to the upstream, and for an inline transport,
    /// collect the reply that writing it produced.
    ///
    /// `Err` means the connection is gone, and says why. The reason is recorded
    /// at once, so later calls fail without being sent, but the actor keeps
    /// reading: replies the upstream sent before it went may still be buffered,
    /// and their callers get them.
    async fn send(&mut self, id: i64, request: Message, waiter: Waiter) -> Result<(), Arc<str>> {
        if waiter.reply.is_closed() {
            // Its caller stopped waiting before its turn came: send nothing.
            return Ok(());
        }
        if let Some(reason) = self.down.get() {
            waiter.finish(Err(CallError::Down(Arc::clone(reason))));
            return Ok(());
        }
        self.waiting.insert(id, waiter);
        match self.transport.send(request).await {
            Ok(()) => {}
            // A closed peer, or a pipe that can no longer be written: every
            // later send would fail the same way.
            Err(e @ (TransportError::Closed | TransportError::Io(_))) => {
                let reason = self.down.set(e.to_string());
                if let Some(waiter) = self.waiting.remove(&id) {
                    waiter.finish(Err(CallError::Down(Arc::clone(&reason))));
                }
                return Err(reason);
            }
            Err(e) => {
                self.fail(id, failed(e));
                return Ok(());
            }
        }
        if self.inline {
            loop {
                match self.transport.recv().await {
                    Ok(Some(message)) => {
                        if let Some(answer) = self.route(message) {
                            let _ = self.transport.send(answer).await;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        self.fail(id, failed(e));
                        break;
                    }
                }
            }
            // Everything the request produced has been routed. If none of it was
            // the reply, none is coming.
            self.fail(
                id,
                CallError::Failed("the upstream returned no reply".into()),
            );
        }
        Ok(())
    }

    /// Hand a message from the upstream to whoever is waiting for it, and
    /// return what to send back: the answer to a request the upstream made.
    fn route(&mut self, message: Message) -> Option<Message> {
        if message.is_response() {
            // Only numeric private ids were ever sent. Any other id, and any id
            // no longer waited on, is dropped.
            if let Some(Id::Num(id)) = message.id {
                if let Some(waiter) = self.waiting.remove(&id) {
                    waiter.finish(Ok(message));
                }
            }
        } else if message.is_notification() {
            // With no subscriber, a notification has nobody to go to.
            if let Some(subscribers) = self.notifications.get() {
                let _ = subscribers.send(message);
            }
        } else if !self.inline {
            // A request of the upstream's own (elicitation, sampling, roots,
            // ping) is answered at once: it is relayed to no client. An inline
            // peer's is not: the call that made it has run to its end.
            let answer = answer_request(&message);
            if answer.is_some() {
                note_refused(&self.name, &message);
            }
            return answer;
        }
        None
    }

    /// Fail call `id` without taking the upstream down, if it is still waiting.
    fn fail(&mut self, id: i64, why: CallError) {
        if let Some(waiter) = self.waiting.remove(&id) {
            waiter.finish(Err(why));
        }
    }
}
