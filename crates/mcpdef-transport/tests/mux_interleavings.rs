// SPDX-License-Identifier: Apache-2.0
//! `UpstreamHandle` under random interleavings.
//!
//! Each case starts a handful of calls at random times against a mock upstream
//! that answers each after a random delay, or never. Calls share caller ids and
//! carry random timeouts, and the mock mixes in noise: replies to ids nobody
//! sent, notifications, and requests of its own that reuse a live call's id.
//! Some cases make each send take time, so calls queue behind the actor, and
//! some drop the connection partway through. Time is Tokio's paused clock, so
//! every case is deterministic and runs in milliseconds however long its
//! timeouts are.
//!
//! What must hold in every case:
//! - a reply only ever reaches the call that sent its request, under that
//!   call's own id;
//! - the upstream never has more than `max_inflight` requests outstanding whose
//!   callers are still waiting;
//! - no request starts going out after its caller gave up (one already going
//!   out when its caller gives up cannot be taken back);
//! - a call that is answered and has no timeout gets its reply, unless the
//!   connection drops first, in which case it fails as down;
//! - notifications arrive complete and in order, and no slot outlives its call;
//! - each request of the upstream's own is answered, under its own id, with
//!   `-32601`: MCPdef relays none of them.
//!
//! When no call has to queue, no send takes time and the connection holds, the
//! outcome is also exactly predictable, and checked.

use async_trait::async_trait;
use mcpdef_core::{Id, Message};
use mcpdef_transport::{duplex_pair, CallError, Duplex, Transport, TransportError, UpstreamHandle};
use proptest::prelude::*;
use serde_json::json;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// Times are in steps of 10 ms. Timeouts end 5 ms into a step, so a reply and
/// a timeout never land on the same instant.
const STEP: u64 = 10;

#[derive(Clone, Debug)]
struct Call {
    /// Drawn from three values, so callers share ids.
    caller_id: i64,
    start: u64,
    /// How long the upstream takes to answer.
    delay: u64,
    answered: bool,
    timeout: Option<u64>,
    /// How many noise messages the upstream sends when the request arrives.
    noise: u8,
    /// How long sending the request takes, in cases with slow sends.
    send: u64,
}

impl Call {
    fn timeout(&self) -> Option<Duration> {
        self.timeout
            .map(|t| Duration::from_millis(t * STEP + STEP / 2))
    }
}

fn call() -> impl Strategy<Value = Call> {
    (
        0i64..3,
        0u64..6,
        0u64..9,
        any::<bool>(),
        proptest::option::of(1u64..9),
        0u8..4,
        0u64..3,
    )
        .prop_map(
            |(caller_id, start, delay, answered, timeout, noise, send)| Call {
                caller_id,
                start,
                delay,
                answered,
                // A call that is never answered needs a timeout, or it waits forever.
                timeout: if answered {
                    timeout
                } else {
                    Some(timeout.unwrap_or(4))
                },
                noise,
                send,
            },
        )
}

/// The actor's end of the pipe, taking each call's `send` steps to send it.
struct SlowSends {
    inner: Duplex,
    calls: Arc<Vec<Call>>,
    log: Arc<Mutex<Log>>,
}

#[async_trait]
impl Transport for SlowSends {
    async fn send(&mut self, msg: Message) -> Result<(), TransportError> {
        // An answer to a request of the upstream's own belongs to no call.
        if msg.is_response() {
            return self.inner.send(msg).await;
        }
        let i = msg.params.as_ref().unwrap()["i"].as_u64().unwrap() as usize;
        {
            let mut log = self.log.lock().unwrap();
            if log.returned.contains(&i) {
                log.violations.push(format!(
                    "call {i} started going out after its caller gave up"
                ));
            }
        }
        tokio::time::sleep(Duration::from_millis(self.calls[i].send * STEP)).await;
        self.inner.send(msg).await
    }

    async fn recv(&mut self) -> Result<Option<Message>, TransportError> {
        self.inner.recv().await
    }
}

/// What the mock upstream saw, and the callers' state as it saw it.
#[derive(Default)]
struct Log {
    /// The private ids requests arrived under, in arrival order.
    ids: Vec<Id>,
    /// Calls whose request arrived.
    received: Vec<usize>,
    /// Calls the upstream has answered.
    answered: HashSet<usize>,
    /// Calls whose caller got its result back and stopped waiting.
    returned: HashSet<usize>,
    /// Broken invariants, noticed as requests arrived.
    violations: Vec<String>,
    /// Notifications numbered so far, and actually sent: a hang-up can strand
    /// some in the outbox.
    notifications_queued: u64,
    notifications_sent: u64,
    /// Requests of the upstream's own it sent, and the answers it got back.
    asked: u64,
    answers: Vec<Message>,
}

/// The mock upstream. Replies go out through `outbox`, so a delayed reply can
/// be sent while the next request is being read. At `disconnect`, it hangs up.
async fn mock(
    mut far: Duplex,
    calls: Arc<Vec<Call>>,
    max_inflight: usize,
    disconnect: Option<Duration>,
    log: Arc<Mutex<Log>>,
) {
    let (outbox, mut queued) = mpsc::unbounded_channel::<(Option<usize>, Message)>();
    let hang_up = tokio::time::sleep(disconnect.unwrap_or(Duration::MAX / 4));
    tokio::pin!(hang_up);
    loop {
        tokio::select! {
            () = &mut hang_up, if disconnect.is_some() => return,
            request = far.recv() => {
                let Ok(Some(request)) = request else { return };
                if request.is_response() {
                    log.lock().unwrap().answers.push(request);
                    continue;
                }
                let i = request.params.as_ref().unwrap()["i"].as_u64().unwrap() as usize;
                let id = request.id.clone().unwrap();
                let call = &calls[i];
                {
                    let mut log = log.lock().unwrap();
                    log.ids.push(id.clone());
                    log.received.push(i);
                    let outstanding = log
                        .received
                        .iter()
                        .filter(|j| !log.answered.contains(j) && !log.returned.contains(j))
                        .count();
                    if outstanding > max_inflight {
                        log.violations.push(format!(
                            "{outstanding} requests outstanding, over the cap of {max_inflight}"
                        ));
                    }
                }
                for k in 0..call.noise {
                    let noise = match k % 3 {
                        0 => Message::result(
                            [Id::Num(-1), Id::Num(0), Id::Num(99), Id::Str("stray".into())]
                                [usize::from(k / 3) % 4]
                                .clone(),
                            json!({ "i": "stray" }),
                        ),
                        1 => {
                            let mut log = log.lock().unwrap();
                            let n = log.notifications_queued;
                            log.notifications_queued += 1;
                            Message::notification("notifications/progress", Some(json!({ "n": n })))
                        }
                        _ => Message::request(id.clone(), "roots/list", Some(json!({ "i": "stray" }))),
                    };
                    let _ = outbox.send((None, noise));
                }
                if call.answered {
                    let reply = Message::result(id, json!({ "i": i }));
                    let outbox = outbox.clone();
                    let delay = Duration::from_millis(call.delay * STEP);
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let _ = outbox.send((Some(i), reply));
                    });
                }
            }
            Some((answers, message)) = queued.recv() => {
                let notification = message.is_notification();
                let asking = message.is_request();
                if let Some(i) = answers {
                    log.lock().unwrap().answered.insert(i);
                }
                if far.send(message).await.is_err() {
                    return;
                }
                if notification {
                    log.lock().unwrap().notifications_sent += 1;
                }
                if asking {
                    log.lock().unwrap().asked += 1;
                }
            }
        }
    }
}

/// The shape of one case, beyond its calls.
#[derive(Clone, Debug)]
struct Case {
    max_inflight: usize,
    slow_sends: bool,
    /// When the upstream hangs up, in steps (ending mid-step, like timeouts).
    disconnect: Option<u64>,
}

fn case() -> impl Strategy<Value = Case> {
    (
        1usize..5,
        any::<bool>(),
        proptest::option::weighted(0.25, 0u64..10),
    )
        .prop_map(|(max_inflight, slow_sends, disconnect)| Case {
            max_inflight,
            slow_sends,
            disconnect,
        })
}

fn run(case: Case, mut calls: Vec<Call>) -> Result<(), TestCaseError> {
    let Case {
        max_inflight,
        slow_sends,
        disconnect,
    } = case;
    if !slow_sends {
        for call in &mut calls {
            call.send = 0;
        }
    }
    let disconnect = disconnect.map(|d| Duration::from_millis(d * STEP + STEP / 2));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    runtime.block_on(async move {
        let (near, far) = duplex_pair();
        let calls = Arc::new(calls);
        let log = Arc::new(Mutex::new(Log::default()));
        let transport = SlowSends {
            inner: near,
            calls: Arc::clone(&calls),
            log: Arc::clone(&log),
        };
        let up = UpstreamHandle::spawn("prop", Box::new(transport), max_inflight);
        let mut notes = up.subscribe();
        tokio::spawn(mock(
            far,
            Arc::clone(&calls),
            max_inflight,
            disconnect,
            Arc::clone(&log),
        ));

        let callers: Vec<_> = calls
            .iter()
            .enumerate()
            .map(|(i, call)| {
                let (up, call, log) = (up.clone(), call.clone(), Arc::clone(&log));
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(call.start * STEP)).await;
                    let request = Message::request(
                        Id::Num(call.caller_id),
                        "tools/call",
                        Some(json!({ "i": i })),
                    );
                    let result = up.call(request, call.timeout()).await;
                    log.lock().unwrap().returned.insert(i);
                    result
                })
            })
            .collect();
        let mut results = Vec::new();
        for caller in callers {
            results.push(caller.await.unwrap());
        }
        // Let every late reply arrive, and be dropped.
        tokio::time::sleep(Duration::from_secs(1)).await;

        let log = log.lock().unwrap();
        prop_assert!(log.violations.is_empty(), "{:?}", log.violations);
        let distinct: HashSet<String> = log.ids.iter().map(|id| format!("{id:?}")).collect();
        prop_assert_eq!(distinct.len(), log.ids.len(), "a private id was reused");
        for (i, (call, result)) in calls.iter().zip(&results).enumerate() {
            match result {
                Ok(reply) => {
                    prop_assert!(
                        log.answered.contains(&i),
                        "call {} got a reply nobody sent it",
                        i
                    );
                    prop_assert_eq!(&reply.result.as_ref().unwrap()["i"], &json!(i));
                    prop_assert_eq!(&reply.id, &Some(Id::Num(call.caller_id)));
                }
                Err(CallError::Timeout(limit)) => {
                    prop_assert_eq!(Some(*limit), call.timeout());
                }
                Err(CallError::Down(why)) => {
                    prop_assert!(disconnect.is_some(), "call {} down with no disconnect", i);
                    // Noticed by reading, or by a send that found the pipe closed.
                    prop_assert!(
                        ["the upstream closed the connection", "transport closed"]
                            .contains(&&**why),
                        "call {} down because {}",
                        i,
                        why
                    );
                    // Its reply, had it been sent, would have come first.
                    prop_assert!(!log.answered.contains(&i), "call {} lost a sent reply", i);
                }
                Err(other) => prop_assert!(false, "call {} failed: {:?}", i, other),
            }
            if call.answered && call.timeout.is_none() {
                prop_assert!(
                    result.is_ok() || disconnect.is_some(),
                    "call {} lost its reply",
                    i
                );
            }
            if calls.len() <= max_inflight && !slow_sends && disconnect.is_none() {
                // Nothing queued, so each request went out when its call started.
                let in_time = call.timeout.is_none_or(|t| call.delay <= t);
                prop_assert_eq!(result.is_ok(), call.answered && in_time, "call {}", i);
            }
        }
        for n in 0..log.notifications_sent {
            let note = notes.try_recv().expect("every notification arrives");
            prop_assert_eq!(&note.params.unwrap()["n"], &json!(n));
        }
        prop_assert!(notes.try_recv().is_err(), "nothing but the notifications");
        for answer in &log.answers {
            let error = answer.error.as_ref();
            prop_assert!(
                error.is_some_and(|e| e["code"] == -32601
                    && e["message"].as_str().unwrap().contains("`roots/list`")),
                "{:?}",
                answer
            );
            // Under the id the upstream asked with: a live call's.
            prop_assert!(
                log.ids.contains(answer.id.as_ref().unwrap()),
                "{:?}",
                answer
            );
        }
        if disconnect.is_none() {
            prop_assert_eq!(
                log.answers.len() as u64,
                log.asked,
                "every request answered"
            );
        }
        prop_assert_eq!(up.inflight(), 0, "a slot outlived its call");
        prop_assert_eq!(
            up.down_reason().is_some(),
            disconnect.is_some(),
            "down exactly when the upstream hung up"
        );
        Ok(())
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn every_reply_reaches_its_own_caller(
        case in case(),
        calls in proptest::collection::vec(call(), 1..12),
    ) {
        run(case, calls)?;
    }
}
