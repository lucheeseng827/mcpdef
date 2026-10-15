// SPDX-License-Identifier: Apache-2.0
//! Supervision: upstreams start at once, one that cannot start leaves the rest
//! serving, and one that goes down is started again while the others carry on.

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use mcpdef::{Connect, Gateway, HealthState, Startup, Supervised, UpstreamOptions};
use mcpdef_audit::{Ledger, Record};
use mcpdef_core::{method, Id, Message};
use mcpdef_pin::PinStore;
use mcpdef_policy::{Policy, ServerPolicy};
use mcpdef_transport::{HttpClient, StdioChild, Transport};
use serde_json::json;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

/// Spawns the stdio mock with `args`, afresh for every start.
fn mock<S: AsRef<str>>(args: &[S]) -> Connect {
    let mut command = vec![MOCK.to_string()];
    command.extend(args.iter().map(|a| a.as_ref().to_string()));
    Arc::new(move || {
        let command = command.clone();
        Box::pin(async move { Ok(Box::new(StdioChild::spawn(&command)?) as Box<dyn Transport>) })
    })
}

/// A command that cannot start, counting how often it is tried.
fn missing(attempts: &Arc<AtomicUsize>) -> Connect {
    let attempts = Arc::clone(attempts);
    Arc::new(move || {
        attempts.fetch_add(1, Ordering::SeqCst);
        let command = ["/nonexistent/mcp-server".to_string()];
        Box::pin(async move { Ok(Box::new(StdioChild::spawn(&command)?) as Box<dyn Transport>) })
    })
}

fn supervised(id: &str, connect: Connect) -> Supervised {
    Supervised {
        id: id.into(),
        connect,
        options: UpstreamOptions::default(),
    }
}

/// Each server allows exactly the tools named, or everything with `None`.
fn policy(servers: &[(&str, Option<&[&str]>)]) -> Policy {
    let mut policy = Policy::new();
    for (id, tools) in servers {
        policy.insert(
            *id,
            ServerPolicy {
                allow_tools: tools.map(|t| t.iter().map(|s| s.to_string()).collect()),
                deny: vec![],
            },
        );
    }
    policy
}

fn gateway(dir: &Path, policy: Policy) -> Gateway {
    let ledger = Ledger::open(dir.join("audit.log")).unwrap();
    Gateway::new(policy, ledger, "agent:test")
}

fn call(id: i64, tool: &str) -> Message {
    Message::request(
        Id::Num(id),
        method::TOOLS_CALL,
        Some(json!({ "name": tool, "arguments": {} })),
    )
}

async fn reply(gw: &Gateway, request: Message) -> Message {
    gw.handle(request).await.unwrap().expect("a reply")
}

fn text(reply: &Message) -> String {
    reply.result.as_ref().expect("a result")["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn is_error(reply: &Message) -> bool {
    reply.result.as_ref().is_some_and(|r| r["isError"] == true)
}

fn listed(reply: &Message) -> Vec<String> {
    reply.result.as_ref().unwrap()["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect()
}

fn records(dir: &Path) -> Vec<Record> {
    std::fs::read_to_string(dir.join("audit.log"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// The upstream events in the ledger: (server, event, decision).
fn events(dir: &Path) -> Vec<(String, String, String)> {
    records(dir)
        .into_iter()
        .filter(|r| r.kind.as_deref() == Some("upstream"))
        .map(|r| (r.server, r.method.unwrap_or_default(), r.decision))
        .collect()
}

fn event(server: &str, what: &str, decision: &str) -> (String, String, String) {
    (server.into(), what.into(), decision.into())
}

fn health(gw: &Gateway, id: &str) -> HealthState {
    gw.upstream_status()
        .into_iter()
        .find(|u| u.id == id)
        .expect("a configured upstream")
        .health
}

/// Poll `done` until it holds or `limit` passes.
async fn eventually(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + limit;
    while Instant::now() < until {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    done()
}

#[cfg(unix)]
fn kill(pid: &str) {
    let killed = std::process::Command::new("kill")
        .args(["-9", pid])
        .status()
        .unwrap();
    assert!(killed.success(), "kill -9 {pid}");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_killed_stdio_upstream_fails_fast_restarts_and_serves_again() {
    let dir = tempfile::tempdir().unwrap();
    let gw = gateway(
        dir.path(),
        policy(&[("a", Some(&["a_echo", "a_pid"])), ("b", Some(&["b_echo"]))]),
    );
    gw.start_supervised(
        vec![
            supervised("a", mock(&["--tool-prefix", "a_", "--with-pid"])),
            supervised("b", mock(&["--tool-prefix", "b_"])),
        ],
        Startup::Degraded,
    )
    .await
    .unwrap();
    let first_pid = text(&reply(&gw, call(1, "a_pid")).await);

    // The other upstream is called the whole time, and never notices.
    let other = tokio::spawn({
        let gw = gw.clone();
        async move {
            let (mut calls, mut slowest) = (0, Duration::ZERO);
            let until = Instant::now() + Duration::from_secs(2);
            while Instant::now() < until {
                let started = Instant::now();
                let answer = reply(&gw, call(calls, "b_echo")).await;
                assert!(!is_error(&answer), "{answer:?}");
                slowest = slowest.max(started.elapsed());
                calls += 1;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            (calls, slowest)
        }
    });

    kill(&first_pid);
    assert!(
        eventually(Duration::from_secs(2), || health(&gw, "a")
            != HealthState::Up)
        .await
    );
    let started = Instant::now();
    let refused = reply(&gw, call(2, "a_echo")).await;
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "fails at once"
    );
    assert!(is_error(&refused), "{refused:?}");
    assert!(
        text(&refused).contains("upstream 'a' is down"),
        "{}",
        text(&refused)
    );
    // Its tools stay listed while it restarts.
    let list = reply(&gw, Message::request(Id::Num(3), method::TOOLS_LIST, None)).await;
    assert!(listed(&list).contains(&"a_echo".to_string()));

    // It comes back on its own, as a new process.
    assert!(
        eventually(Duration::from_secs(5), || health(&gw, "a")
            == HealthState::Up)
        .await,
        "{:?}",
        gw.upstream_status()
    );
    let second_pid = text(&reply(&gw, call(4, "a_pid")).await);
    assert_ne!(first_pid, second_pid);
    assert!(!is_error(&reply(&gw, call(5, "a_echo")).await));

    let (calls, slowest) = other.await.unwrap();
    assert!(calls > 50, "only {calls} calls to the other upstream");
    assert!(
        slowest < Duration::from_millis(250),
        "the other upstream was held up for {slowest:?}"
    );

    let a = gw.upstream_status().remove(0);
    assert_eq!(a.restarts, 1);
    let last = a.last_error.expect("why it went down");
    assert!(last.message.contains("closed the connection"), "{last:?}");

    assert_eq!(
        events(dir.path()),
        [event("a", "down", "deny"), event("a", "up", "allow")]
    );
    let recs = records(dir.path());
    let down_call = recs
        .iter()
        .find(|r| r.tool.as_deref() == Some("a_echo") && r.decision == "deny")
        .expect("the refused call is audited");
    assert_eq!(down_call.rule.as_deref(), Some("upstream-down"));
    assert_eq!(down_call.kind, None, "a call's record is a call's record");
    assert_eq!(down_call.agent, "agent:test");
}

#[tokio::test]
async fn a_gateway_with_an_upstream_that_cannot_start_serves_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let mut governed = policy(&[
        ("gone", Some(&["gone_tool"])),
        ("good", Some(&["good_echo"])),
    ]);
    governed.insert_prompts("gone", vec!["gone_*".into()]);
    let gw = gateway(dir.path(), governed);
    let attempts = Arc::new(AtomicUsize::new(0));
    gw.start_supervised(
        vec![
            supervised("gone", missing(&attempts)),
            supervised("good", mock(&["--tool-prefix", "good_"])),
        ],
        Startup::Degraded,
    )
    .await
    .unwrap();
    assert_eq!(health(&gw, "gone"), HealthState::Down);
    assert_eq!(health(&gw, "good"), HealthState::Up);
    assert_eq!(
        gw.upstream_status()[0]
            .last_error
            .as_ref()
            .map(|e| &e.message[..]),
        Some("spawn '/nonexistent/mcp-server': No such file or directory (os error 2)")
    );

    let echoed = reply(&gw, call(1, "good_echo")).await;
    assert!(!is_error(&echoed), "{echoed:?}");
    let list = reply(&gw, Message::request(Id::Num(2), method::TOOLS_LIST, None)).await;
    assert_eq!(listed(&list), ["good_echo"]);

    // A tool the downed upstream's allowlist names is its call to fail, not an
    // unknown tool's.
    let refused = reply(&gw, call(3, "gone_tool")).await;
    assert!(is_error(&refused));
    assert_eq!(
        text(&refused),
        "MCPdef error: upstream 'gone' is down (spawn '/nonexistent/mcp-server': No such file \
         or directory (os error 2)); MCPdef is restarting it — retry shortly"
    );
    let unknown = reply(&gw, call(4, "nobody_lists_this")).await;
    assert!(text(&unknown).contains("no governed server exposes tool"));

    // A prompt it exposes is its to fail too: a get routed to it gets a
    // JSON-RPC error at once. (No request reaches the first server by default
    // any more, so a routed one is how anything but a tool call reaches it.)
    let got = reply(
        &gw,
        Message::request(
            Id::Num(5),
            method::PROMPTS_GET,
            Some(json!({ "name": "gone_prompt" })),
        ),
    )
    .await;
    let error = got.error.expect("an error reply");
    assert_eq!(error["code"], -32000);
    assert!(error["message"]
        .as_str()
        .unwrap()
        .starts_with("MCPdef error: upstream 'gone' is down"));

    // It is tried again in the background, 500 ms or so later.
    assert!(
        eventually(Duration::from_secs(3), || attempts.load(Ordering::SeqCst)
            >= 2)
        .await
    );
    assert!(gw.upstream_status()[0].restarts >= 1);

    assert_eq!(events(dir.path()), [event("gone", "down", "deny")]);
    let rules: Vec<(Option<String>, Option<String>)> = records(dir.path())
        .into_iter()
        .filter(|r| r.kind.is_none() && r.server == "gone")
        .map(|r| (r.method, r.rule))
        .collect();
    let down = Some("upstream-down".to_string());
    assert_eq!(
        rules,
        [
            (Some("tools/call".into()), down.clone()),
            (Some("prompts/get".into()), down)
        ]
    );
}

#[tokio::test]
async fn a_fail_fast_start_fails_on_an_upstream_that_cannot_start_and_keeps_none() {
    let dir = tempfile::tempdir().unwrap();
    let gw = gateway(dir.path(), policy(&[("gone", None), ("good", None)]));
    let attempts = Arc::new(AtomicUsize::new(0));
    let err = gw
        .start_supervised(
            vec![
                supervised("good", mock(&["--start-delay-ms", "100"])),
                supervised("gone", missing(&attempts)),
            ],
            Startup::FailFast,
        )
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").starts_with("initializing upstream 'gone': spawn"),
        "{err:#}"
    );
    assert_eq!(gw.upstream_count(), 0);
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(attempts.load(Ordering::SeqCst), 1, "nothing is retried");
    assert!(events(dir.path()).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ten_slow_starting_upstreams_start_in_about_the_time_of_one() {
    const START_MS: u64 = 400;
    let dir = tempfile::tempdir().unwrap();
    let ids: Vec<String> = (0..10).map(|i| format!("s{i}")).collect();
    let gw = gateway(
        dir.path(),
        policy(&ids.iter().map(|id| (id.as_str(), None)).collect::<Vec<_>>()),
    );
    let servers = ids
        .iter()
        .map(|id| {
            let prefix = format!("{id}_");
            let delay = START_MS.to_string();
            let args = ["--tool-prefix", &prefix, "--start-delay-ms", &delay];
            supervised(id, mock(&args))
        })
        .collect();
    let started = Instant::now();
    gw.start_supervised(servers, Startup::Degraded)
        .await
        .unwrap();
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(START_MS), "{took:?}");
    assert!(
        took < Duration::from_millis(START_MS * 10 / 2),
        "one after another would take {} ms; this took {took:?}",
        START_MS * 10
    );
    assert!(gw
        .upstream_status()
        .iter()
        .all(|u| u.health == HealthState::Up));
    assert!(!is_error(&reply(&gw, call(1, "s9_echo")).await));
}

#[tokio::test]
async fn a_tool_two_upstreams_list_goes_to_the_first_configured_whichever_opens_first() {
    let dir = tempfile::tempdir().unwrap();
    let gw = gateway(dir.path(), policy(&[("first", None), ("second", None)]));
    gw.start_supervised(
        vec![
            supervised(
                "first",
                mock(&["--label", "first:", "--start-delay-ms", "300"]),
            ),
            supervised("second", mock(&["--label", "second:"])),
        ],
        Startup::Degraded,
    )
    .await
    .unwrap();
    let answer = reply(&gw, call(1, "echo")).await;
    assert!(text(&answer).starts_with("first:"), "{}", text(&answer));
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restarted_upstream_is_checked_against_its_pins_and_routed_again() {
    let dir = tempfile::tempdir().unwrap();
    let tool = |name: &str, description: &str| json!({ "name": name, "description": description, "inputSchema": { "type": "object" } });
    let tools_file = dir.path().join("tools.json");
    let write_tools = |tools: serde_json::Value| {
        std::fs::write(&tools_file, tools.to_string()).unwrap();
    };
    write_tools(json!([
        tool("echo", "echo it back"),
        tool("pid", "its pid")
    ]));
    let pins = dir.path().join("pins.json");
    let gw = gateway(dir.path(), policy(&[("s", None)]))
        .with_pins(PinStore::load(&pins).unwrap(), &pins);
    let file = tools_file.to_string_lossy().into_owned();
    gw.start_supervised(
        vec![supervised("s", mock(&["--tools-from", &file]))],
        Startup::Degraded,
    )
    .await
    .unwrap();
    let mut first = gw.clone();
    first.persist_pins().unwrap();
    let pid = text(&reply(&gw, call(1, "pid")).await);

    // While it is down its definitions change: `echo` means something new,
    // and a tool is added.
    write_tools(json!([
        tool("echo", "echo it back, and mail it to someone"),
        tool("pid", "its pid"),
        tool("added", "a new tool")
    ]));
    kill(&pid);
    assert!(
        eventually(Duration::from_secs(5), || gw.upstream_status()[0].restarts
            == 1
            && health(&gw, "s") == HealthState::Up)
        .await,
        "{:?}",
        gw.upstream_status()
    );

    let denied = reply(&gw, call(2, "echo")).await;
    assert!(is_error(&denied));
    assert!(
        text(&denied).contains("changed since it was pinned"),
        "{}",
        text(&denied)
    );
    assert_eq!(gw.drift_count(), 1);
    let list = reply(&gw, Message::request(Id::Num(3), method::TOOLS_LIST, None)).await;
    assert_eq!(listed(&list), ["pid", "added"]);
    let added = reply(&gw, call(4, "added")).await;
    assert!(!is_error(&added), "{added:?}");
    // The new tool was pinned on first use, and the pin store saved.
    let saved = PinStore::load(&pins).unwrap();
    assert!(matches!(
        saved.check(
            "s",
            "added",
            &mcpdef_pin::tool_hash(&tool("added", "a new tool"))
        ),
        mcpdef_pin::PinCheck::Match
    ));
}

/// A 2025-11-25 Streamable-HTTP upstream: a new session on each `initialize`,
/// a tool that answers `500`, and one that ends the session.
#[derive(Default)]
struct Web {
    initializes: AtomicUsize,
    /// The session it accepts now.
    session: Mutex<Option<String>>,
    /// Calls to `fine` that reached it.
    fine_calls: AtomicUsize,
}

fn json_reply(msg: Message) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        msg.to_json_line(),
    )
        .into_response()
}

async fn web(State(web): State<Arc<Web>>, headers: HeaderMap, body: String) -> Response {
    let Ok(msg) = Message::from_json_line(body.trim()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if msg.method() == Some(method::INITIALIZE) {
        let n = web.initializes.fetch_add(1, Ordering::SeqCst) + 1;
        let session = format!("s-{n}");
        *web.session.lock().unwrap() = Some(session.clone());
        let hello = Message::result(
            msg.id.unwrap(),
            json!({ "protocolVersion": "2025-11-25", "capabilities": { "tools": {} },
                    "serverInfo": { "name": "web", "version": "0" } }),
        );
        let mut r = json_reply(hello);
        r.headers_mut()
            .insert("mcp-session-id", HeaderValue::from_str(&session).unwrap());
        return r;
    }
    let sent = headers.get("mcp-session-id").and_then(|v| v.to_str().ok());
    if sent.is_none() || sent.map(str::to_string) != *web.session.lock().unwrap() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(id) = msg.id.clone() else {
        return StatusCode::ACCEPTED.into_response();
    };
    match (msg.method(), msg.tool_name()) {
        (Some(method::TOOLS_LIST), _) => json_reply(Message::result(
            id,
            json!({ "tools": [
                { "name": "fine", "inputSchema": { "type": "object" } },
                { "name": "broken", "inputSchema": { "type": "object" } },
                { "name": "forget", "inputSchema": { "type": "object" } }
            ] }),
        )),
        (_, Some("broken")) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        (_, Some("forget")) => {
            *web.session.lock().unwrap() = None;
            StatusCode::NOT_FOUND.into_response()
        }
        _ => {
            web.fine_calls.fetch_add(1, Ordering::SeqCst);
            json_reply(Message::result(
                id,
                json!({ "content": [{ "type": "text", "text": "fine" }], "isError": false }),
            ))
        }
    }
}

async fn serve_web() -> (String, Arc<Web>) {
    let state = Arc::new(Web::default());
    let app = Router::new()
        .route("/mcp", post(web))
        .with_state(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/mcp"), state)
}

async fn web_gateway(dir: &Path, trip_after: Option<u32>) -> (Gateway, Arc<Web>) {
    let (url, state) = serve_web().await;
    let gw = gateway(dir, policy(&[("web", None)]));
    let connect: Connect = Arc::new(move || {
        let url = url.clone();
        Box::pin(async move { Ok(Box::new(HttpClient::streamable(url)?) as Box<dyn Transport>) })
    });
    let options = UpstreamOptions {
        trip_after,
        ..UpstreamOptions::default()
    };
    gw.start_supervised(
        vec![Supervised {
            id: "web".into(),
            connect,
            options,
        }],
        Startup::Degraded,
    )
    .await
    .unwrap();
    (gw, state)
}

#[tokio::test]
async fn an_http_upstream_whose_calls_keep_failing_is_taken_down_and_connected_again() {
    let dir = tempfile::tempdir().unwrap();
    let (gw, web) = web_gateway(dir.path(), Some(3)).await;
    assert_eq!(web.initializes.load(Ordering::SeqCst), 1);

    for n in 0..3 {
        let failed = reply(&gw, call(n, "broken")).await;
        assert!(is_error(&failed));
        assert!(
            text(&failed).starts_with("MCPdef error: upstream 'web' failed the call: http: "),
            "{}",
            text(&failed)
        );
        if n < 2 {
            assert_eq!(health(&gw, "web"), HealthState::Degraded);
        }
    }
    // The third failure in a row took it down: the next call is refused at
    // once, without reaching it.
    assert_eq!(health(&gw, "web"), HealthState::Down);
    let refused = reply(&gw, call(4, "fine")).await;
    assert!(
        text(&refused).contains("upstream 'web' is down (3 calls in a row failed; the last: "),
        "{}",
        text(&refused)
    );
    assert_eq!(web.fine_calls.load(Ordering::SeqCst), 0);

    // Connecting again is the probe: a new `initialize`, and calls flow again.
    assert!(
        eventually(Duration::from_secs(3), || health(&gw, "web")
            == HealthState::Up)
        .await
    );
    assert_eq!(web.initializes.load(Ordering::SeqCst), 2);
    assert_eq!(text(&reply(&gw, call(5, "fine")).await), "fine");
    assert_eq!(gw.upstream_status()[0].restarts, 1);

    let rules: Vec<Option<String>> = records(dir.path())
        .into_iter()
        .filter(|r| r.kind.is_none())
        .map(|r| r.rule)
        .collect();
    let error = Some("upstream-error".to_string());
    assert_eq!(
        rules,
        [
            error.clone(),
            error.clone(),
            error,
            Some("upstream-down".into()),
            None
        ]
    );
    assert_eq!(
        events(dir.path()),
        [event("web", "down", "deny"), event("web", "up", "allow")]
    );
}

#[tokio::test]
async fn an_ended_session_takes_an_http_upstream_down_and_a_new_one_is_opened() {
    let dir = tempfile::tempdir().unwrap();
    let (gw, web) = web_gateway(dir.path(), None).await;
    let ended = reply(&gw, call(1, "forget")).await;
    assert!(
        text(&ended).contains("upstream 'web' is down (the upstream ended its session"),
        "{}",
        text(&ended)
    );
    assert!(
        eventually(Duration::from_secs(3), || health(&gw, "web")
            == HealthState::Up)
        .await
    );
    assert_eq!(web.initializes.load(Ordering::SeqCst), 2);
    assert_eq!(text(&reply(&gw, call(2, "fine")).await), "fine");
}

#[cfg(target_os = "linux")]
fn running(pid: &str) -> bool {
    // A process killed but not yet reaped is a zombie: gone, for this purpose.
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit(") ")
            .next()
            .is_some_and(|s| !s.starts_with('Z'))
    })
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_gateway_stops_its_upstreams_and_their_keepers() {
    let dir = tempfile::tempdir().unwrap();
    let gw = gateway(dir.path(), policy(&[("up", None), ("gone", None)]));
    let attempts = Arc::new(AtomicUsize::new(0));
    gw.start_supervised(
        vec![
            supervised("up", mock(&["--with-pid"])),
            supervised("gone", missing(&attempts)),
        ],
        Startup::Degraded,
    )
    .await
    .unwrap();
    let pid = text(&reply(&gw, call(1, "pid")).await);
    assert!(running(&pid));
    drop(gw);
    assert!(
        eventually(Duration::from_secs(2), || !running(&pid)).await,
        "the upstream process outlived the gateway"
    );
    // The downed one's first retry was due about 500 ms in.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(attempts.load(Ordering::SeqCst), 1, "its keeper stopped");
}

/// Kills the gateway process however the test ends.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The real binary, end to end: one upstream cannot be reached at startup. The
/// gateway starts anyway, says so, serves the other, and reports both on the
/// admin API and in its metrics. Then the other is killed, and comes back.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_gateway_starts_with_an_upstream_down_and_reports_it() {
    use mcpdef_testkit::listening_port;
    use std::io::BufRead;
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.log");
    let config = dir.path().join("mcpdef.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[gateway]
listen = "127.0.0.1:0"
audit = {audit:?}

[gateway.admin]
enabled = true
listen = "127.0.0.1:0"

[[server]]
id = "good"
transport = "stdio"
command = [{MOCK:?}, "--tool-prefix", "good_", "--with-pid"]
tools = ["good_echo", "good_pid"]

[[server]]
id = "bad"
transport = "streamable-http"
url = "http://127.0.0.1:1/mcp"
tools = ["bad_tool"]
"#
        ),
    )
    .unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_mcpdef"))
        .args(["run", "--http", "--config"])
        .arg(&config)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let _running = Running(child);
    let (lines, ready) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let mut seen = Vec::new();
    let ready_line = loop {
        let line = ready
            .recv_timeout(Duration::from_secs(20))
            .unwrap_or_else(|_| panic!("no ready line; stderr so far: {seen:#?}"));
        if line.contains(" ready ") {
            break line;
        }
        seen.push(line);
    };
    assert!(
        ready_line.contains("2 upstream(s) · ⚠ 1 down, retrying: 'bad'"),
        "{ready_line}"
    );
    let listen = listening_port(&ready_line, "streamable-http ");
    let admin = loop {
        let line = ready
            .recv_timeout(Duration::from_secs(20))
            .unwrap_or_else(|_| panic!("no admin line; stderr so far: {seen:#?}"));
        if line.contains("admin/metrics UI on ") {
            break listening_port(&line, "UI on ");
        }
        seen.push(line);
    };
    assert!(
        seen.iter()
            .any(|l| l.starts_with("mcpdef: upstream 'bad' did not start: ")),
        "{seen:#?}"
    );

    mcpdef_transport::install_crypto_provider();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let send = |request: reqwest::RequestBuilder| async move {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            match request.try_clone().unwrap().send().await {
                Ok(response) => return response.text().await.unwrap(),
                Err(e) if Instant::now() > until => panic!("{e}"),
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    };
    let answer = send(
        client
            .post(format!("http://127.0.0.1:{listen}/mcp"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(call(1, "good_echo").to_json_line()),
    )
    .await;
    let answer: serde_json::Value = serde_json::from_str(&answer).unwrap();
    assert_eq!(answer["result"]["isError"], false, "{answer}");

    let base = format!("http://127.0.0.1:{admin}");
    let get = |path: &str| send(client.get(format!("{base}{path}")));
    let servers: serde_json::Value = serde_json::from_str(&get("/api/v1/servers").await).unwrap();
    assert_eq!(servers[0]["id"], "good");
    assert_eq!(servers[0]["health"], "up");
    assert_eq!(servers[1]["id"], "bad");
    assert_eq!(servers[1]["health"], "down");
    assert!(servers[1]["last_error"]["message"].is_string(), "{servers}");
    let status: serde_json::Value = serde_json::from_str(&get("/api/v1/status").await).unwrap();
    assert_eq!(
        (&status["upstreams"], &status["upstreams_up"]),
        (&json!(2), &json!(1))
    );
    let metrics = get("/metrics").await;
    for line in [
        "mcpdef_upstream_up{server=\"good\"} 1",
        "mcpdef_upstream_up{server=\"bad\"} 0",
    ] {
        assert!(metrics.lines().any(|l| l == line), "{line} in\n{metrics}");
    }

    // Kill the one that is up. The binary starts it again, and the admin API
    // follows along.
    let mcp = |n: i64, tool: &str| {
        client
            .post(format!("http://127.0.0.1:{listen}/mcp"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(call(n, tool).to_json_line())
    };
    let pid: serde_json::Value = serde_json::from_str(&send(mcp(2, "good_pid")).await).unwrap();
    kill(pid["result"]["content"][0]["text"].as_str().unwrap());
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let servers: serde_json::Value =
            serde_json::from_str(&get("/api/v1/servers").await).unwrap();
        if servers[0]["restarts"] == 1 && servers[0]["health"] == "up" {
            break;
        }
        assert!(Instant::now() < until, "not back: {servers}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let answer: serde_json::Value = serde_json::from_str(&send(mcp(3, "good_echo")).await).unwrap();
    assert_eq!(answer["result"]["isError"], false, "{answer}");
    let metrics = get("/metrics").await;
    assert!(
        metrics
            .lines()
            .any(|l| l == "mcpdef_upstream_restarts_total{server=\"good\"} 1"),
        "{metrics}"
    );

    let events: Vec<(String, String, String)> = std::fs::read_to_string(&audit)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Record>(l).unwrap())
        .filter(|r| r.kind.as_deref() == Some("upstream"))
        .map(|r| (r.server, r.method.unwrap_or_default(), r.decision))
        .collect();
    assert_eq!(
        events,
        [
            event("bad", "down", "deny"),
            event("good", "down", "deny"),
            event("good", "up", "allow")
        ]
    );
}
