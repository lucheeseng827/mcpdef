// SPDX-License-Identifier: Apache-2.0
//! `Gateway::reconfigure`: a new configuration applied to a running gateway,
//! upstreams diffed by id, without dropping a call in flight.

use mcpdef::{
    Connect, ConnectFuture, Gateway, HealthState, Planned, Reconfig, Startup, Supervised,
    UpstreamOptions,
};
use mcpdef_audit::{Ledger, Record};
use mcpdef_core::{method, Id, Message};
use mcpdef_pin::{tool_hash, PinStore};
use mcpdef_policy::{Policy, PolicyRules, Rbac, ServerPolicy};
use mcpdef_transport::{StdioChild, Transport};
use serde_json::json;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

/// Spawns the stdio mock with `args`, afresh for every start, counting starts.
fn mock<S: AsRef<str>>(args: &[S], starts: &Arc<AtomicUsize>) -> Connect {
    let mut command = vec![MOCK.to_string()];
    command.extend(args.iter().map(|a| a.as_ref().to_string()));
    let starts = Arc::clone(starts);
    Arc::new(move || {
        starts.fetch_add(1, Ordering::SeqCst);
        let command = command.clone();
        Box::pin(async move { Ok(Box::new(StdioChild::spawn(&command)?) as Box<dyn Transport>) })
    })
}

fn server(id: &str, connect: Connect) -> Supervised {
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

fn plan(policy: Policy, upstreams: Vec<Planned>) -> Reconfig {
    Reconfig {
        policy,
        rbac: Rbac::new(),
        rules: PolicyRules::default(),
        upstream_timeout: None,
        rate_limit: None,
        inspect: None,
        pins: None,
        tool_prefixes: None,
        upstreams,
    }
}

fn keep(s: Supervised) -> Planned {
    Planned {
        server: s,
        changed: false,
    }
}

fn change(s: Supervised) -> Planned {
    Planned {
        server: s,
        changed: true,
    }
}

async fn gateway(dir: &Path, policy: Policy, servers: Vec<Supervised>) -> Gateway {
    let ledger = Ledger::open(dir.join("audit.log")).unwrap();
    let gw = Gateway::new(policy, ledger, "agent:test");
    gw.start_supervised(servers, Startup::Degraded)
        .await
        .unwrap();
    gw
}

fn call(id: i64, tool: &str) -> Message {
    call_with(id, tool, json!({}))
}

fn call_with(id: i64, tool: &str, arguments: serde_json::Value) -> Message {
    Message::request(
        Id::Num(id),
        method::TOOLS_CALL,
        Some(json!({ "name": tool, "arguments": arguments })),
    )
}

async fn text(gw: &Gateway, request: Message) -> String {
    let reply = gw.handle(request).await.unwrap().expect("a reply");
    reply.result.as_ref().expect("a result")["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn ids(gw: &Gateway) -> Vec<String> {
    gw.upstream_status().into_iter().map(|u| u.id).collect()
}

fn health(gw: &Gateway, id: &str) -> Option<HealthState> {
    gw.upstream_status()
        .into_iter()
        .find(|u| u.id == id)
        .map(|u| u.health)
}

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

#[cfg(target_os = "linux")]
fn running(pid: &str) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit(") ")
            .next()
            .is_some_and(|s| !s.starts_with('Z'))
    })
}

#[tokio::test]
async fn an_added_upstream_opens_before_it_is_routed() {
    let dir = tempfile::tempdir().unwrap();
    let starts = Arc::new(AtomicUsize::new(0));
    let a = || server("a", mock(&["--tool-prefix", "a_"], &starts));
    let gw = gateway(dir.path(), policy(&[("a", None)]), vec![a()]).await;
    let refused = text(&gw, call(1, "b_echo")).await;
    assert!(
        refused.contains("no governed server exposes tool 'b_echo'"),
        "{refused}"
    );

    let report = gw
        .reconfigure(plan(
            policy(&[("a", None), ("b", None)]),
            vec![
                keep(a()),
                keep(server("b", mock(&["--tool-prefix", "b_"], &starts))),
            ],
        ))
        .await;
    assert_eq!(
        (report.added, report.removed),
        (vec!["b".to_string()], vec![])
    );
    assert!(report.failed.is_empty());
    assert_eq!(ids(&gw), ["a", "b"]);
    assert_eq!(health(&gw, "b"), Some(HealthState::Up));
    assert!(text(&gw, call(2, "b_echo")).await.starts_with("b_echo:"));
    assert!(text(&gw, call(3, "a_echo")).await.starts_with("a_echo:"));
    assert_eq!(
        starts.load(Ordering::SeqCst),
        2,
        "the kept one is not restarted"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removed_upstream_finishes_its_calls_then_closes_and_stays_closed() {
    let dir = tempfile::tempdir().unwrap();
    let starts = Arc::new(AtomicUsize::new(0));
    let a = || {
        let args = ["--tool-prefix", "a_", "--with-pid", "--out-of-order"];
        server("a", mock(&args, &starts))
    };
    let b = || server("b", mock(&["--tool-prefix", "b_"], &starts));
    let gw = gateway(
        dir.path(),
        policy(&[("a", None), ("b", None)]),
        vec![a(), b()],
    )
    .await;
    let pid = text(&gw, call(1, "a_pid")).await;

    // A call to `a` that takes 800 ms, already running when `a` is removed.
    let long = tokio::spawn({
        let gw = gw.clone();
        async move { text(&gw, call_with(2, "a_echo", json!({ "delay_ms": 800 }))).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let report = gw
        .reconfigure(plan(policy(&[("b", None)]), vec![keep(b())]))
        .await;
    assert_eq!(report.removed, ["a"]);
    assert_eq!(ids(&gw), ["b"]);
    let refused = text(&gw, call(3, "a_echo")).await;
    assert!(
        refused.contains("no governed server exposes tool 'a_echo'"),
        "{refused}"
    );
    assert!(running(&pid), "it still serves the call in flight");

    let finished = long.await.unwrap();
    assert!(
        finished.starts_with("a_echo:"),
        "the call spanning the reload completes: {finished}"
    );
    assert!(
        eventually(Duration::from_secs(2), || !running(&pid)).await,
        "the removed upstream closes once its call is done"
    );
    // Its keeper stopped with it: nothing starts it again.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(starts.load(Ordering::SeqCst), 2);
}

/// A removed upstream's keeper stops with it: if its connection dies while it
/// drains, nothing reports it down, and nothing starts it again.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removed_upstream_that_dies_while_it_drains_stays_gone() {
    let dir = tempfile::tempdir().unwrap();
    let starts = Arc::new(AtomicUsize::new(0));
    let args = ["--tool-prefix", "a_", "--with-pid", "--out-of-order"];
    let a = server("a", mock(&args, &starts));
    let b = || server("b", mock(&["--tool-prefix", "b_"], &starts));
    let gw = gateway(
        dir.path(),
        policy(&[("a", None), ("b", None)]),
        vec![a, b()],
    )
    .await;
    let pid = text(&gw, call(1, "a_pid")).await;
    let long = tokio::spawn({
        let gw = gw.clone();
        async move {
            gw.handle(call_with(2, "a_echo", json!({ "delay_ms": 2000 })))
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    gw.reconfigure(plan(policy(&[("b", None)]), vec![keep(b())]))
        .await;

    let killed = std::process::Command::new("kill")
        .arg(&pid)
        .status()
        .unwrap();
    assert!(killed.success());
    let _ = long.await.unwrap();
    // Past its first restart, were it to have one.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(starts.load(Ordering::SeqCst), 2);
    assert_eq!(upstream_events(dir.path()), []);
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_changed_upstream_moves_to_its_new_connection_and_the_old_drains() {
    let dir = tempfile::tempdir().unwrap();
    let starts = Arc::new(AtomicUsize::new(0));
    let version = |label: &str| {
        let args = ["--label", label, "--with-pid", "--out-of-order"];
        server("a", mock(&args, &starts))
    };
    let gw = gateway(dir.path(), policy(&[("a", None)]), vec![version("v1:")]).await;
    let old_pid = text(&gw, call(1, "pid")).await;
    let long = tokio::spawn({
        let gw = gw.clone();
        async move { text(&gw, call_with(2, "echo", json!({ "delay_ms": 800 }))).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let report = gw
        .reconfigure(plan(policy(&[("a", None)]), vec![change(version("v2:"))]))
        .await;
    assert_eq!(report.reconnected, ["a"]);
    assert!(
        text(&gw, call(3, "echo")).await.starts_with("v2:"),
        "new calls go to the new one"
    );
    assert_ne!(text(&gw, call(4, "pid")).await, old_pid);
    let finished = long.await.unwrap();
    assert!(
        finished.starts_with("v1:echo"),
        "the old one finishes its call: {finished}"
    );
    assert!(eventually(Duration::from_secs(2), || !running(&old_pid)).await);
    assert_eq!(
        gw.upstream_status()[0].restarts,
        0,
        "a reconnect is not a restart"
    );
}

#[tokio::test]
async fn a_changed_upstream_whose_new_settings_fail_keeps_serving_on_its_old_ones() {
    let dir = tempfile::tempdir().unwrap();
    let starts = Arc::new(AtomicUsize::new(0));
    let good = server("a", mock(&["--label", "v1:"], &starts));
    let gw = gateway(dir.path(), policy(&[("a", None)]), vec![good]).await;

    let missing: Connect = Arc::new(|| {
        let command = ["/nonexistent/mcp-server".to_string()];
        Box::pin(async move { Ok(Box::new(StdioChild::spawn(&command)?) as Box<dyn Transport>) })
    });
    let broken = server("a", missing);
    let report = gw
        .reconfigure(plan(policy(&[("a", None)]), vec![change(broken)]))
        .await;
    assert!(report.reconnected.is_empty());
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0].0, "a");
    assert!(text(&gw, call(1, "echo")).await.starts_with("v1:"));
    assert_eq!(health(&gw, "a"), Some(HealthState::Up));
    let status = gw.upstream_status().remove(0);
    assert!(
        status.last_error.is_some(),
        "why the new settings failed is kept"
    );
    assert_eq!(status.restarts, 0);
    // No down record: it never went down.
    let events: Vec<Record> = std::fs::read_to_string(dir.path().join("audit.log"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Record>(l).unwrap())
        .filter(|r| r.kind.is_some())
        .collect();
    assert!(events.is_empty(), "{events:?}");
}

/// The ledger's upstream events, as `(method, decision)`.
fn upstream_events(dir: &Path) -> Vec<(String, String)> {
    std::fs::read_to_string(dir.join("audit.log"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Record>(l).unwrap())
        .filter(|r| r.kind.as_deref() == Some("upstream"))
        .map(|r| (r.method.unwrap_or_default(), r.decision))
        .collect()
}

fn pair(method: &str, decision: &str) -> (String, String) {
    (method.to_string(), decision.to_string())
}

/// A changed upstream whose new settings do not start serves on its old
/// connection. When that one goes down too, it is down like any other: audited
/// so, and restarted, on its new settings, and audited up once they start.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_changed_upstream_left_on_its_old_connection_goes_down_and_comes_back_audited() {
    let dir = tempfile::tempdir().unwrap();
    let starts = Arc::new(AtomicUsize::new(0));
    let v1 = server("a", mock(&["--label", "v1:", "--with-pid"], &starts));
    let gw = gateway(dir.path(), policy(&[("a", None)]), vec![v1]).await;
    let pid = text(&gw, call(1, "pid")).await;

    // Its new settings do not start until they are fixed.
    let fixed = Arc::new(AtomicBool::new(false));
    let v2: Connect = {
        let (fixed, v2) = (Arc::clone(&fixed), mock(&["--label", "v2:"], &starts));
        Arc::new(move || match fixed.load(Ordering::SeqCst) {
            true => v2(),
            false => Box::pin(async { Err(anyhow::anyhow!("not yet")) }),
        })
    };
    let report = gw
        .reconfigure(plan(policy(&[("a", None)]), vec![change(server("a", v2))]))
        .await;
    assert_eq!(report.failed.len(), 1);
    assert!(text(&gw, call(2, "echo")).await.starts_with("v1:"));

    let killed = std::process::Command::new("kill")
        .arg(&pid)
        .status()
        .unwrap();
    assert!(killed.success());
    let down = [pair("down", "deny")];
    assert!(
        eventually(Duration::from_secs(5), || upstream_events(dir.path())
            == down)
        .await,
        "{:?}",
        upstream_events(dir.path())
    );
    fixed.store(true, Ordering::SeqCst);
    let back = [pair("down", "deny"), pair("up", "allow")];
    assert!(
        eventually(Duration::from_secs(10), || upstream_events(dir.path())
            == back)
        .await,
        "{:?}",
        upstream_events(dir.path())
    );
    assert!(text(&gw, call(3, "echo")).await.starts_with("v2:"));
    let status = gw.upstream_status().remove(0);
    assert_eq!((status.health, status.restarts), (HealthState::Up, 1));
}

/// An upstream that is down when its settings change is up again, and audited
/// so, as soon as its new ones start.
#[tokio::test]
async fn a_down_upstream_whose_new_settings_start_is_audited_up() {
    let dir = tempfile::tempdir().unwrap();
    let missing: Connect = Arc::new(|| {
        let command = ["/nonexistent/mcp-server".to_string()];
        Box::pin(async move { Ok(Box::new(StdioChild::spawn(&command)?) as Box<dyn Transport>) })
    });
    let gw = gateway(
        dir.path(),
        policy(&[("a", None)]),
        vec![server("a", missing)],
    )
    .await;
    assert_eq!(health(&gw, "a"), Some(HealthState::Down));
    assert_eq!(upstream_events(dir.path()), [pair("down", "deny")]);

    let starts = Arc::new(AtomicUsize::new(0));
    let fixed = server("a", mock(&["--label", "v2:"], &starts));
    let report = gw
        .reconfigure(plan(policy(&[("a", None)]), vec![change(fixed)]))
        .await;
    assert_eq!(report.reconnected, ["a"]);
    assert_eq!(health(&gw, "a"), Some(HealthState::Up));
    assert!(text(&gw, call(1, "echo")).await.starts_with("v2:"));
    assert_eq!(
        upstream_events(dir.path()),
        [pair("down", "deny"), pair("up", "allow")]
    );
}

/// A gateway whose upstream `a` went down and is being started again, that
/// start stuck in its opening: its keeper holds it `starting`.
async fn restarting(dir: &Path) -> Gateway {
    let starts = Arc::new(AtomicUsize::new(0));
    let first = mock(&["--tool-prefix", "a_", "--with-pid"], &starts);
    let opened = Arc::new(AtomicBool::new(false));
    let once: Connect = Arc::new(move || {
        if opened.swap(true, Ordering::SeqCst) {
            let stuck: ConnectFuture = Box::pin(std::future::pending());
            stuck
        } else {
            first()
        }
    });
    let gw = gateway(dir, policy(&[("a", None)]), vec![server("a", once)]).await;
    let pid = text(&gw, call(1, "a_pid")).await;
    let killed = std::process::Command::new("kill")
        .arg(&pid)
        .status()
        .unwrap();
    assert!(killed.success());
    let restarting = || health(&gw, "a") == Some(HealthState::Starting);
    assert!(
        eventually(Duration::from_secs(5), restarting).await,
        "no restart began"
    );
    gw
}

/// A reload that reconnects an upstream while its keeper starts it again
/// leaves it up. The keeper the reload retires never settles the health they
/// share, so the reload's own opening does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_upstream_reconnected_mid_restart_is_up_not_starting() {
    let dir = tempfile::tempdir().unwrap();
    let gw = restarting(dir.path()).await;
    let starts = Arc::new(AtomicUsize::new(0));
    let v2 = server(
        "a",
        mock(&["--tool-prefix", "a_", "--label", "v2:"], &starts),
    );
    let report = gw
        .reconfigure(plan(policy(&[("a", None)]), vec![change(v2)]))
        .await;
    assert_eq!(report.reconnected, ["a"]);
    assert_eq!(health(&gw, "a"), Some(HealthState::Up));
    assert!(text(&gw, call(2, "a_echo")).await.starts_with("v2:"));
}

/// And one whose new settings fail is down until they are tried again, as
/// after any start that failed, not starting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_upstream_whose_new_settings_fail_mid_restart_is_down_not_starting() {
    let dir = tempfile::tempdir().unwrap();
    let gw = restarting(dir.path()).await;
    let broken: Connect = Arc::new(|| {
        let command = ["/nonexistent/mcp-server".to_string()];
        Box::pin(async move { Ok(Box::new(StdioChild::spawn(&command)?) as Box<dyn Transport>) })
    });
    let report = gw
        .reconfigure(plan(
            policy(&[("a", None)]),
            vec![change(server("a", broken))],
        ))
        .await;
    assert_eq!(report.failed.len(), 1, "{report:?}");
    assert_eq!(health(&gw, "a"), Some(HealthState::Down));
}

#[tokio::test]
async fn a_policy_change_applies_to_the_next_call() {
    let dir = tempfile::tempdir().unwrap();
    let starts = Arc::new(AtomicUsize::new(0));
    let a = || server("a", mock::<&str>(&[], &starts));
    let gw = gateway(dir.path(), policy(&[("a", Some(&["echo"]))]), vec![a()]).await;
    assert!(text(&gw, call(1, "echo")).await.starts_with("echo:"));

    gw.reconfigure(plan(
        policy(&[("a", Some(&["delete_repo"]))]),
        vec![keep(a())],
    ))
    .await;
    let denied = text(&gw, call(2, "echo")).await;
    assert!(denied.contains("is not on the allowlist"), "{denied}");
    assert!(text(&gw, call(3, "delete_repo"))
        .await
        .starts_with("delete_repo:"));
    assert_eq!(
        starts.load(Ordering::SeqCst),
        1,
        "a policy change reconnects nothing"
    );
}

#[tokio::test]
async fn the_order_planned_is_the_order_calls_prefer() {
    let dir = tempfile::tempdir().unwrap();
    let starts = Arc::new(AtomicUsize::new(0));
    let one = || server("one", mock(&["--label", "one:"], &starts));
    let two = || server("two", mock(&["--label", "two:"], &starts));
    let gw = gateway(
        dir.path(),
        policy(&[("one", None), ("two", None)]),
        vec![one(), two()],
    )
    .await;
    assert!(text(&gw, call(1, "echo")).await.starts_with("one:"));
    gw.reconfigure(plan(
        policy(&[("one", None), ("two", None)]),
        vec![keep(two()), keep(one())],
    ))
    .await;
    assert!(text(&gw, call(2, "echo")).await.starts_with("two:"));
}

#[tokio::test]
async fn a_tool_re_approved_in_the_pin_store_is_let_back_in() {
    let dir = tempfile::tempdir().unwrap();
    let pins = dir.path().join("pins.json");
    // Pinned with a definition the server no longer has: a rug-pull.
    let mut store = PinStore::default();
    let old =
        json!({ "name": "echo", "description": "before", "inputSchema": { "type": "object" } });
    store.record("a", "echo", tool_hash(&old));
    store.save(&pins).unwrap();
    let starts = Arc::new(AtomicUsize::new(0));
    let a = || server("a", mock::<&str>(&[], &starts));
    let ledger = Ledger::open(dir.path().join("audit.log")).unwrap();
    let gw = Gateway::new(policy(&[("a", None)]), ledger, "agent:test")
        .with_pins(PinStore::load(&pins).unwrap(), &pins);
    gw.start_supervised(vec![a()], Startup::Degraded)
        .await
        .unwrap();
    assert_eq!(gw.drift_count(), 1);
    assert!(text(&gw, call(1, "echo"))
        .await
        .contains("changed since it was pinned"));

    // `mcpdef pin` writes the current definitions; a reload reads them.
    let current = json!({ "name": "echo", "description": "echo arguments back", "inputSchema": { "type": "object" } });
    let mut store = PinStore::load(&pins).unwrap();
    store.record("a", "echo", tool_hash(&current));
    store.save(&pins).unwrap();
    let mut reconfig = plan(policy(&[("a", None)]), vec![keep(a())]);
    reconfig.pins = Some((PinStore::load(&pins).unwrap(), pins.clone()));
    gw.reconfigure(reconfig).await;
    assert_eq!(gw.drift_count(), 0);
    assert!(text(&gw, call(2, "echo")).await.starts_with("echo:"));
}
