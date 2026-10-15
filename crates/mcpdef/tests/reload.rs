// SPDX-License-Identifier: Apache-2.0
//! Hot reload: the config read again and applied to a running gateway, whole or
//! not at all, and audited either way.

use mcpdef::connect::build_gateway;
use mcpdef::reload::{Outcome, Reloader, Snapshot, Trigger};
use mcpdef::{Config, Gateway};
use mcpdef_audit::Record;
use mcpdef_core::{method, Id, Message};
use mcpdef_pin::{tool_hash, PinStore};
use serde_json::json;
use std::path::Path;
use std::time::{Duration, Instant};

const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

/// A `[[server]]` entry that runs the stdio mock with `args`, allowed `tools`.
fn server(id: &str, args: &[&str], tools: &[&str]) -> String {
    let quoted = |items: &mut dyn Iterator<Item = &str>| {
        items
            .map(|s| format!("{s:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let command = quoted(&mut std::iter::once(MOCK).chain(args.iter().copied()));
    let tools = quoted(&mut tools.iter().copied());
    format!("[[server]]\nid = {id:?}\ntransport = \"stdio\"\ncommand = [{command}]\ntools = [{tools}]\n\n")
}

/// A config whose ledger is in `dir`, with `gateway` added to its `[gateway]`
/// table.
fn config(dir: &Path, gateway: &str, servers: &[impl AsRef<str>]) -> String {
    let audit = dir.join("audit.log");
    let servers: String = servers.iter().map(AsRef::as_ref).collect();
    format!("[gateway]\nlisten = \"127.0.0.1:0\"\naudit = {audit:?}\n{gateway}\n\n{servers}")
}

/// A gateway started from the config at `path` as `mcpdef run` starts one,
/// and its reloader.
async fn start(path: &Path) -> (Gateway, Reloader) {
    let (config, text) = Config::load_text(path).unwrap();
    assert_eq!(config.validate(), Vec::<String>::new());
    let snapshot = Snapshot::take(text.as_bytes(), &config);
    let gw = build_gateway(&config).await.unwrap();
    let reloader = Reloader::new(path, None, gw.clone(), config, snapshot);
    (gw, reloader)
}

/// The reload records in the ledger in `dir`.
fn reloads(dir: &Path) -> Vec<Record> {
    std::fs::read_to_string(dir.join("audit.log"))
        .unwrap_or_default()
        .lines()
        // A record the gateway is still writing is not one yet.
        .filter_map(|l| serde_json::from_str::<Record>(l).ok())
        .filter(|r| r.kind.as_deref() == Some("reload"))
        .collect()
}

fn call(id: i64, tool: &str, arguments: serde_json::Value) -> Message {
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

async fn echo(gw: &Gateway, tool: &str) -> String {
    text(gw, call(1, tool, json!({}))).await
}

fn ids(gw: &Gateway) -> Vec<String> {
    gw.upstream_status().into_iter().map(|u| u.id).collect()
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

#[tokio::test]
async fn adding_removing_and_changing_a_server_all_apply_and_so_does_a_policy_change() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    let a = |tools: &[&str]| server("a", &[], tools);
    let b = server("b", &["--tool-prefix", "b_"], &["b_echo"]);
    let c = |label| server("c", &["--tool-prefix", "c_", "--label", label], &["c_echo"]);
    let d = server("d", &["--tool-prefix", "d_"], &["d_echo"]);
    std::fs::write(&path, config(dir.path(), "", &[a(&["echo"]), b, c("v1:")])).unwrap();
    let (gw, mut reloader) = start(&path).await;
    let first = reloader.digest().to_string();
    let denied = echo(&gw, "delete_repo").await;
    assert!(denied.contains("is not on the allowlist"), "{denied}");
    assert!(echo(&gw, "c_echo").await.starts_with("v1:"));

    let next = [a(&["echo", "delete_repo"]), c("v2:"), d];
    std::fs::write(&path, config(dir.path(), "", &next)).unwrap();
    let outcome = reloader.reload(Trigger::Signal).await;
    let Outcome::Applied(report) = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(report.added, ["d"]);
    assert_eq!(report.removed, ["b"]);
    assert_eq!(report.reconnected, ["c"]);
    assert!(report.failed.is_empty(), "{report:?}");
    assert_eq!(ids(&gw), ["a", "c", "d"]);
    assert!(
        echo(&gw, "delete_repo").await.starts_with("delete_repo:"),
        "the policy change applies"
    );
    assert!(echo(&gw, "c_echo").await.starts_with("v2:"));
    assert!(echo(&gw, "d_echo").await.starts_with("d_echo:"));
    let gone = echo(&gw, "b_echo").await;
    assert!(
        gone.contains("no governed server exposes tool 'b_echo'"),
        "{gone}"
    );
    let second = reloader.digest().to_string();
    assert_ne!(first, second);

    // A SIGHUP with nothing changed changes nothing, and is audited too.
    let outcome = reloader.reload(Trigger::Signal).await;
    assert_eq!(outcome, Outcome::Applied(Default::default()));
    assert_eq!(reloader.digest(), second);

    let records = reloads(dir.path());
    assert_eq!(records.len(), 2, "{records:?}");
    for r in &records {
        assert_eq!(
            (r.agent.as_str(), r.server.as_str(), r.method.as_deref()),
            ("mcpdef", "(config)", Some("reload"))
        );
        assert_eq!(
            (r.decision.as_str(), r.rule.as_deref(), r.actor.as_deref()),
            ("allow", None, Some("sighup"))
        );
    }
    let digests = |r: &Record| (r.config_from.clone(), r.config_to.clone());
    assert_eq!(
        digests(&records[0]),
        (Some(first), Some(second.clone())),
        "from what ran to what runs now"
    );
    assert_eq!(digests(&records[1]), (Some(second.clone()), Some(second)));
}

/// One reload adds a server, removes one, reconnects one and takes a tool
/// away from another, while a call to each of the last three is running. None
/// of those calls is dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_long_call_spans_a_reload_and_completes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    let slow = |id: &str, label: &str, tools: &[&str]| {
        let prefix = format!("{id}_");
        server(
            id,
            &["--tool-prefix", &prefix, "--label", label, "--out-of-order"],
            tools,
        )
    };
    let before = [
        slow("a", "a:", &["a_echo"]),
        slow("b", "b:", &["b_echo"]),
        slow("c", "v1:", &["c_echo"]),
    ];
    std::fs::write(&path, config(dir.path(), "", &before)).unwrap();
    let (gw, mut reloader) = start(&path).await;
    let long: Vec<_> = ["a_echo", "b_echo", "c_echo"]
        .into_iter()
        .zip(1..)
        .map(|(tool, id)| {
            let gw = gw.clone();
            tokio::spawn(
                async move { text(&gw, call(id, tool, json!({ "delay_ms": 2000 }))).await },
            )
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let after = [
        slow("a", "a:", &["a_delete_repo"]),
        slow("c", "v2:", &["c_echo"]),
        server("d", &["--tool-prefix", "d_"], &["d_echo"]),
    ];
    std::fs::write(&path, config(dir.path(), "", &after)).unwrap();
    let outcome = reloader.reload(Trigger::Signal).await;
    let Outcome::Applied(report) = outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(
        (report.added, report.removed, report.reconnected),
        (vec!["d".into()], vec!["b".into()], vec!["c".into()])
    );
    assert!(
        long.iter().all(|call| !call.is_finished()),
        "the reload does not wait for them"
    );
    // A call that starts now runs under the new config.
    let denied = echo(&gw, "a_echo").await;
    assert!(denied.contains("is not on the allowlist"), "{denied}");
    let gone = echo(&gw, "b_echo").await;
    assert!(gone.contains("no governed server exposes"), "{gone}");
    assert!(echo(&gw, "c_echo").await.starts_with("v2:"));
    assert!(echo(&gw, "d_echo").await.starts_with("d_echo:"));

    // Each call already running completes under the one it started with.
    let mut finished = Vec::new();
    for call in long {
        finished.push(call.await.unwrap());
    }
    for (text, start) in finished
        .iter()
        .zip(["a:a_echo:", "b:b_echo:", "v1:c_echo:"])
    {
        assert!(text.starts_with(start), "{text} should start {start}");
    }
}

#[tokio::test]
async fn an_invalid_config_is_refused_and_audited_and_the_old_one_keeps_serving() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    let a = server("a", &[], &["echo"]);
    std::fs::write(&path, config(dir.path(), "", &[&a])).unwrap();
    let (gw, mut reloader) = start(&path).await;
    let serving = reloader.digest().to_string();

    let mut refusals = Vec::new();
    // Not TOML.
    std::fs::write(&path, "[[server]\nid = ").unwrap();
    refusals.push(reloader.reload(Trigger::Signal).await);
    // TOML, but not a config: it adds a server, under an id already taken.
    let twice = server("a", &["--tool-prefix", "b_"], &["b_echo"]);
    std::fs::write(&path, config(dir.path(), "", &[&a, &twice])).unwrap();
    refusals.push(reloader.reload(Trigger::Signal).await);
    // Gone.
    std::fs::remove_file(&path).unwrap();
    refusals.push(reloader.reload(Trigger::Signal).await);

    let why: Vec<(&str, &str)> = refusals
        .iter()
        .map(|outcome| match outcome {
            Outcome::Refused { rule, reasons } => (*rule, reasons[0].as_str()),
            Outcome::Applied(report) => panic!("applied: {report:?}"),
        })
        .collect();
    assert_eq!(
        why.iter().map(|(rule, _)| *rule).collect::<Vec<_>>(),
        ["invalid-config"; 3]
    );
    assert!(why[0].1.starts_with("parsing "), "{why:?}");
    assert_eq!(why[1].1, "duplicate server id 'a'");
    assert!(why[2].1.starts_with("reading "), "{why:?}");

    assert_eq!(reloader.digest(), serving);
    assert_eq!(ids(&gw), ["a"]);
    assert!(echo(&gw, "echo").await.starts_with("echo:"));
    assert!(echo(&gw, "b_echo").await.contains("no governed server"));
    let records = reloads(dir.path());
    assert_eq!(records.len(), 3, "{records:?}");
    let mut to = Vec::new();
    for r in &records {
        assert_eq!(
            (r.decision.as_str(), r.rule.as_deref()),
            ("deny", Some("invalid-config"))
        );
        assert_eq!(r.config_from.as_deref(), Some(serving.as_str()));
        let digest = r.config_to.clone().unwrap();
        assert!(digest.starts_with("sha256:") && digest != serving, "{r:?}");
        to.push(digest);
    }
    to.dedup();
    assert_eq!(to.len(), 3, "each refused config has a digest of its own");
}

#[tokio::test]
async fn a_change_only_a_restart_can_apply_refuses_the_whole_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    let before = config(dir.path(), "", &[server("a", &[], &["echo"])]);
    std::fs::write(&path, &before).unwrap();
    let (gw, mut reloader) = start(&path).await;

    // The listener moves, and a server is added. Neither applies.
    let b = server("b", &["--tool-prefix", "b_"], &["b_echo"]);
    let after = before.replace("127.0.0.1:0", "127.0.0.1:1") + &b;
    std::fs::write(&path, after).unwrap();
    let outcome = reloader.reload(Trigger::Signal).await;
    assert_eq!(
        outcome,
        Outcome::Refused {
            rule: "restart-required",
            reasons: vec!["[gateway] listen (127.0.0.1:0 → 127.0.0.1:1) changed".to_string()],
        }
    );
    assert_eq!(ids(&gw), ["a"]);
    let records = reloads(dir.path());
    assert_eq!(records.len(), 1);
    assert_eq!(
        (records[0].decision.as_str(), records[0].rule.as_deref()),
        ("deny", Some("restart-required"))
    );
}

/// The kubelet updates a mounted ConfigMap by writing the new version to a
/// directory of its own and swapping the `..data` link to it in one rename.
/// Every key is a link through `..data`, so the file never changes in place,
/// and no event on it announces the change.
#[cfg(unix)]
#[tokio::test]
async fn the_watch_picks_up_a_config_map_update() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let mount = dir.path().join("config");
    let version = |name: &str, text: String| {
        std::fs::create_dir_all(mount.join(name)).unwrap();
        std::fs::write(mount.join(name).join("mcpdef.toml"), text).unwrap();
    };
    let a = server("a", &[], &["echo"]);
    let b = server("b", &["--tool-prefix", "b_"], &["b_echo"]);
    let watched = |servers: &[&String]| config(dir.path(), "watch_config = true", servers);
    version("..2026_09_25_08_00_00.1", watched(&[&a]));
    symlink("..2026_09_25_08_00_00.1", mount.join("..data")).unwrap();
    symlink("..data/mcpdef.toml", mount.join("mcpdef.toml")).unwrap();
    let (gw, reloader) = start(&mount.join("mcpdef.toml")).await;
    let watching = tokio::spawn(reloader.run(Duration::from_millis(50)));

    version("..2026_09_25_08_05_00.2", watched(&[&a, &b]));
    symlink("..2026_09_25_08_05_00.2", mount.join("..data_tmp")).unwrap();
    std::fs::rename(mount.join("..data_tmp"), mount.join("..data")).unwrap();
    assert!(
        eventually(Duration::from_secs(10), || ids(&gw) == ["a", "b"]).await,
        "{:?}",
        ids(&gw)
    );
    assert!(echo(&gw, "b_echo").await.starts_with("b_echo:"));
    watching.abort();
    let records = reloads(dir.path());
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(
        (records[0].decision.as_str(), records[0].actor.as_deref()),
        ("allow", Some("watch"))
    );
}

#[tokio::test]
async fn the_watch_refuses_a_bad_config_once_and_applies_its_fix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    let a = server("a", &[], &["echo"]);
    let watched = |servers: &[&String]| config(dir.path(), "watch_config = true", servers);
    std::fs::write(&path, watched(&[&a])).unwrap();
    let (gw, reloader) = start(&path).await;
    let watching = tokio::spawn(reloader.run(Duration::from_millis(50)));

    std::fs::write(&path, "[gateway\n").unwrap();
    assert!(eventually(Duration::from_secs(5), || reloads(dir.path()).len() == 1).await);
    // Eight more checks of the same bad config.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        reloads(dir.path()).len(),
        1,
        "refused once, not every check"
    );

    let b = server("b", &["--tool-prefix", "b_"], &["b_echo"]);
    std::fs::write(&path, watched(&[&a, &b])).unwrap();
    assert!(eventually(Duration::from_secs(10), || ids(&gw) == ["a", "b"]).await);
    watching.abort();
    let records = reloads(dir.path());
    assert_eq!(records.len(), 2, "{records:?}");
    let (refused, applied) = (&records[0], &records[1]);
    assert_eq!(
        (refused.rule.as_deref(), refused.actor.as_deref()),
        (Some("invalid-config"), Some("watch"))
    );
    assert_eq!(
        (applied.decision.as_str(), applied.actor.as_deref()),
        ("allow", Some("watch"))
    );
    assert_eq!(
        applied.config_from, refused.config_from,
        "the refused config never ran"
    );
}

#[tokio::test]
async fn without_watch_config_a_changed_file_waits_for_a_sighup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    let a = server("a", &[], &["echo"]);
    std::fs::write(&path, config(dir.path(), "", &[&a])).unwrap();
    let (gw, reloader) = start(&path).await;
    let watching = tokio::spawn(reloader.run(Duration::from_millis(50)));

    let b = server("b", &["--tool-prefix", "b_"], &["b_echo"]);
    std::fs::write(&path, config(dir.path(), "", &[&a, &b])).unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    watching.abort();
    assert_eq!(ids(&gw), ["a"]);
    assert!(reloads(dir.path()).is_empty());
}

#[tokio::test]
async fn a_tool_re_approved_with_mcpdef_pin_is_let_back_in_by_a_reload() {
    let dir = tempfile::tempdir().unwrap();
    let pins = dir.path().join("pins.toml");
    // Pinned with a definition the server no longer has: a rug-pull.
    let pinned =
        json!({ "name": "echo", "description": "before", "inputSchema": { "type": "object" } });
    let mut store = PinStore::default();
    store.record("a", "echo", tool_hash(&pinned));
    store.save(&pins).unwrap();
    let path = dir.path().join("mcpdef.toml");
    let gateway = format!("pins = {pins:?}");
    let text = config(dir.path(), &gateway, &[server("a", &[], &["echo"])]);
    std::fs::write(&path, text).unwrap();
    let (gw, mut reloader) = start(&path).await;
    assert_eq!(gw.drift_count(), 1);
    let denied = echo(&gw, "echo").await;
    assert!(denied.contains("changed since it was pinned"), "{denied}");

    // What `mcpdef pin` does: pin every tool as it is now.
    let current = json!({ "name": "echo", "description": "echo arguments back", "inputSchema": { "type": "object" } });
    let mut store = PinStore::load(&pins).unwrap();
    store.record("a", "echo", tool_hash(&current));
    store.save(&pins).unwrap();
    let outcome = reloader.reload(Trigger::Signal).await;
    assert_eq!(outcome, Outcome::Applied(Default::default()));
    assert_eq!(gw.drift_count(), 0);
    assert!(echo(&gw, "echo").await.starts_with("echo:"));
}

/// Kills the gateway process however the test ends.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The real binary: a `SIGHUP`, sent the moment the gateway says it is ready,
/// applies the edited config, and the admin API follows along.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sighup_reloads_the_running_binary() {
    use mcpdef_testkit::listening_port;
    use std::io::BufRead;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    let gateway = "[gateway.admin]\nenabled = true\nlisten = \"127.0.0.1:0\"\n";
    let with = |servers: &[&String]| config(dir.path(), "", servers) + gateway;
    let a = server("a", &[], &["echo"]);
    let b = server("b", &["--tool-prefix", "b_"], &["b_echo"]);
    std::fs::write(&path, with(&[&a])).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_mcpdef"))
        .args(["run", "--http", "--config"])
        .arg(&path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id().to_string();
    let stderr = child.stderr.take().unwrap();
    let mut running = Running(child);
    let (send, lines) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            if send.send(line).is_err() {
                break;
            }
        }
    });
    let mut seen = Vec::new();
    let mut until = |what: &str| loop {
        let line = lines
            .recv_timeout(Duration::from_secs(20))
            .unwrap_or_else(|_| panic!("no line with {what:?}; stderr so far: {seen:#?}"));
        seen.push(line.clone());
        if line.contains(what) {
            break line;
        }
    };
    let listen = listening_port(&until(" ready "), "streamable-http ");
    let admin = listening_port(&until("admin/metrics UI on "), "UI on ");

    std::fs::write(&path, with(&[&a, &b])).unwrap();
    let hup = std::process::Command::new("kill")
        .args(["-HUP", &pid])
        .status()
        .unwrap();
    assert!(hup.success());
    let reloaded = until("mcpdef: config reloaded");
    assert!(
        reloaded.starts_with("mcpdef: config reloaded (sighup): added b; now sha256:"),
        "{reloaded}"
    );
    assert!(
        running.0.try_wait().unwrap().is_none(),
        "SIGHUP did not end it"
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
    let get = |path: &str| send(client.get(format!("http://127.0.0.1:{admin}{path}")));
    let servers: serde_json::Value = serde_json::from_str(&get("/api/v1/servers").await).unwrap();
    let listed: Vec<(&str, &str)> = servers
        .as_array()
        .unwrap()
        .iter()
        .map(|s| (s["id"].as_str().unwrap(), s["health"].as_str().unwrap()))
        .collect();
    assert_eq!(listed, [("a", "up"), ("b", "up")]);
    assert_eq!(servers[1]["tools"], json!(["b_echo"]));
    let status: serde_json::Value = serde_json::from_str(&get("/api/v1/status").await).unwrap();
    assert_eq!(status["upstreams"], 2);
    let metrics = get("/metrics").await;
    assert!(
        metrics.lines().any(|l| l == "mcpdef_upstreams 2"),
        "{metrics}"
    );
    let answer = send(
        client
            .post(format!("http://127.0.0.1:{listen}/mcp"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(call(1, "b_echo", json!({})).to_json_line()),
    )
    .await;
    let answer: serde_json::Value = serde_json::from_str(&answer).unwrap();
    assert_eq!(answer["result"]["isError"], false, "{answer}");

    let records = reloads(dir.path());
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(
        (records[0].decision.as_str(), records[0].actor.as_deref()),
        ("allow", Some("sighup"))
    );

    // And from the admin API, for whoever calls it: with nothing to sign
    // callers in, on loopback, `local`.
    std::fs::write(&path, with(&[&a])).unwrap();
    let reloaded = client
        .post(format!("http://127.0.0.1:{admin}/api/v1/reload"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(reloaded.status(), 200);
    let reloaded: serde_json::Value =
        serde_json::from_str(&reloaded.text().await.unwrap()).unwrap();
    assert_eq!(reloaded["outcome"], "applied", "{reloaded}");
    assert_eq!(reloaded["removed"], json!(["b"]), "{reloaded}");
    let records = reloads(dir.path());
    assert_eq!(records.len(), 2, "{records:?}");
    assert_eq!(
        (records[1].decision.as_str(), records[1].actor.as_deref()),
        ("allow", Some("local"))
    );
    assert!(
        records[1]
            .peer
            .as_deref()
            .is_some_and(|p| p.starts_with("127.0.0.1:")),
        "{records:?}"
    );
    let logged = until("mcpdef: config reloaded (admin API, local)");
    assert!(logged.contains("removed b"), "{logged}");
}

/// Under `[gateway] strict`, a reload to a config with a warning is refused
/// and audited, and the old config keeps serving. Without it, the same change
/// applies.
#[tokio::test]
async fn under_strict_a_reload_to_a_config_with_a_warning_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    let a = server("a", &[], &["echo"]);
    let with_secret = format!("{a}[server.env]\nGITHUB_TOKEN = \"hunter2\"\n");
    std::fs::write(&path, config(dir.path(), "strict = true", &[&a])).unwrap();
    let (gw, mut reloader) = start(&path).await;
    let serving = reloader.digest().to_string();

    std::fs::write(&path, config(dir.path(), "strict = true", &[&with_secret])).unwrap();
    match reloader.reload(Trigger::Signal).await {
        Outcome::Refused { rule, reasons } => {
            assert_eq!(rule, "invalid-config");
            assert_eq!(reasons.len(), 1, "{reasons:?}");
            assert!(
                reasons[0].starts_with("strict: server 'a': [server.env] GITHUB_TOKEN is a secret"),
                "{reasons:?}"
            );
        }
        Outcome::Applied(report) => panic!("applied: {report:?}"),
    }
    assert_eq!(reloader.digest(), serving);
    assert!(echo(&gw, "echo").await.starts_with("echo:"));
    let refused = reloads(dir.path());
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0].rule.as_deref(), Some("invalid-config"));

    std::fs::write(&path, config(dir.path(), "", &[&with_secret])).unwrap();
    let outcome = reloader.reload(Trigger::Signal).await;
    assert!(matches!(outcome, Outcome::Applied(_)), "{outcome:?}");
}

/// The real binary: a reload it applies prints what the new config should
/// not do, as a start does, and a strict one refuses it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reload_prints_its_warnings_and_under_strict_refuses_them() {
    use std::io::BufRead;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    let a = server("a", &[], &["echo"]);
    std::fs::write(&path, config(dir.path(), "", &[&a])).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_mcpdef"))
        .args(["run", "--config"])
        .arg(&path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id().to_string();
    let stderr = child.stderr.take().unwrap();
    let _running = Running(child);
    let (send, lines) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            if send.send(line).is_err() {
                break;
            }
        }
    });
    let mut seen = Vec::new();
    let mut next = || {
        let line = lines
            .recv_timeout(Duration::from_secs(20))
            .unwrap_or_else(|_| panic!("no more lines; stderr so far: {seen:#?}"));
        seen.push(line.clone());
        line
    };
    let hup = || {
        let sent = std::process::Command::new("kill")
            .args(["-HUP", &pid])
            .status()
            .unwrap();
        assert!(sent.success());
    };
    while !next().contains(" ready ") {}

    let with_secret = format!("{a}[server.env]\nGITHUB_TOKEN = \"hunter2\"\n");
    std::fs::write(&path, config(dir.path(), "", &[&with_secret])).unwrap();
    hup();
    let mut line = next();
    while !line.starts_with("mcpdef: config reloaded") {
        line = next();
    }
    assert_eq!(
        next(),
        "mcpdef: warning — server 'a': [server.env] GITHUB_TOKEN is a secret written in the \
         config, so every copy of the config holds it too: read it from a file, a variable or \
         a command instead, as { file = \"…\" }, { env = \"…\" } or { exec = [\"…\"] }"
    );

    std::fs::write(&path, config(dir.path(), "strict = true", &[&with_secret])).unwrap();
    hup();
    let mut line = next();
    while !line.starts_with("mcpdef: config reload refused") {
        line = next();
    }
    assert!(
        line.starts_with(
            "mcpdef: config reload refused (sighup), invalid-config: strict: server 'a': \
             [server.env] GITHUB_TOKEN is a secret written in the config"
        ),
        "{line}"
    );
    assert!(!line.contains("hunter2"), "{line}");
}
