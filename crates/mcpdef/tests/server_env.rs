// SPDX-License-Identifier: Apache-2.0
//! What a stdio upstream is given by its `[server.env]`: each value read from
//! where the config says, at every spawn, so that a restart or a reload picks
//! up a rotated secret; and when one cannot be read, an error that says where
//! it comes from and holds no value.

use mcpdef::connect::build_gateway;
use mcpdef::reload::{Outcome, Reloader, Snapshot, Trigger};
use mcpdef::{Config, Gateway, HealthState};
use mcpdef_core::{method, Id, Message};
use serde_json::json;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

/// A `[gateway]` table with its ledger in `dir`, then `rest`.
fn config(dir: &Path, rest: &str) -> String {
    let audit = dir.join("audit.log");
    format!("[gateway]\nlisten = \"127.0.0.1:0\"\naudit = {audit:?}\n\n{rest}")
}

/// A `[[server]]` entry for the stdio mock, its tools named `{id}_…`, with
/// `flags`, then `env` as its `[server.env]`.
fn server(id: &str, flags: &[&str], env: &str) -> String {
    let mut command = vec![MOCK.to_string(), "--tool-prefix".into(), format!("{id}_")];
    command.extend(flags.iter().map(|f| f.to_string()));
    format!("[[server]]\nid = {id:?}\ntransport = \"stdio\"\ncommand = {command:?}\n[server.env]\n{env}\n\n")
}

async fn start(text: &str) -> Gateway {
    let config = Config::parse(text).unwrap();
    assert_eq!(config.validate(), Vec::<String>::new());
    build_gateway(&config).await.unwrap()
}

async fn call(gw: &Gateway, tool: &str, arguments: serde_json::Value) -> String {
    let call = Message::request(
        Id::Num(1),
        method::TOOLS_CALL,
        Some(json!({ "name": tool, "arguments": arguments })),
    );
    let reply = gw.handle(call).await.unwrap().expect("a reply");
    reply.result.expect("a result")["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// What server `id` sees of its variable `name`, or `(unset)`.
async fn seen(gw: &Gateway, id: &str, name: &str) -> String {
    call(gw, &format!("{id}_env"), json!({ "name": name })).await
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

/// The one test here that sets a variable of the process's own environment.
#[tokio::test]
async fn each_form_of_value_reaches_its_server_and_a_variable_read_reaches_no_other() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, "from-a-file\n").unwrap();
    std::env::set_var("MCPDEF_TEST_ENV_SOURCE", "from-mcpdefs-env");
    let env = format!(
        "LITERAL = \"written\"\nFROM_ENV = {{ env = \"MCPDEF_TEST_ENV_SOURCE\" }}\n\
         FROM_FILE = {{ file = {token:?} }}\nFROM_EXEC = {{ exec = [\"printf\", \"%s\", \"ran\"] }}"
    );
    let text = config(
        dir.path(),
        &format!(
            "{}{}",
            server("a", &["--with-env"], &env),
            server("b", &["--with-env"], "")
        ),
    );
    let gw = start(&text).await;

    assert_eq!(seen(&gw, "a", "LITERAL").await, "written");
    assert_eq!(seen(&gw, "a", "FROM_ENV").await, "from-mcpdefs-env");
    assert_eq!(seen(&gw, "a", "FROM_FILE").await, "from-a-file");
    assert_eq!(seen(&gw, "a", "FROM_EXEC").await, "ran");
    // The variable a value is read from is given to no child as itself, and
    // another server is given none of these.
    assert_eq!(seen(&gw, "a", "MCPDEF_TEST_ENV_SOURCE").await, "(unset)");
    assert_eq!(seen(&gw, "b", "MCPDEF_TEST_ENV_SOURCE").await, "(unset)");
    assert_eq!(seen(&gw, "b", "FROM_ENV").await, "(unset)");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_reads_a_rotated_file_again() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, "v1").unwrap();
    let env = format!("TOKEN = {{ file = {token:?} }}");
    let gw = start(&config(
        dir.path(),
        &server("a", &["--with-env", "--with-pid"], &env),
    ))
    .await;
    assert_eq!(seen(&gw, "a", "TOKEN").await, "v1");

    std::fs::write(&token, "v2").unwrap();
    let pid = call(&gw, "a_pid", json!({})).await;
    let killed = std::process::Command::new("kill")
        .args(["-9", &pid])
        .status()
        .unwrap();
    assert!(killed.success());
    assert!(
        eventually(Duration::from_secs(5), || health(&gw, "a")
            != HealthState::Up)
        .await
    );
    assert!(
        eventually(Duration::from_secs(10), || health(&gw, "a")
            == HealthState::Up)
        .await
    );
    assert_ne!(call(&gw, "a_pid", json!({})).await, pid);
    assert_eq!(seen(&gw, "a", "TOKEN").await, "v2");
}

/// A reload notices a changed file a value is read from, and starts that
/// server again, alone.
#[tokio::test]
async fn a_reload_after_a_file_changed_starts_its_server_again() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, "v1").unwrap();
    let env = format!("TOKEN = {{ file = {token:?} }}");
    let path = dir.path().join("mcpdef.toml");
    let text = config(
        dir.path(),
        &format!(
            "{}{}",
            server("a", &["--with-env"], &env),
            server("b", &["--with-env"], "")
        ),
    );
    std::fs::write(&path, &text).unwrap();
    let (config, text) = Config::load_text(&path).unwrap();
    let snapshot = Snapshot::take(text.as_bytes(), &config);
    let gw = build_gateway(&config).await.unwrap();
    assert_eq!(seen(&gw, "a", "TOKEN").await, "v1");

    let mut reloader = Reloader::new(&path, None, gw.clone(), config, snapshot);
    std::fs::write(&token, "v2").unwrap();
    let Outcome::Applied(report) = reloader.reload(Trigger::Signal).await else {
        panic!("the reload applies")
    };
    assert_eq!(report.reconnected, ["a"]);
    assert_eq!(seen(&gw, "a", "TOKEN").await, "v2");
}

/// A value that cannot be read leaves its server down, and the others
/// serving. What went wrong names the server, the variable and where its value
/// comes from: a command by its program alone, and never a value.
#[tokio::test]
async fn a_value_that_cannot_be_read_leaves_its_server_down_and_says_where() {
    let dir = tempfile::tempdir().unwrap();
    let env = "FINE = \"s3cret-literal\"\nTOKEN = { exec = [\"false\", \"s3cret-argument\"] }";
    let text = config(
        dir.path(),
        &format!(
            "{}{}",
            server("bad", &["--with-env"], env),
            server("good", &["--with-env"], "")
        ),
    );
    let gw = start(&text).await;
    assert_ne!(seen(&gw, "good", "PATH").await, "(unset)");
    let status = gw.upstream_status();
    let bad = status.iter().find(|u| u.id == "bad").unwrap();
    assert_eq!(bad.health, HealthState::Down);
    let error = &bad.last_error.as_ref().expect("an error").message;
    assert!(
        error.contains("server 'bad': [server.env] TOKEN: (exec false): exited with status 1"),
        "{error}"
    );
    assert!(!error.contains("s3cret"), "{error}");
}

/// A value a command writes is read off the async workers: while the command
/// takes its time, the gateway's other tasks go on, though its runtime has one
/// thread.
#[tokio::test(flavor = "current_thread")]
async fn a_value_a_command_writes_leaves_the_runtime_free() {
    let dir = tempfile::tempdir().unwrap();
    let env = "TOKEN = { exec = [\"sh\", \"-c\", \"sleep 0.5; echo slow\"] }";
    let text = config(dir.path(), &server("a", &["--with-env"], env));
    let ticks = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&ticks);
    let ticker = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            counter.fetch_add(1, Ordering::Relaxed);
        }
    });
    let gw = start(&text).await;
    ticker.abort();
    let ticks = ticks.load(Ordering::Relaxed);
    assert!(ticks >= 20, "{ticks} ticks while the server started");
    assert_eq!(seen(&gw, "a", "TOKEN").await, "slow");
}
