// SPDX-License-Identifier: Apache-2.0
//! `[server.auth]`: MCPdef proving itself to an HTTP upstream that asks for a
//! bearer. Without one the upstream refuses it; with one it takes the calls. A
//! token rotated in its file is read again on the upstream's `401`, and a call
//! the upstream still refuses fails closed, audited as `upstream-auth-failed`.
//! The token is never written to the ledger, the log or the admin API.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use mcpdef::connect::build_gateway;
use mcpdef::{Config, Gateway, HealthState};
use mcpdef_audit::Record;
use mcpdef_core::{method, Id, Message};
use serde_json::json;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// An MCP upstream that takes one bearer token at a time, which a test
/// changes, and answers `401` to any other.
#[derive(Default)]
struct Gate {
    wants: Mutex<String>,
    /// The token each request carried, in order.
    seen: Mutex<Vec<String>>,
}

impl Gate {
    fn wants(&self, token: &str) {
        *self.wants.lock().unwrap() = token.to_string();
    }

    /// The tokens the requests since the last look carried.
    fn seen(&self) -> Vec<String> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }
}

async fn mcp(State(gate): State<Arc<Gate>>, headers: HeaderMap, body: String) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_string();
    let ok = token == *gate.wants.lock().unwrap();
    gate.seen.lock().unwrap().push(token);
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
        )
            .into_response();
    }
    let message = Message::from_json_line(body.trim()).unwrap();
    let Some(id) = message.id.clone() else {
        return StatusCode::ACCEPTED.into_response();
    };
    let arguments = message
        .params
        .as_ref()
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let result = match message.method() {
        Some("initialize") => json!({
            "protocolVersion": "2025-11-25",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "gate", "version": "0" }
        }),
        Some("tools/list") => json!({ "tools": [
            { "name": "echo", "description": "echo arguments back", "inputSchema": { "type": "object" } }
        ]}),
        Some("tools/call") => json!({
            "content": [{ "type": "text", "text": format!("echo:{arguments}") }],
            "isError": false
        }),
        _ => json!({}),
    };
    (
        [(header::CONTENT_TYPE, "application/json")],
        Message::result(id, result).to_json_line(),
    )
        .into_response()
}

async fn serve(gate: Arc<Gate>) -> String {
    let app = Router::new().route("/mcp", post(mcp)).with_state(gate);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/mcp")
}

/// A gateway config with its ledger in `dir`, fronting `url` with `auth` as
/// its `[server.auth]`, if any.
fn config(dir: &Path, url: &str, auth: &str) -> String {
    let audit = dir.join("audit.log");
    format!(
        "[gateway]\nlisten = \"127.0.0.1:0\"\naudit = {audit:?}\n\n\
         [[server]]\nid = \"remote\"\ntransport = \"streamable-http\"\nurl = {url:?}\n\
         tools = [\"echo\"]\n{auth}\n"
    )
}

fn bearer_from(file: &Path) -> String {
    format!("[server.auth]\nkind = \"bearer\"\ntoken = {{ file = {file:?} }}")
}

async fn start(text: &str) -> Gateway {
    let config = Config::parse(text).unwrap();
    assert_eq!(config.validate(), Vec::<String>::new());
    build_gateway(&config).await.unwrap()
}

/// Call `echo`, and say what came back: its text, and whether it was an error.
async fn echo(gw: &Gateway) -> (String, bool) {
    let call = Message::request(
        Id::Num(1),
        method::TOOLS_CALL,
        Some(json!({ "name": "echo", "arguments": {} })),
    );
    let reply = gw.handle(call).await.unwrap().expect("a reply");
    let result = reply.result.expect("a result");
    let text = result["content"][0]["text"].as_str().unwrap_or_default();
    (text.to_string(), result["isError"] == true)
}

fn records(dir: &Path) -> Vec<Record> {
    std::fs::read_to_string(dir.join("audit.log"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[tokio::test]
async fn an_upstream_that_wants_a_bearer_refuses_mcpdef_without_one_and_takes_it_with_one() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, "t1").unwrap();
    let gate = Arc::new(Gate::default());
    gate.wants("t1");
    let url = serve(Arc::clone(&gate)).await;

    // Without: the upstream refuses the opening, and so stays down.
    let bare = start(&config(dir.path(), &url, "")).await;
    let status = bare.upstream_status();
    assert_eq!(status[0].health, HealthState::Down);
    let error = &status[0].last_error.as_ref().expect("why").message;
    assert!(
        error.contains(&format!("{url} answered 401 Unauthorized")),
        "{error}"
    );
    let (text, failed) = echo(&bare).await;
    assert!(
        failed && text.contains("upstream 'remote' is down"),
        "{text}"
    );
    let seen = gate.seen();
    assert!(
        !seen.is_empty() && seen.iter().all(String::is_empty),
        "{seen:?}"
    );
    drop(bare);

    // With: every request carries it. (The one without may still be trying.)
    let gw = start(&config(dir.path(), &url, &bearer_from(&token))).await;
    assert_eq!(echo(&gw).await, ("echo:{}".to_string(), false));
    let seen: Vec<String> = gate.seen().into_iter().filter(|t| !t.is_empty()).collect();
    assert!(
        seen.len() >= 3 && seen.iter().all(|t| t == "t1"),
        "{seen:?}"
    );
}

#[tokio::test]
async fn a_rotated_token_is_read_again_and_a_refused_call_fails_closed_and_is_audited() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, "t1").unwrap();
    let gate = Arc::new(Gate::default());
    gate.wants("t1");
    let url = serve(Arc::clone(&gate)).await;
    let gw = start(&config(dir.path(), &url, &bearer_from(&token))).await;
    assert_eq!(echo(&gw).await, ("echo:{}".to_string(), false));
    gate.seen();

    // Rotated in its file: refused once, read again, and taken.
    gate.wants("t2");
    std::fs::write(&token, "t2").unwrap();
    assert_eq!(echo(&gw).await, ("echo:{}".to_string(), false));
    assert_eq!(gate.seen(), ["t1", "t2"]);

    // The upstream wants what the file does not say: refused, and not sent
    // again, since reading the file again changed nothing.
    gate.wants("t3");
    let (text, failed) = echo(&gw).await;
    assert!(failed, "{text}");
    assert!(
        text.contains(&format!(
            "upstream 'remote' refused MCPdef's credentials: {url} answered 401 Unauthorized"
        )),
        "{text}"
    );
    assert_eq!(gate.seen(), ["t2"]);
    let refused: Vec<Record> = records(dir.path())
        .into_iter()
        .filter(|r| r.rule.as_deref() == Some("upstream-auth-failed"))
        .collect();
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0].decision, "deny");
    assert_eq!(refused[0].tool.as_deref(), Some("echo"));
    assert_eq!(gw.upstream_status()[0].health, HealthState::Degraded);
}

/// Kills the gateway however the test ends.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The real binary, end to end: calls that the upstream takes, and one it
/// refuses. The token is then looked for everywhere MCPdef writes: the ledger,
/// its log, and each admin API route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_token_is_in_no_record_log_line_or_admin_answer() {
    use std::io::BufRead;
    const TOKEN: &str = "tOkEn-7c1d9a0e4b";
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, TOKEN).unwrap();
    let gate = Arc::new(Gate::default());
    gate.wants(TOKEN);
    let url = serve(Arc::clone(&gate)).await;
    let text = config(dir.path(), &url, &bearer_from(&token)).replace(
        "\n\n[[server]]",
        "\n\n[gateway.admin]\nenabled = true\nlisten = \"127.0.0.1:0\"\n\n[[server]]",
    );
    let path = dir.path().join("mcpdef.toml");
    std::fs::write(&path, text).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_mcpdef"))
        .args(["run", "--http", "--config"])
        .arg(&path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let running = Running(child);
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let reading = {
        let log = Arc::clone(&log);
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                log.lock().unwrap().push(line);
            }
        })
    };
    let (listen, admin) = mcpdef_testkit::listening_ports(&log).await;

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
    let call = || {
        let request = Message::request(
            Id::Num(1),
            method::TOOLS_CALL,
            Some(json!({ "name": "echo", "arguments": {} })),
        );
        client
            .post(format!("http://127.0.0.1:{listen}/mcp"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(request.to_json_line())
    };
    let taken: serde_json::Value = serde_json::from_str(&send(call()).await).unwrap();
    assert_eq!(taken["result"]["isError"], false, "{taken}");
    gate.wants("another");
    let refused: serde_json::Value = serde_json::from_str(&send(call()).await).unwrap();
    assert_eq!(refused["result"]["isError"], true, "{refused}");

    let mut answers = Vec::new();
    for route in [
        "/api/v1/servers",
        "/api/v1/status",
        "/api/v1/stats",
        "/api/v1/audit",
        "/metrics",
    ] {
        answers.push((
            route,
            send(client.get(format!("http://127.0.0.1:{admin}{route}"))).await,
        ));
    }
    assert!(
        answers[0].1.contains("\"kind\":\"bearer\""),
        "{}",
        answers[0].1
    );
    assert!(
        answers[3].1.contains("upstream-auth-failed"),
        "{}",
        answers[3].1
    );
    drop(running);
    reading.join().unwrap();

    let ledger = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(ledger.contains("upstream-auth-failed"));
    assert!(!ledger.contains(TOKEN), "the ledger: {ledger}");
    let log = log.lock().unwrap().join("\n");
    assert!(!log.contains(TOKEN), "the log: {log}");
    for (route, answer) in answers {
        assert!(!answer.contains(TOKEN), "{route}: {answer}");
    }
}
