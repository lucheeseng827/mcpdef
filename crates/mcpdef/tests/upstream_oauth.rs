// SPDX-License-Identifier: Apache-2.0
//! `[server.auth] kind = "oauth2"`: MCPdef fetching a token by the client
//! credentials grant, from a mock authorization server, for a mock upstream
//! that takes the tokens it issues. Fifty calls at once send one token, and
//! when it expires fifty more fetch one more. With no token to send, a call
//! fails closed, audited as `credentials-unavailable`. Neither the client
//! secret nor a token is written to the ledger, the log or the admin API.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use mcpdef::connect::build_gateway;
use mcpdef::{Config, Gateway, HealthState};
use mcpdef_audit::Record;
use mcpdef_core::{method, Id, Message};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// An authorization server's token endpoint, and an MCP upstream that takes
/// the token it issued last and refuses any other.
struct Idp {
    /// The token endpoint's answer: a token with these fields beside it, or
    /// `Err` with this status and body.
    answer: Mutex<Result<Value, (StatusCode, Value)>>,
    /// What each token it issued is called, with a number after it.
    prefix: String,
    issued: Mutex<Vec<String>>,
    /// Each token request's form, in order.
    asked: Mutex<Vec<Vec<(String, String)>>>,
    /// The token each upstream request carried, in order.
    seen: Mutex<Vec<String>>,
}

impl Idp {
    fn new(prefix: &str) -> Arc<Self> {
        Arc::new(Idp {
            answer: Mutex::new(Ok(json!({ "token_type": "Bearer", "expires_in": 3600 }))),
            prefix: prefix.to_string(),
            issued: Mutex::default(),
            asked: Mutex::default(),
            seen: Mutex::default(),
        })
    }

    fn issues(&self, fields: Value) {
        *self.answer.lock().unwrap() = Ok(fields);
    }

    fn fails(&self, status: StatusCode, body: Value) {
        *self.answer.lock().unwrap() = Err((status, body));
    }

    /// How many tokens it was asked for since the last look.
    fn asked(&self) -> usize {
        std::mem::take(&mut *self.asked.lock().unwrap()).len()
    }

    fn seen(&self) -> Vec<String> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }
}

async fn token_endpoint(State(idp): State<Arc<Idp>>, body: String) -> Response {
    idp.asked.lock().unwrap().push(
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect(),
    );
    let answer = idp.answer.lock().unwrap().clone();
    match answer {
        Ok(mut fields) => {
            let mut issued = idp.issued.lock().unwrap();
            let token = format!("{}-{}", idp.prefix, issued.len() + 1);
            issued.push(token.clone());
            fields["access_token"] = token.into();
            Json(fields).into_response()
        }
        Err((status, body)) => (status, Json(body)).into_response(),
    }
}

async fn mcp(State(idp): State<Arc<Idp>>, headers: HeaderMap, body: String) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_string();
    let ok = idp.issued.lock().unwrap().last() == Some(&token);
    idp.seen.lock().unwrap().push(token);
    if !ok {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let message = Message::from_json_line(body.trim()).unwrap();
    let Some(id) = message.id.clone() else {
        return StatusCode::ACCEPTED.into_response();
    };
    let result = match message.method() {
        Some("initialize") => json!({
            "protocolVersion": "2025-11-25",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "gate", "version": "0" }
        }),
        Some("tools/list") => json!({ "tools": [
            { "name": "echo", "description": "echo", "inputSchema": { "type": "object" } }
        ]}),
        _ => json!({ "content": [{ "type": "text", "text": "echo:{}" }], "isError": false }),
    };
    (
        [(header::CONTENT_TYPE, "application/json")],
        Message::result(id, result).to_json_line(),
    )
        .into_response()
}

/// The upstream's URL, and the token endpoint's.
async fn serve(idp: &Arc<Idp>) -> (String, String) {
    let app = Router::new()
        .route("/mcp", post(mcp))
        .route("/token", post(token_endpoint))
        .with_state(Arc::clone(idp));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/mcp"), format!("http://{addr}/token"))
}

/// A gateway config with its ledger in `dir`, fronting `url` with a token
/// from `token_url`, its client secret `secret`.
fn config(dir: &Path, url: &str, token_url: &str, secret: &str) -> String {
    let audit = dir.join("audit.log");
    format!(
        "[gateway]\nlisten = \"127.0.0.1:0\"\naudit = {audit:?}\n\n\
         [[server]]\nid = \"remote\"\ntransport = \"streamable-http\"\nurl = {url:?}\n\
         tools = [\"echo\"]\n\n\
         [server.auth]\nkind = \"oauth2\"\ntoken_url = {token_url:?}\n\
         client_id = \"mcpdef\"\nclient_secret = {secret}\nscopes = [\"mcp:tools\"]\n"
    )
}

async fn start(text: &str) -> Gateway {
    let config = Config::parse(text).unwrap();
    assert_eq!(config.validate(), Vec::<String>::new());
    build_gateway(&config).await.unwrap()
}

/// Call `echo`, and say what came back: its text, and whether it was an error.
async fn echo(gw: Gateway) -> (String, bool) {
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

/// Fifty calls at once, each of which must be answered.
async fn fifty(gw: &Gateway) {
    let calls = (0..50).map(|_| tokio::spawn(echo(gw.clone())));
    for answer in futures_util::future::join_all(calls).await {
        assert_eq!(answer.unwrap(), ("echo:{}".to_string(), false));
    }
}

fn records(dir: &Path) -> Vec<Record> {
    std::fs::read_to_string(dir.join("audit.log"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fifty_calls_at_once_fetch_one_token_and_one_more_once_it_expires() {
    let dir = tempfile::tempdir().unwrap();
    let idp = Idp::new("tok");
    // Sent for half its life: a second.
    idp.issues(json!({ "token_type": "Bearer", "expires_in": 2 }));
    let (url, token_url) = serve(&idp).await;
    let fetched = Instant::now();
    let gw = start(&config(dir.path(), &url, &token_url, "\"s3cret\"")).await;
    fifty(&gw).await;
    assert!(
        fetched.elapsed() < Duration::from_secs(1),
        "too slow to tell"
    );
    let asked = std::mem::take(&mut *idp.asked.lock().unwrap());
    assert_eq!(asked.len(), 1, "{asked:?}");
    // For the upstream it fronts: RFC 8707's resource.
    let field = |name: &str| {
        asked[0]
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(field("grant_type").as_deref(), Some("client_credentials"));
    assert_eq!(field("scope").as_deref(), Some("mcp:tools"));
    assert_eq!(field("resource"), Some(url.clone()));
    assert!(idp.seen().iter().all(|t| t == "tok-1"));

    // Expired: fifty more fetch one more, and all send it.
    tokio::time::sleep(Duration::from_millis(1100).saturating_sub(fetched.elapsed())).await;
    fifty(&gw).await;
    assert_eq!(idp.asked(), 1);
    let seen = idp.seen();
    assert_eq!(seen.len(), 50, "none refused: {seen:?}");
    assert!(seen.iter().all(|t| t == "tok-2"), "{seen:?}");
}

#[tokio::test]
async fn with_no_token_a_call_fails_closed_and_is_audited_as_credentials_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let idp = Idp::new("tok");
    idp.issues(json!({ "token_type": "Bearer", "expires_in": 1 }));
    let (url, token_url) = serve(&idp).await;
    let gw = start(&config(dir.path(), &url, &token_url, "\"s3cret\"")).await;
    assert_eq!(echo(gw.clone()).await, ("echo:{}".to_string(), false));
    idp.seen();

    // The token expires while the server is down: nothing is sent.
    idp.fails(
        StatusCode::SERVICE_UNAVAILABLE,
        json!({ "error": "temporarily_unavailable" }),
    );
    tokio::time::sleep(Duration::from_millis(600)).await;
    let (text, failed) = echo(gw.clone()).await;
    assert!(failed, "{text}");
    assert!(
        text.contains(&format!(
            "no credentials for upstream 'remote': token endpoint {token_url} answered 503 \
             Service Unavailable: temporarily_unavailable"
        )),
        "{text}"
    );
    assert!(idp.seen().is_empty(), "nothing sent without a token");
    let denied: Vec<Record> = records(dir.path())
        .into_iter()
        .filter(|r| r.rule.as_deref() == Some("credentials-unavailable"))
        .collect();
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0].decision, "deny");
    assert_eq!(denied[0].tool.as_deref(), Some("echo"));

    // Back: the next call fetches, and is answered.
    idp.issues(json!({ "token_type": "Bearer", "expires_in": 3600 }));
    assert_eq!(echo(gw.clone()).await, ("echo:{}".to_string(), false));
    assert_eq!(idp.seen(), ["tok-2"]);
}

#[tokio::test]
async fn an_upstream_whose_token_endpoint_fails_does_not_open_and_says_why() {
    let dir = tempfile::tempdir().unwrap();
    let idp = Idp::new("tok");
    idp.fails(
        StatusCode::UNAUTHORIZED,
        json!({ "error": "invalid_client" }),
    );
    let (url, token_url) = serve(&idp).await;
    let gw = start(&config(dir.path(), &url, &token_url, "\"s3cret\"")).await;
    let status = gw.upstream_status();
    assert_eq!(status[0].health, HealthState::Down);
    let error = &status[0].last_error.as_ref().expect("why").message;
    assert!(
        error.contains(&format!(
            "token endpoint {token_url} answered 401 Unauthorized: invalid_client"
        )),
        "{error}"
    );
    assert!(idp.seen().is_empty(), "the upstream was sent nothing");
    let (text, failed) = echo(gw.clone()).await;
    assert!(
        failed && text.contains("upstream 'remote' is down"),
        "{text}"
    );
}

/// Kills the gateway however the test ends.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The real binary, end to end: calls with a token, one refused and sent
/// again with a fresh one, and one with none to send, from a server that
/// repeats the client secret in its error. Then the secret and every token
/// are looked for everywhere MCPdef writes: the ledger, its log, and each
/// admin API route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_client_secret_and_the_tokens_are_in_no_record_log_line_or_admin_answer() {
    use std::io::BufRead;
    const SECRET: &str = "cLiEnT-s3cret-5e0b2d";
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("client-secret");
    std::fs::write(&secret, SECRET).unwrap();
    let idp = Idp::new("aCcEsS-9f41c7");
    let (url, token_url) = serve(&idp).await;
    let text = config(
        dir.path(),
        &url,
        &token_url,
        &format!("{{ file = {secret:?} }}"),
    )
    .replace(
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
    let answered = |text: String| -> Value { serde_json::from_str(&text).unwrap() };
    let taken = answered(send(call()).await);
    assert_eq!(taken["result"]["isError"], false, "{taken}");
    // Revoked: refused, a fresh token fetched, and taken.
    idp.issued.lock().unwrap().push("revoked".to_string());
    let taken = answered(send(call()).await);
    assert_eq!(taken["result"]["isError"], false, "{taken}");
    // Refused, and the server will not issue another, and says the secret.
    idp.issued.lock().unwrap().push("revoked again".to_string());
    idp.fails(
        StatusCode::UNAUTHORIZED,
        json!({ "error": "invalid_client", "error_description": format!("bad secret {SECRET}") }),
    );
    let refused = answered(send(call()).await);
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
        answers[0].1.contains("\"kind\":\"oauth2\""),
        "{}",
        answers[0].1
    );
    assert!(
        answers[3].1.contains("credentials-unavailable"),
        "{}",
        answers[3].1
    );
    drop(running);
    reading.join().unwrap();

    let issued = idp.issued.lock().unwrap().clone();
    let tokens: Vec<&String> = issued.iter().filter(|t| t.starts_with("aCcEsS")).collect();
    assert_eq!(tokens.len(), 2, "{issued:?}");
    let ledger = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(ledger.contains("credentials-unavailable"));
    let log = log.lock().unwrap().join("\n");
    let mut outputs = vec![("the ledger", ledger), ("the log", log)];
    outputs.extend(answers);
    for (name, output) in &outputs {
        for secret in std::iter::once(SECRET).chain(tokens.iter().map(|t| t.as_str())) {
            assert!(!output.contains(secret), "{name} holds {secret}: {output}");
        }
        // Nor any token's prefix: a token cut short is still one.
        assert!(!output.contains("aCcEsS"), "{name}: {output}");
    }
}
