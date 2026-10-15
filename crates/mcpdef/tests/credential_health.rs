// SPDX-License-Identifier: Apache-2.0
//! How the credentials MCPdef sends each upstream fare, and the secrets a URL
//! holds, kept out of everything MCPdef writes.
//!
//! For an upstream sent credentials (`[server.auth]`), the gateway shows when
//! it last took them, the last time it refused them or there were none to
//! send, and when they expire. `/metrics` counts the failures and says when
//! each credential expires: an OAuth token, or the certificate MCPdef
//! presents. A URL's password, and a key in its query, are masked wherever the
//! URL is shown.

use axum::extract::{Path as Route, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use mcpdef::connect::build_gateway;
use mcpdef::metrics::render_upstreams;
use mcpdef::reload::{Outcome, Reloader, Snapshot, Trigger};
use mcpdef::{Config, Gateway, HealthState, UpstreamStatus};
use mcpdef_audit::Record;
use mcpdef_core::{method, Id, Message};
use mcpdef_testkit::{listening_ports, HttpsUpstream, Pki};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// An authorization server and the MCP upstreams behind it, on one port.
///
/// `/token` issues tokens by the client credentials grant. `/oauth` and
/// `/bearer` take a token it issued or one put in `taken`, `/keyed` takes its
/// key in its query, and `/open` takes any request. Each lists one tool, named
/// for it: `oauth_echo`, and so on.
struct Mock {
    /// What `/token` answers: a token with these fields beside it, or `Err`
    /// with this status and body.
    answer: Mutex<Result<Value, (StatusCode, Value)>>,
    /// What each token it issues is called, with a number after it.
    prefix: String,
    issued: Mutex<Vec<String>>,
    /// The tokens `/oauth` and `/bearer` take.
    taken: Mutex<Vec<String>>,
    /// The key `/keyed` takes.
    key: String,
    /// What a route answers every request with, in place of its own answer.
    refusing: Mutex<HashMap<String, StatusCode>>,
}

impl Mock {
    fn new(prefix: &str, key: &str) -> Arc<Self> {
        Arc::new(Mock {
            answer: Mutex::new(Ok(json!({ "token_type": "Bearer", "expires_in": 3600 }))),
            prefix: prefix.to_string(),
            issued: Mutex::default(),
            taken: Mutex::default(),
            key: key.to_string(),
            refusing: Mutex::default(),
        })
    }

    fn issues(&self, fields: Value) {
        *self.answer.lock().unwrap() = Ok(fields);
    }

    fn fails(&self, status: StatusCode, body: Value) {
        *self.answer.lock().unwrap() = Err((status, body));
    }

    /// `route` answers every request with `status`, or with None as itself
    /// again.
    fn answers(&self, route: &str, status: Option<StatusCode>) {
        let mut refusing = self.refusing.lock().unwrap();
        match status {
            Some(status) => refusing.insert(route.to_string(), status),
            None => refusing.remove(route),
        };
    }
}

async fn token_endpoint(State(mock): State<Arc<Mock>>) -> Response {
    let answer = mock.answer.lock().unwrap().clone();
    match answer {
        Ok(mut fields) => {
            let mut issued = mock.issued.lock().unwrap();
            let token = format!("{}-{}", mock.prefix, issued.len() + 1);
            issued.push(token.clone());
            mock.taken.lock().unwrap().push(token.clone());
            fields["access_token"] = token.into();
            Json(fields).into_response()
        }
        Err((status, body)) => (status, Json(body)).into_response(),
    }
}

async fn upstream(
    State(mock): State<Arc<Mock>>,
    Route(route): Route<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let refusal = mock.refusing.lock().unwrap().get(&route).copied();
    if let Some(status) = refusal {
        return status.into_response();
    }
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let admitted = match route.as_str() {
        "oauth" | "bearer" => {
            bearer.is_some_and(|token| mock.taken.lock().unwrap().iter().any(|t| t == token))
        }
        "keyed" => query.get("api_key") == Some(&mock.key),
        _ => true,
    };
    if !admitted {
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
            "serverInfo": { "name": "mock", "version": "0" }
        }),
        Some("tools/list") => json!({ "tools": [
            { "name": format!("{route}_echo"), "inputSchema": { "type": "object" } }
        ]}),
        _ => {
            json!({ "content": [{ "type": "text", "text": format!("{route}:ok") }], "isError": false })
        }
    };
    (
        [(header::CONTENT_TYPE, "application/json")],
        Message::result(id, result).to_json_line(),
    )
        .into_response()
}

/// Where `mock` listens: `127.0.0.1:<port>`.
async fn serve(mock: &Arc<Mock>) -> String {
    let app = Router::new()
        .route("/token", post(token_endpoint))
        .route("/{route}", post(upstream))
        .with_state(Arc::clone(mock));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr.to_string()
}

/// A config with its ledger in `dir`, `gateway` added to its `[gateway]`
/// table, then `servers`.
fn config(dir: &Path, gateway: &str, servers: &str) -> String {
    let audit = dir.join("audit.log");
    format!("[gateway]\nlisten = \"127.0.0.1:0\"\naudit = {audit:?}\n{gateway}\n\n{servers}")
}

/// A `[[server]]` entry for the Streamable-HTTP upstream at `url`, then
/// `rest`.
fn server(id: &str, url: &str, rest: &str) -> String {
    format!("[[server]]\nid = {id:?}\ntransport = \"streamable-http\"\nurl = {url:?}\n{rest}\n\n")
}

/// `[server.auth]` for tokens from `token_url`, the client secret `secret`.
fn oauth2(token_url: &str, secret: &str) -> String {
    format!(
        "[server.auth]\nkind = \"oauth2\"\ntoken_url = {token_url:?}\nclient_id = \"mcpdef\"\n\
         client_secret = {secret}\n"
    )
}

/// `[server.auth]` for the bearer token in `file`.
fn bearer(file: &Path) -> String {
    format!("[server.auth]\nkind = \"bearer\"\ntoken = {{ file = {file:?} }}\n")
}

async fn start(text: &str) -> Gateway {
    let config = Config::parse(text).unwrap();
    assert_eq!(config.validate(), Vec::<String>::new());
    build_gateway(&config).await.unwrap()
}

/// Call `tool`, and say what came back: its text, and whether it was an error.
async fn call(gw: &Gateway, tool: &str) -> (String, bool) {
    let request = Message::request(
        Id::Num(1),
        method::TOOLS_CALL,
        Some(json!({ "name": tool, "arguments": {} })),
    );
    let reply = gw.handle(request).await.unwrap().expect("a reply");
    let result = reply.result.expect("a result");
    let text = result["content"][0]["text"].as_str().unwrap_or_default();
    (text.to_string(), result["isError"] == true)
}

fn status(gw: &Gateway, id: &str) -> UpstreamStatus {
    gw.upstream_status()
        .into_iter()
        .find(|u| u.id == id)
        .expect("the upstream")
}

fn now() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

fn records(dir: &Path) -> Vec<Record> {
    std::fs::read_to_string(dir.join("audit.log"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// The lines of `metrics` for `name`, less its HELP and TYPE.
fn samples<'a>(metrics: &'a str, name: &str) -> Vec<&'a str> {
    metrics.lines().filter(|l| l.starts_with(name)).collect()
}

#[tokio::test]
async fn each_upstream_sent_credentials_shows_when_they_were_taken_refused_and_expire() {
    let dir = tempfile::tempdir().unwrap();
    let mock = Mock::new("tok", "the-key");
    // Sent for half its life: half a second.
    mock.issues(json!({ "token_type": "Bearer", "expires_in": 1 }));
    mock.taken.lock().unwrap().push("static-1".into());
    let base = serve(&mock).await;
    let token = dir.path().join("token");
    std::fs::write(&token, "static-1").unwrap();
    let token_url = format!("http://{base}/token");
    let servers = [
        server(
            "oauth",
            &format!("http://{base}/oauth"),
            &format!(
                "tools = [\"oauth_echo\"]\n{}",
                oauth2(&token_url, "\"s3cret\"")
            ),
        ),
        server(
            "bearer",
            &format!("http://{base}/bearer"),
            &format!("tools = [\"bearer_echo\"]\n{}", bearer(&token)),
        ),
        server(
            "open",
            &format!("http://{base}/open"),
            "tools = [\"open_echo\"]",
        ),
    ]
    .concat();
    let started = now();
    let gw = start(&config(dir.path(), "", &servers)).await;

    // Each opened with its credentials, and so took them. A token says when
    // it expires.
    let oauth = status(&gw, "oauth");
    let credential = oauth.credential.expect("oauth2 is sent credentials");
    let taken = credential.last_ok.expect("taken as it opened").at_unix_ms;
    assert!(taken >= started.as_millis() as u64, "{taken} {started:?}");
    assert_eq!(credential.last_error, None);
    let expiry = credential.expires_at_unix.expect("a token says");
    let secs = |d: Duration| d.as_secs() as i64;
    assert!(
        (secs(started) + 1..=secs(now()) + 1).contains(&expiry),
        "{expiry} {started:?}"
    );
    assert_eq!(
        credential.expires_at,
        Some(mcpdef_transport::rfc3339(expiry))
    );
    assert_eq!(oauth.auth_failures, 0);
    let credential = status(&gw, "bearer").credential.expect("a bearer is sent");
    assert!(credential.last_ok.is_some());
    assert_eq!(credential.expires_at, None, "a bearer token does not say");
    let open = status(&gw, "open");
    assert_eq!(open.credential, None, "it is sent none");
    assert_eq!(open.auth_failures, 0);

    // The token expires while the authorization server is down: there is
    // none to send.
    mock.fails(
        StatusCode::SERVICE_UNAVAILABLE,
        json!({ "error": "temporarily_unavailable" }),
    );
    tokio::time::sleep(Duration::from_millis(600)).await;
    let (text, failed) = call(&gw, "oauth_echo").await;
    assert!(failed, "{text}");
    let oauth = status(&gw, "oauth");
    assert_eq!(oauth.auth_failures, 1);
    let credential = oauth.credential.unwrap();
    assert_eq!(
        credential.last_error.expect("why").message,
        format!(
            "credentials: token endpoint {token_url} answered 503 Service Unavailable: \
             temporarily_unavailable"
        )
    );
    assert_eq!(credential.last_ok.unwrap().at_unix_ms, taken, "not since");
    assert_eq!(credential.expires_at, None, "it holds no token");

    // Back, but the upstream takes no token now: it refuses the call, and a
    // fresh token too.
    mock.issues(json!({ "token_type": "Bearer", "expires_in": 3600 }));
    mock.answers("oauth", Some(StatusCode::UNAUTHORIZED));
    let (text, failed) = call(&gw, "oauth_echo").await;
    assert!(
        failed && text.contains("refused MCPdef's credentials"),
        "{text}"
    );
    let oauth = status(&gw, "oauth");
    assert_eq!(oauth.auth_failures, 2);
    let credential = oauth.credential.unwrap();
    assert_eq!(
        credential.last_error.unwrap().message,
        format!("http://{base}/oauth answered 401 Unauthorized")
    );
    let expiry = credential.expires_at_unix.expect("the fresh token's");
    assert!(expiry >= secs(now()) + 3590, "{expiry}");

    // Taken again, and the refusal stays the last one.
    mock.answers("oauth", None);
    assert_eq!(
        call(&gw, "oauth_echo").await,
        ("oauth:ok".to_string(), false)
    );
    let credential = status(&gw, "oauth").credential.unwrap();
    assert!(credential.last_ok.unwrap().at_unix_ms > taken);
    assert!(credential.last_error.is_some());

    // A bearer refused, counted for its upstream alone.
    mock.answers("bearer", Some(StatusCode::UNAUTHORIZED));
    let (text, failed) = call(&gw, "bearer_echo").await;
    assert!(failed, "{text}");
    let bearer = status(&gw, "bearer");
    assert_eq!(bearer.auth_failures, 1);
    assert_eq!(
        bearer.credential.unwrap().last_error.unwrap().message,
        format!("http://{base}/bearer answered 401 Unauthorized")
    );

    // Each failure is audited under its rule...
    let rules: Vec<Option<String>> = records(dir.path())
        .into_iter()
        .filter(|r| r.decision == "deny")
        .map(|r| r.rule)
        .collect();
    assert_eq!(
        rules,
        [
            Some("credentials-unavailable".to_string()),
            Some("upstream-auth-failed".to_string()),
            Some("upstream-auth-failed".to_string()),
        ]
    );
    // ...and counted, and the token says when it expires.
    let metrics = render_upstreams(&gw.upstream_status());
    assert_eq!(
        samples(&metrics, "mcpdef_upstream_auth_failures_total"),
        [
            "mcpdef_upstream_auth_failures_total{server=\"oauth\"} 2",
            "mcpdef_upstream_auth_failures_total{server=\"bearer\"} 1",
            "mcpdef_upstream_auth_failures_total{server=\"open\"} 0",
        ]
    );
    let expiry = status(&gw, "oauth").credential.unwrap().expires_at_unix;
    assert_eq!(
        samples(&metrics, "mcpdef_credential_expiry_seconds"),
        [format!(
            "mcpdef_credential_expiry_seconds{{server=\"oauth\",credential=\"token\"}} {}",
            expiry.unwrap()
        )]
    );
}

#[tokio::test]
async fn an_upstream_whose_credentials_fail_as_it_opens_shows_why_and_that_it_never_took_them() {
    let dir = tempfile::tempdir().unwrap();
    let mock = Mock::new("tok", "the-key");
    mock.fails(
        StatusCode::UNAUTHORIZED,
        json!({ "error": "invalid_client" }),
    );
    mock.answers("open", Some(StatusCode::UNAUTHORIZED));
    let base = serve(&mock).await;
    let token_url = format!("http://{base}/token");
    let servers = [
        server(
            "oauth",
            &format!("http://{base}/oauth"),
            &oauth2(&token_url, "\"s3cret\""),
        ),
        server("open", &format!("http://{base}/open"), ""),
    ]
    .concat();
    let gw = start(&config(dir.path(), "", &servers)).await;

    let oauth = status(&gw, "oauth");
    assert_eq!(oauth.health, HealthState::Down);
    let credential = oauth.credential.expect("it is sent credentials");
    assert_eq!(credential.last_ok, None);
    assert_eq!(credential.expires_at, None);
    let why = format!("token endpoint {token_url} answered 401 Unauthorized: invalid_client");
    let error = credential.last_error.expect("why").message;
    assert!(error.contains(&why), "{error}");
    let error = oauth.last_error.expect("why").message;
    assert!(error.contains(&why), "{error}");
    assert!(oauth.auth_failures >= 1);

    // One that wants credentials it is not sent: counted, though it shows no
    // credential.
    let open = status(&gw, "open");
    assert_eq!(open.health, HealthState::Down);
    assert_eq!(open.credential, None);
    assert!(open.auth_failures >= 1);
    let error = open.last_error.expect("why").message;
    assert!(
        error.contains(&format!("http://{base}/open answered 401 Unauthorized")),
        "{error}"
    );
}

#[tokio::test]
async fn the_certificate_mcpdef_presents_says_when_it_expires() {
    let dir = tempfile::tempdir().unwrap();
    let servers_ca = Pki::new("servers CA");
    let clients = Pki::new("clients CA");
    let upstream = HttpsUpstream::start_mtls(
        &servers_ca
            .leaf()
            .name("127.0.0.1")
            .server_auth()
            .valid((2020, 1, 1), (2031, 2, 3))
            .issue(),
        &clients,
        &[],
    )
    .await;
    let plain = HttpsUpstream::start(&servers_ca.server(&["127.0.0.1"])).await;
    let ca = servers_ca.write_root(dir.path(), "ca");
    let leaf = clients
        .leaf()
        .uri("spiffe://example.org/mcpdef")
        .client_auth()
        .valid((2020, 1, 1), (2032, 5, 6))
        .issue();
    let (cert, key) = leaf.write(dir.path(), "gateway");
    let servers = [
        server(
            "mtls",
            &upstream.url(),
            &format!(
                "[server.tls]\nca = [{ca:?}]\nclient_cert = {cert:?}\n\
                 client_key = {{ file = {key:?} }}"
            ),
        ),
        server(
            "server-only",
            &plain.url(),
            &format!("[server.tls]\nca = [{ca:?}]"),
        ),
    ]
    .concat();
    let gw = start(&config(dir.path(), "", &servers)).await;

    let tls = status(&gw, "mtls").tls.expect("an HTTPS upstream");
    assert_eq!(
        tls.client_not_after.as_deref(),
        Some("2032-05-06T00:00:00Z")
    );
    assert_eq!(tls.client_not_after_unix, Some(1_967_414_400));
    assert_eq!(
        tls.not_after.as_deref(),
        Some("2031-02-03T00:00:00Z"),
        "the server's own"
    );
    // On `/api/v1/servers`, in RFC 3339 alone.
    let shown = serde_json::to_value(&tls).unwrap();
    assert_eq!(shown["client_not_after"], "2032-05-06T00:00:00Z");
    assert_eq!(shown.get("client_not_after_unix"), None, "{shown}");
    let tls = status(&gw, "server-only").tls.expect("an HTTPS upstream");
    assert_eq!(tls.client_not_after, None);
    let shown = serde_json::to_value(&tls).unwrap();
    assert_eq!(shown.get("client_not_after"), None, "{shown}");

    let metrics = render_upstreams(&gw.upstream_status());
    assert_eq!(
        samples(&metrics, "mcpdef_credential_expiry_seconds"),
        ["mcpdef_credential_expiry_seconds{server=\"mtls\",credential=\"client_cert\"} 1967414400"]
    );
}

#[tokio::test]
async fn a_reload_that_gives_upstreams_credentials_shows_them_and_one_that_takes_them_away_does_not(
) {
    let dir = tempfile::tempdir().unwrap();
    let mock = Mock::new("tok", "the-key");
    let base = serve(&mock).await;
    let token = dir.path().join("token");
    std::fs::write(&token, "static-1").unwrap();
    let url = format!("http://{base}/open");
    let without = config(dir.path(), "", &server("open", &url, ""));
    let with = config(
        dir.path(),
        "",
        &[
            server("open", &url, &bearer(&token)),
            server("added", &url, &bearer(&token)),
        ]
        .concat(),
    );
    let path = dir.path().join("mcpdef.toml");
    std::fs::write(&path, &without).unwrap();
    let (config, text) = Config::load_text(&path).unwrap();
    let snapshot = Snapshot::take(text.as_bytes(), &config);
    let gw = build_gateway(&config).await.unwrap();
    let mut reloader = Reloader::new(&path, None, gw.clone(), config, snapshot);
    assert_eq!(status(&gw, "open").credential, None);

    std::fs::write(&path, &with).unwrap();
    assert!(matches!(
        reloader.reload(Trigger::Signal).await,
        Outcome::Applied(_)
    ));
    for id in ["open", "added"] {
        let credential = status(&gw, id).credential.expect("it is sent some now");
        assert!(
            credential.last_ok.is_some(),
            "{id}: its new connection took them"
        );
    }

    std::fs::write(&path, &without).unwrap();
    assert!(matches!(
        reloader.reload(Trigger::Signal).await,
        Outcome::Applied(_)
    ));
    assert_eq!(status(&gw, "open").credential, None);
}

/// Kills the gateway however the test ends.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// What the binary run with `args` wrote, stdout and stderr together.
fn mcpdef(args: &[&str]) -> String {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_mcpdef"))
        .args(args)
        .output()
        .unwrap();
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The real binary, end to end, fronting upstreams sent every kind of
/// credential: an OAuth token from a token endpoint whose URL holds a key, a
/// bearer token, and a URL holding a password and a key, one that answers and
/// one that never does. Calls are taken, refused, and made with no token to
/// send. Then each secret planted is looked for in everything MCPdef wrote:
/// the ledger, its log, its answers, each admin API route, `servers list`,
/// `egress show`, `validate`, `call`, and an error a command exits with. Each
/// URL is shown, masked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_secret_a_url_or_a_credential_holds_is_in_anything_mcpdef_writes() {
    use std::io::BufRead;
    const PASSWORD: &str = "pAsSwOrD-3c1f";
    const KEY: &str = "kEy-77b0e2";
    const IDP_KEY: &str = "iDpKeY-5d2a";
    const CLIENT_SECRET: &str = "cLiEnT-9e44";
    const BEARER: &str = "bEaReR-0a6c";
    const TOKEN: &str = "aCcEsS-41f8";
    let dir = tempfile::tempdir().unwrap();
    let mock = Mock::new(TOKEN, KEY);
    // Sent for half its life: half a second.
    mock.issues(json!({ "token_type": "Bearer", "expires_in": 1 }));
    mock.taken.lock().unwrap().push(BEARER.into());
    let base = serve(&mock).await;
    let (secret, token) = (dir.path().join("client-secret"), dir.path().join("token"));
    std::fs::write(&secret, CLIENT_SECRET).unwrap();
    std::fs::write(&token, BEARER).unwrap();
    let token_url = format!("http://{base}/token?api_key={IDP_KEY}");
    let keyed = format!("http://mcpdef:{PASSWORD}@{base}/keyed?api_key={KEY}&v=2");
    let far = format!("https://mcpdef:{PASSWORD}@127.0.0.1:1/mcp?api_key={KEY}");
    let servers = [
        server(
            "oauth",
            &format!("http://{base}/oauth"),
            &format!(
                "tools = [\"oauth_echo\"]\n{}",
                oauth2(&token_url, &format!("{{ file = {secret:?} }}"))
            ),
        ),
        server(
            "bearer",
            &format!("http://{base}/bearer"),
            &format!("tools = [\"bearer_echo\"]\n{}", bearer(&token)),
        ),
        server("keyed", &keyed, "tools = [\"keyed_echo\"]"),
        server("far", &far, "tools = [\"far_echo\"]"),
    ]
    .concat();
    let text = config(
        dir.path(),
        "\n[gateway.admin]\nenabled = true\nlisten = \"127.0.0.1:0\"",
        &servers,
    );
    let path = dir.path().join("mcpdef.toml");
    std::fs::write(&path, text).unwrap();
    let config_path = path.to_str().unwrap();

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_mcpdef"))
        .args(["run", "--http", "--config", config_path])
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
    let (listen, admin) = listening_ports(&log).await;

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
    let mut answers = Vec::new();
    let mut call = async |tool: &str| {
        let request = Message::request(
            Id::Num(1),
            method::TOOLS_CALL,
            Some(json!({ "name": tool, "arguments": {} })),
        );
        let answer = send(
            client
                .post(format!("http://127.0.0.1:{listen}/mcp"))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .body(request.to_json_line()),
        )
        .await;
        let parsed: Value = serde_json::from_str(&answer).unwrap();
        answers.push(answer);
        parsed["result"]["isError"] == false
    };
    // Taken, each of them.
    assert!(call("oauth_echo").await);
    assert!(call("bearer_echo").await);
    assert!(call("keyed_echo").await);
    // The token expires, and the token endpoint refuses MCPdef, repeating
    // its client secret.
    mock.fails(
        StatusCode::UNAUTHORIZED,
        json!({ "error": "invalid_client", "error_description": format!("bad {CLIENT_SECRET}") }),
    );
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(!call("oauth_echo").await);
    // Refused, then failed until it is down, with the URL named each time.
    mock.answers("keyed", Some(StatusCode::UNAUTHORIZED));
    assert!(!call("keyed_echo").await);
    mock.answers("keyed", Some(StatusCode::INTERNAL_SERVER_ERROR));
    for _ in 0..5 {
        assert!(!call("keyed_echo").await);
    }
    mock.answers("bearer", Some(StatusCode::UNAUTHORIZED));
    assert!(!call("bearer_echo").await);
    let answers = answers.join("\n");

    let mut routes = Vec::new();
    for route in [
        "/api/v1/servers",
        "/api/v1/status",
        "/api/v1/stats",
        "/api/v1/audit",
        "/metrics",
    ] {
        let url = format!("http://127.0.0.1:{admin}{route}");
        routes.push((route, send(client.get(url)).await));
    }
    let until = Instant::now() + Duration::from_secs(10);
    while !log
        .lock()
        .unwrap()
        .iter()
        .any(|l| l.contains("upstream 'keyed' is down"))
    {
        assert!(
            Instant::now() < until,
            "not down: {:#?}",
            log.lock().unwrap()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(running);
    reading.join().unwrap();

    // What the commands print, the keyed upstream refusing MCPdef still.
    let servers_list = mcpdef(&["servers", "list", "--config", config_path]);
    let egress_show = mcpdef(&["egress", "show", "--config", config_path]);
    let validate = mcpdef(&["validate", "--config", config_path]);
    let called = mcpdef(&["call", "--config", config_path, "keyed_echo"]);
    let pinned = mcpdef(&["tls", "pin", &far]);

    let masked_keyed = format!("http://***:***@{base}/keyed?api_key=***&v=2");
    let failed =
        format!("Streamable HTTP POST to {masked_keyed} returned 500 Internal Server Error");
    let down = format!("5 calls in a row failed; the last: http: {failed}");
    let masked_far = "https://***:***@127.0.0.1:1/mcp?api_key=***";
    let masked_token_url = format!("http://{base}/token?api_key=***");
    let ledger = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    let log = log.lock().unwrap().join("\n");
    let servers: Value = serde_json::from_str(&routes[0].1).unwrap();
    let by_id = |id: &str| {
        servers
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == id)
            .cloned()
            .unwrap()
    };

    // Each URL is shown, masked. (The ledger records a denial's rule, not
    // its reason, so it names no URL.)
    for (name, output, masked) in [
        ("the answers", &answers, masked_keyed.as_str()),
        ("the answers", &answers, masked_token_url.as_str()),
        (
            "the answers",
            &answers,
            &format!("upstream 'keyed' is down ({down})"),
        ),
        (
            "the log",
            &log,
            &format!("upstream 'keyed' is down: {down}"),
        ),
        ("the log", &log, "https://127.0.0.1:1/mcp?api_key=***"),
        ("servers list", &servers_list, masked_token_url.as_str()),
        ("egress show", &egress_show, masked_far),
        ("call", &called, masked_keyed.as_str()),
        (
            "tls pin",
            &pinned,
            "https://***:***@127.0.0.1:1/mcp?api_key=***",
        ),
    ] {
        assert!(output.contains(masked), "{name} lacks {masked}: {output}");
    }
    assert!(answers.contains(&failed), "{answers}");
    assert_eq!(by_id("keyed")["url"], masked_keyed);
    assert_eq!(by_id("far")["url"], masked_far);
    assert_eq!(by_id("oauth")["auth"]["token_url"], masked_token_url);
    let oauth = by_id("oauth");
    let why = oauth["credential"]["last_error"]["message"]
        .as_str()
        .unwrap();
    assert!(
        why.contains(&format!("token endpoint {masked_token_url} answered 401")),
        "{oauth}"
    );
    assert!(
        oauth["credential"]["last_ok"]["at_unix_ms"].is_u64(),
        "{oauth}"
    );
    let bearer = by_id("bearer");
    assert!(
        bearer["credential"]["last_error"]["message"].is_string(),
        "{bearer}"
    );
    assert_eq!(
        by_id("keyed").get("credential"),
        None,
        "sent no [server.auth]"
    );
    let far_error = by_id("far")["last_error"]["message"].to_string();
    assert!(far_error.contains("api_key=***"), "{far_error}");
    let metrics = &routes[4].1;
    for line in [
        "mcpdef_upstream_auth_failures_total{server=\"oauth\"} 1",
        "mcpdef_upstream_auth_failures_total{server=\"bearer\"} 1",
        "mcpdef_upstream_auth_failures_total{server=\"keyed\"} 1",
        "mcpdef_upstream_auth_failures_total{server=\"far\"} 0",
    ] {
        assert!(metrics.lines().any(|l| l == line), "no {line}: {metrics}");
    }

    // ...and no secret is anywhere.
    let mut outputs = vec![
        ("the ledger", ledger),
        ("the log", log),
        ("the answers", answers),
        ("servers list", servers_list),
        ("egress show", egress_show),
        ("validate", validate),
        ("call", called),
        ("tls pin", pinned),
    ];
    outputs.extend(routes);
    // Every token issued begins with the same prefix.
    for (name, output) in &outputs {
        for secret in [PASSWORD, KEY, IDP_KEY, CLIENT_SECRET, BEARER, TOKEN] {
            assert!(!output.contains(secret), "{name} holds {secret}: {output}");
        }
    }
}
