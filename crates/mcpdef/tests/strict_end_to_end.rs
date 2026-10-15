// SPDX-License-Identifier: Apache-2.0
//! A gateway run as a careful deployment runs it, end to end: strict, every
//! secret kept out of its config, and none of them in anything it writes.
//!
//! It fronts two stdio servers that each take an API key, one from a variable
//! of MCPdef's own and one from a file, and a Streamable-HTTP upstream on a
//! private CA that wants a client certificate and an OAuth token. The token
//! comes by the client credentials grant from an authorization server on the
//! same CA, with a client secret a command prints. `validate --strict` passes
//! the config, the gateway starts with every upstream up, and each server gets
//! the credentials meant for it and no other's. No secret appears in the
//! ledger, the log, the admin API (the audit API's pages, verify and exports,
//! every state view, and the config file as it shows it, among it), its
//! status page, `/metrics`, `servers list`, `egress show`, `doctor` (which
//! opens every upstream as the gateway does), `tls show` or `connect`.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use mcpdef_core::{method, Id, Message};
use mcpdef_testkit::{listening_ports, HttpsUpstream, Pki};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");
const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

/// The secrets planted. None has a known credential's shape, so none can be
/// found by its shape: each must be kept out by where it comes from.
const GITHUB_TOKEN: &str = "gItHuB-pLaNtEd-6f2a91";
const SLACK_TOKEN: &str = "sLaCk-pLaNtEd-3d77c0";
const CLIENT_SECRET: &str = "cLiEnT-pLaNtEd-9b1e44";
/// What each access token the authorization server issues begins with.
const TOKEN_PREFIX: &str = "aCcEsS-pLaNtEd";

/// An authorization server that issues tokens to one client, `mcpdef`, and
/// the upstream that takes the tokens it issued.
#[derive(Default)]
struct Idp {
    /// Whether it refuses the client, as if it were revoked.
    refusing: Mutex<bool>,
    issued: Mutex<Vec<String>>,
    /// Whether the upstream takes no token, as if each were revoked.
    revoked: Mutex<bool>,
}

/// Standard, padded base64, as HTTP Basic sends it.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let bits =
            chunk.iter().fold(0u32, |n, b| (n << 8) | u32::from(*b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            match i <= chunk.len() {
                true => out.push(char::from(ALPHABET[((bits >> (18 - 6 * i)) & 63) as usize])),
                false => out.push('='),
            }
        }
    }
    out
}

async fn token_endpoint(State(idp): State<Arc<Idp>>, headers: HeaderMap) -> Response {
    let sent = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let client = format!(
        "Basic {}",
        base64(format!("mcpdef:{CLIENT_SECRET}").as_bytes())
    );
    if *idp.refusing.lock().unwrap() || sent != client {
        // A server that says too much: the secret it was sent, in its
        // description.
        let description = format!("client secret {CLIENT_SECRET} ({sent}) is revoked");
        let body = json!({ "error": "invalid_client", "error_description": description });
        return (StatusCode::UNAUTHORIZED, Json(body)).into_response();
    }
    let mut issued = idp.issued.lock().unwrap();
    let token = format!("{TOKEN_PREFIX}-{}", issued.len() + 1);
    issued.push(token.clone());
    Json(json!({ "access_token": token, "token_type": "Bearer", "expires_in": 3600 }))
        .into_response()
}

async fn upstream(State(idp): State<Arc<Idp>>, headers: HeaderMap, body: String) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    let taken =
        !*idp.revoked.lock().unwrap() && idp.issued.lock().unwrap().iter().any(|t| t == token);
    if !taken {
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
            "serverInfo": { "name": "remote", "version": "0" }
        }),
        Some("tools/list") => json!({ "tools": [
            { "name": "remote_echo", "inputSchema": { "type": "object" } }
        ]}),
        _ => json!({ "content": [{ "type": "text", "text": "remote:ok" }], "isError": false }),
    };
    (
        [(header::CONTENT_TYPE, "application/json")],
        Message::result(id, result).to_json_line(),
    )
        .into_response()
}

/// `secret` in a file in `dir` that only its owner can read.
fn secret_file(dir: &Path, name: &str, secret: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, secret).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

/// Kills the gateway however the test ends.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// What the binary run with `args` wrote, stdout and stderr together, and
/// whether it succeeded.
fn mcpdef(args: &[&str]) -> (String, bool) {
    let out = Command::new(BIN).args(args).output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (text, out.status.success())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_strict_gateway_serves_every_upstream_and_writes_none_of_their_secrets() {
    use std::io::BufRead;
    let dir = tempfile::tempdir().unwrap();
    let servers_ca = Pki::new("mcpdef servers CA");
    let clients_ca = Pki::new("mcpdef clients CA");
    let idp = Arc::new(Idp::default());
    let authorization = HttpsUpstream::start_app(
        &servers_ca.server(&["127.0.0.1"]),
        Router::new()
            .route("/token", post(token_endpoint))
            .with_state(Arc::clone(&idp)),
    )
    .await;
    let remote = HttpsUpstream::start_mtls_app(
        &servers_ca.server(&["127.0.0.1"]),
        &clients_ca,
        &[],
        Router::new()
            .route("/mcp", post(upstream))
            .with_state(Arc::clone(&idp)),
    )
    .await;
    let ca = servers_ca.write_root(dir.path(), "servers-ca");
    let identity = clients_ca.client("spiffe://mcpdef.test/gateway");
    let (cert, key) = identity.write(dir.path(), "gateway");
    // The client key's own part: a P-256 key's PKCS #8 body opens with the
    // same 48 characters whichever key it is, and its private scalar follows.
    let key_body: String = identity
        .key_pem()
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    assert!(
        key_body.starts_with("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg"),
        "the test knows where a P-256 key's secret part is: {} characters",
        key_body.len()
    );
    let private_key = key_body[48..80].to_string();
    let slack = secret_file(dir.path(), "slack-token", SLACK_TOKEN);
    let client_secret = secret_file(dir.path(), "client-secret", CLIENT_SECRET);
    let audit = dir.path().join("audit.log");
    let token_url = format!("https://127.0.0.1:{}/token", authorization.addr().port());
    let config = format!(
        "[gateway]\nlisten = \"127.0.0.1:0\"\naudit = {audit:?}\nstrict = true\n\n\
         [gateway.admin]\nenabled = true\nlisten = \"127.0.0.1:0\"\n\n\
         [gateway.upstream_tls]\nca = [{ca:?}]\n\n\
         [[server]]\nid = \"github\"\ntransport = \"stdio\"\n\
         command = [{MOCK:?}, \"--tool-prefix\", \"gh_\", \"--with-env\"]\n\
         tools = [\"gh_echo\", \"gh_env\"]\n\
         [server.env]\nGITHUB_PERSONAL_ACCESS_TOKEN = {{ env = \"MCPDEF_GITHUB_TOKEN\" }}\n\
         LOG_LEVEL = \"info\"\n\n\
         [[server]]\nid = \"slack\"\ntransport = \"stdio\"\n\
         command = [{MOCK:?}, \"--tool-prefix\", \"slack_\", \"--with-env\"]\n\
         tools = [\"slack_echo\", \"slack_env\"]\n\
         [server.env]\nSLACK_BOT_TOKEN = {{ file = {slack:?} }}\n\n\
         [[server]]\nid = \"remote\"\ntransport = \"streamable-http\"\nurl = {url:?}\n\
         tools = [\"remote_echo\"]\n\
         [server.tls]\nclient_cert = {cert:?}\nclient_key = {{ file = {key:?} }}\n\
         [server.auth]\nkind = \"oauth2\"\ntoken_url = {token_url:?}\nclient_id = \"mcpdef\"\n\
         client_secret = {{ exec = [\"cat\", {client_secret:?}] }}\nscopes = [\"mcp:tools\"]\n",
        url = remote.url(),
    );
    let path = dir.path().join("mcpdef.toml");
    std::fs::write(&path, config).unwrap();
    let path = path.to_str().unwrap();

    // Strict passes it, with nothing to warn about.
    let (validated, valid) = mcpdef(&["validate", "--strict", "--config", path]);
    assert!(valid, "{validated}");
    assert!(
        validated.contains("3 upstream(s), config valid, strictly"),
        "{validated}"
    );
    assert!(!validated.contains('⚠'), "{validated}");

    let mut child = Command::new(BIN)
        .args(["run", "--http", "--config", path])
        .env("MCPDEF_GITHUB_TOKEN", GITHUB_TOKEN)
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
    // Strict starts every upstream or none: a ready gateway has all three up.
    let (listen, admin) = listening_ports(&log).await;
    let ready = log
        .lock()
        .unwrap()
        .iter()
        .find(|l| l.contains(" ready "))
        .cloned()
        .unwrap();
    assert!(
        ready.contains("3 upstream(s)") && ready.contains(" · strict"),
        "{ready}"
    );
    assert!(!ready.contains("down"), "{ready}");

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
    // What each call answered, its text and whether it was an error.
    let call = async |tool: &str, arguments: Value| -> (String, bool, String) {
        let request = Message::request(
            Id::Num(1),
            method::TOOLS_CALL,
            Some(json!({ "name": tool, "arguments": arguments })),
        );
        let answer = send(
            client
                .post(format!("http://127.0.0.1:{listen}/mcp"))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .body(request.to_json_line()),
        )
        .await;
        let reply: Value = serde_json::from_str(&answer).unwrap();
        let text = reply["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        (text.to_string(), reply["result"]["isError"] == true, answer)
    };

    // Each stdio server has its own key, and not the other's, nor the
    // variable MCPdef reads the first from.
    let env = |name: &str| json!({ "name": name });
    let (text, _, _) = call("gh_env", env("GITHUB_PERSONAL_ACCESS_TOKEN")).await;
    assert_eq!(text, GITHUB_TOKEN);
    let (text, _, _) = call("slack_env", env("SLACK_BOT_TOKEN")).await;
    assert_eq!(text, SLACK_TOKEN);
    let mut answers = Vec::new();
    for (tool, name) in [
        ("gh_env", "SLACK_BOT_TOKEN"),
        ("slack_env", "GITHUB_PERSONAL_ACCESS_TOKEN"),
        ("slack_env", "MCPDEF_GITHUB_TOKEN"),
        ("gh_env", "MCPDEF_GITHUB_TOKEN"),
    ] {
        let (text, failed, answer) = call(tool, env(name)).await;
        assert_eq!((text.as_str(), failed), ("(unset)", false), "{tool} {name}");
        answers.push(answer);
    }
    // The remote upstream took the client certificate and the token.
    let (text, failed, answer) = call("remote_echo", json!({})).await;
    assert_eq!((text.as_str(), failed), ("remote:ok", false));
    answers.push(answer);
    assert!(!remote.client_certificates().is_empty());
    // Every token revoked, and the client refused: nothing to send. The
    // authorization server repeats the client secret, and it goes no further.
    *idp.revoked.lock().unwrap() = true;
    *idp.refusing.lock().unwrap() = true;
    let (text, failed, answer) = call("remote_echo", json!({})).await;
    assert!(failed, "{text}");
    assert!(
        text.contains(&format!(
            "no credentials for upstream 'remote': token endpoint {token_url} answered 401 \
             Unauthorized: invalid_client"
        )),
        "{text}"
    );
    answers.push(answer);
    // Restored: the next call fetches a token, and is taken.
    *idp.revoked.lock().unwrap() = false;
    *idp.refusing.lock().unwrap() = false;
    let (text, failed, answer) = call("remote_echo", json!({})).await;
    assert_eq!((text.as_str(), failed), ("remote:ok", false));
    answers.push(answer);

    let mut routes = Vec::new();
    for route in [
        "/",
        "/api/v1/servers",
        "/api/v1/status",
        "/api/v1/stats",
        "/api/v1/audit?limit=1000",
        "/metrics",
        "/api/v1/audit?cursor=&limit=500",
        "/api/v1/audit/0",
        "/api/v1/audit/verify",
        "/api/v1/audit/export?format=json",
        "/api/v1/audit/export?format=ocsf",
        "/api/v1/audit/export?format=cef",
        "/api/v1/audit/export?format=syslog",
        "/health",
        "/api/v1/info",
        "/api/v1/metrics",
        "/api/v1/servers/remote",
        "/api/v1/servers/remote/tools",
        "/api/v1/servers/github/tools",
        "/api/v1/policy/rules",
        "/api/v1/policy/rbac",
        "/api/v1/policy/profiles",
        "/api/v1/inspect/config",
        "/api/v1/inspect/findings",
        "/api/v1/config",
        "/api/v1/tls",
        "/api/v1/credentials",
        "/api/v1/clients/generic/snippet",
        "/api/v1/clients/claude-code/snippet",
        "/api/v1/identity",
        "/api/v1/ca.pem",
    ] {
        let url = format!("http://127.0.0.1:{admin}{route}");
        routes.push((route, send(client.get(url)).await));
    }
    drop(running);
    reading.join().unwrap();

    // How each credential fares, with none of them shown.
    let servers: Value = serde_json::from_str(&routes[1].1).unwrap();
    let remote_view = servers
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "remote")
        .unwrap();
    assert_eq!(remote_view["health"], "up", "{remote_view}");
    assert!(
        remote_view["credential"]["last_ok"].is_object(),
        "{remote_view}"
    );
    let refusal = remote_view["credential"]["last_error"]["message"].to_string();
    assert!(refusal.contains("invalid_client"), "{refusal}");
    assert!(
        remote_view["tls"]["client_not_after"].is_string(),
        "{remote_view}"
    );
    assert_eq!(
        remote_view["auth"]["client_secret"],
        json!({ "scheme": "exec", "from": "(exec cat)" })
    );
    let github = servers
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "github")
        .unwrap();
    assert_eq!(
        github["env"]["GITHUB_PERSONAL_ACCESS_TOKEN"],
        json!({ "scheme": "env", "from": "$MCPDEF_GITHUB_TOKEN" })
    );
    let metrics = &routes[5].1;
    for sample in [
        "mcpdef_upstream_auth_failures_total{server=\"remote\"} 1",
        "mcpdef_credential_expiry_seconds{server=\"remote\",credential=\"token\"}",
        "mcpdef_credential_expiry_seconds{server=\"remote\",credential=\"client_cert\"}",
    ] {
        assert!(metrics.contains(sample), "no {sample}: {metrics}");
    }

    let ledger = std::fs::read_to_string(&audit).unwrap();
    assert!(ledger.contains("credentials-unavailable"), "{ledger}");
    let (servers_list, listed) = mcpdef(&["servers", "list", "--config", path]);
    assert!(listed, "{servers_list}");
    assert!(
        servers_list.contains("GITHUB_PERSONAL_ACCESS_TOKEN=$MCPDEF_GITHUB_TOKEN"),
        "{servers_list}"
    );
    let (egress_show, shown) = mcpdef(&["egress", "show", "--config", path]);
    assert!(shown, "{egress_show}");
    // `doctor` opens every upstream as `run` does, with the same secrets,
    // a token fetched and a client certificate presented among them.
    let checked = Command::new(BIN)
        .args(["doctor", "--wait", "10", "--config", path])
        .env("MCPDEF_GITHUB_TOKEN", GITHUB_TOKEN)
        .output()
        .unwrap();
    let doctor = format!(
        "{}{}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    for server in ["github", "slack", "remote"] {
        assert!(
            doctor.contains(server),
            "doctor checked no {server}: {doctor}"
        );
    }
    let (tls_show, shown) = mcpdef(&["tls", "show", "--config", path]);
    assert!(shown, "{tls_show}");
    let (connect, connected) = mcpdef(&["connect", "claude-code", "--config", path]);
    assert!(connected, "{connect}");
    let log = log.lock().unwrap().join("\n");
    let mut outputs = vec![
        ("validate --strict", validated),
        ("the log", log),
        ("the ledger", ledger),
        ("the answers", answers.join("\n")),
        ("servers list", servers_list),
        ("egress show", egress_show),
        ("doctor", doctor),
        ("tls show", tls_show),
        ("connect claude-code", connect),
    ];
    outputs.extend(routes);
    // Every token issued begins with the prefix.
    let issued = idp.issued.lock().unwrap().clone();
    assert!(issued.len() >= 2, "{issued:?}");
    for (name, output) in &outputs {
        for secret in [
            GITHUB_TOKEN,
            SLACK_TOKEN,
            CLIENT_SECRET,
            TOKEN_PREFIX,
            private_key.as_str(),
        ] {
            assert!(!output.contains(secret), "{name} holds {secret}: {output}");
        }
    }
}
