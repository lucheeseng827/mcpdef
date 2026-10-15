// SPDX-License-Identifier: Apache-2.0
//! Automation on the admin API, and break-glass:
//!   * a token the identity provider issued for the admin API, its audience
//!     `api_audience`, names its caller `token:<subject>`: `mcpdef:admin:read`
//!     reads, `mcpdef:admin:write` acts too, and a role `[identity]` gives
//!     counts as well;
//!   * a token for the MCP listener is refused on the admin API, and one for
//!     the admin API on the MCP listener; so is one expired, and one for
//!     another audience;
//!   * the break-glass token holds `console:admin`, and every request it
//!     makes is recorded before it is served; another token is refused, and
//!     not recorded; where it is all that signs callers in, anyone else holds
//!     no role;
//!   * `mcpdef admin token` makes one, and the SHA-256 the config keeps;
//!   * no token shows in any answer or record.

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Json};
use axum::routing::get;
use axum::Router;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mcpdef::connect::build_gateway;
use mcpdef::listener::{serve_http_on, AuthState, HttpConfig};
use mcpdef::reload::{channel, Reloader, Snapshot};
use mcpdef::{serve_admin_on, AdminState, Config, Metrics};
use mcpdef_audit::read_all;
use mcpdef_auth::Verifier;
use mcpdef_core::wire::WireMode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TEST_PRIV_PEM: &str = include_str!("../../mcpdef-auth/src/testdata/test_priv.pem");
const TEST_JWKS: &str = include_str!("../../mcpdef-auth/src/testdata/test_jwks.json");
const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");
const RESOURCE: &str = "https://mcp.example/mcp";
const API_AUDIENCE: &str = "https://mcpdef.example/admin";
/// A break-glass token, made as `mcpdef admin token` makes one.
const GLASS: &str = "mcpdef_bg_bReAk-gLaSs-pLaNtEd-0123456789abcdefghijk";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A task stopped however the test ends.
struct Aborted(tokio::task::JoinHandle<()>);

impl Drop for Aborted {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// An identity provider's discovery document and keys.
async fn provider() -> (String, Aborted) {
    let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", bound.local_addr().unwrap());
    let discovery = |State(issuer): State<String>| async move {
        Json(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
        }))
    };
    let keys =
        || async { ([(header::CONTENT_TYPE, "application/json")], TEST_JWKS).into_response() };
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(keys))
        .with_state(issuer.clone());
    let serving = Aborted(tokio::spawn(async move {
        axum::serve(bound, app).await.unwrap();
    }));
    (issuer, serving)
}

/// A token of `issuer`'s for `audience`, with `claims` besides.
fn token(issuer: &str, audience: &str, claims: Value) -> String {
    let at = now();
    let mut all =
        json!({ "iss": issuer, "aud": audience, "sub": "robot", "iat": at, "exp": at + 300 });
    for (name, value) in claims.as_object().unwrap() {
        all[name] = value.clone();
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".into());
    let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
    encode(&header, &all, &key).unwrap()
}

/// The MCP listener and the admin listener of one gateway, and every answer
/// they gave.
struct Gateway {
    admin: String,
    mcp: String,
    dir: tempfile::TempDir,
    client: reqwest::Client,
    seen: Mutex<Vec<String>>,
    _serving: Vec<Aborted>,
}

impl Gateway {
    /// A gateway whose admin listener holds `admin` besides `[gateway.admin]`
    /// itself, and whose MCP listener takes `issuer`'s tokens for
    /// [`RESOURCE`].
    async fn start(issuer: &str, admin: &str) -> Gateway {
        let dir = tempfile::tempdir().unwrap();
        let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", bound.local_addr().unwrap());
        let path = dir.path().join("mcpdef.toml");
        std::fs::write(
            &path,
            format!(
                "[gateway]\nlisten = \"127.0.0.1:7878\"\naudit = {audit:?}\nstate_dir = {state:?}\n\n\
                 [gateway.auth]\nenabled = true\nissuer = {issuer:?}\nresource = {RESOURCE:?}\n\
                 jwks = {TEST_JWKS:?}\n\n\
                 [gateway.admin]\nenabled = true\nlisten = \"127.0.0.1:0\"\n\
                 tls = {{ mode = \"off\" }}\npublic_url = {base:?}\n\n\
                 {admin}\n\n\
                 [[server]]\nid = \"a\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\n",
                audit = dir.path().join("audit.log"),
                state = dir.path().join("state"),
            ),
        )
        .unwrap();
        let (cfg, text) = Config::load_text(&path).unwrap();
        assert_eq!(cfg.validate(), Vec::<String>::new());
        let gw = build_gateway(&cfg).await.unwrap();
        let (reloads, requests) = channel();
        let mut state = AdminState::new(&cfg, Arc::new(Metrics::new(2)), gw.clone(), "test")
            .with_config_path(&path)
            .with_reloads(reloads);
        if cfg.gateway.admin.oidc.is_some() {
            state = state.with_sign_in(&cfg, mcpdef::admin::session::keys(&cfg).unwrap());
        }
        let state = Arc::new(state);
        // As `mcpdef run` wires it.
        let refreshed = Arc::clone(&state);
        let snapshot = Snapshot::take(text.as_bytes(), &cfg);
        let reloader = Reloader::new(&path, None, gw.clone(), cfg, snapshot)
            .on_applied(move |cfg| refreshed.reconfigure(cfg))
            .with_requests(requests);
        let reloading = Aborted(tokio::spawn(reloader.run(Duration::from_secs(3600))));
        let admin = Aborted(tokio::spawn(async move {
            serve_admin_on(state, bound, None).await.unwrap();
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mcp = format!("http://{}/mcp", listener.local_addr().unwrap());
        let verifier = Verifier::from_jwks_json(TEST_JWKS, issuer, RESOURCE).unwrap();
        let http = HttpConfig {
            listen: listener.local_addr().unwrap().to_string(),
            allowed_origins: vec![],
            max_inflight: None,
            wire: WireMode::default(),
        };
        let data = Aborted(tokio::spawn(async move {
            serve_http_on(listener, gw, http, Some(AuthState::new(verifier)))
                .await
                .unwrap();
        }));
        mcpdef_transport::install_crypto_provider();
        Gateway {
            admin: base,
            mcp,
            dir,
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            seen: Mutex::default(),
            _serving: vec![admin, data, reloading],
        }
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> (u16, Answer) {
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.text().await.unwrap();
        self.seen
            .lock()
            .unwrap()
            .push(format!("{status} {headers:?} {body}"));
        let json = serde_json::from_str(&body).unwrap_or(Value::Null);
        (status, Answer { headers, json })
    }

    /// `GET` a route of the admin API, with `token` as its bearer.
    async fn get(&self, route: &str, token: Option<&str>) -> (u16, Answer) {
        let mut request = self.client.get(format!("{}{route}", self.admin));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        self.send(request).await
    }

    /// `POST` a route of the admin API, as automation does: no browser's
    /// headers, no body.
    async fn post(&self, route: &str, token: &str) -> (u16, Answer) {
        let request = self
            .client
            .post(format!("{}{route}", self.admin))
            .bearer_auth(token);
        self.send(request).await
    }

    /// The status a `tools/list` on the MCP listener gets with `token`.
    async fn mcp(&self, token: &str) -> u16 {
        let request = self
            .client
            .post(&self.mcp)
            .bearer_auth(token)
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::CONTENT_TYPE, "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        self.send(request).await.0
    }

    /// The admin and reload records: actor, action, decision, rule and what
    /// it asked.
    fn records(&self) -> Vec<Recorded> {
        read_all(self.dir.path().join("audit.log"))
            .unwrap()
            .into_iter()
            .filter(|r| matches!(r.kind.as_deref(), Some("admin" | "reload")))
            .map(|r| {
                (
                    r.actor.unwrap_or_default(),
                    r.method.unwrap_or_default(),
                    r.decision,
                    r.rule,
                    r.uri,
                )
            })
            .collect()
    }

    /// That `tokens` are in no answer either listener gave, and no record.
    fn shows_none_of(&self, tokens: &[&str]) {
        let ledger = std::fs::read_to_string(self.dir.path().join("audit.log")).unwrap();
        for token in tokens {
            for seen in self.seen.lock().unwrap().iter() {
                assert!(!seen.contains(token), "a token in {seen}");
            }
            assert!(!ledger.contains(token), "a token in the ledger");
        }
    }
}

/// What an answer said: its headers, and its body as JSON.
struct Answer {
    headers: reqwest::header::HeaderMap,
    json: Value,
}

fn digest(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

type Recorded = (String, String, String, Option<String>, Option<String>);

fn record(actor: &str, action: &str, refused: Option<&str>, asked: Option<&str>) -> Recorded {
    (
        actor.to_string(),
        action.to_string(),
        if refused.is_some() { "deny" } else { "allow" }.to_string(),
        refused.map(str::to_string),
        asked.map(str::to_string),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn automation_and_break_glass_on_the_admin_api() {
    let (issuer, _provider) = provider().await;
    let gateway = Gateway::start(
        &issuer,
        &format!(
            "[gateway.admin.oidc]\nissuer = {issuer:?}\nclient_id = \"mcpdef-console\"\n\
             api_audience = {API_AUDIENCE:?}\n\n\
             [gateway.admin.break_glass]\ntoken_sha256 = \"{}\"\n\n\
             [[identity.role_map]]\nclaim = \"groups\"\nvalue = \"mcp-admins\"\n\
             roles = [\"console:admin\"]",
            digest(GLASS)
        ),
    )
    .await;
    let mut expected = Vec::new();

    // A reader: its scope gives console:viewer.
    let reader = token(
        &issuer,
        API_AUDIENCE,
        json!({ "sub": "robot-1", "scope": "openid mcpdef:admin:read" }),
    );
    let (status, session) = gateway.get("/api/v1/session", Some(&reader)).await;
    assert_eq!(status, 200);
    assert_eq!(session.json["actor"], "token:robot-1");
    assert_eq!(session.json["role"], "console:viewer");
    assert_eq!(gateway.get("/api/v1/status", Some(&reader)).await.0, 200);
    assert_eq!(gateway.post("/api/v1/reload", &reader).await.0, 403);
    expected.push(record(
        "token:robot-1",
        "reload",
        Some("console-role"),
        None,
    ));

    // A writer acts: its reload is its own.
    let writer = token(
        &issuer,
        API_AUDIENCE,
        json!({ "sub": "robot-2", "scp": ["mcpdef:admin:write"] }),
    );
    let (status, reloaded) = gateway.post("/api/v1/reload", &writer).await;
    assert_eq!(status, 200, "{}", reloaded.json);
    expected.push(record("token:robot-2", "reload", None, None));
    assert_eq!(gateway.get("/api/v1/config", Some(&writer)).await.0, 403);

    // A role `[identity]` gives counts: here an admin's.
    let admin = token(
        &issuer,
        API_AUDIENCE,
        json!({ "sub": "robot-3", "groups": ["mcp-admins"] }),
    );
    assert_eq!(gateway.get("/api/v1/config", Some(&admin)).await.0, 200);

    // Refused: a token for the MCP listener, one expired, one for another
    // audience, and what is no token at all.
    let mcp_token = token(
        &issuer,
        RESOURCE,
        json!({ "scope": "mcpdef:admin:write", "groups": ["mcp-admins"] }),
    );
    let expired = token(
        &issuer,
        API_AUDIENCE,
        json!({ "scope": "mcpdef:admin:read", "exp": now() - 3600 }),
    );
    let elsewhere = token(
        &issuer,
        "https://other.example/api",
        json!({ "scope": "mcpdef:admin:read" }),
    );
    for refused in [
        &mcp_token,
        &expired,
        &elsewhere,
        &"mcpdef_bg_not-the-one".to_string(),
    ] {
        let (status, answer) = gateway.get("/api/v1/status", Some(refused)).await;
        assert_eq!(status, 401, "{}", answer.json);
        assert_eq!(answer.json["title"], "Bearer token refused");
        assert_eq!(
            answer.headers[header::WWW_AUTHENTICATE],
            "Bearer error=\"invalid_token\""
        );
    }
    // And on the MCP listener, a token for the admin API is refused, as one
    // for it is taken.
    assert_eq!(gateway.mcp(&writer).await, 401);
    assert_eq!(gateway.mcp(&mcp_token).await, 200);

    // Break-glass: console:admin, each request recorded before it is served.
    let (status, session) = gateway.get("/api/v1/session", Some(GLASS)).await;
    assert_eq!(status, 200);
    assert_eq!(session.json["actor"], "break-glass");
    assert_eq!(session.json["role"], "console:admin");
    expected.push(record(
        "break-glass",
        "break-glass",
        None,
        Some("GET /api/v1/session"),
    ));
    assert_eq!(gateway.get("/api/v1/config", Some(GLASS)).await.0, 200);
    expected.push(record(
        "break-glass",
        "break-glass",
        None,
        Some("GET /api/v1/config"),
    ));
    assert_eq!(gateway.post("/api/v1/reload", GLASS).await.0, 200);
    expected.extend([
        record(
            "break-glass",
            "break-glass",
            None,
            Some("POST /api/v1/reload"),
        ),
        record("break-glass", "reload", None, None),
    ]);
    let (_, identity) = gateway.get("/api/v1/identity", Some(GLASS)).await;
    expected.push(record(
        "break-glass",
        "break-glass",
        None,
        Some("GET /api/v1/identity"),
    ));
    assert_eq!(identity.json["console"]["break_glass"], true);
    assert_eq!(
        identity.json["console"]["oidc"]["api_audience"],
        API_AUDIENCE
    );

    assert_eq!(gateway.records(), expected);
    gateway.shows_none_of(&[GLASS, &reader, &writer, &admin, &mcp_token]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn break_glass_alone_closes_the_listener_to_everyone_else() {
    let (issuer, _provider) = provider().await;
    let gateway = Gateway::start(
        &issuer,
        &format!(
            "[gateway.admin.break_glass]\ntoken_sha256 = \"{}\"",
            digest(GLASS)
        ),
    )
    .await;
    // No token: no role, though the listener is on loopback.
    let (status, session) = gateway.get("/api/v1/session", None).await;
    assert_eq!(status, 200);
    assert_eq!(session.json["role"], Value::Null);
    assert_eq!(session.json["open"], false);
    assert_eq!(gateway.get("/api/v1/status", None).await.0, 403);
    // A token of the provider's: this admin API takes none.
    let writer = token(
        &issuer,
        API_AUDIENCE,
        json!({ "scope": "mcpdef:admin:write" }),
    );
    let (status, refused) = gateway.get("/api/v1/status", Some(&writer)).await;
    assert_eq!(status, 401);
    assert!(
        refused.json["detail"]
            .as_str()
            .unwrap()
            .contains("it is not the break-glass token, and this admin API takes no other"),
        "{}",
        refused.json
    );
    assert_eq!(gateway.get("/api/v1/status", Some(GLASS)).await.0, 200);

    // A new token, by a reload: the old one opens nothing from then on.
    let new = "mcpdef_bg_aNoThEr-pLaNtEd-0123456789abcdefghijklmn";
    let path = gateway.dir.path().join("mcpdef.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replace(&digest(GLASS), &digest(new));
    std::fs::write(&path, text).unwrap();
    assert_eq!(gateway.post("/api/v1/reload", GLASS).await.0, 200);
    assert_eq!(gateway.get("/api/v1/status", Some(GLASS)).await.0, 401);
    assert_eq!(gateway.get("/api/v1/status", Some(new)).await.0, 200);
    assert_eq!(
        gateway.records(),
        [
            record(
                "break-glass",
                "break-glass",
                None,
                Some("GET /api/v1/status"),
            ),
            record(
                "break-glass",
                "break-glass",
                None,
                Some("POST /api/v1/reload"),
            ),
            record("break-glass", "reload", None, None),
            record(
                "break-glass",
                "break-glass",
                None,
                Some("GET /api/v1/status"),
            ),
        ]
    );
    gateway.shows_none_of(&[GLASS, new, &writer]);
}

#[test]
fn admin_token_makes_a_token_and_the_digest_the_config_keeps() {
    let make = || {
        let out = Command::new(env!("CARGO_BIN_EXE_mcpdef"))
            .args(["admin", "token"])
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    let (first, second) = (make(), make());
    assert_ne!(first, second, "each token is new");
    let lines: Vec<&str> = first
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let [token, table, kept] = lines[..] else {
        panic!("{first}");
    };
    assert!(token.starts_with("mcpdef_bg_"), "{token}");
    assert_eq!(
        token.len(),
        "mcpdef_bg_".len() + 43,
        "32 bytes, in base64url"
    );
    assert_eq!(table, "[gateway.admin.break_glass]");
    assert_eq!(kept, format!("token_sha256 = \"{}\"", digest(token)));
    // As the config takes it.
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("mcpdef.toml");
    std::fs::write(
        &config,
        format!(
            "[gateway.admin]\nenabled = true\n\n{table}\n{kept}\n\n\
             [[server]]\nid = \"a\"\ntransport = \"stdio\"\ncommand = [\"x\"]\n"
        ),
    )
    .unwrap();
    let cfg = Config::load(Path::new(&config)).unwrap();
    assert_eq!(cfg.validate(), Vec::<String>::new());
}
