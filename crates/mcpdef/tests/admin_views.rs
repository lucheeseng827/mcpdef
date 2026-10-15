// SPDX-License-Identifier: Apache-2.0
//! The config and connection views, against a running admin listener:
//!   * `GET /api/v1/config` shows the config file with its secrets masked,
//!     and `POST /api/v1/config/validate` checks a config without applying
//!     it, reading and running nothing it names;
//!   * `GET /api/v1/tls` shows each listener's TLS and the local CA, and
//!     `GET /api/v1/ca.pem` the CA's certificate and nothing else;
//!   * `GET /api/v1/credentials` says how each upstream's credentials fare,
//!     `GET /api/v1/clients/{client}/snippet` gives a client's entry, and
//!     `GET /api/v1/identity` who the gateway takes its callers to be;
//!   * no planted secret shows in any of them.

use mcpdef::connect::build_gateway;
use mcpdef::tls::{ListenerTls, Serving};
use mcpdef::{serve_admin_on, AdminState, Config, Metrics};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;

const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");
/// A literal `[server.env]` value, a header credential read from a variable
/// of MCPdef's own, and a URL's query token: none may show.
const LITERAL: &str = "lItErAl-pLaNtEd-7";
const HEADER: &str = "hEaDeR-pLaNtEd-8";
const QUERY: &str = "qUeRy-pLaNtEd-9";

/// A task stopped however the test ends.
struct Aborted(tokio::task::JoinHandle<()>);

impl Drop for Aborted {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn config_text(dir: &Path) -> String {
    format!(
        "[gateway]\nlisten = \"127.0.0.1:7878\"\naudit = {audit:?}\nstate_dir = {state:?}\n\n\
         [gateway.tls]\nmode = \"self-signed\"\nhostnames = [\"gw.internal\"]\n\n\
         [gateway.admin]\nenabled = true\nlisten = \"127.0.0.1:0\"\ntls = {{ mode = \"off\" }}\n\n\
         [[server]]\nid = \"a\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\ntools = [\"echo\"]\n\n\
         [server.env]\nAPI_KEY = {LITERAL:?}\n\n\
         [[server]]\nid = \"b\"\ntransport = \"streamable-http\"\nurl = \"http://127.0.0.1:1/mcp\"\n\
         tools = [\"b_echo\"]\n\n\
         [server.auth]\nkind = \"header\"\nname = \"x-api-key\"\nvalue = {{ env = \"MCPDEF_VIEWS_TEST_HEADER\" }}\n\n\
         [[identity.cert_map]]\nidentity = \"spiffe://example.org/ns/ops/*\"\nroles = [\"console:viewer\"]\n\n\
         # the old endpoint, kept for reference: https://mcp.example/mcp?token={QUERY}\n",
        audit = dir.join("audit.log"),
        state = dir.join("state"),
    )
}

async fn start(dir: &Path) -> (String, Aborted) {
    std::env::set_var("MCPDEF_VIEWS_TEST_HEADER", HEADER);
    let path = dir.join("mcpdef.toml");
    std::fs::write(&path, config_text(dir)).unwrap();
    let cfg = Config::load(&path).unwrap();
    assert_eq!(cfg.validate(), Vec::<String>::new());
    // As `mcpdef run` does for an HTTP gateway: the local CA and the
    // listener's certificate are made before anything serves.
    ListenerTls::start(&cfg, Serving::of(&cfg, true)).unwrap();
    let gw = build_gateway(&cfg).await.unwrap();
    let state = Arc::new(
        AdminState::new(&cfg, Arc::new(Metrics::new(2)), gw, "test").with_config_path(&path),
    );
    let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", bound.local_addr().unwrap());
    let serving = Aborted(tokio::spawn(async move {
        serve_admin_on(state, bound, None).await.unwrap();
    }));
    (base, serving)
}

/// The admin API, and every answer it gave.
struct Api {
    base: String,
    client: reqwest::Client,
    answers: Vec<(String, String)>,
}

impl Api {
    async fn send(
        &mut self,
        route: &str,
        request: reqwest::RequestBuilder,
    ) -> (u16, String, Value) {
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let kind = response
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        let text = response.text().await.unwrap();
        self.answers.push((route.to_string(), text.clone()));
        let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
        (status, kind, body)
    }

    async fn get(&mut self, route: &str) -> (u16, String, Value) {
        let request = self.client.get(format!("{}{route}", self.base));
        self.send(route, request).await
    }

    async fn validate(&mut self, text: &str) -> (u16, String, Value) {
        let request = self
            .client
            .post(format!("{}/api/v1/config/validate", self.base))
            .header("content-type", "application/json")
            .body(json!({ "text": text }).to_string());
        self.send("/api/v1/config/validate", request).await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_config_and_connection_views_show_no_secret() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _serving) = start(dir.path()).await;
    mcpdef_transport::install_crypto_provider();
    let mut api = Api {
        base,
        client: reqwest::Client::builder().no_proxy().build().unwrap(),
        answers: Vec::new(),
    };

    // The file, masked: the literal and the URL in a comment; what names a
    // source is kept.
    let (status, _, config) = api.get("/api/v1/config").await;
    assert_eq!(status, 200, "{config}");
    let text = config["text"].as_str().unwrap();
    assert!(text.contains("API_KEY = \"***\""), "{text}");
    assert!(
        text.contains("value = { env = \"MCPDEF_VIEWS_TEST_HEADER\" }"),
        "{text}"
    );
    assert!(text.contains("token=***"), "{text}");
    assert_eq!(config["redacted"], json!(["/server/0/env/API_KEY"]));
    assert_eq!(
        config["path"],
        dir.path().join("mcpdef.toml").display().to_string()
    );

    // Checked, not applied, and nothing it names read or run.
    let (status, _, valid) = api.validate(&config_text(dir.path())).await;
    assert_eq!(status, 200);
    assert_eq!(valid, json!({ "valid": true, "problems": [] }));
    let ran = dir.path().join("ran");
    let hostile = format!(
        "[gateway]\nlisten = \"127.0.0.1:7878\"\n\n[gateway.tls]\nmode = \"files\"\ncert = \"/etc/hostname\"\n\
         key = {{ file = \"/etc/shadow\" }}\n\n[[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = [\"true\"]\n\n\
         [server.env]\nTOKEN = {{ exec = [\"touch\", {ran:?}] }}\n"
    );
    let (status, _, checked) = api.validate(&hostile).await;
    assert_eq!(status, 200, "{checked}");
    assert!(!ran.exists(), "validate ran a command the config named");
    let (_, _, invalid) = api.validate("[gateway]\nlisten = \"x\"\n").await;
    assert_eq!(invalid["valid"], false);
    assert!(
        invalid["problems"][0]
            .as_str()
            .unwrap()
            .contains("no [[server]] entries"),
        "{invalid}"
    );
    let (_, _, unparsed) = api.validate("[gateway\n").await;
    assert_eq!(unparsed["valid"], false);
    let not_json = api
        .client
        .post(format!("{}/api/v1/config/validate", api.base))
        .header("content-type", "text/plain")
        .body("[gateway]");
    assert_eq!(api.send("validate", not_json).await.0, 415);

    // Each listener's TLS, and the local CA's certificate alone.
    let (_, _, tls) = api.get("/api/v1/tls").await;
    assert_eq!(tls["mcp"]["mode"], "self-signed");
    assert_eq!(tls["mcp"]["hostnames"], json!(["gw.internal"]));
    let names = tls["mcp"]["certificate"]["names"].as_array().unwrap();
    assert!(names.contains(&json!("DNS:gw.internal")), "{tls}");
    assert!(tls["mcp"]["certificate"]["not_after"].is_string(), "{tls}");
    assert_eq!(tls["admin"]["mode"], "off");
    assert_eq!(
        tls["local_ca"]["subject"],
        tls["mcp"]["certificate"]["issuer"]
    );
    let (status, kind, pem) = api.get("/api/v1/ca.pem").await;
    assert_eq!((status, kind.as_str()), (200, "application/x-pem-file"));
    let pem = pem.as_str().unwrap();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"), "{pem}");
    assert!(!pem.contains("PRIVATE KEY"));
    let on_disk = std::fs::read_to_string(dir.path().join("state/tls/ca.crt")).unwrap();
    assert_eq!(pem.trim(), on_disk.trim());

    // Credentials, by kind and health, never the value.
    let (_, _, credentials) = api.get("/api/v1/credentials").await;
    let only = credentials.as_array().unwrap();
    assert_eq!(only.len(), 1, "{credentials}");
    assert_eq!(
        (only[0]["server"].clone(), only[0]["kind"].clone()),
        ("b".into(), "header".into())
    );

    // A client's entry.
    let (status, _, snippet) = api.get("/api/v1/clients/claude-code/snippet?name=gw").await;
    assert_eq!(status, 200, "{snippet}");
    assert_eq!(snippet["name"], "gw");
    assert_eq!(snippet["url"], "https://127.0.0.1:7878/mcp");
    assert!(
        snippet["text"]
            .as_str()
            .unwrap()
            .contains("https://127.0.0.1:7878/mcp"),
        "{snippet}"
    );
    let (status, _, _) = api.get("/api/v1/clients/notepad/snippet").await;
    assert_eq!(status, 404);

    // Who callers are taken to be.
    let (_, _, identity) = api.get("/api/v1/identity").await;
    assert_eq!(identity["console"]["signs_in"], json!([]));
    assert_eq!(identity["console"]["oidc"], Value::Null);
    assert_eq!(
        identity["model"],
        json!({ "subject_claim": "sub", "roles_claims": ["roles"], "role_map": [] })
    );
    assert_eq!(identity["mcp"]["bearer"]["enabled"], false);
    assert_eq!(identity["cert_map"][0]["roles"], json!(["console:viewer"]));

    for (route, text) in &api.answers {
        for secret in [LITERAL, HEADER, QUERY] {
            assert!(!text.contains(secret), "{route} holds {secret}: {text}");
        }
    }
}
