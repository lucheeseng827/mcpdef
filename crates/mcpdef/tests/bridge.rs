// SPDX-License-Identifier: Apache-2.0
//! `mcpdef bridge <url>`, end to end: a stdio client, the real `mcpdef bridge`
//! binary, and a remote gateway serving HTTPS on a PKI made when the test runs.
//!
//! - A stdio client lists and calls tools through the bridge, to a gateway
//!   on a test PKI.
//! - Governance stays with the remote end: a call the remote's policy denies
//!   is denied through the bridge too, and the bridge relays why.
//! - Resources and prompts pass through as well as tools. MCPdef is
//!   deny-by-default and an unset `resources` list exposes nothing, so a
//!   bridge that opened only `tools` would drop them without a word.
//! - A client certificate (`--cert`/`--key`) gets through a remote that
//!   requires one; without it, nothing does.
//! - A token file (`--token-file`) is sent as the bearer, and a remote that
//!   requires a token refuses a bridge without one.
//! - `--print-config` prints a valid gateway config that names the token's
//!   file, never its contents.

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mcpdef::connect::build_gateway;
use mcpdef::listener::{serve_https_on, AuthState, HttpConfig};
use mcpdef::tls::{ListenerTls, Serving};
use mcpdef::Config;
use mcpdef_auth::Verifier;
use mcpdef_core::wire::WireMode;
use mcpdef_core::{method, Id, Message};
use mcpdef_testkit::Pki;
use mcpdef_transport::{StdioChild, Transport};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");
const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

// The keypair `mcpdef-auth` trusts in its own tests.
const TEST_PRIV_PEM: &str = include_str!("../../mcpdef-auth/src/testdata/test_priv.pem");
const TEST_JWKS: &str = include_str!("../../mcpdef-auth/src/testdata/test_jwks.json");
const ISSUER: &str = "https://auth.example.com";
const RESOURCE: &str = "https://mcpdef.acme.internal/mcp";

const BOT: &str = "spiffe://prod.acme.internal/ns/ci/sa/bot";

/// A task stopped however the test ends.
struct Aborted(tokio::task::JoinHandle<()>);

impl Drop for Aborted {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The remote end: a gateway serving HTTPS, over the stdio mock with a
/// resource and a prompt as well as its tools.
struct Remote {
    url: String,
    _serving: Aborted,
}

/// Its config. `echo` is the one tool it lists, and a policy of its own denies
/// `echo` when `msg` is `"forbidden"`: a rule only the remote end holds.
fn remote_config(dir: &Path, gateway_extra: &str) -> String {
    format!(
        "[gateway]\naudit = {audit:?}\nstate_dir = {state:?}\n\n\
         [gateway.tls]\nmode = \"files\"\ncert = {cert:?}\nkey = {{ file = {key:?} }}\n\n\
         {gateway_extra}\n\n\
         [[server]]\nid = \"mock\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}, \"--resources\"]\n\
         tools = [\"echo\"]\nresources = [\"*\"]\nprompts = [\"*\"]\n\n\
         [[policy]]\nname = \"no-forbidden-echo\"\neffect = \"deny\"\ntools = [\"echo\"]\n\
         args = [ {{ path = \"msg\", equals = \"forbidden\" }} ]\n",
        audit = dir.join("remote-audit.log"),
        state = dir.join("remote-state"),
        cert = dir.join("listener.crt"),
        key = dir.join("listener.key"),
    )
}

impl Remote {
    async fn start(dir: &Path, pki: &Pki, gateway_extra: &str, auth: Option<AuthState>) -> Remote {
        pki.server(&["127.0.0.1"]).write(dir, "listener");
        let path = dir.join("remote.toml");
        std::fs::write(&path, remote_config(dir, gateway_extra)).unwrap();
        let (cfg, _) = Config::load_text(&path).unwrap();
        assert_eq!(cfg.validate(), Vec::<String>::new());
        let serving = Serving {
            mcp: true,
            admin: false,
        };
        let (listener_tls, _) = ListenerTls::start(&cfg, serving).unwrap().unwrap();
        let gw = build_gateway(&cfg).await.unwrap();
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let http = HttpConfig {
            listen: addr.to_string(),
            allowed_origins: Vec::new(),
            max_inflight: None,
            wire: WireMode::default(),
        };
        let slot = listener_tls.mcp().unwrap();
        let serving = tokio::spawn(async move {
            serve_https_on(tcp, gw, http, auth, slot).await.unwrap();
        });
        Remote {
            url: format!("https://127.0.0.1:{}/mcp", addr.port()),
            _serving: Aborted(serving),
        }
    }
}

/// `mcpdef bridge` to `url`, trusting the test CA, with its own ledger and
/// state under `dir`, and `extra` flags.
fn bridge(url: &str, dir: &Path, ca: &Path, extra: &[String]) -> StdioChild {
    let mut command = vec![
        BIN.to_string(),
        "bridge".to_string(),
        url.to_string(),
        "--ca".to_string(),
        ca.display().to_string(),
        "--audit".to_string(),
        dir.join("bridge-audit.log").display().to_string(),
        "--state-dir".to_string(),
        dir.join("bridge-state").display().to_string(),
    ];
    command.extend(extra.iter().cloned());
    StdioChild::spawn(&command).unwrap()
}

/// A stdio MCP client: what an editor does with the bridge it launched.
struct Client {
    child: StdioChild,
    next: i64,
}

impl Client {
    /// Open the session the way a 2025-11-25 client does.
    async fn open(child: StdioChild) -> Client {
        let mut c = Client { child, next: 1 };
        let hello = c
            .ask(
                method::INITIALIZE,
                json!({
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": { "name": "bridge-test", "version": "0" }
                }),
            )
            .await;
        assert!(hello.result.is_some(), "initialize: {hello:?}");
        c.child
            .send(Message::notification(method::INITIALIZED, None))
            .await
            .unwrap();
        c
    }

    /// One request, and its reply. Notifications on the way are passed over.
    async fn ask(&mut self, method: &str, params: Value) -> Message {
        let id = Id::Num(self.next);
        self.next += 1;
        self.child
            .send(Message::request(id.clone(), method, Some(params)))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let msg = self
                    .child
                    .recv()
                    .await
                    .unwrap()
                    .expect("the bridge closed its stdout");
                if msg.is_response() && msg.id.as_ref() == Some(&id) {
                    return msg;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no reply to {method} within 20s"))
    }

    async fn tool_names(&mut self) -> Vec<String> {
        let reply = self.ask(method::TOOLS_LIST, json!({})).await;
        reply.result.unwrap_or_default()["tools"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|t| t["name"].as_str().map(str::to_string))
            .collect()
    }

    async fn call(&mut self, tool: &str, args: Value) -> Value {
        let reply = self
            .ask(
                method::TOOLS_CALL,
                json!({ "name": tool, "arguments": args }),
            )
            .await;
        match reply.result {
            Some(result) => result,
            None => panic!("{tool}: no result, the error was {:?}", reply.error),
        }
    }
}

fn text(result: &Value) -> &str {
    result["content"][0]["text"].as_str().unwrap_or_default()
}

/// A signed token the remote's verifier accepts.
fn token() -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".into());
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let claims = json!({ "sub": "user:bridge", "iss": ISSUER, "aud": RESOURCE, "exp": exp });
    let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
    encode(&header, &claims, &key).unwrap()
}

/// What the bridge is for: a stdio client lists and calls tools through it,
/// to a gateway on the test PKI.
#[tokio::test]
async fn a_stdio_client_lists_and_calls_tools_through_a_bridge_on_the_test_pki() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let ca = pki.write_root(dir.path(), "server-ca");
    let remote = Remote::start(dir.path(), &pki, "", None).await;

    let mut client = Client::open(bridge(&remote.url, dir.path(), &ca, &[])).await;
    assert_eq!(client.tool_names().await, vec!["echo".to_string()]);

    let result = client.call("echo", json!({ "msg": "hello" })).await;
    assert_eq!(result["isError"], json!(false), "{result}");
    assert!(text(&result).contains("hello"), "{result}");
}

/// The remote end governs. Its policy denies `echo` when `msg` is
/// `"forbidden"`; the bridge, opened wide, holds no such rule. If the bridge
/// decided anything itself the call would go through.
#[tokio::test]
async fn governance_stays_with_the_remote_end() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let ca = pki.write_root(dir.path(), "server-ca");
    let remote = Remote::start(dir.path(), &pki, "", None).await;

    let mut client = Client::open(bridge(&remote.url, dir.path(), &ca, &[])).await;
    let allowed = client.call("echo", json!({ "msg": "fine" })).await;
    assert_eq!(allowed["isError"], json!(false), "{allowed}");

    let denied = client.call("echo", json!({ "msg": "forbidden" })).await;
    assert_eq!(denied["isError"], json!(true), "{denied}");
    assert!(
        text(&denied).contains("no-forbidden-echo"),
        "the remote's rule should be named in the denial the bridge relays: {denied}"
    );
}

/// Resources and prompts reach the client as well as tools. An unset
/// `resources` exposes nothing, so this fails if the bridge's config opens
/// only `tools`.
#[tokio::test]
async fn resources_and_prompts_pass_through_as_well_as_tools() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let ca = pki.write_root(dir.path(), "server-ca");
    let remote = Remote::start(dir.path(), &pki, "", None).await;

    let mut client = Client::open(bridge(&remote.url, dir.path(), &ca, &[])).await;

    let listed = client.ask(method::RESOURCES_LIST, json!({})).await;
    let uris: Vec<&str> = listed.result.as_ref().unwrap()["resources"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["uri"].as_str())
        .collect();
    assert_eq!(uris, vec!["file:///notes/readme.md"], "{listed:?}");

    let read = client
        .ask(
            method::RESOURCES_READ,
            json!({ "uri": "file:///notes/readme.md" }),
        )
        .await;
    assert_eq!(
        read.result.as_ref().unwrap()["contents"][0]["text"],
        json!("the readme"),
        "{read:?}"
    );

    let prompts = client.ask(method::PROMPTS_LIST, json!({})).await;
    assert_eq!(
        prompts.result.as_ref().unwrap()["prompts"][0]["name"],
        json!("summarize"),
        "{prompts:?}"
    );
}

/// A remote that requires a client certificate serves a bridge that presents
/// one, and nothing reaches it through a bridge that does not.
#[tokio::test]
async fn a_client_certificate_gets_through_a_remote_that_requires_one() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let agents = Pki::new("agents CA");
    let ca = pki.write_root(dir.path(), "server-ca");
    let agents_ca = agents.write_root(dir.path(), "agents-ca");
    let client_auth = format!(
        "[gateway.tls.client_auth]\nmode = \"required\"\nca = [{agents_ca:?}]\n\
         identity = \"spiffe\"\ntrust_domains = [\"prod.acme.internal\"]"
    );
    let remote = Remote::start(dir.path(), &pki, &client_auth, None).await;
    let (cert, key) = agents.client(BOT).write(dir.path(), "agent");

    let with = [
        "--cert".to_string(),
        cert.display().to_string(),
        "--key".to_string(),
        key.display().to_string(),
    ];
    let mut client = Client::open(bridge(&remote.url, dir.path(), &ca, &with)).await;
    assert_eq!(client.tool_names().await, vec!["echo".to_string()]);
    let result = client
        .call("echo", json!({ "msg": "with a certificate" }))
        .await;
    assert_eq!(result["isError"], json!(false), "{result}");

    // Without one the handshake is refused, so the bridge has no tools to offer.
    let other = tempfile::tempdir().unwrap();
    let mut client = Client::open(bridge(&remote.url, other.path(), &ca, &[])).await;
    assert_eq!(
        client.tool_names().await,
        Vec::<String>::new(),
        "a bridge without a certificate must reach nothing"
    );
}

/// A token file is sent as the bearer; a remote that requires a token
/// refuses a bridge that has none.
#[tokio::test]
async fn a_token_file_is_sent_as_the_bearer() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let ca = pki.write_root(dir.path(), "server-ca");
    let auth_table = format!(
        "[gateway.auth]\nenabled = true\nissuer = {ISSUER:?}\nresource = {RESOURCE:?}\n\
         jwks = {TEST_JWKS:?}"
    );
    let verifier = Verifier::from_jwks_json(TEST_JWKS, ISSUER, RESOURCE).unwrap();
    let remote = Remote::start(
        dir.path(),
        &pki,
        &auth_table,
        Some(AuthState::new(verifier)),
    )
    .await;

    let token_file = dir.path().join("token");
    std::fs::write(&token_file, token()).unwrap();
    let with = ["--token-file".to_string(), token_file.display().to_string()];
    let mut client = Client::open(bridge(&remote.url, dir.path(), &ca, &with)).await;
    let result = client.call("echo", json!({ "msg": "with a token" })).await;
    assert_eq!(result["isError"], json!(false), "{result}");

    let other = tempfile::tempdir().unwrap();
    let mut client = Client::open(bridge(&remote.url, other.path(), &ca, &[])).await;
    assert_eq!(
        client.tool_names().await,
        Vec::<String>::new(),
        "a bridge without a token must reach nothing"
    );
}

/// `--print-config` prints a valid gateway config, and names the token's file
/// rather than its contents.
#[test]
fn print_config_is_a_valid_gateway_config_and_holds_no_secret() {
    let dir = tempfile::tempdir().unwrap();
    let secret = "s3cr3t-token-value-that-must-not-print";
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, secret).unwrap();

    let out = Command::new(BIN)
        .args(["bridge", "https://mcpdef.example.com/mcp", "--print-config"])
        .arg("--token-file")
        .arg(&token_file)
        .arg("--audit")
        .arg(dir.path().join("audit.log"))
        .arg("--state-dir")
        .arg(dir.path().join("state"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        !text.contains(secret),
        "the token's value was printed:\n{text}"
    );
    assert!(text.contains(&token_file.display().to_string()), "{text}");

    let cfg = Config::parse(&text).unwrap();
    assert_eq!(cfg.validate(), Vec::<String>::new(), "{text}");
}

/// With no home to put its ledger in and no flags naming a place, the bridge
/// refuses, naming the flags, rather than writing into the working directory.
#[test]
fn without_a_home_the_bridge_names_the_flags_instead_of_guessing() {
    let out = Command::new(BIN)
        .args(["bridge", "https://mcpdef.example.com/mcp", "--print-config"])
        .env_remove("HOME")
        .output()
        .unwrap();
    assert!(!out.status.success(), "{out:?}");
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(
        err.contains("--audit") && err.contains("--state-dir"),
        "{err}"
    );
}

/// The ledger and state default under the home directory, never the working
/// directory a client happened to launch the bridge from.
#[test]
fn the_defaults_live_under_home() {
    let home = tempfile::tempdir().unwrap();
    let out = Command::new(BIN)
        .args(["bridge", "https://mcpdef.example.com/mcp", "--print-config"])
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    let under: PathBuf = home.path().join(".mcpdef").join("bridge");
    assert!(
        text.contains(&under.join("audit.log").display().to_string()),
        "{text}"
    );
    assert!(
        text.contains(&under.join("state").display().to_string()),
        "{text}"
    );
}
