// SPDX-License-Identifier: Apache-2.0
//! What the admin API does, and who may ask it:
//!   * `POST /api/v1/reload` reads the config again and applies it, as
//!     `SIGHUP` does, answering what changed; a config that does not apply is
//!     refused `409`, with the rule and its reasons, and the old one keeps
//!     serving. Both are recorded with the caller as the reload's actor, and
//!     the address it called from;
//!   * an action needs `console:operator`: a viewer asking for one is
//!     refused `403`, and the refusal is recorded too, as an admin action
//!     refused under `console-role`.

use mcpdef::connect::build_gateway;
use mcpdef::reload::{channel, Reloader, Snapshot};
use mcpdef::tls::{ListenerTls, Serving};
use mcpdef::{serve_admin_on, AdminState, Config, Metrics};
use mcpdef_audit::{read_all, Record};
use mcpdef_testkit::{Leaf, Pki};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");
const OPS: &str = "spiffe://prod.acme.internal/ns/ops/sa/alice";
const AUDITOR: &str = "spiffe://prod.acme.internal/ns/audit/sa/bob";

/// A task stopped however the test ends.
struct Aborted(tokio::task::JoinHandle<()>);

impl Drop for Aborted {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn server(id: &str) -> String {
    format!(
        "[[server]]\nid = {id:?}\ntransport = \"stdio\"\ncommand = [{MOCK:?}, \"--tool-prefix\", \
         \"{id}_\"]\ntools = [\"{id}_echo\"]\n\n"
    )
}

/// The config at `dir/mcpdef.toml`: an admin listener with `admin` in its
/// table, `rest` after it, and `servers`.
fn write(dir: &Path, admin: &str, rest: &str, servers: &[&str]) {
    let text = format!(
        "[gateway]\naudit = {audit:?}\nstate_dir = {state:?}\n\n\
         [gateway.admin]\nenabled = true\nlisten = \"127.0.0.1:0\"\n{admin}\n\n{rest}\n{servers}",
        audit = dir.join("audit.log"),
        state = dir.join("state"),
        servers = servers.concat(),
    );
    std::fs::write(dir.join("mcpdef.toml"), text).unwrap();
}

/// A gateway on the config `write` wrote in `dir`, its reloader running and
/// taking the admin API's requests, and its admin listener on a loopback
/// port, over TLS when the config says.
async fn start(dir: &Path) -> (SocketAddr, Aborted, Aborted) {
    let path = dir.join("mcpdef.toml");
    let (cfg, text) = Config::load_text(&path).unwrap();
    assert_eq!(cfg.validate(), Vec::<String>::new());
    let snapshot = Snapshot::take(text.as_bytes(), &cfg);
    let slot = ListenerTls::start(&cfg, Serving::of(&cfg, false))
        .unwrap()
        .and_then(|(tls, _)| tls.admin());
    let gw = build_gateway(&cfg).await.unwrap();
    let (reloads, requests) = channel();
    let state = Arc::new(
        AdminState::new(&cfg, Arc::new(Metrics::new(1)), gw.clone(), "test").with_reloads(reloads),
    );
    // As `mcpdef run` wires it: each config applied refreshes the admin view.
    let refreshed = Arc::clone(&state);
    let reloader = Reloader::new(&path, None, gw, cfg, snapshot)
        .on_applied(move |cfg| refreshed.reconfigure(cfg))
        .with_requests(requests);
    let reloading = Aborted(tokio::spawn(reloader.run(Duration::from_secs(3600))));
    let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = bound.local_addr().unwrap();
    let serving = Aborted(tokio::spawn(async move {
        serve_admin_on(state, bound, slot).await.unwrap();
    }));
    (addr, serving, reloading)
}

/// A request's status and its body as JSON.
async fn send(request: reqwest::RequestBuilder) -> (u16, Value) {
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

/// `POST /api/v1/reload`, as a script would send it.
fn reload(client: &reqwest::Client, base: &str) -> reqwest::RequestBuilder {
    client
        .post(format!("{base}/api/v1/reload"))
        .header("content-type", "application/json")
        .body("{}")
}

/// The ledger's records of `kind`.
fn records(dir: &Path, kind: &str) -> Vec<Record> {
    read_all(dir.join("audit.log"))
        .unwrap()
        .into_iter()
        .filter(|r| r.kind.as_deref() == Some(kind))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_console_reload_applies_or_is_refused_and_names_its_caller() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "", "", &[&server("a")]);
    let (addr, _serving, _reloading) = start(dir.path()).await;
    mcpdef_transport::install_crypto_provider();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let base = format!("http://{addr}");

    // A server added: applied, and said so.
    write(dir.path(), "", "", &[&server("a"), &server("b")]);
    let (status, applied) = send(reload(&client, &base)).await;
    assert_eq!(status, 200, "{applied}");
    assert_eq!(
        applied,
        json!({ "outcome": "applied", "added": ["b"], "removed": [], "reconnected": [], "failed": [] })
    );
    let (_, servers) = send(client.get(format!("{base}/api/v1/servers"))).await;
    let ids: Vec<&str> = servers
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["a", "b"]);

    // A config that does not parse: refused, with why, and the old one serves.
    std::fs::write(dir.path().join("mcpdef.toml"), "[gateway\n").unwrap();
    let (status, refused) = send(reload(&client, &base)).await;
    assert_eq!(status, 409, "{refused}");
    assert_eq!(refused["outcome"], "refused");
    assert_eq!(refused["rule"], "invalid-config");
    assert_eq!(refused["status"], 409);
    assert!(
        !refused["reasons"].as_array().unwrap().is_empty(),
        "{refused}"
    );
    let (_, servers) = send(client.get(format!("{base}/api/v1/servers"))).await;
    assert_eq!(servers.as_array().unwrap().len(), 2, "{servers}");

    // Both are in the ledger, with who asked and from where.
    let reloads = records(dir.path(), "reload");
    let seen: Vec<(&str, Option<&str>, Option<&str>)> = reloads
        .iter()
        .map(|r| (r.decision.as_str(), r.rule.as_deref(), r.actor.as_deref()))
        .collect();
    assert_eq!(
        seen,
        [
            ("allow", None, Some("local")),
            ("deny", Some("invalid-config"), Some("local")),
        ]
    );
    for record in &reloads {
        assert!(
            record
                .peer
                .as_deref()
                .is_some_and(|p| p.starts_with("127.0.0.1:")),
            "{record:?}"
        );
    }
}

/// An admin listener on TLS that requires a certificate from the agents' CA:
/// Alice, of ops, may act; Bob, an auditor, may read.
fn requiring_certificates(dir: &Path, servers: &[&str]) -> (Pki, Pki) {
    let (server_pki, agents) = (Pki::new("mcpdef test CA"), Pki::new("agents CA"));
    let (cert, key) = server_pki.server(&["127.0.0.1"]).write(dir, "listener");
    let ca = agents.write_root(dir, "agents-ca");
    let admin = format!(
        "[gateway.admin.tls]\nmode = \"files\"\ncert = {cert:?}\nkey = {{ file = {key:?} }}\n\n\
         [gateway.admin.tls.client_auth]\nmode = \"required\"\nca = [{ca:?}]\n\
         identity = \"spiffe\"\ntrust_domains = [\"prod.acme.internal\"]"
    );
    let rest = "[[identity.cert_map]]\nidentity = \"spiffe://prod.acme.internal/ns/ops/*\"\n\
         roles = [\"console:operator\"]\n\n\
         [[identity.cert_map]]\nidentity = \"spiffe://prod.acme.internal/ns/audit/*\"\n\
         roles = [\"console:viewer\"]\n";
    write(dir, &admin, rest, servers);
    (server_pki, agents)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewer_may_not_reload_and_the_refusal_is_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let (server_pki, agents) = requiring_certificates(dir.path(), &[&server("a")]);
    let (addr, _serving, _reloading) = start(dir.path()).await;
    let client = |leaf: &Leaf| mcpdef_testkit::https_client(&server_pki, Some(leaf));
    let base = format!("https://{addr}");
    let (alice, bob) = (client(&agents.client(OPS)), client(&agents.client(AUDITOR)));

    let (status, refused) = send(reload(&bob, &base)).await;
    assert_eq!(status, 403, "{refused}");
    assert_eq!(
        refused["detail"],
        format!("cert:{AUDITOR} holds console:viewer, and reload needs console:operator")
    );
    // Refused before any reload ran.
    assert!(records(dir.path(), "reload").is_empty());
    let admin = records(dir.path(), "admin");
    assert_eq!(admin.len(), 1, "{admin:?}");
    let record = &admin[0];
    assert_eq!(
        (
            record.server.as_str(),
            record.method.as_deref(),
            record.decision.as_str(),
            record.rule.as_deref(),
            record.actor.as_deref(),
        ),
        (
            "(config)",
            Some("reload"),
            "deny",
            Some("console-role"),
            Some(format!("cert:{AUDITOR}").as_str()),
        )
    );
    assert!(record.peer.is_some(), "{record:?}");

    // The operator's goes through, with her as its actor.
    write_servers_again(dir.path(), &agents);
    let (status, applied) = send(reload(&alice, &base)).await;
    assert_eq!(status, 200, "{applied}");
    let reloads = records(dir.path(), "reload");
    assert_eq!(reloads.len(), 1, "{reloads:?}");
    assert_eq!(
        reloads[0].actor.as_deref(),
        Some(format!("cert:{OPS}").as_str())
    );
    // The ledger still verifies, its new kinds of record and all.
    let verified = mcpdef_audit::verify(dir.path().join("audit.log")).unwrap();
    assert_eq!((verified.records, verified.broken_at), (2, None));
}

/// The same config, a server added: the CAs and files are as they were.
fn write_servers_again(dir: &Path, _agents: &Pki) {
    let text = std::fs::read_to_string(dir.join("mcpdef.toml")).unwrap();
    std::fs::write(dir.join("mcpdef.toml"), text + &server("b")).unwrap();
}
