// SPDX-License-Identifier: Apache-2.0
//! What the gateway reports of each HTTPS upstream's certificate: on
//! `/api/v1/servers`, as `mcpdef_upstream_cert_expiry_seconds`, and in the
//! profile `mcpdef egress show` prints. A plain-HTTP upstream has none of it.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use mcpdef::connect::build_gateway;
use mcpdef::reload::{Outcome, Reloader, Snapshot, Trigger};
use mcpdef::{serve_admin_on, AdminState, Config, Gateway, HealthState, Metrics, TlsStatus};
use mcpdef_testkit::{HttpsUpstream, Leaf, Pki};
use mcpdef_transport::Pin;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A `[gateway]` table with its ledger in `dir`, then `rest`.
fn config(dir: &Path, rest: &str) -> String {
    let audit = dir.join("audit.log");
    format!("[gateway]\nlisten = \"127.0.0.1:0\"\naudit = {audit:?}\n\n{rest}")
}

/// A `[[server]]` entry for a Streamable-HTTP upstream at `url`, then `rest`.
fn server(id: &str, url: &str, rest: &str) -> String {
    format!("[[server]]\nid = {id:?}\ntransport = \"streamable-http\"\nurl = {url:?}\n{rest}\n\n")
}

async fn start(text: &str) -> (Config, Gateway) {
    let config = Config::parse(text).unwrap();
    assert_eq!(config.validate(), Vec::<String>::new());
    let gateway = build_gateway(&config).await.unwrap();
    (config, gateway)
}

/// The SHA-256 of `leaf`'s certificate, in the colon-separated hex `openssl
/// x509 -fingerprint -sha256` prints, worked out here rather than by the code
/// under test.
fn fingerprint(leaf: &Leaf) -> String {
    Sha256::digest(leaf.cert_der())
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn status(gw: &Gateway, id: &str) -> mcpdef::UpstreamStatus {
    gw.upstream_status()
        .into_iter()
        .find(|u| u.id == id)
        .expect("the upstream")
}

/// An MCP upstream on plain HTTP: `initialize`, `tools/list` and `tools/call`.
async fn plain_upstream() -> String {
    async fn mcp(body: String) -> Response {
        let Ok(request) = serde_json::from_str::<Value>(&body) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        let Some(id) = request.get("id").cloned() else {
            return StatusCode::ACCEPTED.into_response();
        };
        let result = match request["method"].as_str() {
            Some("initialize") => json!({
                "protocolVersion": "2025-11-25",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "plain", "version": "0" }
            }),
            Some("tools/list") => json!({ "tools": [
                { "name": "plain_echo", "inputSchema": { "type": "object" } }
            ]}),
            _ => json!({ "content": [{ "type": "text", "text": "plain" }], "isError": false }),
        };
        let reply = json!({ "jsonrpc": "2.0", "id": id, "result": result });
        (
            [(header::CONTENT_TYPE, "application/json")],
            reply.to_string(),
        )
            .into_response()
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(
        async move { axum::serve(listener, Router::new().route("/mcp", post(mcp))).await },
    );
    format!("http://{addr}/mcp")
}

/// `/api/v1/servers` and `/metrics`, from an admin server on `gw`, as
/// `mcpdef run` serves them.
async fn admin(config: &Config, gw: &Gateway) -> (Value, String) {
    let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap().to_string();
    let state = Arc::new(AdminState::new(
        config,
        Arc::new(Metrics::new(config.servers.len() as u64)),
        gw.clone(),
        "test",
    ));
    tokio::spawn(serve_admin_on(state, bound, None));
    mcpdef_transport::install_crypto_provider();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let get = |path: &str| {
        let request = client.get(format!("http://{listen}{path}"));
        async move {
            let until = Instant::now() + Duration::from_secs(5);
            loop {
                match request.try_clone().unwrap().send().await {
                    Ok(response) => return response.text().await.unwrap(),
                    Err(e) if Instant::now() > until => panic!("{e}"),
                    Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
                }
            }
        }
    };
    let servers = serde_json::from_str(&get("/api/v1/servers").await).unwrap();
    (servers, get("/metrics").await)
}

/// The lines of the expiry metric in `metrics`, its HELP and TYPE included.
fn expiry_lines(metrics: &str) -> Vec<&str> {
    metrics
        .lines()
        .filter(|l| l.contains("mcpdef_upstream_cert_expiry_seconds"))
        .collect()
}

#[tokio::test]
async fn an_https_upstream_shows_its_certificate_and_a_plain_http_one_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let leaf = pki
        .leaf()
        .name("127.0.0.1")
        .server_auth()
        .valid((2020, 1, 1), (2031, 2, 3))
        .issue();
    let secure = HttpsUpstream::start(&leaf).await;
    let plain = plain_upstream().await;
    let ca = pki.write_root(dir.path(), "ca");
    let (config, gw) = start(&config(
        dir.path(),
        &format!(
            "{}{}",
            server(
                "secure",
                &secure.url(),
                &format!("[server.tls]\nca = [{ca:?}]")
            ),
            server("plain", &plain, ""),
        ),
    ))
    .await;

    assert_eq!(
        status(&gw, "secure").tls,
        Some(TlsStatus {
            verify: "ca",
            fingerprint: Some(fingerprint(&leaf)),
            not_after: Some("2031-02-03T00:00:00Z".into()),
            not_after_unix: Some(1_927_843_200),
            client_not_after: None,
            client_not_after_unix: None,
        })
    );
    assert_eq!(status(&gw, "plain").health, HealthState::Up);
    assert_eq!(status(&gw, "plain").tls, None);

    let (servers, metrics) = admin(&config, &gw).await;
    assert_eq!(servers[0]["id"], "secure");
    assert_eq!(
        servers[0]["tls"],
        json!({
            "verify": "ca",
            "fingerprint": fingerprint(&leaf),
            "not_after": "2031-02-03T00:00:00Z",
        })
    );
    assert_eq!(servers[1]["id"], "plain");
    assert_eq!(servers[1]["health"], "up");
    assert_eq!(servers[1].get("tls"), None, "{}", servers[1]);
    assert_eq!(
        expiry_lines(&metrics),
        [
            "# HELP mcpdef_upstream_cert_expiry_seconds When the certificate an HTTPS upstream presented last expires, as a Unix time.",
            "# TYPE mcpdef_upstream_cert_expiry_seconds gauge",
            "mcpdef_upstream_cert_expiry_seconds{server=\"secure\"} 1927843200",
        ]
    );
}

/// `verify` says how the certificate shown was checked: by a pin, or not at
/// all. A certificate is shown once a connection that took it has answered;
/// one the gateway refused shows nothing.
#[tokio::test]
async fn each_https_upstream_says_how_its_certificate_was_checked() {
    let dir = tempfile::tempdir().unwrap();
    let leaf = Leaf::self_signed(&["127.0.0.1"]);
    let (pinned, unchecked, untrusted) = (
        HttpsUpstream::start(&leaf).await,
        HttpsUpstream::start(&leaf).await,
        HttpsUpstream::start(&leaf).await,
    );
    let pin = Pin::of(leaf.cert_der()).unwrap();
    let (config, gw) = start(&config(
        dir.path(),
        &format!(
            "{}{}{}",
            server(
                "pinned",
                &pinned.url(),
                &format!("[server.tls]\npin_sha256 = [\"{pin}\"]")
            ),
            server(
                "unchecked",
                &unchecked.url(),
                "[server.tls]\ninsecure_skip_verify = true"
            ),
            server("untrusted", &untrusted.url(), ""),
        ),
    ))
    .await;

    for (id, verify) in [("pinned", "pin"), ("unchecked", "disabled")] {
        let tls = status(&gw, id).tls.expect("a certificate");
        assert_eq!(tls.verify, verify);
        assert_eq!(tls.fingerprint, Some(fingerprint(&leaf)));
        // The testkit's certificates run to 4096 unless told otherwise.
        assert_eq!(tls.not_after.as_deref(), Some("4096-01-01T00:00:00Z"));
    }
    assert_eq!(status(&gw, "untrusted").health, HealthState::Down);
    assert_eq!(status(&gw, "untrusted").tls, None);

    let (servers, metrics) = admin(&config, &gw).await;
    assert_eq!(servers[0]["tls"]["verify"], "pin");
    assert_eq!(servers[1]["tls"]["verify"], "disabled");
    assert_eq!(servers[2].get("tls"), None, "{}", servers[2]);
    let expiry = expiry_lines(&metrics);
    assert_eq!(
        expiry[2..],
        [
            "mcpdef_upstream_cert_expiry_seconds{server=\"pinned\"} 67090118400",
            "mcpdef_upstream_cert_expiry_seconds{server=\"unchecked\"} 67090118400",
        ]
    );
}

/// `verify` is how the connection in use was checked. A reload that pins the
/// upstream reconnects it, and the new connection says `pin`, with the same
/// certificate.
#[tokio::test]
async fn a_reload_that_pins_an_upstream_shows_it_verified_by_its_pin() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let leaf = pki.server(&["127.0.0.1"]);
    let upstream = HttpsUpstream::start(&leaf).await;
    let ca = pki.write_root(dir.path(), "ca");
    let path = dir.path().join("mcpdef.toml");
    let write = |tls: &str| {
        let text = config(dir.path(), &server("secure", &upstream.url(), tls));
        std::fs::write(&path, text).unwrap();
    };
    write(&format!("[server.tls]\nca = [{ca:?}]"));
    let (config, text) = Config::load_text(&path).unwrap();
    let snapshot = Snapshot::take(text.as_bytes(), &config);
    let gw = build_gateway(&config).await.unwrap();
    let mut reloader = Reloader::new(&path, None, gw.clone(), config, snapshot);
    let before = status(&gw, "secure").tls.expect("a certificate");
    assert_eq!(before.verify, "ca");

    let pin = Pin::of(leaf.cert_der()).unwrap();
    write(&format!("[server.tls]\npin_sha256 = [\"{pin}\"]"));
    let Outcome::Applied(report) = reloader.reload(Trigger::Signal).await else {
        panic!("the reload applies")
    };
    assert_eq!(report.reconnected, ["secure"]);
    let after = status(&gw, "secure").tls.expect("a certificate");
    assert_eq!(after.verify, "pin");
    assert_eq!(after.fingerprint, before.fingerprint);
    assert_eq!(after.fingerprint, Some(fingerprint(&leaf)));
}

/// `mcpdef egress show` prints the TLS profile of each HTTPS upstream, its
/// `[server.tls]` over `[gateway.upstream_tls]`, and of the gateway's own
/// fetches. A plain-HTTP or stdio upstream has none, and is not named.
#[test]
fn egress_show_prints_each_https_upstreams_tls_profile() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    let text = config(
        dir.path(),
        &format!(
            "[gateway.upstream_tls]\nca = [\"/etc/mcpdef/ca.pem\"]\ncrl = [\"/etc/mcpdef/ca.crl\"]\n\n{}{}{}{}[[server]]\nid = \"fs\"\ntransport = \"stdio\"\ncommand = [\"true\"]\n",
            server(
                "internal",
                "https://mcp.internal.example/mcp",
                "[server.tls]\nroots = \"both\"\nmin_version = \"1.3\"\nclient_cert = \"/etc/mcpdef/client.pem\"\nclient_key = { file = \"/etc/mcpdef/client.key\" }\nconnect_to = \"10.0.0.5\"",
            ),
            server(
                "appliance",
                "https://10.1.2.3/mcp",
                "[server.tls]\npin_sha256 = [\"kW1vBnQpOt7wBNmvZG2itgd9KUyIIeTffw1ZmJMRQXg=\"]",
            ),
            server(
                "lab",
                "https://lab.local/mcp",
                "[server.tls]\ninsecure_skip_verify = true"
            ),
            server("local", "http://127.0.0.1:9000/mcp", ""),
        ),
    );
    std::fs::write(&path, text).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_mcpdef"))
        .args(["egress", "show", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let tls: Vec<&str> = stdout
        .lines()
        .skip_while(|l| !l.starts_with("tls profiles"))
        .collect();
    let ca = "its chain to a trusted root, its name and its dates are checked";
    assert_eq!(
        tls,
        [
            "tls profiles (HTTPS upstreams; plain-HTTP and stdio ones have none):",
            "  [gateway.upstream_tls], for the jwks_uri fetch and under every [server.tls]:",
            &format!("    verify       : ca        {ca}"),
            "    roots        : bundled",
            "    ca           : /etc/mcpdef/ca.pem",
            "    crl          : /etc/mcpdef/ca.crl",
            "    min_version  : 1.2",
            "    client_cert  : none",
            "  server 'internal' (https://mcp.internal.example/mcp):",
            &format!("    verify       : ca        {ca}"),
            "    roots        : both",
            "    ca           : /etc/mcpdef/ca.pem",
            "    crl          : /etc/mcpdef/ca.crl",
            "    min_version  : 1.3",
            "    client_cert  : /etc/mcpdef/client.pem",
            "    connect_to   : 10.0.0.5",
            "  server 'appliance' (https://10.1.2.3/mcp):",
            "    verify       : pin       its key alone is checked: not its issuer, names or dates",
            "    pin_sha256   : kW1vBnQpOt7wBNmvZG2itgd9KUyIIeTffw1ZmJMRQXg=",
            "    min_version  : 1.2",
            "    client_cert  : none",
            "  server 'lab' (https://lab.local/mcp):",
            "    verify       : disabled  nothing is checked (insecure_skip_verify)",
            "    min_version  : 1.2",
            "    client_cert  : none",
        ]
    );
    assert!(
        !stdout.contains("'local'") && !stdout.contains("'fs'"),
        "{stdout}"
    );
}
