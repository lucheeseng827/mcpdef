// SPDX-License-Identifier: Apache-2.0
//! The admin listener's envelope, end to end over HTTP and HTTPS:
//!   * a request naming a host this listener does not answer to is refused
//!     `421` (a page that rebinds its own name to it names its own name);
//!   * a request that changes something from another origin is refused
//!     `403`, and one sending a form `415`, before any route sees it;
//!   * every answer carries the content security policy and the headers that
//!     keep it out of frames and caches, refusals included, and every
//!     refusal is a problem document;
//!   * with nothing to sign callers in, a loopback listener is open to
//!     whoever reaches it, as `local`, and says so;
//!   * where it requires a client certificate, the certificate's console role
//!     decides: one mapped to `console:viewer` reads, and one with none is
//!     refused every route but who it is.

use mcpdef::connect::build_gateway;
use mcpdef::tls::{ListenerTls, Serving};
use mcpdef::{serve_admin_on, AdminState, Config, Metrics, CONTENT_SECURITY_POLICY};
use mcpdef_testkit::{Leaf, Pki};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");
const OPS: &str = "spiffe://prod.acme.internal/ns/ops/sa/alice";
const BOT: &str = "spiffe://prod.acme.internal/ns/ci/sa/bot";

/// A task stopped however the test ends.
struct Aborted(tokio::task::JoinHandle<()>);

impl Drop for Aborted {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// An admin listener over a gateway with the stdio mock, its config
/// `[gateway.admin]`'s `admin` and `rest` after its server, its files in
/// `dir`; served on a loopback port, over TLS when the config says.
async fn serve(dir: &Path, admin: &str, rest: &str) -> (SocketAddr, Aborted) {
    let text = format!(
        "[gateway]\naudit = {audit:?}\nstate_dir = {state:?}\n\n\
         [gateway.admin]\nenabled = true\nlisten = \"127.0.0.1:0\"\n{admin}\n\n\
         [[server]]\nid = \"mock\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\n\
         tools = [\"echo\"]\n\n{rest}\n",
        audit = dir.join("audit.log"),
        state = dir.join("state"),
    );
    let path = dir.join("mcpdef.toml");
    std::fs::write(&path, text).unwrap();
    let (cfg, _) = Config::load_text(&path).unwrap();
    assert_eq!(cfg.validate(), Vec::<String>::new());
    let slot = ListenerTls::start(&cfg, Serving::of(&cfg, false))
        .unwrap()
        .and_then(|(tls, _)| tls.admin());
    let gw = build_gateway(&cfg).await.unwrap();
    let state = Arc::new(AdminState::new(&cfg, Arc::new(Metrics::new(1)), gw, "test"));
    let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = bound.local_addr().unwrap();
    let serving = Aborted(tokio::spawn(async move {
        serve_admin_on(state, bound, slot).await.unwrap();
    }));
    (addr, serving)
}

fn plain() -> reqwest::Client {
    mcpdef_transport::install_crypto_provider();
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// A request's status, headers and body, parsed as JSON when it is.
async fn send(request: reqwest::RequestBuilder) -> (u16, HeaderMap, Value) {
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let text = response.text().await.unwrap();
    let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, headers, body)
}

/// Every answer carries these, whatever it is.
fn assert_secured(headers: &HeaderMap, what: &str) {
    for (name, value) in [
        ("content-security-policy", CONTENT_SECURITY_POLICY),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
    ] {
        assert_eq!(
            headers.get(name),
            Some(&HeaderValue::from_static(value)),
            "{name} on {what}"
        );
    }
}

/// A refusal is a problem document with `status`.
fn assert_problem(status: u16, headers: &HeaderMap, body: &Value, what: &str) {
    assert_eq!(
        headers.get("content-type"),
        Some(&HeaderValue::from_static("application/problem+json")),
        "{what}: {body}"
    );
    assert_eq!(body["status"], json!(status), "{what}: {body}");
    assert!(
        body["title"].is_string() && body["detail"].is_string(),
        "{what}: {body}"
    );
}

#[tokio::test]
async fn an_open_listener_checks_host_and_origin_and_says_who_is_calling() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _serving) = serve(dir.path(), "hosts = [\"mcpdef-admin.lan\"]", "").await;
    let client = plain();
    let url = |path: &str| format!("http://{addr}{path}");

    // Anyone on this machine: `local`, holding every role, told so.
    let (status, headers, session) = send(client.get(url("/api/v1/session"))).await;
    assert_eq!(status, 200, "{session}");
    assert_secured(&headers, "/api/v1/session");
    assert_eq!(
        session,
        json!({
            "actor": "local",
            "role": "console:admin",
            "roles": ["console:viewer", "console:operator", "console:admin"],
            "open": true,
        })
    );
    for path in ["/api/v1/status", "/api/v1/servers", "/metrics"] {
        let (status, headers, body) = send(client.get(url(path))).await;
        assert_eq!(status, 200, "{path}: {body}");
        assert_secured(&headers, path);
    }
    // The page, whichever this build serves: the console, or the built-in
    // status page. It loads no script and no style inline, as the policy
    // wants: each is a file of its own, which it may load.
    let (status, headers, page) = send(client.get(url("/"))).await;
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("content-security-policy"),
        Some(&HeaderValue::from_static(CONTENT_SECURITY_POLICY))
    );
    let page = page.as_str().unwrap();
    assert!(!page.contains("<style"), "{page}");
    let sources: Vec<&str> = page
        .split("<script")
        .skip(1)
        .map(|tag| {
            let tag = &tag[..tag.find('>').unwrap()];
            let src = tag
                .split(" src=\"")
                .nth(1)
                .unwrap_or_else(|| panic!("inline: {tag}"));
            &src[..src.find('"').unwrap()]
        })
        .collect();
    assert!(!sources.is_empty(), "{page}");
    for src in sources {
        let (status, headers, _) = send(client.get(url(src))).await;
        assert_eq!(status, 200, "{src}");
        assert_eq!(
            headers["content-type"], "text/javascript; charset=utf-8",
            "{src}"
        );
    }

    // A name another page rebound to this address: refused, whatever the path.
    for host in [
        "evil.example",
        "evil.example:7879",
        "localhost.evil.example",
    ] {
        let (status, headers, body) =
            send(client.get(url("/api/v1/status")).header("host", host)).await;
        assert_eq!(status, 421, "{host}: {body}");
        assert_problem(421, &headers, &body, host);
        assert_secured(&headers, host);
    }
    // The names it answers to: an IP literal, localhost, and one it was given.
    for host in [
        "127.0.0.1",
        "localhost:7879",
        "mcpdef-admin.lan:7879",
        "[::1]:7879",
    ] {
        let (status, _, body) = send(client.get(url("/api/v1/status")).header("host", host)).await;
        assert_eq!(status, 200, "{host}: {body}");
    }

    // A change another origin asks for: refused before any route sees it.
    let own = format!("http://{addr}");
    for (name, value) in [
        ("sec-fetch-site", "cross-site"),
        ("sec-fetch-site", "same-site"),
        ("origin", "http://evil.example"),
        ("origin", "null"),
    ] {
        let (status, headers, body) = send(
            client
                .post(url("/api/v1/reload"))
                .header(name, value)
                .header("content-type", "application/json")
                .body("{}"),
        )
        .await;
        assert_eq!(status, 403, "{name}: {value}: {body}");
        assert_problem(403, &headers, &body, value);
        assert!(
            body["detail"].as_str().unwrap().contains("own origin"),
            "{body}"
        );
    }
    // A form, from an origin an old browser vouches for: refused.
    let (status, headers, body) = send(
        client
            .post(url("/api/v1/reload"))
            .header("origin", &own)
            .header("content-type", "application/x-www-form-urlencoded")
            .body("a=b"),
    )
    .await;
    assert_eq!(status, 415, "{body}");
    assert_problem(415, &headers, &body, "a form");
    // The console's own origin, and no browser at all, reach the routes: this
    // one is not there yet.
    for request in [
        client
            .post(url("/api/v1/nothing"))
            .header("sec-fetch-site", "same-origin"),
        client.post(url("/api/v1/nothing")).header("origin", &own),
        client.post(url("/api/v1/nothing")),
    ] {
        let (status, headers, body) = send(
            request
                .header("content-type", "application/json")
                .body("{}"),
        )
        .await;
        assert_eq!(status, 404, "{body}");
        assert_problem(404, &headers, &body, "an unknown route");
    }
    // A route there is, with a method it does not take: a problem document
    // too, and the methods it does take.
    let (status, headers, body) = send(
        client
            .post(url("/api/v1/info"))
            .header("sec-fetch-site", "same-origin"),
    )
    .await;
    assert_eq!(status, 405, "{body}");
    assert_problem(405, &headers, &body, "a method the route does not take");
    assert_eq!(
        headers.get("allow").and_then(|v| v.to_str().ok()),
        Some("GET,HEAD"),
        "{body}"
    );
    assert_secured(&headers, "POST /api/v1/info");
}

/// A gateway whose admin listener serves TLS from the listener's PKI and
/// requires a certificate from the agents' CA: Alice's, from ops, holds
/// `console:viewer`; the bot's holds `ci` alone.
async fn requiring_certificates(dir: &Path) -> (SocketAddr, Aborted, Pki, Pki) {
    let (server, agents) = (Pki::new("mcpdef test CA"), Pki::new("agents CA"));
    let (cert, key) = server.server(&["127.0.0.1"]).write(dir, "listener");
    let ca = agents.write_root(dir, "agents-ca");
    let admin = format!(
        "[gateway.admin.tls]\nmode = \"files\"\ncert = {cert:?}\nkey = {{ file = {key:?} }}\n\n\
         [gateway.admin.tls.client_auth]\nmode = \"required\"\nca = [{ca:?}]\n\
         identity = \"spiffe\"\ntrust_domains = [\"prod.acme.internal\"]"
    );
    let rest = "[[role]]\nname = \"ci\"\ngrants = [\"mock:echo\"]\n\n\
         [[identity.cert_map]]\nidentity = \"spiffe://prod.acme.internal/ns/ops/*\"\n\
         roles = [\"console:viewer\"]\n\n\
         [[identity.cert_map]]\nidentity = \"spiffe://prod.acme.internal/ns/ci/*\"\n\
         roles = [\"ci\"]\n";
    let (addr, serving) = serve(dir, &admin, rest).await;
    (addr, serving, server, agents)
}

/// The reads a viewer may make, and a caller with no console role may not.
const READS: [&str; 16] = [
    "/api/v1/status",
    "/api/v1/servers",
    "/api/v1/audit",
    "/metrics",
    "/api/v1/info",
    "/api/v1/metrics",
    "/api/v1/audit/verify",
    "/api/v1/policy/rules",
    "/api/v1/policy/rbac",
    "/api/v1/policy/profiles",
    "/api/v1/inspect/config",
    "/api/v1/inspect/findings",
    "/api/v1/servers/nowhere/tools",
    "/api/v1/tls",
    "/api/v1/credentials",
    "/api/v1/clients/generic/snippet",
];

#[tokio::test]
async fn where_a_certificate_is_required_its_console_role_decides() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, _serving, server, agents) = requiring_certificates(dir.path()).await;
    let client = |leaf: &Leaf| mcpdef_testkit::https_client(&server, Some(leaf));
    let url = |path: &str| format!("https://{addr}{path}");
    let (alice, bot) = (client(&agents.client(OPS)), client(&agents.client(BOT)));

    let (status, _, session) = send(alice.get(url("/api/v1/session"))).await;
    assert_eq!(status, 200);
    assert_eq!(
        session,
        json!({
            "actor": format!("cert:{OPS}"),
            "role": "console:viewer",
            "roles": ["console:viewer"],
            "open": false,
        })
    );
    for path in READS {
        let (status, headers, body) = send(alice.get(url(path))).await;
        // Past the role: an unknown server is not found, and the rest answer.
        let expected = if path.contains("nowhere") { 404 } else { 200 };
        assert_eq!(status, expected, "{path}: {body}");
        assert_secured(&headers, path);
    }

    // The config and who callers are taken to be are an admin's to read.
    for path in ["/api/v1/config", "/api/v1/identity"] {
        let (status, headers, body) = send(alice.get(url(path))).await;
        assert_eq!(status, 403, "{path}: {body}");
        assert_problem(403, &headers, &body, path);
    }

    // The bot holds a role the MCP listener knows, and none the console does.
    let (status, _, session) = send(bot.get(url("/api/v1/session"))).await;
    assert_eq!(status, 200);
    assert_eq!(session["role"], Value::Null);
    assert_eq!(session["roles"], json!([]));
    for path in READS {
        let (status, headers, body) = send(bot.get(url(path))).await;
        assert_eq!(status, 403, "{path}: {body}");
        assert_problem(403, &headers, &body, path);
        assert_secured(&headers, path);
        assert_eq!(
            body["detail"],
            format!(
                "cert:{BOT} holds no console role: give it one of console:viewer, \
                 console:operator or console:admin"
            ),
        );
    }
    // A probe needs no role.
    let (status, _, body) = send(bot.get(url("/health"))).await;
    assert_eq!((status, body), (200, json!({ "status": "ok" })));
    // No certificate: refused at the handshake.
    let anonymous = mcpdef_testkit::https_client(&server, None);
    assert!(anonymous.get(url("/api/v1/session")).send().await.is_err());
}
