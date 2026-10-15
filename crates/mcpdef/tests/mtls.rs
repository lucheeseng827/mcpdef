// SPDX-License-Identifier: Apache-2.0
//! mTLS on the gateway's own listener (`[gateway.tls.client_auth]`), end to
//! end, against a PKI made when the test runs.
//!
//! - `required` refuses a client with no certificate, or one the agents' CA
//!   did not issue, at the handshake, before anything is governed.
//! - A SPIFFE ID maps to roles through `[[identity.cert_map]]`, the RBAC gate
//!   judges them, and the record names the certificate, and where it came
//!   from. One no entry maps holds no role.
//! - A certificate a CRL revokes is refused at the handshake, and one a CRL a
//!   reload brings in revokes is refused from the next request on a
//!   connection already open.
//! - `mcpdef tls issue` gives a workload a certificate from the local CA that
//!   the gateway takes, and `mcpdef tls revoke` puts it in the CRL a reload
//!   brings in.
//! - `optional` serves a client with no certificate, as no one.
//! - `[gateway.auth] methods` and `require`: a certificate alone, a token or
//!   a certificate, a token and a certificate.
//! - The admin listener, whose TLS is the MCP listener's unless it sets its
//!   own, checks client certificates as the MCP listener does.
//! - Behind a trusted proxy (`[gateway.trusted_proxy]`): a client
//!   certificate header from a peer the listener does not trust is not read,
//!   so a forged one names no one; from the proxy, the certificate it
//!   forwards, in XFCC or RFC 9440's `Client-Cert`, is checked as one
//!   presented at the handshake, and is the caller. The proxy's own is never
//!   its client's.
//! - The binary: `validate`, `tls show`, and `run --http` with a certificate
//!   alone as `[gateway.auth]`'s method, a refused certificate logged; and
//!   behind a trusted proxy.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mcpdef::connect::build_gateway;
use mcpdef::listener::{serve_https_on, serve_proxied_on, AuthState, HttpConfig};
use mcpdef::reload::{Outcome, Reloader, Snapshot, Trigger};
use mcpdef::tls::{ListenerTls, Serving};
use mcpdef::{serve_admin_on, AdminState, Config, Metrics};
use mcpdef_audit::{read_all, Record};
use mcpdef_auth::Verifier;
use mcpdef_core::wire::WireMode;
use mcpdef_testkit::{listening_port, Leaf, Pki};
use serde_json::{json, Value};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");
const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

// The RSA-2048 keypair `mcpdef-auth` trusts in its own tests: the private PEM
// to sign with, and the JWKS the verifier loads.
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

/// The two CAs a test needs: the one the listener's certificate is from,
/// which clients trust, and the agents' CA, which the listener trusts.
struct Pkis {
    server: Pki,
    agents: Pki,
}

impl Pkis {
    fn new() -> Pkis {
        Pkis {
            server: Pki::new("mcpdef test CA"),
            agents: Pki::new("agents CA"),
        }
    }

    /// A client that trusts the listener, presenting `identity` if given.
    fn client(&self, identity: Option<&Leaf>) -> reqwest::Client {
        mcpdef_testkit::https_client(&self.server, identity)
    }
}

/// A gateway over the stdio mock, on a loopback port, its listener on TLS
/// with `client_auth` as its `[gateway.tls.client_auth]`, and `rest` after
/// its `[[server]]`: roles, a cert map.
struct Gateway {
    url: String,
    dir: PathBuf,
    reloader: Reloader,
    _serving: Aborted,
}

/// The config of a gateway over the mock, its files under `dir`.
fn config_text(dir: &Path, client_auth: &str, rest: &str) -> String {
    format!(
        "[gateway]\naudit = {audit:?}\nstate_dir = {state:?}\n\n\
         [gateway.tls]\nmode = \"files\"\ncert = {cert:?}\nkey = {{ file = {key:?} }}\n\n\
         [gateway.tls.client_auth]\n{client_auth}\n\n\
         [[server]]\nid = \"mock\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\n\
         tools = [\"echo\", \"delete_repo\"]\n\n{rest}\n",
        audit = dir.join("audit.log"),
        state = dir.join("state"),
        cert = dir.join("listener.crt"),
        key = dir.join("listener.key"),
    )
}

/// `[gateway.tls.client_auth]` that `requires` a certificate or takes one
/// optionally, from the agents' CA in `dir`, read as a SPIFFE ID.
fn spiffe(dir: &Path, mode: &str) -> String {
    format!(
        "mode = {mode:?}\nca = [{ca:?}]\nidentity = \"spiffe\"\n\
         trust_domains = [\"prod.acme.internal\"]",
        ca = dir.join("agents-ca.pem"),
    )
}

/// `[[role]] ci` grants `echo` alone, and the CI service accounts hold it.
/// The bot may read the admin listener, which requires a console role of a
/// certificate it requires.
const CONSOLE_VIEWER: &str =
    "[[identity.cert_map]]\nidentity = \"spiffe://prod.acme.internal/ns/ci/sa/bot\"\n\
     roles = [\"console:viewer\"]\n";

const CI_ROLE: &str = "[[role]]\nname = \"ci\"\ngrants = [\"mock:echo\"]\n\n\
     [[identity.cert_map]]\nidentity = \"spiffe://prod.acme.internal/ns/ci/*\"\nroles = [\"ci\"]\n";

impl Gateway {
    /// Serve with `[gateway.auth]` off.
    async fn start(dir: &Path, pkis: &Pkis, client_auth: &str, rest: &str) -> Gateway {
        Self::start_with(dir, pkis, client_auth, rest, None).await
    }

    /// Serve, requiring of each request what `auth` says. The config says
    /// it too, as `rest`, for validation to see.
    async fn start_with(
        dir: &Path,
        pkis: &Pkis,
        client_auth: &str,
        rest: &str,
        auth: Option<AuthState>,
    ) -> Gateway {
        pkis.server.server(&["127.0.0.1"]).write(dir, "listener");
        pkis.agents.write_root(dir, "agents-ca");
        let path = dir.join("mcpdef.toml");
        std::fs::write(&path, config_text(dir, client_auth, rest)).unwrap();
        let (cfg, text) = Config::load_text(&path).unwrap();
        assert_eq!(cfg.validate(), Vec::<String>::new());
        let snapshot = Snapshot::take(text.as_bytes(), &cfg);
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
        let serving = tokio::spawn({
            let gw = gw.clone();
            async move {
                serve_https_on(tcp, gw, http, auth, slot).await.unwrap();
            }
        });
        let reloader =
            Reloader::new(&path, None, gw, cfg, snapshot).with_listener_tls(listener_tls);
        Gateway {
            url: format!("https://127.0.0.1:{}/mcp", addr.port()),
            dir: dir.to_path_buf(),
            reloader,
            _serving: Aborted(serving),
        }
    }

    /// The `tools/call` records in the ledger, in order.
    fn calls(&self) -> Vec<Record> {
        read_all(self.dir.join("audit.log"))
            .unwrap()
            .into_iter()
            .filter(|r| r.method.as_deref() == Some("tools/call"))
            .collect()
    }
}

/// A `tools/call` of `tool`, as `client` sends it, with a bearer `token` if
/// given: the status, and the body.
async fn call(
    client: &reqwest::Client,
    url: &str,
    tool: &str,
    token: Option<&str>,
) -> Result<(u16, String), reqwest::Error> {
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": tool, "arguments": {} },
    });
    let mut request = client
        .post(url)
        .header("content-type", "application/json")
        .body(body.to_string());
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let resp = request.send().await?;
    let status = resp.status().as_u16();
    Ok((status, resp.text().await?))
}

/// Whether a `200`'s body is a result the mock gave, not a denial.
fn allowed(body: &str) -> bool {
    let reply: Value = serde_json::from_str(body).unwrap();
    reply["result"]["isError"] == json!(false)
}

/// The text of a tool error, a denial.
fn denial(body: &str) -> String {
    let reply: Value = serde_json::from_str(body).unwrap();
    assert_eq!(reply["result"]["isError"], json!(true), "{reply}");
    reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_string()
}

/// A token for `sub`, signed with the key the verifier trusts.
fn token(sub: &str, roles: &[&str]) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".into());
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let claims = json!({ "sub": sub, "iss": ISSUER, "aud": RESOURCE, "exp": exp, "roles": roles });
    let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
    encode(&header, &claims, &key).unwrap()
}

/// `[gateway.auth]` as the config says it, with `methods` and `require`.
fn auth_table(methods: &str, require: &str) -> String {
    format!(
        "[gateway.auth]\nenabled = true\nissuer = {ISSUER:?}\nresource = {RESOURCE:?}\n\
         jwks = {jwks:?}\nmethods = {methods}\nrequire = {require:?}\n",
        jwks = TEST_JWKS,
    )
}

fn verifier() -> Verifier {
    Verifier::from_jwks_json(TEST_JWKS, ISSUER, RESOURCE).unwrap()
}

#[tokio::test]
async fn required_refuses_a_client_without_a_certificate_at_the_handshake() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    let s = Gateway::start(dir.path(), &pkis, &spiffe(dir.path(), "required"), CI_ROLE).await;

    // No certificate: the handshake is refused, and nothing is governed.
    let refused = call(&pkis.client(None), &s.url, "echo", None).await;
    assert!(refused.is_err(), "{refused:?}");
    // Nor one the agents' CA did not issue, a SPIFFE ID or not.
    let stranger = Pki::new("another CA").client(BOT);
    let refused = call(&pkis.client(Some(&stranger)), &s.url, "echo", None).await;
    assert!(refused.is_err(), "{refused:?}");
    // Nor one that is not for a TLS client.
    let server_only = pkis.agents.leaf().uri(BOT).server_auth().issue();
    let refused = call(&pkis.client(Some(&server_only)), &s.url, "echo", None).await;
    assert!(refused.is_err(), "{refused:?}");
    // Nor one that says it is a CA: an X509-SVID's leaf is not one.
    let ca_leaf = pkis.agents.leaf().uri(BOT).client_auth().ca().issue();
    let refused = call(&pkis.client(Some(&ca_leaf)), &s.url, "echo", None).await;
    assert!(refused.is_err(), "{refused:?}");
    // Nor one that has expired.
    let expired = pkis
        .agents
        .leaf()
        .uri(BOT)
        .client_auth()
        .valid((2000, 1, 1), (2001, 1, 1))
        .issue();
    let refused = call(&pkis.client(Some(&expired)), &s.url, "echo", None).await;
    assert!(refused.is_err(), "{refused:?}");
    assert!(s.calls().is_empty());

    // The agents' own certificate is served.
    let bot = pkis.agents.client(BOT);
    let (status, body) = call(&pkis.client(Some(&bot)), &s.url, "echo", None)
        .await
        .unwrap();
    assert_eq!(status, 200, "{body}");
    assert!(allowed(&body), "{body}");
}

#[tokio::test]
async fn a_spiffe_id_maps_to_its_roles_and_the_record_names_the_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    // A rule's `agents` names a certificate as the records do.
    let rest = format!(
        "{CI_ROLE}\n[[policy]]\nname = \"no-staging-bots\"\neffect = \"deny\"\n\
         agents = [\"cert:spiffe://prod.acme.internal/ns/ci/sa/staging-*\"]\n"
    );
    let s = Gateway::start(dir.path(), &pkis, &spiffe(dir.path(), "required"), &rest).await;
    let bot = pkis.client(Some(&pkis.agents.client(BOT)));

    // `ci` grants echo, and not delete_repo, which the allowlist lets by.
    let (status, body) = call(&bot, &s.url, "echo", None).await.unwrap();
    assert_eq!(status, 200);
    assert!(allowed(&body), "{body}");
    let (_, body) = call(&bot, &s.url, "delete_repo", None).await.unwrap();
    assert_eq!(
        denial(&body),
        "MCPdef denied: no role grants 'delete_repo' on 'mock'"
    );

    // A workload no entry maps holds no role, never a default one.
    let web = pkis
        .agents
        .client("spiffe://prod.acme.internal/ns/web/sa/app");
    let (_, body) = call(&pkis.client(Some(&web)), &s.url, "echo", None)
        .await
        .unwrap();
    assert_eq!(
        denial(&body),
        "MCPdef denied: no role grants 'echo' on 'mock'"
    );

    let staging = pkis
        .agents
        .client("spiffe://prod.acme.internal/ns/ci/sa/staging-runner");
    let (_, body) = call(&pkis.client(Some(&staging)), &s.url, "echo", None)
        .await
        .unwrap();
    assert!(denial(&body).contains("no-staging-bots"), "{body}");

    // Each record names the certificate, the rule that decided, and the
    // address the call came from.
    let calls = s.calls();
    let who: Vec<(&str, Option<&str>, &str, Option<&str>)> = calls
        .iter()
        .map(|r| {
            (
                r.agent.as_str(),
                r.actor.as_deref(),
                r.decision.as_str(),
                r.rule.as_deref(),
            )
        })
        .collect();
    let bot = format!("cert:{BOT}");
    assert_eq!(
        who,
        [
            (bot.as_str(), None, "allow", None),
            (bot.as_str(), None, "deny", Some("rbac")),
            (
                "cert:spiffe://prod.acme.internal/ns/web/sa/app",
                None,
                "deny",
                Some("rbac")
            ),
            (
                "cert:spiffe://prod.acme.internal/ns/ci/sa/staging-runner",
                None,
                "deny",
                Some("no-staging-bots")
            ),
        ]
    );
    for record in &calls {
        let peer: std::net::SocketAddr = record.peer.as_deref().unwrap().parse().unwrap();
        assert!(peer.ip().is_loopback(), "{peer}");
    }
}

#[tokio::test]
async fn a_certificate_that_gives_no_identity_is_refused_and_says_why() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    let s = Gateway::start(dir.path(), &pkis, &spiffe(dir.path(), "required"), CI_ROLE).await;
    let cases = [
        (
            pkis.agents
                .client("spiffe://staging.acme.internal/ns/ci/sa/bot"),
            "its SPIFFE ID is in trust domain \"staging.acme.internal\", which is not one of \
             trust_domains",
        ),
        (
            pkis.agents
                .leaf()
                .name("bot.acme.internal")
                .client_auth()
                .issue(),
            "it has 0 URI names, where an X509-SVID has exactly one, its SPIFFE ID",
        ),
        (
            pkis.agents
                .leaf()
                .uri(BOT)
                .uri("spiffe://prod.acme.internal/ns/ci/sa/other")
                .client_auth()
                .issue(),
            "it has 2 URI names, where an X509-SVID has exactly one, its SPIFFE ID",
        ),
        (
            pkis.agents.client("https://bot.acme.internal/"),
            "its URI name is not a SPIFFE ID: it does not start with spiffe://",
        ),
    ];
    for (leaf, why) in cases {
        let (status, body) = call(&pkis.client(Some(&leaf)), &s.url, "echo", None)
            .await
            .unwrap();
        assert_eq!(status, 403, "{body}");
        assert_eq!(
            body,
            format!("the client certificate names no identity MCPdef accepts: {why}")
        );
    }
    assert!(s.calls().is_empty());
}

#[tokio::test]
async fn a_revoked_certificate_is_refused_and_one_a_reload_revokes_from_its_next_request() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    let bot = pkis.agents.client(BOT);
    let revoked = pkis
        .agents
        .client("spiffe://prod.acme.internal/ns/ci/sa/stolen");
    let crl = pkis.agents.crl(&[&revoked]).write(dir.path(), "agents");
    let with_crl = format!("{}\ncrl = [{crl:?}]", spiffe(dir.path(), "required"));
    let mut s = Gateway::start(dir.path(), &pkis, &with_crl, CI_ROLE).await;

    // Revoked: refused at the handshake. Not revoked: served.
    let refused = call(&pkis.client(Some(&revoked)), &s.url, "echo", None).await;
    assert!(refused.is_err(), "{refused:?}");
    let kept = pkis.client(Some(&bot));
    let (status, body) = call(&kept, &s.url, "echo", None).await.unwrap();
    assert_eq!((status, allowed(&body)), (200, true), "{body}");
    // A reload checks the open connection's certificate again, and it
    // passes.
    let outcome = s.reloader.reload(Trigger::Signal).await;
    assert!(matches!(outcome, Outcome::Applied(_)), "{outcome:?}");
    let (status, body) = call(&kept, &s.url, "echo", None).await.unwrap();
    assert_eq!((status, allowed(&body)), (200, true), "{body}");

    // The bot's key leaks too: a new CRL revokes it, and a reload brings it
    // in. The connection the bot already has open is refused from its next
    // request, and a new one at its handshake.
    pkis.agents
        .crl(&[&revoked, &bot])
        .write(dir.path(), "agents");
    let outcome = s.reloader.reload(Trigger::Signal).await;
    assert!(matches!(outcome, Outcome::Applied(_)), "{outcome:?}");
    let (status, body) = call(&kept, &s.url, "echo", None).await.unwrap();
    assert_eq!(
        (status, body.as_str()),
        (
            403,
            "the client certificate is refused: invalid peer certificate: Revoked"
        )
    );
    let refused = call(&pkis.client(Some(&bot)), &s.url, "echo", None).await;
    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(s.calls().len(), 2);

    // A CRL file that does not read refuses the reload, and the one before it
    // stays in force.
    std::fs::write(&crl, "not a CRL").unwrap();
    match s.reloader.reload(Trigger::Signal).await {
        Outcome::Refused { rule, reasons } => {
            assert_eq!(rule, "invalid-config");
            assert!(
                reasons[0].starts_with("[gateway.tls.client_auth] crl "),
                "{reasons:?}"
            );
        }
        other => panic!("{other:?}"),
    }
    let other = pkis
        .agents
        .client("spiffe://prod.acme.internal/ns/ci/sa/other");
    let (status, _) = call(&pkis.client(Some(&other)), &s.url, "echo", None)
        .await
        .unwrap();
    assert_eq!(status, 200);
}

/// A client presenting the certificate and key in these files, as `mcpdef
/// tls issue` writes them, that trusts the listener.
fn presenting(pkis: &Pkis, cert: &Path, key: &Path) -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = reqwest::Certificate::from_der(pkis.server.root_der()).unwrap();
    let pem = [std::fs::read(cert).unwrap(), std::fs::read(key).unwrap()].concat();
    reqwest::Client::builder()
        .tls_certs_only([root])
        .no_proxy()
        .identity(reqwest::Identity::from_pem(&pem).unwrap())
        .build()
        .unwrap()
}

/// mTLS with no PKI of one's own: the local CA issues a workload its
/// certificate, the gateway takes it, and once it is revoked a reload
/// refuses it, on the connection the workload has open and at the handshake
/// of a new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_local_ca_issues_a_client_certificate_and_revokes_it() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    let ca_dir = dir.path().join("state/tls");
    let client_auth = format!(
        "mode = \"required\"\nca = [{ca:?}]\ncrl = [{crl:?}]\nidentity = \"spiffe\"\n\
         trust_domains = [\"prod.acme.internal\"]",
        ca = ca_dir.join("ca.crt"),
        crl = ca_dir.join("ca.crl"),
    );
    // The config `tls issue` reads its state_dir from, and the gateway runs.
    let path = dir.path().join("mcpdef.toml");
    std::fs::write(&path, config_text(dir.path(), &client_auth, CI_ROLE)).unwrap();
    let config = path.to_str().unwrap();
    let out = dir.path().join("agent");
    let (issued, ok) = mcpdef(&[
        "tls",
        "issue",
        "--client",
        "ci-bot",
        "--spiffe-id",
        BOT,
        "--out",
        out.to_str().unwrap(),
        "--config",
        config,
    ]);
    assert!(ok, "{issued}");
    assert!(issued.contains("takes it"), "{issued}");
    let serial = issued
        .lines()
        .find_map(|line| line.strip_prefix("serial       : "))
        .unwrap()
        .to_string();

    let mut s = Gateway::start(dir.path(), &pkis, &client_auth, CI_ROLE).await;
    let (cert, key) = (out.join("ci-bot.crt"), out.join("ci-bot.key"));
    let bot = presenting(&pkis, &cert, &key);
    let (status, body) = call(&bot, &s.url, "echo", None).await.unwrap();
    assert_eq!((status, allowed(&body)), (200, true), "{body}");
    // The record names the workload by the SPIFFE ID its certificate holds.
    assert_eq!(s.calls()[0].agent, format!("cert:{BOT}"));

    let (revoked, ok) = mcpdef(&["tls", "revoke", &serial, "--config", config]);
    assert!(ok, "{revoked}");
    let outcome = s.reloader.reload(Trigger::Signal).await;
    assert!(matches!(outcome, Outcome::Applied(_)), "{outcome:?}");
    let (status, body) = call(&bot, &s.url, "echo", None).await.unwrap();
    assert_eq!(
        (status, body.as_str()),
        (
            403,
            "the client certificate is refused: invalid peer certificate: Revoked"
        )
    );
    let refused = call(&presenting(&pkis, &cert, &key), &s.url, "echo", None).await;
    assert!(refused.is_err(), "{refused:?}");
}

#[tokio::test]
async fn optional_serves_a_client_without_a_certificate_as_no_one() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    let s = Gateway::start(dir.path(), &pkis, &spiffe(dir.path(), "optional"), CI_ROLE).await;

    // No certificate: served, as no credential names it, with no RBAC gate.
    let (status, body) = call(&pkis.client(None), &s.url, "delete_repo", None)
        .await
        .unwrap();
    assert_eq!((status, allowed(&body)), (200, true), "{body}");
    // A certificate presented is still checked at the handshake...
    let stranger = Pki::new("another CA").client(BOT);
    assert!(call(&pkis.client(Some(&stranger)), &s.url, "echo", None)
        .await
        .is_err());
    // ...and still the caller's identity, with the roles it maps to.
    let bot = pkis.client(Some(&pkis.agents.client(BOT)));
    let (_, body) = call(&bot, &s.url, "delete_repo", None).await.unwrap();
    assert_eq!(
        denial(&body),
        "MCPdef denied: no role grants 'delete_repo' on 'mock'"
    );
    let agents: Vec<String> = s.calls().into_iter().map(|r| r.agent).collect();
    assert_eq!(agents[1], format!("cert:{BOT}"));
    assert!(!agents[0].starts_with("cert:"), "{agents:?}");
}

#[tokio::test]
async fn a_reload_that_requires_a_certificate_refuses_a_connection_made_without_one() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    let mut s = Gateway::start(dir.path(), &pkis, &spiffe(dir.path(), "optional"), CI_ROLE).await;
    let kept = pkis.client(None);
    let (status, _) = call(&kept, &s.url, "echo", None).await.unwrap();
    assert_eq!(status, 200);
    std::fs::write(
        s.dir.join("mcpdef.toml"),
        config_text(&s.dir, &spiffe(&s.dir, "required"), CI_ROLE),
    )
    .unwrap();
    let outcome = s.reloader.reload(Trigger::Signal).await;
    assert!(matches!(outcome, Outcome::Applied(_)), "{outcome:?}");
    // The connection made without one is refused from its next request, and
    // a new one at its handshake.
    let (status, body) = call(&kept, &s.url, "echo", None).await.unwrap();
    assert_eq!(
        (status, body.as_str()),
        (403, "a client certificate is required")
    );
    assert!(call(&pkis.client(None), &s.url, "echo", None)
        .await
        .is_err());
}

#[tokio::test]
async fn a_certificate_alone_is_what_methods_mtls_requires() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    let rest = format!("{CI_ROLE}\n[gateway.auth]\nenabled = true\nmethods = [\"mtls\"]\n");
    let s = Gateway::start_with(
        dir.path(),
        &pkis,
        &spiffe(dir.path(), "optional"),
        &rest,
        Some(AuthState::certificate()),
    )
    .await;
    // The listener takes a client without one; auth does not.
    let (status, body) = call(&pkis.client(None), &s.url, "echo", None)
        .await
        .unwrap();
    assert_eq!(
        (status, body.as_str()),
        (403, "a client certificate is required")
    );
    // A token is not one of the methods: it changes nothing.
    let (status, _) = call(
        &pkis.client(None),
        &s.url,
        "echo",
        Some(&token("alice", &["ci"])),
    )
    .await
    .unwrap();
    assert_eq!(status, 403);
    let bot = pkis.client(Some(&pkis.agents.client(BOT)));
    let (status, body) = call(&bot, &s.url, "echo", None).await.unwrap();
    assert_eq!((status, allowed(&body)), (200, true), "{body}");
}

#[tokio::test]
async fn with_require_any_a_token_or_a_certificate_names_the_caller() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    let rest = format!("{CI_ROLE}\n{}", auth_table("[\"bearer\", \"mtls\"]", "any"));
    let auth = AuthState::new(verifier()).or_certificate(false);
    let s = Gateway::start_with(
        dir.path(),
        &pkis,
        &spiffe(dir.path(), "optional"),
        &rest,
        Some(auth),
    )
    .await;
    let anonymous = pkis.client(None);
    let bot = pkis.client(Some(&pkis.agents.client(BOT)));

    // Neither: the challenge that says where to get a token.
    let resp = anonymous
        .post(&s.url)
        .header("content-type", "application/json")
        .body(json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(resp.headers().contains_key("www-authenticate"));
    // A token alone, a certificate alone, or both.
    let alice = token("alice", &["ci"]);
    let (status, body) = call(&anonymous, &s.url, "echo", Some(&alice))
        .await
        .unwrap();
    assert_eq!((status, allowed(&body)), (200, true), "{body}");
    let (status, body) = call(&bot, &s.url, "echo", None).await.unwrap();
    assert_eq!((status, allowed(&body)), (200, true), "{body}");
    let (status, body) = call(&bot, &s.url, "echo", Some(&alice)).await.unwrap();
    assert_eq!((status, allowed(&body)), (200, true), "{body}");
    // A token that does not check out is refused, a certificate or not.
    let forged = format!("{alice}x");
    let (status, _) = call(&bot, &s.url, "echo", Some(&forged)).await.unwrap();
    assert_eq!(status, 401);

    let who: Vec<(String, Option<String>)> =
        s.calls().into_iter().map(|r| (r.agent, r.actor)).collect();
    assert_eq!(
        who,
        [
            ("sub:alice".to_string(), None),
            (format!("cert:{BOT}"), None),
            ("sub:alice".to_string(), Some(format!("cert:{BOT}"))),
        ]
    );
}

#[tokio::test]
async fn with_require_all_the_token_is_the_subject_and_the_certificate_the_actor() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    let rest = format!("{CI_ROLE}\n{}", auth_table("[\"bearer\", \"mtls\"]", "all"));
    let auth = AuthState::new(verifier()).or_certificate(true);
    let s = Gateway::start_with(
        dir.path(),
        &pkis,
        &spiffe(dir.path(), "optional"),
        &rest,
        Some(auth),
    )
    .await;
    let anonymous = pkis.client(None);
    let bot = pkis.client(Some(&pkis.agents.client(BOT)));
    // The token's roles are what RBAC judges: `reader` grants nothing here.
    let alice = token("alice", &["reader"]);

    // A token without a certificate, and a certificate without a token.
    let (status, body) = call(&anonymous, &s.url, "echo", Some(&alice))
        .await
        .unwrap();
    assert_eq!(
        (status, body.as_str()),
        (403, "a client certificate is required")
    );
    let (status, _) = call(&bot, &s.url, "echo", None).await.unwrap();
    assert_eq!(status, 401);
    // Both: the token's subject, its roles judged, the certificate behind it.
    let (_, body) = call(&bot, &s.url, "echo", Some(&alice)).await.unwrap();
    assert_eq!(
        denial(&body),
        "MCPdef denied: no role grants 'echo' on 'mock'"
    );
    let (_, body) = call(&bot, &s.url, "echo", Some(&token("alice", &["ci"])))
        .await
        .unwrap();
    assert!(allowed(&body), "{body}");
    let calls = s.calls();
    assert_eq!(calls.len(), 2);
    for record in calls {
        assert_eq!(record.agent, "sub:alice");
        assert_eq!(record.actor, Some(format!("cert:{BOT}")));
    }
}

#[tokio::test]
async fn the_admin_listener_checks_the_client_certificates_its_tls_inherits() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    pkis.server
        .server(&["127.0.0.1"])
        .write(dir.path(), "listener");
    pkis.agents.write_root(dir.path(), "agents-ca");
    let crl = pkis.agents.crl(&[]).write(dir.path(), "agents");
    let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap().to_string();
    // No [gateway.admin.tls]: the admin listener serves [gateway.tls], and
    // asks for the certificates it asks for.
    let client_auth = format!("{}\ncrl = [{crl:?}]", spiffe(dir.path(), "required"));
    // The admin listener requires a certificate, so a caller needs a console
    // role: the bot's reads.
    let admin = format!("[gateway.admin]\nenabled = true\nlisten = {listen:?}\n\n{CONSOLE_VIEWER}");
    let path = dir.path().join("mcpdef.toml");
    std::fs::write(&path, config_text(dir.path(), &client_auth, &admin)).unwrap();
    let (cfg, text) = Config::load_text(&path).unwrap();
    assert_eq!(cfg.validate(), Vec::<String>::new());
    let serving = Serving {
        mcp: false,
        admin: true,
    };
    let (listener_tls, _) = ListenerTls::start(&cfg, serving).unwrap().unwrap();
    let gw = build_gateway(&cfg).await.unwrap();
    let state = Arc::new(AdminState::new(
        &cfg,
        Arc::new(Metrics::new(cfg.servers.len() as u64)),
        gw.clone(),
        "test",
    ));
    let slot = listener_tls.admin();
    let _serving = Aborted(tokio::spawn(async move {
        serve_admin_on(state, bound, slot).await.unwrap();
    }));
    let snapshot = Snapshot::take(text.as_bytes(), &cfg);
    let mut reloader =
        Reloader::new(&path, None, gw, cfg, snapshot).with_listener_tls(listener_tls);
    let url = format!("https://{listen}/api/v1/status");

    // The agents' certificate is served, once the listener is up.
    let bot = pkis.agents.client(BOT);
    let kept = pkis.client(Some(&bot));
    let until = Instant::now() + Duration::from_secs(5);
    let status = loop {
        match kept.get(&url).send().await {
            Ok(response) => break response.status(),
            Err(e) if Instant::now() > until => panic!("{e}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };
    assert_eq!(status, 200);
    // No certificate: refused at the handshake.
    assert!(pkis.client(None).get(&url).send().await.is_err());
    // Revoked, and a reload brings the CRL in: the open connection is
    // refused from its next request.
    pkis.agents.crl(&[&bot]).write(dir.path(), "agents");
    let outcome = reloader.reload(Trigger::Signal).await;
    assert!(matches!(outcome, Outcome::Applied(_)), "{outcome:?}");
    let refused = kept.get(&url).send().await.unwrap();
    assert_eq!(refused.status(), 403);
    // The admin listener refuses with a problem document, saying what the
    // MCP listener says.
    let problem: serde_json::Value = serde_json::from_str(&refused.text().await.unwrap()).unwrap();
    assert_eq!(
        problem["detail"],
        "the client certificate is refused: invalid peer certificate: Revoked"
    );
}

#[tokio::test]
async fn the_admin_listener_reads_no_forwarded_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    pkis.server
        .server(&["127.0.0.1"])
        .write(dir.path(), "listener");
    pkis.agents.write_root(dir.path(), "agents-ca");
    let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap().to_string();
    // The MCP listener trusts a proxy on this machine; the admin listener,
    // which serves [gateway.tls] and asks what it asks, reads no header.
    let rest = format!(
        "[gateway.admin]\nenabled = true\nlisten = {listen:?}\n\n\
         [gateway.trusted_proxy]\ncidrs = [\"127.0.0.0/8\"]\n\
         client_cert_header = \"x-forwarded-client-cert\"\n\n{CONSOLE_VIEWER}"
    );
    let path = dir.path().join("mcpdef.toml");
    std::fs::write(
        &path,
        config_text(dir.path(), &spiffe(dir.path(), "required"), &rest),
    )
    .unwrap();
    let (cfg, _) = Config::load_text(&path).unwrap();
    assert_eq!(cfg.validate(), Vec::<String>::new());
    let serving = Serving {
        mcp: false,
        admin: true,
    };
    let (listener_tls, _) = ListenerTls::start(&cfg, serving).unwrap().unwrap();
    let gw = build_gateway(&cfg).await.unwrap();
    let state = Arc::new(AdminState::new(
        &cfg,
        Arc::new(Metrics::new(cfg.servers.len() as u64)),
        gw,
        "test",
    ));
    let slot = listener_tls.admin();
    let _serving = Aborted(tokio::spawn(async move {
        serve_admin_on(state, bound, slot).await.unwrap();
    }));
    let url = format!("https://{listen}/api/v1/status");
    let bot = pkis.client(Some(&pkis.agents.client(BOT)));
    // The certificate presented at the handshake is the client's, with no
    // header, and with one naming a certificate no CA here issued.
    let stranger = Pki::new("another CA").client(BOT);
    for forwarded in [vec![], xfcc(&stranger, false)] {
        let until = Instant::now() + Duration::from_secs(5);
        let status = loop {
            let mut request = bot.get(&url);
            for (name, value) in &forwarded {
                request = request.header(*name, value);
            }
            match request.send().await {
                Ok(response) => break response.status(),
                Err(e) if Instant::now() > until => panic!("{e}"),
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        };
        assert_eq!(status, 200, "{forwarded:?}");
    }
}

/// The config of a gateway over the mock behind a proxy MCPdef trusts, with
/// no TLS of its own: `client_auth` checks and reads the certificates the
/// proxy forwards, `proxy` is its `[gateway.trusted_proxy]`, and `rest` comes
/// after its `[[server]]`.
fn proxied_config_text(dir: &Path, client_auth: &str, proxy: &str, rest: &str) -> String {
    format!(
        "[gateway]\naudit = {audit:?}\nstate_dir = {state:?}\n\n\
         [gateway.tls.client_auth]\n{client_auth}\n\n\
         [gateway.trusted_proxy]\n{proxy}\n\n\
         [[server]]\nid = \"mock\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\n\
         tools = [\"echo\", \"delete_repo\"]\n\n{rest}\n",
        audit = dir.join("audit.log"),
        state = dir.join("state"),
    )
}

/// `[gateway.trusted_proxy]` for a proxy at `cidrs` that forwards each
/// client's certificate in `header`.
fn trusting(cidrs: &str, header: &str) -> String {
    format!("cidrs = [{cidrs:?}]\nclient_cert_header = {header:?}")
}

impl Gateway {
    /// Serve plain HTTP behind the proxy `proxy` says, `[gateway.auth]` off.
    async fn behind(
        dir: &Path,
        pkis: &Pkis,
        client_auth: &str,
        proxy: &str,
        rest: &str,
    ) -> Gateway {
        pkis.agents.write_root(dir, "agents-ca");
        let path = dir.join("mcpdef.toml");
        std::fs::write(&path, proxied_config_text(dir, client_auth, proxy, rest)).unwrap();
        let (cfg, text) = Config::load_text(&path).unwrap();
        assert_eq!(cfg.validate(), Vec::<String>::new());
        let snapshot = Snapshot::take(text.as_bytes(), &cfg);
        // The listener has a slot, though it serves no TLS: what the proxy
        // forwards is checked as it says.
        let serving = Serving::of(&cfg, true);
        assert_eq!(
            serving,
            Serving {
                mcp: true,
                admin: false
            }
        );
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
        let serving = tokio::spawn({
            let gw = gw.clone();
            async move {
                serve_proxied_on(tcp, gw, http, None, slot).await.unwrap();
            }
        });
        let reloader =
            Reloader::new(&path, None, gw, cfg, snapshot).with_listener_tls(listener_tls);
        Gateway {
            url: format!("http://127.0.0.1:{}/mcp", addr.port()),
            dir: dir.to_path_buf(),
            reloader,
            _serving: Aborted(serving),
        }
    }
}

/// A plain HTTP client, as the proxy in front of the listener is: no ambient
/// proxy in its way, and rustls' crypto provider installed first, which
/// reqwest cannot build a client without.
fn plain_client() -> reqwest::Client {
    mcpdef_transport::install_crypto_provider();
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// A `tools/call` of `tool`, as `client` sends it with the headers
/// `forwarded`, as a proxy forwards it: the status, and the body.
async fn forward(
    client: &reqwest::Client,
    url: &str,
    tool: &str,
    forwarded: &[(&'static str, String)],
) -> Result<(u16, String), reqwest::Error> {
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": tool, "arguments": {} },
    });
    let mut request = client
        .post(url)
        .header("content-type", "application/json")
        .body(body.to_string());
    for (name, value) in forwarded {
        request = request.header(*name, value);
    }
    let resp = request.send().await?;
    let status = resp.status().as_u16();
    Ok((status, resp.text().await?))
}

/// `text`, URL-encoded, as Envoy writes a PEM in XFCC.
fn url_encoded(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            b => format!("%{b:02X}"),
        })
        .collect()
}

/// The XFCC Envoy's SANITIZE_SET writes for a client that presented `leaf`:
/// its `Cert`, and its `Chain` if `chain`, beside names MCPdef does not read.
fn xfcc(leaf: &Leaf, chain: bool) -> Vec<(&'static str, String)> {
    let mut element = format!(
        "By=spiffe://cluster.local/ns/mcp/sa/envoy;Hash=00ff;Cert={}",
        url_encoded(leaf.cert_pem())
    );
    if chain {
        element.push_str(&format!(";Chain={}", url_encoded(&leaf.chain_pem())));
    }
    element.push_str(";Subject=\"CN=x, O=y\";URI=spiffe://prod.acme.internal/ns/ops/sa/root");
    vec![("x-forwarded-client-cert", element)]
}

/// RFC 9440's headers for a client that presented `leaf`: `Client-Cert`, and
/// `Client-Cert-Chain` if it came with intermediates.
fn client_cert(leaf: &Leaf) -> Vec<(&'static str, String)> {
    let sf = |der: &[u8]| format!(":{}:", STANDARD.encode(der));
    let mut headers = vec![("client-cert", sf(leaf.cert_der()))];
    let chain: Vec<String> = leaf.chain()[1..].iter().map(|der| sf(der)).collect();
    if !chain.is_empty() {
        headers.push(("client-cert-chain", chain.join(", ")));
    }
    headers
}

#[tokio::test]
async fn a_forged_client_certificate_header_from_a_peer_not_trusted_is_ignored() {
    // The listener trusts a proxy at 10.0.0.0/8, and the test's client, at
    // 127.0.0.1, is not it.
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    let bot = pkis.agents.client(BOT);
    let s = Gateway::behind(
        dir.path(),
        &pkis,
        &spiffe(dir.path(), "required"),
        &trusting("10.0.0.0/8", "x-forwarded-client-cert"),
        CI_ROLE,
    )
    .await;
    // The bot's certificate is no secret: a forged header carries it whole,
    // and it would check out. Neither header is read.
    let plain = plain_client();
    for forged in [xfcc(&bot, false), client_cert(&bot)] {
        let (status, body) = forward(&plain, &s.url, "echo", &forged).await.unwrap();
        assert_eq!(
            (status, body.as_str()),
            (403, "a client certificate is required")
        );
    }
    assert!(s.calls().is_empty());

    // On TLS, a forged header never names anyone else than the certificate
    // presented at the handshake, or no one.
    let dir = tempfile::tempdir().unwrap();
    let rest = format!(
        "{CI_ROLE}\n[gateway.trusted_proxy]\ncidrs = [\"10.0.0.0/8\"]\n\
         client_cert_header = \"x-forwarded-client-cert\"\n"
    );
    let s = Gateway::start(dir.path(), &pkis, &spiffe(dir.path(), "optional"), &rest).await;
    let web = pkis
        .agents
        .client("spiffe://prod.acme.internal/ns/web/sa/app");
    let (_, body) = forward(&pkis.client(Some(&web)), &s.url, "echo", &xfcc(&bot, false))
        .await
        .unwrap();
    assert_eq!(
        denial(&body),
        "MCPdef denied: no role grants 'echo' on 'mock'"
    );
    let (status, _) = forward(&pkis.client(None), &s.url, "echo", &xfcc(&bot, false))
        .await
        .unwrap();
    assert_eq!(status, 200);
    let agents: Vec<String> = s.calls().into_iter().map(|r| r.agent).collect();
    assert_eq!(agents[0], "cert:spiffe://prod.acme.internal/ns/web/sa/app");
    assert!(!agents[1].starts_with("cert:"), "{agents:?}");
}

#[tokio::test]
async fn a_trusted_proxy_forwards_the_client_certificate_in_xfcc() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    let s = Gateway::behind(
        dir.path(),
        &pkis,
        &spiffe(dir.path(), "required"),
        &trusting("127.0.0.0/8", "x-forwarded-client-cert"),
        CI_ROLE,
    )
    .await;
    let proxy = plain_client();
    let bot = pkis.agents.client(BOT);

    // The bot, as the proxy forwards it: its roles, and only its roles. The
    // names in XFCC beside its certificate are not read.
    let (status, body) = forward(&proxy, &s.url, "echo", &xfcc(&bot, false))
        .await
        .unwrap();
    assert_eq!((status, allowed(&body)), (200, true), "{body}");
    let (_, body) = forward(&proxy, &s.url, "delete_repo", &xfcc(&bot, true))
        .await
        .unwrap();
    assert_eq!(
        denial(&body),
        "MCPdef denied: no role grants 'delete_repo' on 'mock'"
    );

    // A certificate from an intermediate CA: checked through the chain the
    // proxy forwards with it, and refused without it.
    let issuing = pkis.agents.intermediate("agents issuing CA");
    let runner = issuing.client("spiffe://prod.acme.internal/ns/ci/sa/runner");
    let (status, body) = forward(&proxy, &s.url, "echo", &xfcc(&runner, true))
        .await
        .unwrap();
    assert_eq!((status, allowed(&body)), (200, true), "{body}");
    let (status, body) = forward(&proxy, &s.url, "echo", &xfcc(&runner, false))
        .await
        .unwrap();
    assert_eq!(
        (status, body.as_str()),
        (
            403,
            "the client certificate is refused: invalid peer certificate: UnknownIssuer"
        )
    );

    // A request the proxy forwards no certificate with.
    let (status, body) = forward(&proxy, &s.url, "echo", &[]).await.unwrap();
    assert_eq!(
        (status, body.as_str()),
        (403, "a client certificate is required")
    );

    // Each record names the certificate, and the address the call came
    // from: the proxy's.
    let calls = s.calls();
    let agents: Vec<&str> = calls.iter().map(|r| r.agent.as_str()).collect();
    assert_eq!(
        agents,
        [
            format!("cert:{BOT}").as_str(),
            &format!("cert:{BOT}"),
            "cert:spiffe://prod.acme.internal/ns/ci/sa/runner",
        ]
    );
    for record in &calls {
        let peer: std::net::SocketAddr = record.peer.as_deref().unwrap().parse().unwrap();
        assert!(peer.ip().is_loopback(), "{peer}");
    }
}

#[tokio::test]
async fn a_trusted_proxy_forwards_the_client_certificate_in_rfc_9440_client_cert() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    let s = Gateway::behind(
        dir.path(),
        &pkis,
        &spiffe(dir.path(), "required"),
        &trusting("127.0.0.1", "client-cert"),
        CI_ROLE,
    )
    .await;
    let proxy = plain_client();
    let (status, body) = forward(
        &proxy,
        &s.url,
        "echo",
        &client_cert(&pkis.agents.client(BOT)),
    )
    .await
    .unwrap();
    assert_eq!((status, allowed(&body)), (200, true), "{body}");
    let issuing = pkis.agents.intermediate("agents issuing CA");
    let runner = issuing.client("spiffe://prod.acme.internal/ns/ci/sa/runner");
    let headers = client_cert(&runner);
    assert_eq!(headers.len(), 2);
    let (status, body) = forward(&proxy, &s.url, "echo", &headers).await.unwrap();
    assert_eq!((status, allowed(&body)), (200, true), "{body}");
    // The other header is not this proxy's.
    let (status, _) = forward(&proxy, &s.url, "echo", &xfcc(&runner, true))
        .await
        .unwrap();
    assert_eq!(status, 403);
    let agents: Vec<String> = s.calls().into_iter().map(|r| r.agent).collect();
    assert_eq!(
        agents,
        [
            format!("cert:{BOT}"),
            "cert:spiffe://prod.acme.internal/ns/ci/sa/runner".to_string()
        ]
    );
}

#[tokio::test]
async fn a_forwarded_certificate_is_checked_as_one_presented_at_the_handshake() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    let bot = pkis.agents.client(BOT);
    let stolen = pkis
        .agents
        .client("spiffe://prod.acme.internal/ns/ci/sa/stolen");
    let crl = pkis.agents.crl(&[&stolen]).write(dir.path(), "agents");
    let with_crl = format!("{}\ncrl = [{crl:?}]", spiffe(dir.path(), "required"));
    let mut s = Gateway::behind(
        dir.path(),
        &pkis,
        &with_crl,
        &trusting("127.0.0.0/8", "x-forwarded-client-cert"),
        CI_ROLE,
    )
    .await;
    let proxy = plain_client();
    let refused = |why: &str| (403, format!("the client certificate is refused: {why}"));
    let stranger = Pki::new("another CA").client(BOT);
    let server_only = pkis.agents.leaf().uri(BOT).server_auth().issue();
    let a_ca = pkis.agents.leaf().uri(BOT).client_auth().ca().issue();
    let expired = pkis
        .agents
        .leaf()
        .uri(BOT)
        .client_auth()
        .valid((2020, 1, 1), (2021, 1, 1))
        .issue();
    for (leaf, want) in [
        (
            &stranger,
            refused("invalid peer certificate: UnknownIssuer"),
        ),
        (&stolen, refused("invalid peer certificate: Revoked")),
        (&expired, refused("it has expired")),
    ] {
        let (status, body) = forward(&proxy, &s.url, "echo", &xfcc(leaf, false))
            .await
            .unwrap();
        assert_eq!((status, body), want);
    }
    // For a server alone, or a CA: refused, as the handshake refuses them.
    for leaf in [&server_only, &a_ca] {
        let (status, body) = forward(&proxy, &s.url, "echo", &xfcc(leaf, false))
            .await
            .unwrap();
        assert_eq!(status, 403, "{body}");
        assert!(
            body.starts_with("the client certificate is refused: invalid peer certificate"),
            "{body}"
        );
    }
    // One that gives no identity, saying why.
    let two_ids = pkis
        .agents
        .leaf()
        .uri(BOT)
        .uri("spiffe://prod.acme.internal/ns/ci/sa/other")
        .client_auth()
        .issue();
    let (status, body) = forward(&proxy, &s.url, "echo", &xfcc(&two_ids, false))
        .await
        .unwrap();
    assert_eq!(
        (status, body.as_str()),
        (
            403,
            "the client certificate names no identity MCPdef accepts: it has 2 URI names, \
             where an X509-SVID has exactly one, its SPIFFE ID"
        )
    );

    // A CRL a reload brings in revokes the bot from its next request.
    let (status, _) = forward(&proxy, &s.url, "echo", &xfcc(&bot, false))
        .await
        .unwrap();
    assert_eq!(status, 200);
    pkis.agents
        .crl(&[&stolen, &bot])
        .write(dir.path(), "agents");
    let outcome = s.reloader.reload(Trigger::Signal).await;
    assert!(matches!(outcome, Outcome::Applied(_)), "{outcome:?}");
    let (status, body) = forward(&proxy, &s.url, "echo", &xfcc(&bot, false))
        .await
        .unwrap();
    assert_eq!((status, body), refused("invalid peer certificate: Revoked"));
    assert_eq!(s.calls().len(), 1);
}

#[tokio::test]
async fn what_a_trusted_proxy_forwards_is_refused_unless_it_reads_whole() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    // `optional`: a header that does not read is refused, never taken for
    // no certificate.
    let s = Gateway::behind(
        dir.path(),
        &pkis,
        &spiffe(dir.path(), "optional"),
        &trusting("127.0.0.0/8", "x-forwarded-client-cert"),
        CI_ROLE,
    )
    .await;
    let proxy = plain_client();
    let bot = pkis.agents.client(BOT);
    let element = &xfcc(&bot, false)[0].1;
    let does_not_read = "the client certificate the proxy forwarded does not read: ";
    // Two elements: a proxy that appended to what its client sent.
    let appended = format!("{element},{element}");
    // Istio's default, which names the client and forwards no certificate.
    let names_only = format!("By=spiffe://cluster.local/ns/mcp/sa/envoy;URI={BOT}");
    for (value, why) in [
        (appended.as_str(), "x-forwarded-client-cert has 2 elements"),
        (
            names_only.as_str(),
            "x-forwarded-client-cert carries no Cert",
        ),
        (
            "Cert=\"unterminated",
            "x-forwarded-client-cert has a quoted value",
        ),
    ] {
        let (status, body) = forward(
            &proxy,
            &s.url,
            "echo",
            &[("x-forwarded-client-cert", value.to_string())],
        )
        .await
        .unwrap();
        assert_eq!(status, 403, "{body}");
        assert!(body.starts_with(&format!("{does_not_read}{why}")), "{body}");
    }
    // None forwarded: served as no one.
    let (status, body) = forward(&proxy, &s.url, "echo", &[]).await.unwrap();
    assert_eq!((status, allowed(&body)), (200, true), "{body}");
    let agents: Vec<String> = s.calls().into_iter().map(|r| r.agent).collect();
    assert_eq!(agents.len(), 1);
    assert!(!agents[0].starts_with("cert:"), "{agents:?}");
}

#[tokio::test]
async fn a_proxys_own_certificate_is_never_taken_for_its_clients() {
    // The proxy reaches the listener over TLS, presenting a certificate of
    // its own, from the agents' CA, and mapped to every tool.
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    let rest = format!(
        "{CI_ROLE}\n[[role]]\nname = \"mesh\"\ngrants = [\"*\"]\n\n\
         [[identity.cert_map]]\nidentity = \"spiffe://prod.acme.internal/ns/mesh/*\"\n\
         roles = [\"mesh\"]\n\n\
         [gateway.trusted_proxy]\ncidrs = [\"127.0.0.0/8\"]\n\
         client_cert_header = \"x-forwarded-client-cert\"\n\n\
         [gateway.auth]\nenabled = true\nmethods = [\"mtls\"]\n"
    );
    let s = Gateway::start_with(
        dir.path(),
        &pkis,
        &spiffe(dir.path(), "optional"),
        &rest,
        Some(AuthState::certificate()),
    )
    .await;
    let envoy = pkis
        .agents
        .client("spiffe://prod.acme.internal/ns/mesh/sa/envoy");
    let proxy = pkis.client(Some(&envoy));
    // It forwards no client's: no one, so `methods = ["mtls"]` refuses it.
    let (status, body) = forward(&proxy, &s.url, "delete_repo", &[]).await.unwrap();
    assert_eq!(
        (status, body.as_str()),
        (403, "a client certificate is required")
    );
    // It forwards the bot's: the bot, with the bot's roles.
    let (_, body) = forward(
        &proxy,
        &s.url,
        "delete_repo",
        &xfcc(&pkis.agents.client(BOT), false),
    )
    .await
    .unwrap();
    assert_eq!(
        denial(&body),
        "MCPdef denied: no role grants 'delete_repo' on 'mock'"
    );
    let agents: Vec<String> = s.calls().into_iter().map(|r| r.agent).collect();
    assert_eq!(agents, [format!("cert:{BOT}")]);
}

#[tokio::test]
async fn a_reload_changes_which_addresses_are_the_proxys() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    let client_auth = spiffe(dir.path(), "required");
    let mut s = Gateway::behind(
        dir.path(),
        &pkis,
        &client_auth,
        &trusting("10.0.0.0/8", "x-forwarded-client-cert"),
        CI_ROLE,
    )
    .await;
    let proxy = plain_client();
    let bot = pkis.agents.client(BOT);
    let (status, _) = forward(&proxy, &s.url, "echo", &xfcc(&bot, false))
        .await
        .unwrap();
    assert_eq!(status, 403);
    let moved = trusting("127.0.0.0/8", "x-forwarded-client-cert");
    std::fs::write(
        s.dir.join("mcpdef.toml"),
        proxied_config_text(&s.dir, &client_auth, &moved, CI_ROLE),
    )
    .unwrap();
    let outcome = s.reloader.reload(Trigger::Signal).await;
    assert!(matches!(outcome, Outcome::Applied(_)), "{outcome:?}");
    let (status, body) = forward(&proxy, &s.url, "echo", &xfcc(&bot, false))
        .await
        .unwrap();
    assert_eq!((status, allowed(&body)), (200, true), "{body}");
    // And which header is the proxy's.
    let rfc_9440 = trusting("127.0.0.0/8", "client-cert");
    std::fs::write(
        s.dir.join("mcpdef.toml"),
        proxied_config_text(&s.dir, &client_auth, &rfc_9440, CI_ROLE),
    )
    .unwrap();
    let outcome = s.reloader.reload(Trigger::Signal).await;
    assert!(matches!(outcome, Outcome::Applied(_)), "{outcome:?}");
    let (status, _) = forward(&proxy, &s.url, "echo", &xfcc(&bot, false))
        .await
        .unwrap();
    assert_eq!(status, 403);
    let (status, _) = forward(&proxy, &s.url, "echo", &client_cert(&bot))
        .await
        .unwrap();
    assert_eq!(status, 200);
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

/// The first line in `log` that holds `text`, waited for.
async fn line_with(log: &Mutex<Vec<String>>, text: &str) -> String {
    let until = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(line) = log.lock().unwrap().iter().find(|l| l.contains(text)) {
            return line.clone();
        }
        assert!(
            Instant::now() < until,
            "no line with {text:?}: {:#?}",
            log.lock().unwrap()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The binary, run with `run --http` on the config at `path`, and what it
/// writes to stderr, line by line.
fn run_binary(path: &str) -> (Running, Arc<Mutex<Vec<String>>>) {
    let mut child = Command::new(BIN)
        .args(["run", "--http", "--config", path])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    {
        let log = Arc::clone(&log);
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                log.lock().unwrap().push(line);
            }
        });
    }
    (Running(child), log)
}

/// A config for the binary, listening on a free loopback port, written to
/// `dir`: its path, and the port.
fn binary_config(dir: &Path, client_auth: &str, rest: &str) -> String {
    let config = config_text(dir, client_auth, rest).replacen(
        "[gateway]\n",
        "[gateway]\nlisten = \"127.0.0.1:0\"\n",
        1,
    );
    let path = dir.join("mcpdef.toml");
    std::fs::write(&path, config).unwrap();
    path.to_str().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_binary_takes_a_certificate_as_its_one_auth_method() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    pkis.server
        .server(&["127.0.0.1"])
        .write(dir.path(), "listener");
    let ca = pkis.agents.write_root(dir.path(), "agents-ca");
    let rest = format!("{CI_ROLE}\n[gateway.auth]\nenabled = true\nmethods = [\"mtls\"]\n");
    let path = binary_config(dir.path(), &spiffe(dir.path(), "optional"), &rest);
    let path = path.as_str();

    let (validated, ok) = mcpdef(&["validate", "--config", path]);
    assert!(ok, "{validated}");
    let (show, ok) = mcpdef(&["tls", "show", "--config", path]);
    assert!(ok, "{show}");
    for says in [
        "client certs : optional, identity spiffe".to_string(),
        "trust domains: prod.acme.internal".to_string(),
        format!("client CAs   : {}", ca.display()),
    ] {
        assert!(show.contains(&says), "{says:?}: {show}");
    }

    let (_running, log) = run_binary(path);
    let ready = line_with(&log, " ready ").await;
    let port = listening_port(&ready, "streamable-http ");
    for says in [
        " · mtls on · 1 role(s)",
        &format!("streamable-http 127.0.0.1:{port} · tls files · client certificates optional"),
    ] {
        assert!(ready.contains(says), "{says:?}: {ready}");
    }
    let url = format!("https://127.0.0.1:{port}/mcp");

    // No certificate: the listener takes it, and auth refuses it.
    let (status, body) = call(&pkis.client(None), &url, "echo", None).await.unwrap();
    assert_eq!(
        (status, body.as_str()),
        (403, "a client certificate is required")
    );
    // One the agents' CA did not issue: refused at the handshake, and logged.
    let stranger = Pki::new("another CA").client(BOT);
    assert!(call(&pkis.client(Some(&stranger)), &url, "echo", None)
        .await
        .is_err());
    let refused = line_with(&log, "refused the client certificate").await;
    assert!(
        refused.starts_with("mcpdef: refused the client certificate 127.0.0.1:")
            && refused.ends_with(" presented: invalid peer certificate: UnknownIssuer"),
        "{refused}"
    );
    // The bot's: served, as the bot.
    let bot = pkis.client(Some(&pkis.agents.client(BOT)));
    let (status, body) = call(&bot, &url, "echo", None).await.unwrap();
    assert_eq!((status, allowed(&body)), (200, true), "{body}");
    let calls: Vec<Record> = read_all(dir.path().join("audit.log"))
        .unwrap()
        .into_iter()
        .filter(|r| r.method.as_deref() == Some("tools/call"))
        .collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].agent, format!("cert:{BOT}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_binary_takes_a_token_and_a_certificate_with_require_all() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    pkis.server
        .server(&["127.0.0.1"])
        .write(dir.path(), "listener");
    pkis.agents.write_root(dir.path(), "agents-ca");
    let rest = format!("{CI_ROLE}\n{}", auth_table("[\"bearer\", \"mtls\"]", "all"));
    let path = binary_config(dir.path(), &spiffe(dir.path(), "optional"), &rest);
    let (_running, log) = run_binary(&path);
    let ready = line_with(&log, " ready ").await;
    let port = listening_port(&ready, "streamable-http ");
    assert!(
        ready.contains(" · oauth and mtls on · 1 role(s)"),
        "{ready}"
    );
    let url = format!("https://127.0.0.1:{port}/mcp");
    let bot = pkis.client(Some(&pkis.agents.client(BOT)));
    let alice = token("alice", &["ci"]);

    // A certificate without a token, and a token without a certificate.
    let (status, _) = call(&bot, &url, "echo", None).await.unwrap();
    assert_eq!(status, 401);
    let (status, body) = call(&pkis.client(None), &url, "echo", Some(&alice))
        .await
        .unwrap();
    assert_eq!(
        (status, body.as_str()),
        (403, "a client certificate is required")
    );
    // Both: the token's subject, and the certificate behind it.
    let (status, body) = call(&bot, &url, "echo", Some(&alice)).await.unwrap();
    assert_eq!((status, allowed(&body)), (200, true), "{body}");
    let calls: Vec<Record> = read_all(dir.path().join("audit.log"))
        .unwrap()
        .into_iter()
        .filter(|r| r.method.as_deref() == Some("tools/call"))
        .collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].agent, "sub:alice");
    assert_eq!(calls[0].actor, Some(format!("cert:{BOT}")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_binary_serves_plain_http_behind_a_trusted_proxy() {
    let dir = tempfile::tempdir().unwrap();
    let pkis = Pkis::new();
    let ca = pkis.agents.write_root(dir.path(), "agents-ca");
    let config = proxied_config_text(
        dir.path(),
        &spiffe(dir.path(), "required"),
        &trusting("127.0.0.1", "x-forwarded-client-cert"),
        CI_ROLE,
    )
    .replacen("[gateway]\n", "[gateway]\nlisten = \"127.0.0.1:0\"\n", 1);
    let path = dir.path().join("mcpdef.toml");
    std::fs::write(&path, config).unwrap();
    let path = path.to_str().unwrap();

    let (validated, ok) = mcpdef(&["validate", "--config", path]);
    assert!(ok, "{validated}");
    let (show, ok) = mcpdef(&["tls", "show", "--config", path]);
    assert!(ok, "{show}");
    for says in [
        "tls          : off".to_string(),
        "client certs : required, identity spiffe".to_string(),
        format!("client CAs   : {}", ca.display()),
        "trusted proxy: x-forwarded-client-cert from 127.0.0.1".to_string(),
    ] {
        assert!(show.contains(&says), "{says:?}: {show}");
    }

    let (_running, log) = run_binary(path);
    let ready = line_with(&log, " ready ").await;
    let port = listening_port(&ready, "streamable-http ");
    let says = format!(
        "listening streamable-http 127.0.0.1:{port} · client certificates required · \
         x-forwarded-client-cert from a trusted proxy"
    );
    assert!(ready.ends_with(&says), "{says:?}: {ready}");
    let url = format!("http://127.0.0.1:{port}/mcp");
    let proxy = plain_client();
    let (status, body) = forward(&proxy, &url, "echo", &[]).await.unwrap();
    assert_eq!(
        (status, body.as_str()),
        (403, "a client certificate is required")
    );
    let bot = pkis.agents.client(BOT);
    let (status, body) = forward(&proxy, &url, "echo", &xfcc(&bot, false))
        .await
        .unwrap();
    assert_eq!((status, allowed(&body)), (200, true), "{body}");
    let calls: Vec<Record> = read_all(dir.path().join("audit.log"))
        .unwrap()
        .into_iter()
        .filter(|r| r.method.as_deref() == Some("tools/call"))
        .collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].agent, format!("cert:{BOT}"));
}
