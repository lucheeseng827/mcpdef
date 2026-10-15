// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the OAuth 2.1 termination + RBAC on the HTTP listener
//! (`mcpdef run --http` with `[gateway.auth]`). A real client reaches mcpdef over
//! HTTP and:
//!   * a valid bearer whose role grants the tool → `tools/call` succeeds;
//!   * no bearer → `401` with a `WWW-Authenticate` challenge pointing at the
//!     RFC 9728 Protected Resource Metadata document;
//!   * a valid bearer whose role does NOT grant the tool → the RBAC gate denies
//!     it (a `MCPdef denied` tool error), even though the static allowlist permits;
//!   * `GET /.well-known/oauth-protected-resource` serves the PRM document.
//!
//! Tokens are signed with the same fixed RSA fixture `mcpdef-auth` validates
//! against (committed under `mcpdef-auth/src/testdata/`), so the full crypto path
//! runs offline and deterministically.

use axum::{routing::get, Router};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mcpdef::listener::{serve_http_on, AuthState, HttpConfig, JwksRefresher};
use mcpdef::Gateway;
use mcpdef_audit::Ledger;
use mcpdef_auth::Verifier;
use mcpdef_core::wire::WireMode;
use mcpdef_policy::{Policy, Rbac, ServerPolicy};
use mcpdef_transport::{EgressPolicy, StdioChild};
use serde::Serialize;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

// The matched RSA-2048 keypair `mcpdef-auth` trusts (private PEM to sign with, the
// public JWKS the verifier loads).
const TEST_PRIV_PEM: &str = include_str!("../../mcpdef-auth/src/testdata/test_priv.pem");
const TEST_JWKS: &str = include_str!("../../mcpdef-auth/src/testdata/test_jwks.json");
const ISSUER: &str = "https://auth.example.com";
const RESOURCE: &str = "https://mcpdef.acme.internal/mcp";

#[derive(Serialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: String,
    exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    roles: Option<Vec<String>>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Sign a valid bearer (correct `aud`/`iss`/`exp`, fixture key) carrying `roles`.
fn token_with_roles(roles: &[&str]) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".into());
    let claims = Claims {
        sub: "agent-7".into(),
        iss: ISSUER.into(),
        aud: RESOURCE.into(),
        exp: now() + 3600,
        roles: Some(roles.iter().map(|r| r.to_string()).collect()),
    };
    let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
    encode(&header, &claims, &key).unwrap()
}

fn allow_echo() -> Policy {
    let mut p = Policy::new();
    p.insert(
        "mock",
        ServerPolicy {
            allow_tools: Some(vec!["echo".into()]),
            deny: vec![],
        },
    );
    p
}

/// RBAC: only the `reader` role grants `echo` on the `mock` server.
fn reader_grants_echo() -> Rbac {
    let mut rbac = Rbac::new();
    rbac.insert_role("reader", vec![("mock".into(), "echo".into())]);
    rbac
}

fn spawn_mock() -> Box<StdioChild> {
    let bin = env!("CARGO_BIN_EXE_mock_mcp_server").to_string();
    Box::new(StdioChild::spawn(&[bin]).unwrap())
}

/// A loopback client that does NOT route through any ambient proxy (the test env
/// sets HTTPS_PROXY, which would otherwise hijack the 127.0.0.1 request).
fn client() -> reqwest::Client {
    mcpdef_transport::install_crypto_provider();
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// Start an authenticated listener on an ephemeral loopback port. Returns the
/// base URL (no path) and the tempdir guard (keeps the audit file alive).
async fn start_authed() -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Ledger::open(dir.path().join("audit.log")).unwrap();
    let mut gw =
        Gateway::new(allow_echo(), ledger, "agent:test").with_rbac(Some(reader_grants_echo()));
    gw.add_upstream("mock", spawn_mock()).await.unwrap();

    let verifier = Verifier::from_jwks_json(TEST_JWKS, ISSUER, RESOURCE).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = HttpConfig {
        listen: addr.to_string(),
        allowed_origins: vec![],
        max_inflight: None,
        wire: WireMode::default(),
    };
    tokio::spawn(serve_http_on(
        listener,
        gw,
        cfg,
        Some(AuthState::new(verifier)),
    ));
    (format!("http://{addr}"), dir)
}

/// Serve a JWKS document on an ephemeral loopback port; returns its URL. Stands in
/// for the authorization server's `jwks_uri`.
async fn serve_jwks(body: &'static str) -> String {
    let app = Router::new().route("/jwks.json", get(move || async move { body }));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(l, app).await.unwrap();
    });
    format!("http://{addr}/jwks.json")
}

/// Like [`start_authed`], but the verifier starts with a **stale** JWKS (the real
/// key under a different `kid`) and is given a `jwks_uri` refresher pointing at a
/// mock server that serves the current keys — so a token signed with the current
/// `kid` only validates if the listener re-fetches on the cache miss.
async fn start_authed_needing_refresh() -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Ledger::open(dir.path().join("audit.log")).unwrap();
    let mut gw =
        Gateway::new(allow_echo(), ledger, "agent:test").with_rbac(Some(reader_grants_echo()));
    gw.add_upstream("mock", spawn_mock()).await.unwrap();

    // Stale initial keys: the token's `kid` ("test-key-1") is absent here.
    let stale = TEST_JWKS.replace("test-key-1", "old-key");
    let verifier = Verifier::from_jwks_json(&stale, ISSUER, RESOURCE).unwrap();
    // The mock jwks_uri serves the current JWKS; loopback is allowed by default.
    let jwks_url = serve_jwks(TEST_JWKS).await;
    let refresher = JwksRefresher::new(jwks_url, EgressPolicy::default());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = HttpConfig {
        listen: addr.to_string(),
        allowed_origins: vec![],
        max_inflight: None,
        wire: WireMode::default(),
    };
    tokio::spawn(serve_http_on(
        listener,
        gw,
        cfg,
        Some(AuthState::with_refresher(verifier, refresher)),
    ));
    (format!("http://{addr}"), dir)
}

#[tokio::test]
async fn valid_bearer_with_granting_role_succeeds() {
    let (base, _dir) = start_authed().await;
    let url = format!("{base}/mcp");
    let c = client();
    let tok = token_with_roles(&["reader"]);

    let resp = c
        .post(&url)
        .bearer_auth(&tok)
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(v["result"]["isError"], false);
}

#[tokio::test]
async fn missing_bearer_gets_401_with_prm_challenge() {
    let (base, _dir) = start_authed().await;
    let url = format!("{base}/mcp");

    let resp = client()
        .post(&url)
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let challenge = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(challenge.starts_with("Bearer "));
    assert!(challenge.contains("resource_metadata="));
    assert!(challenge.contains("/.well-known/oauth-protected-resource"));
}

/// A bearer that is valid in all but one way: it is not valid until tomorrow,
/// and says so with a string. jsonwebtoken 9 skips an `nbf` it cannot read as
/// a number (CVE-2026-25537), so this call went through.
#[tokio::test]
async fn a_bearer_whose_nbf_is_a_string_gets_401() {
    let (base, _dir) = start_authed().await;
    let url = format!("{base}/mcp");
    let claims = serde_json::json!({
        "sub": "agent-7",
        "iss": ISSUER,
        "aud": RESOURCE,
        "exp": now() + 3 * 86_400,
        "nbf": (now() + 86_400).to_string(),
        "roles": ["reader"],
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".into());
    let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
    let tok = encode(&header, &claims, &key).unwrap();

    let resp = client()
        .post(&url)
        .bearer_auth(&tok)
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn invalid_bearer_gets_401() {
    let (base, _dir) = start_authed().await;
    let url = format!("{base}/mcp");

    let resp = client()
        .post(&url)
        .bearer_auth("not-a-real-jwt")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn valid_bearer_without_granting_role_is_denied_by_rbac() {
    let (base, _dir) = start_authed().await;
    let url = format!("{base}/mcp");
    let c = client();
    // A valid token, but the `viewer` role is not in the RBAC model → no grant.
    let tok = token_with_roles(&["viewer"]);

    let resp = c
        .post(&url)
        .bearer_auth(&tok)
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}"#)
        .send()
        .await
        .unwrap();
    // Auth passed (200), but the RBAC gate denies the call as a tool error.
    assert_eq!(resp.status(), 200);
    let v: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(v["result"]["isError"], true);
    let text = v["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        text.contains("denied"),
        "expected an RBAC denial, got: {text}"
    );
}

#[tokio::test]
async fn rotated_signing_key_is_picked_up_via_jwks_uri_refresh() {
    // The token's `kid` is missing from the listener's initial (stale) JWKS — as
    // after the IdP rotates its signing key. The listener must re-fetch the
    // `jwks_uri`, pick up the new key, and authorize the call, all without a
    // restart. A gateway that loaded keys once at startup would 401 here.
    let (base, _dir) = start_authed_needing_refresh().await;
    let url = format!("{base}/mcp");
    let tok = token_with_roles(&["reader"]);

    let resp = client()
        .post(&url)
        .bearer_auth(&tok)
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "an unknown kid must trigger a JWKS refresh that authorizes the call"
    );
    let v: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(v["result"]["isError"], false);
}

#[tokio::test]
async fn protected_resource_metadata_is_served() {
    let (base, _dir) = start_authed().await;
    let url = format!("{base}/.well-known/oauth-protected-resource");

    let resp = client().get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let v: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(v["resource"], RESOURCE);
    assert_eq!(v["authorization_servers"][0], ISSUER);
}

/// Like [`start_authed_needing_refresh`], with `refresher` as the listener's
/// JWKS refresher.
async fn start_authed_refreshing_with(refresher: JwksRefresher) -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Ledger::open(dir.path().join("audit.log")).unwrap();
    let mut gw =
        Gateway::new(allow_echo(), ledger, "agent:test").with_rbac(Some(reader_grants_echo()));
    gw.add_upstream("mock", spawn_mock()).await.unwrap();
    let stale = TEST_JWKS.replace("test-key-1", "old-key");
    let verifier = Verifier::from_jwks_json(&stale, ISSUER, RESOURCE).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = HttpConfig {
        listen: addr.to_string(),
        allowed_origins: vec![],
        max_inflight: None,
        wire: WireMode::default(),
    };
    tokio::spawn(serve_http_on(
        listener,
        gw,
        cfg,
        Some(AuthState::with_refresher(verifier, refresher)),
    ));
    (format!("http://{addr}"), dir)
}

/// An identity provider on a private CA: its `jwks_uri` is fetched with
/// `[gateway.upstream_tls]`, as a reload last stored it.
#[tokio::test]
async fn a_jwks_uri_on_a_private_ca_is_refreshed_with_the_gateway_tls_profile() {
    use arc_swap::ArcSwap;
    use mcpdef::listener::Fetching;
    use mcpdef_testkit::{HttpsUpstream, Pki};
    use mcpdef_transport::TlsSettings;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("idp CA");
    let app = Router::new().route("/jwks.json", get(|| async { TEST_JWKS }));
    let idp = HttpsUpstream::start_app(&pki.server(&["127.0.0.1"]), app).await;
    let jwks_uri = format!("https://127.0.0.1:{}/jwks.json", idp.addr().port());
    let tok = token_with_roles(&["reader"]);
    let status = |base: String| {
        let tok = tok.clone();
        async move {
            client()
                .post(format!("{base}/mcp"))
                .bearer_auth(&tok)
                .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#)
                .send()
                .await
                .unwrap()
                .status()
        }
    };

    // With the bundled roots alone, the refresh cannot reach the IdP: closed.
    let bundled = Arc::new(ArcSwap::from_pointee(Fetching::default()));
    let (base, _a) =
        start_authed_refreshing_with(JwksRefresher::following(jwks_uri.clone(), bundled)).await;
    assert_eq!(status(base).await, 401);

    // Settings stored after the listener started, as a reload stores them,
    // are the ones the refresh goes out with.
    let fetching = Arc::new(ArcSwap::from_pointee(Fetching::default()));
    let (base, _b) =
        start_authed_refreshing_with(JwksRefresher::following(jwks_uri, Arc::clone(&fetching)))
            .await;
    fetching.store(Arc::new(Fetching {
        tls: TlsSettings {
            ca: vec![pki.write_root(dir.path(), "idp")],
            ..TlsSettings::default()
        },
        ..Fetching::default()
    }));
    assert_eq!(status(base).await, 200);
}

/// A client key a command writes, for the `jwks_uri` fetch, is read off the
/// async workers: while the command takes its time, the listener's other tasks
/// go on, though its runtime has one thread.
#[tokio::test(flavor = "current_thread")]
async fn a_jwks_refresh_whose_client_key_a_command_writes_leaves_the_runtime_free() {
    use arc_swap::ArcSwap;
    use mcpdef::listener::Fetching;
    use mcpdef_secrets::SecretRef;
    use mcpdef_testkit::{HttpsUpstream, Pki};
    use mcpdef_transport::{IdentityFiles, TlsSettings};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("idp CA");
    let app = Router::new().route("/jwks.json", get(|| async { TEST_JWKS }));
    let idp = HttpsUpstream::start_app(&pki.server(&["127.0.0.1"]), app).await;
    let jwks_uri = format!("https://127.0.0.1:{}/jwks.json", idp.addr().port());
    let leaf = Pki::new("client CA").client("spiffe://example.org/mcpdef");
    let (cert, key) = leaf.write(dir.path(), "gateway");
    let fetching = Arc::new(ArcSwap::from_pointee(Fetching {
        tls: TlsSettings {
            ca: vec![pki.write_root(dir.path(), "idp")],
            identity: Some(IdentityFiles {
                cert,
                key: SecretRef::Exec {
                    program: "sh".into(),
                    args: vec!["-c".into(), format!("sleep 0.5; cat '{}'", key.display())],
                },
            }),
            ..TlsSettings::default()
        },
        ..Fetching::default()
    }));
    let (base, _audit) =
        start_authed_refreshing_with(JwksRefresher::following(jwks_uri, fetching)).await;

    let ticks = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&ticks);
    let ticker = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            counter.fetch_add(1, Ordering::Relaxed);
        }
    });
    let status = client()
        .post(format!("{base}/mcp"))
        .bearer_auth(token_with_roles(&["reader"]))
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#)
        .send()
        .await
        .unwrap()
        .status();
    ticker.abort();
    assert_eq!(status, 200);
    let ticks = ticks.load(Ordering::Relaxed);
    assert!(ticks >= 20, "{ticks} ticks while the JWKS was fetched");
}
