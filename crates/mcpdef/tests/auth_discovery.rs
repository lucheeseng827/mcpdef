// SPDX-License-Identifier: Apache-2.0
//! `[gateway.auth] discovery` and `audiences`, through the real binary:
//!   * an issuer with a path, whose server publishes RFC 8414 metadata alone:
//!     OpenID Connect's document is looked for and not found, RFC 8414's is,
//!     and a token is verified by the keys its `jwks_uri` names, as
//!     `mcpdef auth test` and `mcpdef doctor` show;
//!   * an issuer whose metadata names another issuer is refused, by both;
//!   * `audiences`: a token for one of them is taken, as one for `resource`
//!     is, and one for neither is not.

use axum::http::{header, Uri};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");
const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");
const TEST_PRIV_PEM: &str = include_str!("../../mcpdef-auth/src/testdata/test_priv.pem");
const TEST_JWKS: &str = include_str!("../../mcpdef-auth/src/testdata/test_jwks.json");
const RESOURCE: &str = "https://mcp.example/mcp";
const APP_ID_URI: &str = "api://0000-aaaa";

/// An authorization server at `base`: `/tenant` publishes RFC 8414 metadata
/// alone, and `/liar` an OpenID Connect document that names another issuer.
/// Each path it was asked for is kept, in order.
async fn authorization_server() -> (String, Arc<Mutex<Vec<String>>>) {
    let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", bound.local_addr().unwrap());
    let asked = Arc::new(Mutex::new(Vec::new()));
    let (at, seen) = (base.clone(), Arc::clone(&asked));
    let app = Router::new()
        .route(
            "/.well-known/oauth-authorization-server/tenant",
            get({
                let at = at.clone();
                move || {
                    let found = json!({ "issuer": format!("{at}/tenant"), "jwks_uri": format!("{at}/keys") });
                    async move { Json(found) }
                }
            }),
        )
        .route(
            "/liar/.well-known/openid-configuration",
            get({
                let at = at.clone();
                move || {
                    let found = json!({ "issuer": format!("{at}/other"), "jwks_uri": format!("{at}/keys") });
                    async move { Json(found) }
                }
            }),
        )
        .route(
            "/keys",
            get(|| async { ([(header::CONTENT_TYPE, "application/json")], TEST_JWKS).into_response() }),
        )
        .layer(axum::middleware::from_fn(
            move |uri: Uri, request: axum::extract::Request, next: axum::middleware::Next| {
                let seen = Arc::clone(&seen);
                async move {
                    seen.lock().unwrap().push(uri.path().to_string());
                    next.run(request).await
                }
            },
        ));
    tokio::spawn(async move {
        axum::serve(bound, app).await.unwrap();
    });
    (base, asked)
}

/// A token of `issuer`'s for `audience`.
fn token(issuer: &str, audience: &str) -> String {
    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims =
        json!({ "iss": issuer, "aud": audience, "sub": "ann", "iat": at, "exp": at + 300 });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-1".into());
    let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
    encode(&header, &claims, &key).unwrap()
}

/// A config in `dir` whose `[gateway.auth]` finds `issuer`'s keys by
/// discovery, and takes [`APP_ID_URI`] beside the resource.
fn config(dir: &Path, issuer: &str) -> std::path::PathBuf {
    let path = dir.join("mcpdef.toml");
    std::fs::write(
        &path,
        format!(
            "[gateway]\nlisten = \"127.0.0.1:7878\"\naudit = {audit:?}\nstate_dir = {state:?}\n\n\
             [gateway.auth]\nenabled = true\nissuer = {issuer:?}\nresource = {RESOURCE:?}\n\
             discovery = true\naudiences = [{APP_ID_URI:?}]\n\n\
             [[server]]\nid = \"mock\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\n",
            audit = dir.join("audit.log"),
            state = dir.join("state"),
        ),
    )
    .unwrap();
    path
}

/// `mcpdef <args>`: whether it succeeded, and what it wrote.
fn mcpdef(args: &[&str], config: &Path) -> (bool, String) {
    let out = Command::new(BIN)
        .args(args)
        .arg("--config")
        .arg(config)
        .output()
        .unwrap();
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), said)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keys_are_found_from_the_issuers_metadata_and_audiences_are_taken() {
    let (base, asked) = authorization_server().await;
    let issuer = format!("{base}/tenant");
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path(), &issuer);

    // Verified with the keys RFC 8414's metadata names, after OpenID
    // Connect's document was looked for first.
    for audience in [APP_ID_URI, RESOURCE] {
        let (ok, said) = tokio::task::spawn_blocking({
            let config = config.clone();
            let token = token(&issuer, audience);
            move || mcpdef(&["auth", "test", "--token", &token], &config)
        })
        .await
        .unwrap();
        assert!(ok, "{audience}: {said}");
        assert!(said.contains("subject : ann"), "{said}");
    }
    assert_eq!(
        asked.lock().unwrap()[..3],
        [
            "/tenant/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server/tenant",
            "/keys",
        ]
    );
    // An audience it does not take.
    let (ok, said) = tokio::task::spawn_blocking({
        let config = config.clone();
        let token = token(&issuer, "api://0000-bbbb");
        move || mcpdef(&["auth", "test", "--token", &token], &config)
    })
    .await
    .unwrap();
    assert!(!ok, "{said}");
    assert!(said.contains("InvalidAudience"), "{said}");

    // `mcpdef doctor` finds the keys as the gateway does.
    let (_, said) = tokio::task::spawn_blocking({
        let config = config.clone();
        move || mcpdef(&["doctor", "--wait", "10"], &config)
    })
    .await
    .unwrap();
    assert!(
        said.contains(&format!(
            "discovery: the issuer's metadata names jwks_uri {base}/keys"
        )),
        "{said}"
    );
    assert!(said.contains(&format!("jwks_uri {base}/keys: ")), "{said}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_that_names_another_issuer_is_refused() {
    let (base, _) = authorization_server().await;
    let issuer = format!("{base}/liar");
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path(), &issuer);
    let (ok, said) = tokio::task::spawn_blocking({
        let config = config.clone();
        let token = token(&issuer, RESOURCE);
        move || mcpdef(&["auth", "test", "--token", &token], &config)
    })
    .await
    .unwrap();
    assert!(!ok, "{said}");
    assert!(
        said.contains(&format!(
            "names the issuer \"{base}/other\", and the config names \"{issuer}\""
        )),
        "{said}"
    );
    let (ok, said) =
        tokio::task::spawn_blocking(move || mcpdef(&["doctor", "--wait", "10"], &config))
            .await
            .unwrap();
    assert!(!ok, "{said}");
    assert!(said.contains("✗ discovery: "), "{said}");
}

#[test]
fn discovery_and_the_keys_it_would_replace_are_one_or_the_other() {
    let dir = tempfile::tempdir().unwrap();
    let path = config(dir.path(), "https://as.example");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        text.replace(
            "discovery = true",
            "discovery = true\njwks_uri = \"https://as.example/keys\"",
        ),
    )
    .unwrap();
    let (ok, said) = mcpdef(&["validate"], &path);
    assert!(!ok, "{said}");
    assert!(
        said.contains("[gateway.auth] discovery finds jwks_uri itself"),
        "{said}"
    );
}
