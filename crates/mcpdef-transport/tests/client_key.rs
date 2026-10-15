// SPDX-License-Identifier: Apache-2.0
//! A client key from each place a secret can be: a file, a variable of
//! MCPdef's own environment, the config itself, or a command.

use mcpdef_core::{Id, Message};
use mcpdef_secrets::{SecretRef, SecretString};
use mcpdef_testkit::{HttpsUpstream, Pki};
use mcpdef_transport::{HttpClient, IdentityFiles, TlsSettings, Transport};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn initialize() -> Message {
    Message::request(
        Id::Num(1),
        "initialize",
        Some(serde_json::json!({ "clientInfo": { "name": "t" } })),
    )
}

/// Settings that trust `ca`, and present `cert` with `key`.
fn presenting(ca: Option<PathBuf>, cert: PathBuf, key: SecretRef) -> TlsSettings {
    TlsSettings {
        ca: ca.into_iter().collect(),
        identity: Some(IdentityFiles { cert, key }),
        ..TlsSettings::default()
    }
}

/// Why `settings` do not load, which `check` says the same way.
fn refusal(settings: &TlsSettings) -> String {
    let error = settings.load().unwrap_err().to_string();
    assert_eq!(settings.check().unwrap_err().to_string(), error);
    error
}

/// The only test here that sets a variable of the process's environment.
#[tokio::test]
async fn a_client_key_is_read_from_each_place_a_secret_can_be() {
    let dir = tempfile::tempdir().unwrap();
    let servers = Pki::new("server CA");
    let clients = Pki::new("client CA");
    let upstream = HttpsUpstream::start_mtls(&servers.server(&["127.0.0.1"]), &clients, &[]).await;
    let ca = servers.write_root(dir.path(), "ca");
    let leaf = clients.client("spiffe://example.org/mcpdef");
    let (cert, key_file) = leaf.write(dir.path(), "gateway");
    std::env::set_var("MCPDEF_TEST_CLIENT_KEY", leaf.key_pem());

    let places = [
        SecretRef::Exec {
            program: "cat".into(),
            args: vec![key_file.to_str().unwrap().into()],
        },
        SecretRef::File(key_file),
        SecretRef::Env("MCPDEF_TEST_CLIENT_KEY".into()),
        SecretRef::Literal(SecretString::from(leaf.key_pem())),
    ];
    for key in places {
        let tls = presenting(Some(ca.clone()), cert.clone(), key.clone());
        let mut client = HttpClient::streamable(upstream.url())
            .unwrap()
            .with_tls(tls.load().unwrap())
            .unwrap();
        client
            .send(initialize())
            .await
            .unwrap_or_else(|e| panic!("{key}: {e}"));
    }
    assert_eq!(
        upstream.client_certificates(),
        vec![leaf.cert_der().clone(); 4]
    );
}

/// A key a command writes can take seconds. `load_async` takes them on a
/// thread of its own, and the caller's runtime goes on meanwhile, though it
/// has only one thread.
#[tokio::test(flavor = "current_thread")]
async fn a_slow_key_leaves_the_runtime_free_while_it_loads() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("client CA");
    let leaf = pki.client("spiffe://example.org/mcpdef");
    let (cert, key_file) = leaf.write(dir.path(), "gateway");
    let slow = SecretRef::Exec {
        program: "sh".into(),
        args: vec![
            "-c".into(),
            format!("sleep 0.5; cat '{}'", key_file.display()),
        ],
    };
    let tls = presenting(None, cert, slow);
    let ticks = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&ticks);
    let ticker = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            counter.fetch_add(1, Ordering::Relaxed);
        }
    });
    tls.load_async().await.unwrap();
    ticker.abort();
    let ticks = ticks.load(Ordering::Relaxed);
    assert!(ticks >= 20, "{ticks} ticks while the key loaded");
}

#[test]
fn a_client_key_that_cannot_be_used_says_where_it_came_from() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("client CA");
    let leaf = pki.client("spiffe://example.org/mcpdef");
    let (cert, _) = leaf.write(dir.path(), "gateway");
    let with_key = |key: SecretRef| refusal(&presenting(None, cert.clone(), key));

    assert_eq!(
        with_key(SecretRef::Env("MCPDEF_TEST_NO_SUCH_KEY".into())),
        "tls: client_key $MCPDEF_TEST_NO_SUCH_KEY: not set in MCPdef's environment"
    );
    assert_eq!(
        with_key(SecretRef::Exec {
            program: "false".into(),
            args: vec!["s3cret".into()],
        }),
        "tls: client_key (exec false): exited with status 1"
    );

    // A path written where the key goes, which is the key itself: the error
    // says how to name a file, and does not repeat what was written.
    let error = with_key(SecretRef::Literal(SecretString::from(
        "/etc/mcpdef/client.key",
    )));
    assert!(
        error.starts_with("tls: client_key (literal): a string is the key itself"),
        "{error}"
    );
    assert!(
        error.contains("client_key = { file = \"/path/to/key.pem\" }"),
        "{error}"
    );
    assert!(!error.contains("/etc/mcpdef"), "{error}");

    // PEM that holds no key: a certificate where the key goes.
    let error = with_key(SecretRef::Literal(SecretString::from(leaf.cert_pem())));
    assert!(
        error.starts_with("tls: client_key (literal): holds no private key"),
        "{error}"
    );

    // A DER key in a file, which is not text: how to make it PEM.
    let der = dir.path().join("key.der");
    std::fs::write(&der, leaf.key_der().secret_der()).unwrap();
    let error = with_key(SecretRef::File(der.clone()));
    assert!(
        error.starts_with(&format!("tls: client_key {}: is not PEM", der.display())),
        "{error}"
    );
    assert!(error.contains("openssl pkey -inform DER"), "{error}");

    // A missing file, named.
    let error = with_key(SecretRef::File("/nonexistent/client.key".into()));
    assert!(
        error.starts_with("tls: client_key /nonexistent/client.key: No such file"),
        "{error}"
    );
}
