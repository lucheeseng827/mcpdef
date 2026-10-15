// SPDX-License-Identifier: Apache-2.0
//! `roots = "system"`: the host's store, here the file `SSL_CERT_FILE` names.
//! A test binary of its own, because it sets that for the whole process.

use mcpdef_core::{Id, Message};
use mcpdef_testkit::{HttpsUpstream, Pki};
use mcpdef_transport::{HttpClient, IdentityFiles, Roots, TlsSettings, Transport};

async fn opens(url: &str, tls: &TlsSettings) -> Result<(), String> {
    let mut client = HttpClient::streamable(url)
        .unwrap()
        .with_tls(tls.load().map_err(|e| e.to_string())?)
        .unwrap();
    let initialize = Message::request(Id::Num(1), "initialize", Some(serde_json::json!({})));
    client.send(initialize).await.map_err(|e| e.to_string())
}

/// A server verified through the host's store still gets the client
/// certificate: the certificate goes with every choice of roots, not only
/// with the bundled ones.
#[tokio::test]
async fn the_hosts_roots_verify_the_server_and_the_client_certificate_still_goes() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let clients = Pki::new("mcpdef client CA");
    let upstream = HttpsUpstream::start_mtls(&pki.server(&["127.0.0.1"]), &clients, &[]).await;
    let leaf = clients.client("spiffe://example.org/mcpdef");
    let (cert, key) = leaf.write(dir.path(), "client");
    let settings = TlsSettings {
        roots: Roots::System,
        identity: Some(IdentityFiles {
            cert,
            key: key.into(),
        }),
        ..TlsSettings::default()
    };

    // A host with no store: the profile does not load, and says why. Checking
    // a config reads no host store, so it does not mind.
    std::env::set_var("SSL_CERT_FILE", dir.path().join("missing.pem"));
    std::env::remove_var("SSL_CERT_DIR");
    let error = settings.load().unwrap_err().to_string();
    assert!(
        error.contains("the host's CA store has no certificate to trust"),
        "{error}"
    );
    assert!(error.contains("SSL_CERT_FILE"), "{error}");
    settings.check().unwrap();

    // The test CA as the host's store.
    std::env::set_var("SSL_CERT_FILE", pki.write_root(dir.path(), "host-store"));
    opens(&upstream.url(), &settings).await.unwrap();
    assert_eq!(upstream.client_certificates(), [leaf.cert_der().clone()]);

    // `both` trusts it too; the bundled roots alone do not.
    let both = TlsSettings {
        roots: Roots::Both,
        ..settings.clone()
    };
    opens(&upstream.url(), &both).await.unwrap();
    let bundled = TlsSettings {
        roots: Roots::Bundled,
        ..settings
    };
    let error = opens(&upstream.url(), &bundled).await.unwrap_err();
    assert!(error.contains("UnknownIssuer"), "{error}");
    assert_eq!(upstream.client_certificates().len(), 2);
}
