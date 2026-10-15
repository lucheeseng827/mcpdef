// SPDX-License-Identifier: Apache-2.0
//! The gateway's HTTP clients need neither a system CA store nor a crypto
//! provider installed beforehand. A test binary of its own, because it points
//! the system store at nothing for the whole process.

use mcpdef_transport::{fetch_text, EgressPolicy, TlsProfile};
use rustls::crypto::CryptoProvider;

#[tokio::test]
async fn a_client_builds_with_no_system_ca_store_and_no_provider_installed() {
    // Where rustls-native-certs would look, before anything has looked.
    std::env::set_var("SSL_CERT_FILE", "/nonexistent/ca-certificates.crt");
    std::env::set_var("SSL_CERT_DIR", "/nonexistent/certs");
    assert!(CryptoProvider::get_default().is_none());

    let app = axum::Router::new().route("/jwks", axum::routing::get(|| async { "{\"keys\":[]}" }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let policy = EgressPolicy {
        allow_private_network: true,
        require_https_public: true,
    };
    // The default profile: the bundled roots, as every client had before profiles.
    let tls = TlsProfile::default();
    let body = fetch_text(&format!("http://{addr}/jwks"), &policy, &tls).await;
    assert_eq!(body.unwrap(), "{\"keys\":[]}");
    assert!(
        CryptoProvider::get_default().is_some(),
        "installed on demand"
    );
}
