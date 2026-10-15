// SPDX-License-Identifier: Apache-2.0
//! `roots = "system"` in a config: the host's store, here the file
//! `SSL_CERT_FILE` names. A test binary of its own, because it sets that for
//! the whole process.

use mcpdef::connect::build_gateway;
use mcpdef::{Config, HealthState};
use mcpdef_testkit::{HttpsUpstream, Pki};

/// A server verified through the host's store still gets the gateway's
/// client certificate: the certificate goes with every choice of roots, not
/// only with the bundled ones.
#[tokio::test]
async fn roots_system_verifies_the_upstream_and_the_client_certificate_still_goes() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("corp CA");
    let clients = Pki::new("client CA");
    let upstream = HttpsUpstream::start_mtls(&pki.server(&["127.0.0.1"]), &clients, &[]).await;
    let leaf = clients.client("spiffe://example.org/mcpdef");
    let (cert, key) = leaf.write(dir.path(), "gateway");
    std::env::set_var("SSL_CERT_FILE", pki.write_root(dir.path(), "host-store"));
    std::env::remove_var("SSL_CERT_DIR");

    let audit = dir.path().join("audit.log");
    let url = upstream.url();
    let text = format!(
        "[gateway]\naudit = {audit:?}\n\n\
         [[server]]\nid = \"corp\"\ntransport = \"streamable-http\"\nurl = {url:?}\n\
         [server.tls]\nroots = \"system\"\nclient_cert = {cert:?}\nclient_key = {{ file = {key:?} }}\n"
    );
    let config = Config::parse(&text).unwrap();
    assert_eq!(config.validate(), Vec::<String>::new());
    let gw = build_gateway(&config).await.unwrap();

    let status = gw.upstream_status();
    assert_eq!(status[0].health, HealthState::Up, "{status:?}");
    let presented = upstream.client_certificates();
    assert!(!presented.is_empty());
    assert!(presented.iter().all(|c| c == leaf.cert_der()));
}
