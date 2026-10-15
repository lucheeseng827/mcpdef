// SPDX-License-Identifier: Apache-2.0
//! The kit end to end: certificates from its PKI, served by its HTTPS
//! upstream, reached with its client.

use mcpdef_testkit::{https_client, HttpsUpstream, Pki};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// An error and every cause under it, as one line.
fn causes(e: &(dyn std::error::Error + 'static)) -> String {
    let mut line = e.to_string();
    let mut cause = e.source();
    while let Some(c) = cause {
        line.push_str(": ");
        line.push_str(&c.to_string());
        cause = c.source();
    }
    line
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    message: Value,
) -> reqwest::Result<reqwest::Response> {
    client
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(message.to_string())
        .send()
        .await
}

fn initialize() -> Value {
    json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": { "name": "smoke", "version": "0" }
    }})
}

/// The upstream's refusals, once there is one: the server side of a refused
/// handshake can finish a moment after the client gives up.
async fn refusals(upstream: &HttpsUpstream) -> Vec<String> {
    let until = Instant::now() + Duration::from_secs(5);
    while upstream.refusals().is_empty() && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    upstream.refusals()
}

#[tokio::test]
async fn an_upstream_on_a_private_ca_initializes_over_https() {
    let pki = Pki::new("mcpdef test CA");
    let upstream = HttpsUpstream::start(&pki.server(&["localhost", "127.0.0.1"])).await;
    let client = https_client(&pki, None);

    let response = post(&client, &upstream.url(), initialize()).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["mcp-session-id"],
        "mcpdef-testkit-session"
    );
    let tls = response.extensions().get::<reqwest::tls::TlsInfo>();
    assert!(tls.is_none(), "not asked for");
    let body: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(body["result"]["serverInfo"]["name"], "mcpdef-testkit");

    let initialized = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    let response = post(&client, &upstream.url(), initialized).await.unwrap();
    assert_eq!(response.status(), 202);
    let call = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": { "name": "echo", "arguments": { "x": 1 } } });
    let body = post(&client, &upstream.url(), call)
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["result"]["content"][0]["text"], "echo:{\"x\":1}");
    let unknown = json!({ "jsonrpc": "2.0", "id": 3, "method": "server/discover" });
    let body = post(&client, &upstream.url(), unknown)
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["error"]["code"], -32601);

    assert_eq!(
        upstream.methods(),
        [
            "initialize",
            "notifications/initialized",
            "tools/call",
            "server/discover"
        ]
    );
    assert!(upstream.client_certificates().is_empty());
    assert!(upstream.refusals().is_empty());
}

#[tokio::test]
async fn a_client_that_does_not_trust_the_ca_is_refused() {
    let pki = Pki::new("mcpdef test CA");
    let upstream = HttpsUpstream::start(&pki.server(&["127.0.0.1"])).await;
    let stranger = https_client(&Pki::new("another CA"), None);

    let error = post(&stranger, &upstream.url(), initialize())
        .await
        .unwrap_err();
    assert!(
        causes(&error).contains("UnknownIssuer"),
        "{}",
        causes(&error)
    );
    let refused = refusals(&upstream).await;
    assert_eq!(refused, ["received fatal alert: UnknownCA"]);
    assert!(upstream.methods().is_empty());
}

#[tokio::test]
async fn a_name_the_certificate_does_not_carry_is_refused() {
    let pki = Pki::new("mcpdef test CA");
    let upstream = HttpsUpstream::start(&pki.server(&["upstream.test"])).await;

    let error = post(&https_client(&pki, None), &upstream.url(), initialize())
        .await
        .unwrap_err();
    assert!(
        causes(&error).contains("not valid for name \"127.0.0.1\""),
        "{}",
        causes(&error)
    );

    // Dialled at the loopback address, under the name it does carry.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = reqwest::Certificate::from_der(pki.root_der()).unwrap();
    let client = reqwest::Client::builder()
        .tls_certs_only([root])
        .resolve("upstream.test", upstream.addr())
        .no_proxy()
        .build()
        .unwrap();
    let response = post(&client, &upstream.url_for("upstream.test"), initialize())
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn mutual_tls_refuses_a_client_without_a_certificate_and_serves_one_with() {
    let pki = Pki::new("mcpdef test CA");
    let agent = pki.client("spiffe://mcpdef.test/agent");
    let upstream = HttpsUpstream::start_mtls(&pki.server(&["127.0.0.1"]), &pki, &[]).await;

    let anonymous = https_client(&pki, None);
    assert!(post(&anonymous, &upstream.url(), initialize())
        .await
        .is_err());
    assert_eq!(refusals(&upstream).await, ["peer sent no certificates"]);
    assert!(upstream.methods().is_empty());

    let response = post(
        &https_client(&pki, Some(&agent)),
        &upstream.url(),
        initialize(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(upstream.client_certificates(), [agent.cert_der().clone()]);
    assert_eq!(upstream.methods(), ["initialize"]);
}

#[tokio::test]
async fn a_revoked_client_certificate_is_refused() {
    let pki = Pki::new("mcpdef test CA");
    let (good, revoked) = (
        pki.client("spiffe://mcpdef.test/good"),
        pki.client("spiffe://mcpdef.test/revoked"),
    );
    let crl = pki.crl(&[&revoked]);
    let upstream = HttpsUpstream::start_mtls(&pki.server(&["127.0.0.1"]), &pki, &[&crl]).await;

    let refused = post(
        &https_client(&pki, Some(&revoked)),
        &upstream.url(),
        initialize(),
    )
    .await;
    assert!(refused.is_err());
    assert_eq!(
        refusals(&upstream).await,
        ["invalid peer certificate: Revoked"]
    );

    let served = post(
        &https_client(&pki, Some(&good)),
        &upstream.url(),
        initialize(),
    )
    .await;
    assert_eq!(served.unwrap().status(), 200);
    assert_eq!(upstream.client_certificates(), [good.cert_der().clone()]);
}

#[tokio::test]
async fn an_intermediate_ca_issues_certificates_that_carry_it() {
    let root = Pki::new("mcpdef test root");
    let issuing = root.intermediate("mcpdef test issuing CA");
    let server = issuing.server(&["127.0.0.1"]);
    let (agent, revoked) = (
        issuing.client("spiffe://mcpdef.test/agent"),
        issuing.client("spiffe://mcpdef.test/revoked"),
    );
    assert_eq!(
        server.chain(),
        [server.cert_der().clone(), issuing.cert_der().clone()]
    );
    assert_eq!(issuing.root_der(), root.cert_der());

    // Both ends trust only the root, and each presents its intermediate.
    let crl = issuing.crl(&[&revoked]);
    let upstream = HttpsUpstream::start_mtls(&server, &issuing, &[&crl]).await;
    let response = post(
        &https_client(&root, Some(&agent)),
        &upstream.url(),
        initialize(),
    )
    .await;
    assert_eq!(response.unwrap().status(), 200);
    let refused = post(
        &https_client(&root, Some(&revoked)),
        &upstream.url(),
        initialize(),
    )
    .await;
    assert!(refused.is_err());
    assert_eq!(
        refusals(&upstream).await,
        ["invalid peer certificate: Revoked"]
    );
}

#[tokio::test]
async fn an_expired_server_certificate_is_refused() {
    let pki = Pki::new("mcpdef test CA");
    let expired = pki
        .leaf()
        .name("127.0.0.1")
        .server_auth()
        .valid((2000, 1, 1), (2001, 1, 1))
        .issue();
    let upstream = HttpsUpstream::start(&expired).await;
    let error = post(&https_client(&pki, None), &upstream.url(), initialize())
        .await
        .unwrap_err();
    assert!(
        causes(&error).contains("certificate expired"),
        "{}",
        causes(&error)
    );
}

#[test]
fn a_certificate_carries_the_names_and_key_it_was_issued_with() {
    let pki = Pki::new("mcpdef test CA");
    let server = pki.server(&["localhost", "upstream.test", "127.0.0.1"]);
    let agent = pki
        .leaf()
        .uri("spiffe://mcpdef.test/agent")
        .email("agent@mcpdef.test")
        .common_name("agent")
        .client_auth()
        .issue();

    let cert = webpki::EndEntityCert::try_from(server.cert_der()).unwrap();
    let names: Vec<&str> = cert.valid_dns_names().collect();
    assert_eq!(names, ["localhost", "upstream.test"]);
    assert_eq!(cert.subject_public_key_info().as_ref(), server.spki_der());

    let cert = webpki::EndEntityCert::try_from(agent.cert_der()).unwrap();
    let uris: Vec<&str> = cert.valid_uri_names().collect();
    assert_eq!(uris, ["spiffe://mcpdef.test/agent"]);
    assert_eq!(cert.valid_dns_names().count(), 0);
    assert_ne!(server.cert_der(), agent.cert_der());
}

#[test]
fn files_read_back_as_what_was_written_and_keys_stay_private() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let issuing = pki.intermediate("mcpdef test issuing CA");
    let agent = issuing.client("spiffe://mcpdef.test/agent");
    let crl = issuing.crl(&[&agent]);

    // The root, even written from the intermediate: what a peer trusts.
    let root = issuing.write_root(dir.path(), "ca");
    let (cert, key) = agent.write(dir.path(), "agent");
    let crl_path = crl.write(dir.path(), "agents");

    let root: Vec<CertificateDer> = CertificateDer::pem_file_iter(&root)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(root, [pki.cert_der().clone()]);
    let chain: Vec<CertificateDer> = CertificateDer::pem_file_iter(&cert)
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(chain, agent.chain());
    let key_read = PrivateKeyDer::from_pem_file(&key).unwrap();
    assert_eq!(key_read.secret_der(), agent.key_der().secret_der());
    let crl_read = CertificateRevocationListDer::from_pem_file(&crl_path).unwrap();
    assert_eq!(&crl_read, crl.der());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "a key file is the owner's alone");
    }
}

#[tokio::test]
async fn a_client_that_never_finishes_its_handshake_holds_up_no_one() {
    let pki = Pki::new("mcpdef test CA");
    let upstream = HttpsUpstream::start(&pki.server(&["127.0.0.1"])).await;
    // Connected, and silent: no ClientHello ever comes.
    let _stalled = tokio::net::TcpStream::connect(upstream.addr())
        .await
        .unwrap();

    let started = Instant::now();
    let response = post(&https_client(&pki, None), &upstream.url(), initialize()).await;
    assert_eq!(response.unwrap().status(), 200);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
}

/// A self-signed certificate is its own issuer, a renewal of it keeps its
/// key, and the upstream records what ALPN settled on.
#[tokio::test]
async fn a_self_signed_certificate_renews_on_its_key_and_alpn_is_recorded() {
    let leaf = mcpdef_testkit::Leaf::self_signed(&["127.0.0.1", "appliance.test"]);
    let parsed = webpki::EndEntityCert::try_from(leaf.cert_der()).unwrap();
    let names: Vec<&str> = parsed.valid_dns_names().collect();
    assert_eq!(names, ["appliance.test"]);
    assert_eq!(leaf.chain().len(), 1, "no intermediates");

    let renewed = leaf.renewed();
    assert_ne!(renewed.cert_der(), leaf.cert_der());
    assert_eq!(renewed.spki_der(), leaf.spki_der());

    // Trusted as its own root, it serves; the kit's client offers HTTP/1.1.
    let upstream = HttpsUpstream::start(&leaf).await;
    let reply = post(&upstream_client(&leaf), &upstream.url(), initialize())
        .await
        .map(|r| r.status().as_u16());
    // A certificate that says it is a CA cannot also be a server's for webpki.
    assert!(reply.is_err(), "{reply:?}");
    let pki = Pki::new("mcpdef test CA");
    let served = HttpsUpstream::start(&pki.server(&["127.0.0.1"])).await;
    let reply = post(&https_client(&pki, None), &served.url(), initialize())
        .await
        .unwrap();
    assert_eq!(reply.status(), 200);
    assert_eq!(served.protocols(), [Some("http/1.1".to_string())]);
}

/// A client whose one root is `leaf` itself.
fn upstream_client(leaf: &mcpdef_testkit::Leaf) -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = reqwest::Certificate::from_der(leaf.cert_der()).unwrap();
    reqwest::Client::builder()
        .tls_certs_only([root])
        .no_proxy()
        .build()
        .unwrap()
}
