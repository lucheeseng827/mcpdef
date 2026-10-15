// SPDX-License-Identifier: Apache-2.0
//! An upstream over HTTPS, reached the way the gateway reaches one: with the
//! bundled roots alone, or with a TLS profile.

use mcpdef_core::{Id, Message};
use mcpdef_testkit::{HttpsUpstream, Pki};
use mcpdef_transport::{
    fetch_text, EgressPolicy, HttpClient, IdentityFiles, MinVersion, TlsProfile, TlsSettings,
    Transport,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn initialize() -> Message {
    Message::request(
        Id::Num(1),
        "initialize",
        Some(serde_json::json!({ "clientInfo": { "name": "t" } })),
    )
}

/// Open `client` with an `initialize`: `Ok` once the upstream answers.
async fn opens(mut client: HttpClient) -> Result<(), String> {
    client.send(initialize()).await.map_err(|e| e.to_string())
}

/// A client for `url` with the profile `tls` reads.
fn client(url: &str, tls: &TlsSettings) -> HttpClient {
    HttpClient::streamable(url)
        .unwrap()
        .with_tls(tls.load().unwrap())
        .unwrap()
}

/// Settings that trust `ca` besides the bundled roots, and do nothing else.
fn trusting(ca: PathBuf) -> TlsSettings {
    TlsSettings {
        ca: vec![ca],
        ..TlsSettings::default()
    }
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

/// With nothing configured, the gateway trusts Mozilla's roots alone. An
/// upstream whose certificate comes from any other CA is refused at the
/// handshake, before a request reaches it.
#[tokio::test]
async fn an_upstream_on_a_private_ca_is_refused_while_nothing_trusts_its_ca() {
    let pki = Pki::new("mcpdef test CA");
    let upstream = HttpsUpstream::start(&pki.server(&["127.0.0.1"])).await;
    let mut client = HttpClient::streamable(upstream.url()).unwrap();

    let initialize = Message::request(
        Id::Num(1),
        "initialize",
        Some(serde_json::json!({ "clientInfo": { "name": "t" } })),
    );
    let error = client.send(initialize).await.unwrap_err().to_string();
    assert!(error.contains("UnknownIssuer"), "{error}");
    assert!(upstream.methods().is_empty());
}

/// The same upstream, once a profile names its CA: the refusal above turns
/// into an answer.
#[tokio::test]
async fn an_upstream_on_a_private_ca_is_served_once_a_profile_trusts_its_ca() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let upstream = HttpsUpstream::start(&pki.server(&["127.0.0.1"])).await;

    let tls = trusting(pki.write_root(dir.path(), "ca"));
    opens(client(&upstream.url(), &tls)).await.unwrap();
    assert_eq!(upstream.methods(), ["initialize"]);

    // Trusting some other CA does not trust this one.
    let other = Pki::new("some other CA");
    let tls = trusting(other.write_root(dir.path(), "other"));
    let error = opens(client(&upstream.url(), &tls)).await.unwrap_err();
    assert!(error.contains("UnknownIssuer"), "{error}");
}

#[tokio::test]
async fn a_client_certificate_is_presented_to_an_upstream_that_asks_for_one() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let clients = Pki::new("mcpdef client CA");
    let upstream = HttpsUpstream::start_mtls(&pki.server(&["127.0.0.1"]), &clients, &[]).await;
    let ca = pki.write_root(dir.path(), "ca");

    // Without one, the upstream refuses the handshake.
    assert!(opens(client(&upstream.url(), &trusting(ca.clone())))
        .await
        .is_err());
    let refused = refusals(&upstream).await;
    assert!(
        refused
            .iter()
            .any(|r| r.contains("peer sent no certificates")),
        "{refused:?}"
    );
    assert!(upstream.methods().is_empty());

    // With one, it is served, and the certificate it saw is the gateway's.
    let gateway = clients.client("spiffe://example.org/mcpdef");
    let (cert, key) = gateway.write(dir.path(), "gateway");
    let tls = TlsSettings {
        identity: Some(IdentityFiles {
            cert,
            key: key.into(),
        }),
        ..trusting(ca)
    };
    opens(client(&upstream.url(), &tls)).await.unwrap();
    assert_eq!(upstream.client_certificates(), [gateway.cert_der().clone()]);
    assert_eq!(upstream.methods(), ["initialize"]);
}

#[tokio::test]
async fn a_server_certificate_a_crl_revokes_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let server = pki.server(&["127.0.0.1"]);
    let upstream = HttpsUpstream::start(&server).await;
    let ca = pki.write_root(dir.path(), "ca");

    // A CRL that revokes some other certificate: served.
    let elsewhere = pki.server(&["127.0.0.2"]);
    let tls = TlsSettings {
        crl: vec![pki.crl(&[&elsewhere]).write(dir.path(), "other")],
        ..trusting(ca.clone())
    };
    opens(client(&upstream.url(), &tls)).await.unwrap();

    // One that revokes this one: refused, before a request is sent.
    let tls = TlsSettings {
        crl: vec![pki.crl(&[&server]).write(dir.path(), "revoked")],
        ..trusting(ca)
    };
    let error = opens(client(&upstream.url(), &tls)).await.unwrap_err();
    assert!(error.contains("Revoked"), "{error}");
    assert_eq!(
        upstream.methods(),
        ["initialize"],
        "only the first was served"
    );
}

/// rustls checks every certificate in the chain, and refuses one whose status
/// no CRL tells. Behind an intermediate, that takes the root's CRL (for the
/// intermediate) as well as the intermediate's (for the server).
#[tokio::test]
async fn with_crls_every_ca_in_the_chain_needs_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let root = Pki::new("mcpdef test root");
    let issuing = root.intermediate("mcpdef issuing CA");
    let upstream = HttpsUpstream::start(&issuing.server(&["127.0.0.1"])).await;
    let ca = root.write_root(dir.path(), "ca");
    let issuing_crl = issuing.crl(&[]).write(dir.path(), "issuing");
    let root_crl = root.crl(&[]).write(dir.path(), "root");

    let tls = TlsSettings {
        crl: vec![issuing_crl.clone()],
        ..trusting(ca.clone())
    };
    let error = opens(client(&upstream.url(), &tls)).await.unwrap_err();
    assert!(error.contains("UnknownRevocationStatus"), "{error}");

    let tls = TlsSettings {
        crl: vec![issuing_crl, root_crl],
        ..trusting(ca)
    };
    opens(client(&upstream.url(), &tls)).await.unwrap();
}

/// `connect_to` dials an address the URL's host does not resolve to, and the
/// certificate is still checked against the host's name.
#[tokio::test]
async fn connect_to_dials_the_address_and_checks_the_name() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let tls = trusting(pki.write_root(dir.path(), "ca"));
    let loopback = "127.0.0.1".parse().unwrap();

    // `upstream.test` resolves nowhere: without connect_to there is no one
    // to dial.
    let upstream = HttpsUpstream::start(&pki.server(&["upstream.test"])).await;
    let url = upstream.url_for("upstream.test");
    let error = opens(client(&url, &tls)).await.unwrap_err();
    assert!(error.contains("resolving 'upstream.test'"), "{error}");

    opens(client(&url, &tls).with_connect_to(loopback))
        .await
        .unwrap();
    assert_eq!(upstream.methods(), ["initialize"]);

    // An upstream whose certificate names another host is refused, wherever
    // it is dialled.
    let impostor = HttpsUpstream::start(&pki.server(&["elsewhere.test"])).await;
    let url = impostor.url_for("upstream.test");
    let error = opens(client(&url, &tls).with_connect_to(loopback))
        .await
        .unwrap_err();
    assert!(
        error.contains("not valid for name \"upstream.test\""),
        "{error}"
    );
    assert!(impostor.methods().is_empty());
}

#[tokio::test]
async fn connect_to_the_metadata_address_is_refused_before_anything_is_sent() {
    for addr in ["169.254.169.254", "::ffff:169.254.169.254", "fe80::1"] {
        let client = HttpClient::streamable("https://upstream.test/mcp")
            .unwrap()
            .with_connect_to(addr.parse().unwrap());
        let error = opens(client).await.unwrap_err();
        assert!(
            error.starts_with("egress blocked") && error.contains("always blocked"),
            "{addr}: {error}"
        );
    }
}

#[tokio::test]
async fn min_version_1_3_refuses_an_upstream_that_speaks_only_1_2() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let server = pki.server(&["127.0.0.1"]);
    let tls12 = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS12])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(server.chain(), server.key_der())
    .unwrap();
    let upstream = HttpsUpstream::serve(tls12).await;
    let tls = trusting(pki.write_root(dir.path(), "ca"));

    // 1.2 by default: served.
    opens(client(&upstream.url(), &tls)).await.unwrap();

    let tls = TlsSettings {
        min_version: MinVersion::Tls13,
        ..tls
    };
    let error = opens(client(&upstream.url(), &tls)).await.unwrap_err();
    assert!(error.contains("ProtocolVersion"), "{error}");
    assert_eq!(
        upstream.methods(),
        ["initialize"],
        "only the first was served"
    );
}

/// What `insecure_skip_verify` gives away: an upstream that no root vouches
/// for, under a name its certificate does not carry, is served.
#[tokio::test]
async fn insecure_skip_verify_accepts_what_nothing_vouches_for() {
    let pki = Pki::new("mcpdef test CA");
    let upstream = HttpsUpstream::start(&pki.server(&["elsewhere.test"])).await;
    let tls = TlsSettings {
        insecure_skip_verify: true,
        ..TlsSettings::default()
    };
    assert!(!tls.load().unwrap().verifies());
    assert!(TlsProfile::default().verifies());
    opens(client(&upstream.url(), &tls)).await.unwrap();
    assert_eq!(upstream.methods(), ["initialize"]);
}

/// The gateway's own fetches, a `jwks_uri` among them, go out with a profile
/// too: an identity provider on a private CA is reached with its CA.
#[tokio::test]
async fn a_jwks_on_a_private_ca_is_fetched_with_the_profile_that_trusts_it() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let app = axum::Router::new().route(
        "/jwks.json",
        axum::routing::get(|| async { "{\"keys\":[]}" }),
    );
    let idp = HttpsUpstream::start_app(&pki.server(&["127.0.0.1"]), app).await;
    let url = format!("https://127.0.0.1:{}/jwks.json", idp.addr().port());
    let policy = EgressPolicy::default();

    let error = fetch_text(&url, &policy, &TlsProfile::default())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("UnknownIssuer"), "{error}");

    let tls = trusting(pki.write_root(dir.path(), "ca")).load().unwrap();
    assert_eq!(
        fetch_text(&url, &policy, &tls).await.unwrap(),
        "{\"keys\":[]}"
    );
}
