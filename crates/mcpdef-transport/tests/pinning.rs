// SPDX-License-Identifier: Apache-2.0
//! SPKI pinning: an upstream trusted by its key alone, and the certificate
//! `mcpdef tls pin` reads off a server.

use base64::Engine as _;
use mcpdef_core::{Id, Message};
use mcpdef_testkit::{HttpsUpstream, Leaf, Pki};
use mcpdef_transport::{
    presented_certificate, EgressPolicy, HttpClient, IdentityFiles, MinVersion, Pin, TlsSettings,
    Transport,
};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};

async fn opens(mut client: HttpClient) -> Result<(), String> {
    let initialize = Message::request(Id::Num(1), "initialize", Some(serde_json::json!({})));
    client.send(initialize).await.map_err(|e| e.to_string())
}

fn client(url: &str, tls: &TlsSettings) -> HttpClient {
    HttpClient::streamable(url)
        .unwrap()
        .with_tls(tls.load().unwrap())
        .unwrap()
}

/// The pin of `leaf`'s key, worked out here from its SubjectPublicKeyInfo
/// rather than by the code under test.
fn pin_of(leaf: &Leaf) -> String {
    base64::engine::general_purpose::STANDARD.encode(Sha256::digest(leaf.spki_der()))
}

fn pinned(pins: &[&Leaf]) -> TlsSettings {
    TlsSettings {
        pin_sha256: pins.iter().map(|leaf| pin_of(leaf)).collect(),
        ..TlsSettings::default()
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

async fn refusals(upstream: &HttpsUpstream) -> Vec<String> {
    let until = Instant::now() + Duration::from_secs(5);
    while upstream.refusals().is_empty() && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    upstream.refusals()
}

#[test]
fn a_pin_is_the_sha256_of_the_certificates_key() {
    let leaf = Leaf::self_signed(&["127.0.0.1"]);
    let pin = Pin::of(leaf.cert_der()).unwrap();
    assert_eq!(pin.to_string(), pin_of(&leaf));
    assert_eq!(pin_of(&leaf).parse::<Pin>().unwrap(), pin);
    // A renewal on the same key is another certificate with the same pin.
    let renewed = leaf.renewed();
    assert_ne!(renewed.cert_der(), leaf.cert_der());
    assert_eq!(Pin::of(renewed.cert_der()).unwrap(), pin);
    let other = Leaf::self_signed(&["127.0.0.1"]);
    assert_ne!(Pin::of(other.cert_der()).unwrap(), pin);
}

/// A self-signed upstream: nothing vouches for it, and it calls itself a CA,
/// which a chain check refuses outright. Pinned, it is served.
#[tokio::test]
async fn a_pinned_self_signed_upstream_is_served() {
    let leaf = Leaf::self_signed(&["127.0.0.1"]);
    let upstream = HttpsUpstream::start(&leaf).await;

    let error = opens(HttpClient::streamable(upstream.url()).unwrap())
        .await
        .unwrap_err();
    assert!(error.contains("invalid peer certificate"), "{error}");

    let tls = pinned(&[&leaf]);
    assert!(tls.load().unwrap().is_pinned());
    opens(client(&upstream.url(), &tls)).await.unwrap();
    assert_eq!(upstream.methods(), ["initialize"]);
}

#[tokio::test]
async fn a_wrong_pin_is_refused_naming_the_key_it_saw() {
    let leaf = Leaf::self_signed(&["127.0.0.1"]);
    let upstream = HttpsUpstream::start(&leaf).await;
    let stranger = Leaf::self_signed(&["127.0.0.1"]);

    let error = opens(client(&upstream.url(), &pinned(&[&stranger])))
        .await
        .unwrap_err();
    let expected = format!(
        "no pin_sha256 matches the server's key, whose pin is \"{}\"",
        pin_of(&leaf)
    );
    assert!(error.contains(&expected), "{error}");
    assert!(upstream.methods().is_empty());

    // Among several pins, one that matches is enough: the next key can be
    // pinned before the server moves to it.
    opens(client(&upstream.url(), &pinned(&[&stranger, &leaf])))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_certificate_renewed_on_the_same_key_still_matches() {
    let leaf = Leaf::self_signed(&["127.0.0.1"]);
    let tls = pinned(&[&leaf]);

    let renewed = HttpsUpstream::start(&leaf.renewed()).await;
    opens(client(&renewed.url(), &tls)).await.unwrap();
    assert_eq!(renewed.methods(), ["initialize"]);

    // A new key is a new pin.
    let rekeyed = HttpsUpstream::start(&Leaf::self_signed(&["127.0.0.1"])).await;
    let error = opens(client(&rekeyed.url(), &tls)).await.unwrap_err();
    assert!(error.contains("no pin_sha256 matches"), "{error}");
}

/// Presents a certificate it holds no key for, signing with another key: what
/// someone who copied a server's public certificate could do.
#[derive(Debug)]
struct Impostor(Arc<CertifiedKey>);

impl ResolvesServerCert for Impostor {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// A pin names a key, and only a server that signs the handshake with that
/// key matches it. The pinned certificate itself is public.
#[tokio::test]
async fn a_server_showing_the_pinned_certificate_without_its_key_is_refused() {
    let genuine = Leaf::self_signed(&["127.0.0.1"]);
    let other = Leaf::self_signed(&["127.0.0.1"]);
    let provider = provider();
    let key = provider
        .key_provider
        .load_private_key(other.key_der())
        .unwrap();
    let copied = CertifiedKey::new(vec![genuine.cert_der().clone()], key);
    let config = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Impostor(Arc::new(copied))));
    let impostor = HttpsUpstream::serve(config).await;

    let error = opens(client(&impostor.url(), &pinned(&[&genuine])))
        .await
        .unwrap_err();
    assert!(error.contains("BadSignature"), "{error}");
    assert!(impostor.methods().is_empty());
}

/// A pinned profile's rustls configuration is built by the transport and
/// handed to reqwest whole, so it carries what reqwest's own settings would:
/// the client certificate, the oldest TLS version, and ALPN.
#[tokio::test]
async fn the_pinned_path_presents_a_client_certificate_and_offers_http_1_1() {
    let dir = tempfile::tempdir().unwrap();
    let server = Leaf::self_signed(&["127.0.0.1"]);
    let clients = Pki::new("mcpdef client CA");
    let upstream = HttpsUpstream::start_mtls(&server, &clients, &[]).await;
    let gateway = clients.client("spiffe://example.org/mcpdef");
    let (cert, key) = gateway.write(dir.path(), "gateway");

    // Without a certificate, the upstream refuses the handshake.
    assert!(opens(client(&upstream.url(), &pinned(&[&server])))
        .await
        .is_err());
    let refused = refusals(&upstream).await;
    assert!(
        refused
            .iter()
            .any(|r| r.contains("peer sent no certificates")),
        "{refused:?}"
    );

    let tls = TlsSettings {
        identity: Some(IdentityFiles {
            cert,
            key: key.into(),
        }),
        ..pinned(&[&server])
    };
    opens(client(&upstream.url(), &tls)).await.unwrap();
    assert_eq!(upstream.client_certificates(), [gateway.cert_der().clone()]);
    assert_eq!(upstream.protocols(), [Some("http/1.1".to_string())]);
}

#[tokio::test]
async fn the_pinned_path_keeps_to_the_oldest_tls_version_it_is_given() {
    let leaf = Leaf::self_signed(&["127.0.0.1"]);
    let tls12 = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(leaf.chain(), leaf.key_der())
        .unwrap();
    let upstream = HttpsUpstream::serve(tls12).await;

    opens(client(&upstream.url(), &pinned(&[&leaf])))
        .await
        .unwrap();
    let tls = TlsSettings {
        min_version: MinVersion::Tls13,
        ..pinned(&[&leaf])
    };
    let error = opens(client(&upstream.url(), &tls)).await.unwrap_err();
    assert!(error.contains("ProtocolVersion"), "{error}");
}

/// A name no DNS knows, dialled at the address `connect_to` gives, and
/// verified by its pin: the DNS pinning and the pinned configuration work
/// together.
#[tokio::test]
async fn connect_to_and_a_pin_reach_a_self_signed_upstream_by_name() {
    let leaf = Leaf::self_signed(&["appliance.test"]);
    let upstream = HttpsUpstream::start(&leaf).await;
    let client = client(&upstream.url_for("appliance.test"), &pinned(&[&leaf]))
        .with_connect_to("127.0.0.1".parse().unwrap());
    opens(client).await.unwrap();
    assert_eq!(upstream.methods(), ["initialize"]);
}

/// reqwest takes a preconfigured TLS setup only if it is a `ClientConfig` of
/// the very rustls it was built against. Were the transport's rustls another
/// version, a pinned client would not build ("Unknown TLS backend passed to
/// `use_preconfigured_tls`"), and every test above would fail with it.
/// `deny.toml`'s single-rustls rule refuses such a build first.
#[test]
fn a_pinned_client_builds_on_the_rustls_reqwest_uses() {
    let leaf = Leaf::self_signed(&["127.0.0.1"]);
    let profile = pinned(&[&leaf]).load().unwrap();
    assert!(profile.is_pinned() && profile.verifies());
    HttpClient::streamable("https://127.0.0.1:1/mcp")
        .unwrap()
        .with_tls(profile)
        .unwrap();
}

#[test]
fn a_pinned_profile_reads_no_roots_and_refuses_to_skip_verification() {
    // The host's store is not read: a pinned upstream works on a host
    // without one.
    let leaf = Leaf::self_signed(&["127.0.0.1"]);
    let tls = TlsSettings {
        roots: mcpdef_transport::Roots::System,
        ca: vec!["/nonexistent/ca.pem".into()],
        ..pinned(&[&leaf])
    };
    tls.load().unwrap();

    let lax = TlsSettings {
        insecure_skip_verify: true,
        ..pinned(&[&leaf])
    };
    let error = lax.load().unwrap_err().to_string();
    assert!(error.contains("contradict"), "{error}");

    let garbled = TlsSettings {
        pin_sha256: vec!["kW1v".into()],
        ..TlsSettings::default()
    };
    let error = garbled.load().unwrap_err().to_string();
    assert!(error.contains("pin_sha256 'kW1v' is not a pin"), "{error}");
    assert_eq!(garbled.check().unwrap_err().to_string(), error);
}

#[tokio::test]
async fn the_certificate_a_server_presents_is_read_with_its_pin_and_fingerprint() {
    let pki = Pki::new("mcpdef test CA");
    let leaf = pki
        .leaf()
        .name("upstream.test")
        .uri("spiffe://example.org/upstream")
        .server_auth()
        .issue();
    let upstream = HttpsUpstream::start(&leaf).await;
    let policy = EgressPolicy::default();

    let presented = presented_certificate(&upstream.url(), &policy, None)
        .await
        .unwrap();
    assert_eq!(presented.addr, upstream.addr());
    assert_eq!(presented.cert, *leaf.cert_der());
    assert_eq!(presented.pin.to_string(), pin_of(&leaf));
    let fingerprint: Vec<String> = Sha256::digest(leaf.cert_der().as_ref())
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    assert_eq!(presented.fingerprint(), fingerprint.join(":"));
    assert_eq!(
        presented.names(),
        ["DNS:upstream.test", "URI:spiffe://example.org/upstream"]
    );

    // By name, at the address `connect_to` gives.
    let by_name = presented_certificate(
        &upstream.url_for("upstream.test"),
        &policy,
        Some("127.0.0.1".parse().unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(by_name.pin, presented.pin);
}

/// A server that asks for a client certificate still shows its own first,
/// and signs the handshake with its key before it refuses: that is enough
/// to read the pin from.
#[tokio::test]
async fn the_pin_of_a_server_that_wants_a_client_certificate_can_still_be_read() {
    let server = Leaf::self_signed(&["127.0.0.1"]);
    let clients = Pki::new("mcpdef client CA");
    let upstream = HttpsUpstream::start_mtls(&server, &clients, &[]).await;
    let presented = presented_certificate(&upstream.url(), &EgressPolicy::default(), None)
        .await
        .unwrap();
    assert_eq!(presented.pin.to_string(), pin_of(&server));
}

#[tokio::test]
async fn reading_a_certificate_goes_through_the_egress_guard() {
    let policy = EgressPolicy::default();
    for (url, connect_to) in [
        ("https://169.254.169.254/", None),
        ("https://metadata.test/", Some("169.254.169.254")),
    ] {
        let connect_to = connect_to.map(|ip| ip.parse().unwrap());
        let error = presented_certificate(url, &policy, connect_to)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.starts_with("egress blocked") && error.contains("always blocked"),
            "{url}: {error}"
        );
    }
    let error = presented_certificate("http://127.0.0.1:1/", &policy, None)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("not an https:// URL"), "{error}");
}

/// `mcpdef tls pin` reads the pin of a key the server proves it holds, by
/// signing the handshake with it. A server showing a copied certificate
/// proves nothing, and gets no pin read off it.
#[tokio::test]
async fn reading_a_pin_needs_the_handshake_signed_with_its_key() {
    let genuine = Leaf::self_signed(&["127.0.0.1"]);
    let other = Leaf::self_signed(&["127.0.0.1"]);
    let provider = provider();
    let key = provider
        .key_provider
        .load_private_key(other.key_der())
        .unwrap();
    let copied = CertifiedKey::new(vec![genuine.cert_der().clone()], key);
    let config = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Impostor(Arc::new(copied))));
    let impostor = HttpsUpstream::serve(config).await;

    let error = presented_certificate(&impostor.url(), &EgressPolicy::default(), None)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("presented a certificate"), "{error}");
    assert!(error.contains("BadSignature"), "{error}");
}
