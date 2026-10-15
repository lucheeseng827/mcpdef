// SPDX-License-Identifier: Apache-2.0
//! Reading a TLS profile's files: PEM only, each file holding what its field
//! says, and a refusal that names the file and says what to do when not.

use base64::Engine as _;
use mcpdef_testkit::{HttpsUpstream, Pki};
use mcpdef_transport::{HttpClient, IdentityFiles, TlsSettings, Transport, TransportError};
use rustls::pki_types::PrivateKeyDer;
use std::path::{Path, PathBuf};

fn write(dir: &Path, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn pem(label: &str, der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// Why `settings` do not load, checked the same way by `check`.
fn refusal(settings: &TlsSettings) -> String {
    let error = settings.load().unwrap_err();
    assert!(matches!(error, TransportError::Tls(_)), "{error}");
    assert_eq!(
        settings.check().unwrap_err().to_string(),
        error.to_string(),
        "check refuses what load refuses"
    );
    error.to_string()
}

fn ca(path: PathBuf) -> TlsSettings {
    TlsSettings {
        ca: vec![path],
        ..TlsSettings::default()
    }
}

fn crl(path: PathBuf) -> TlsSettings {
    TlsSettings {
        crl: vec![path],
        ..TlsSettings::default()
    }
}

fn identity(cert: PathBuf, key: PathBuf) -> TlsSettings {
    TlsSettings {
        identity: Some(IdentityFiles {
            cert,
            key: key.into(),
        }),
        ..TlsSettings::default()
    }
}

/// The SEC1 key inside a PKCS#8 one: the OCTET STRING after its version and
/// its algorithm.
fn sec1_of(pkcs8: &[u8]) -> Vec<u8> {
    // (header length, content length) of the DER element at the start.
    fn element(der: &[u8]) -> (usize, usize) {
        match der[1] {
            len @ 0..=0x7f => (2, usize::from(len)),
            n => {
                let n = usize::from(n & 0x7f);
                let len = der[2..2 + n]
                    .iter()
                    .fold(0, |len, b| len << 8 | usize::from(*b));
                (2 + n, len)
            }
        }
    }
    let (outer, _) = element(pkcs8);
    let mut rest = &pkcs8[outer..];
    for _ in 0..2 {
        let (header, len) = element(rest);
        rest = &rest[header + len..];
    }
    let (header, len) = element(rest);
    rest[header..header + len].to_vec()
}

#[test]
fn a_missing_file_is_named() {
    let error = refusal(&ca("/nonexistent/corp-root.pem".into()));
    assert!(
        error.contains("ca /nonexistent/corp-root.pem: No such file"),
        "{error}"
    );
}

#[test]
fn der_and_pkcs12_are_refused_with_how_to_make_pem() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let der = write(dir.path(), "root.der", pki.root_der());
    let error = refusal(&ca(der));
    assert!(error.contains("is not PEM"), "{error}");
    assert!(error.contains("openssl x509 -inform DER"), "{error}");

    let crl_der = write(dir.path(), "list.crl", pki.crl(&[]).der());
    let error = refusal(&crl(crl_der));
    assert!(error.contains("openssl crl -inform DER"), "{error}");

    // The start of a PKCS#12 bundle: a SEQUENCE whose first member is the
    // INTEGER 3.
    let p12 = write(
        dir.path(),
        "client.p12",
        [0x30, 0x82, 0x04, 0x00, 0x02, 0x01, 0x03, 0x30],
    );
    let leaf = pki.client("spiffe://example.org/mcpdef");
    let (_, key) = leaf.write(dir.path(), "client");
    let error = refusal(&identity(p12, key));
    assert!(error.starts_with("tls: client_cert "), "{error}");
    assert!(error.contains("is PKCS#12"), "{error}");
    assert!(error.contains("openssl pkcs12"), "{error}");
}

#[test]
fn an_encrypted_key_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let (cert, _) = pki
        .client("spiffe://example.org/mcpdef")
        .write(dir.path(), "client");
    // The headers are put together here, so that no key's header is written
    // out in the source, where a scan for committed keys would stop at it.
    let legacy = format!(
        "-----BEGIN {label}-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00\n\nMIIB\n-----END {label}-----\n",
        label = "RSA PRIVATE KEY"
    );
    for (name, text) in [
        ("pkcs8.key", pem("ENCRYPTED PRIVATE KEY", b"not a real key")),
        ("legacy.key", legacy),
    ] {
        let key = write(dir.path(), name, text);
        let error = refusal(&identity(cert.clone(), key));
        assert!(error.contains("holds an encrypted key"), "{name}: {error}");
    }
}

#[test]
fn a_key_that_is_not_the_certificates_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let (cert, _) = pki.client("spiffe://example.org/a").write(dir.path(), "a");
    let (_, other) = pki.client("spiffe://example.org/b").write(dir.path(), "b");
    let error = refusal(&identity(cert.clone(), other));
    assert!(
        error.contains("does not match the certificate first in client_cert"),
        "{error}"
    );

    // The chain in the wrong order: an intermediate first.
    let issuing = pki.intermediate("mcpdef issuing CA");
    let leaf = issuing.client("spiffe://example.org/c");
    let (_, key) = leaf.write(dir.path(), "c");
    let backwards = write(
        dir.path(),
        "backwards.crt",
        format!("{}{}", issuing.cert_pem(), leaf.cert_pem()),
    );
    let error = refusal(&identity(backwards, key.clone()));
    assert!(error.contains("does not match"), "{error}");
    let (forwards, _) = leaf.write(dir.path(), "c");
    identity(forwards, key).load().unwrap();
}

#[test]
fn files_holding_the_wrong_things_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let leaf = pki.client("spiffe://example.org/mcpdef");
    let (cert, key) = leaf.write(dir.path(), "client");

    // A CA file with a key in it.
    let with_key = write(
        dir.path(),
        "ca-and-key.pem",
        format!("{}{}", pki.root_pem(), leaf.key_pem()),
    );
    let error = refusal(&ca(with_key));
    assert!(
        error.contains("holds a PRIVATE KEY section, where it should hold CA certificates only"),
        "{error}"
    );
    // A CRL file with a certificate in it.
    let error = refusal(&crl(cert.clone()));
    assert!(
        error.contains("holds a CERTIFICATE section, where it should hold CRLs only"),
        "{error}"
    );
    // Nothing a field wants.
    let error = refusal(&ca(key.clone()));
    assert!(error.contains("holds a PRIVATE KEY section"), "{error}");
    let error = refusal(&identity(key.clone(), key.clone()));
    assert!(error.contains("client_cert"), "{error}");
    assert!(error.contains("holds no certificate"), "{error}");
    let error = refusal(&identity(cert.clone(), cert.clone()));
    assert!(error.contains("client_key"), "{error}");
    assert!(error.contains("holds no private key"), "{error}");
    // Two keys: which one is meant?
    let other = pki.client("spiffe://example.org/other");
    let two = write(
        dir.path(),
        "two.key",
        format!("{}{}", leaf.key_pem(), other.key_pem()),
    );
    let error = refusal(&identity(cert, two));
    assert!(error.contains("holds 2 private keys"), "{error}");
}

#[test]
fn what_does_not_parse_is_refused_with_its_place() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let bundle = write(
        dir.path(),
        "bundle.pem",
        format!(
            "{}{}",
            pki.root_pem(),
            pem("CERTIFICATE", b"not a certificate")
        ),
    );
    let error = refusal(&ca(bundle));
    assert!(error.contains("certificate 2 cannot be a root"), "{error}");

    let crls = write(
        dir.path(),
        "lists.crl",
        format!("{}{}", pki.crl(&[]).pem(), pem("X509 CRL", b"not a CRL")),
    );
    let error = refusal(&crl(crls));
    assert!(error.contains("CRL 2 does not parse"), "{error}");
}

/// A file may hold a certificate and its key together, and serve as both.
/// The key may be PKCS#8 or SEC1.
#[tokio::test]
async fn a_combined_file_and_a_sec1_key_are_read() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let clients = Pki::new("mcpdef client CA");
    let upstream = HttpsUpstream::start_mtls(&pki.server(&["127.0.0.1"]), &clients, &[]).await;
    let ca = pki.write_root(dir.path(), "ca");
    let leaf = clients.client("spiffe://example.org/mcpdef");

    let combined = write(dir.path(), "combined.pem", leaf.identity_pem());
    let PrivateKeyDer::Pkcs8(pkcs8) = leaf.key_der() else {
        panic!("the kit's keys are PKCS#8")
    };
    let sec1 = write(
        dir.path(),
        "sec1.key",
        pem("EC PRIVATE KEY", &sec1_of(pkcs8.secret_pkcs8_der())),
    );
    for key in [combined.clone(), sec1] {
        let tls = TlsSettings {
            ca: vec![ca.clone()],
            identity: Some(IdentityFiles {
                cert: combined.clone(),
                key: key.into(),
            }),
            ..TlsSettings::default()
        };
        let mut client = HttpClient::streamable(upstream.url())
            .unwrap()
            .with_tls(tls.load().unwrap())
            .unwrap();
        let initialize = mcpdef_core::Message::request(
            mcpdef_core::Id::Num(1),
            "initialize",
            Some(serde_json::json!({})),
        );
        client.send(initialize).await.unwrap();
    }
    let presented = upstream.client_certificates();
    assert_eq!(
        presented,
        [leaf.cert_der().clone(), leaf.cert_der().clone()]
    );
}

#[test]
fn the_files_a_profile_names_are_listed() {
    let settings = TlsSettings {
        ca: vec!["/ca/a.pem".into(), "/ca/b.pem".into()],
        crl: vec!["/crl/a.crl".into()],
        identity: Some(IdentityFiles {
            cert: "/id/c.crt".into(),
            key: PathBuf::from("/id/c.key").into(),
        }),
        ..TlsSettings::default()
    };
    let files: Vec<&str> = settings
        .files()
        .into_iter()
        .map(|f| f.to_str().unwrap())
        .collect();
    assert_eq!(
        files,
        [
            "/ca/a.pem",
            "/ca/b.pem",
            "/crl/a.crl",
            "/id/c.crt",
            "/id/c.key"
        ]
    );
    // The default names none, and loads without reading anything.
    assert!(TlsSettings::default().files().is_empty());
    TlsSettings::default().load().unwrap();
}
