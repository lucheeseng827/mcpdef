// SPDX-License-Identifier: Apache-2.0
//! A PKI made when a test runs: certificate authorities, the certificates
//! they issue, and the revocation lists they sign.
//!
//! Every key is generated in memory, and reaches the disk only in a file a
//! test writes to a directory of its own. Validity is fixed and wide, from
//! 1975 to 4096, so a certificate is valid whenever the test runs, unless the
//! test asks otherwise.

use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, CertificateRevocationListParams,
    CertifiedIssuer, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod,
    KeyPair, KeyUsagePurpose, PublicKeyData, RevocationReason, RevokedCertParams, SanType,
    SerialNumber,
};
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, PrivatePkcs8KeyDer,
};
use rustls::RootCertStore;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Serial numbers unique within the process, so that a CRL revokes exactly
/// the certificates it names.
static SERIAL: AtomicU64 = AtomicU64::new(1);

fn serial() -> SerialNumber {
    SerialNumber::from(SERIAL.fetch_add(1, Ordering::Relaxed))
}

fn named(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    name
}

/// A name a TLS client asks for, as a certificate carries it: a DNS name, or
/// an IP address.
fn san(name: &str) -> SanType {
    match name.parse::<IpAddr>() {
        Ok(ip) => SanType::IpAddress(ip),
        Err(_) => SanType::DnsName(name.try_into().expect("an ASCII DNS name")),
    }
}

/// A certificate, in both of the forms tests use.
#[derive(Clone)]
struct Cert {
    der: CertificateDer<'static>,
    pem: String,
}

/// A certificate authority: a root, or an intermediate under one.
pub struct Pki {
    issuer: CertifiedIssuer<'static, KeyPair>,
    /// The CA certificates a leaf this CA issues is presented with, after the
    /// leaf itself: this CA's own if it is an intermediate, then those above
    /// it. Empty for a root, which a peer holds as a trust anchor.
    intermediates: Vec<Cert>,
    root: Cert,
}

impl Pki {
    /// A new root CA.
    pub fn new(common_name: &str) -> Pki {
        let key = KeyPair::generate().expect("a key pair");
        let issuer =
            CertifiedIssuer::self_signed(ca_params(common_name), key).expect("a CA certificate");
        let root = Cert {
            der: issuer.der().clone(),
            pem: issuer.pem(),
        };
        Pki {
            issuer,
            intermediates: Vec::new(),
            root,
        }
    }

    /// A new CA, signed by this one.
    pub fn intermediate(&self, common_name: &str) -> Pki {
        let key = KeyPair::generate().expect("a key pair");
        let issuer = CertifiedIssuer::signed_by(ca_params(common_name), key, &self.issuer)
            .expect("a CA certificate");
        let own = Cert {
            der: issuer.der().clone(),
            pem: issuer.pem(),
        };
        let mut intermediates = vec![own];
        intermediates.extend(self.intermediates.iter().cloned());
        Pki {
            issuer,
            intermediates,
            root: self.root.clone(),
        }
    }

    /// A server certificate for `names`: each a DNS name or an IP address.
    pub fn server(&self, names: &[&str]) -> Leaf {
        names
            .iter()
            .fold(self.leaf(), |leaf, name| leaf.name(name))
            .server_auth()
            .issue()
    }

    /// A client certificate whose one identity is `uri`, such as a SPIFFE ID.
    pub fn client(&self, uri: &str) -> Leaf {
        self.leaf().uri(uri).client_auth().issue()
    }

    /// Any other certificate this CA issues.
    pub fn leaf(&self) -> LeafBuilder<'_> {
        let mut params = CertificateParams::default();
        params.distinguished_name = named("mcpdef test certificate");
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.serial_number = Some(serial());
        params.use_authority_key_identifier_extension = true;
        LeafBuilder { ca: self, params }
    }

    /// A CRL, signed by this CA, that revokes `revoked`: certificates this CA
    /// issued.
    pub fn crl(&self, revoked: &[&Leaf]) -> Crl {
        let revoked = revoked
            .iter()
            .map(|leaf| {
                assert!(
                    leaf.issuer == *self.cert_der(),
                    "a CRL comes from the CA that issued what it revokes"
                );
                RevokedCertParams {
                    serial_number: leaf.serial.clone(),
                    revocation_time: date_time_ymd(2020, 1, 1),
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                }
            })
            .collect();
        let params = CertificateRevocationListParams {
            this_update: date_time_ymd(2020, 1, 1),
            next_update: date_time_ymd(4000, 1, 1),
            crl_number: serial(),
            issuing_distribution_point: None,
            revoked_certs: revoked,
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let crl = params.signed_by(&self.issuer).expect("a CRL");
        Crl {
            pem: crl.pem().expect("a CRL in PEM"),
            der: crl.der().clone(),
        }
    }

    /// This CA's own certificate.
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        self.issuer.der()
    }

    /// This CA's own certificate, in PEM.
    pub fn cert_pem(&self) -> String {
        self.issuer.pem()
    }

    /// The root this CA chains to, which a peer trusts: itself, for a root.
    pub fn root_der(&self) -> &CertificateDer<'static> {
        &self.root.der
    }

    /// The root this CA chains to, in PEM.
    pub fn root_pem(&self) -> &str {
        &self.root.pem
    }

    /// A trust store holding just the root.
    pub fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.root.der.clone()).expect("a usable root");
        roots
    }

    /// Write the root to `dir/{stem}.pem`, as a CA file for a config.
    pub fn write_root(&self, dir: &Path, stem: &str) -> PathBuf {
        let path = dir.join(format!("{stem}.pem"));
        std::fs::write(&path, &self.root.pem).expect("the root written");
        path
    }
}

fn ca_params(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = named(common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.serial_number = Some(serial());
    params.use_authority_key_identifier_extension = true;
    params
}

/// What a certificate [`Pki::leaf`] issues says, set one part at a time.
pub struct LeafBuilder<'a> {
    ca: &'a Pki,
    params: CertificateParams,
}

impl LeafBuilder<'_> {
    /// A name a TLS client asks for: a DNS name, or an IP address.
    pub fn name(mut self, name: &str) -> Self {
        self.params.subject_alt_names.push(san(name));
        self
    }

    /// A URI identity, such as a SPIFFE ID.
    pub fn uri(mut self, uri: &str) -> Self {
        let san = SanType::URI(uri.try_into().expect("an ASCII URI"));
        self.params.subject_alt_names.push(san);
        self
    }

    /// An email identity.
    pub fn email(mut self, email: &str) -> Self {
        let san = SanType::Rfc822Name(email.try_into().expect("an ASCII address"));
        self.params.subject_alt_names.push(san);
        self
    }

    /// The subject's common name.
    pub fn common_name(mut self, common_name: &str) -> Self {
        self.params.distinguished_name = named(common_name);
        self
    }

    /// Usable by a TLS server.
    pub fn server_auth(mut self) -> Self {
        let usage = ExtendedKeyUsagePurpose::ServerAuth;
        self.params.extended_key_usages.push(usage);
        self
    }

    /// Usable by a TLS client.
    pub fn client_auth(mut self) -> Self {
        let usage = ExtendedKeyUsagePurpose::ClientAuth;
        self.params.extended_key_usages.push(usage);
        self
    }

    /// Says it is a CA, which a TLS client's certificate must not: for a
    /// check that refuses one.
    pub fn ca(mut self) -> Self {
        self.params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        self
    }

    /// Valid from `not_before` to `not_after`, each `(year, month, day)`:
    /// for a certificate that has expired, or is not valid yet.
    pub fn valid(mut self, not_before: (i32, u8, u8), not_after: (i32, u8, u8)) -> Self {
        self.params.not_before = date_time_ymd(not_before.0, not_before.1, not_before.2);
        self.params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
        self
    }

    /// The certificate, with a key of its own.
    pub fn issue(self) -> Leaf {
        let key = KeyPair::generate().expect("a key pair");
        let cert = self
            .params
            .signed_by(&key, &self.ca.issuer)
            .expect("a certificate");
        let cert = Cert {
            der: cert.der().clone(),
            pem: cert.pem(),
        };
        let mut chain = vec![cert];
        chain.extend(self.ca.intermediates.iter().cloned());
        Leaf {
            chain,
            key,
            serial: self.params.serial_number.clone().expect("a serial number"),
            issuer: self.ca.cert_der().clone(),
            params: self.params,
        }
    }
}

/// A certificate a [`Pki`] issued, or one that is its own issuer, and its key.
pub struct Leaf {
    /// The certificate, then the intermediates it is presented with.
    chain: Vec<Cert>,
    key: KeyPair,
    serial: SerialNumber,
    /// The certificate of the CA that issued it: its own, if self-signed.
    issuer: CertificateDer<'static>,
    /// What it says, for issuing it again.
    params: CertificateParams,
}

impl Leaf {
    /// A certificate that is its own issuer, for `names`, each a DNS name or
    /// an IP address: what a server with no CA makes for itself. Like one
    /// `openssl req -x509` makes, it says it is a CA, which a chain check
    /// refuses in a server's certificate; a pin does not look.
    pub fn self_signed(names: &[&str]) -> Leaf {
        let mut params = CertificateParams::default();
        params.distinguished_name = named(names.first().copied().unwrap_or("self-signed"));
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.subject_alt_names = names.iter().map(|name| san(name)).collect();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.serial_number = Some(serial());
        Leaf::sign_self(params, KeyPair::generate().expect("a key pair"))
    }

    /// This self-signed certificate issued again on the same key, as a
    /// renewal issues it: the same names, a new serial number and a new
    /// signature. Its key, and so its SPKI pin, is the same.
    pub fn renewed(&self) -> Leaf {
        assert!(
            self.issuer == *self.cert_der(),
            "renewed() issues a self-signed certificate again"
        );
        let mut params = self.params.clone();
        params.serial_number = Some(serial());
        let key = KeyPair::try_from(self.key.serialize_der().as_slice()).expect("the same key");
        Leaf::sign_self(params, key)
    }

    fn sign_self(params: CertificateParams, key: KeyPair) -> Leaf {
        let cert = params.self_signed(&key).expect("a certificate");
        let der = cert.der().clone();
        Leaf {
            chain: vec![Cert {
                der: der.clone(),
                pem: cert.pem(),
            }],
            key,
            serial: params.serial_number.clone().expect("a serial number"),
            issuer: der,
            params,
        }
    }

    /// The certificate.
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.chain[0].der
    }

    /// The certificate, in PEM.
    pub fn cert_pem(&self) -> &str {
        &self.chain[0].pem
    }

    /// What a peer presenting this certificate sends: the certificate, then
    /// any intermediate CAs.
    pub fn chain(&self) -> Vec<CertificateDer<'static>> {
        self.chain.iter().map(|cert| cert.der.clone()).collect()
    }

    /// The chain, in PEM.
    pub fn chain_pem(&self) -> String {
        self.chain.iter().map(|cert| cert.pem.as_str()).collect()
    }

    /// The private key, in PKCS#8.
    pub fn key_der(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.key.serialize_der()).into()
    }

    /// The private key, in PKCS#8 PEM.
    pub fn key_pem(&self) -> String {
        self.key.serialize_pem()
    }

    /// The chain, then the key: the PEM a client identity is read from.
    pub fn identity_pem(&self) -> Vec<u8> {
        format!("{}{}", self.chain_pem(), self.key_pem()).into_bytes()
    }

    /// The SubjectPublicKeyInfo, which an SPKI pin is the hash of.
    pub fn spki_der(&self) -> Vec<u8> {
        self.key.subject_public_key_info()
    }

    /// Write the chain to `dir/{stem}.crt` and the key to `dir/{stem}.key`,
    /// readable by the owner alone, and return both paths.
    pub fn write(&self, dir: &Path, stem: &str) -> (PathBuf, PathBuf) {
        let cert = dir.join(format!("{stem}.crt"));
        std::fs::write(&cert, self.chain_pem()).expect("the certificate written");
        let key = dir.join(format!("{stem}.key"));
        write_private(&key, self.key_pem().as_bytes());
        (cert, key)
    }
}

/// A certificate revocation list a [`Pki`] signed.
pub struct Crl {
    der: CertificateRevocationListDer<'static>,
    pem: String,
}

impl Crl {
    pub fn der(&self) -> &CertificateRevocationListDer<'static> {
        &self.der
    }

    pub fn pem(&self) -> &str {
        &self.pem
    }

    /// Write the CRL to `dir/{stem}.crl`, in PEM.
    pub fn write(&self, dir: &Path, stem: &str) -> PathBuf {
        let path = dir.join(format!("{stem}.crl"));
        std::fs::write(&path, &self.pem).expect("the CRL written");
        path
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .expect("the key file");
    file.write_all(bytes).expect("the key written");
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("the key written");
}
