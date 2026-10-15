// SPDX-License-Identifier: Apache-2.0
//! The one TLS stack: rustls, on ring. And the TLS profiles every HTTPS
//! client is built from: the roots it trusts, the CRLs it checks, the
//! certificate it presents, and the oldest version it speaks.

use crate::cert::Verification;
use crate::pin::Pin;
use crate::TransportError;
use base64::Engine as _;
use mcpdef_secrets::{ExposeSecret, SecretError, SecretRef};
use rustls::pki_types::pem::{self, SectionKind};
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use std::fmt;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// Make ring rustls' crypto provider for the whole process, before anything
/// builds a TLS configuration.
///
/// rustls picks a provider by itself only when exactly one is compiled in,
/// and panics at the first TLS configuration when it cannot. Installed up
/// front, ring is the provider for every TLS connection the process makes,
/// whatever else the build comes to contain. `deny.toml` keeps any other
/// provider out of the build to begin with.
///
/// Call it first thing in `main`, and in a test that builds a TLS
/// configuration or a `reqwest` client: `reqwest` panics when it builds a
/// client with no provider installed. The transport's own clients call it as
/// well, so they build in any process. Once a provider is installed, a call
/// changes nothing.
pub fn install_crypto_provider() {
    // An error only means a provider is installed already.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Mozilla's root certificates, bundled into the binary: what an HTTPS
/// upstream is verified against, whatever the host's own store holds.
pub(crate) fn bundled_roots() -> Vec<reqwest::Certificate> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .filter_map(|cert| reqwest::Certificate::from_der(cert).ok())
        .collect()
}

/// Where a TLS profile's trust starts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Roots {
    /// Mozilla's roots, bundled into the binary: the same whatever the host
    /// holds, and what every HTTPS upstream was verified against before
    /// profiles.
    #[default]
    Bundled,
    /// The host's store: the files `SSL_CERT_FILE` and `SSL_CERT_DIR` name,
    /// if either is set, and the system's own otherwise.
    System,
    /// Both of them.
    Both,
}

/// The oldest TLS version a profile speaks. rustls speaks none older than
/// 1.2.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MinVersion {
    #[default]
    Tls12,
    Tls13,
}

/// A client certificate to present, as the file that holds it, and its key,
/// from wherever that is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityFiles {
    /// PEM: the certificate, then any intermediate CA certificates it needs.
    pub cert: PathBuf,
    /// PEM: the key, unencrypted, as PKCS#8, PKCS#1 or SEC1: from a file,
    /// which may hold the certificates too (only its key is read), from an
    /// environment variable, or written in the config.
    pub key: SecretRef,
}

/// A TLS profile as a config gives it: choices, and the files that hold the
/// rest. [`load`](Self::load) reads them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsSettings {
    /// Whose roots to trust.
    pub roots: Roots,
    /// More roots: PEM files of CA certificates.
    pub ca: Vec<PathBuf>,
    /// PEM files of CRLs. A server certificate one of them revokes is
    /// refused. So is one whose status none of them tells: with any CRL,
    /// every certificate in a server's chain needs one from the CA that
    /// issued it, since rustls checks the whole chain.
    pub crl: Vec<PathBuf>,
    pub min_version: MinVersion,
    /// A certificate to present to a server that asks for one.
    pub identity: Option<IdentityFiles>,
    /// Accept whatever certificate a server presents: no chain, name or CRL
    /// is checked.
    pub insecure_skip_verify: bool,
    /// SPKI pins, as `mcpdef tls pin` prints them. With any, a server is
    /// verified by its key alone, and the roots, CAs and CRLs are not read:
    /// see [`Pin`].
    pub pin_sha256: Vec<String>,
}

impl TlsSettings {
    /// Every file these settings name.
    pub fn files(&self) -> Vec<&Path> {
        let identity = self
            .identity
            .iter()
            .flat_map(|i| std::iter::once(i.cert.as_path()).chain(i.key.path()));
        self.ca
            .iter()
            .chain(&self.crl)
            .map(PathBuf::as_path)
            .chain(identity)
            .collect()
    }

    /// Read the files these settings name, and the host's roots if they
    /// trust them, into a profile to build clients from. A pinned profile
    /// reads neither roots nor CRLs, which a pin does not use.
    pub fn load(&self) -> Result<TlsProfile, TransportError> {
        let pins = self.pins()?;
        if !pins.is_empty() {
            if self.insecure_skip_verify {
                return Err(TransportError::Tls(
                    "pin_sha256 and insecure_skip_verify contradict each other".to_string(),
                ));
            }
            let identity = self.identity.as_ref().map(read_identity).transpose()?;
            return Ok(TlsProfile {
                bundled: false,
                identity: identity.map(Arc::new),
                min_version: self.min_version,
                key_pins: pins.into(),
                ..TlsProfile::default()
            });
        }
        let files = self.read()?;
        let mut roots = match self.roots {
            Roots::Bundled => Vec::new(),
            Roots::System | Roots::Both => system_roots()?,
        };
        roots.extend(files.ca);
        Ok(TlsProfile {
            bundled: matches!(self.roots, Roots::Bundled | Roots::Both),
            roots: roots.into(),
            crls: files.crls.into(),
            identity: files.identity.map(Arc::new),
            min_version: self.min_version,
            verify: !self.insecure_skip_verify,
            key_pins: Arc::new([]),
        })
    }

    /// [`load`](Self::load), on a thread kept for blocking work: a client key
    /// that a command writes can take seconds to read, which must not hold up
    /// the tasks that share the caller's thread.
    pub async fn load_async(&self) -> Result<TlsProfile, TransportError> {
        let settings = self.clone();
        crate::blocking(move || settings.load()).await
    }

    /// The pins, read.
    fn pins(&self) -> Result<Vec<Pin>, TransportError> {
        self.pin_sha256
            .iter()
            .map(|pin| {
                pin.parse::<Pin>()
                    .map_err(|e| TransportError::Tls(format!("pin_sha256 {e}")))
            })
            .collect()
    }

    /// How a server is verified under these settings: by its key when they
    /// pin one, not at all when they skip verification, and by its chain
    /// otherwise.
    pub fn verification(&self) -> Verification {
        if !self.pin_sha256.is_empty() {
            Verification::Pin
        } else if self.insecure_skip_verify {
            Verification::Disabled
        } else {
            Verification::Ca
        }
    }

    /// Check the files these settings name, as [`load`](Self::load) reads
    /// them, without reading the host's roots: the host that checks a config
    /// need not be the one that runs it.
    pub fn check(&self) -> Result<(), TransportError> {
        self.read().map(drop)
    }

    fn read(&self) -> Result<Files, TransportError> {
        self.pins()?;
        let mut ca = Vec::new();
        for path in &self.ca {
            ca.extend(read_ca(path)?);
        }
        let mut crls = String::new();
        for path in &self.crl {
            crls.push_str(&read_crls(path)?);
        }
        let identity = self.identity.as_ref().map(read_identity).transpose()?;
        Ok(Files { ca, crls, identity })
    }
}

/// What a profile's files hold.
struct Files {
    ca: Vec<reqwest::Certificate>,
    crls: String,
    identity: Option<Identity>,
}

/// A client certificate and its key, read. Kept as rustls takes them, for a
/// pinned profile's own configuration, and made into reqwest's PEM for the
/// rest. The key is wiped when the identity is dropped.
pub(crate) struct Identity {
    pub(crate) chain: Vec<CertificateDer<'static>>,
    pub(crate) key: PrivateKeyDer<'static>,
}

impl Identity {
    /// The identity as reqwest takes one: PEM, in a buffer made to measure,
    /// since one that grew would leave a copy of the key behind, and wiped
    /// once reqwest has read it.
    pub(crate) fn to_reqwest(&self) -> Result<reqwest::Identity, TransportError> {
        let label = match &self.key {
            PrivateKeyDer::Pkcs1(_) => "RSA PRIVATE KEY",
            PrivateKeyDer::Sec1(_) => "EC PRIVATE KEY",
            _ => "PRIVATE KEY",
        };
        let certs: String = self
            .chain
            .iter()
            .map(|cert| to_pem("CERTIFICATE", cert))
            .collect();
        let key = Zeroizing::new(to_pem(label, self.key.secret_der()));
        let mut pem = Zeroizing::new(String::with_capacity(certs.len() + key.len()));
        pem.push_str(&certs);
        pem.push_str(&key);
        reqwest::Identity::from_pem(pem.as_bytes())
            .map_err(|e| TransportError::Tls(format!("the client certificate: {e}")))
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// A TLS profile, read: what an HTTPS client trusts, checks and presents.
/// Cheap to clone. The transport builds each of its clients from one.
#[derive(Clone)]
pub struct TlsProfile {
    /// Trust Mozilla's roots, bundled into the binary. They are made afresh
    /// for each client rather than held, as they always were.
    pub(crate) bundled: bool,
    /// The other roots: the host's, if the profile trusts them, and its
    /// extra CAs.
    pub(crate) roots: Arc<[reqwest::Certificate]>,
    /// Its CRLs, as PEM; empty for none.
    pub(crate) crls: Arc<str>,
    pub(crate) identity: Option<Arc<Identity>>,
    pub(crate) min_version: MinVersion,
    pub(crate) verify: bool,
    /// The keys it trusts, when it is pinned: then nothing else counts.
    pub(crate) key_pins: Arc<[Pin]>,
}

impl Default for TlsProfile {
    /// Mozilla's roots, bundled into the binary, and nothing else.
    fn default() -> Self {
        TlsProfile {
            bundled: true,
            roots: Arc::new([]),
            crls: "".into(),
            identity: None,
            min_version: MinVersion::Tls12,
            verify: true,
            key_pins: Arc::new([]),
        }
    }
}

impl TlsProfile {
    /// Whether it checks the certificate a server presents: by its chain, or
    /// by its key when pinned.
    pub fn verifies(&self) -> bool {
        self.verify
    }

    /// Whether it trusts a server by its key alone.
    pub fn is_pinned(&self) -> bool {
        !self.key_pins.is_empty()
    }

    /// The certificate it presents, the first of its client identity's, if it
    /// has one.
    pub(crate) fn client_certificate(&self) -> Option<&[u8]> {
        Some(self.identity.as_ref()?.chain.first()?.as_ref())
    }

    /// How it verifies a server.
    pub fn verification(&self) -> Verification {
        if self.is_pinned() {
            Verification::Pin
        } else if !self.verify {
            Verification::Disabled
        } else {
            Verification::Ca
        }
    }
}

impl fmt::Debug for TlsProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsProfile")
            .field("bundled", &self.bundled)
            .field("roots", &self.roots.len())
            .field("crls", &!self.crls.is_empty())
            .field("identity", &self.identity.is_some())
            .field("min_version", &self.min_version)
            .field("verify", &self.verify)
            .field("key_pins", &self.key_pins)
            .finish()
    }
}

/// The host's roots: those `SSL_CERT_FILE` and `SSL_CERT_DIR` name, if either
/// is set, and the system's otherwise. A certificate that cannot be a root
/// is left out, as rustls leaves it out; finding none at all is an error.
fn system_roots() -> Result<Vec<reqwest::Certificate>, TransportError> {
    let found = rustls_native_certs::load_native_certs();
    let roots: Vec<reqwest::Certificate> = found
        .certs
        .iter()
        .filter(|der| webpki::anchor_from_trusted_cert(der).is_ok())
        .filter_map(|der| reqwest::Certificate::from_der(der).ok())
        .collect();
    if roots.is_empty() {
        let errors: Vec<String> = found.errors.iter().map(ToString::to_string).collect();
        let why = match errors.is_empty() {
            true => String::new(),
            false => format!(": {}", errors.join("; ")),
        };
        return Err(TransportError::Tls(format!(
            "roots: the host's CA store has no certificate to trust{why}. Install the \
             system's CA certificates, or point SSL_CERT_FILE at a PEM bundle"
        )));
    }
    Ok(roots)
}

/// What a listener checks a client's certificate against: the CA
/// certificates it has to chain to, and the CRLs.
pub struct ClientTrust {
    pub roots: Vec<CertificateDer<'static>>,
    pub crls: Vec<CertificateRevocationListDer<'static>>,
}

/// The CA certificates and CRLs in `ca` and `crl`, `[gateway.tls.client_auth]`'s,
/// read by the rules an upstream's are read by: PEM only, each CA one that
/// can be a root, and each CRL one that parses. The errors name them `ca`
/// and `crl`, for the caller to say which table they are in.
pub fn read_client_trust(ca: &[PathBuf], crl: &[PathBuf]) -> Result<ClientTrust, TransportError> {
    let mut roots = Vec::new();
    for path in ca {
        roots.extend(ca_ders(path)?);
    }
    let mut crls = Vec::new();
    for path in crl {
        crls.extend(crl_ders(path)?);
    }
    Ok(ClientTrust { roots, crls })
}

/// The CA certificates in a PEM file, each one usable as a root.
fn read_ca(path: &Path) -> Result<Vec<reqwest::Certificate>, TransportError> {
    ca_ders(path)?
        .iter()
        .map(|der| {
            reqwest::Certificate::from_der(der).map_err(|e| tls_error("ca", path.display(), e))
        })
        .collect()
}

/// [`read_ca`], as DER.
fn ca_ders(path: &Path) -> Result<Vec<CertificateDer<'static>>, TransportError> {
    let mut certs = Vec::new();
    for (kind, der) in read_pem("ca", path)? {
        if kind != SectionKind::Certificate {
            return Err(tls_error(
                "ca",
                path.display(),
                only("CA certificates", kind),
            ));
        }
        let der = CertificateDer::from(der);
        let n = certs.len() + 1;
        webpki::anchor_from_trusted_cert(&der).map_err(|e| {
            tls_error(
                "ca",
                path.display(),
                format!("certificate {n} cannot be a root: {e}"),
            )
        })?;
        certs.push(der);
    }
    if certs.is_empty() {
        return Err(tls_error(
            "ca",
            path.display(),
            "holds no certificate (-----BEGIN CERTIFICATE-----)",
        ));
    }
    Ok(certs)
}

/// The CRLs in a PEM file, each one checked to parse, as PEM.
fn read_crls(path: &Path) -> Result<String, TransportError> {
    Ok(crl_ders(path)?
        .iter()
        .map(|der| to_pem("X509 CRL", der))
        .collect())
}

/// [`read_crls`], as DER.
fn crl_ders(path: &Path) -> Result<Vec<CertificateRevocationListDer<'static>>, TransportError> {
    let mut crls = Vec::new();
    for (n, (kind, der)) in read_pem("crl", path)?.into_iter().enumerate() {
        if kind != SectionKind::Crl {
            return Err(tls_error("crl", path.display(), only("CRLs", kind)));
        }
        webpki::OwnedCertRevocationList::from_der(&der).map_err(|e| {
            tls_error(
                "crl",
                path.display(),
                format!("CRL {} does not parse: {e}", n + 1),
            )
        })?;
        crls.push(CertificateRevocationListDer::from(der));
    }
    if crls.is_empty() {
        return Err(tls_error(
            "crl",
            path.display(),
            "holds no CRL (-----BEGIN X509 CRL-----)",
        ));
    }
    Ok(crls)
}

/// A client identity: the certificates in its certificate file, and the one
/// key its key holds, which has to be a key ring signs with and has to match
/// the first certificate.
fn read_identity(files: &IdentityFiles) -> Result<Identity, TransportError> {
    read_certified(files, ["client_cert", "client_key"]).map(|(identity, _)| identity)
}

/// The certificate a listener serves, and its key: `[gateway.tls]`'s `cert`
/// and `key`. They are read by the rules a client certificate is read by:
/// PEM only, the certificate first in its file and any intermediates after
/// it, and the one unencrypted key its source holds, which has to match that
/// certificate and be one ring signs with. The errors name them `cert` and
/// `key`, for the caller to say which table they are in.
pub fn read_served(files: &IdentityFiles) -> Result<rustls::sign::CertifiedKey, TransportError> {
    read_certified(files, ["cert", "key"]).map(|(_, certified)| certified)
}

/// A certificate chain and its key, read, and the two as rustls signs with
/// them. `what` names the certificate and the key in the errors.
fn read_certified(
    files: &IdentityFiles,
    [cert, key_name]: [&str; 2],
) -> Result<(Identity, rustls::sign::CertifiedKey), TransportError> {
    let chain: Vec<CertificateDer<'static>> = read_pem(cert, &files.cert)?
        .into_iter()
        .filter(|(kind, _)| *kind == SectionKind::Certificate)
        .map(|(_, der)| CertificateDer::from(der))
        .collect();
    if chain.is_empty() {
        return Err(tls_error(
            cert,
            files.cert.display(),
            "holds no certificate (-----BEGIN CERTIFICATE-----)",
        ));
    }
    let secret = match files.key.resolve() {
        Ok(secret) => secret,
        // A file that is not text is DER or PKCS#12, and read again to say
        // which, and how to make it PEM.
        Err(SecretError::NotText(path)) => {
            let bytes = Zeroizing::new(std::fs::read(&path).unwrap_or_default());
            return Err(tls_error(
                key_name,
                path.display(),
                not_pem(key_name, &bytes),
            ));
        }
        Err(e) => return Err(TransportError::Tls(format!("{key_name} {e}"))),
    };
    let pem = secret.expose_secret().as_bytes();
    if matches!(files.key, SecretRef::Literal(_)) && !contains(pem, b"-----BEGIN ") {
        return Err(tls_error(
            key_name,
            &files.key,
            format!(
                "a string is the key itself, and this one holds no PEM: to read the key \
                 from a file, write {key_name} = {{ file = \"/path/to/key.pem\" }}"
            ),
        ));
    }
    let mut keys: Vec<PrivateKeyDer<'static>> = parse_pem(key_name, &files.key, pem)?
        .into_iter()
        .filter_map(|(kind, der)| match kind {
            SectionKind::PrivateKey => Some(PrivateKeyDer::Pkcs8(der.into())),
            SectionKind::RsaPrivateKey => Some(PrivateKeyDer::Pkcs1(der.into())),
            SectionKind::EcPrivateKey => Some(PrivateKeyDer::Sec1(der.into())),
            _ => None,
        })
        .collect();
    if keys.len() != 1 {
        let n = keys.len();
        keys.iter_mut().for_each(Zeroize::zeroize);
        return Err(tls_error(
            key_name,
            &files.key,
            match n {
                0 => "holds no private key: no PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY \
                      section"
                    .to_string(),
                n => format!("holds {n} private keys: give it the one for {cert}"),
            },
        ));
    }
    let key = keys.remove(0);
    let provider = rustls::crypto::ring::default_provider();
    let certified = rustls::sign::CertifiedKey::from_der(chain.clone(), key.clone_key(), &provider)
        .map_err(|e| match e {
            rustls::Error::InconsistentKeys(rustls::InconsistentKeys::KeyMismatch) => {
                format!(
                    "does not match the certificate first in {cert} {}",
                    files.cert.display()
                )
            }
            e => e.to_string(),
        });
    // Made an identity first, so that a key refused here is wiped too.
    let identity = Identity { chain, key };
    match certified {
        Ok(certified) => Ok((identity, certified)),
        Err(why) => Err(tls_error(key_name, &files.key, why)),
    }
}

/// The PEM sections in a file, each with what it holds: see [`parse_pem`].
fn read_pem(what: &str, path: &Path) -> Result<Vec<(SectionKind, Vec<u8>)>, TransportError> {
    let bytes = std::fs::read(path).map_err(|e| tls_error(what, path.display(), e))?;
    parse_pem(what, &path.display(), &bytes)
}

/// The PEM sections in `bytes`, read from `from`, each with what it holds.
///
/// A section with a label rustls does not know is skipped, so what would
/// otherwise go missing unexplained is refused up front: bytes that are not
/// PEM at all, and an encrypted key.
fn parse_pem(
    what: &str,
    from: &dyn fmt::Display,
    bytes: &[u8],
) -> Result<Vec<(SectionKind, Vec<u8>)>, TransportError> {
    if !contains(bytes, b"-----BEGIN ") {
        return Err(tls_error(what, from, not_pem(what, bytes)));
    }
    // Matched without its `BEGIN`, which a scan for committed keys looks for.
    if contains(bytes, b"ENCRYPTED PRIVATE KEY-----") || contains(bytes, b"Proc-Type: 4,ENCRYPTED")
    {
        return Err(tls_error(
            what,
            from,
            "holds an encrypted key, and MCPdef reads an unencrypted one: decrypt it with \
             `openssl pkey -in FILE -out key.pem`, and keep that file readable by MCPdef alone",
        ));
    }
    let mut reader = Cursor::new(bytes);
    let mut sections = Vec::new();
    while let Some(section) = pem::from_buf(&mut reader)
        .map_err(|e| tls_error(what, from, format!("is not valid PEM: {e}")))?
    {
        sections.push(section);
    }
    Ok(sections)
}

/// Why a file that has no PEM in it is refused, and how to make it PEM.
fn not_pem(what: &str, bytes: &[u8]) -> String {
    if is_pkcs12(bytes) {
        return "is PKCS#12, and MCPdef reads PEM only: split it with `openssl pkcs12 -in FILE \
                -nokeys -out cert.pem` and `openssl pkcs12 -in FILE -nocerts -nodes -out key.pem`"
            .to_string();
    }
    let tool = match what {
        "crl" => "openssl crl",
        key if key.ends_with("key") => "openssl pkey",
        _ => "openssl x509",
    };
    format!(
        "is not PEM, and MCPdef reads PEM only: if it is DER, convert it with `{tool} -inform DER \
         -in FILE -out FILE.pem`"
    )
}

/// Whether `bytes` look like a PKCS#12 bundle: a DER SEQUENCE whose first
/// member is the INTEGER 3, the version every one has.
fn is_pkcs12(bytes: &[u8]) -> bool {
    let [0x30, len, rest @ ..] = bytes else {
        return false;
    };
    let skip = match *len {
        0..=0x7f => 0,
        0x81..=0x84 => usize::from(*len - 0x80),
        _ => return false,
    };
    rest.get(skip..skip + 3) == Some(&[0x02, 0x01, 0x03][..])
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The refusal of a file that holds something besides `wanted`.
fn only(wanted: &str, found: SectionKind) -> String {
    format!(
        "holds a {} section, where it should hold {wanted} only",
        label(found)
    )
}

/// The PEM label of a section.
fn label(kind: SectionKind) -> &'static str {
    match kind {
        SectionKind::Certificate => "CERTIFICATE",
        SectionKind::PublicKey => "PUBLIC KEY",
        SectionKind::RsaPrivateKey => "RSA PRIVATE KEY",
        SectionKind::PrivateKey => "PRIVATE KEY",
        SectionKind::EcPrivateKey => "EC PRIVATE KEY",
        SectionKind::Crl => "X509 CRL",
        SectionKind::Csr => "CERTIFICATE REQUEST",
        SectionKind::EchConfigList => "ECHCONFIG",
        _ => "unrecognised",
    }
}

/// `der` as a PEM section. A key goes through here, so the buffer is made
/// to measure, since one that grew would leave copies behind, and the base64
/// is wiped.
fn to_pem(label: &str, der: &[u8]) -> String {
    let body = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(der));
    let lines = body.len().div_ceil(64);
    let mut pem = String::with_capacity(32 + 2 * label.len() + body.len() + lines);
    for part in ["-----BEGIN ", label, "-----\n"] {
        pem.push_str(part);
    }
    for line in body.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    for part in ["-----END ", label, "-----\n"] {
        pem.push_str(part);
    }
    pem
}

/// The refusal of `what`, read from `from`: a file's path, or a secret's
/// place.
fn tls_error(what: &str, from: impl fmt::Display, e: impl fmt::Display) -> TransportError {
    TransportError::Tls(format!("{what} {from}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pkcs12_bundle_is_told_from_other_der() {
        // The start of a PFX: SEQUENCE (long form), INTEGER 3.
        assert!(is_pkcs12(&[0x30, 0x82, 0x0a, 0x1b, 0x02, 0x01, 0x03, 0x30]));
        assert!(is_pkcs12(&[0x30, 0x40, 0x02, 0x01, 0x03]));
        // A certificate: SEQUENCE, then its tbsCertificate SEQUENCE.
        assert!(!is_pkcs12(&[0x30, 0x82, 0x03, 0x01, 0x30, 0x82, 0x02]));
        // A PKCS#8 key: SEQUENCE, INTEGER 0.
        assert!(!is_pkcs12(&[0x30, 0x81, 0x87, 0x02, 0x01, 0x00]));
        assert!(!is_pkcs12(b"-----BEGIN CERTIFICATE-----"));
        assert!(!is_pkcs12(&[0x30]));
        assert!(!is_pkcs12(&[]));
    }

    #[test]
    fn pem_lines_are_64_characters_and_read_back() {
        let der: Vec<u8> = (0..=255).collect();
        let pem = to_pem("X509 CRL", &der);
        assert!(pem.lines().all(|line| line.len() <= 64));
        // Made to measure: a buffer that had grown would have left a copy of
        // what it held behind, a key's included.
        assert_eq!(pem.len(), pem.capacity());
        for n in [0, 1, 47, 48, 49, 96] {
            let pem = to_pem("PRIVATE KEY", &der[..n]);
            assert_eq!(pem.len(), pem.capacity(), "{n} bytes");
        }
        let mut reader = Cursor::new(pem.as_bytes());
        let (kind, back) = pem::from_buf(&mut reader).unwrap().unwrap();
        assert_eq!(kind, SectionKind::Crl);
        assert_eq!(back, der);
    }
}
