// SPDX-License-Identifier: Apache-2.0
//! SPKI pins: trusting one server's key, whatever certificate carries it.
//!
//! A pin is the SHA-256 of a certificate's SubjectPublicKeyInfo, in base64:
//! RFC 7469's `pin-sha256`, and what curl's `--pinnedpubkey sha256//…` takes.
//! It is the answer to a self-signed upstream: rather than turn verification
//! off, trust exactly the key the server holds. A renewal that keeps the key
//! keeps the pin.
//!
//! A pinned profile is verified by [`PinVerifier`] alone, which reqwest's own
//! TLS settings cannot express, so its rustls configuration is built here and
//! handed to reqwest whole (`tls_backend_preconfigured`). That configuration
//! is only taken when it is a `ClientConfig` of the very rustls reqwest was
//! built against; `deny.toml` keeps the build to one rustls.

use crate::egress::{self, EgressPolicy};
use crate::tls::{MinVersion, TlsProfile};
use crate::TransportError;
use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    verify_tls12_signature, verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, OtherError, SignatureScheme,
    SupportedProtocolVersion,
};
use sha2::{Digest, Sha256};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::{Host, Url};

/// An SPKI pin: the SHA-256 of a SubjectPublicKeyInfo. It reads and prints as
/// base64, the form `pin_sha256` takes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pin([u8; 32]);

impl Pin {
    /// The pin of the key `cert` carries.
    pub fn of(cert: &CertificateDer<'_>) -> Result<Pin, TransportError> {
        let cert = webpki::EndEntityCert::try_from(cert)
            .map_err(|e| TransportError::Tls(format!("the certificate does not parse: {e}")))?;
        let mut pin = [0; 32];
        pin.copy_from_slice(&Sha256::digest(cert.subject_public_key_info().as_ref()));
        Ok(Pin(pin))
    }
}

impl FromStr for Pin {
    type Err = String;

    fn from_str(pin: &str) -> Result<Pin, String> {
        base64::engine::general_purpose::STANDARD
            .decode(pin)
            .ok()
            .and_then(|digest| <[u8; 32]>::try_from(digest).ok())
            .map(Pin)
            .ok_or_else(|| {
                format!(
                    "'{pin}' is not a pin: a pin is the base64 of a SHA-256 digest, 44 \
                     characters, as `mcpdef tls pin` prints it"
                )
            })
    }
}

impl fmt::Display for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&base64::engine::general_purpose::STANDARD.encode(self.0))
    }
}

impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pin({self})")
    }
}

/// Verifies a server by its key: the certificate it presents has to carry a
/// key one of the pins names. Its issuer, names and dates are not checked,
/// which is what lets a self-signed server be trusted, and what a pin means:
/// the key alone. The handshake's signatures are checked with webpki as they
/// are for any server. They are what proves the server holds that key.
#[derive(Debug)]
pub(crate) struct PinVerifier {
    pins: Arc<[Pin]>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinVerifier {
    fn new(pins: Arc<[Pin]>, provider: &CryptoProvider) -> Self {
        PinVerifier {
            pins,
            algorithms: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let pin = Pin::of(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if self.pins.contains(&pin) {
            return Ok(ServerCertVerified::assertion());
        }
        let unpinned = OtherError(Arc::new(Unpinned(pin)));
        Err(rustls::Error::InvalidCertificate(CertificateError::Other(
            unpinned,
        )))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// A server key that no pin names. rustls shows it through `Debug`, so both
/// say the same.
struct Unpinned(Pin);

impl fmt::Display for Unpinned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "no pin_sha256 matches the server's key, whose pin is \"{}\"",
            self.0
        )
    }
}

impl fmt::Debug for Unpinned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for Unpinned {}

/// The rustls configuration of a pinned profile, which reqwest takes whole.
/// None of reqwest's own TLS settings reach it, so it carries what they
/// would: the TLS versions, the client certificate, and ALPN.
pub(crate) fn pinned_config(tls: &TlsProfile) -> Result<ClientConfig, TransportError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions: &[&'static SupportedProtocolVersion] = match tls.min_version {
        MinVersion::Tls12 => rustls::ALL_VERSIONS,
        MinVersion::Tls13 => &[&rustls::version::TLS13],
    };
    let verifier = Arc::new(PinVerifier::new(Arc::clone(&tls.key_pins), &provider));
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| TransportError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut config = match &tls.identity {
        Some(identity) => builder
            .with_client_auth_cert(identity.chain.clone(), identity.key.clone_key())
            .map_err(|e| TransportError::Tls(format!("the client certificate: {e}")))?,
        None => builder.with_no_client_auth(),
    };
    // reqwest speaks HTTP/1.1 alone, and leaves ALPN to a configuration it
    // is handed.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// The certificate a server presented, unverified, as `mcpdef tls pin` shows
/// it.
#[derive(Clone, Debug)]
pub struct PresentedCertificate {
    /// The address that presented it.
    pub addr: SocketAddr,
    /// The certificate itself.
    pub cert: CertificateDer<'static>,
    /// Its key's pin.
    pub pin: Pin,
}

impl PresentedCertificate {
    /// The SHA-256 of the whole certificate, in the colon-separated hex that
    /// `openssl x509 -fingerprint -sha256` prints, to check it against out of
    /// band.
    pub fn fingerprint(&self) -> String {
        crate::cert::fingerprint(self.cert.as_ref())
    }

    /// The DNS names and URIs it is for.
    pub fn names(&self) -> Vec<String> {
        let Ok(cert) = webpki::EndEntityCert::try_from(&self.cert) else {
            return Vec::new();
        };
        let dns = cert.valid_dns_names().map(|name| format!("DNS:{name}"));
        let uris = cert.valid_uri_names().map(|uri| format!("URI:{uri}"));
        dns.chain(uris).collect()
    }
}

/// Keeps the certificate a server presents, and accepts it: trust on first
/// use. The handshake's signature is still checked, so what is kept is the
/// certificate of a key the server holds.
#[derive(Debug)]
struct Keep {
    presented: Mutex<Option<CertificateDer<'static>>>,
    signed: AtomicBool,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Keep {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut presented = self
            .presented
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *presented = Some(end_entity.clone().into_owned());
        self.signed.store(false, Ordering::SeqCst);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let valid = verify_tls12_signature(message, cert, dss, &self.algorithms)?;
        self.signed.store(true, Ordering::SeqCst);
        Ok(valid)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let valid = verify_tls13_signature(message, cert, dss, &self.algorithms)?;
        self.signed.store(true, Ordering::SeqCst);
        Ok(valid)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Connect to `url`'s host, or to `connect_to` for it, through the egress
/// guard, and return the certificate it presents. Nothing about it is
/// verified but the handshake's signature: this is trust on first use, what
/// `mcpdef tls pin` prints for an operator to check out of band.
///
/// The certificate counts once the server has signed the handshake with its
/// key, even if the handshake then fails, as it does on a server that wants a
/// client certificate and gets none.
pub async fn presented_certificate(
    url: &str,
    policy: &EgressPolicy,
    connect_to: Option<IpAddr>,
) -> Result<PresentedCertificate, TransportError> {
    const TIMEOUT: Duration = Duration::from_secs(10);
    let parsed = Url::parse(url).map_err(|e| TransportError::Tls(format!("{url}: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(TransportError::Tls(format!(
            "{url} is not an https:// URL, so there is no certificate to pin"
        )));
    }
    let name = match parsed.host() {
        Some(Host::Domain(domain)) => ServerName::try_from(domain.to_string())
            .map_err(|e| TransportError::Tls(format!("{domain}: {e}")))?,
        Some(Host::Ipv4(ip)) => ServerName::IpAddress(IpAddr::V4(ip).into()),
        Some(Host::Ipv6(ip)) => ServerName::IpAddress(IpAddr::V6(ip).into()),
        None => return Err(TransportError::Tls(format!("{url} has no host"))),
    };
    let work = async {
        let resolved = match connect_to {
            Some(ip) => egress::validate_at(url, ip, policy)?,
            None => egress::validate(url, policy).await?,
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let keep = Arc::new(Keep {
            presented: Mutex::new(None),
            signed: AtomicBool::new(false),
            algorithms: provider.signature_verification_algorithms,
        });
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| TransportError::Tls(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::clone(&keep) as Arc<dyn ServerCertVerifier>)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let mut failures = Vec::new();
        for addr in resolved.addrs {
            let handshake = async {
                let tcp = tokio::net::TcpStream::connect(addr).await?;
                connector.connect(name.clone(), tcp).await
            };
            let failure = match handshake.await {
                Ok(_) => None,
                Err(e) => Some(e.to_string()),
            };
            let presented = keep
                .presented
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            match (presented, keep.signed.load(Ordering::SeqCst)) {
                (Some(cert), true) => {
                    let pin = Pin::of(&cert)?;
                    return Ok(PresentedCertificate { addr, cert, pin });
                }
                _ => failures.push(format!(
                    "{addr}: {}",
                    failure.unwrap_or_else(|| "no certificate".to_string())
                )),
            }
        }
        Err(TransportError::Tls(format!(
            "no server at {url} presented a certificate: {}",
            failures.join("; ")
        )))
    };
    match tokio::time::timeout(TIMEOUT, work).await {
        Ok(presented) => presented,
        Err(_) => Err(TransportError::Tls(format!(
            "{url} did not complete a handshake within {}s",
            TIMEOUT.as_secs()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pin_reads_as_the_base64_of_32_bytes_and_prints_back() {
        let text = "kW1vBnQpOt7wBNmvZG2itgd9KUyIIeTffw1ZmJMRQXg=";
        let pin: Pin = text.parse().unwrap();
        assert_eq!(pin.to_string(), text);
        for bad in [
            "",
            "kW1vBnQpOt7wBNmvZG2itgd9KUyIIeTffw1ZmJMRQXg", // unpadded
            "sha256//kW1vBnQpOt7wBNmvZG2itgd9KUyIIeTffw1ZmJMRQXg=",
            "AAAA", // 3 bytes
            "not base64 at all!",
        ] {
            let error = bad.parse::<Pin>().unwrap_err();
            assert!(error.contains("is not a pin"), "{bad}: {error}");
        }
    }
}
