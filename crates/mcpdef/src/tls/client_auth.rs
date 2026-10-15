// SPDX-License-Identifier: Apache-2.0
//! mTLS on MCPdef's own listeners (`[gateway.tls.client_auth]`): a client's
//! certificate, checked at the handshake, and read as who the client is.
//!
//! **Checked by rustls.** Its `WebPkiClientVerifier` checks the chain to
//! `ca`, the dates, that the certificate is for a TLS client, and, with
//! `crl`, revocation, every CA in the chain included. A certificate that
//! says it is a CA is refused as a client's. It checks no names.
//!
//! **Read by MCPdef.** Which name is the client's identity is MCPdef's own
//! code, here, on the names [`CertificateNames`] reads, as `identity` says:
//! - `spiffe`: the certificate's one SPIFFE ID, under the X509-SVID rules:
//!   exactly one URI name, a `spiffe://` URI with a well-formed trust domain
//!   and path, its trust domain one of `trust_domains`;
//! - `san-dns`: its first DNS name;
//! - `san-email`: its first email address;
//! - `subject-cn`: its subject's common name.
//!
//! A certificate that gives no identity this way refuses the request it
//! carries: a client is never taken for no one when it presented someone.
//!
//! **Checked again after a reload.** A connection keeps the certificate it
//! presented at its handshake. When a reload builds the listener's check
//! again, with what may be a new CA or a new CRL, the next request on a
//! connection already open checks that certificate again against it, so a
//! certificate a new CRL revokes is refused from then on, on every
//! connection. One that expires while its connection is open is refused from
//! its next request.
//!
//! **Forwarded by a trusted proxy** (see [`forwarded`](super::forwarded)): a
//! certificate no handshake of MCPdef's own checked is checked here, as one
//! presented at it would be, before a request relies on it.

use crate::config::{CertIdentity, ClientAuthConfig, ClientAuthMode};
use mcpdef_transport::{CertificateNames, PeerCertificate, TransportError};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// The last generation handed out: each [`ClientCerts`] built has one of its
/// own, from 1.
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// The generation of no [`ClientCerts`]: a certificate none has checked.
const UNCHECKED: u64 = 0;

/// The longest SPIFFE ID the SPIFFE ID rules allow, in bytes.
const SPIFFE_ID_MAX: usize = 2048;

/// The longest trust domain name the SPIFFE ID rules allow, in bytes.
const TRUST_DOMAIN_MAX: usize = 255;

/// What a listener asks of a client's certificate, as its config said when
/// this was built: rustls' check of the chain, and which name is the
/// client's identity.
pub struct ClientCerts {
    verifier: Arc<dyn ClientCertVerifier>,
    mode: ClientAuthMode,
    identity: CertIdentity,
    trust_domains: Vec<String>,
    /// Unique in the process: a certificate an earlier build checked is
    /// checked again by this one before a request relies on it.
    generation: u64,
}

impl std::fmt::Debug for ClientCerts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCerts")
            .field("mode", &self.mode)
            .field("identity", &self.identity)
            .field("trust_domains", &self.trust_domains)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl ClientCerts {
    /// What `config`, the table `table` names, asks of a client's
    /// certificate: its CAs and CRLs read now. `None` when it asks for none.
    pub fn build(table: &str, config: &ClientAuthConfig) -> Result<Option<Arc<Self>>, String> {
        if !config.mode.is_on() {
            return Ok(None);
        }
        let mode = config.mode.as_str();
        let identity = config
            .identity
            .ok_or_else(|| format!("{table} mode = \"{mode}\" needs `identity`"))?;
        if config.ca.is_empty() {
            return Err(format!("{table} mode = \"{mode}\" needs `ca`"));
        }
        let paths = |files: &[String]| files.iter().map(PathBuf::from).collect::<Vec<_>>();
        let trust = mcpdef_transport::read_client_trust(&paths(&config.ca), &paths(&config.crl))
            .map_err(|e| match e {
                TransportError::Tls(e) => format!("{table} {e}"),
                e => format!("{table} {e}"),
            })?;
        let mut roots = RootCertStore::empty();
        for der in trust.roots {
            roots.add(der).map_err(|e| format!("{table} ca: {e}"))?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
            .with_crls(trust.crls);
        if config.mode == ClientAuthMode::Optional {
            verifier = verifier.allow_unauthenticated();
        }
        let verifier = verifier
            .build()
            .map_err(|e| format!("{table} client certificates: {e}"))?;
        Ok(Some(Arc::new(ClientCerts {
            verifier,
            mode: config.mode,
            identity,
            trust_domains: config.trust_domains.clone(),
            generation: GENERATION.fetch_add(1, Ordering::Relaxed) + 1,
        })))
    }

    /// rustls' check of a client's chain, for the listener's `ServerConfig`.
    pub(crate) fn verifier(&self) -> Arc<dyn ClientCertVerifier> {
        Arc::clone(&self.verifier)
    }

    /// Whether a client may go without a certificate.
    pub fn mode(&self) -> ClientAuthMode {
        self.mode
    }

    /// The certificate a client presented at a handshake this check passed,
    /// as a connection keeps it. `None` when it presented none.
    pub(crate) fn presented(&self, chain: Option<&[CertificateDer<'_>]>) -> Option<Arc<Presented>> {
        let chain = chain?.iter().map(|der| der.clone().into_owned()).collect();
        Presented::new(chain, self.generation).map(Arc::new)
    }

    /// Whether `presented` still checks out, as of `now`: it has not expired,
    /// and, if an earlier build checked it, this one passes it too. Why not,
    /// if it does not.
    pub fn admit(&self, presented: &Presented, now: SystemTime) -> Result<(), String> {
        let since = now.duration_since(UNIX_EPOCH).unwrap_or_default();
        if presented
            .not_after
            .is_some_and(|not_after| i64::try_from(since.as_secs()).unwrap_or(i64::MAX) > not_after)
        {
            return Err("it has expired".to_string());
        }
        if presented.checked.load(Ordering::Acquire) == self.generation {
            return Ok(());
        }
        let Some((leaf, intermediates)) = presented.chain.split_first() else {
            return Err("it holds no certificate".to_string());
        };
        self.verifier
            .verify_client_cert(leaf, intermediates, UnixTime::since_unix_epoch(since))
            .map_err(|e| e.to_string())?;
        presented.checked.store(self.generation, Ordering::Release);
        Ok(())
    }

    /// The identity `presented` gives, as `identity` reads it, or why it
    /// gives none.
    pub fn identity(&self, presented: &Presented) -> Result<String, String> {
        let names = &presented.names;
        let first = |prefix: &str| {
            names
                .alt_names
                .iter()
                .find_map(|name| name.strip_prefix(prefix))
                .map(str::to_string)
        };
        let identity = match self.identity {
            CertIdentity::Spiffe => spiffe_id(names, &self.trust_domains)?,
            CertIdentity::SanDns => first("DNS:").ok_or("it has no DNS name")?,
            CertIdentity::SanEmail => first("email:").ok_or("it has no email address")?,
            CertIdentity::SubjectCn => names
                .subject
                .clone()
                .ok_or("its subject has no common name")?,
        };
        if identity.is_empty() || identity.chars().any(char::is_control) {
            return Err(format!(
                "its {} is empty, or holds a control character",
                self.identity.as_str()
            ));
        }
        Ok(identity)
    }
}

/// The certificate a client presented at a connection's handshake, as the
/// connection keeps it; or one a trusted proxy forwarded, as a request
/// carries it.
#[derive(Debug)]
pub struct Presented {
    /// As the client sent it: its certificate, then any intermediates.
    chain: Vec<CertificateDer<'static>>,
    names: CertificateNames,
    /// When it expires, in seconds since the Unix epoch.
    not_after: Option<i64>,
    /// The generation of the [`ClientCerts`] that last checked it.
    checked: AtomicU64,
}

impl Presented {
    /// `chain`, a certificate then its intermediates, as checked by the
    /// generation `checked`. `None` when it holds none.
    fn new(chain: Vec<CertificateDer<'static>>, checked: u64) -> Option<Presented> {
        let leaf = chain.first()?;
        Some(Presented {
            names: CertificateNames::read(leaf),
            not_after: PeerCertificate::read(leaf).not_after,
            chain,
            checked: AtomicU64::new(checked),
        })
    }

    /// A certificate then its intermediates, as a trusted proxy forwarded
    /// them: checked by no [`ClientCerts`] yet, so
    /// [`admit`](ClientCerts::admit) checks it whole. `None` when `chain`
    /// holds none.
    pub fn forwarded(chain: Vec<CertificateDer<'static>>) -> Option<Presented> {
        Self::new(chain, UNCHECKED)
    }
}

/// The one SPIFFE ID among `names`, under the X509-SVID rules, if its trust
/// domain is one of `trust_domains`; or why there is none.
fn spiffe_id(names: &CertificateNames, trust_domains: &[String]) -> Result<String, String> {
    let uris: Vec<&str> = names
        .alt_names
        .iter()
        .filter_map(|name| name.strip_prefix("URI:"))
        .collect();
    let [id] = uris[..] else {
        return Err(format!(
            "it has {} URI names, where an X509-SVID has exactly one, its SPIFFE ID",
            uris.len()
        ));
    };
    let domain = spiffe_trust_domain(id)?;
    if !trust_domains.iter().any(|allowed| allowed == domain) {
        return Err(format!(
            "its SPIFFE ID is in trust domain {domain:?}, which is not one of trust_domains"
        ));
    }
    Ok(id.to_string())
}

/// The trust domain of the SPIFFE ID `id`, or why `id` is not one: under the
/// SPIFFE ID rules, `spiffe://`, a trust domain, then a path whose segments
/// are letters, digits, `.`, `-` and `_`, none of them empty, `.` or `..`.
pub fn spiffe_trust_domain(id: &str) -> Result<&str, String> {
    if id.len() > SPIFFE_ID_MAX {
        return Err(format!(
            "its URI name is longer than a SPIFFE ID may be, {SPIFFE_ID_MAX} bytes"
        ));
    }
    let Some(rest) = id.strip_prefix("spiffe://") else {
        return Err("its URI name is not a SPIFFE ID: it does not start with spiffe://".into());
    };
    let (domain, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    if let Some(why) = trust_domain_problem(domain) {
        return Err(format!("its SPIFFE ID's trust domain {domain:?} {why}"));
    }
    let segment_ok = |segment: &str| {
        !matches!(segment, "" | "." | "..")
            && segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    };
    if let Some(segments) = path.strip_prefix('/') {
        if !segments.split('/').all(segment_ok) {
            return Err(format!(
                "its SPIFFE ID's path {path:?} is not one a SPIFFE ID may have: segments of \
                 letters, digits, '.', '-' and '_', none of them empty, '.' or '..'"
            ));
        }
    }
    Ok(domain)
}

/// Why `domain` cannot be a SPIFFE trust domain, if it cannot: one is
/// lowercase letters, digits, `.`, `-` and `_`, and at most 255 bytes.
pub fn trust_domain_problem(domain: &str) -> Option<String> {
    if domain.is_empty() {
        return Some("is empty".to_string());
    }
    if domain.len() > TRUST_DOMAIN_MAX {
        return Some(format!(
            "is longer than a trust domain may be, {TRUST_DOMAIN_MAX} bytes"
        ));
    }
    let allowed =
        |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_');
    if !domain.chars().all(allowed) {
        return Some(
            "is not a trust domain: one is lowercase letters, digits, '.', '-' and '_', \
             written without spiffe://"
                .to_string(),
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpdef_testkit::{Crl, Leaf, Pki};
    use std::path::Path;
    use std::time::Duration;

    const BOT: &str = "spiffe://prod.acme.internal/ns/ci/sa/bot";

    /// What `[gateway.tls.client_auth]` asks under `identity`, with `pki`'s
    /// root as its one CA, and `crls`, its files written to `dir`.
    fn certs(dir: &Path, pki: &Pki, identity: CertIdentity, crls: &[&Crl]) -> Arc<ClientCerts> {
        let ca = pki.write_root(dir, "ca");
        let crl = crls
            .iter()
            .enumerate()
            .map(|(n, crl)| crl.write(dir, &format!("crl{n}")).display().to_string())
            .collect();
        let config = ClientAuthConfig {
            mode: ClientAuthMode::Required,
            ca: vec![ca.display().to_string()],
            crl,
            identity: Some(identity),
            trust_domains: vec!["prod.acme.internal".into()],
        };
        ClientCerts::build("[gateway.tls.client_auth]", &config)
            .unwrap()
            .unwrap()
    }

    /// `leaf` as a connection keeps it, checked by `certs` at its handshake.
    fn presented(certs: &ClientCerts, leaf: &Leaf) -> Arc<Presented> {
        certs.presented(Some(&leaf.chain())).unwrap()
    }

    #[test]
    fn each_identity_mode_reads_one_name() {
        let dir = tempfile::tempdir().unwrap();
        let pki = Pki::new("agents CA");
        let leaf = pki
            .leaf()
            .common_name("ci bot")
            .name("a.acme.internal")
            .email("bot@acme.internal")
            .uri(BOT)
            .name("b.acme.internal")
            .email("ops@acme.internal")
            .client_auth()
            .issue();
        for (identity, read) in [
            (CertIdentity::Spiffe, BOT),
            (CertIdentity::SanDns, "a.acme.internal"),
            (CertIdentity::SanEmail, "bot@acme.internal"),
            (CertIdentity::SubjectCn, "ci bot"),
        ] {
            let certs = certs(dir.path(), &pki, identity, &[]);
            assert_eq!(
                certs.identity(&presented(&certs, &leaf)),
                Ok(read.to_string())
            );
        }

        // A certificate without the name its mode reads gives no identity.
        let bare = pki.leaf().uri(BOT).client_auth().issue();
        for (identity, why) in [
            (CertIdentity::SanDns, "it has no DNS name"),
            (CertIdentity::SanEmail, "it has no email address"),
        ] {
            let certs = certs(dir.path(), &pki, identity, &[]);
            assert_eq!(
                certs.identity(&presented(&certs, &bare)),
                Err(why.to_string())
            );
        }
        let certs = certs(dir.path(), &pki, CertIdentity::SubjectCn, &[]);
        for name in ["", "ci\nbot", "ci\u{7}bot"] {
            let leaf = pki.leaf().common_name(name).client_auth().issue();
            assert_eq!(
                certs.identity(&presented(&certs, &leaf)),
                Err("its subject-cn is empty, or holds a control character".to_string()),
                "{name:?}"
            );
        }
    }

    #[test]
    fn a_new_build_checks_an_open_connections_certificate_again() {
        let dir = tempfile::tempdir().unwrap();
        let pki = Pki::new("agents CA");
        let bot = pki.client(BOT);
        let first = certs(dir.path(), &pki, CertIdentity::Spiffe, &[]);
        let kept = presented(&first, &bot);
        let now = SystemTime::now();
        assert_eq!(first.admit(&kept, now), Ok(()));

        // Built again, as a reload builds it: the certificate passes again.
        let again = certs(dir.path(), &pki, CertIdentity::Spiffe, &[]);
        assert_ne!(again.generation, first.generation);
        assert_eq!(again.admit(&kept, now), Ok(()));
        // Once: a build that checked it does not check it again, so not even a
        // time before it was valid fails it.
        let early = UNIX_EPOCH + Duration::from_secs(86_400);
        assert_eq!(again.admit(&kept, early), Ok(()));
        // With a CRL that revokes it: refused, and refused again.
        let crl = pki.crl(&[&bot]);
        let revoking = certs(dir.path(), &pki, CertIdentity::Spiffe, &[&crl]);
        for _ in 0..2 {
            assert_eq!(
                revoking.admit(&kept, now),
                Err("invalid peer certificate: Revoked".to_string())
            );
        }
        // With another CA in place of the one that issued it: refused.
        let other = certs(
            dir.path(),
            &Pki::new("another CA"),
            CertIdentity::Spiffe,
            &[],
        );
        assert!(other
            .admit(&kept, now)
            .unwrap_err()
            .contains("UnknownIssuer"));

        // Expired while its connection is open: refused from then on, by the
        // build that checked it too.
        let later = now + Duration::from_secs(5_000 * 366 * 86_400);
        assert_eq!(first.admit(&kept, later), Err("it has expired".to_string()));
    }

    #[test]
    fn a_certificate_from_an_intermediate_is_checked_again_with_its_chain() {
        let dir = tempfile::tempdir().unwrap();
        let root = Pki::new("agents root");
        let issuing = root.intermediate("agents issuing CA");
        let bot = issuing.client(BOT);
        let first = certs(dir.path(), &root, CertIdentity::Spiffe, &[]);
        let kept = presented(&first, &bot);
        let again = certs(dir.path(), &root, CertIdentity::Spiffe, &[]);
        assert_eq!(again.admit(&kept, SystemTime::now()), Ok(()));
        assert_eq!(again.identity(&kept), Ok(BOT.to_string()));
    }

    #[test]
    fn no_chain_is_no_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let pki = Pki::new("agents CA");
        let certs = certs(dir.path(), &pki, CertIdentity::Spiffe, &[]);
        assert!(certs.presented(None).is_none());
        assert!(certs.presented(Some(&[])).is_none());
    }

    #[test]
    fn a_table_that_asks_for_nothing_builds_nothing() {
        let config = ClientAuthConfig::default();
        assert!(ClientCerts::build("[gateway.tls.client_auth]", &config)
            .unwrap()
            .is_none());
    }

    fn names(alt_names: &[&str], subject: Option<&str>) -> CertificateNames {
        CertificateNames {
            subject: subject.map(str::to_string),
            issuer: Some("mcpdef test CA".to_string()),
            alt_names: alt_names.iter().map(|n| n.to_string()).collect(),
        }
    }

    #[test]
    fn a_spiffe_id_follows_the_spiffe_id_rules() {
        for good in [
            "spiffe://prod.acme.internal/ns/ci/sa/bot",
            "spiffe://example.org",
            "spiffe://a_b-c.9/x/Y.z/-_",
        ] {
            assert!(spiffe_trust_domain(good).is_ok(), "{good}");
        }
        assert_eq!(
            spiffe_trust_domain("spiffe://prod.acme.internal/ns/ci"),
            Ok("prod.acme.internal")
        );
        for (bad, why) in [
            (
                "https://prod.acme.internal/ns",
                "does not start with spiffe://",
            ),
            (
                "SPIFFE://prod.acme.internal/ns",
                "does not start with spiffe://",
            ),
            ("spiffe:///ns/ci", "trust domain \"\" is empty"),
            ("spiffe://Prod.acme/ns", "is not a trust domain"),
            ("spiffe://acme:8443/ns", "is not a trust domain"),
            ("spiffe://user@acme/ns", "is not a trust domain"),
            ("spiffe://acme/ns/", "is not one a SPIFFE ID may have"),
            ("spiffe://acme/", "is not one a SPIFFE ID may have"),
            ("spiffe://acme//ns", "is not one a SPIFFE ID may have"),
            (
                "spiffe://acme/ns/../admin",
                "is not one a SPIFFE ID may have",
            ),
            ("spiffe://acme/ns/./ci", "is not one a SPIFFE ID may have"),
            ("spiffe://acme/ns?ci=1", "is not one a SPIFFE ID may have"),
            ("spiffe://acme/ns#ci", "is not one a SPIFFE ID may have"),
            ("spiffe://acme/n%41s", "is not one a SPIFFE ID may have"),
        ] {
            let e = spiffe_trust_domain(bad).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
        let long = format!("spiffe://acme/{}", "a".repeat(SPIFFE_ID_MAX));
        assert!(spiffe_trust_domain(&long)
            .unwrap_err()
            .contains("longer than a SPIFFE ID may be"));
        assert!(trust_domain_problem(&"a".repeat(TRUST_DOMAIN_MAX)).is_none());
        assert!(trust_domain_problem(&"a".repeat(TRUST_DOMAIN_MAX + 1)).is_some());
    }

    #[test]
    fn an_x509_svid_has_exactly_one_uri_name_in_an_allowed_trust_domain() {
        let domains = ["prod.acme.internal".to_string()];
        let id = "spiffe://prod.acme.internal/ns/ci/sa/bot";
        let uri = format!("URI:{id}");
        // DNS names beside the one URI are allowed.
        assert_eq!(
            spiffe_id(&names(&["DNS:bot.acme.internal", &uri], None), &domains),
            Ok(id.to_string())
        );
        assert_eq!(
            spiffe_id(&names(&["DNS:bot.acme.internal"], None), &domains),
            Err("it has 0 URI names, where an X509-SVID has exactly one, its SPIFFE ID".into())
        );
        let two = names(
            &[&uri, "URI:spiffe://prod.acme.internal/ns/ci/sa/other"],
            None,
        );
        assert!(spiffe_id(&two, &domains)
            .unwrap_err()
            .starts_with("it has 2 URI names"));
        // A URI name that is not a SPIFFE ID is still the one URI name.
        assert!(
            spiffe_id(&names(&["URI:https://acme.internal/bot"], None), &domains)
                .unwrap_err()
                .contains("does not start with spiffe://")
        );
        assert_eq!(
            spiffe_id(
                &names(&["URI:spiffe://staging.acme.internal/bot"], None),
                &domains
            ),
            Err(
                "its SPIFFE ID is in trust domain \"staging.acme.internal\", which is not one of \
                 trust_domains"
                    .into()
            )
        );
        // A trust domain that ends where an allowed one does is another.
        assert!(spiffe_id(
            &names(&["URI:spiffe://evil-prod.acme.internal/bot"], None),
            &domains
        )
        .is_err());
    }
}
