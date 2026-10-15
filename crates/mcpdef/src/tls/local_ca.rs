// SPDX-License-Identifier: Apache-2.0
//! The local CA behind `[gateway.tls] mode = "self-signed"`, and the
//! certificate it issues the gateway's listeners.
//!
//! **A CA and a short-lived certificate under it, not a bare self-signed
//! certificate.** A client trusts the CA once. The certificate the listeners
//! serve lasts [`LEAF_LIFETIME`] and is issued again well before it runs out,
//! without anyone trusting anything again.
//!
//! **The CA vouches for a few names and no others.** It is made with a name
//! constraint, which clients check: `localhost`, the loopback addresses, the
//! addresses the listeners bind to, and the configured `hostnames`. So its
//! key, were it stolen, could not mint a certificate for any other name that
//! a client trusting it would believe. The price is that a name added later
//! needs a new CA, and every client to trust that one instead.
//!
//! **The CA is read back from its key alone.** Its certificate is kept for
//! clients to trust. Issuing needs only its key and its name, and its name is
//! made from its key, so nothing parses the certificate to use the CA. Each
//! certificate it issues is checked as a client that trusts it would check
//! it, before it is used.
//!
//! **It issues clients' certificates too** (`mcpdef tls issue`), and revokes
//! them by serial in its CRL (`mcpdef tls revoke`): see
//! [`issued`](super::issued).
//!
//! Its files are under `<state_dir>/tls/`: `ca.crt` and `ca.key`, then
//! `tls.crt` and `tls.key`, and once it has issued a client's certificate,
//! `ca.crl` and `revoked.json`. The directory is `0700` and the keys `0600`.
//! Each pair is written beside where it goes and renamed into place, the
//! certificate first, with the one it replaces set aside until the key has
//! landed too: a full disk or a failed rename leaves the old pair as it was,
//! never a certificate with a key that is not its own.

use mcpdef_secrets::{ExposeSecret, SecretRef};
use mcpdef_transport::{read_served, CertificateNames, IdentityFiles, PeerCertificate};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CidrSubnet,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyIdMethod,
    KeyPair, KeyUsagePurpose, NameConstraints, PublicKeyData, RevokedCertParams, SanType,
    SerialNumber,
};
use rustls::client::danger::ServerCertVerifier;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::sign::CertifiedKey;
use rustls::RootCertStore;
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// How long the CA is valid: ten years. Every client trusts it by hand.
pub const CA_LIFETIME: Duration = Duration::from_secs(3_650 * 86_400);
/// How long a certificate it issues is valid: thirty days.
pub const LEAF_LIFETIME: Duration = Duration::from_secs(30 * 86_400);
/// How much of a certificate's life is left when it is issued again: ten
/// days, a third of it.
pub const RENEW_BEFORE: Duration = Duration::from_secs(10 * 86_400);
/// How far before it is made a certificate's validity starts, so that a
/// client whose clock runs a little behind still takes one made a moment ago.
const BACKDATE: Duration = Duration::from_secs(3_600);

/// A name a certificate is for: a DNS name, or an IP address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Name {
    Dns(String),
    Ip(IpAddr),
}

impl Name {
    /// `name` as a certificate names it: an IP address if it is one, and
    /// otherwise a DNS name, in lower case and without a final dot.
    pub fn parse(name: &str) -> Name {
        match name.trim_matches(['[', ']']).parse::<IpAddr>() {
            Ok(ip) => Name::Ip(ip),
            Err(_) => Name::Dns(name.trim_end_matches('.').to_ascii_lowercase()),
        }
    }

    /// As a certificate's subjectAltName lists it, and as
    /// [`CertificateNames`] reads it back: `DNS:…` or `IP:…`.
    fn alt_name(&self) -> String {
        match self {
            Name::Dns(name) => format!("DNS:{name}"),
            Name::Ip(ip) => format!("IP:{ip}"),
        }
    }

    fn san(&self) -> Result<SanType, String> {
        Ok(match self {
            Name::Dns(name) => SanType::DnsName(
                name.as_str()
                    .try_into()
                    .map_err(|_| format!("{name:?} is not an ASCII DNS name"))?,
            ),
            Name::Ip(ip) => SanType::IpAddress(*ip),
        })
    }

    /// What the CA may vouch for, for this name: the name and every name
    /// under it; a whole loopback block for a loopback address, and any
    /// other address alone.
    fn subtree(&self) -> GeneralSubtree {
        match self {
            Name::Dns(name) => GeneralSubtree::DnsName(name.clone()),
            Name::Ip(IpAddr::V4(ip)) if ip.is_loopback() => {
                GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix([127, 0, 0, 0], 8))
            }
            Name::Ip(ip @ IpAddr::V4(_)) => {
                GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(*ip, 32))
            }
            Name::Ip(ip @ IpAddr::V6(_)) => {
                GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(*ip, 128))
            }
        }
    }

    /// What a client asks for, when it connects by this name.
    fn server_name(&self) -> Result<ServerName<'static>, String> {
        match self {
            Name::Dns(name) => ServerName::try_from(name.clone())
                .map_err(|_| format!("{name:?} is not a DNS name")),
            Name::Ip(ip) => Ok(ServerName::IpAddress((*ip).into())),
        }
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Name::Dns(name) => f.write_str(name),
            Name::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// What a listener certificate is for, each name once, in order: always
/// `localhost`, `127.0.0.1` and `::1`, then the rest. The CA is made to vouch
/// for the names of the first certificate it issues.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Names(Vec<Name>);

impl Names {
    /// `localhost`, `127.0.0.1` and `::1`, then `more`.
    pub fn new<S: AsRef<str>>(more: impl IntoIterator<Item = S>) -> Names {
        let mut names: Vec<Name> = Vec::new();
        let always = ["localhost", "127.0.0.1", "::1"].map(Name::parse);
        for name in always
            .into_iter()
            .chain(more.into_iter().map(|n| Name::parse(n.as_ref())))
        {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        Names(names)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Name> {
        self.0.iter()
    }

    /// As a certificate's subjectAltName lists them.
    fn alt_names(&self) -> Vec<String> {
        self.0.iter().map(Name::alt_name).collect()
    }

    /// What the CA may vouch for, for these names, each subtree once.
    fn subtrees(&self) -> Vec<GeneralSubtree> {
        let mut subtrees = Vec::new();
        for subtree in self.0.iter().map(Name::subtree) {
            if !subtrees.contains(&subtree) {
                subtrees.push(subtree);
            }
        }
        subtrees
    }
}

impl fmt::Display for Names {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<String> = self.0.iter().map(Name::to_string).collect();
        f.write_str(&names.join(", "))
    }
}

/// Where the CA and the listener certificate are kept: `<state_dir>/tls/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    dir: PathBuf,
}

impl Paths {
    /// The files under `state_dir`.
    pub fn under(state_dir: impl AsRef<Path>) -> Paths {
        Paths {
            dir: state_dir.as_ref().join("tls"),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The CA's certificate: what a client trusts.
    pub fn ca_cert(&self) -> PathBuf {
        self.dir.join("ca.crt")
    }

    pub fn ca_key(&self) -> PathBuf {
        self.dir.join("ca.key")
    }

    /// The certificate the listeners serve.
    pub fn cert(&self) -> PathBuf {
        self.dir.join("tls.crt")
    }

    pub fn key(&self) -> PathBuf {
        self.dir.join("tls.key")
    }

    /// The CA's CRL: the certificates it issued clients that are revoked.
    pub fn crl(&self) -> PathBuf {
        self.dir.join("ca.crl")
    }

    /// What is revoked, and when, and the number of the last CRL: what each
    /// CRL is written from.
    pub fn revoked(&self) -> PathBuf {
        self.dir.join("revoked.json")
    }
}

/// The CA's certificate kept at `paths`, as PEM, if there is one: what a
/// client trusts. Its key is not read, so any user who can read the
/// certificate can hand it out.
pub fn ca_cert_pem(paths: &Paths) -> Result<Option<String>, String> {
    let path = paths.ca_cert();
    if !present(&path) {
        return Ok(None);
    }
    let pem = std::fs::read_to_string(&path)
        .map_err(|e| format!("reading the local CA {}: {e}", path.display()))?;
    CertificateDer::from_pem_slice(pem.as_bytes()).map_err(|e| {
        format!(
            "the local CA {} holds no certificate that reads: {e}",
            path.display()
        )
    })?;
    Ok(Some(pem))
}

/// The local CA: its certificate, which clients trust, and its key, which
/// issues the listeners' certificates.
pub struct LocalCa {
    cert: CertificateDer<'static>,
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl LocalCa {
    /// A new CA that vouches for `names` and nothing else, valid for
    /// [`CA_LIFETIME`] from `now`.
    pub fn new(names: &Names, now: SystemTime) -> Result<LocalCa, String> {
        let key = KeyPair::generate().map_err(|e| format!("making the local CA's key: {e}"))?;
        let mut params = ca_params(&key);
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: names.subtrees(),
            excluded_subtrees: Vec::new(),
        });
        params.not_before = datetime(now.checked_sub(BACKDATE).unwrap_or(now));
        params.not_after = datetime(later(now, CA_LIFETIME)?);
        let cert = params
            .self_signed(&key)
            .map_err(|e| format!("making the local CA's certificate: {e}"))?;
        Ok(LocalCa {
            cert_pem: cert.pem(),
            cert: cert.der().clone(),
            issuer: Issuer::new(params, key),
        })
    }

    /// The CA kept at `paths`, or `None` when neither its certificate nor
    /// its key is there.
    pub fn load(paths: &Paths) -> Result<Option<LocalCa>, String> {
        let (cert, key) = (paths.ca_cert(), paths.ca_key());
        match (present(&cert), present(&key)) {
            (false, false) => return Ok(None),
            (true, true) => {}
            (have_cert, _) => {
                let missing = if have_cert { &key } else { &cert };
                return Err(format!(
                    "the local CA in {} is half there, {} is missing: make a new one with \
                     `mcpdef tls init --new-ca`, and have every client trust it",
                    paths.dir.display(),
                    missing.display()
                ));
            }
        }
        let cert_pem = std::fs::read_to_string(&cert)
            .map_err(|e| format!("reading the local CA {}: {e}", cert.display()))?;
        let der = CertificateDer::from_pem_slice(cert_pem.as_bytes()).map_err(|e| {
            format!(
                "the local CA {} holds no certificate that reads: {e}",
                cert.display()
            )
        })?;
        let secret = SecretRef::File(key.clone())
            .resolve()
            .map_err(|e| format!("reading the local CA's key: {e}"))?;
        let key_pair = KeyPair::from_pem(secret.expose_secret())
            .map_err(|e| format!("the local CA's key {} does not read: {e}", key.display()))?;
        // Its name is made from its key, as when it was made.
        let params = ca_params(&key_pair);
        let ca = LocalCa {
            cert: der,
            cert_pem,
            issuer: Issuer::new(params, key_pair),
        };
        ca.consistent().map_err(|e| {
            format!(
                "the local CA's key {} is not the one its certificate {} was made with ({e}): \
                 make a new CA with `mcpdef tls init --new-ca`, and have every client trust it",
                key.display(),
                cert.display()
            )
        })?;
        Ok(Some(ca))
    }

    /// Whether its key and name are its certificate's: a certificate it
    /// issues for `localhost`, which every local CA vouches for, has to
    /// check against its certificate, at a time both are valid.
    fn consistent(&self) -> Result<(), String> {
        let until = self
            .not_after()
            .ok_or("its certificate has no end date that reads")?;
        let at = UNIX_EPOCH + Duration::from_secs(until.saturating_sub(86_400).max(0) as u64);
        let localhost = Names(vec![Name::parse("localhost")]);
        let probe = self.sign(&localhost, at)?;
        self.check(probe.cert_der(), &localhost, at)
    }

    /// Write the CA to `paths`, over any there.
    pub fn write(&self, paths: &Paths) -> Result<(), String> {
        let key = Zeroizing::new(self.issuer.key().serialize_pem());
        write_pair(
            &paths.dir,
            (&paths.ca_cert(), &self.cert_pem),
            (&paths.ca_key(), &key),
        )
    }

    /// Its certificate, which clients trust.
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// When it expires, in seconds since the Unix epoch.
    pub fn not_after(&self) -> Option<i64> {
        PeerCertificate::read(&self.cert).not_after
    }

    /// A certificate for `names`, valid from `now` for [`LEAF_LIFETIME`], or
    /// until the CA expires if that comes first. It is checked before it is
    /// returned, as a client that trusts the CA checks it, for each name: a
    /// name the CA does not vouch for is refused, and named.
    pub fn issue(&self, names: &Names, now: SystemTime) -> Result<Leaf, String> {
        let leaf = self.sign(names, now)?;
        if self.check(&leaf.cert, names, now).is_err() {
            let outside: Vec<String> = names
                .iter()
                .filter(|name| {
                    let one = Names(vec![(*name).clone()]);
                    self.sign(&one, now)
                        .and_then(|probe| self.check(&probe.cert, &one, now))
                        .is_err()
                })
                .map(Name::to_string)
                .collect();
            return Err(match outside.is_empty() {
                // Each name alone checks, and all of them together do not.
                true => self.check(&leaf.cert, names, now).unwrap_err(),
                false => format!(
                    "the local CA vouches only for the names it was made with, and not for {}: \
                     make a new one that does with `mcpdef tls init --new-ca`, and have every \
                     client trust it in place of this one",
                    outside.join(", ")
                ),
            });
        }
        Ok(leaf)
    }

    /// Why it cannot issue at `now`, if it cannot: it has expired.
    fn usable(&self, now: SystemTime) -> Result<(), String> {
        match self.not_after() {
            Some(ca) if now >= UNIX_EPOCH + Duration::from_secs(ca.max(0) as u64) => Err(format!(
                "the local CA expired at {}: make a new one with `mcpdef tls init --new-ca`, \
                 and have every client trust it in place of this one",
                mcpdef_transport::rfc3339(ca)
            )),
            _ => Ok(()),
        }
    }

    /// When a certificate issued at `now` for `lifetime` ends: then, or when
    /// the CA does, if that is sooner.
    fn until(&self, now: SystemTime, lifetime: Duration) -> Result<SystemTime, String> {
        let until = later(now, lifetime)?;
        Ok(match self.not_after() {
            Some(ca) => until.min(UNIX_EPOCH + Duration::from_secs(ca.max(0) as u64)),
            None => until,
        })
    }

    /// Issue, unchecked.
    fn sign(&self, names: &Names, now: SystemTime) -> Result<Leaf, String> {
        self.usable(now)?;
        let key = KeyPair::generate().map_err(|e| format!("making a key: {e}"))?;
        let mut params = CertificateParams::default();
        let mut subject = DistinguishedName::new();
        subject.push(DnType::CommonName, "localhost");
        params.distinguished_name = subject;
        params.subject_alt_names = names.iter().map(Name::san).collect::<Result<_, _>>()?;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = datetime(now.checked_sub(BACKDATE).unwrap_or(now));
        params.not_after = datetime(self.until(now, LEAF_LIFETIME)?);
        let cert = params
            .signed_by(&key, &self.issuer)
            .map_err(|e| format!("issuing the listener certificate: {e}"))?;
        Ok(Leaf {
            cert: cert.der().clone(),
            cert_pem: cert.pem(),
            key,
        })
    }

    /// A certificate for a client of the gateway's, unchecked: `name` as its
    /// subject's common name, and `spiffe_id` in a URI name if it is given;
    /// for TLS client authentication alone, and no CA; with a random serial,
    /// which is what a CRL revokes it by; valid from `now` for `lifetime`, or
    /// until the CA expires if that comes first.
    ///
    /// It carries no DNS name and no IP address: those are what the CA's
    /// name constraints are on, kept for the listeners. A common name and a
    /// URI name are not constrained.
    pub fn sign_client(
        &self,
        name: &str,
        spiffe_id: Option<&str>,
        lifetime: Duration,
        now: SystemTime,
    ) -> Result<Leaf, String> {
        self.usable(now)?;
        let key = KeyPair::generate().map_err(|e| format!("making a key: {e}"))?;
        let mut params = CertificateParams::default();
        let mut subject = DistinguishedName::new();
        subject.push(DnType::CommonName, name);
        params.distinguished_name = subject;
        if let Some(id) = spiffe_id {
            let uri = id
                .try_into()
                .map_err(|_| format!("{id:?} is not an ASCII URI"))?;
            params.subject_alt_names = vec![SanType::URI(uri)];
        }
        params.serial_number = Some(random_serial()?);
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = datetime(now.checked_sub(BACKDATE).unwrap_or(now));
        params.not_after = datetime(self.until(now, lifetime)?);
        let cert = params
            .signed_by(&key, &self.issuer)
            .map_err(|e| format!("issuing the client certificate: {e}"))?;
        Ok(Leaf {
            cert: cert.der().clone(),
            cert_pem: cert.pem(),
            key,
        })
    }

    /// Its CRL, as PEM: `revoked`, each a serial and when it was revoked, as
    /// CRL number `number`. It is dated a little before `now`, as its
    /// certificates are, and its next update is due when the CA expires:
    /// each `tls issue` and `tls revoke` writes a new one.
    pub fn crl(
        &self,
        revoked: &[(Vec<u8>, SystemTime)],
        number: u64,
        now: SystemTime,
    ) -> Result<String, String> {
        let next = self
            .not_after()
            .map(|ca| UNIX_EPOCH + Duration::from_secs(ca.max(0) as u64))
            .filter(|ca| *ca > now)
            .unwrap_or(now + Duration::from_secs(86_400));
        let params = CertificateRevocationListParams {
            this_update: datetime(now.checked_sub(BACKDATE).unwrap_or(now)),
            next_update: datetime(next),
            crl_number: SerialNumber::from(number),
            issuing_distribution_point: None,
            revoked_certs: revoked
                .iter()
                .map(|(serial, at)| RevokedCertParams {
                    serial_number: SerialNumber::from_slice(serial),
                    revocation_time: datetime(*at),
                    reason_code: None,
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        params
            .signed_by(&self.issuer)
            .and_then(|crl| crl.pem())
            .map_err(|e| format!("signing the local CA's CRL: {e}"))
    }

    /// Whether `leaf` is a certificate this CA issued for each of `names`,
    /// valid at `now`: what a client that trusts the CA checks.
    pub fn check(
        &self,
        leaf: &CertificateDer<'_>,
        names: &Names,
        now: SystemTime,
    ) -> Result<(), String> {
        let mut roots = RootCertStore::empty();
        roots
            .add(self.cert.clone())
            .map_err(|e| format!("the local CA's certificate is not one a client takes: {e}"))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .map_err(|e| e.to_string())?;
        let at = UnixTime::since_unix_epoch(now.duration_since(UNIX_EPOCH).unwrap_or_default());
        for name in names.iter() {
            verifier
                .verify_server_cert(leaf, &[], &name.server_name()?, &[], at)
                .map_err(|e| format!("a client asking for {name} refuses it: {e}"))?;
        }
        Ok(())
    }
}

/// The CA's parameters but its dates and names: all of them made again from
/// its key when it is read back, so they have to come out the same each
/// time. Its name holds the first 8 hex digits of the SHA-256 of its public
/// key, which tells one install's CA from another's in a trust store.
fn ca_params(key: &KeyPair) -> CertificateParams {
    let id = hex::encode(&Sha256::digest(key.subject_public_key_info())[..4]);
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, format!("MCPdef local CA {id}"));
    name.push(DnType::OrganizationName, "MCPdef");
    let mut params = CertificateParams::default();
    params.distinguished_name = name;
    // It issues certificates for the listeners, and no CA below it.
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

/// A certificate the CA issued, and its key.
pub struct Leaf {
    cert: CertificateDer<'static>,
    cert_pem: String,
    key: KeyPair,
}

impl Leaf {
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert
    }

    /// Write it to `paths`, over any there.
    pub fn write(&self, paths: &Paths) -> Result<(), String> {
        self.write_to(&paths.dir, &paths.cert(), &paths.key())
    }

    /// Write it to `cert` and its key to `key`, in `dir`, which is made
    /// `0700` if it is not there; the key `0600`.
    pub fn write_to(&self, dir: &Path, cert: &Path, key: &Path) -> Result<(), String> {
        let pem = Zeroizing::new(self.key.serialize_pem());
        write_pair(dir, (cert, &self.cert_pem), (key, &pem))
    }

    /// It and its key, as rustls serves them.
    pub fn certified(&self) -> Result<CertifiedKey, String> {
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(self.key.serialize_der());
        let provider = rustls::crypto::ring::default_provider();
        CertifiedKey::from_der(vec![self.cert.clone()], key.into(), &provider)
            .map_err(|e| format!("the listener certificate: {e}"))
    }
}

/// The listener certificate [`ensure`] found, or issued.
pub struct Ensured {
    /// It and its key, as rustls serves them.
    pub certified: CertifiedKey,
    /// When it expires, in seconds since the Unix epoch.
    pub not_after: i64,
    /// When it is to be issued again: [`RENEW_BEFORE`] before it expires,
    /// unless the CA expires first, when issuing it again would not help.
    pub renew_at: Option<SystemTime>,
    /// What an operator should hear: a CA made, a certificate issued, or a
    /// CA near its end.
    pub notes: Vec<String>,
}

/// The listener certificate for `names` in `paths`: the one there, if the CA
/// there issued it for exactly `names` and more than [`RENEW_BEFORE`] of it
/// is left at `now`, and otherwise one issued now and written there. With
/// no CA there, one is made if `make_ca` says so, and it is an error
/// otherwise: a CA gone from under a running gateway is not quietly
/// replaced by one no client trusts.
pub fn ensure(
    paths: &Paths,
    names: &Names,
    now: SystemTime,
    make_ca: bool,
) -> Result<Ensured, String> {
    let mut notes = Vec::new();
    let ca = match LocalCa::load(paths)? {
        Some(ca) => ca,
        None if make_ca => {
            let ca = LocalCa::new(names, now)?;
            ca.write(paths)?;
            notes.push(format!(
                "made a local CA, {}, for {names}: every client that connects over TLS has to \
                 trust it (`mcpdef tls init` says how)",
                paths.ca_cert().display()
            ));
            ca
        }
        None => {
            return Err(format!(
                "there is no local CA in {}: make one with `mcpdef tls init`, and have every \
                 client trust it",
                paths.dir.display()
            ))
        }
    };
    let ca_until = ca.not_after().unwrap_or(i64::MAX);
    let secs = |t: SystemTime| t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let renewal_left = secs(now) + RENEW_BEFORE.as_secs() as i64;
    if ca_until <= secs(now) + LEAF_LIFETIME.as_secs() as i64 {
        notes.push(format!(
            "the local CA {} expires at {}: make a new one with `mcpdef tls init --new-ca`, and \
             have every client trust it in place of this one",
            paths.ca_cert().display(),
            mcpdef_transport::rfc3339(ca_until)
        ));
    }
    let kept = kept(paths, &ca, names, now).filter(|(_, until)| *until > renewal_left);
    let (certified, not_after) = match kept {
        Some(kept) => kept,
        None => {
            let leaf = ca.issue(names, now)?;
            leaf.write(paths)?;
            let not_after = PeerCertificate::read(leaf.cert_der())
                .not_after
                .unwrap_or_default();
            notes.push(format!(
                "issued the listener certificate {}, for {names}, until {}",
                paths.cert().display(),
                mcpdef_transport::rfc3339(not_after)
            ));
            (leaf.certified()?, not_after)
        }
    };
    // A certificate that runs to the CA's own end is as late as one can run.
    let renew_at = (not_after < ca_until)
        .then(|| UNIX_EPOCH + Duration::from_secs(not_after.max(0) as u64) - RENEW_BEFORE);
    Ok(Ensured {
        certified,
        not_after,
        renew_at,
        notes,
    })
}

/// The listener certificate already in `paths`, and when it expires, if it
/// is one `ca` issued for exactly `names` that a client takes at `now`.
fn kept(
    paths: &Paths,
    ca: &LocalCa,
    names: &Names,
    now: SystemTime,
) -> Option<(CertifiedKey, i64)> {
    if !present(&paths.cert()) || !present(&paths.key()) {
        return None;
    }
    let files = IdentityFiles {
        cert: paths.cert(),
        key: SecretRef::File(paths.key()),
    };
    let certified = read_served(&files).ok()?;
    let leaf = certified.end_entity_cert().ok()?;
    if CertificateNames::read(leaf).alt_names != names.alt_names() {
        return None;
    }
    ca.check(leaf, names, now).ok()?;
    let not_after = PeerCertificate::read(leaf).not_after?;
    Some((certified, not_after))
}

/// `now` plus `lifetime`, if a certificate can say it.
fn later(now: SystemTime, lifetime: Duration) -> Result<SystemTime, String> {
    now.checked_add(lifetime)
        .filter(|t| {
            t.duration_since(UNIX_EPOCH)
                .is_ok_and(|d| d.as_secs() < 253_402_300_799)
        })
        .ok_or_else(|| "a certificate cannot run that long".to_string())
}

/// A random serial: 16 bytes, the first between `0x01` and `0x7f`, so that
/// in DER it is a positive INTEGER of exactly those 16 bytes, which reads
/// back, and prints, as it was made.
fn random_serial() -> Result<SerialNumber, String> {
    let mut bytes = [0u8; 16];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| "no randomness to be had for a serial".to_string())?;
    bytes[0] = (bytes[0] & 0x7f).max(1);
    Ok(SerialNumber::from_slice(&bytes))
}

pub(super) fn datetime(t: SystemTime) -> time::OffsetDateTime {
    time::OffsetDateTime::from(t)
}

/// Whether anything is at `path`: a symlink whose target is missing counts,
/// so that it is not written over as if nothing were there.
pub(super) fn present(path: &Path) -> bool {
    !matches!(
        std::fs::symlink_metadata(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound
    )
}

/// Write a certificate and its key into `dir`, made `0700` if it is not
/// there. Both are staged beside where they go before either is renamed into
/// place, and the certificate they replace is set aside until the key has
/// landed: after any failure, the old pair is as it was.
fn write_pair(dir: &Path, cert: (&Path, &str), key: (&Path, &str)) -> Result<(), String> {
    make_dir(dir)?;
    let (cert_path, key_path) = (cert.0, key.0);
    let cert_tmp = stage(cert_path, cert.1.as_bytes(), false)
        .map_err(|e| format!("writing {}: {e}", cert_path.display()))?;
    let key_tmp = match stage(key_path, key.1.as_bytes(), true) {
        Ok(tmp) => tmp,
        Err(e) => {
            let _ = std::fs::remove_file(&cert_tmp);
            return Err(format!("writing {}: {e}", key_path.display()));
        }
    };
    let backup = sibling(cert_path, "bak");
    let had_cert = match std::fs::rename(cert_path, &backup) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            let _ = std::fs::remove_file(&cert_tmp);
            let _ = std::fs::remove_file(&key_tmp);
            return Err(format!("setting {} aside: {e}", cert_path.display()));
        }
    };
    let published =
        std::fs::rename(&cert_tmp, cert_path).and_then(|()| std::fs::rename(&key_tmp, key_path));
    match published {
        Ok(()) => {
            if had_cert {
                let _ = std::fs::remove_file(&backup);
            }
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(cert_path);
            if had_cert {
                let _ = std::fs::rename(&backup, cert_path);
            }
            let _ = std::fs::remove_file(&cert_tmp);
            let _ = std::fs::remove_file(&key_tmp);
            Err(format!(
                "putting {} and {} in place: {e}",
                cert_path.display(),
                key_path.display()
            ))
        }
    }
}

/// `path` with `.{what}.{pid}` added: beside it, so a rename stays on one
/// filesystem, and this process's own.
fn sibling(path: &Path, what: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{what}.{}", std::process::id()));
    path.with_file_name(name)
}

/// Write `contents` to a new file beside `path`, `0600` if `private`, and
/// flushed to disk, and return where. A file left there by a run that died
/// is removed first: a new file takes its mode from here, not from it.
pub(super) fn stage(path: &Path, contents: &[u8], private: bool) -> std::io::Result<PathBuf> {
    #[cfg(not(unix))]
    let _ = private;
    let tmp = sibling(path, "tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let written = (|| {
        let mut file = options.open(&tmp)?;
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(contents)?;
        file.sync_all()
    })();
    match written {
        Ok(()) => Ok(tmp),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Make `dir` and those above it, `dir` itself readable by its owner alone.
pub(super) fn make_dir(dir: &Path) -> Result<(), String> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|e| format!("making {}: {e}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// 2026-09-30T00:00:00Z.
    const NOW: u64 = 1_790_726_400;

    #[test]
    fn names_start_with_localhost_and_the_loopbacks_and_come_once() {
        let names = Names::new(["mcpdef.internal", "127.0.0.1", "MCPdef.Internal.", "[::1]"]);
        assert_eq!(
            names.to_string(),
            "localhost, 127.0.0.1, ::1, mcpdef.internal"
        );
        assert_eq!(
            names.alt_names(),
            [
                "DNS:localhost",
                "IP:127.0.0.1",
                "IP:::1",
                "DNS:mcpdef.internal"
            ]
        );
        // The loopback block once, however many loopback addresses.
        let subtrees = Names::new(["127.0.0.2", "10.1.2.3"]).subtrees();
        assert_eq!(
            subtrees,
            [
                GeneralSubtree::DnsName("localhost".into()),
                GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix([127, 0, 0, 0], 8)),
                GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(
                    "::1".parse().unwrap(),
                    128
                )),
                GeneralSubtree::IpAddress(CidrSubnet::from_v4_prefix([10, 1, 2, 3], 32)),
            ]
        );
    }

    #[test]
    fn a_certificate_the_ca_issues_checks_for_each_of_its_names() {
        let names = Names::new(["mcpdef.internal", "10.1.2.3"]);
        let ca = LocalCa::new(&names, at(NOW)).unwrap();
        let leaf = ca.issue(&names, at(NOW)).unwrap();
        ca.check(leaf.cert_der(), &names, at(NOW)).unwrap();
        let read = CertificateNames::read(leaf.cert_der());
        assert_eq!(read.alt_names, names.alt_names());
        assert_eq!(read.subject.as_deref(), Some("localhost"));
        assert!(
            read.issuer
                .as_deref()
                .unwrap()
                .starts_with("MCPdef local CA "),
            "{read:?}"
        );
        // A name under a DNS name it vouches for is within it too.
        let under = Names::new(["api.mcpdef.internal"]);
        ca.issue(&under, at(NOW)).unwrap();
        // Valid from an hour before it was made, for thirty days.
        let until = PeerCertificate::read(leaf.cert_der()).not_after.unwrap();
        assert_eq!(until, (NOW + LEAF_LIFETIME.as_secs()) as i64);
        assert!(ca.check(leaf.cert_der(), &names, at(NOW - 3_000)).is_ok());
        assert!(ca.check(leaf.cert_der(), &names, at(NOW - 4_000)).is_err());
        assert!(ca
            .check(leaf.cert_der(), &names, at(until as u64 + 1))
            .is_err());
    }

    #[test]
    fn the_ca_vouches_for_no_name_it_was_not_made_with() {
        let ca = LocalCa::new(&Names::new(["mcpdef.internal"]), at(NOW)).unwrap();
        for (other, named) in [
            ("github.com", "github.com"),
            ("mcpdef.internal.evil.test", "mcpdef.internal.evil.test"),
            ("10.0.0.1", "10.0.0.1"),
            ("::2", "::2"),
        ] {
            let e = ca
                .issue(&Names::new(["mcpdef.internal", other]), at(NOW))
                .err()
                .unwrap_or_else(|| panic!("{other} was vouched for"));
            assert!(e.contains(&format!("and not for {named}:")), "{other}: {e}");
            assert!(e.contains("mcpdef tls init --new-ca"), "{e}");
        }
        // A client refuses one it issued anyway: the constraint is in the
        // CA's certificate, where every client reads it.
        let names = Names::new(["github.com"]);
        let forged = ca.sign(&names, at(NOW)).unwrap();
        let e = ca.check(forged.cert_der(), &names, at(NOW)).unwrap_err();
        assert!(
            e.starts_with("a client asking for localhost refuses it"),
            "{e}"
        );
    }

    #[test]
    fn a_ca_read_back_from_its_files_issues_what_its_certificate_checks() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let names = Names::new(["mcpdef.internal"]);
        assert!(LocalCa::load(&paths).unwrap().is_none());
        let made = LocalCa::new(&names, at(NOW)).unwrap();
        made.write(&paths).unwrap();
        let read = LocalCa::load(&paths).unwrap().unwrap();
        assert_eq!(read.cert_der(), made.cert_der());
        // Its name is made again from its key alone, and a certificate it
        // issues chains to the certificate on disk.
        let leaf = read.issue(&names, at(NOW)).unwrap();
        made.check(leaf.cert_der(), &names, at(NOW)).unwrap();
        // Another CA's key beside this one's certificate is refused as it
        // is read, whatever the time.
        let other = LocalCa::new(&names, at(NOW)).unwrap();
        other
            .write(&Paths::under(dir.path().join("other")))
            .unwrap();
        std::fs::copy(
            dir.path().join("other/tls/ca.key"),
            dir.path().join("tls/ca.key"),
        )
        .unwrap();
        let e = LocalCa::load(&paths).err().unwrap();
        assert!(
            e.starts_with("the local CA's key") && e.contains("is not the one its certificate"),
            "{e}"
        );
        assert!(e.contains("mcpdef tls init --new-ca"), "{e}");
    }

    #[test]
    fn an_expired_ca_says_so() {
        let names = Names::new([] as [&str; 0]);
        let ca = LocalCa::new(&names, at(NOW)).unwrap();
        let after = at(ca.not_after().unwrap() as u64 + 1);
        let e = ca.issue(&names, after).err().unwrap();
        assert!(e.starts_with("the local CA expired at 2036-"), "{e}");
    }

    #[test]
    fn half_a_ca_is_an_error_that_names_what_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        LocalCa::new(&Names::new([] as [&str; 0]), at(NOW))
            .unwrap()
            .write(&paths)
            .unwrap();
        std::fs::remove_file(paths.ca_key()).unwrap();
        let e = LocalCa::load(&paths).err().unwrap();
        assert!(e.contains("is half there"), "{e}");
        assert!(e.contains("ca.key is missing"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn keys_are_the_owners_alone_and_nothing_is_left_behind() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path().join("state"));
        let names = Names::new([] as [&str; 0]);
        ensure(&paths, &names, at(NOW), true).unwrap();
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(paths.dir()), 0o700);
        assert_eq!(mode(&paths.ca_key()), 0o600);
        assert_eq!(mode(&paths.key()), 0o600);
        let mut files: Vec<String> = std::fs::read_dir(paths.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        files.sort();
        assert_eq!(files, ["ca.crt", "ca.key", "tls.crt", "tls.key"]);
        // A key made readable by others is made the owner's again when it is
        // written over.
        std::fs::set_permissions(paths.key(), std::fs::Permissions::from_mode(0o644)).unwrap();
        ensure(&paths, &names, at(NOW + 25 * 86_400), false).unwrap();
        assert_eq!(mode(&paths.key()), 0o600);
    }

    #[test]
    fn a_failed_key_write_leaves_the_pair_there_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let names = Names::new([] as [&str; 0]);
        ensure(&paths, &names, at(NOW), true).unwrap();
        let before = std::fs::read(paths.cert()).unwrap();
        // A directory where the key goes: staging works, the rename fails.
        std::fs::remove_file(paths.key()).unwrap();
        std::fs::create_dir(paths.key()).unwrap();
        std::fs::write(paths.key().join("in-the-way"), "x").unwrap();
        let ca = LocalCa::load(&paths).unwrap().unwrap();
        let leaf = ca.issue(&names, at(NOW)).unwrap();
        assert!(leaf.write(&paths).is_err());
        assert_eq!(std::fs::read(paths.cert()).unwrap(), before);
        let strays: Vec<String> = std::fs::read_dir(paths.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp.") || name.contains(".bak."))
            .collect();
        assert!(strays.is_empty(), "{strays:?}");
    }

    #[test]
    fn a_kept_certificate_is_served_until_a_third_of_it_is_left() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let names = Names::new(["mcpdef.internal"]);
        let first = ensure(&paths, &names, at(NOW), true).unwrap();
        assert_eq!(first.notes.len(), 2, "{:?}", first.notes);
        assert!(
            first.notes[0].starts_with("made a local CA"),
            "{:?}",
            first.notes
        );
        assert_eq!(
            first.renew_at,
            Some(at(NOW + (LEAF_LIFETIME - RENEW_BEFORE).as_secs()))
        );
        let serial = |e: &Ensured| e.certified.cert[0].clone();
        // Kept at a restart, and up to its renewal.
        let again = ensure(&paths, &names, at(NOW + 19 * 86_400), false).unwrap();
        assert_eq!(serial(&again), serial(&first));
        assert!(again.notes.is_empty(), "{:?}", again.notes);
        // Issued again once it is due, by the same CA.
        let renewed = ensure(&paths, &names, at(NOW + 20 * 86_400 + 1), false).unwrap();
        assert_ne!(serial(&renewed), serial(&first));
        let ca = LocalCa::load(&paths).unwrap().unwrap();
        ca.check(&serial(&renewed), &names, at(NOW + 20 * 86_400 + 1))
            .unwrap();
        // And when the names change, whatever is left of it.
        let fewer = Names::new([] as [&str; 0]);
        let reissued = ensure(&paths, &fewer, at(NOW + 20 * 86_400 + 2), false).unwrap();
        assert_ne!(serial(&reissued), serial(&renewed));
        assert_eq!(
            CertificateNames::read(&serial(&reissued)).alt_names,
            fewer.alt_names()
        );
    }

    #[test]
    fn with_no_ca_one_is_made_only_when_asked() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let names = Names::new([] as [&str; 0]);
        let e = ensure(&paths, &names, at(NOW), false).err().unwrap();
        assert!(e.starts_with("there is no local CA in"), "{e}");
        assert!(!paths.dir().exists());
    }

    #[test]
    fn a_certificate_runs_no_later_than_its_ca() {
        let names = Names::new([] as [&str; 0]);
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        ensure(&paths, &names, at(NOW), true).unwrap();
        let ca = LocalCa::load(&paths).unwrap().unwrap();
        let ca_until = ca.not_after().unwrap();
        let late = at(ca_until as u64 - 5 * 86_400);
        let ensured = ensure(&paths, &names, late, false).unwrap();
        assert_eq!(ensured.not_after, ca_until);
        // Issuing it again would not help: no renewal is due.
        assert_eq!(ensured.renew_at, None);
        assert!(
            ensured.notes.iter().any(|n| n.contains("expires at")),
            "{:?}",
            ensured.notes
        );
    }
}
