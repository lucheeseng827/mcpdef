// SPDX-License-Identifier: Apache-2.0
//! The local CA's certificates for clients, and their revocation: what
//! `mcpdef tls issue` and `mcpdef tls revoke` do. mTLS for a workload with
//! no PKI of its own.
//!
//! **Named as the gateway reads names.** A client's certificate carries its
//! name as its subject's common name, what `[gateway.tls.client_auth]
//! identity = "subject-cn"` reads, and a SPIFFE ID in a URI name if it is
//! given one, what `identity = "spiffe"` reads. It carries no DNS name: the
//! CA's name constraints are on DNS names and IP addresses, which it keeps
//! for the listeners, so `san-dns` cannot read a client of this CA.
//!
//! **Checked as the gateway checks it.** Before it is written, a certificate
//! is checked by the check `[gateway.tls.client_auth]` builds, with the CA as
//! its `ca` and the CA's CRL as its `crl`, and each name is read back as the
//! gateway reads it. A certificate the gateway would refuse is never handed
//! out.
//!
//! **Revoked by its serial**, 16 random bytes. The CRL, `ca.crl`, is written
//! afresh from `revoked.json`, which says what is revoked and when, each
//! time either command runs: the first `issue` writes one that revokes
//! nothing, so that `crl` can name it from the start, as it must, since a
//! certificate whose CA has no CRL among `crl` is refused. A gateway reads it
//! again when it reloads, and checks every open connection's certificate
//! against it at the connection's next request.

use super::client_auth::{spiffe_trust_domain, ClientCerts, Presented};
use super::local_ca::{datetime, make_dir, present, stage, LocalCa, Names, Paths};
use crate::config::{CertIdentity, ClientAuthConfig, ClientAuthMode};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The longest a client's name may be: X.520's bound on a common name.
const NAME_MAX: usize = 64;

/// A client to issue a certificate for.
#[derive(Clone, Copy, Debug)]
pub struct Client<'a> {
    /// Its name: its certificate's subject's common name, and its files'.
    pub name: &'a str,
    /// Its SPIFFE ID, if it has one.
    pub spiffe_id: Option<&'a str>,
}

impl Client<'_> {
    /// Why it cannot have a certificate, if it cannot. Its name names its
    /// files, so it is letters, digits, `.`, `-` and `_`, and does not start
    /// with a `.`; its SPIFFE ID keeps the SPIFFE ID rules.
    fn problem(&self) -> Option<String> {
        let name = self.name;
        let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_');
        if name.is_empty() || name.len() > NAME_MAX {
            return Some(format!(
                "a client's name is 1 to {NAME_MAX} characters, and {name:?} is not"
            ));
        }
        if name.starts_with('.') || !name.chars().all(allowed) {
            return Some(format!(
                "a client's name is letters, digits, '.', '-' and '_', not starting with '.', \
                 since it names the client's files, and {name:?} is not"
            ));
        }
        let id = self.spiffe_id?;
        spiffe_trust_domain(id).err().map(|why| {
            let why = why.replacen("its URI name", "it", 1);
            format!(
                "--spiffe-id {id:?}: {}",
                why.replacen("its SPIFFE ID's", "its", 1)
            )
        })
    }
}

/// What [`issue`] wrote.
#[derive(Debug)]
pub struct Issued {
    /// The certificate.
    pub cert: PathBuf,
    /// Its key, `0600`.
    pub key: PathBuf,
    /// Its serial, as `openssl x509 -noout -serial` prints it: what
    /// `mcpdef tls revoke` takes.
    pub serial: String,
    /// When it expires, in seconds since the Unix epoch.
    pub not_after: i64,
    /// What else was done: a CA made.
    pub notes: Vec<String>,
}

/// Issue `client` a certificate from the CA in `paths`, valid for
/// `lifetime` from `now`, and write it, and its key, to `<name>.crt` and
/// `<name>.key` in `out`. A CA is made, for `names`, if there is none, and
/// its CRL written. Files already there are not written over.
pub fn issue(
    paths: &Paths,
    names: &Names,
    client: &Client,
    lifetime: Duration,
    out: &Path,
    now: SystemTime,
) -> Result<Issued, String> {
    if let Some(problem) = client.problem() {
        return Err(problem);
    }
    let cert = out.join(format!("{}.crt", client.name));
    let key = out.join(format!("{}.key", client.name));
    for path in [&cert, &key] {
        if present(path) {
            return Err(format!(
                "{} is there already: move it aside, or give --out another directory",
                path.display()
            ));
        }
    }
    let mut notes = Vec::new();
    let ca = match LocalCa::load(paths)? {
        Some(ca) => ca,
        None => {
            let ca = LocalCa::new(names, now)?;
            ca.write(paths)?;
            notes.push(format!(
                "made a local CA, {}, for {names}",
                paths.ca_cert().display()
            ));
            ca
        }
    };
    // Signed afresh, so it is this CA's even if the CA was made anew since
    // the last one.
    write_crl(paths, &ca, &mut Revocations::read(paths)?, now)?;
    let leaf = ca.sign_client(client.name, client.spiffe_id, lifetime, now)?;
    check(paths, leaf.cert_der(), client, now)?;
    leaf.write_to(out, &cert, &key)?;
    let serial = mcpdef_transport::certificate_serial(leaf.cert_der())
        .ok_or("the certificate issued has no serial that reads")?;
    let not_after = mcpdef_transport::PeerCertificate::read(leaf.cert_der())
        .not_after
        .unwrap_or_default();
    Ok(Issued {
        cert,
        key,
        serial: serial_hex(&serial),
        not_after,
        notes,
    })
}

/// Check `leaf` as a gateway whose `[gateway.tls.client_auth]` takes the CA
/// and its CRL checks it, and read each of its names as that gateway would:
/// its common name, and its SPIFFE ID if it has one.
fn check(
    paths: &Paths,
    leaf: &rustls::pki_types::CertificateDer<'static>,
    client: &Client,
    now: SystemTime,
) -> Result<(), String> {
    let file = |path: PathBuf| {
        path.to_str()
            .map(str::to_string)
            .ok_or_else(|| format!("{} is not UTF-8", path.display()))
    };
    let (ca, crl) = (file(paths.ca_cert())?, file(paths.crl())?);
    let mut reads = vec![(CertIdentity::SubjectCn, client.name, Vec::new())];
    if let Some(id) = client.spiffe_id {
        let domain = spiffe_trust_domain(id)?.to_string();
        reads.push((CertIdentity::Spiffe, id, vec![domain]));
    }
    for (identity, name, trust_domains) in reads {
        let config = ClientAuthConfig {
            mode: ClientAuthMode::Required,
            ca: vec![ca.clone()],
            crl: vec![crl.clone()],
            identity: Some(identity),
            trust_domains,
        };
        let certs = ClientCerts::build("the local CA's check", &config)?
            .ok_or("the local CA's check asks for no certificate")?;
        let presented =
            Presented::forwarded(vec![leaf.clone()]).ok_or("the certificate issued is empty")?;
        let refused = |why: String| format!("a gateway would refuse the certificate issued: {why}");
        certs.admit(&presented, now).map_err(refused)?;
        let read = certs.identity(&presented).map_err(refused)?;
        if read != name {
            return Err(refused(format!(
                "its {} reads {read:?}, not {name:?}",
                identity.as_str()
            )));
        }
    }
    Ok(())
}

/// What [`revoke`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum Revoked {
    /// Revoked now: the CRL revokes `listed` certificates.
    Now { listed: usize },
    /// Revoked already, at `at`, in seconds since the Unix epoch.
    Already { at: i64 },
}

/// Revoke the certificate with `serial` the CA in `paths` issued: add it to
/// what is revoked, and write the CRL. A serial revoked already is left as
/// it was, and the CRL written all the same.
pub fn revoke(paths: &Paths, serial: &[u8], now: SystemTime) -> Result<Revoked, String> {
    let ca = LocalCa::load(paths)?.ok_or_else(|| {
        format!(
            "there is no local CA in {}, and so nothing it issued to revoke",
            paths.dir().display()
        )
    })?;
    let mut revocations = Revocations::read(paths)?;
    let serial = serial_hex(serial);
    let already = revocations
        .revoked
        .iter()
        .find(|r| r.serial == serial)
        .map(|r| r.at);
    if already.is_none() {
        revocations.revoked.push(Revocation {
            serial,
            at: unix(now),
        });
    }
    write_crl(paths, &ca, &mut revocations, now)?;
    Ok(match already {
        Some(at) => Revoked::Already { at },
        None => Revoked::Now {
            listed: revocations.revoked.len(),
        },
    })
}

/// Write the CRL afresh, signed by the CA now in `paths`, if one has been
/// written: after `mcpdef tls init --new-ca`, so that the `crl` a gateway
/// names is the new CA's, and its certificates can be checked against it.
/// Whether there was one.
pub fn refresh_crl(paths: &Paths, now: SystemTime) -> Result<bool, String> {
    if !present(&paths.crl()) && !present(&paths.revoked()) {
        return Ok(false);
    }
    let ca = LocalCa::load(paths)?
        .ok_or_else(|| format!("there is no local CA in {}", paths.dir().display()))?;
    write_crl(paths, &ca, &mut Revocations::read(paths)?, now)?;
    Ok(true)
}

/// What is revoked, and the number of the last CRL written: `revoked.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Revocations {
    /// The last CRL's number. Each is one more than the last.
    number: u64,
    revoked: Vec<Revocation>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Revocation {
    /// Upper-case hex, as [`serial_hex`] writes it.
    serial: String,
    /// When, in seconds since the Unix epoch.
    at: i64,
}

impl Revocations {
    /// The ones in `paths`, or none if nothing has been revoked.
    fn read(paths: &Paths) -> Result<Revocations, String> {
        let path = paths.revoked();
        if !present(&path) {
            return Ok(Revocations::default());
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        serde_json::from_str(&text).map_err(|e| {
            format!(
                "{} does not read as what is revoked: {e}. Mend it, or remove it to start again \
                 from nothing revoked",
                path.display()
            )
        })
    }
}

/// Write `revocations`, numbered one more, and the CRL `ca` signs from them.
/// The list goes first: a CRL that does not land is written from it next
/// time, and nothing revoked is ever lost from it.
fn write_crl(
    paths: &Paths,
    ca: &LocalCa,
    revocations: &mut Revocations,
    now: SystemTime,
) -> Result<(), String> {
    revocations.number += 1;
    let revoked = revocations
        .revoked
        .iter()
        .map(|r| {
            let serial = parse_serial(&r.serial)
                .map_err(|e| format!("{}: {e}", paths.revoked().display()))?;
            let at = UNIX_EPOCH + Duration::from_secs(r.at.max(0) as u64);
            Ok((serial, at))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let crl = ca.crl(&revoked, revocations.number, now)?;
    let list = serde_json::to_string_pretty(revocations).map_err(|e| e.to_string())? + "\n";
    make_dir(paths.dir())?;
    for (path, contents) in [(paths.revoked(), list), (paths.crl(), crl)] {
        let tmp = stage(&path, contents.as_bytes(), false)
            .map_err(|e| format!("writing {}: {e}", path.display()))?;
        std::fs::rename(&tmp, &path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("putting {} in place: {e}", path.display())
        })?;
    }
    Ok(())
}

/// A serial as it is typed: hex digits in either case, with or without
/// colons or spaces between them, or as `openssl x509 -noout -serial` prints
/// it, `serial=…`. As a certificate holds it: with no zero byte in front,
/// unless the first bit of the next is set.
pub fn parse_serial(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    let digits: String = text
        .strip_prefix("serial=")
        .unwrap_or(text)
        .chars()
        .filter(|c| !matches!(c, ':' | ' '))
        .collect();
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "{text:?} is not a serial: one is hex digits, as `mcpdef tls issue` printed it"
        ));
    }
    let digits = match digits.len() % 2 {
        1 => format!("0{digits}"),
        _ => digits,
    };
    let mut bytes = hex::decode(&digits).map_err(|e| format!("{text:?}: {e}"))?;
    while bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0 {
        bytes.remove(0);
    }
    Ok(bytes)
}

/// The trust domain of a SPIFFE ID, as `trust_domains` lists it: what is
/// between `spiffe://` and the path.
pub fn trust_domain(id: &str) -> &str {
    let rest = id.strip_prefix("spiffe://").unwrap_or(id);
    rest.split('/').next().unwrap_or(rest)
}

/// A serial in upper-case hex, as `openssl x509 -noout -serial` prints it.
pub fn serial_hex(serial: &[u8]) -> String {
    hex::encode_upper(serial)
}

fn unix(t: SystemTime) -> i64 {
    datetime(t).unix_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// 2026-09-30T00:00:00Z.
    const NOW: u64 = 1_790_726_400;
    const DAY: Duration = Duration::from_secs(86_400);
    const BOT: &str = "spiffe://prod.acme.internal/ns/ci/sa/bot";

    struct Dirs {
        _root: tempfile::TempDir,
        paths: Paths,
        out: PathBuf,
    }

    fn dirs() -> Dirs {
        let root = tempfile::tempdir().unwrap();
        let paths = Paths::under(root.path().join("state"));
        let out = root.path().join("out");
        Dirs {
            _root: root,
            paths,
            out,
        }
    }

    fn names() -> Names {
        Names::new(["mcpdef.internal"])
    }

    fn bot() -> Client<'static> {
        Client {
            name: "ci-bot",
            spiffe_id: Some(BOT),
        }
    }

    /// The certificate in `issued`, as DER.
    fn der(issued: &Issued) -> rustls::pki_types::CertificateDer<'static> {
        use rustls::pki_types::pem::PemObject;
        rustls::pki_types::CertificateDer::from_pem_file(&issued.cert).unwrap()
    }

    /// The first certificate makes the CA, if there is none, and the CRL;
    /// the certificate is for TLS clients alone, names the client as the
    /// gateway reads it, and its key is its owner's alone.
    #[test]
    fn a_client_certificate_names_its_client_and_its_key_is_kept_close() {
        let d = dirs();
        let issued = issue(&d.paths, &names(), &bot(), 30 * DAY, &d.out, at(NOW)).unwrap();
        assert!(issued.notes[0].starts_with("made a local CA"), "{issued:?}");
        assert!(present(&d.paths.crl()), "the CRL is written at once");
        assert_eq!(issued.cert, d.out.join("ci-bot.crt"));

        let read = mcpdef_transport::CertificateNames::read(&der(&issued));
        assert_eq!(read.subject.as_deref(), Some("ci-bot"));
        assert_eq!(read.alt_names, [format!("URI:{BOT}")]);
        assert_eq!(
            issued.not_after,
            (NOW + 30 * 86_400) as i64,
            "valid for the days asked"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&issued.key).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // A second is issued by the same CA, with a serial of its own.
        let other = Client {
            name: "ci-bot-2",
            spiffe_id: None,
        };
        let second = issue(&d.paths, &names(), &other, DAY, &d.out, at(NOW)).unwrap();
        assert!(second.notes.is_empty(), "{second:?}");
        assert_ne!(second.serial, issued.serial);
        assert_eq!(issued.serial.len(), 32, "16 random bytes");
    }

    /// The serial printed is the certificate's, as openssl reads it, and the
    /// one `revoke` takes.
    #[test]
    fn the_serial_printed_is_the_certificates() {
        let d = dirs();
        let issued = issue(&d.paths, &names(), &bot(), DAY, &d.out, at(NOW)).unwrap();
        let read = mcpdef_transport::certificate_serial(&der(&issued)).unwrap();
        assert_eq!(serial_hex(&read), issued.serial);
        assert_eq!(parse_serial(&issued.serial).unwrap(), read);
    }

    /// What the gateway checks, `issue` checks first: a certificate that the
    /// CA's own CRL revokes, or one that is no longer valid, does not check.
    #[test]
    fn a_revoked_certificate_fails_the_check_a_gateway_makes() {
        let d = dirs();
        let issued = issue(&d.paths, &names(), &bot(), DAY, &d.out, at(NOW)).unwrap();
        let leaf = der(&issued);
        check(&d.paths, &leaf, &bot(), at(NOW)).unwrap();

        let serial = parse_serial(&issued.serial).unwrap();
        assert_eq!(
            revoke(&d.paths, &serial, at(NOW + 60)).unwrap(),
            Revoked::Now { listed: 1 }
        );
        let refused = check(&d.paths, &leaf, &bot(), at(NOW + 120)).unwrap_err();
        assert!(refused.contains("Revoked"), "{refused}");

        // Past its end, it does not check either.
        let fresh = Client {
            name: "fresh",
            spiffe_id: None,
        };
        let other = issue(&d.paths, &names(), &fresh, DAY, &d.out, at(NOW)).unwrap();
        let late = check(&d.paths, &der(&other), &fresh, at(NOW + 2 * 86_400));
        assert!(late.is_err(), "{late:?}");
    }

    /// Revoking twice is revoking once, and the list keeps when it was.
    #[test]
    fn revoking_again_changes_nothing_but_the_crls_number() {
        let d = dirs();
        let issued = issue(&d.paths, &names(), &bot(), DAY, &d.out, at(NOW)).unwrap();
        let serial = parse_serial(&issued.serial).unwrap();
        revoke(&d.paths, &serial, at(NOW + 60)).unwrap();
        assert_eq!(
            revoke(&d.paths, &serial, at(NOW + 120)).unwrap(),
            Revoked::Already {
                at: (NOW + 60) as i64
            }
        );
        let list = Revocations::read(&d.paths).unwrap();
        assert_eq!(list.revoked.len(), 1);
        // The first issue's CRL, then one for each revoke.
        assert_eq!(list.number, 3);
    }

    /// A CA made anew gets a CRL of its own: until then, the CRL a gateway
    /// names is the old CA's, and no certificate of the new one's can be
    /// checked against it.
    #[test]
    fn a_new_ca_has_its_crl_signed_afresh() {
        let d = dirs();
        assert!(
            !refresh_crl(&d.paths, at(NOW)).unwrap(),
            "no CRL to refresh"
        );
        issue(&d.paths, &names(), &bot(), DAY, &d.out, at(NOW)).unwrap();
        let new = LocalCa::new(&names(), at(NOW)).unwrap();
        new.write(&d.paths).unwrap();
        let fresh = Client {
            name: "fresh",
            spiffe_id: None,
        };
        let leaf = new.sign_client("fresh", None, DAY, at(NOW)).unwrap();
        let unknown = check(&d.paths, leaf.cert_der(), &fresh, at(NOW)).unwrap_err();
        assert!(unknown.contains("UnknownRevocationStatus"), "{unknown}");
        assert!(refresh_crl(&d.paths, at(NOW)).unwrap());
        check(&d.paths, leaf.cert_der(), &fresh, at(NOW)).unwrap();
    }

    /// With no CA there is nothing to revoke, and nothing is made.
    #[test]
    fn with_no_ca_nothing_is_revoked() {
        let d = dirs();
        let refused = revoke(&d.paths, &[1, 2, 3], at(NOW)).unwrap_err();
        assert!(refused.contains("no local CA"), "{refused}");
        assert!(!present(&d.paths.crl()));
    }

    /// A name names files, so it can hold no path; a SPIFFE ID keeps the
    /// rules; and nothing is written over.
    #[test]
    fn what_cannot_be_issued_is_refused_before_anything_is_written() {
        let d = dirs();
        let long = "x".repeat(65);
        for name in [
            "",
            "../etc/passwd",
            "certs/ci-bot",
            "a\\b",
            ".hidden",
            "a b",
            &long,
        ] {
            let client = Client {
                name,
                spiffe_id: None,
            };
            let refused = issue(&d.paths, &names(), &client, DAY, &d.out, at(NOW));
            assert!(refused.is_err(), "{name:?}");
        }
        let bad_id = Client {
            name: "bot",
            spiffe_id: Some("spiffe://Prod/x"),
        };
        let refused = issue(&d.paths, &names(), &bad_id, DAY, &d.out, at(NOW)).unwrap_err();
        assert!(refused.starts_with("--spiffe-id"), "{refused}");
        assert!(!present(&d.paths.ca_cert()), "nothing made for a refusal");

        issue(&d.paths, &names(), &bot(), DAY, &d.out, at(NOW)).unwrap();
        let before = std::fs::read(d.out.join("ci-bot.key")).unwrap();
        let again = issue(&d.paths, &names(), &bot(), DAY, &d.out, at(NOW)).unwrap_err();
        assert!(again.contains("is there already"), "{again}");
        assert_eq!(std::fs::read(d.out.join("ci-bot.key")).unwrap(), before);
    }

    #[test]
    fn a_serial_reads_as_it_is_typed() {
        let bytes = vec![0x4f, 0x2a, 0x01];
        for typed in [
            "4F2A01",
            "4f2a01",
            "4f:2a:01",
            "serial=4F2A01",
            " 4F 2A 01 ",
        ] {
            assert_eq!(parse_serial(typed).unwrap(), bytes, "{typed:?}");
        }
        // As a certificate holds it: a zero in front only where it keeps
        // the number positive.
        assert_eq!(parse_serial("004F").unwrap(), [0x4f]);
        assert_eq!(parse_serial("0080").unwrap(), [0x00, 0x80]);
        assert_eq!(parse_serial("abc").unwrap(), [0x0a, 0xbc]);
        for wrong in ["", "serial=", "4G", "ci-bot.crt"] {
            assert!(parse_serial(wrong).is_err(), "{wrong:?}");
        }
    }
}
