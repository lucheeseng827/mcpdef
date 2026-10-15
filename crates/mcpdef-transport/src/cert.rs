// SPDX-License-Identifier: Apache-2.0
//! The certificate an HTTPS upstream presents, as the gateway reports it:
//! which one it is, and when it expires.
//!
//! Every client asks reqwest for its connections' TLS details (`tls_info`),
//! and each response from the configured URL leaves the certificate it came
//! over in the upstream's [`TlsWatch`], which the gateway reads for the admin
//! API and the expiry metric. Of the certificate, only its fingerprint and its
//! `notAfter` are wanted, so it is not parsed as X.509: the DER walk here
//! reads the one field and nothing else.

use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// How an HTTPS upstream's server is verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verification {
    /// By its chain, up to a root the profile trusts, and by its name and its
    /// dates.
    Ca,
    /// By its key alone: `pin_sha256`.
    Pin,
    /// Not at all: `insecure_skip_verify`.
    Disabled,
}

impl Verification {
    /// As the admin API and `mcpdef egress show` say it: `ca`, `pin` or
    /// `disabled`.
    pub fn as_str(self) -> &'static str {
        match self {
            Verification::Ca => "ca",
            Verification::Pin => "pin",
            Verification::Disabled => "disabled",
        }
    }
}

/// A certificate a server presented.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerCertificate {
    /// The SHA-256 of the whole certificate, in the colon-separated hex that
    /// `openssl x509 -fingerprint -sha256` prints.
    pub fingerprint: String,
    /// When it expires, its `notAfter`, in seconds since the Unix epoch. None
    /// if the certificate does not say, as far as the DER walk can read it.
    pub not_after: Option<i64>,
}

impl PeerCertificate {
    /// The certificate `der` holds.
    pub fn read(der: &[u8]) -> PeerCertificate {
        PeerCertificate {
            fingerprint: fingerprint(der),
            not_after: not_after(der),
        }
    }

    /// Its `notAfter` in RFC 3339, in UTC: `2031-02-03T00:00:00Z`.
    pub fn not_after_rfc3339(&self) -> Option<String> {
        self.not_after.map(rfc3339)
    }
}

/// What an HTTPS upstream's connections have shown: how its server is
/// verified, and the certificate it presented last. Clones share it.
///
/// The transport keeps it from every response to the configured URL, so it
/// follows the certificate a renewal puts in place as soon as a new
/// connection meets it: a new connection with a full handshake, that is. One
/// that resumes an earlier TLS session is vouched for by the certificate that
/// session began with, the server presents none, and the session's is what
/// shows. The gateway reads the watch when it reports on the upstream.
#[derive(Clone, Debug)]
pub struct TlsWatch {
    verification: Verification,
    last: Arc<Mutex<Option<Seen>>>,
    /// When the certificate MCPdef presents to the server expires, if it
    /// presents one, in seconds since the Unix epoch.
    client_not_after: Option<i64>,
}

/// A certificate as it came, and as it reads.
#[derive(Debug)]
struct Seen {
    der: Vec<u8>,
    certificate: PeerCertificate,
}

impl TlsWatch {
    pub(crate) fn new(verification: Verification) -> TlsWatch {
        TlsWatch {
            verification,
            last: Arc::default(),
            client_not_after: None,
        }
    }

    /// The watch of connections that present `client`, the first certificate
    /// of a client identity: MCPdef's own, for mTLS.
    pub(crate) fn presenting(mut self, client: Option<&[u8]>) -> TlsWatch {
        self.client_not_after = client.and_then(not_after);
        self
    }

    /// How the server is verified.
    pub fn verification(&self) -> Verification {
        self.verification
    }

    /// When the certificate MCPdef presents to the server expires, its
    /// `notAfter` in seconds since the Unix epoch, if it presents one.
    pub fn client_not_after(&self) -> Option<i64> {
        self.client_not_after
    }

    /// The certificate the server presented last, once one has been seen.
    pub fn certificate(&self) -> Option<PeerCertificate> {
        self.lock().as_ref().map(|seen| seen.certificate.clone())
    }

    /// Keep the certificate `resp` came over, if it came over TLS.
    pub(crate) fn observe(&self, resp: &reqwest::Response) {
        let info = resp.extensions().get::<reqwest::tls::TlsInfo>();
        if let Some(der) = info.and_then(reqwest::tls::TlsInfo::peer_certificate) {
            self.record(der);
        }
    }

    /// Keep `der`. It is nearly always the one kept already, and then this
    /// is a comparison: only a new certificate is read.
    fn record(&self, der: &[u8]) {
        let mut last = self.lock();
        if last.as_ref().is_some_and(|seen| seen.der == der) {
            return;
        }
        *last = Some(Seen {
            der: der.to_vec(),
            certificate: PeerCertificate::read(der),
        });
    }

    fn lock(&self) -> MutexGuard<'_, Option<Seen>> {
        self.last.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The SHA-256 of `der`, in colon-separated hex.
pub(crate) fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
/// A certificate's `version`, `[0] EXPLICIT`: absent from a version 1 one.
const VERSION: u8 = 0xA0;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;

/// A certificate's `notAfter`, in seconds since the Unix epoch.
///
/// RFC 5280 §4.1: the certificate is a SEQUENCE whose first element, the
/// `tbsCertificate`, is one too. In that come an optional `version`, the
/// `serialNumber`, the `signature` algorithm, the `issuer`, and then the
/// `validity`: `notBefore`, then `notAfter`.
fn not_after(der: &[u8]) -> Option<i64> {
    let (certificate, _) = expect(der, SEQUENCE)?;
    let (mut fields, _) = expect(certificate, SEQUENCE)?;
    if let Some((VERSION, _, rest)) = element(fields) {
        fields = rest;
    }
    for tag in [INTEGER, SEQUENCE, SEQUENCE] {
        (_, fields) = expect(fields, tag)?;
    }
    let (validity, _) = expect(fields, SEQUENCE)?;
    let (_, _, times) = element(validity)?;
    match element(times)? {
        (UTC_TIME, time, _) => utc_time(time),
        (GENERALIZED_TIME, time, _) => generalized_time(time),
        _ => None,
    }
}

/// A certificate's `serialNumber`, the INTEGER's bytes less the zero byte DER
/// puts in front of one whose first bit is set: the bytes `openssl x509
/// -noout -serial` prints, and a CRL names the certificate by. RFC 5280
/// §4.1: it comes first in the `tbsCertificate`, after the optional
/// `version`.
pub fn certificate_serial(der: &[u8]) -> Option<Vec<u8>> {
    let (certificate, _) = expect(der, SEQUENCE)?;
    let (mut fields, _) = expect(certificate, SEQUENCE)?;
    if let Some((VERSION, _, rest)) = element(fields) {
        fields = rest;
    }
    let (serial, _) = expect(fields, INTEGER)?;
    let serial = match serial {
        [0, rest @ ..] if rest.first().is_some_and(|b| b & 0x80 != 0) => rest,
        serial => serial,
    };
    (!serial.is_empty()).then(|| serial.to_vec())
}

/// The contents of the element `der` starts with, which has to be a `tag`,
/// and what follows it.
fn expect(der: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    match element(der)? {
        (found, contents, rest) if found == tag => Some((contents, rest)),
        _ => None,
    }
}

/// The element `der` starts with: its tag, its contents, and what follows it.
/// DER's lengths are definite; one of more than four bytes is refused.
fn element(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0..=0x7F => (usize::from(first), rest),
        0x81..=0x84 => {
            let (bytes, rest) = rest.split_at_checked(usize::from(first & 0x7F))?;
            let len = bytes
                .iter()
                .fold(0, |len, &byte| (len << 8) | usize::from(byte));
            (len, rest)
        }
        _ => return None,
    };
    let (contents, rest) = rest.split_at_checked(len)?;
    Some((tag, contents, rest))
}

/// A UTCTime, `YYMMDDHHMMSSZ`, whose years RFC 5280 has run from 1950 to
/// 2049.
fn utc_time(text: &[u8]) -> Option<i64> {
    let yy = number(text.get(..2)?)?;
    time(if yy < 50 { 2000 + yy } else { 1900 + yy }, &text[2..])
}

/// A GeneralizedTime, `YYYYMMDDHHMMSSZ`, as RFC 5280 has it: in UTC, and
/// with no fraction of a second.
fn generalized_time(text: &[u8]) -> Option<i64> {
    time(number(text.get(..4)?)?, &text[4..])
}

/// `MMDDHHMMSSZ` of `year`, in seconds since the Unix epoch: how both of
/// RFC 5280's times end.
fn time(year: i64, text: &[u8]) -> Option<i64> {
    if text.len() != 11 || text[10] != b'Z' {
        return None;
    }
    let field = |at: usize| number(&text[at..at + 2]);
    let (month, day) = (field(0)?, field(2)?);
    let (hour, minute, second) = (field(4)?, field(6)?, field(8)?);
    let valid = (1..=12).contains(&month)
        && (1..=days_in_month(year, month)).contains(&day)
        && hour < 24
        && minute < 60
        && second < 60;
    valid.then(|| days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// The number `digits` spells, if they are all digits.
fn number(digits: &[u8]) -> Option<i64> {
    digits.iter().try_fold(0, |n, &digit| {
        digit
            .is_ascii_digit()
            .then(|| n * 10 + i64::from(digit - b'0'))
    })
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to `year-month-day` in the proleptic Gregorian
/// calendar: Howard Hinnant's `days_from_civil`.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let (era, year_of_era) = (year.div_euclid(400), year.rem_euclid(400));
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The date `days` after 1970-01-01: Hinnant's `civil_from_days`, the
/// inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let (era, day_of_era) = (days.div_euclid(146_097), days.rem_euclid(146_097));
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted + 2) / 5 + 1;
    let month = if shifted < 10 {
        shifted + 3
    } else {
        shifted - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Whom a certificate is for, and who issued it, as `mcpdef tls show` says
/// it. Read by the same DER walk as [`PeerCertificate`]: what it cannot read
/// is left out, never guessed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertificateNames {
    /// The subject's common name, if it has one.
    pub subject: Option<String>,
    /// The issuer's common name, if it has one.
    pub issuer: Option<String>,
    /// Its subjectAltName entries, in order: `DNS:…`, `IP:…`, `URI:…` and
    /// `email:…`, as `openssl x509 -text` shows them, less its long labels.
    pub alt_names: Vec<String>,
}

impl CertificateNames {
    /// The names the certificate `der` holds.
    pub fn read(der: &[u8]) -> CertificateNames {
        let Some(fields) = named(der) else {
            return CertificateNames::default();
        };
        CertificateNames {
            subject: common_name(fields.subject),
            issuer: common_name(fields.issuer),
            alt_names: fields.extensions.and_then(alt_names).unwrap_or_default(),
        }
    }
}

/// The fields of a certificate that name someone: its `issuer` and
/// `subject`, each a Name's contents, and its `extensions`' contents if it
/// has any.
struct Named<'a> {
    issuer: &'a [u8],
    subject: &'a [u8],
    extensions: Option<&'a [u8]>,
}

const OID: u8 = 0x06;
const OCTET_STRING: u8 = 0x04;
const BOOLEAN: u8 = 0x01;
const SET: u8 = 0x31;
/// A certificate's `extensions`, `[3] EXPLICIT`.
const EXTENSIONS: u8 = 0xA3;
/// `id-at-commonName`, 2.5.4.3.
const COMMON_NAME: [u8; 3] = [0x55, 0x04, 0x03];
/// `id-ce-subjectAltName`, 2.5.29.17.
const SUBJECT_ALT_NAME: [u8; 3] = [0x55, 0x1D, 0x11];

/// The fields of the certificate `der` that name someone.
fn named(der: &[u8]) -> Option<Named<'_>> {
    let (certificate, _) = expect(der, SEQUENCE)?;
    let (mut fields, _) = expect(certificate, SEQUENCE)?;
    if let Some((VERSION, _, rest)) = element(fields) {
        fields = rest;
    }
    for tag in [INTEGER, SEQUENCE] {
        (_, fields) = expect(fields, tag)?;
    }
    let (issuer, fields) = expect(fields, SEQUENCE)?;
    let (_, fields) = expect(fields, SEQUENCE)?;
    let (subject, mut fields) = expect(fields, SEQUENCE)?;
    (_, fields) = expect(fields, SEQUENCE)?;
    // The unique identifiers, `[1]` and `[2]`, come before the extensions.
    let mut extensions = None;
    while let Some((tag, contents, rest)) = element(fields) {
        if tag == EXTENSIONS {
            extensions = Some(expect(contents, SEQUENCE)?.0);
        }
        fields = rest;
    }
    Some(Named {
        issuer,
        subject,
        extensions,
    })
}

/// The first common name in a Name's contents: a SEQUENCE of RDNs, each a
/// SET of attributes, each a SEQUENCE of its type and value.
fn common_name(mut rdns: &[u8]) -> Option<String> {
    while !rdns.is_empty() {
        let (mut attributes, rest) = expect(rdns, SET)?;
        rdns = rest;
        while !attributes.is_empty() {
            let (attribute, rest) = expect(attributes, SEQUENCE)?;
            attributes = rest;
            let (oid, value) = expect(attribute, OID)?;
            if oid == COMMON_NAME {
                // UTF8String, PrintableString or IA5String; any other kind
                // of string reads as none.
                return match element(value)? {
                    (0x0C | 0x13 | 0x16, text, _) => std::str::from_utf8(text).ok().map(Into::into),
                    _ => None,
                };
            }
        }
    }
    None
}

/// The subjectAltName entries in a certificate's extensions, or none when it
/// has none: RFC 5280 §4.2.1.6.
fn alt_names(mut extensions: &[u8]) -> Option<Vec<String>> {
    while !extensions.is_empty() {
        let (extension, rest) = expect(extensions, SEQUENCE)?;
        extensions = rest;
        let (oid, mut value) = expect(extension, OID)?;
        if oid != SUBJECT_ALT_NAME {
            continue;
        }
        if let Some((BOOLEAN, _, rest)) = element(value) {
            value = rest;
        }
        let (general_names, _) = expect(value, OCTET_STRING)?;
        let (mut general_names, _) = expect(general_names, SEQUENCE)?;
        let mut names = Vec::new();
        while !general_names.is_empty() {
            let (tag, contents, rest) = element(general_names)?;
            general_names = rest;
            let text = || std::str::from_utf8(contents).ok();
            names.push(match tag {
                0x81 => format!("email:{}", text()?),
                0x82 => format!("DNS:{}", text()?),
                0x86 => format!("URI:{}", text()?),
                0x87 => format!("IP:{}", ip(contents)?),
                // otherName, x400Address, directoryName, ediPartyName and
                // registeredID: nothing a TLS client matches.
                _ => continue,
            });
        }
        return Some(names);
    }
    None
}

/// An iPAddress entry: four bytes, or sixteen.
fn ip(octets: &[u8]) -> Option<std::net::IpAddr> {
    match octets.len() {
        4 => Some(<[u8; 4]>::try_from(octets).ok()?.into()),
        16 => Some(<[u8; 16]>::try_from(octets).ok()?.into()),
        _ => None,
    }
}

/// `secs` since the Unix epoch in RFC 3339, in UTC, to the second:
/// `2031-02-03T00:00:00Z`.
pub fn rfc3339(secs: i64) -> String {
    let (days, secs) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3_600,
        secs / 60 % 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpdef_testkit::{Leaf, Pki};
    use proptest::prelude::*;

    /// DER: `tag`, the length of `contents`, and `contents`.
    fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        let len = contents.len();
        let mut out = vec![tag];
        match len {
            0..=0x7F => out.push(len as u8),
            0x80..=0xFF => out.extend([0x81, len as u8]),
            _ => out.extend([0x82, (len >> 8) as u8, len as u8]),
        }
        out.extend_from_slice(contents);
        out
    }

    /// A certificate's outline, with `version` or none, and `not_after` as
    /// `tag` and text. Nothing but the structure is real.
    fn outline(version: bool, tag: u8, not_after: &str) -> Vec<u8> {
        let mut tbs = Vec::new();
        if version {
            tbs.extend(tlv(VERSION, &tlv(INTEGER, &[2])));
        }
        tbs.extend(tlv(INTEGER, &[0x01, 0x23]));
        tbs.extend(tlv(SEQUENCE, &tlv(0x06, &[0x2A, 0x03])));
        tbs.extend(tlv(SEQUENCE, &[0x31; 200]));
        let mut validity = tlv(UTC_TIME, b"200101000000Z");
        validity.extend(tlv(tag, not_after.as_bytes()));
        tbs.extend(tlv(SEQUENCE, &validity));
        tbs.extend(tlv(SEQUENCE, &[]));
        let mut certificate = tlv(SEQUENCE, &tbs);
        certificate.extend(tlv(SEQUENCE, &tlv(0x06, &[0x2A, 0x03])));
        certificate.extend(tlv(0x03, &[0; 65]));
        tlv(SEQUENCE, &certificate)
    }

    /// The serial as the certificate holds it, less the zero byte DER puts in
    /// front of one whose first bit is set, with a `version` or without.
    #[test]
    fn a_serial_is_read_less_the_byte_that_keeps_it_positive() {
        let with = |version: bool, serial: &[u8]| {
            let mut tbs = Vec::new();
            if version {
                tbs.extend(tlv(VERSION, &tlv(INTEGER, &[2])));
            }
            tbs.extend(tlv(INTEGER, serial));
            tbs.extend(tlv(SEQUENCE, &[]));
            tlv(SEQUENCE, &tlv(SEQUENCE, &tbs))
        };
        for version in [true, false] {
            let read = |serial: &[u8]| certificate_serial(&with(version, serial));
            assert_eq!(read(&[0x4F, 0x2A]), Some(vec![0x4F, 0x2A]));
            assert_eq!(read(&[0x00, 0x80, 0x01]), Some(vec![0x80, 0x01]));
            assert_eq!(read(&[0x00]), Some(vec![0x00]));
            assert_eq!(read(&[]), None);
        }
        assert_eq!(
            certificate_serial(&outline(true, UTC_TIME, "300101000000Z")),
            Some(vec![0x01, 0x23])
        );
        assert_eq!(certificate_serial(b"not DER"), None);
    }

    #[test]
    fn the_not_after_of_an_issued_certificate_is_read_from_either_kind_of_time() {
        let pki = Pki::new("mcpdef test CA");
        // Before 2050, a UTCTime.
        let leaf = pki
            .leaf()
            .name("upstream.test")
            .valid((2020, 1, 1), (2031, 2, 3))
            .issue();
        let read = PeerCertificate::read(leaf.cert_der());
        assert_eq!(read.not_after, Some(1_927_843_200));
        assert_eq!(
            read.not_after_rfc3339().as_deref(),
            Some("2031-02-03T00:00:00Z")
        );
        // The testkit's default runs to 4096: a GeneralizedTime.
        let read = PeerCertificate::read(Leaf::self_signed(&["127.0.0.1"]).cert_der());
        assert_eq!(read.not_after, Some(67_090_118_400));
        assert_eq!(
            read.not_after_rfc3339().as_deref(),
            Some("4096-01-01T00:00:00Z")
        );
    }

    #[test]
    fn the_fingerprint_is_the_sha256_of_the_whole_certificate() {
        let leaf = Leaf::self_signed(&["127.0.0.1"]);
        let read = PeerCertificate::read(leaf.cert_der());
        let digest: Vec<String> = Sha256::digest(leaf.cert_der())
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        assert_eq!(read.fingerprint, digest.join(":"));
        assert_eq!(read.fingerprint.len(), 32 * 3 - 1);
    }

    #[test]
    fn the_times_rfc_5280_allows_are_read_at_their_edges() {
        for (tag, text, secs) in [
            (UTC_TIME, "310203000000Z", 1_927_843_200),
            (UTC_TIME, "491231235959Z", 2_524_607_999),
            (UTC_TIME, "500101000000Z", -631_152_000),
            (UTC_TIME, "750101000000Z", 157_766_400),
            (UTC_TIME, "000229123456Z", 951_827_696),
            (GENERALIZED_TIME, "20500101000000Z", 2_524_608_000),
            (GENERALIZED_TIME, "99991231235959Z", 253_402_300_799),
            (GENERALIZED_TIME, "20310203000000Z", 1_927_843_200),
        ] {
            for version in [true, false] {
                assert_eq!(
                    not_after(&outline(version, tag, text)),
                    Some(secs),
                    "{text}, version {version}"
                );
            }
        }
    }

    #[test]
    fn a_time_rfc_5280_does_not_allow_reads_as_none() {
        for (tag, text) in [
            (UTC_TIME, "3102030000Z"),
            (UTC_TIME, "310203000000"),
            (UTC_TIME, "310203000000+0100"),
            (UTC_TIME, "310230000000Z"),
            (UTC_TIME, "010229000000Z"),
            (UTC_TIME, "311303000000Z"),
            (UTC_TIME, "310003000000Z"),
            (UTC_TIME, "310200000000Z"),
            (UTC_TIME, "310203240000Z"),
            (UTC_TIME, "310203006000Z"),
            (UTC_TIME, "310203000060Z"),
            (UTC_TIME, "3102030000 0Z"),
            (UTC_TIME, "-10203000000Z"),
            (GENERALIZED_TIME, "20310203000000.5Z"),
            (GENERALIZED_TIME, "310203000000Z"),
            (GENERALIZED_TIME, "21000229000000Z"),
            (0x13, "310203000000Z"),
        ] {
            assert_eq!(not_after(&outline(true, tag, text)), None, "{tag} {text}");
        }
        // 2000 was a leap year, 2100 will not be.
        assert!(not_after(&outline(true, GENERALIZED_TIME, "20000229000000Z")).is_some());
    }

    #[test]
    fn what_is_not_a_certificate_reads_as_none() {
        let der = Pki::new("mcpdef test CA").server(&["127.0.0.1"]);
        let der = der.cert_der().to_vec();
        assert!(not_after(&der).is_some());
        // Every truncation of a real one.
        for end in 0..der.len() {
            assert_eq!(not_after(&der[..end]), None, "cut at {end}");
        }
        // A length DER does not have: indefinite, or of more than four bytes.
        for bad in [
            vec![SEQUENCE, 0x80, 0, 0],
            vec![SEQUENCE, 0x85, 0, 0, 0, 0, 1, 0],
            vec![SEQUENCE, 0x84, 0xFF, 0xFF, 0xFF, 0xFF],
            vec![],
            vec![SEQUENCE],
        ] {
            assert_eq!(not_after(&bad), None, "{bad:02X?}");
        }
        // A field out of place: the serial number where the version was.
        let mut swapped = outline(false, UTC_TIME, "310203000000Z");
        let at = swapped.iter().position(|&b| b == INTEGER).unwrap();
        swapped[at] = VERSION;
        assert_eq!(not_after(&swapped), None);
    }

    #[test]
    fn the_names_of_an_issued_certificate_are_read_in_order() {
        let pki = Pki::new("mcpdef test CA");
        let leaf = pki
            .leaf()
            .common_name("upstream")
            .name("upstream.test")
            .name("127.0.0.1")
            .name("::1")
            .uri("spiffe://mcpdef.test/upstream")
            .email("ops@mcpdef.test")
            .issue();
        let strings = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        assert_eq!(
            CertificateNames::read(leaf.cert_der()),
            CertificateNames {
                subject: Some("upstream".to_string()),
                issuer: Some("mcpdef test CA".to_string()),
                alt_names: strings(&[
                    "DNS:upstream.test",
                    "IP:127.0.0.1",
                    "IP:::1",
                    "URI:spiffe://mcpdef.test/upstream",
                    "email:ops@mcpdef.test",
                ]),
            }
        );
        // A root names itself as its issuer, and has no alternative names.
        assert_eq!(
            CertificateNames::read(pki.cert_der()),
            CertificateNames {
                subject: Some("mcpdef test CA".to_string()),
                issuer: Some("mcpdef test CA".to_string()),
                alt_names: Vec::new(),
            }
        );
        // Under an intermediate, the issuer is the intermediate.
        let intermediate = pki.intermediate("mcpdef issuing CA");
        let names = CertificateNames::read(intermediate.server(&["a.test"]).cert_der());
        assert_eq!(names.issuer.as_deref(), Some("mcpdef issuing CA"));
        assert_eq!(names.alt_names, strings(&["DNS:a.test"]));
    }

    #[test]
    fn what_is_not_a_certificate_names_nothing() {
        let der = Pki::new("mcpdef test CA").server(&["127.0.0.1"]);
        let der = der.cert_der().to_vec();
        assert_eq!(
            CertificateNames::read(&der).alt_names,
            ["IP:127.0.0.1".to_string()]
        );
        // Every truncation of a real one reads as nothing: its outer lengths
        // no longer fit.
        for end in 0..der.len() {
            assert_eq!(
                CertificateNames::read(&der[..end]),
                CertificateNames::default(),
                "cut at {end}"
            );
        }
        // An address of neither four bytes nor sixteen is no address.
        assert_eq!(ip(&[127, 0, 0]), None);
        assert_eq!(ip(&[0; 16]), Some("::".parse().unwrap()));
    }

    #[test]
    fn a_watch_keeps_the_certificate_seen_last_and_its_clones_share_it() {
        let watch = TlsWatch::new(Verification::Pin);
        assert_eq!(watch.verification(), Verification::Pin);
        assert_eq!(watch.certificate(), None);
        let first = Leaf::self_signed(&["127.0.0.1"]);
        let renewed = first.renewed();
        let clone = watch.clone();
        clone.record(first.cert_der());
        assert_eq!(
            watch.certificate(),
            Some(PeerCertificate::read(first.cert_der()))
        );
        watch.record(renewed.cert_der());
        assert_eq!(
            clone.certificate(),
            Some(PeerCertificate::read(renewed.cert_der()))
        );
        assert_ne!(
            PeerCertificate::read(first.cert_der()).fingerprint,
            PeerCertificate::read(renewed.cert_der()).fingerprint
        );
    }

    #[test]
    fn rfc3339_prints_the_epoch_and_the_edges() {
        for (secs, text) in [
            (0, "1970-01-01T00:00:00Z"),
            (-1, "1969-12-31T23:59:59Z"),
            (-631_152_000, "1950-01-01T00:00:00Z"),
            (951_827_696, "2000-02-29T12:34:56Z"),
            (253_402_300_799, "9999-12-31T23:59:59Z"),
        ] {
            assert_eq!(rfc3339(secs), text);
        }
    }

    proptest! {
        /// A GeneralizedTime read, then printed in RFC 3339, is the date and
        /// time it spelled: the two calendar conversions are each other's
        /// inverse, over every date a certificate can hold.
        #[test]
        fn a_time_read_prints_as_what_it_spelled(
            year in 0i64..=9999,
            month in 1i64..=12,
            day in 1i64..=31,
            hour in 0i64..24,
            minute in 0i64..60,
            second in 0i64..60,
        ) {
            let day = day.min(days_in_month(year, month));
            let text = format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z");
            let secs = generalized_time(text.as_bytes()).expect("a valid time");
            prop_assert_eq!(
                rfc3339(secs),
                format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
            );
            // A day later is 86,400 seconds later, across months and years.
            let (y, m, d) = civil_from_days(secs.div_euclid(86_400) + 1);
            prop_assert_eq!(days_from_civil(y, m, d) * 86_400, secs - secs.rem_euclid(86_400) + 86_400);
        }

        /// No input makes the walk panic, and whatever it reads is a time a
        /// certificate can hold, from 0000-01-01 to 9999-12-31: for arbitrary
        /// bytes, and for a certificate's outline with any one byte changed,
        /// which takes the walk deeper than noise does.
        #[test]
        fn any_bytes_read_without_panicking(
            bytes in proptest::collection::vec(any::<u8>(), 0..512),
            at in any::<proptest::sample::Index>(),
            byte in any::<u8>(),
        ) {
            let mut changed = outline(true, UTC_TIME, "310203000000Z");
            let at = at.index(changed.len());
            changed[at] = byte;
            for der in [&bytes, &changed] {
                let read = not_after(der);
                prop_assert!(
                    read.is_none_or(|t| (-62_167_219_200..=253_402_300_799).contains(&t)),
                    "{read:?}"
                );
                CertificateNames::read(der);
            }
        }

        /// Nor does a real certificate with any one byte changed make the
        /// names' walk panic: it goes through every field of one, its
        /// extensions included.
        #[test]
        fn a_changed_certificate_names_without_panicking(
            at in any::<proptest::sample::Index>(),
            byte in any::<u8>(),
        ) {
            let leaf = names_leaf();
            let mut der = leaf.to_vec();
            let at = at.index(der.len());
            der[at] = byte;
            CertificateNames::read(&der);
        }
    }

    /// One certificate for the property above, made once: a key pair per
    /// case would be most of its time.
    fn names_leaf() -> &'static [u8] {
        static LEAF: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        LEAF.get_or_init(|| {
            Pki::new("mcpdef test CA")
                .leaf()
                .common_name("upstream")
                .name("upstream.test")
                .name("::1")
                .uri("spiffe://mcpdef.test/upstream")
                .issue()
                .cert_der()
                .to_vec()
        })
    }
}
