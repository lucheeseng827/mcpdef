// SPDX-License-Identifier: Apache-2.0
//! A client's certificate as a proxy in front of MCPdef forwards it
//! (`[gateway.trusted_proxy]`), having terminated the client's TLS itself:
//! in an RFC 9440 `Client-Cert` header, its chain in `Client-Cert-Chain`, or
//! in the `x-forwarded-client-cert` (XFCC) that Envoy and Istio write.
//!
//! **From the proxy alone.** The header is read on a connection from an
//! address in `cidrs`, and on no other: anyone can write it, which is why
//! RFC 9440 has the proxy strip it from what it forwards, and Envoy's own
//! docs call XFCC easily spoofed. A certificate is no secret, so whoever
//! may send the header can be any client whose certificate they have seen.
//! From anyone else the header is not read at all; and like every header a
//! client sends, it is never forwarded to an upstream.
//!
//! **Checked by MCPdef.** The proxy is trusted to say which certificate its
//! client presented, not that it checks out. MCPdef checks it as it checks
//! one presented at its own handshake, against `[gateway.tls.client_auth]`'s
//! CAs and CRLs, and reads its identity by the same rules (see
//! [`client_auth`](super::client_auth)).
//!
//! **Read strictly.** What does not read whole is refused, saying why, and
//! never taken for no certificate:
//! - `client-cert`: one Byte Sequence (RFC 8941), `:` base64 `:`, with no
//!   parameters, in one header; `client-cert-chain`, a List of them, the
//!   intermediates, only beside it.
//! - `x-forwarded-client-cert`: exactly one element, the one the proxy in
//!   front of MCPdef set (Envoy: `forward_client_cert_details =
//!   SANITIZE_SET`). Of more, MCPdef cannot tell which proxy wrote which. Its
//!   `Cert`, URL-encoded PEM, is the certificate, or else the first of its
//!   `Chain`, the rest of which are the intermediates. One that carries
//!   neither, as Istio's does by default, names a client MCPdef cannot check.
//! - At most [`MOST_CERTIFICATES`] certificates in all.

use crate::config::{ClientCertHeader, TrustedProxyConfig};
use axum::http::header::GetAll;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine as _;
use rustls::pki_types::pem::{self, SectionKind};
use rustls::pki_types::CertificateDer;
use std::net::IpAddr;

/// The most certificates a forwarded chain may hold, the client's own
/// among them: a deep chain is four or five.
pub const MOST_CERTIFICATES: usize = 10;

const CLIENT_CERT: HeaderName = HeaderName::from_static("client-cert");
const CLIENT_CERT_CHAIN: HeaderName = HeaderName::from_static("client-cert-chain");
const XFCC: HeaderName = HeaderName::from_static("x-forwarded-client-cert");

/// Base64 as RFC 8941 has a Byte Sequence read: the standard alphabet, with
/// or without its `=` padding, and pad bits that need not be zero.
const BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Optional whitespace, as HTTP and RFC 8941 allow it around a list's
/// members.
const OWS: [char; 2] = [' ', '\t'];

/// A range of addresses, as `cidrs` writes it: `10.0.0.0/8`, `fd00::/8`, or
/// an address alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// The range `text` writes, or why it writes none.
    pub fn parse(text: &str) -> Result<Cidr, String> {
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| {
            "is not an address, or a range such as 10.0.0.0/8 or fd00::/8".to_string()
        })?;
        if let IpAddr::V6(v6) = addr {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return Err(format!(
                    "is an IPv4 address written as IPv6: write it as IPv4, {v4}"
                ));
            }
        }
        let most = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => most,
            Some(prefix) => Some(prefix)
                .filter(|prefix| !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|prefix| prefix.parse::<u8>().ok())
                .filter(|&prefix| prefix <= most)
                .ok_or_else(|| format!("has a prefix length that is not 0 to {most}"))?,
        };
        let cidr = Cidr { addr, prefix };
        let network = cidr.network();
        if network != addr {
            return Err(format!(
                "has bits set past its prefix length: the range is {network}/{prefix}"
            ));
        }
        Ok(cidr)
    }

    /// Its prefix length: 0 for every address.
    pub fn prefix(self) -> u8 {
        self.prefix
    }

    /// Whether `ip` is in the range. An IPv4 address a dual-stack listener
    /// sees as IPv6 (`::ffff:10.1.2.3`) is the IPv4 address.
    pub fn contains(self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let diff = u32::from(net) ^ u32::from(ip);
                diff.checked_shr(32 - u32::from(self.prefix)).unwrap_or(0) == 0
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let diff = u128::from(net) ^ u128::from(ip);
                diff.checked_shr(128 - u32::from(self.prefix)).unwrap_or(0) == 0
            }
            _ => false,
        }
    }

    /// Its address with the bits past its prefix cleared.
    fn network(self) -> IpAddr {
        match self.addr {
            IpAddr::V4(addr) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                IpAddr::from((u32::from(addr) & mask).to_be_bytes())
            }
            IpAddr::V6(addr) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                IpAddr::from((u128::from(addr) & mask).to_be_bytes())
            }
        }
    }
}

/// The proxy a listener trusts in front of it: the addresses it connects
/// from, and the header it forwards its clients' certificates in.
#[derive(Clone, Debug)]
pub struct TrustedProxy {
    cidrs: Vec<Cidr>,
    header: ClientCertHeader,
}

impl TrustedProxy {
    /// The proxy `config` says.
    pub fn build(config: &TrustedProxyConfig) -> Result<TrustedProxy, String> {
        let cidrs = config
            .cidrs
            .iter()
            .map(|cidr| {
                Cidr::parse(cidr)
                    .map_err(|why| format!("[gateway.trusted_proxy] cidrs entry {cidr:?} {why}"))
            })
            .collect::<Result<_, _>>()?;
        Ok(TrustedProxy {
            cidrs,
            header: config.client_cert_header,
        })
    }

    /// Whether a connection from `peer` is from the proxy.
    pub fn trusts(&self, peer: IpAddr) -> bool {
        self.cidrs.iter().any(|cidr| cidr.contains(peer))
    }

    /// The certificate the proxy forwarded in `headers`, then its
    /// intermediates: `None` when it forwarded none; or why what it
    /// forwarded does not read.
    pub fn certificate(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<Vec<CertificateDer<'static>>>, String> {
        let chain = match self.header {
            ClientCertHeader::ClientCert => client_cert(
                headers.get_all(CLIENT_CERT),
                headers.get_all(CLIENT_CERT_CHAIN),
            )?,
            ClientCertHeader::XForwardedClientCert => xfcc(headers.get_all(XFCC))?,
        };
        match chain {
            Some(chain) if chain.len() > MOST_CERTIFICATES => Err(format!(
                "it holds {} certificates, and a chain of more than {MOST_CERTIFICATES} is \
                 refused",
                chain.len()
            )),
            chain => Ok(chain),
        }
    }
}

/// Each value of a header, as text, in order.
fn texts<'h>(values: GetAll<'h, HeaderValue>, name: &str) -> Result<Vec<&'h str>, String> {
    values
        .iter()
        .map(|value| {
            value
                .to_str()
                .map_err(|_| format!("{name} holds bytes that are not visible ASCII"))
        })
        .collect()
}

/// RFC 9440: the certificate in `Client-Cert`, one Byte Sequence in one
/// header, then the intermediates in `Client-Cert-Chain`, a List of them
/// that may come in several.
fn client_cert(
    cert: GetAll<'_, HeaderValue>,
    chain: GetAll<'_, HeaderValue>,
) -> Result<Option<Vec<CertificateDer<'static>>>, String> {
    let certs = texts(cert, "client-cert")?;
    let chain = texts(chain, "client-cert-chain")?.join(",");
    let cert = match certs[..] {
        [] if chain.trim_matches(OWS).is_empty() => return Ok(None),
        [] => return Err("client-cert-chain came without client-cert".to_string()),
        [cert] => cert,
        _ => {
            return Err(format!(
                "client-cert came {} times, where RFC 9440 has it once",
                certs.len()
            ))
        }
    };
    let cert = byte_sequence(cert).map_err(|why| format!("client-cert {why}"))?;
    let mut ders = vec![CertificateDer::from(cert)];
    if !chain.trim_matches(OWS).is_empty() {
        for (n, member) in chain.split(',').enumerate() {
            let der = byte_sequence(member)
                .map_err(|why| format!("client-cert-chain member {} {why}", n + 1))?;
            ders.push(CertificateDer::from(der));
        }
    }
    Ok(Some(ders))
}

/// The bytes an RFC 8941 Byte Sequence holds, `:` base64 `:`, written
/// alone: with no parameters, and nothing after it.
fn byte_sequence(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim_matches(OWS);
    // RFC 8941 ends a Byte Sequence at its second colon: one inside it is
    // its end, with more after it.
    let base64 = text
        .strip_prefix(':')
        .and_then(|rest| rest.strip_suffix(':'))
        .filter(|base64| !base64.contains(':'))
        .ok_or("is not a Byte Sequence, base64 between colons, written alone")?;
    let bytes = BASE64
        .decode(base64)
        .map_err(|e| format!("does not decode as base64: {e}"))?;
    if bytes.is_empty() {
        return Err("is empty".to_string());
    }
    Ok(bytes)
}

/// Envoy's XFCC: the certificate its one element's `Cert` holds, or the
/// first its `Chain` holds, then the rest of that chain.
fn xfcc(values: GetAll<'_, HeaderValue>) -> Result<Option<Vec<CertificateDer<'static>>>, String> {
    let value = texts(values, "x-forwarded-client-cert")?.join(",");
    if value.trim_matches(OWS).is_empty() {
        return Ok(None);
    }
    let elements = xfcc_elements(&value).map_err(|why| format!("x-forwarded-client-cert {why}"))?;
    let [element] = &elements[..] else {
        return Err(format!(
            "x-forwarded-client-cert has {} elements, and MCPdef cannot tell which proxy wrote \
             which: have the proxy in front of it set the header, not append to it (Envoy: \
             forward_client_cert_details = SANITIZE_SET)",
            elements.len()
        ));
    };
    let once = |key: &str| {
        let values: Vec<&str> = element
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
            .collect();
        match values[..] {
            [] => Ok(None),
            [value] => Ok(Some(value)),
            _ => Err(format!("x-forwarded-client-cert has {key} twice")),
        }
    };
    let pem = |key: &str, value: &str| {
        percent_decoded(value)
            .and_then(|pem| pem_certificates(&pem))
            .map_err(|why| format!("x-forwarded-client-cert {key} {why}"))
    };
    let cert = once("Cert")?.map(|cert| pem("Cert", cert)).transpose()?;
    let chain = once("Chain")?
        .map(|chain| pem("Chain", chain))
        .transpose()?;
    let leaf = match (cert, chain.as_deref().and_then(<[_]>::first)) {
        (Some(certs), _) => match <[CertificateDer<'static>; 1]>::try_from(certs) {
            Ok([leaf]) => leaf,
            Err(certs) => {
                return Err(format!(
                    "x-forwarded-client-cert Cert holds {} certificates, where it holds the \
                     client's one",
                    certs.len()
                ))
            }
        },
        (None, Some(first)) => first.clone(),
        (None, None) => {
            return Err(
                "x-forwarded-client-cert carries no Cert: MCPdef checks the client's \
                        certificate itself, so the proxy has to forward it (Envoy: \
                        set_current_client_cert_details { cert: true })"
                    .to_string(),
            )
        }
    };
    let mut ders = vec![leaf];
    for der in chain.into_iter().flatten() {
        if der != ders[0] {
            ders.push(der);
        }
    }
    Ok(Some(ders))
}

/// The elements of an XFCC value, each its `key=value` pairs in order:
/// elements separated by `,`, pairs by `;`, and a value with `,`, `;` or
/// `=` in it double-quoted, a `"` in it written `\"`. Or why it does not
/// read so.
fn xfcc_elements(text: &str) -> Result<Vec<Vec<(String, String)>>, String> {
    let mut elements = Vec::new();
    let mut pairs = Vec::new();
    let mut rest = text.trim_start_matches(OWS);
    loop {
        let Some((key, after)) = rest.split_once('=') else {
            return Err("has a key with no `=` after it".to_string());
        };
        let key = key.trim_matches(OWS);
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(format!("has a key that is not one: {key:?}"));
        }
        let after = after.trim_start_matches(OWS);
        let value;
        (value, rest) = match after.strip_prefix('"') {
            Some(quoted) => unquoted(quoted)?,
            None => {
                let end = after.find([';', ',']).unwrap_or(after.len());
                let value = after[..end].trim_end_matches(OWS);
                if value.contains('"') {
                    return Err(format!("{key} has a `\"` in a value not quoted"));
                }
                (value.to_string(), &after[end..])
            }
        };
        pairs.push((key.to_string(), value));
        rest = rest.trim_start_matches(OWS);
        match rest.as_bytes().first() {
            None => {
                elements.push(pairs);
                return Ok(elements);
            }
            Some(b';') => rest = &rest[1..],
            Some(b',') => {
                elements.push(std::mem::take(&mut pairs));
                rest = rest[1..].trim_start_matches(OWS);
            }
            Some(_) => return Err(format!("{key}'s quoted value has more after it")),
        }
    }
}

/// A quoted value, from just after its opening `"`, read to its closing
/// one, a character after `\` taken as it is; and what follows it.
fn unquoted(quoted: &str) -> Result<(String, &str), String> {
    let mut value = String::new();
    let mut chars = quoted.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Ok((value, &quoted[i + 1..])),
            '\\' => match chars.next() {
                Some((_, escaped)) => value.push(escaped),
                None => break,
            },
            c => value.push(c),
        }
    }
    Err("has a quoted value that is never closed".to_string())
}

/// `text` with each `%` and the two hex digits after it read as the byte
/// they write, as a URL encodes. Or why it does not read so.
fn percent_decoded(text: &str) -> Result<Vec<u8>, String> {
    let hex = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    };
    let mut bytes = text.bytes();
    let mut decoded = Vec::with_capacity(text.len());
    while let Some(b) = bytes.next() {
        if b != b'%' {
            decoded.push(b);
            continue;
        }
        match (bytes.next().and_then(hex), bytes.next().and_then(hex)) {
            (Some(high), Some(low)) => decoded.push(high << 4 | low),
            _ => return Err("has a `%` not followed by two hex digits".to_string()),
        }
    }
    Ok(decoded)
}

/// The certificates PEM `text` holds, in order: one or more, and nothing
/// else. Or why it does not hold them.
fn pem_certificates(text: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut reader = text;
    let mut certs = Vec::new();
    loop {
        match pem::from_buf(&mut reader) {
            Ok(Some((SectionKind::Certificate, der))) => certs.push(CertificateDer::from(der)),
            Ok(Some((kind, _))) => {
                return Err(format!(
                    "holds a {kind:?} section, where it holds certificates alone"
                ))
            }
            Ok(None) if certs.is_empty() => {
                return Err("holds no certificate (-----BEGIN CERTIFICATE-----)".to_string())
            }
            Ok(None) => return Ok(certs),
            Err(e) => return Err(format!("does not read as PEM: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    fn proxy(header: ClientCertHeader) -> TrustedProxy {
        TrustedProxy::build(&TrustedProxyConfig {
            cidrs: vec!["10.0.0.0/8".into()],
            client_cert_header: header,
        })
        .unwrap()
    }

    /// What the proxy forwarded, as `header` and `pairs` say.
    fn forwarded(
        header: ClientCertHeader,
        pairs: &[(&'static str, &str)],
    ) -> Result<Option<Vec<Vec<u8>>>, String> {
        let chain = proxy(header).certificate(&headers(pairs))?;
        Ok(chain.map(|chain| chain.iter().map(|der| der.to_vec()).collect()))
    }

    fn sf(bytes: &[u8]) -> String {
        format!(
            ":{}:",
            base64::engine::general_purpose::STANDARD.encode(bytes)
        )
    }

    /// PEM for each of `ders`, URL-encoded as Envoy writes it.
    fn url_pem(ders: &[&[u8]]) -> String {
        let pem: String = ders
            .iter()
            .map(|der| {
                let b64 = base64::engine::general_purpose::STANDARD.encode(der);
                let lines: Vec<&str> = b64
                    .as_bytes()
                    .chunks(64)
                    .map(|line| std::str::from_utf8(line).unwrap())
                    .collect();
                format!(
                    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                    lines.join("\n")
                )
            })
            .collect();
        pem.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    (b as char).to_string()
                }
                b => format!("%{b:02X}"),
            })
            .collect()
    }

    #[test]
    fn a_range_holds_the_addresses_under_its_prefix() {
        let net = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(net.contains("10.255.1.2".parse().unwrap()));
        assert!(!net.contains("11.0.0.1".parse().unwrap()));
        assert!(!net.contains("::1".parse().unwrap()));
        // An IPv4 client of a dual-stack listener.
        assert!(net.contains("::ffff:10.1.2.3".parse().unwrap()));
        let one = Cidr::parse("192.0.2.7").unwrap();
        assert_eq!(one.prefix(), 32);
        assert!(one.contains("192.0.2.7".parse().unwrap()));
        assert!(!one.contains("192.0.2.8".parse().unwrap()));
        let every = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(every.contains("203.0.113.9".parse().unwrap()));
        assert!(!every.contains("2001:db8::1".parse().unwrap()));
        let v6 = Cidr::parse("fd00::/8").unwrap();
        assert!(v6.contains("fd12:3456::1".parse().unwrap()));
        assert!(!v6.contains("fe80::1".parse().unwrap()));
        assert!(Cidr::parse("::/0")
            .unwrap()
            .contains("2001:db8::1".parse().unwrap()));
        assert!(Cidr::parse("2001:db8::1/128")
            .unwrap()
            .contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn a_range_that_is_not_one_says_why() {
        let why = |text: &str| Cidr::parse(text).unwrap_err();
        assert_eq!(
            why("10.0.0.1/8"),
            "has bits set past its prefix length: the range is 10.0.0.0/8"
        );
        assert_eq!(
            why("10.0.0.0/33"),
            "has a prefix length that is not 0 to 32"
        );
        assert_eq!(
            why("fd00::/129"),
            "has a prefix length that is not 0 to 128"
        );
        assert_eq!(why("10.0.0.0/"), "has a prefix length that is not 0 to 32");
        assert_eq!(
            why("10.0.0.0/-1"),
            "has a prefix length that is not 0 to 32"
        );
        assert_eq!(
            why("10.0.0.0/+8"),
            "has a prefix length that is not 0 to 32"
        );
        assert!(why("proxy.internal").starts_with("is not an address"));
        assert!(why("10.0.0.0/8/8").starts_with("has a prefix length"));
        assert_eq!(
            why("::ffff:10.0.0.0/104"),
            "is an IPv4 address written as IPv6: write it as IPv4, 10.0.0.0"
        );
    }

    #[test]
    fn rfc_9440_reads_the_certificate_and_its_chain() {
        let header = ClientCertHeader::ClientCert;
        assert_eq!(forwarded(header, &[]), Ok(None));
        let leaf = sf(b"leaf");
        assert_eq!(
            forwarded(header, &[("client-cert", &leaf)]),
            Ok(Some(vec![b"leaf".to_vec()]))
        );
        // The chain as one list, and as several headers: the same.
        let chain = format!("{}, {}", sf(b"intermediate"), sf(b"root"));
        let want = Ok(Some(vec![
            b"leaf".to_vec(),
            b"intermediate".to_vec(),
            b"root".to_vec(),
        ]));
        assert_eq!(
            forwarded(
                header,
                &[("client-cert", &leaf), ("client-cert-chain", &chain)]
            ),
            want
        );
        assert_eq!(
            forwarded(
                header,
                &[
                    ("client-cert", &leaf),
                    ("client-cert-chain", &sf(b"intermediate")),
                    ("client-cert-chain", &sf(b"root")),
                ]
            ),
            want
        );
        // Unpadded base64, which RFC 8941 has a parser take.
        assert_eq!(
            forwarded(header, &[("client-cert", ":bGVhZg:")]),
            Ok(Some(vec![b"leaf".to_vec()]))
        );
        // The other header is not read.
        assert_eq!(
            forwarded(
                ClientCertHeader::XForwardedClientCert,
                &[("client-cert", &leaf)]
            ),
            Ok(None)
        );
    }

    #[test]
    fn rfc_9440_refuses_what_it_does_not_read_whole() {
        let refused = |pairs: &[(&'static str, &str)]| {
            forwarded(ClientCertHeader::ClientCert, pairs).unwrap_err()
        };
        let leaf = sf(b"leaf");
        assert_eq!(
            refused(&[("client-cert", &leaf), ("client-cert", &leaf)]),
            "client-cert came 2 times, where RFC 9440 has it once"
        );
        assert_eq!(
            refused(&[("client-cert-chain", &leaf)]),
            "client-cert-chain came without client-cert"
        );
        let not_one = "client-cert is not a Byte Sequence, base64 between colons, written alone";
        for value in [
            "bGVhZg==",
            ":bGVhZg==",
            ":bGVhZg==:;a=1",
            ":bGVh:Zg==:",
            "\"bGVhZg==\"",
        ] {
            assert_eq!(refused(&[("client-cert", value)]), not_one, "{value}");
        }
        assert!(refused(&[("client-cert", ":bGV*Zg==:")])
            .starts_with("client-cert does not decode as base64"));
        assert_eq!(refused(&[("client-cert", "::")]), "client-cert is empty");
        assert_eq!(
            refused(&[
                ("client-cert", &leaf),
                ("client-cert-chain", &format!("{leaf},,{leaf}"))
            ]),
            "client-cert-chain member 2 is not a Byte Sequence, base64 between colons, \
             written alone"
        );
        let mut many = vec![leaf.clone(); MOST_CERTIFICATES];
        many.push(leaf.clone());
        let chain = many[1..].join(", ");
        assert_eq!(
            refused(&[("client-cert", &leaf), ("client-cert-chain", &chain)]),
            format!(
                "it holds {} certificates, and a chain of more than {MOST_CERTIFICATES} is \
                 refused",
                MOST_CERTIFICATES + 1
            )
        );
    }

    #[test]
    fn xfcc_reads_its_one_element_cert_and_chain() {
        let header = ClientCertHeader::XForwardedClientCert;
        let read = |value: &str| forwarded(header, &[("x-forwarded-client-cert", value)]);
        let leaf: &[u8] = b"leaf certificate";
        let intermediate: &[u8] = b"intermediate certificate";
        let cert = url_pem(&[leaf]);
        let chain = url_pem(&[leaf, intermediate]);
        // As Envoy writes it, the subject quoted for its `,` and `=`.
        let value = format!(
            "By=spiffe://cluster.local/ns/mcp/sa/mcpdef;Hash=0123abcd;Cert={cert};\
             Chain={chain};Subject=\"CN=bot,O=Acme \\\"CI\\\"\";URI=spiffe://prod.acme.internal/ns/ci/sa/bot"
        );
        assert_eq!(
            read(&value),
            Ok(Some(vec![leaf.to_vec(), intermediate.to_vec()]))
        );
        // Its Cert alone, or its Chain alone, the first of which is the
        // client's.
        assert_eq!(read(&format!("Cert={cert}")), Ok(Some(vec![leaf.to_vec()])));
        assert_eq!(
            read(&format!("chain=\"{chain}\"")),
            Ok(Some(vec![leaf.to_vec(), intermediate.to_vec()]))
        );
        assert_eq!(read(""), Ok(None));
        assert_eq!(forwarded(header, &[]), Ok(None));
        // The other header is not read.
        assert_eq!(
            forwarded(
                ClientCertHeader::ClientCert,
                &[("x-forwarded-client-cert", &value)]
            ),
            Ok(None)
        );
    }

    #[test]
    fn xfcc_refuses_what_it_does_not_read_whole() {
        let refused = |value: &str| {
            forwarded(
                ClientCertHeader::XForwardedClientCert,
                &[("x-forwarded-client-cert", value)],
            )
            .unwrap_err()
        };
        let cert = url_pem(&[b"leaf"]);
        let two = format!("Cert={cert},By=spiffe://edge;Cert={cert}");
        assert!(refused(&two).starts_with("x-forwarded-client-cert has 2 elements"));
        // Two in two headers, as a proxy that appends would send them.
        let in_two = forwarded(
            ClientCertHeader::XForwardedClientCert,
            &[
                ("x-forwarded-client-cert", &format!("Cert={cert}")),
                ("x-forwarded-client-cert", &format!("Cert={cert}")),
            ],
        );
        assert!(in_two
            .unwrap_err()
            .starts_with("x-forwarded-client-cert has 2 elements"));
        assert!(
            refused("By=spiffe://edge;URI=spiffe://prod.acme.internal/ns/ci/sa/bot")
                .starts_with("x-forwarded-client-cert carries no Cert")
        );
        assert_eq!(
            refused(&format!("Cert={cert};Cert={cert}")),
            "x-forwarded-client-cert has Cert twice"
        );
        assert_eq!(
            refused(&format!("Cert={}", url_pem(&[b"one", b"two"]))),
            "x-forwarded-client-cert Cert holds 2 certificates, where it holds the client's one"
        );
        assert_eq!(
            refused("Cert=%2"),
            "x-forwarded-client-cert Cert has a `%` not followed by two hex digits"
        );
        assert_eq!(
            refused("Cert=%+1"),
            "x-forwarded-client-cert Cert has a `%` not followed by two hex digits"
        );
        assert_eq!(
            refused("Cert=MIIB"),
            "x-forwarded-client-cert Cert holds no certificate (-----BEGIN CERTIFICATE-----)"
        );
        let crl = "-----BEGIN X509 CRL-----\nMIIB\n-----END X509 CRL-----\n"
            .replace('\n', "%0A")
            .replace(' ', "%20");
        assert_eq!(
            refused(&format!("Cert={crl}")),
            "x-forwarded-client-cert Cert holds a Crl section, where it holds certificates alone"
        );
        assert_eq!(
            refused("Subject=\"CN=bot;Cert="),
            "x-forwarded-client-cert has a quoted value that is never closed"
        );
        assert_eq!(
            refused("Subject=\"CN=bot\"x;Cert=a"),
            "x-forwarded-client-cert Subject's quoted value has more after it"
        );
        assert_eq!(
            refused("Cert=a\"b"),
            "x-forwarded-client-cert Cert has a `\"` in a value not quoted"
        );
        assert_eq!(
            refused("Cert"),
            "x-forwarded-client-cert has a key with no `=` after it"
        );
        assert_eq!(
            refused("By=x;;Cert=y"),
            "x-forwarded-client-cert has a key that is not one: \";Cert\""
        );
        assert_eq!(
            refused("=x"),
            "x-forwarded-client-cert has a key that is not one: \"\""
        );
        assert_eq!(
            refused("By=x,"),
            "x-forwarded-client-cert has a key with no `=` after it"
        );
    }

    #[test]
    fn xfcc_elements_split_where_quotes_say() {
        assert_eq!(
            xfcc_elements("By=a;Subject=\"x,y;z=1\",URI=b"),
            Ok(vec![
                vec![
                    ("By".to_string(), "a".to_string()),
                    ("Subject".to_string(), "x,y;z=1".to_string()),
                ],
                vec![("URI".to_string(), "b".to_string())],
            ])
        );
        // An unquoted value runs to the next `;` or `,`, `=` and all.
        assert_eq!(
            xfcc_elements("Hash=ab=cd"),
            Ok(vec![vec![("Hash".to_string(), "ab=cd".to_string())]])
        );
        assert_eq!(
            xfcc_elements("Subject=\"a\\\\b\\\"c\""),
            Ok(vec![vec![("Subject".to_string(), "a\\b\"c".to_string())]])
        );
    }

    proptest! {
        // Fuzzing: whatever a proxy, or a peer it relays for, writes, the
        // parsers answer, and never panic.
        #[test]
        fn the_parsers_take_any_text(text in "\\PC{0,200}") {
            let _ = byte_sequence(&text);
            let _ = xfcc_elements(&text);
            let _ = percent_decoded(&text);
            let _ = pem_certificates(text.as_bytes());
            let _ = Cidr::parse(&text);
        }

        #[test]
        fn the_parsers_take_any_text_of_their_own_alphabet(
            text in "[A-Za-z0-9+/=:;,\"\\\\% \t-]{0,200}",
        ) {
            let _ = byte_sequence(&text);
            let _ = xfcc_elements(&text);
            let _ = percent_decoded(&text);
            if let Ok(value) = HeaderValue::from_str(&text) {
                let mut map = HeaderMap::new();
                map.append(CLIENT_CERT, value.clone());
                map.append(CLIENT_CERT_CHAIN, value.clone());
                map.append(XFCC, value);
                let _ = proxy(ClientCertHeader::ClientCert).certificate(&map);
                let _ = proxy(ClientCertHeader::XForwardedClientCert).certificate(&map);
            }
        }

        #[test]
        fn a_byte_sequence_reads_back_what_it_writes(bytes in proptest::collection::vec(any::<u8>(), 1..300)) {
            prop_assert_eq!(byte_sequence(&sf(&bytes)), Ok(bytes));
        }

        #[test]
        fn percent_decoding_reads_back_what_encoding_writes(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            let encoded: String = bytes.iter().map(|b| format!("%{b:02x}")).collect();
            prop_assert_eq!(percent_decoded(&encoded), Ok(bytes));
        }

        #[test]
        fn xfcc_reads_back_any_quoted_value(value in "\\PC{0,100}", key in "[A-Za-z][A-Za-z0-9-]{0,10}") {
            let quoted = value.replace('\\', "\\\\").replace('"', "\\\"");
            let text = format!("{key}=\"{quoted}\"");
            prop_assert_eq!(xfcc_elements(&text), Ok(vec![vec![(key, value)]]));
        }

        #[test]
        fn a_range_holds_its_own_network_and_the_addresses_under_it(
            addr in any::<u32>(),
            prefix in 0u8..=32,
            host in any::<u32>(),
        ) {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            let network = std::net::Ipv4Addr::from(addr & mask);
            let cidr = Cidr::parse(&format!("{network}/{prefix}")).unwrap();
            let inside = std::net::Ipv4Addr::from((addr & mask) | (host & !mask));
            prop_assert!(cidr.contains(IpAddr::V4(inside)));
            let outside = u32::from(inside) ^ (1u32.checked_shl(32 - u32::from(prefix)).unwrap_or(0));
            if prefix > 0 {
                prop_assert!(!cidr.contains(IpAddr::V4(outside.into())));
            }
        }
    }
}
