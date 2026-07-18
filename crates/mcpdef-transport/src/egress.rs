// SPDX-License-Identifier: Apache-2.0
//! `egress` — the SSRF guard for HTTP upstreams (ARCHITECTURE.md §7/§9).
//!
//! An MCP gateway dials out to upstream servers, and — in the legacy HTTP+SSE
//! bridge — to a POST URL the *server itself* names in its `endpoint` event. A
//! compromised or malicious server can use that to point MCPdef at a host it was
//! never meant to reach: cloud-metadata (`169.254.169.254`), a private service,
//! or `localhost`. This module classifies a destination's resolved IP(s) and
//! enforces an [`EgressPolicy`] before any bytes are sent.
//!
//! Two design points specific to *MCPdef* (vs. a generic web-app SSRF guard):
//!
//! 1. **Private / loopback is allowed by default**, because MCPdef's whole job is
//!    fronting *internal* MCP servers (`http://127.0.0.1:3000`,
//!    `https://mcp.internal`). A blanket private-range block would break the
//!    primary use case. Operators can flip [`EgressPolicy::allow_private_network`]
//!    off for a hardened deployment.
//! 2. **Cloud-metadata / link-local is ALWAYS blocked**, regardless of policy —
//!    no MCP upstream legitimately lives at `169.254/16` or `fe80::/10`, and the
//!    instance-metadata endpoint is the single highest-value SSRF target.
//!
//! [`validate`] resolves the host **once** and returns the validated
//! [`SocketAddr`]s so the caller can **DNS-pin** the connection to exactly those
//! IPs — defeating a TOCTOU rebind between our check and the client's connect.

use crate::TransportError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use url::{Host, Url};

/// The egress rules applied to every HTTP destination MCPdef dials.
///
/// Cloud-metadata / link-local (`169.254/16`, `fe80::/10`) and the unspecified
/// address are **always** blocked and are not represented here — they are never
/// a valid upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressPolicy {
    /// Allow private / loopback / unique-local destinations
    /// (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `127/8`, `::1`,
    /// `fc00::/7`). **Default `true`** — MCPdef commonly fronts internal or
    /// localhost MCP servers. Set `false` to only reach public upstreams.
    pub allow_private_network: bool,
    /// Require HTTPS for **public** destinations (private/loopback may be plain
    /// HTTP for dev/internal use). **Default `true`** — never leak a brokered
    /// credential to a public plaintext endpoint.
    pub require_https_public: bool,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        EgressPolicy {
            allow_private_network: true,
            require_https_public: true,
        }
    }
}

impl EgressPolicy {
    /// A hardened policy: block all private/loopback ranges, require HTTPS.
    pub fn hardened() -> Self {
        EgressPolicy {
            allow_private_network: false,
            require_https_public: true,
        }
    }
}

/// The reachability class of a resolved IP, coarsest-blocked first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpClass {
    /// `169.254/16` (incl. the instance-metadata `169.254.169.254`) or `fe80::/10`.
    LinkLocal,
    /// `0.0.0.0` / `::` — never a real destination.
    Unspecified,
    /// Special-use / non-global ranges that are never a real public upstream:
    /// multicast, documentation (`192.0.2/24`, `2001:db8::/32`), benchmarking
    /// (`198.18/15`), IETF protocol assignments (`192.0.0/24`), and reserved
    /// (`240/4`, `ff00::/8`). Always blocked, like link-local.
    SpecialUse,
    /// `127/8` / `::1`.
    Loopback,
    /// RFC 1918 + CGNAT + unique-local.
    Private,
    /// Globally routable.
    Public,
}

/// A validated destination: the resolved addresses to **pin** the connection to.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The URL host as written (domain or IP literal) — the key for DNS pinning.
    pub host: String,
    /// Validated `(ip, port)` pairs; pin the client to exactly these.
    pub addrs: Vec<SocketAddr>,
    /// True if `host` is a domain (so DNS pinning is meaningful).
    pub is_domain: bool,
}

fn classify_v4(ip: Ipv4Addr) -> IpClass {
    if ip.is_unspecified() {
        return IpClass::Unspecified;
    }
    if ip.is_loopback() {
        return IpClass::Loopback; // 127/8
    }
    if ip.is_link_local() || ip.is_broadcast() {
        return IpClass::LinkLocal; // 169.254/16 (incl. metadata), 255.255.255.255
    }
    if ip.is_private() {
        return IpClass::Private; // 10/8, 172.16/12, 192.168/16
    }
    let o = ip.octets();
    // Carrier-grade NAT 100.64/10 — treat as private (not a public upstream).
    if o[0] == 100 && (0x40..=0x7f).contains(&o[1]) {
        return IpClass::Private;
    }
    // Special-use / non-global ranges that are never a real public upstream.
    // (std's is_documentation/is_benchmarking/is_reserved are still unstable, so
    // match the octets directly.)
    let special = o[0] == 0                                            // 0.0.0.0/8 "this network"
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)                    // 192.0.0.0/24 IETF protocol
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)                    // 192.0.2.0/24 TEST-NET-1
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))               // 198.18.0.0/15 benchmarking
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)                // 198.51.100.0/24 TEST-NET-2
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)                 // 203.0.113.0/24 TEST-NET-3
        || ip.is_multicast()                                          // 224.0.0.0/4
        || (o[0] >= 240); // 240.0.0.0/4 reserved (255.255.255.255 already LinkLocal above)
    if special {
        return IpClass::SpecialUse;
    }
    IpClass::Public
}

fn classify_v6(ip: Ipv6Addr) -> IpClass {
    // IPv4-mapped (`::ffff:a.b.c.d`) — classify the embedded v4 so a domain that
    // resolves to a mapped metadata address can't slip through.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    if ip.is_unspecified() {
        return IpClass::Unspecified;
    }
    if ip.is_loopback() {
        return IpClass::Loopback; // ::1
    }
    let s = ip.segments();
    if (s[0] & 0xffc0) == 0xfe80 {
        return IpClass::LinkLocal; // fe80::/10
    }
    if (s[0] & 0xfe00) == 0xfc00 {
        return IpClass::Private; // fc00::/7 unique-local
    }
    // Special-use ranges that are never a real public upstream (IANA IPv6
    // special-purpose registry). Always blocked, like link-local.
    let special = ip.is_multicast()                          // ff00::/8
        || (s[0] == 0x2001 && s[1] == 0x0db8)                // 2001:db8::/32 documentation
        || (s[0] == 0x3fff && (s[1] & 0xf000) == 0)          // 3fff::/20 documentation (RFC 9637)
        || (s[0] == 0x2001 && s[1] == 0x0002 && s[2] == 0)   // 2001:2::/48 benchmarking
        || s[0] == 0x5f00                                    // 5f00::/16 SRv6 SIDs (RFC 9602)
        || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0)        // 100::/48 discard-only + dummy
        || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001); // 64:ff9b:1::/48 local NAT64
    if special {
        return IpClass::SpecialUse;
    }
    IpClass::Public
}

fn classify(ip: IpAddr) -> IpClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// Decide a single resolved IP against `policy`. `Ok(true)` if the IP is public.
fn check_ip(host: &str, ip: IpAddr, policy: &EgressPolicy) -> Result<bool, TransportError> {
    match classify(ip) {
        IpClass::LinkLocal | IpClass::Unspecified => Err(TransportError::Egress(format!(
            "{host} → {ip} is a link-local/metadata/unspecified address (always blocked)"
        ))),
        IpClass::SpecialUse => Err(TransportError::Egress(format!(
            "{host} → {ip} is a special-use/non-global address (multicast/doc/benchmark/reserved — always blocked)"
        ))),
        IpClass::Loopback | IpClass::Private => {
            if policy.allow_private_network {
                Ok(false)
            } else {
                Err(TransportError::Egress(format!(
                    "{host} → {ip} is a private/loopback address and egress.allow_private = false"
                )))
            }
        }
        IpClass::Public => Ok(true),
    }
}

/// Decide a single **resolved** socket IP for a non-HTTP egress path (the WASM
/// sandbox's outbound sockets), reusing the exact HTTP IP classification: cloud-
/// metadata / link-local / special-use / unspecified are **always** blocked;
/// private / loopback are gated by [`EgressPolicy::allow_private_network`]; public
/// is allowed. `Ok(())` means the address passes; `Err` describes the block.
///
/// Unlike [`validate`], this takes an already-resolved [`IpAddr`] (the sandbox's
/// host-fn socket hook hands us the resolved address), so there is no DNS step
/// here — the caller pairs this with an explicit destination allowlist.
pub fn check_socket_ip(ip: IpAddr, policy: &EgressPolicy) -> Result<(), TransportError> {
    check_ip("sandbox egress", ip, policy).map(|_| ())
}

/// Validate `url_str` against `policy`, resolving the host and checking **every**
/// resolved IP (a split-horizon / multi-record host is only as safe as its worst
/// address). Returns the validated [`Resolved`] addresses for DNS pinning, or a
/// [`TransportError::Egress`] describing the block.
pub async fn validate(url_str: &str, policy: &EgressPolicy) -> Result<Resolved, TransportError> {
    let url = Url::parse(url_str)
        .map_err(|e| TransportError::Egress(format!("invalid url '{url_str}': {e}")))?;
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(TransportError::Egress(format!(
            "unsupported scheme '{scheme}' (only http/https) in {url_str}"
        )));
    }
    let host = url
        .host()
        .ok_or_else(|| TransportError::Egress(format!("url {url_str} has no host")))?;
    let port = url
        .port_or_known_default()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });

    let (host_str, is_domain, ips): (String, bool, Vec<IpAddr>) = match host {
        Host::Ipv4(a) => (a.to_string(), false, vec![IpAddr::V4(a)]),
        Host::Ipv6(a) => (a.to_string(), false, vec![IpAddr::V6(a)]),
        Host::Domain(d) => {
            let resolved: Vec<IpAddr> = tokio::net::lookup_host((d, port))
                .await
                .map_err(|e| TransportError::Egress(format!("resolving '{d}': {e}")))?
                .map(|sa| sa.ip())
                .collect();
            (d.to_string(), true, resolved)
        }
    };

    if ips.is_empty() {
        return Err(TransportError::Egress(format!(
            "host '{host_str}' resolved to no addresses"
        )));
    }

    let mut any_public = false;
    for ip in &ips {
        any_public |= check_ip(&host_str, *ip, policy)?;
    }
    if any_public && scheme == "http" && policy.require_https_public {
        return Err(TransportError::Egress(format!(
            "refusing plaintext HTTP to public host '{host_str}' (egress.require_https = true)"
        )));
    }

    let addrs = ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    Ok(Resolved {
        host: host_str,
        addrs,
        is_domain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn classifies_v4_ranges() {
        assert_eq!(classify(ip("169.254.169.254")), IpClass::LinkLocal); // cloud metadata
        assert_eq!(classify(ip("169.254.0.1")), IpClass::LinkLocal);
        assert_eq!(classify(ip("127.0.0.1")), IpClass::Loopback);
        assert_eq!(classify(ip("10.0.0.5")), IpClass::Private);
        assert_eq!(classify(ip("172.16.3.4")), IpClass::Private);
        assert_eq!(classify(ip("192.168.1.1")), IpClass::Private);
        assert_eq!(classify(ip("100.64.0.1")), IpClass::Private); // CGNAT
        assert_eq!(classify(ip("0.0.0.0")), IpClass::Unspecified);
        assert_eq!(classify(ip("8.8.8.8")), IpClass::Public);
        assert_eq!(classify(ip("172.32.0.1")), IpClass::Public); // just outside 172.16/12
    }

    #[test]
    fn classifies_special_use_ranges_as_blocked() {
        // IPv4 special-use ranges that are never a real public upstream.
        for s in [
            "0.1.2.3",         // 0/8 "this network" (0.0.0.0 itself is Unspecified)
            "192.0.0.1",       // 192.0.0/24 IETF protocol assignments
            "192.0.2.5",       // TEST-NET-1
            "198.18.0.1",      // benchmarking
            "198.19.255.254",  // benchmarking
            "198.51.100.10",   // TEST-NET-2
            "203.0.113.10",    // TEST-NET-3
            "224.0.0.1",       // multicast
            "239.255.255.250", // multicast (SSDP)
            "240.0.0.1",       // reserved
        ] {
            assert_eq!(
                classify(ip(s)),
                IpClass::SpecialUse,
                "{s} should be special-use"
            );
        }
        // IPv6 special-use (IANA special-purpose registry).
        for s in [
            "ff02::1",      // multicast
            "2001:db8::1",  // documentation
            "3fff::1",      // documentation (RFC 9637)
            "3fff:0fff::1", // still within 3fff::/20
            "2001:2::1",    // benchmarking
            "5f00::1",      // SRv6 SIDs (RFC 9602)
            "100::1",       // discard-only
            "100:0:0:1::1", // dummy address
            "64:ff9b:1::1", // local-use NAT64
        ] {
            assert_eq!(
                classify(ip(s)),
                IpClass::SpecialUse,
                "{s} should be special-use"
            );
        }
        // The GLOBAL NAT64 prefix (64:ff9b::/96) and real public addresses stay public.
        assert_eq!(classify(ip("64:ff9b::808:808")), IpClass::Public);
        assert_eq!(classify(ip("2606:4700:4700::1111")), IpClass::Public);
        assert_eq!(classify(ip("1.1.1.1")), IpClass::Public);
    }

    #[tokio::test]
    async fn validate_blocks_special_use_even_when_private_allowed() {
        // Default policy allows private/loopback but special-use is ALWAYS blocked.
        for url in [
            "https://192.0.2.10/x",    // documentation
            "https://198.18.0.10/x",   // benchmarking
            "https://240.0.0.10/x",    // reserved
            "https://[2001:db8::1]/x", // doc IPv6
        ] {
            assert!(
                validate(url, &EgressPolicy::default()).await.is_err(),
                "{url} must be blocked"
            );
        }
    }

    #[test]
    fn classifies_v6_ranges() {
        assert_eq!(classify(ip("::1")), IpClass::Loopback);
        assert_eq!(classify(ip("fe80::1")), IpClass::LinkLocal);
        assert_eq!(classify(ip("fc00::1")), IpClass::Private);
        assert_eq!(classify(ip("fd12:3456::1")), IpClass::Private);
        assert_eq!(classify(ip("2606:4700:4700::1111")), IpClass::Public);
        // IPv4-mapped metadata must be caught through the v6 form too.
        assert_eq!(classify(ip("::ffff:169.254.169.254")), IpClass::LinkLocal);
        assert_eq!(classify(ip("::ffff:10.0.0.1")), IpClass::Private);
    }

    #[test]
    fn metadata_blocked_even_when_private_allowed() {
        let permissive = EgressPolicy {
            allow_private_network: true,
            require_https_public: true,
        };
        assert!(check_ip("h", ip("169.254.169.254"), &permissive).is_err());
        assert!(check_ip("h", ip("fe80::1"), &permissive).is_err());
        assert!(check_ip("h", ip("0.0.0.0"), &permissive).is_err());
    }

    #[test]
    fn private_gated_by_policy() {
        let permissive = EgressPolicy::default();
        let hardened = EgressPolicy::hardened();
        assert!(check_ip("h", ip("10.0.0.1"), &permissive).is_ok());
        assert!(check_ip("h", ip("127.0.0.1"), &permissive).is_ok());
        assert!(check_ip("h", ip("10.0.0.1"), &hardened).is_err());
        assert!(check_ip("h", ip("127.0.0.1"), &hardened).is_err());
        // public is fine under both (and classified as public → `true`)
        assert!(check_ip("h", ip("8.8.8.8"), &permissive).unwrap());
        assert!(check_ip("h", ip("8.8.8.8"), &hardened).unwrap());
    }

    #[tokio::test]
    async fn validate_blocks_metadata_literal() {
        let err = validate(
            "http://169.254.169.254/latest/meta-data/",
            &EgressPolicy::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, TransportError::Egress(_)));
    }

    #[tokio::test]
    async fn validate_allows_loopback_literal() {
        let r = validate("http://127.0.0.1:7878/mcp", &EgressPolicy::default())
            .await
            .unwrap();
        assert_eq!(r.addrs.len(), 1);
        assert!(!r.is_domain);
    }

    #[tokio::test]
    async fn validate_rejects_plaintext_public() {
        // 8.8.8.8 is public; plain http must be refused under the default policy.
        let err = validate("http://8.8.8.8/x", &EgressPolicy::default())
            .await
            .unwrap_err();
        assert!(matches!(err, TransportError::Egress(_)));
        // …but https to the same public host is fine.
        assert!(validate("https://8.8.8.8/x", &EgressPolicy::default())
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn validate_rejects_private_when_hardened() {
        assert!(validate("https://10.1.2.3/mcp", &EgressPolicy::hardened())
            .await
            .is_err());
        assert!(validate("https://10.1.2.3/mcp", &EgressPolicy::default())
            .await
            .is_ok());
    }
}
