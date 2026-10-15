// SPDX-License-Identifier: Apache-2.0
//! `mcpdef-testkit` — support for testing MCPdef's TLS, on either end.
//!
//! - [`Pki`]: certificate authorities made when a test runs, the server and
//!   client certificates they issue, and the CRLs they sign.
//! - [`HttpsUpstream`]: an MCP server over HTTPS for the gateway to dial,
//!   which can require a client certificate.
//! - [`https_client`]: a client that trusts a test PKI, for talking to either
//!   of the above, or to the gateway's own TLS listener.
//!
//! Tests only: the crate is never published, and the gateway never depends
//! on it. Nothing in it comes from the repository: every key is generated in
//! memory, and reaches the disk only in a file a test writes to a directory
//! of its own.

pub mod pki;
pub mod upstream;

pub use self::pki::{Crl, Leaf, LeafBuilder, Pki};
pub use self::upstream::HttpsUpstream;

/// A client that trusts `pki`'s root and nothing else, presenting `identity`
/// when given one.
///
/// It installs ring as rustls' crypto provider first, if the process has
/// none, since reqwest cannot build a client without one.
pub fn https_client(pki: &Pki, identity: Option<&Leaf>) -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = reqwest::Certificate::from_der(pki.root_der()).expect("a usable root");
    let mut builder = reqwest::Client::builder().tls_certs_only([root]).no_proxy();
    if let Some(leaf) = identity {
        let identity = reqwest::Identity::from_pem(&leaf.identity_pem()).expect("an identity");
        builder = builder.identity(identity);
    }
    builder.build().expect("a client")
}

/// The port a line `mcpdef run` writes says a listener took: the one in the
/// address that follows `after`. `listening_port(&ready, "streamable-http ")`
/// reads the MCP listener's from the ready line, and
/// `listening_port(&line, "UI on ")` the admin listener's from the line after
/// it. A test that configures port 0 reads the port the system gave from
/// there, rather than reserving a port and freeing it for the gateway, which
/// another test may take first.
pub fn listening_port(line: &str, after: &str) -> u16 {
    let address = line
        .split_once(after)
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no address after {after:?} in {line:?}"));
    address
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .unwrap_or_else(|| panic!("no port in {address:?}: {line:?}"))
}

/// The ports `mcpdef run`'s MCP and admin listeners took, once the lines it
/// writes to stderr, collected in `log`, say: the ready line, and the admin
/// listener's line after it. Panics after 20 seconds without them.
pub async fn listening_ports(log: &std::sync::Mutex<Vec<String>>) -> (u16, u16) {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        {
            let log = log
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let line = |text: &str| log.iter().find(|l| l.contains(text)).cloned();
            if let (Some(ready), Some(admin)) = (line(" ready "), line("admin/metrics UI on ")) {
                return (
                    listening_port(&ready, "streamable-http "),
                    listening_port(&admin, "UI on "),
                );
            }
            assert!(
                std::time::Instant::now() < until,
                "no ready line and admin line: {log:#?}"
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
