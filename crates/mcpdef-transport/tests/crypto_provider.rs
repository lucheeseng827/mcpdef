// SPDX-License-Identifier: Apache-2.0
//! `install_crypto_provider` makes ring rustls' crypto provider for the
//! process. A test binary of its own, because it needs a process in which
//! nothing has installed a provider yet.

use rustls::crypto::CryptoProvider;
use std::sync::Arc;

/// A provider's cipher suites and key-exchange groups, by name.
fn algorithms(provider: &CryptoProvider) -> (Vec<String>, Vec<String>) {
    let suites = provider.cipher_suites.iter();
    let groups = provider.kx_groups.iter();
    (
        suites.map(|s| format!("{:?}", s.suite())).collect(),
        groups.map(|g| format!("{:?}", g.name())).collect(),
    )
}

#[test]
fn ring_becomes_the_process_provider() {
    assert!(
        CryptoProvider::get_default().is_none(),
        "none installed yet"
    );
    mcpdef_transport::install_crypto_provider();
    let installed = CryptoProvider::get_default().expect("one is installed now");
    let ring = rustls::crypto::ring::default_provider();
    assert_eq!(algorithms(installed), algorithms(&ring));

    // Once more: it changes nothing, and does not panic.
    mcpdef_transport::install_crypto_provider();
    assert!(Arc::ptr_eq(
        installed,
        CryptoProvider::get_default().unwrap()
    ));

    // What the gateway builds on it: a rustls configuration from the process
    // provider, and a reqwest client.
    let _config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    reqwest::Client::builder().build().unwrap();
}
