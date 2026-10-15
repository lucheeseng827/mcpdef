// SPDX-License-Identifier: Apache-2.0
//! An authorization server's metadata, found from its issuer: OpenID Connect
//! Discovery's document first, then RFC 8414's. Each is fetched through the
//! egress guard, verified by the TLS profile given, and its `issuer` must be
//! the one asked for, exactly (OpenID Connect Discovery §4.3, RFC 8414 §3.3),
//! or the document is not taken.

use mcpdef_transport::{EgressPolicy, TlsProfile};
use serde::Deserialize;

/// What MCPdef reads of an issuer's metadata.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Metadata {
    pub issuer: String,
    /// Where its signing keys are. Optional in RFC 8414, needed here: a
    /// token is verified by them.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    /// RFC 9207: whether it sends `iss` with each authorization answer.
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
}

/// Where `issuer`'s metadata may be, in the order they are tried: OpenID
/// Connect Discovery's, `<issuer>/.well-known/openid-configuration`; then
/// RFC 8414's, `/.well-known/oauth-authorization-server` put before the
/// issuer's path, `https://as.example/.well-known/oauth-authorization-server/tenant`
/// for `https://as.example/tenant`.
pub fn locations(issuer: &str) -> Vec<String> {
    let mut found = vec![format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )];
    if let Ok(mut url) = url::Url::parse(issuer) {
        let path = url.path().trim_end_matches('/').to_string();
        url.set_path(&format!("/.well-known/oauth-authorization-server{path}"));
        url.set_query(None);
        url.set_fragment(None);
        found.push(url.to_string());
    }
    found
}

/// `issuer`'s metadata, from the first of its [`locations`] that serves a
/// document. One that names another issuer is refused, not passed over.
pub async fn metadata(
    issuer: &str,
    egress: &EgressPolicy,
    tls: &TlsProfile,
) -> Result<Metadata, String> {
    let mut missed = Vec::new();
    for at in locations(issuer) {
        let text = match mcpdef_transport::fetch_text(&at, egress, tls).await {
            Ok(text) => text,
            Err(e) => {
                missed.push(format!("{at}: {e}"));
                continue;
            }
        };
        let found: Metadata = match serde_json::from_str(&text) {
            Ok(found) => found,
            Err(e) => {
                missed.push(format!("{at} is no metadata document: {e}"));
                continue;
            }
        };
        if found.issuer != issuer {
            return Err(format!(
                "{at} names the issuer {:?}, and the config names {issuer:?}: they must be the \
                 same, exactly",
                found.issuer
            ));
        }
        return Ok(found);
    }
    Err(format!(
        "no metadata for the issuer {issuer:?}: {}",
        missed.join("; ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_is_looked_for_as_each_standard_puts_it() {
        assert_eq!(
            locations("https://as.example"),
            [
                "https://as.example/.well-known/openid-configuration",
                "https://as.example/.well-known/oauth-authorization-server",
            ]
        );
        // Keycloak's realms, Okta's authorization servers, Entra's tenants:
        // an issuer with a path.
        assert_eq!(
            locations("https://kc.example/realms/ops/"),
            [
                "https://kc.example/realms/ops/.well-known/openid-configuration",
                "https://kc.example/.well-known/oauth-authorization-server/realms/ops",
            ]
        );
        assert_eq!(
            locations("http://127.0.0.1:8080/t/1"),
            [
                "http://127.0.0.1:8080/t/1/.well-known/openid-configuration",
                "http://127.0.0.1:8080/.well-known/oauth-authorization-server/t/1",
            ]
        );
    }
}
