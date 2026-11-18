// SPDX-License-Identifier: Apache-2.0
//! The bearer token for `allowed-bearer`: the cost of a gateway with
//! `[gateway.auth]` on, which checks a token on every call it serves.
//!
//! The token is RS256, what identity providers sign with by default, signed with
//! the auth crate's committed test key. The gateway holds that key's JWKS pinned
//! in its config, so its keys are in memory and nothing is fetched while calls are
//! timed: the steady state of a gateway whose fetched JWKS is cached. The gateway
//! keeps no cache of tokens it has checked, so every call's token is checked in
//! full, its signature and its claims.

use anyhow::{Context, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The `iss` the gateway expects and the token carries.
pub const ISSUER: &str = "https://auth.mcpdef-bench.test";
/// The gateway's `resource`: the audience its tokens must name.
pub const RESOURCE: &str = "https://mcpdef-bench.test/mcp";
/// The test key's JWKS, as `[gateway.auth] jwks` pins it.
pub const JWKS: &str = include_str!("../../mcpdef-auth/src/testdata/test_jwks.json");
/// The test key itself: a throwaway, committed for the auth crate's tests.
const KEY_PEM: &str = include_str!("../../mcpdef-auth/src/testdata/test_priv.pem");
/// The key's id in that JWKS.
const KID: &str = "test-key-1";

/// A token for the subject `mcpdef-bench`, good for `lifetime`.
pub fn token(lifetime: Duration) -> Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.into());
    let claims = json!({
        "sub": "mcpdef-bench",
        "iss": ISSUER,
        "aud": RESOURCE,
        "iat": now,
        "exp": now + lifetime.as_secs(),
    });
    let key = EncodingKey::from_rsa_pem(KEY_PEM.as_bytes()).context("reading the test key")?;
    encode(&header, &claims, &key).context("signing the bench's token")
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};

    /// The token verifies against the JWKS the gateway is given, as the gateway
    /// would check it: so a run measures checked calls, never refused ones.
    #[test]
    fn the_token_verifies_against_the_pinned_jwks() {
        let token = token(Duration::from_secs(60)).unwrap();
        let kid = decode_header(&token).unwrap().kid.unwrap();
        let jwks: JwkSet = serde_json::from_str(JWKS).unwrap();
        let key = DecodingKey::from_jwk(jwks.find(&kid).expect("the key is in the JWKS")).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[RESOURCE]);
        let claims = decode::<serde_json::Value>(&token, &key, &validation)
            .unwrap()
            .claims;
        assert_eq!(claims["sub"], "mcpdef-bench");
    }
}
