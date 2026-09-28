// SPDX-License-Identifier: Apache-2.0
//! `mcpdef-auth` — the OAuth 2.1 **Resource Server**: validate a bearer JWT on
//! every request and turn it into a [`Principal`] the gateway can authorize and
//! audit.
//!
//! MCP authorization is OAuth 2.1-based and (per spec) the server MUST NOT use
//! sessions for auth — so MCPdef validates the bearer **per request**:
//!
//! 1. read the JWT header, require a `kid`, and select the matching key from the
//!    configured **JWKS** (no trusting the header `alg` for `none`/HMAC — only an
//!    asymmetric allow-list is accepted);
//! 2. verify the signature, and check `aud` contains this resource's canonical URI
//!    (RFC 8707 / RFC 9068), `iss` matches the configured authorization server,
//!    and `exp`/`nbf` are numbers that make the token valid now;
//! 3. return a [`Principal`] (subject, scopes, roles, client_id).
//!
//! On a missing/invalid token the gateway returns `401` with a
//! [`Verifier::challenge`] `WWW-Authenticate` header pointing at the
//! **RFC 9728 Protected Resource Metadata** document this crate also builds
//! ([`Verifier::protected_resource_metadata`]), so a client can discover the
//! authorization server.
//!
//! This crate is the *validation* core; fetching a JWKS over `jwks_uri` (behind
//! the egress/SSRF guard) and wiring `401`/discovery into the HTTP listener live
//! in the binary. Token **brokering** to upstreams and **RBAC** layer on top of
//! the `Principal` this produces.

use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::de::{self, Deserializer, Visitor};
use serde::Deserialize;
use std::fmt;
use std::sync::{Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Asymmetric algorithms MCPdef will accept. `none` and HMAC are deliberately
/// excluded — accepting a header-chosen HMAC alg against a public key is the
/// classic JWT algorithm-confusion forgery.
const ALLOWED_ALGS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::ES256,
    Algorithm::ES384,
];

/// Default minimum interval between JWKS refresh *attempts* (see
/// [`Verifier::should_attempt_refresh`]). Bounds how often an unknown-`kid` token
/// can trigger a re-fetch of the `jwks_uri`.
const DEFAULT_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Parse a JWKS document and reject an empty key set. Shared by the initial load
/// ([`Verifier::from_jwks_json`]) and a runtime rotation ([`Verifier::refresh_jwks`])
/// so the two validation paths can never drift apart.
fn parse_nonempty_jwks(json: &str) -> Result<JwkSet, AuthError> {
    let jwks: JwkSet = serde_json::from_str(json)
        .map_err(|e| AuthError::Malformed(format!("invalid JWKS: {e}")))?;
    if jwks.keys.is_empty() {
        return Err(AuthError::Malformed("JWKS has no keys".into()));
    }
    Ok(jwks)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    /// No bearer token was presented.
    #[error("missing bearer token")]
    Missing,
    /// The token is structurally malformed (not a JWT, no `kid`, …).
    #[error("malformed token: {0}")]
    Malformed(String),
    /// The token is signed by a key id not in the JWKS.
    #[error("unknown signing key id {0:?}")]
    UnknownKey(String),
    /// Signature / audience / issuer / expiry / not-before validation failed.
    #[error("invalid token: {0}")]
    Invalid(String),
}

/// The authenticated caller, derived from a validated token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The `sub` claim — the stable subject identifier (the audit `agent`).
    pub subject: String,
    /// OAuth scopes (`scope` space-delimited or the `scp` array).
    pub scopes: Vec<String>,
    /// A `roles` claim, if the IdP issues one.
    pub roles: Vec<String>,
    /// The OAuth client (`client_id` or `azp`), if present.
    pub client_id: Option<String>,
    /// The `iss` that minted the token.
    pub issuer: String,
}

impl Principal {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// Scopes ∪ roles — the set RBAC matches role names against.
    pub fn grants_subjects(&self) -> impl Iterator<Item = &str> {
        self.scopes
            .iter()
            .chain(self.roles.iter())
            .map(String::as_str)
    }
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    /// When the token expires: a number, or the token is refused.
    #[serde(deserialize_with = "expiry")]
    exp: f64,
    /// When it becomes valid, if it says: a number too.
    #[serde(default, deserialize_with = "not_before")]
    nbf: Option<f64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    scp: Option<Vec<String>>,
    #[serde(default)]
    roles: Option<Vec<String>>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    azp: Option<String>,
}

/// Reads a time claim: RFC 7519's NumericDate, a JSON number of seconds since
/// 1970, which may have a fraction. Anything else, `null` included, fails, and
/// the token with it. jsonwebtoken 9 reads a time claim of another type as
/// absent, and skips an absent `nbf`'s check (CVE-2026-25537): a token whose
/// `nbf` was a string was taken before its time. It holds the claim's name, for
/// the error to say which.
struct NumericDate(&'static str);

impl Visitor<'_> for NumericDate {
    type Value = f64;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}` as a number of seconds since 1970", self.0)
    }

    fn visit_u64<E: de::Error>(self, seconds: u64) -> Result<f64, E> {
        Ok(seconds as f64)
    }

    fn visit_i64<E: de::Error>(self, seconds: i64) -> Result<f64, E> {
        Ok(seconds as f64)
    }

    fn visit_f64<E: de::Error>(self, seconds: f64) -> Result<f64, E> {
        Ok(seconds)
    }
}

fn expiry<'de, D: Deserializer<'de>>(claim: D) -> Result<f64, D::Error> {
    claim.deserialize_f64(NumericDate("exp"))
}

fn not_before<'de, D: Deserializer<'de>>(claim: D) -> Result<Option<f64>, D::Error> {
    claim.deserialize_f64(NumericDate("nbf")).map(Some)
}

/// Refuse a token that has expired, or is not valid yet, allowing `leeway`
/// seconds of clock skew either way. jsonwebtoken has checked both, but only a
/// time it reads as a whole number of seconds that fits a u64: an `nbf` beyond
/// that, 1e20 say, it passes over as it would a string.
fn check_times(exp: f64, nbf: Option<f64>, now: f64, leeway: f64) -> Result<(), AuthError> {
    if exp < now - leeway {
        return Err(AuthError::Invalid("the token has expired".into()));
    }
    if nbf.is_some_and(|nbf| nbf > now + leeway) {
        return Err(AuthError::Invalid("the token is not valid yet".into()));
    }
    Ok(())
}

/// Validates bearer JWTs against a JWKS as an OAuth 2.1 Resource Server.
///
/// The JWKS is held behind an [`RwLock`] so it can be **rotated at runtime**
/// ([`refresh_jwks`](Verifier::refresh_jwks)) when the authorization server rolls
/// its signing keys — without which a rotation would reject every token until the
/// gateway restarts. [`verify`](Verifier::verify) still takes `&self`, so one
/// `Verifier` is shared read-only across all concurrent requests.
pub struct Verifier {
    jwks: RwLock<JwkSet>,
    issuer: String,
    resource: String,
    metadata_path: String,
    /// When a refresh was last *attempted* (the slot [`should_attempt_refresh`]
    /// reserves); `None` until the first attempt.
    ///
    /// [`should_attempt_refresh`]: Verifier::should_attempt_refresh
    last_refresh: Mutex<Option<Instant>>,
    /// Minimum interval between refresh attempts.
    min_refresh_interval: Duration,
}

impl Verifier {
    /// `resource` is this server's canonical URI — the audience tokens must carry
    /// (RFC 8707). `issuer` is the authorization server's `iss`.
    pub fn new(jwks: JwkSet, issuer: impl Into<String>, resource: impl Into<String>) -> Self {
        Verifier {
            jwks: RwLock::new(jwks),
            issuer: issuer.into(),
            resource: resource.into(),
            metadata_path: "/.well-known/oauth-protected-resource".to_string(),
            last_refresh: Mutex::new(None),
            min_refresh_interval: DEFAULT_MIN_REFRESH_INTERVAL,
        }
    }

    /// Override the minimum interval between JWKS refresh attempts (default 60s).
    pub fn with_min_refresh_interval(mut self, interval: Duration) -> Self {
        self.min_refresh_interval = interval;
        self
    }

    /// Build from a JWKS JSON document (inline config, or a fetched `jwks_uri`).
    pub fn from_jwks_json(
        json: &str,
        issuer: impl Into<String>,
        resource: impl Into<String>,
    ) -> Result<Self, AuthError> {
        let jwks = parse_nonempty_jwks(json)?;
        Ok(Self::new(jwks, issuer, resource))
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }

    pub fn metadata_path(&self) -> &str {
        &self.metadata_path
    }

    /// Replace the cached JWKS with a freshly-fetched document — how the gateway
    /// picks up an authorization-server **signing-key rotation** at runtime. The
    /// new document must parse and be non-empty; on any error the existing keys are
    /// left intact (a bad fetch never blanks out a working key set). The actual
    /// network fetch of `jwks_uri` lives in the binary (behind the egress/SSRF
    /// guard); this crate only swaps the validated result in.
    pub fn refresh_jwks(&self, json: &str) -> Result<(), AuthError> {
        let jwks = parse_nonempty_jwks(json)?;
        *self.jwks.write().unwrap_or_else(PoisonError::into_inner) = jwks;
        Ok(())
    }

    /// Rate-limit gate for refresh-on-unknown-`kid`. Returns `true` — **reserving
    /// the slot** — at most once per [`min_refresh_interval`](Self::with_min_refresh_interval),
    /// so a flood of tokens carrying bogus `kid`s triggers at most one JWKS
    /// re-fetch per interval (a cheap DoS otherwise). The caller fetches +
    /// [`refresh_jwks`](Self::refresh_jwks) only when this returns `true`. The slot
    /// is reserved on the *attempt*, not on success, so a failing IdP is not
    /// hammered either.
    pub fn should_attempt_refresh(&self) -> bool {
        let mut last = self
            .last_refresh
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        match *last {
            Some(t) if now.duration_since(t) < self.min_refresh_interval => false,
            _ => {
                *last = Some(now);
                true
            }
        }
    }

    /// Validate a raw bearer token (no `Bearer ` prefix) and return the caller.
    pub fn verify(&self, token: &str) -> Result<Principal, AuthError> {
        let token = token.trim();
        if token.is_empty() {
            return Err(AuthError::Missing);
        }
        let header = decode_header(token).map_err(|e| AuthError::Malformed(e.to_string()))?;
        if !ALLOWED_ALGS.contains(&header.alg) {
            return Err(AuthError::Invalid(format!(
                "algorithm {:?} not accepted",
                header.alg
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| AuthError::Malformed("token has no `kid`".into()))?;

        // Select the key and build the (owned) decoding key while holding only a
        // READ lock on the JWKS, then release it before the CPU-bound signature
        // check below — so a concurrent rotation (a rare write) never waits on
        // crypto, and simultaneous verifies don't serialize on each other.
        let key = {
            let jwks = self.jwks.read().unwrap_or_else(PoisonError::into_inner);
            let jwk = jwks
                .find(&kid)
                .ok_or_else(|| AuthError::UnknownKey(kid.clone()))?;

            // Bind the verification algorithm to the SELECTED KEY's family, not just
            // the token header. The header `alg` is attacker-controlled, so trusting
            // it to choose the algorithm is the root of algorithm-confusion forgery.
            // We already rejected `none`/HMAC (the allow-list pre-check above), and we
            // assert here that the header alg's family matches the JWK's key type — so
            // e.g. an `RS256` header can never be verified against an EC key (or vice
            // versa). jsonwebtoken enforces the same internally, but asserting it
            // explicitly means the defense does not silently depend on that.
            let key_is_rsa = matches!(jwk.algorithm, AlgorithmParameters::RSA(_));
            let key_is_ec = matches!(jwk.algorithm, AlgorithmParameters::EllipticCurve(_));
            let alg_fits_key = match header.alg {
                Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 | Algorithm::PS256 => {
                    key_is_rsa
                }
                Algorithm::ES256 | Algorithm::ES384 => key_is_ec,
                // Unreachable: ALLOWED_ALGS already filtered everything else.
                _ => false,
            };
            if !alg_fits_key {
                return Err(AuthError::Invalid(format!(
                    "token algorithm {:?} does not match the key type for kid {kid:?}",
                    header.alg
                )));
            }
            DecodingKey::from_jwk(jwk).map_err(|e| AuthError::Invalid(format!("bad key: {e}")))?
        };

        // `Validation::new` sets `algorithms = [header.alg]` — now that the alg is
        // pinned to the key family above, this validates with exactly that one
        // asymmetric algorithm against a key of the matching family.
        let mut validation = Validation::new(header.alg);
        validation.set_audience(&[self.resource.as_str()]);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let data = decode::<Claims>(token, &key, &validation)
            .map_err(|e| AuthError::Invalid(e.to_string()))?;
        let c = data.claims;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        check_times(c.exp, c.nbf, now, validation.leeway as f64)?;
        let scopes = c.scp.unwrap_or_else(|| {
            c.scope
                .map(|s| s.split_whitespace().map(String::from).collect())
                .unwrap_or_default()
        });
        Ok(Principal {
            subject: c.sub,
            scopes,
            roles: c.roles.unwrap_or_default(),
            client_id: c.client_id.or(c.azp),
            issuer: c.iss,
        })
    }

    /// The RFC 9728 Protected Resource Metadata document served at
    /// [`metadata_path`](Verifier::metadata_path).
    pub fn protected_resource_metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "bearer_methods_supported": ["header"],
        })
    }

    /// The `WWW-Authenticate` header value for a `401`, pointing a client at the
    /// PRM document at `metadata_url` so it can discover the authorization server.
    pub fn challenge(&self, metadata_url: &str) -> String {
        format!("Bearer resource_metadata=\"{metadata_url}\", error=\"invalid_token\"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;
    use serde_json::{json, Value};

    // A fixed RSA-2048 test keypair (generated with openssl) + its public JWKS,
    // committed under src/testdata/ and embedded so the crypto path is exercised
    // fully offline and deterministically (and the pair can never drift).
    const TEST_PRIV_PEM: &str = include_str!("testdata/test_priv.pem");
    const TEST_JWKS: &str = include_str!("testdata/test_jwks.json");

    const ISSUER: &str = "https://auth.example.com";
    const RESOURCE: &str = "https://mcpdef.acme.internal/mcp";

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        iss: String,
        aud: String,
        exp: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        roles: Option<Vec<String>>,
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Sign a token with the test key, with overridable `aud`/`iss`/`exp`.
    fn sign(aud: &str, iss: &str, exp: u64, scope: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-1".into());
        let claims = TestClaims {
            sub: "agent-7".into(),
            iss: iss.into(),
            aud: aud.into(),
            exp,
            scope: scope.map(String::from),
            roles: Some(vec!["reader".into()]),
        };
        let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    fn verifier() -> Verifier {
        Verifier::from_jwks_json(TEST_JWKS, ISSUER, RESOURCE).unwrap()
    }

    #[test]
    fn valid_token_yields_principal() {
        let token = sign(RESOURCE, ISSUER, now() + 3600, Some("mcp.read mcp.write"));
        let p = verifier().verify(&token).unwrap();
        assert_eq!(p.subject, "agent-7");
        assert_eq!(p.issuer, ISSUER);
        assert!(p.has_scope("mcp.read") && p.has_scope("mcp.write"));
        assert!(p.roles.contains(&"reader".to_string()));
    }

    #[test]
    fn rejects_wrong_audience() {
        let token = sign("https://other.example/mcp", ISSUER, now() + 3600, None);
        assert!(matches!(
            verifier().verify(&token),
            Err(AuthError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_wrong_issuer() {
        let token = sign(RESOURCE, "https://evil.example", now() + 3600, None);
        assert!(matches!(
            verifier().verify(&token),
            Err(AuthError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_expired_token() {
        let token = sign(RESOURCE, ISSUER, now() - 3600, None);
        assert!(matches!(
            verifier().verify(&token),
            Err(AuthError::Invalid(_))
        ));
    }

    /// Sign `claims` as they are, whatever their types, with the test key.
    fn sign_claims(claims: &Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-1".into());
        let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
        encode(&header, claims, &key).unwrap()
    }

    /// A valid token's claims, but with `time` (`exp` or `nbf`) set to
    /// `value`, or left out for `None`.
    fn with_time(time: &str, value: Option<Value>) -> Value {
        let mut claims =
            json!({ "sub": "agent-7", "iss": ISSUER, "aud": RESOURCE, "exp": now() + 3600 });
        match value {
            Some(value) => claims[time] = value,
            None => {
                claims.as_object_mut().unwrap().remove(time);
            }
        }
        claims
    }

    /// The token jsonwebtoken 9 takes before its time (CVE-2026-25537): not
    /// valid until tomorrow, but saying so with a string.
    #[test]
    fn a_string_nbf_is_refused() {
        let tomorrow = (now() + 86_400).to_string();
        let token = sign_claims(&with_time("nbf", Some(json!(tomorrow))));
        let refusal = verifier().verify(&token).unwrap_err();
        assert!(
            matches!(&refusal, AuthError::Invalid(why) if why.contains("`nbf` as a number")),
            "{refusal}"
        );
    }

    #[test]
    fn a_future_nbf_is_refused() {
        let token = sign_claims(&with_time("nbf", Some(json!(now() + 3600))));
        assert!(matches!(
            verifier().verify(&token),
            Err(AuthError::Invalid(_))
        ));
    }

    /// A past `nbf` is accepted, one before 1970 as well.
    #[test]
    fn a_past_nbf_is_accepted() {
        for past in [json!(now() - 3600), json!(-1)] {
            let token = sign_claims(&with_time("nbf", Some(past.clone())));
            let subject = verifier().verify(&token).map(|p| p.subject);
            assert_eq!(subject, Ok("agent-7".to_string()), "{past}");
        }
    }

    /// Clocks disagree, so a token is taken up to a minute either side of its
    /// times, as jsonwebtoken takes it.
    #[test]
    fn the_leeway_allows_for_clock_skew() {
        let mut claims = with_time("nbf", Some(json!(now() + 30)));
        claims["exp"] = json!(now() - 30);
        let token = sign_claims(&claims);
        assert_eq!(verifier().verify(&token).unwrap().subject, "agent-7");
    }

    /// jsonwebtoken refuses a string `exp` too, but only because it requires
    /// `exp` and a string does not count. This refusal is the claim's own type
    /// check, whichever claims jsonwebtoken is told to require.
    #[test]
    fn a_string_exp_is_refused() {
        let later = (now() + 3600).to_string();
        let token = sign_claims(&with_time("exp", Some(json!(later))));
        let refusal = verifier().verify(&token).unwrap_err();
        assert!(
            matches!(&refusal, AuthError::Invalid(why) if why.contains("`exp` as a number")),
            "{refusal}"
        );
    }

    /// A time claim is a number, or the token is refused, whatever time it
    /// would name: each value here holds a time that, as a number, would be
    /// valid. A token with no `exp` at all is refused as well.
    #[test]
    fn a_time_claim_of_any_other_type_is_refused() {
        for (time, at) in [("exp", now() + 3600), ("nbf", now() - 3600)] {
            let others = [
                json!(at.to_string()),
                json!(null),
                json!(true),
                json!([at]),
                json!({ "seconds": at }),
            ];
            for value in others {
                let token = sign_claims(&with_time(time, Some(value.clone())));
                assert!(
                    matches!(verifier().verify(&token), Err(AuthError::Invalid(_))),
                    "{time}: {value}"
                );
            }
        }
        let token = sign_claims(&with_time("exp", None));
        assert!(matches!(
            verifier().verify(&token),
            Err(AuthError::Invalid(_))
        ));
    }

    /// RFC 7519 lets a time carry a fraction of a second. jsonwebtoken takes
    /// one, and so does the verifier.
    #[test]
    fn a_time_with_a_fraction_is_accepted() {
        let mut claims = with_time("nbf", Some(json!(now() as f64 - 3600.5)));
        claims["exp"] = json!(now() as f64 + 3600.5);
        let token = sign_claims(&claims);
        assert_eq!(verifier().verify(&token).unwrap().subject, "agent-7");
    }

    /// An `nbf` too large for a u64 is still a number, so it decodes, and
    /// jsonwebtoken passes over it as it would a string. The token is not
    /// valid for a very long time yet.
    #[test]
    fn an_nbf_too_large_for_jsonwebtoken_is_refused() {
        let token = sign_claims(&with_time("nbf", Some(json!(1e20))));
        assert_eq!(
            verifier().verify(&token),
            Err(AuthError::Invalid("the token is not valid yet".into()))
        );
    }

    /// Both times, with the leeway jsonwebtoken allows: a time up to the
    /// leeway either side of now is valid, and one a second beyond is not.
    #[test]
    fn times_are_checked_with_the_leeway() {
        let (now, leeway, later) = (1_800_000_000.0, 60.0, 1_800_003_600.0);
        let expired = Err(AuthError::Invalid("the token has expired".into()));
        let early = Err(AuthError::Invalid("the token is not valid yet".into()));
        assert_eq!(check_times(now - leeway, None, now, leeway), Ok(()));
        assert_eq!(check_times(now - leeway - 1.0, None, now, leeway), expired);
        assert_eq!(check_times(later, Some(now + leeway), now, leeway), Ok(()));
        assert_eq!(
            check_times(later, Some(now + leeway + 1.0), now, leeway),
            early
        );
        assert_eq!(check_times(later, Some(1e20), now, leeway), early);
    }

    #[test]
    fn rejects_unknown_kid() {
        // Sign with a header kid that isn't in the JWKS.
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("other-key".into());
        let claims = TestClaims {
            sub: "x".into(),
            iss: ISSUER.into(),
            aud: RESOURCE.into(),
            exp: now() + 3600,
            scope: None,
            roles: None,
        };
        let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
        let token = encode(&header, &claims, &key).unwrap();
        assert!(matches!(
            verifier().verify(&token),
            Err(AuthError::UnknownKey(_))
        ));
    }

    #[test]
    fn rejects_tampered_signature() {
        let mut token = sign(RESOURCE, ISSUER, now() + 3600, None);
        // Flip the last char of the signature segment.
        let last = token.pop().unwrap();
        token.push(if last == 'A' { 'B' } else { 'A' });
        assert!(matches!(
            verifier().verify(&token),
            Err(AuthError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_hmac_algorithm_confusion() {
        // An attacker forges an HS256 token (kid points at the RSA key). The RS
        // must refuse HMAC — only asymmetric algs are accepted.
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("test-key-1".into());
        let claims = TestClaims {
            sub: "attacker".into(),
            iss: ISSUER.into(),
            aud: RESOURCE.into(),
            exp: now() + 3600,
            scope: None,
            roles: None,
        };
        let token = encode(&header, &claims, &EncodingKey::from_secret(b"secret")).unwrap();
        assert!(matches!(
            verifier().verify(&token),
            Err(AuthError::Invalid(_))
        ));
    }

    #[test]
    fn empty_token_is_missing() {
        assert_eq!(verifier().verify("   "), Err(AuthError::Missing));
    }

    #[test]
    fn rejects_alg_that_does_not_match_key_family() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        // A token whose header claims ES256 but whose `kid` points at the RSA
        // JWKS key. The alg↔key-family bind must reject it *before* any signature
        // check (so the bogus signature here is never reached) — this is the part
        // the `none`/HMAC pre-check does NOT cover, and the reason verification
        // must be pinned to the key, not the attacker-supplied header `alg`.
        let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": "test-key-1" });
        let claims =
            serde_json::json!({ "sub": "x", "iss": ISSUER, "aud": RESOURCE, "exp": now() + 3600 });
        let token = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()),
            URL_SAFE_NO_PAD.encode(b"not-a-real-signature"),
        );
        assert!(matches!(
            verifier().verify(&token),
            Err(AuthError::Invalid(_))
        ));
    }

    #[test]
    fn refresh_picks_up_a_rotated_key() {
        // Simulate an IdP key rotation: start with a JWKS that holds the key under
        // a *stale* kid, so a token signed with the current kid misses the cache.
        let stale = TEST_JWKS.replace("test-key-1", "stale-key-1");
        let v = Verifier::from_jwks_json(&stale, ISSUER, RESOURCE).unwrap();
        let token = sign(RESOURCE, ISSUER, now() + 3600, None);
        assert!(
            matches!(v.verify(&token), Err(AuthError::UnknownKey(_))),
            "before refresh, the rotated kid is unknown"
        );
        // Rotate: refresh with the current JWKS (the real kid) — the same token now
        // verifies, without rebuilding the Verifier.
        v.refresh_jwks(TEST_JWKS).unwrap();
        assert_eq!(v.verify(&token).unwrap().subject, "agent-7");
    }

    #[test]
    fn refresh_rejects_bad_jwks_and_keeps_existing_keys() {
        let v = verifier();
        let token = sign(RESOURCE, ISSUER, now() + 3600, None);
        assert!(v.verify(&token).is_ok());
        // Neither malformed JSON nor an empty key set replaces the working keys.
        assert!(matches!(
            v.refresh_jwks("not json"),
            Err(AuthError::Malformed(_))
        ));
        assert!(matches!(
            v.refresh_jwks(r#"{"keys":[]}"#),
            Err(AuthError::Malformed(_))
        ));
        assert!(
            v.verify(&token).is_ok(),
            "a bad refresh must leave the existing keys intact"
        );
    }

    #[test]
    fn refresh_attempts_are_rate_limited() {
        // Default 60s interval: the first attempt is granted (and reserves the
        // slot), an immediate second is denied — so a bogus-kid flood re-fetches
        // the JWKS at most once per interval.
        let v = verifier();
        assert!(v.should_attempt_refresh());
        assert!(!v.should_attempt_refresh());
        // A zero interval always grants (e.g. a caller that does its own limiting).
        let v0 = verifier().with_min_refresh_interval(Duration::ZERO);
        assert!(v0.should_attempt_refresh());
        assert!(v0.should_attempt_refresh());
    }

    #[test]
    fn protected_resource_metadata_advertises_the_as() {
        let v = verifier();
        let prm = v.protected_resource_metadata();
        assert_eq!(prm["resource"], RESOURCE);
        assert_eq!(prm["authorization_servers"][0], ISSUER);
        let ch = v.challenge("https://mcpdef.acme.internal/.well-known/oauth-protected-resource");
        assert!(ch.starts_with("Bearer resource_metadata="));
    }
}
