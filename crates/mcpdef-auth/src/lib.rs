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

mod identity;

pub use self::identity::{claim, strings, IdentityModel, RoleMapping};

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
    /// Scopes as Entra and others send them: an array, or one string of
    /// them separated by spaces.
    #[serde(default)]
    scp: Option<serde_json::Value>,
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

/// Whether `a` and `b` are the same bytes, compared in time that depends on
/// their lengths alone.
pub fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

/// The claims of `token`, a JWT whose signature has been verified: its
/// payload, read as a JSON object.
fn payload(token: &str) -> Result<serde_json::Map<String, serde_json::Value>, AuthError> {
    use base64::Engine as _;
    let part = token
        .split('.')
        .nth(1)
        .ok_or_else(|| AuthError::Malformed("token has no payload".into()))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part.trim_end_matches('='))
        .map_err(|e| AuthError::Malformed(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| AuthError::Malformed(e.to_string()))
}

/// How far this machine's clock may be from the authorization server's before
/// its tokens are refused: the skew a token's `exp` and `nbf` are allowed
/// either way. `mcpdef doctor` measures the skew against it.
pub fn clock_leeway() -> Duration {
    Duration::from_secs(Validation::default().leeway)
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
    /// How a token's claims name its caller.
    identity: IdentityModel,
    /// Audiences a token may carry besides `resource`.
    audiences: Vec<String>,
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
            identity: IdentityModel::default(),
            audiences: Vec::new(),
        }
    }

    /// Take tokens whose `aud` holds one of `audiences` as well as those for
    /// `resource`: an identity provider that names an API its own way, as
    /// Entra's `api://<app id>` does. `resource` stays what RFC 9728's
    /// metadata says.
    pub fn with_audiences(mut self, audiences: Vec<String>) -> Self {
        self.audiences = audiences;
        self
    }

    /// Read each token's subject and roles by `identity`, not as the
    /// default does (`sub`, and the `roles` claim).
    pub fn with_identity(mut self, identity: IdentityModel) -> Self {
        self.identity = identity;
        self
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
        self.verify_claims(token).map(|(principal, _)| principal)
    }

    /// [`verify`](Verifier::verify), and the claims the token holds, as
    /// verified: for showing someone what their identity provider said of
    /// them.
    pub fn verify_claims(
        &self,
        token: &str,
    ) -> Result<(Principal, serde_json::Map<String, serde_json::Value>), AuthError> {
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
        validation.leeway = clock_leeway().as_secs();
        let audiences: Vec<&str> = std::iter::once(self.resource.as_str())
            .chain(self.audiences.iter().map(String::as_str))
            .collect();
        validation.set_audience(&audiences);
        validation.set_issuer(&[self.issuer.as_str()]);
        // jsonwebtoken checks `aud` and `iss` only when the token carries
        // them: a token with no `aud`, which the issuer minted for some other
        // use, passed. RFC 9068 requires both, with `exp` and `sub`.
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let data = decode::<Claims>(token, &key, &validation)
            .map_err(|e| AuthError::Invalid(e.to_string()))?;
        let c = data.claims;
        // Every claim, as the payload just verified holds it.
        let claims = payload(token)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        check_times(c.exp, c.nbf, now, validation.leeway as f64)?;
        let scopes: Vec<String> = match &c.scp {
            Some(scp) => strings(Some(scp))
                .flat_map(str::split_whitespace)
                .map(String::from)
                .collect(),
            None => c
                .scope
                .as_deref()
                .map(|s| s.split_whitespace().map(String::from).collect())
                .unwrap_or_default(),
        };
        let subject = match self.identity.subject_claim.as_str() {
            "sub" => c.sub,
            _ => self.identity.subject(&claims).map_err(AuthError::Invalid)?,
        };
        let principal = Principal {
            subject,
            scopes,
            roles: self.identity.roles(&claims),
            client_id: c.client_id.or(c.azp),
            issuer: c.iss,
        };
        Ok((principal, claims))
    }

    /// An OpenID Connect ID token, its audience being the client this
    /// verifier was made for: verified as [`verify_claims`](Self::verify_claims)
    /// verifies an access token, and then as OpenID Connect Core §3.1.3.7
    /// asks: its `nonce` the one the sign-in sent, compared in constant time;
    /// its `azp`, when it has one or names several audiences, the client; and
    /// its `iat` there, and not in the future.
    pub fn verify_id_token(
        &self,
        token: &str,
        nonce: &str,
    ) -> Result<(Principal, serde_json::Map<String, serde_json::Value>), AuthError> {
        let (principal, claims) = self.verify_claims(token)?;
        let invalid = |why: &str| Err(AuthError::Invalid(why.to_string()));
        match claims.get("nonce").and_then(serde_json::Value::as_str) {
            Some(sent) if same(sent.as_bytes(), nonce.as_bytes()) => {}
            _ => return invalid("its nonce is not the one the sign-in sent"),
        }
        let audiences = strings(claims.get("aud")).count();
        match claims.get("azp").and_then(serde_json::Value::as_str) {
            Some(azp) if azp != self.resource => {
                return invalid("it was issued to another client (azp)")
            }
            None if audiences > 1 => {
                return invalid("it names several audiences, and no authorized party (azp)")
            }
            _ => {}
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        match claims.get("iat").and_then(serde_json::Value::as_f64) {
            Some(iat) if iat <= now + clock_leeway().as_secs_f64() => {}
            Some(_) => return invalid("it was issued in the future (iat)"),
            None => return invalid("it says nothing of when it was issued (iat)"),
        }
        Ok((principal, claims))
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

    /// A token's claims: the ones every valid token has, then `extra`.
    fn token_with(extra: Value) -> String {
        let mut claims =
            json!({ "sub": "agent-7", "iss": ISSUER, "aud": RESOURCE, "exp": now() + 3600 });
        for (name, value) in extra.as_object().unwrap() {
            claims[name] = value.clone();
        }
        sign_claims(&claims)
    }

    #[test]
    fn audiences_besides_the_resource_are_taken_and_no_others() {
        let entra = verifier().with_audiences(vec!["api://0000-aaaa".into()]);
        let token = |aud: Value| token_with(json!({ "aud": aud }));
        assert!(entra.verify(&token(json!("api://0000-aaaa"))).is_ok());
        assert!(entra.verify(&token(json!(RESOURCE))).is_ok());
        assert!(entra
            .verify(&token(json!(["x", "api://0000-aaaa"])))
            .is_ok());
        for refused in [json!("api://0000-bbbb"), json!(["x", "y"])] {
            assert!(
                matches!(
                    entra.verify(&token(refused.clone())),
                    Err(AuthError::Invalid(_))
                ),
                "{refused}"
            );
        }
        // Without them, only the resource.
        assert!(verifier().verify(&token(json!("api://0000-aaaa"))).is_err());
        // The metadata still names the resource alone.
        assert_eq!(entra.protected_resource_metadata()["resource"], RESOURCE);
    }

    #[test]
    fn an_entra_scp_string_is_read_as_scopes_and_a_string_role_as_a_role() {
        let token = token_with(json!({ "scp": "User.Read  Mail.Read", "roles": "Mcp.Admin" }));
        let p = verifier().verify(&token).unwrap();
        assert_eq!(p.scopes, ["User.Read", "Mail.Read"]);
        assert_eq!(p.roles, ["Mcp.Admin"]);
        let token = token_with(json!({ "scp": ["a", "b c"] }));
        assert_eq!(verifier().verify(&token).unwrap().scopes, ["a", "b", "c"]);
    }

    #[test]
    fn the_identity_model_names_the_subject_and_the_roles() {
        let model = IdentityModel {
            subject_claim: "preferred_username".into(),
            roles_claims: vec!["realm_access.roles".into()],
            role_map: vec![RoleMapping {
                claim: "groups".into(),
                value: "/mcp-admins".into(),
                roles: vec!["admin".into()],
            }],
        };
        let token = token_with(json!({
            "preferred_username": "ann",
            "realm_access": { "roles": ["reader"] },
            "groups": ["/mcp-admins"],
            "roles": ["ignored"],
        }));
        let (p, claims) = verifier()
            .with_identity(model.clone())
            .verify_claims(&token)
            .unwrap();
        assert_eq!(
            (p.subject.as_str(), p.roles.as_slice()),
            ("ann", &["reader".to_string(), "admin".to_string()][..])
        );
        assert_eq!(claims["groups"], json!(["/mcp-admins"]));
        assert_eq!(claims["sub"], "agent-7");
        // No such claim: the token names no subject, and is refused.
        let nameless = token_with(json!({}));
        let refusal = verifier()
            .with_identity(model)
            .verify(&nameless)
            .unwrap_err();
        assert!(
            matches!(&refusal, AuthError::Invalid(why) if why.contains("`preferred_username`")),
            "{refusal}"
        );
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

    /// A token the issuer signed for no audience is not a token for this
    /// resource: RFC 9068 makes `aud` required, and a token minted for some
    /// other use, an ID token without one say, must not open the gateway.
    #[test]
    fn a_token_with_no_aud_is_refused() {
        let token = sign_claims(&json!({ "sub": "agent-7", "iss": ISSUER, "exp": now() + 3600 }));
        assert!(
            matches!(verifier().verify(&token), Err(AuthError::Invalid(_))),
            "a token with no `aud` was accepted"
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

    /// `clock_leeway` is the skew `verify` allows, so what `mcpdef doctor`
    /// measures against it is what tokens meet: valid a little inside it is
    /// taken, a little beyond it is not.
    #[test]
    fn clock_leeway_is_the_skew_verify_allows() {
        let leeway = clock_leeway().as_secs();
        let inside = sign_claims(&with_time("nbf", Some(json!(now() + leeway - 5))));
        assert!(verifier().verify(&inside).is_ok());
        let beyond = sign_claims(&with_time("nbf", Some(json!(now() + leeway + 5))));
        assert!(verifier().verify(&beyond).is_err());
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
