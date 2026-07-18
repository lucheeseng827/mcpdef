// SPDX-License-Identifier: Apache-2.0
//! The downstream **Streamable HTTP listener** — the slice of Phase 1 that lets
//! MCP clients reach mcpdef over HTTP instead of stdio (the shared-gateway shape:
//! "point every agent at one endpoint, govern centrally").
//!
//! Design (ARCHITECTURE.md §4, built **stateless-first** for the 2026-07-28 RC):
//! a `POST` to the single MCP endpoint carries one JSON-RPC message; the gateway
//! handles it and replies with a single `application/json` response, or `202
//! Accepted` for a notification. The gateway's `handle` is already per-message
//! and keeps no per-client session state, so this works for **both** the stateful
//! 2025-11-25 model and the stateless 2026-07-28 model — a client `Mcp-Session-Id`
//! is simply ignored, never required or issued.
//!
//! Defenses on by default:
//! * **Origin validation** — a browser cross-site `Origin` is rejected `403`
//!   (DNS-rebinding defense). Loopback origins + no-Origin (CLI/agent) clients
//!   pass; extra origins are allowlisted in config.
//! * **Loopback bind** — `[gateway] listen` defaults to `127.0.0.1`, not `0.0.0.0`.
//! * **Load-shedding** — an optional in-flight cap sheds excess with `503` +
//!   `Retry-After` (fail-fast over unbounded buffering, §5b) rather than queueing
//!   unboundedly behind the serialized gateway.
//! * **OAuth 2.1 bearer auth** (when `[gateway.auth]` is enabled) — every `POST`
//!   must carry a valid `Authorization: Bearer` JWT (validated per request by
//!   [`mcpdef_auth::Verifier`] as an OAuth 2.1 Resource Server); a missing/invalid
//!   token gets `401` with a `WWW-Authenticate` challenge pointing at the
//!   RFC 9728 Protected Resource Metadata document served at
//!   `/.well-known/oauth-protected-resource`. The validated [`Principal`] becomes
//!   the audit identity and drives the RBAC gate.
//!
//! A server→client `GET` SSE stream is **not** offered in this phase, so `GET`
//! on the MCP endpoint returns `405` (spec-compliant: "405 if the server does not
//! offer one").

use crate::Gateway;
use anyhow::{Context, Result};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use mcpdef_auth::{AuthError, Principal, Verifier};
use mcpdef_core::Message;
use mcpdef_transport::{fetch_text, EgressPolicy};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore};

/// Listener settings derived from `[gateway]`.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// `host:port` to bind (loopback by default).
    pub listen: String,
    /// Extra allowed Origins beyond loopback.
    pub allowed_origins: Vec<String>,
    /// Max concurrent in-flight requests (load-shedding); `None` = unlimited.
    pub max_inflight: Option<usize>,
}

/// Re-fetches the JWKS from a configured `jwks_uri`, through the same egress/SSRF
/// guard as the startup fetch. Present only when keys came from a `jwks_uri` (an
/// inline / file JWKS is static and can't be re-fetched). Lets the listener pick
/// up an authorization-server signing-key rotation without a restart.
pub struct JwksRefresher {
    uri: String,
    egress: EgressPolicy,
}

impl JwksRefresher {
    pub fn new(uri: impl Into<String>, egress: EgressPolicy) -> Self {
        JwksRefresher {
            uri: uri.into(),
            egress,
        }
    }

    /// Fetch the current JWKS document, or `None` on any error (logged). The caller
    /// treats a failed fetch as fail-closed (the request is denied).
    async fn fetch(&self) -> Option<String> {
        match fetch_text(&self.uri, &self.egress).await {
            Ok(json) => Some(json),
            Err(e) => {
                eprintln!("mcpdef: JWKS refresh from {} failed: {e}", self.uri);
                None
            }
        }
    }
}

/// The listener's OAuth state: the per-request bearer [`Verifier`] plus an optional
/// [`JwksRefresher`] used to rotate keys on an unknown `kid`.
pub struct AuthState {
    verifier: Verifier,
    refresher: Option<JwksRefresher>,
}

impl AuthState {
    /// Auth with a static JWKS (inline / file) — no runtime refresh.
    pub fn new(verifier: Verifier) -> Self {
        AuthState {
            verifier,
            refresher: None,
        }
    }

    /// Auth that re-fetches the JWKS from `jwks_uri` on an unknown `kid`, so an
    /// IdP key rotation is picked up without a restart.
    pub fn with_refresher(verifier: Verifier, refresher: JwksRefresher) -> Self {
        AuthState {
            verifier,
            refresher: Some(refresher),
        }
    }
}

/// Verify a bearer, refreshing the JWKS **once** on an unknown `kid` (a signing-key
/// rotation) when a `jwks_uri` refresher is configured. Fail-closed throughout: no
/// refresher, a rate-limited attempt, a failed fetch, or a bad document all leave
/// the caller denied — the token is never trusted against keys it doesn't match.
///
/// Operator note: during an IdP key rotation only the *first* unknown-`kid` request
/// wins `should_attempt_refresh` and does the fetch; other requests arriving in that
/// brief async window are rate-limited and get a `401`. This self-heals in
/// milliseconds once the new keys land (and never trusts a bad key), so clients
/// should simply retry — expect a short `401` blip, not an outage.
async fn verify_with_rotation(auth: &AuthState, token: &str) -> Result<Principal, AuthError> {
    match auth.verifier.verify(token) {
        Err(AuthError::UnknownKey(kid)) => {
            let Some(refresher) = &auth.refresher else {
                return Err(AuthError::UnknownKey(kid)); // static JWKS — nothing to refresh
            };
            if !auth.verifier.should_attempt_refresh() {
                return Err(AuthError::UnknownKey(kid)); // rate-limited — don't hammer the IdP
            }
            let Some(json) = refresher.fetch().await else {
                return Err(AuthError::UnknownKey(kid)); // fetch failed — deny
            };
            auth.verifier
                .refresh_jwks(&json)
                .map_err(|_| AuthError::UnknownKey(kid))?;
            // Retry exactly once against the rotated keys; still-unknown → deny (no loop).
            auth.verifier.verify(token)
        }
        other => other,
    }
}

struct AppState {
    /// The gateway is serialized: it runs one upstream request/response at a time
    /// (per the Phase-1 transport model), so all client requests funnel through
    /// this mutex. Bounded concurrency on top is the in-flight cap below.
    gw: Mutex<Gateway>,
    allowed_origins: Vec<String>,
    inflight: Option<Arc<Semaphore>>,
    spec_version: &'static str,
    /// OAuth 2.1 bearer auth (verifier + optional JWKS refresher), when
    /// `[gateway.auth]` is enabled. `None` leaves the endpoint unauthenticated
    /// (loopback/dev). Shared via the surrounding `Arc<AppState>`; the verifier's
    /// JWKS is internally lock-guarded so a rotation needs no `&mut`.
    auth: Option<AuthState>,
}

const SPEC_VERSION: &str = "2025-11-25";

/// Max request body the listener buffers (one JSON-RPC message). An in-path
/// component must cap this so a client can't force unbounded allocation *before*
/// auth/policy run (the `String` body is fully read by the extractor). 2 MiB is
/// axum's own default; we declare it explicitly so the bound is intentional and
/// easy to find. JSON-RPC requests are small; a tool whose arguments exceed this
/// is the rare case to revisit.
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Bind `cfg.listen` and serve until shutdown. `auth` enables OAuth 2.1 bearer
/// validation on every request when `Some`.
pub async fn serve_http(gw: Gateway, cfg: HttpConfig, auth: Option<AuthState>) -> Result<()> {
    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("binding HTTP listener on {}", cfg.listen))?;
    serve_http_on(listener, gw, cfg, auth).await
}

/// Serve on an already-bound listener (the test entry point — bind `127.0.0.1:0`
/// and read `local_addr()` for the ephemeral port).
pub async fn serve_http_on(
    listener: TcpListener,
    gw: Gateway,
    cfg: HttpConfig,
    auth: Option<AuthState>,
) -> Result<()> {
    let app = router(gw, cfg, auth);
    axum::serve(listener, app)
        .await
        .context("HTTP listener failed")?;
    Ok(())
}

fn router(gw: Gateway, cfg: HttpConfig, auth: Option<AuthState>) -> Router {
    let state = Arc::new(AppState {
        // One gateway instance serves every HTTP client, so a client's
        // `initialize` must not be allowed to set the shared audit identity.
        gw: Mutex::new(gw.shared_across_clients()),
        allowed_origins: cfg.allowed_origins,
        inflight: cfg.max_inflight.map(|n| Arc::new(Semaphore::new(n.max(1)))),
        spec_version: SPEC_VERSION,
        auth,
    });
    Router::new()
        .route("/mcp", post(handle_post).get(handle_get))
        // RFC 9728 Protected Resource Metadata — a 401'd client fetches this to
        // discover the authorization server. Always routed; 404s if auth is off.
        .route("/.well-known/oauth-protected-resource", get(handle_prm))
        // Cap the request body (a `413` over the limit) so an unauthenticated
        // client can't force a large allocation before auth/policy run.
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

async fn handle_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    // 1. Origin (DNS-rebinding defense) — before any work.
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if !origin_allowed(origin, &state.allowed_origins) {
        return (
            StatusCode::FORBIDDEN,
            format!("origin {:?} not allowed", origin.unwrap_or("")),
        )
            .into_response();
    }

    // 2. Load-shedding: a non-blocking permit. Over the cap → 503 (fail fast).
    let _permit = match &state.inflight {
        Some(sem) => match Arc::clone(sem).try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::RETRY_AFTER, "1")],
                    "gateway overloaded — retry shortly",
                )
                    .into_response()
            }
        },
        None => None,
    };

    // 3. OAuth 2.1 bearer validation (Resource Server), when enabled. A
    //    missing/invalid token → 401 + a `WWW-Authenticate` challenge pointing at
    //    this resource's PRM document, per RFC 6750 / RFC 9728.
    let principal = match &state.auth {
        Some(auth) => {
            // On an unknown `kid`, verify_with_rotation re-fetches the JWKS once
            // (rate-limited, egress-guarded) to pick up an IdP key rotation.
            let result = match bearer_token(&headers) {
                Some(token) => verify_with_rotation(auth, token).await,
                None => Err(AuthError::Missing),
            };
            match result {
                Ok(p) => Some(p),
                Err(_) => {
                    let url = metadata_url(&auth.verifier);
                    return unauthorized(&auth.verifier.challenge(&url));
                }
            }
        }
        None => None,
    };

    // 4. Parse one JSON-RPC message.
    let msg = match Message::from_json_line(body.trim()) {
        Ok(m) => m,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("invalid JSON-RPC: {e}")).into_response()
        }
    };

    // 5. Hand to the gateway (serialized), carrying the authenticated principal so
    //    it sets the audit identity and applies the RBAC gate.
    let outcome = {
        let mut gw = state.gw.lock().await;
        gw.handle_authed(msg, principal.as_ref()).await
    };

    match outcome {
        // A request → a single JSON response.
        Ok(Some(resp)) => (
            [
                ("content-type", "application/json"),
                ("mcp-protocol-version", state.spec_version),
            ],
            resp.to_json_line(),
        )
            .into_response(),
        // A notification → 202 Accepted, no body (per the Streamable HTTP spec).
        Ok(None) => StatusCode::ACCEPTED.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("gateway error: {e}"),
        )
            .into_response(),
    }
}

/// No server-initiated SSE stream is offered in this phase → `405` (spec-allowed).
async fn handle_get() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        "mcpdef does not offer a server→client GET stream",
    )
        .into_response()
}

/// The RFC 9728 Protected Resource Metadata document, so a `401`'d client can
/// discover the authorization server. `404` when auth is disabled.
async fn handle_prm(State(state): State<Arc<AppState>>) -> Response {
    match &state.auth {
        Some(auth) => (
            [(header::CONTENT_TYPE, "application/json")],
            auth.verifier.protected_resource_metadata().to_string(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Extract a bearer token from `Authorization: Bearer <token>` (scheme is
/// case-insensitive per RFC 7235). Returns the raw token without the prefix.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    scheme.eq_ignore_ascii_case("Bearer").then(|| token.trim())
}

/// The absolute URL of this resource's PRM document, for the `WWW-Authenticate`
/// challenge. Built from the gateway's **configured** canonical resource origin
/// (`[gateway.auth] resource`) + the metadata path — never from the request
/// `Host` / `X-Forwarded-Proto`, which a client or proxy could spoof to make a
/// `401` advertise attacker-chosen metadata. Falls back to the bare path if the
/// configured resource somehow isn't a parseable absolute URL.
fn metadata_url(verifier: &Verifier) -> String {
    match url::Url::parse(verifier.resource()) {
        Ok(mut u) => {
            u.set_path(verifier.metadata_path());
            u.set_query(None);
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => verifier.metadata_path().to_string(),
    }
}

/// A `401 Unauthorized` carrying the OAuth `WWW-Authenticate` challenge.
fn unauthorized(challenge: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, challenge)],
        "missing or invalid bearer token",
    )
        .into_response()
}

/// Whether a request `Origin` is allowed. No Origin (non-browser clients) passes;
/// loopback origins always pass; anything else must be explicitly allowlisted.
fn origin_allowed(origin: Option<&str>, allowed: &[String]) -> bool {
    let Some(origin) = origin else {
        return true; // CLI / agent clients send no Origin
    };
    if allowed.iter().any(|a| a == origin) {
        return true;
    }
    // Loopback is always allowed — DNS-rebinding targets cross-site *browser*
    // origins, which resolve to a non-loopback host.
    if let Ok(u) = url::Url::parse(origin) {
        match u.host_str() {
            Some("localhost") => return true,
            Some(host) => {
                if let Ok(ip) = host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
                    return ip.is_loopback();
                }
            }
            None => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_policy() {
        let allow = vec!["https://app.example.com".to_string()];
        // no Origin → allowed (CLI/agent)
        assert!(origin_allowed(None, &allow));
        // loopback origins → allowed regardless of allowlist
        assert!(origin_allowed(Some("http://localhost:7878"), &[]));
        assert!(origin_allowed(Some("http://127.0.0.1:9000"), &[]));
        assert!(origin_allowed(Some("http://[::1]:7878"), &[]));
        // explicit allowlist entry → allowed
        assert!(origin_allowed(Some("https://app.example.com"), &allow));
        // a cross-site browser origin → rejected
        assert!(!origin_allowed(Some("https://evil.example.com"), &allow));
        assert!(!origin_allowed(Some("http://10.0.0.5"), &[]));
    }
}
