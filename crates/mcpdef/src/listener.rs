// SPDX-License-Identifier: Apache-2.0
//! The downstream **Streamable HTTP listener** — the slice of Phase 1 that lets
//! MCP clients reach mcpdef over HTTP instead of stdio (the shared-gateway shape:
//! "point every agent at one endpoint, govern centrally").
//!
//! Design (ARCHITECTURE.md §4, built **stateless-first**): a `POST` to the single
//! MCP endpoint carries one JSON-RPC message; the gateway handles it and replies
//! with a single `application/json` response, or `202 Accepted` for a
//! notification. The gateway's `handle` is already per-message and keeps no
//! per-client session state, so a client `Mcp-Session-Id` is simply ignored,
//! never required or issued — which is what 2026-07-28 requires of a
//! modern-only server anyway.
//!
//! **Two wire models, one endpoint.** `[gateway] wire` picks which eras are
//! served: `legacy` (2025-11-25, the default — an upgrade changes nothing),
//! `modern` (2026-07-28), or `dual`. A request's era is read off the message
//! itself, per the revision's own rule for a dual-era server, and on the modern
//! wire the mirrored `Mcp-Method` / `Mcp-Name` headers are checked against the
//! body **before anything routes**. That check is not politeness: the allowlist,
//! the pin and the rate limit all key on the tool name, so a request whose
//! header says `safe_tool` and whose body calls `dangerous_tool` is a policy
//! bypass unless the two are made to agree first.
//!
//! Defenses on by default:
//! * **Origin validation** — a browser cross-site `Origin` is rejected `403`
//!   (DNS-rebinding defense). Loopback origins + no-Origin (CLI/agent) clients
//!   pass; extra origins are allowlisted in config.
//! * **Loopback bind** — `[gateway] listen` defaults to `127.0.0.1`, not `0.0.0.0`.
//! * **Load-shedding** — an optional in-flight cap sheds excess with `503` +
//!   `Retry-After` (fail-fast over unbounded buffering, §5b) rather than queueing
//!   without bound.
//! * **OAuth 2.1 bearer auth** (when `[gateway.auth]` is enabled) — every `POST`
//!   must carry a valid `Authorization: Bearer` JWT (validated per request by
//!   [`mcpdef_auth::Verifier`] as an OAuth 2.1 Resource Server); a missing/invalid
//!   token gets `401` with a `WWW-Authenticate` challenge pointing at the
//!   RFC 9728 Protected Resource Metadata document served at
//!   `/.well-known/oauth-protected-resource`. The validated [`Principal`] becomes
//!   the audit identity and drives the RBAC gate.
//!
//! * **TLS** (when `[gateway.tls]` is on) — [`serve_https`] serves the same
//!   routes over TLS, from a certificate in files or one a local CA issues
//!   (see [`crate::tls`]), swapped whole on reload.
//! * **mTLS** (when `[gateway.tls.client_auth]` is on) — the certificate a
//!   client presented at the handshake is who it is: its identity is the
//!   audit identity when no token names the caller, and the `actor` behind
//!   one that does, and `[[identity.cert_map]]` gives it its roles. A
//!   certificate a reload's CA or CRL no longer passes, or one that names no
//!   identity MCPdef accepts, is refused `403`. `[gateway.auth] methods` and
//!   `require` say which credentials a request needs: a token, a
//!   certificate, or both.
//! * **Behind a trusted proxy** (`[gateway.trusted_proxy]`) — on a request
//!   from the proxy, the client's certificate is the one it forwards in a
//!   header, checked as one presented at the handshake would be; the proxy's
//!   own, if it presented one, is never taken for its client's. From anyone
//!   else, the header is not read. [`serve_proxied`] serves plain HTTP so,
//!   the proxy terminating TLS in front.
//!
//! A server→client `GET` SSE stream is **not** offered in this phase, so `GET`
//! on the MCP endpoint returns `405` (spec-compliant: "405 if the server does not
//! offer one").
//!
//! **Concurrency.** One [`Gateway`] serves every client, and requests run
//! through it at once: a slow upstream holds up only the calls sent to it. A
//! call runs to its end even if its client disconnects first, so its audit
//! record is still written.

use crate::config::ClientAuthMode;
use crate::gateway::Caller;
use crate::tls::client_auth::Presented;
use crate::tls::{TlsListener, TlsSlot};
use crate::{Config, Gateway};
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use axum::{
    extract::connect_info::{ConnectInfo, Connected},
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    serve::IncomingStream,
    Router,
};
use mcpdef_auth::{AuthError, Principal, Verifier};
use mcpdef_core::wire::{self, validate_headers, WireError, WireMode, WireModel};
use mcpdef_core::{Id, Message};
use mcpdef_transport::{fetch_text, EgressPolicy, TlsSettings};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::SystemTime;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Listener settings derived from `[gateway]`.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// `host:port` to bind (loopback by default).
    pub listen: String,
    /// Extra allowed Origins beyond loopback.
    pub allowed_origins: Vec<String>,
    /// Max concurrent in-flight requests (load-shedding); `None` = unlimited.
    pub max_inflight: Option<usize>,
    /// Which MCP wire models this listener serves (`[gateway] wire`).
    pub wire: WireMode,
}

/// How the gateway's own fetches go out: through the egress guard, with the
/// TLS profile of `[gateway.upstream_tls]`, its files read at each fetch.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Fetching {
    pub egress: EgressPolicy,
    pub tls: TlsSettings,
}

impl Fetching {
    /// How `cfg` says to fetch.
    pub fn of(cfg: &Config) -> Self {
        Fetching {
            egress: cfg.gateway.egress_policy(),
            tls: cfg.gateway.fetch_tls(),
        }
    }
}

/// Re-fetches the JWKS from a configured `jwks_uri`, through the same egress/SSRF
/// guard as the startup fetch. Present only when keys came from a `jwks_uri` (an
/// inline / file JWKS is static and can't be re-fetched). Lets the listener pick
/// up an authorization-server signing-key rotation without a restart.
pub struct JwksRefresher {
    uri: String,
    fetching: Arc<ArcSwap<Fetching>>,
}

impl JwksRefresher {
    /// Fetch through `egress`, with the bundled roots alone.
    pub fn new(uri: impl Into<String>, egress: EgressPolicy) -> Self {
        let fetching = Fetching {
            egress,
            tls: TlsSettings::default(),
        };
        Self::following(uri, Arc::new(ArcSwap::from_pointee(fetching)))
    }

    /// Fetch as `fetching` says at the time: a reload that stores new
    /// settings there changes how the next fetch goes out.
    pub fn following(uri: impl Into<String>, fetching: Arc<ArcSwap<Fetching>>) -> Self {
        JwksRefresher {
            uri: uri.into(),
            fetching,
        }
    }

    /// Fetch the current JWKS document, or `None` on any error (logged). The caller
    /// treats a failed fetch as fail-closed (the request is denied).
    async fn fetch(&self) -> Option<String> {
        let fetching = self.fetching.load_full();
        let fetched = match fetching.tls.load_async().await {
            Ok(tls) => fetch_text(&self.uri, &fetching.egress, &tls).await,
            Err(e) => Err(e),
        };
        match fetched {
            Ok(json) => Some(json),
            Err(e) => {
                eprintln!("mcpdef: {}", refresh_failed(&self.uri, &e));
                None
            }
        }
    }
}

/// What the log says of a JWKS refresh from `uri` that failed with `e`, any
/// secret a URL in it holds masked.
fn refresh_failed(uri: &str, e: &impl std::fmt::Display) -> String {
    crate::redact::redact_urls(&format!("JWKS refresh from {uri} failed: {e}")).into_owned()
}

/// What `[gateway.auth]` requires of every request: a bearer token, checked by
/// the per-request [`Verifier`], with an optional [`JwksRefresher`] used to
/// rotate keys on an unknown `kid`; a client certificate; or both.
pub struct AuthState {
    /// When `bearer` is one of the methods.
    bearer: Option<Bearer>,
    /// Whether `key` is one of the methods: a bearer token that is a client
    /// key the gateway issued names its caller.
    keys: bool,
    /// Whether `mtls` is one of the methods.
    certificate: bool,
    /// Whether a request needs a credential of each method (`require =
    /// "all"`), not just one.
    all: bool,
}

/// The bearer token's check.
struct Bearer {
    verifier: Verifier,
    refresher: Option<JwksRefresher>,
}

impl Bearer {
    /// A `401` whose `WWW-Authenticate` challenge points at this resource's
    /// metadata, for a request whose token is missing or does not check out.
    fn unauthorized(&self) -> Response {
        unauthorized(&self.verifier.challenge(&metadata_url(&self.verifier)))
    }
}

impl AuthState {
    /// A bearer token, with a static JWKS (inline / file) — no runtime refresh.
    pub fn new(verifier: Verifier) -> Self {
        AuthState {
            bearer: Some(Bearer {
                verifier,
                refresher: None,
            }),
            keys: false,
            certificate: false,
            all: false,
        }
    }

    /// A bearer token, with the JWKS re-fetched from `jwks_uri` on an unknown
    /// `kid`, so an IdP key rotation is picked up without a restart.
    pub fn with_refresher(verifier: Verifier, refresher: JwksRefresher) -> Self {
        AuthState {
            bearer: Some(Bearer {
                verifier,
                refresher: Some(refresher),
            }),
            keys: false,
            certificate: false,
            all: false,
        }
    }

    /// A client certificate alone: `methods = ["mtls"]`.
    pub fn certificate() -> Self {
        AuthState {
            bearer: None,
            keys: false,
            certificate: true,
            all: false,
        }
    }

    /// A client key the gateway issued alone: `methods = ["key"]`.
    pub fn keys() -> Self {
        AuthState {
            bearer: None,
            keys: true,
            certificate: false,
            all: false,
        }
    }

    /// A client key the gateway issued besides what this takes: `key` among
    /// the methods.
    pub fn or_keys(self) -> Self {
        AuthState { keys: true, ..self }
    }

    /// A client certificate besides the bearer token: `methods = ["bearer",
    /// "mtls"]`, with `all` when a request needs both (`require = "all"`).
    pub fn or_certificate(self, all: bool) -> Self {
        AuthState {
            certificate: true,
            all,
            ..self
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
async fn verify_with_rotation(auth: &Bearer, token: &str) -> Result<Principal, AuthError> {
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
    /// Shared by every request, which run through it at once. Bounded
    /// concurrency on top is the in-flight cap below.
    gw: Gateway,
    allowed_origins: Vec<String>,
    inflight: Option<Arc<Semaphore>>,
    wire: WireMode,
    /// What `[gateway.auth]` requires, when it is enabled: a bearer token
    /// (verifier + optional JWKS refresher), a client certificate, or both.
    /// `None` leaves the endpoint unauthenticated (loopback/dev). Shared via
    /// the surrounding `Arc<AppState>`; the verifier's JWKS is internally
    /// lock-guarded so a rotation needs no `&mut`.
    auth: Option<AuthState>,
    /// The listener's slot, on HTTPS or behind a trusted proxy: what it asks
    /// of a client's certificate, and the proxy it trusts to forward one, as
    /// the last reload left them.
    tls: Option<TlsSlot>,
}

/// Who is at the other end of a connection: its address, and on a TLS
/// listener that asked for one, the certificate it presented at the
/// handshake. Read once per connection, for each request on it.
#[derive(Clone, Debug)]
pub(crate) struct Peer {
    addr: SocketAddr,
    presented: Option<Arc<Presented>>,
}

impl Peer {
    /// The address the connection came from.
    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Connected<IncomingStream<'_, TcpListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        Peer {
            addr: *stream.remote_addr(),
            presented: None,
        }
    }
}

impl Connected<IncomingStream<'_, TlsListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, TlsListener>) -> Self {
        Peer {
            addr: *stream.remote_addr(),
            presented: stream.io().presented().cloned(),
        }
    }
}

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
    serve_plain(listener, router(gw, cfg, auth, None)).await
}

/// [`serve_http`] behind a proxy that terminates TLS in front of it and
/// forwards each client's certificate (`[gateway.trusted_proxy]`): each
/// request's checked and read as `slot` holds it when the request comes, so
/// one a reload stores there checks every request after it.
pub async fn serve_proxied(
    gw: Gateway,
    cfg: HttpConfig,
    auth: Option<AuthState>,
    slot: TlsSlot,
) -> Result<()> {
    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("binding HTTP listener on {}", cfg.listen))?;
    serve_proxied_on(listener, gw, cfg, auth, slot).await
}

/// [`serve_proxied`] on an already-bound listener.
pub async fn serve_proxied_on(
    listener: TcpListener,
    gw: Gateway,
    cfg: HttpConfig,
    auth: Option<AuthState>,
    slot: TlsSlot,
) -> Result<()> {
    serve_plain(listener, router(gw, cfg, auth, Some(slot))).await
}

/// Serve `app` over plain HTTP on `listener`, each request knowing its peer.
async fn serve_plain(listener: TcpListener, app: Router) -> Result<()> {
    axum::serve(listener, app.into_make_service_with_connect_info::<Peer>())
        .await
        .context("HTTP listener failed")?;
    Ok(())
}

/// [`serve_http`] over TLS (`[gateway.tls]`): each connection is served the
/// `ServerConfig` `tls` holds when it is accepted, so one a reload stores
/// there serves every connection after it.
pub async fn serve_https(
    gw: Gateway,
    cfg: HttpConfig,
    auth: Option<AuthState>,
    tls: TlsSlot,
) -> Result<()> {
    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("binding HTTPS listener on {}", cfg.listen))?;
    serve_https_on(listener, gw, cfg, auth, tls).await
}

/// [`serve_https`] on an already-bound listener.
pub async fn serve_https_on(
    listener: TcpListener,
    gw: Gateway,
    cfg: HttpConfig,
    auth: Option<AuthState>,
    tls: TlsSlot,
) -> Result<()> {
    let app = router(gw, cfg, auth, Some(Arc::clone(&tls)));
    let listener = TlsListener::new(listener, tls).context("HTTPS listener")?;
    axum::serve(listener, app.into_make_service_with_connect_info::<Peer>())
        .await
        .context("HTTPS listener failed")?;
    Ok(())
}

fn router(gw: Gateway, cfg: HttpConfig, auth: Option<AuthState>, tls: Option<TlsSlot>) -> Router {
    let state = Arc::new(AppState {
        // One gateway instance serves every HTTP client, so a client's
        // `initialize` must not be allowed to set the shared audit identity.
        gw: gw.shared_across_clients(),
        allowed_origins: cfg.allowed_origins,
        inflight: cfg.max_inflight.map(|n| Arc::new(Semaphore::new(n.max(1)))),
        wire: cfg.wire,
        auth,
        tls,
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
    ConnectInfo(peer): ConnectInfo<Peer>,
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
    //    The call holds it until it ends, even if the client leaves first.
    let permit = match &state.inflight {
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

    // 3. The client certificate, on a listener that asks for one: the one
    //    presented at the handshake, or on a request from a trusted proxy,
    //    the one it forwards. Checked again first when a reload changed what
    //    the listener trusts since the handshake, or whole if forwarded, then
    //    read for the identity it gives. One that does not check out, or
    //    names no identity MCPdef accepts, refuses the request, whatever else
    //    it carries: a client is never taken for no one when it presented
    //    someone.
    let certificate = match certified(state.tls.as_ref(), &peer, &headers, SystemTime::now()) {
        Ok(identity) => identity,
        Err(why) => return forbidden(why),
    };

    // 4. What `[gateway.auth]` requires, when enabled: a bearer token (OAuth
    //    2.1, validated as a Resource Server), a client certificate, or both.
    //    A token that is presented and does not check out → 401 + a
    //    `WWW-Authenticate` challenge pointing at this resource's PRM document,
    //    per RFC 6750 / RFC 9728, whatever else the request carries.
    let principal = match &state.auth {
        Some(auth) => match authenticated(auth, &state.gw, &headers, certificate.is_some()).await {
            Ok(principal) => principal,
            Err(missing) => return auth.refusal(missing),
        },
        None => None,
    };
    let caller = Caller {
        principal,
        certificate,
        peer: Some(peer.addr),
    };

    // 5. Parse one JSON-RPC message.
    let msg = match Message::from_json_line(body.trim()) {
        Ok(m) => m,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("invalid JSON-RPC: {e}")).into_response()
        }
    };

    // 6. Wire model. Which era this message belongs to comes off the message,
    //    and `[gateway] wire` decides whether this listener serves it. On the
    //    modern wire the mirrored headers are reconciled with the body here,
    //    before the tool name reaches anything that decides on it.
    let spec_version = match wire_check(state.wire, &msg, &headers) {
        Ok(v) => v,
        Err(e) => return wire_rejected(&e, msg.id.clone()),
    };
    let modern = WireModel::of(&msg) == Some(WireModel::Modern);
    // And a modern `tools/call`'s `Mcp-Param-{Name}` headers, by the
    // `x-mcp-header` annotations of the tool it names, as its server lists it
    // now. The gateway has them; it is asked at this moment rather than told
    // once, because a re-list, a restart or a reload can change them.
    if modern {
        if let Err(e) = state
            .gw
            .check_param_headers(&msg, |name| param_header(&headers, name))
        {
            return wire_rejected(&e, msg.id.clone());
        }
    }

    // 7. Hand to the gateway, carrying who the caller is so it sets the audit
    //    identity and applies the RBAC gate. Unchanged by the wire model: both
    //    eras carry the same JSON-RPC and are governed the same.
    let gw = state.gw.clone();
    let outcome = RunToEnd::new(async move {
        let _permit = permit;
        gw.handle_from(msg, &caller).await
    })
    .await;

    match outcome {
        // A request → a single JSON response. On the modern wire a method the
        // gateway does not serve is `404` with its `-32601`, as the revision
        // requires; that body is what tells it from a server with no MCP
        // endpoint there at all.
        Ok(Some(resp)) => {
            let not_found = modern
                && resp.error.as_ref().and_then(|e| e["code"].as_i64())
                    == Some(wire::error_code::METHOD_NOT_FOUND);
            let status = if not_found {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::OK
            };
            (
                status,
                [
                    ("content-type", "application/json"),
                    ("mcp-protocol-version", spec_version.as_str()),
                ],
                resp.to_json_line(),
            )
                .into_response()
        }
        // A notification → 202 Accepted, no body (per the Streamable HTTP spec).
        Ok(None) => StatusCode::ACCEPTED.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("gateway error: {e}"),
        )
            .into_response(),
    }
}

/// Runs a call to its end even if whoever awaits it goes away.
///
/// A client that disconnects mid-call makes hyper drop the handler, and dropping
/// a future cancels what it was doing: here a governed call, whose audit record
/// would then never be written. So the call is boxed, where it can move without
/// moving, and dropped before it finished, this hands the rest of it to a task
/// of its own. A call that runs to its end, nearly every one, never pays for a
/// task.
struct RunToEnd<F>(Option<Pin<Box<F>>>)
where
    F: Future + Send + 'static,
    F::Output: Send + 'static;

impl<F> RunToEnd<F>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn new(call: F) -> Self {
        RunToEnd(Some(Box::pin(call)))
    }
}

impl<F> Future for RunToEnd<F>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<F::Output> {
        let call = self.0.as_mut().expect("polled after it finished");
        let done = call.as_mut().poll(cx);
        if done.is_ready() {
            self.0 = None;
        }
        done
    }
}

impl<F> Drop for RunToEnd<F>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn drop(&mut self) {
        if let Some(call) = self.0.take() {
            // Without a runtime (it is shutting down) there is nowhere to finish.
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(call);
            }
        }
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
/// discover the authorization server. `404` when no bearer token is taken.
async fn handle_prm(State(state): State<Arc<AppState>>) -> Response {
    match state.auth.as_ref().and_then(|auth| auth.bearer.as_ref()) {
        Some(bearer) => (
            [(header::CONTENT_TYPE, "application/json")],
            bearer.verifier.protected_resource_metadata().to_string(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The identity the client's certificate gives, on a listener that asks for
/// one and from a client that presented one, as of `now`; or why the request
/// is refused: the listener requires a certificate and the client presented
/// none, the one it presented no longer checks out, or it names no identity
/// the listener accepts.
///
/// On a request from the proxy the listener trusts, the client's certificate
/// is the one the proxy forwarded in `headers`, and what it forwarded must
/// read; the proxy's own, if it presented one, is not its client's. From
/// anyone else, `headers` are not read.
pub(crate) fn certified(
    tls: Option<&TlsSlot>,
    peer: &Peer,
    headers: &HeaderMap,
    now: SystemTime,
) -> Result<Option<String>, String> {
    let Some(served) = tls.map(|tls| tls.load_full()) else {
        return Ok(None);
    };
    let Some(clients) = &served.clients else {
        return Ok(None);
    };
    let forwarded;
    let presented = match &served.proxy {
        Some(proxy) if proxy.trusts(peer.addr.ip()) => {
            let chain = proxy.certificate(headers).map_err(|why| {
                format!("the client certificate the proxy forwarded does not read: {why}")
            })?;
            forwarded = chain.and_then(Presented::forwarded);
            forwarded.as_ref()
        }
        _ => peer.presented.as_deref(),
    };
    let Some(presented) = presented else {
        return match clients.mode() {
            ClientAuthMode::Required => Err("a client certificate is required".to_string()),
            _ => Ok(None),
        };
    };
    clients
        .admit(presented, now)
        .map_err(|why| format!("the client certificate is refused: {why}"))?;
    clients
        .identity(presented)
        .map(Some)
        .map_err(|why| format!("the client certificate names no identity MCPdef accepts: {why}"))
}

/// What a request lacks that `[gateway.auth]` requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Missing {
    /// A token that checks out: none was presented, or the one presented
    /// does not.
    Token,
    /// A client certificate that gives an identity.
    Certificate,
}

impl AuthState {
    /// The answer to a request that lacks `missing`: for a token, the
    /// challenge that says where to get one, and for a certificate, `403`.
    fn refusal(&self, missing: Missing) -> Response {
        match (missing, &self.bearer) {
            (Missing::Token, Some(bearer)) => bearer.unauthorized(),
            // Client keys alone: no metadata to point at.
            (Missing::Token, None) if self.keys => unauthorized("Bearer"),
            _ => forbidden("a client certificate is required".to_string()),
        }
    }
}

/// The bearer token's principal, when the request carries one `auth` takes,
/// once the request has what `auth` requires: a credential of one of its
/// methods, or of each with `require = "all"`; or what it lacks. `certified`
/// says whether the request came with a client certificate that gave an
/// identity. A token that is presented and does not check out is lacking
/// whatever else the request carries.
async fn authenticated(
    auth: &AuthState,
    gw: &Gateway,
    headers: &HeaderMap,
    certified: bool,
) -> Result<Option<Principal>, Missing> {
    let principal = match (bearer_token(headers), &auth.bearer) {
        // A client key the gateway issued, where it takes them, by its own
        // prefix: one it did not issue, or no longer lists, is refused.
        (Some(token), _) if auth.keys && token.starts_with(KEY_PREFIX) => {
            match gw.issued_key(token) {
                Some(principal) => Some(principal),
                None => return Err(Missing::Token),
            }
        }
        // On an unknown `kid`, verify_with_rotation re-fetches the JWKS once
        // (rate-limited, egress-guarded) to pick up an IdP key rotation.
        (Some(token), Some(bearer)) => match verify_with_rotation(bearer, token).await {
            Ok(principal) => Some(principal),
            Err(_) => return Err(Missing::Token),
        },
        // Another token, where keys alone are taken.
        (Some(_), None) if auth.keys => return Err(Missing::Token),
        _ => None,
    };
    let token_missing = (auth.bearer.is_some() || auth.keys) && principal.is_none();
    let certificate_missing = auth.certificate && !certified;
    let refused = match auth.all {
        true => token_missing || certificate_missing,
        false => principal.is_none() && !(auth.certificate && certified),
    };
    if !refused {
        return Ok(principal);
    }
    match token_missing {
        true => Err(Missing::Token),
        false => Err(Missing::Certificate),
    }
}

/// What every client key the gateway issues begins with, as `mcpdef keys
/// create` makes them.
pub const KEY_PREFIX: &str = "mcpdef_key_";

/// A `403 Forbidden` that says why.
fn forbidden(why: String) -> Response {
    (StatusCode::FORBIDDEN, why).into_response()
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

/// Decide whether this listener serves the message's era, and on the modern wire
/// reconcile the mirrored headers with the body. Returns the protocol version to
/// stamp on the response.
///
/// The era comes off the message — modern `_meta` means modern, `initialize`
/// means legacy — which is the revision's own rule for a dual-era server, and it
/// is why an era-ambiguous request reads as legacy: a modern client always
/// carries its `_meta`, so a request without one was never modern.
fn wire_check(mode: WireMode, msg: &Message, headers: &HeaderMap) -> Result<String, WireError> {
    let served = mode.served();
    // `HeaderMap::get` already matches names case-insensitively, and `to_str`
    // refuses a value that is not ASCII — which for a mirrored header is the
    // same as not having sent one we can compare.
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());

    match WireModel::of(msg) {
        Some(WireModel::Modern) if mode.serves_modern() => Ok(validate_headers(msg, get, served)?
            .protocol_version
            .to_string()),
        // A modern request at a legacy-only listener. Naming what *is* served is
        // the whole point of the error: it is what the client retries against.
        Some(WireModel::Modern) => Err(WireError::UnsupportedProtocolVersion {
            requested: wire::protocol_version(msg).unwrap_or_default().to_string(),
            supported: served.iter().map(|v| v.to_string()).collect(),
        }),
        _ if mode.serves_legacy() => Ok(wire::SPEC_2025_11_25.to_string()),
        // Modern-only, and the client opened with `initialize`. It has no
        // fall-forward mechanism, so this message may be the only diagnostic it
        // can show a human — name the revisions and how to speak them.
        Some(WireModel::Legacy) => Err(WireError::HeaderMismatch(format!(
            "this gateway serves {served:?}, which have no `initialize` handshake. Send the \
             request itself, carrying {} in params._meta and the matching {} header.",
            wire::meta_key::PROTOCOL_VERSION,
            wire::header::PROTOCOL_VERSION,
        ))),
        // Modern-only, and the request named no era at all. Header validation
        // says precisely which piece is missing, which beats a generic refusal.
        None => Err(validate_headers(msg, get, served).err().unwrap_or_else(|| {
            WireError::HeaderMismatch(format!(
                "a request to this gateway must carry {} in params._meta",
                wire::meta_key::PROTOCOL_VERSION,
            ))
        })),
    }
}

/// An `Mcp-Param-{Name}` header's value, by its lower-case `name`.
///
/// Unlike the standard headers in [`wire_check`], one that is not ASCII is not
/// taken for absent: for an argument the body leaves out, absent is the state
/// that passes. Its bytes are read as they are, `U+FFFD` for any that are not
/// UTF-8, so the check refuses it as a value a header cannot carry.
fn param_header<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    headers
        .get(name)
        .map(|v| std::str::from_utf8(v.as_bytes()).unwrap_or("\u{fffd}"))
}

/// Render a wire rejection as the revision defines it: the HTTP status it names,
/// and a JSON-RPC error body carrying the code and, for an unsupported version,
/// the `data.supported` list a client retries against.
fn wire_rejected(e: &WireError, id: Option<Id>) -> Response {
    (
        StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::BAD_REQUEST),
        [("content-type", "application/json")],
        e.to_message(id).to_json_line(),
    )
        .into_response()
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

    #[test]
    fn a_failed_refresh_names_its_url_without_the_secrets_it_holds() {
        let uri = "https://idp.test/jwks.json?api_key=s3cret-key";
        let e = mcpdef_transport::TransportError::Http(format!("GET {uri} returned 500"));
        assert_eq!(
            refresh_failed(uri, &e),
            "JWKS refresh from https://idp.test/jwks.json?api_key=*** failed: http: GET \
             https://idp.test/jwks.json?api_key=*** returned 500"
        );
    }
}
