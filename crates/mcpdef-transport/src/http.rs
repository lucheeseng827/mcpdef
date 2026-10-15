// SPDX-License-Identifier: Apache-2.0
//! `http` — the Phase-1 Streamable HTTP transport and the Phase-1.5 legacy
//! HTTP+SSE bridge, behind one [`HttpClient`] that implements [`Transport`].
//!
//! Two upstream wire formats, one transport:
//!
//! * **Streamable HTTP** (current, `2025-03-26`+): a single endpoint. Each
//!   client→server message is an HTTP `POST`; the server replies with a single
//!   JSON body, an SSE stream, or `202 Accepted` (for a notification). The
//!   `Mcp-Session-Id` the server returns on `initialize` is echoed on every
//!   later request, and so is the revision `initialize` settled on, as the
//!   `MCP-Protocol-Version` header 2025-11-25 requires after the handshake.
//! * **Legacy HTTP+SSE** (`2024-11-05`): the client opens a `GET` SSE stream;
//!   the server's first event is `endpoint`, naming the POST URL. Thereafter
//!   client→server messages `POST` to that URL (answered `202`), and *all*
//!   server→client messages — including responses — arrive on the held-open SSE
//!   stream. A dropped stream resumes via `Last-Event-ID`.
//!
//! [`HttpClient::streamable`] tries Streamable HTTP first and, on a `400/404/405`
//! to the initial `POST`, **falls back** to the legacy bridge — the
//! backwards-compatible client behaviour the MCP spec describes. The resolution
//! happens lazily on the first `send` (always the `initialize` request), so the
//! gateway's transport-agnostic handshake is unchanged.
//!
//! Once Streamable HTTP is negotiated, its endpoint takes concurrent POSTs:
//! [`Transport::concurrent`] hands that side to an
//! [`UpstreamHandle`](crate::UpstreamHandle), which posts from every caller at
//! once. The legacy bridge answers on one shared stream, so it stays behind the
//! handle's single task.

use crate::cert::{TlsWatch, Verification};
use crate::egress::{self, EgressPolicy};
use crate::tls::{MinVersion, TlsProfile};
use crate::{answer_request, Exchange, Transport, TransportError};
use async_trait::async_trait;
use futures_util::StreamExt;
use mcpdef_core::wire::{self, is_modern_error, mirrored_headers, ParamHeader};
use mcpdef_core::{method, Message};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::SystemTime;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;

type Inbound = Result<Message, TransportError>;

/// How an [`HttpClient`] resolves its wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpKind {
    /// Streamable HTTP, with automatic fallback to the legacy HTTP+SSE bridge on
    /// a `400/404/405` (config `transport = "streamable-http"`).
    Auto,
    /// Force the legacy `2024-11-05` HTTP+SSE bridge (config `transport = "sse"`).
    Legacy,
}

/// The `x-mcp-header` annotations of an upstream's tools, by tool name: the
/// arguments a `tools/call` to each goes out with, mirrored into
/// `Mcp-Param-{Name}` headers ([`wire::param_header_values`]).
///
/// A modern Streamable-HTTP server rejects a call whose annotated argument is
/// in the body with no matching header, so a tool that asks for one cannot be
/// called without it. Which ones a tool asks for is in its definition, which
/// the transport never reads: whoever lists the tools [`set`](Self::set)s
/// them here, each time it lists them, and every request after that is sent
/// by what they say then. It is shared: the one
/// [`Transport::param_headers`] hands out is the one the transport's
/// concurrent side keeps, so it holds for as long as the transport runs.
#[derive(Clone, Debug, Default)]
pub struct ParamHeaders(Arc<RwLock<ByTool>>);

/// Each tool's annotations, by its name upstream: replaced whole, never edited.
type ByTool = Arc<HashMap<String, Vec<ParamHeader>>>;

impl ParamHeaders {
    /// Send each request from now on by `by_tool`: the annotations of each
    /// tool that has any, by its name upstream.
    pub fn set(&self, by_tool: Arc<HashMap<String, Vec<ParamHeader>>>) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = by_tool;
    }

    /// The `Mcp-Param-{Name}` headers `msg` goes out with: none unless it is
    /// a modern `tools/call` of a tool with annotations.
    fn values(&self, msg: &Message) -> Vec<(String, String)> {
        let Some(tool) = msg.tool_name() else {
            return Vec::new();
        };
        let by_tool = Arc::clone(&self.0.read().unwrap_or_else(PoisonError::into_inner));
        by_tool
            .get(tool)
            .map(|annotations| wire::param_header_values(msg, annotations))
            .unwrap_or_default()
    }
}

/// Credentials for one upstream, added to every HTTP request sent to it.
///
/// The seam `[server.auth]` plugs into. `apply` runs once per request, just
/// before it is sent, and may run for many requests at once: an implementation
/// that fetches tokens shares one fetch between them.
///
/// It only adds headers. The headers the transport sets itself (`Content-Type`,
/// `Accept`, `Mcp-Session-Id`, `MCP-Protocol-Version`, `Last-Event-ID` and the
/// mirrored `Mcp-*` ones) replace any of the same name set here.
///
/// When the upstream answers `401`, the transport calls `refresh` with the
/// headers `apply` added to that request. If it says the credentials changed,
/// the request goes once more; a second `401`, or no change, fails it as
/// [`TransportError::Unauthorized`].
#[async_trait]
pub trait RequestAuth: Send + Sync {
    async fn apply(&self, headers: &mut HeaderMap) -> Result<(), TransportError>;

    /// The upstream refused a request that carried `sent`. Get fresh
    /// credentials if there are any to get, and say whether the next `apply`
    /// adds other ones than `sent` holds. None, by default.
    async fn refresh(&self, sent: &HeaderMap) -> Result<bool, TransportError> {
        let _ = sent;
        Ok(false)
    }

    /// When the credentials it adds now expire, in seconds since the Unix
    /// epoch, if they say: an OAuth token's. None, by default.
    fn expires_at(&self) -> Option<i64> {
        None
    }
}

enum State {
    /// Not yet resolved; the first `send` (the `initialize`) decides the mode.
    Init {
        url: String,
        kind: HttpKind,
    },
    Modern(Arc<Streamable>),
    Legacy {
        post_url: String,
    },
    Failed,
}

/// The negotiated Streamable-HTTP binding: one endpoint, taking concurrent POSTs.
///
/// Shared by the [`HttpClient`] that opened it and, after the opening, by every
/// caller of the [`UpstreamHandle`](crate::UpstreamHandle) it is handed to. Only
/// the session id and the negotiated revision change after negotiation, so they
/// alone sit behind locks, each held for a copy and never across a request. The
/// client is the one built for the endpoint's validated, pinned addresses, with
/// redirects off.
struct Streamable {
    client: reqwest::Client,
    endpoint: String,
    session_id: Mutex<Option<String>>,
    /// The revision this endpoint's latest `initialize` settled on, repeated
    /// as `MCP-Protocol-Version` on every request after it. `None` until an
    /// `initialize` settles one, and again if a later one settles none.
    protocol_version: Mutex<Option<String>>,
    auth: Option<Arc<dyn RequestAuth>>,
    /// The [`HttpClient`]'s, kept from every answer.
    watch: TlsWatch,
    /// The [`HttpClient`]'s: what each `tools/call` mirrors into headers.
    params: ParamHeaders,
}

/// An MCP upstream reached over HTTP — Streamable HTTP or the legacy HTTP+SSE
/// bridge. Inbound messages from either mode funnel through one channel that
/// [`recv`](Transport::recv) drains.
pub struct HttpClient {
    client: reqwest::Client,
    /// The egress/SSRF policy enforced before dialing any host.
    policy: EgressPolicy,
    /// What `client` trusts, checks and presents. It is built again from this
    /// whenever a pin is added.
    tls: TlsProfile,
    /// Dial this address for the configured URL's host, rather than what the
    /// host resolves to.
    connect_to: Option<IpAddr>,
    /// The configured URL: its host is the one `connect_to` stands in for.
    origin: String,
    /// DNS pins (host → validated addrs) baked into `client`. The egress guard
    /// resolves a host once and pins the connection to exactly those IPs, so
    /// reqwest cannot re-resolve to a rebind target between check and connect.
    pins: Vec<(String, Vec<SocketAddr>)>,
    state: State,
    inbound_tx: UnboundedSender<Inbound>,
    inbound_rx: UnboundedReceiver<Inbound>,
    last_event_id: Arc<Mutex<Option<String>>>,
    auth: Option<Arc<dyn RequestAuth>>,
    /// What the configured URL's connections have shown: every response
    /// from it leaves the certificate it came over here. Only the configured
    /// URL's count. A legacy bridge's POST URL is the server's to name, and
    /// may be another host's.
    watch: TlsWatch,
    /// What each `tools/call` mirrors into headers, as its tools' definitions
    /// say: shared with the endpoint once one is settled on.
    params: ParamHeaders,
}

struct ModernPost {
    status: reqwest::StatusCode,
    session_id: Option<String>,
    messages: Vec<Message>,
}

/// A reqwest error as a transport error, with its causes. reqwest's own message
/// names only what it was doing (`error sending request for url (…)`); why it
/// failed, a refused connection say, is in its sources.
fn http_error(e: reqwest::Error) -> TransportError {
    let mut message = e.to_string();
    let mut cause = std::error::Error::source(&e);
    while let Some(c) = cause {
        let text = c.to_string();
        if !message.contains(&text) {
            message.push_str(": ");
            message.push_str(&text);
        }
        cause = c.source();
    }
    TransportError::Http(message)
}

/// Whether two URLs name the same host.
fn same_host(a: &str, b: &str) -> bool {
    let host = |u: &str| {
        url::Url::parse(u)
            .ok()?
            .host_str()
            .map(str::to_ascii_lowercase)
    };
    matches!((host(a), host(b)), (Some(a), Some(b)) if a == b)
}

/// Build a reqwest client with the given DNS pins and TLS profile.
///
/// `tls_certs_only`: an HTTPS upstream is verified against the profile's
/// roots and nothing else: by default Mozilla's, bundled into the binary, as
/// it always has been. Left to itself, reqwest would verify against the
/// host's store, which a minimal container may not have: then no client
/// builds at all, not even one for a plain-HTTP upstream. A profile that
/// trusts the host's store has read it already.
///
/// `no_proxy`: MCP upstreams are typically internal/loopback, and routing them
/// through an outbound corporate proxy is wrong (and would break loopback
/// tests). A configurable proxy is a later concern.
///
/// `redirect(none)`: the egress/SSRF guard validates + DNS-pins the *requested*
/// URL, but reqwest's default redirect policy would follow a `3xx` to an
/// arbitrary `Location` — a validated host could redirect to
/// `http://169.254.169.254/` and be dialed **without** going back through the
/// guard. MCP endpoints (and a JWKS URL) don't rely on HTTP redirects, so we
/// fail closed: a redirect surfaces as a non-success status the caller reports,
/// never a silent SSRF hop. (The legacy-SSE `endpoint` URL is an application-level
/// indirection that IS re-validated via `guard_and_pin`, not an HTTP redirect.)
///
/// A pinned profile is verified by its key instead. reqwest's own TLS
/// settings cannot say "this key and no other", so its rustls configuration
/// is built whole (`pin::pinned_config`) and handed over as it is.
/// `no_proxy`, `redirect(none)` and the DNS pins apply to it as to any.
///
/// `tls_info`: each response carries the certificate its connection was
/// handed, for the upstream's [`TlsWatch`]. reqwest copies the certificate
/// once per connection and onto each response.
fn build_client(
    pins: &[(String, Vec<SocketAddr>)],
    tls: &TlsProfile,
) -> Result<reqwest::Client, TransportError> {
    crate::install_crypto_provider();
    let mut b = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_info(true);
    b = match tls.is_pinned() {
        true => b.tls_backend_preconfigured(crate::pin::pinned_config(tls)?),
        false => with_tls_settings(b, tls)?,
    };
    for (host, addrs) in pins {
        if !addrs.is_empty() {
            b = b.resolve_to_addrs(host, addrs);
        }
    }
    b.build().map_err(http_error)
}

/// `b` with an unpinned profile, set through reqwest's own TLS settings.
fn with_tls_settings(
    b: reqwest::ClientBuilder,
    tls: &TlsProfile,
) -> Result<reqwest::ClientBuilder, TransportError> {
    let bundled = tls.bundled.then(crate::tls::bundled_roots);
    let roots = bundled
        .into_iter()
        .flatten()
        .chain(tls.roots.iter().cloned());
    let mut b = b
        .tls_certs_only(roots)
        .tls_version_min(match tls.min_version {
            MinVersion::Tls12 => reqwest::tls::Version::TLS_1_2,
            MinVersion::Tls13 => reqwest::tls::Version::TLS_1_3,
        });
    if !tls.crls.is_empty() {
        let crls = reqwest::tls::CertificateRevocationList::from_pem_bundle(tls.crls.as_bytes())
            .map_err(http_error)?;
        b = b.tls_crls_only(crls);
    }
    if let Some(identity) = &tls.identity {
        b = b.identity(identity.to_reqwest()?);
    }
    if !tls.verify {
        b = b.tls_danger_accept_invalid_certs(true);
    }
    Ok(b)
}

/// `GET` a URL's body as text **through the egress/SSRF guard** (cloud-metadata
/// always blocked, DNS-pinned to the validated IPs), verified by `tls`. The
/// one-shot fetch the binary uses to retrieve an OAuth `jwks_uri`, so a JWKS
/// URL is subject to the same SSRF defenses as an MCP upstream, and an IdP on
/// a private CA is reached with the gateway's TLS profile.
pub async fn fetch_text(
    url: &str,
    policy: &EgressPolicy,
    tls: &TlsProfile,
) -> Result<String, TransportError> {
    let get = |client: &reqwest::Client| {
        client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
    };
    let answer = fetch(url, "GET", policy, tls, &get).await?;
    if !answer.status.is_success() {
        return Err(TransportError::Http(format!(
            "GET {url} returned {}",
            answer.status
        )));
    }
    String::from_utf8(answer.body).map_err(|e| TransportError::Http(e.to_string()))
}

/// What one of [`post_form`] and [`get_bearer`] got back: the status, and
/// the body, whatever the status.
#[derive(Debug)]
pub struct Replied {
    pub status: u16,
    pub body: Vec<u8>,
}

/// `POST` a form (`form`, already URL-encoded) to `url`, **through the
/// egress/SSRF guard** and verified by `tls`, as a token request is made:
/// with `authorization` as the header of that name when given. For a code
/// the console's sign-in exchanges at its identity provider.
pub async fn post_form(
    url: &str,
    form: String,
    authorization: Option<reqwest::header::HeaderValue>,
    policy: &EgressPolicy,
    tls: &TlsProfile,
) -> Result<Replied, TransportError> {
    let post = |client: &reqwest::Client| {
        let request = client
            .post(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(form.clone());
        match &authorization {
            Some(value) => request.header(reqwest::header::AUTHORIZATION, value.clone()),
            None => request,
        }
    };
    let answer = fetch(url, "POST", policy, tls, &post).await?;
    Ok(Replied {
        status: answer.status.as_u16(),
        body: answer.body,
    })
}

/// `GET` `url` with `token` as its bearer, through the egress/SSRF guard and
/// verified by `tls`: an OpenID Connect userinfo request.
pub async fn get_bearer(
    url: &str,
    token: &str,
    policy: &EgressPolicy,
    tls: &TlsProfile,
) -> Result<Replied, TransportError> {
    let get = |client: &reqwest::Client| {
        client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .bearer_auth(token)
    };
    let answer = fetch(url, "GET", policy, tls, &get).await?;
    Ok(Replied {
        status: answer.status.as_u16(),
        body: answer.body,
    })
}

/// What a `GET` of a URL showed of the server that answered it.
#[derive(Debug)]
pub struct Dated {
    /// The status it answered with.
    pub status: u16,
    /// The time its `Date` header gave, if it gave one that reads.
    pub date: Option<SystemTime>,
    /// When this machine sent the request.
    pub sent: SystemTime,
    /// When the head of the answer was in.
    pub received: SystemTime,
    /// The body, whatever the status.
    pub body: Vec<u8>,
}

/// `GET` a URL as [`fetch_text`] does, through the egress/SSRF guard and
/// verified by `tls`, and keep what the answer shows of the server's clock.
/// Any status comes back: a server's `Date` reads the same on a `404` as on a
/// `200`. `mcpdef doctor` compares an identity provider's clock with this
/// machine's this way.
pub async fn fetch_dated(
    url: &str,
    policy: &EgressPolicy,
    tls: &TlsProfile,
) -> Result<Dated, TransportError> {
    let get = |client: &reqwest::Client| {
        client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
    };
    let answer = fetch(url, "GET", policy, tls, &get).await?;
    Ok(Dated {
        status: answer.status.as_u16(),
        date: answer.date,
        sent: answer.sent,
        received: answer.received,
        body: answer.body,
    })
}

/// What one of the gateway's own requests got back.
pub(crate) struct Answer {
    pub(crate) status: reqwest::StatusCode,
    /// The time the `Date` header gave, if it gave one that reads.
    pub(crate) date: Option<SystemTime>,
    /// When the request went out, and when the head of the answer was in.
    pub(crate) sent: SystemTime,
    pub(crate) received: SystemTime,
    pub(crate) body: Vec<u8>,
}

/// One request of the gateway's own, such as for a JWKS or a token: through
/// the egress/SSRF guard, DNS-pinned to the addresses it validated, verified
/// by `tls`, with redirects off. `request` builds it, with `method`, on the
/// client made for it. The answer's status comes back with its body, whatever
/// the status.
///
/// It runs when the gateway starts, or while a call waits, so the WHOLE of
/// it is bounded by one deadline: DNS resolution (`egress::validate`),
/// connect, and the response read. A wedged resolver or a silent server
/// cannot hang either. The body is capped too: reqwest has no limit of its
/// own, and a huge or never-ending response would otherwise exhaust memory.
/// The cap matches the listener's inbound one.
pub(crate) async fn fetch(
    url: &str,
    method: &str,
    policy: &EgressPolicy,
    tls: &TlsProfile,
    request: &(dyn Fn(&reqwest::Client) -> reqwest::RequestBuilder + Sync),
) -> Result<Answer, TransportError> {
    const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    const MAX_BYTES: usize = 2 * 1024 * 1024;

    let work = async {
        let resolved = egress::validate(url, policy).await?;
        let pins = if resolved.is_domain {
            vec![(resolved.host.clone(), resolved.addrs.clone())]
        } else {
            Vec::new()
        };
        let client = build_client(&pins, tls)?;
        let sent = SystemTime::now();
        let resp = request(&client).send().await.map_err(http_error)?;
        let received = SystemTime::now();
        let status = resp.status();
        let date = resp
            .headers()
            .get(reqwest::header::DATE)
            .and_then(|date| date.to_str().ok())
            .and_then(|date| httpdate::parse_http_date(date).ok());
        // Sized to the answer when it says how long it is, so that a body
        // holding a token is not copied as it grows.
        let expected = resp.content_length().unwrap_or(0).min(MAX_BYTES as u64);
        let mut body: Vec<u8> = Vec::with_capacity(expected as usize);
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(http_error)?;
            if body.len() + chunk.len() > MAX_BYTES {
                return Err(TransportError::Http(format!(
                    "response body from {url} exceeds the {MAX_BYTES}-byte cap"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Answer {
            status,
            date,
            sent,
            received,
            body,
        })
    };
    match tokio::time::timeout(FETCH_TIMEOUT, work).await {
        Ok(r) => r,
        Err(_) => Err(TransportError::Http(format!(
            "{method} {url} timed out after {}s",
            FETCH_TIMEOUT.as_secs()
        ))),
    }
}

impl HttpClient {
    fn new(url: impl Into<String>, kind: HttpKind) -> Result<Self, TransportError> {
        let (inbound_tx, inbound_rx) = unbounded_channel();
        let tls = TlsProfile::default();
        let url = url.into();
        Ok(HttpClient {
            client: build_client(&[], &tls)?,
            policy: EgressPolicy::default(),
            tls,
            connect_to: None,
            origin: url.clone(),
            pins: Vec::new(),
            state: State::Init { url, kind },
            inbound_tx,
            inbound_rx,
            last_event_id: Arc::new(Mutex::new(None)),
            auth: None,
            watch: TlsWatch::new(Verification::Ca),
            params: ParamHeaders::default(),
        })
    }

    /// Streamable HTTP with automatic legacy fallback (the probe).
    pub fn streamable(url: impl Into<String>) -> Result<Self, TransportError> {
        Self::new(url, HttpKind::Auto)
    }

    /// Force the legacy `2024-11-05` HTTP+SSE bridge.
    pub fn legacy_sse(url: impl Into<String>) -> Result<Self, TransportError> {
        Self::new(url, HttpKind::Legacy)
    }

    /// Override the egress/SSRF policy for this upstream. Default is
    /// [`EgressPolicy::default`] — private/loopback allowed, HTTPS required for
    /// public hosts, cloud-metadata/link-local always blocked. Must be set
    /// before the first [`send`](Transport::send) (which resolves + pins).
    pub fn with_egress(mut self, policy: EgressPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Add `auth`'s credentials to every request this client sends upstream:
    /// each POST, and on the legacy bridge the `GET` stream too. Like the egress
    /// policy, it must be set before the first [`send`](Transport::send).
    pub fn with_auth(mut self, auth: Arc<dyn RequestAuth>) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Verify the upstream, and present to it, as `tls` says, in place of
    /// the bundled roots alone. Like the egress policy, it must be set before
    /// the first [`send`](Transport::send).
    pub fn with_tls(mut self, tls: TlsProfile) -> Result<Self, TransportError> {
        self.client = build_client(&self.pins, &tls)?;
        self.watch = TlsWatch::new(tls.verification()).presenting(tls.client_certificate());
        self.tls = tls;
        Ok(self)
    }

    /// Dial `ip` for the configured URL's host, rather than what the host
    /// resolves to, and still check the certificate against the host's name.
    /// `ip` passes the egress policy as a resolved address would. It must be
    /// set before the first [`send`](Transport::send).
    pub fn with_connect_to(mut self, ip: IpAddr) -> Self {
        self.connect_to = Some(ip);
        self
    }

    /// Validate `url` against the egress policy and DNS-pin the client to the
    /// validated addresses. Errors (SSRF block) propagate to the caller before
    /// any request is sent. Re-pinning the same host is a no-op.
    ///
    /// A URL on the configured URL's host goes to `connect_to`, when it is
    /// set: a legacy bridge's POST URL there too.
    async fn guard_and_pin(&mut self, url: &str) -> Result<(), TransportError> {
        let resolved = match self.connect_to {
            Some(ip) if same_host(url, &self.origin) => egress::validate_at(url, ip, &self.policy)?,
            _ => egress::validate(url, &self.policy).await?,
        };
        // An IP literal needs no pin (reqwest dials it directly); a domain is
        // pinned so the connect uses the exact IP we just validated.
        if resolved.is_domain && !self.pins.iter().any(|(h, _)| h == &resolved.host) {
            self.pins.push((resolved.host.clone(), resolved.addrs));
            self.client = build_client(&self.pins, &self.tls)?;
        }
        Ok(())
    }

    /// Open the legacy SSE stream, returning the POST endpoint from its first
    /// `endpoint` event. A background task keeps reading the stream (and resumes
    /// it via `Last-Event-ID`), feeding inbound messages to `recv`.
    async fn connect_legacy(&self, url: &str) -> Result<String, TransportError> {
        let (endpoint_tx, endpoint_rx) = oneshot::channel();
        tokio::spawn(legacy_sse_loop(
            self.client.clone(),
            url.to_string(),
            self.inbound_tx.clone(),
            self.last_event_id.clone(),
            Some(endpoint_tx),
            self.auth.clone(),
            self.watch.clone(),
        ));
        endpoint_rx
            .await
            .map_err(|_| TransportError::Decode("legacy SSE closed before `endpoint` event".into()))
    }

    async fn legacy_post(&self, post_url: &str, msg: &Message) -> Result<(), TransportError> {
        let body = msg.to_json_line();
        let resp = send_authorized(self.auth.as_deref(), post_url, &|mut headers| {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            self.client
                .post(post_url)
                .headers(headers)
                .body(body.clone())
        })
        .await?;
        if !resp.status().is_success() {
            return Err(TransportError::Http(format!(
                "legacy POST to {post_url} returned {}",
                resp.status()
            )));
        }
        Ok(())
    }

    /// Settle on the Streamable-HTTP binding at `endpoint`, with the client
    /// pinned for it, and the session id and revision its first reply handed
    /// out, if any.
    fn adopt(
        &self,
        endpoint: String,
        session_id: Option<String>,
        protocol_version: Option<String>,
    ) -> State {
        State::Modern(Arc::new(Streamable {
            client: self.client.clone(),
            endpoint,
            session_id: Mutex::new(session_id),
            protocol_version: Mutex::new(protocol_version),
            auth: self.auth.clone(),
            watch: self.watch.clone(),
            params: self.params.clone(),
        }))
    }
}

#[async_trait]
impl Transport for HttpClient {
    async fn send(&mut self, msg: Message) -> Result<(), TransportError> {
        // Resolve the wire format on the first send (the `initialize` request).
        if let State::Init { url, kind } = &self.state {
            let (url, kind) = (url.clone(), *kind);
            // SSRF guard: validate + DNS-pin the configured upstream before any
            // bytes go out. A blocked destination errors here, before connect.
            self.guard_and_pin(&url).await?;
            match kind {
                HttpKind::Auto => {
                    let probe = post_to(
                        &self.client,
                        &url,
                        None,
                        None,
                        self.auth.as_deref(),
                        &msg,
                        &self.watch,
                        &self.params,
                    )
                    .await?;
                    if probe.status.is_success() {
                        let protocol_version = negotiated_version(&msg, &probe.messages);
                        for m in probe.messages {
                            let _ = self.inbound_tx.send(Ok(m));
                        }
                        self.state = self.adopt(url, probe.session_id, protocol_version);
                    } else if probe.messages.iter().any(is_modern_error) {
                        // It answered with a JSON-RPC error only a modern server
                        // produces — an unsupported version, a header mismatch, a
                        // method it does not implement. That settles the
                        // *transport* question: this is a Streamable-HTTP
                        // endpoint, which simply did not like this particular
                        // request. So resolve as modern and hand the caller the
                        // reason. Failing here instead would lose it, and the
                        // caller cannot pick a supported version from a dead
                        // transport.
                        for m in probe.messages {
                            let _ = self.inbound_tx.send(Ok(m));
                        }
                        // A refusal settles no revision.
                        self.state = self.adopt(url, probe.session_id, None);
                    } else if matches!(probe.status.as_u16(), 400 | 404 | 405) {
                        // Fall back to legacy by re-POSTing `initialize` to the
                        // SSE endpoint. The assumption is that a 400/404/405 means
                        // the upstream did NOT process the probe body, so there is
                        // no double-`initialize` side effect.
                        //
                        // That was unconditionally true until 2026-07-28, and is
                        // not any more: a modern server answers an unsupported
                        // version, a header mismatch or an unknown method with
                        // exactly these statuses *and* a JSON-RPC error body —
                        // which the arm above has already claimed. What is left
                        // here is a status with no MCP body at all, which is what
                        // a 2024-11-05 server with no modern endpoint looks like.
                        let post_url = self.connect_legacy(&url).await?;
                        // The server NAMES this POST URL — it is untrusted input,
                        // a classic SSRF vector. Guard it before posting.
                        self.guard_and_pin(&post_url).await?;
                        // Record the binding *before* the POST. The binding is
                        // resolved the moment the SSE stream names an endpoint;
                        // whether this particular message posts cleanly is a
                        // separate question. Leaving the state `Init` on a failed
                        // POST meant the next `send` re-ran the whole
                        // negotiation and spawned a *second* `legacy_sse_loop`
                        // feeding the same channel — two readers, duplicated
                        // inbound messages, and a resumption id racing itself.
                        self.state = State::Legacy {
                            post_url: post_url.clone(),
                        };
                        self.legacy_post(&post_url, &msg).await?;
                    } else {
                        self.state = State::Failed;
                        return Err(TransportError::Http(format!(
                            "Streamable HTTP probe to {url} returned {}",
                            probe.status
                        )));
                    }
                }
                HttpKind::Legacy => {
                    let post_url = self.connect_legacy(&url).await?;
                    // Server-named POST URL is untrusted — guard before posting.
                    self.guard_and_pin(&post_url).await?;
                    // Before the POST, for the reason given in the `Auto` arm.
                    self.state = State::Legacy {
                        post_url: post_url.clone(),
                    };
                    self.legacy_post(&post_url, &msg).await?;
                }
            }
            return Ok(());
        }

        match &self.state {
            State::Modern(streamable) => {
                for m in streamable.post(&msg).await? {
                    let _ = self.inbound_tx.send(Ok(m));
                }
                Ok(())
            }
            State::Legacy { post_url } => self.legacy_post(post_url, &msg).await,
            State::Failed => Err(TransportError::Closed),
            State::Init { .. } => unreachable!("resolved above"),
        }
    }

    async fn recv(&mut self) -> Result<Option<Message>, TransportError> {
        match self.inbound_rx.recv().await {
            Some(Ok(m)) => Ok(Some(m)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// The Streamable-HTTP endpoint, once negotiated. The legacy bridge answers
    /// every request on one shared stream, so it has no concurrent side.
    fn concurrent(&self) -> Option<Arc<dyn Exchange>> {
        match &self.state {
            State::Modern(streamable) => Some(Arc::clone(streamable) as Arc<dyn Exchange>),
            _ => None,
        }
    }

    /// An HTTPS upstream's watch. A plain-HTTP one has no certificate to
    /// show, even when its legacy bridge names an HTTPS URL to post to.
    fn tls(&self) -> Option<TlsWatch> {
        let https = url::Url::parse(&self.origin).is_ok_and(|url| url.scheme() == "https");
        https.then(|| self.watch.clone())
    }

    fn auth(&self) -> Option<Arc<dyn RequestAuth>> {
        self.auth.clone()
    }

    /// Whichever mode it settles on: the legacy bridge sends only legacy
    /// requests, which carry no `Mcp-Param-*` headers.
    fn param_headers(&self) -> Option<ParamHeaders> {
        Some(self.params.clone())
    }
}

impl Streamable {
    /// POST one request or notification and judge the answer: the messages
    /// that came back, or why there are none.
    async fn post(&self, msg: &Message) -> Result<Vec<Message>, TransportError> {
        let session = self
            .session_id
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let protocol_version = self
            .protocol_version
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let post = post_to(
            &self.client,
            &self.endpoint,
            session.as_deref(),
            protocol_version.as_deref(),
            self.auth.as_deref(),
            msg,
            &self.watch,
            &self.params,
        )
        .await?;
        // A later `initialize` starts over, so what it settles replaces what
        // the last one did, even when that is nothing, and whatever status its
        // reply came back with: the old revision belongs to a session the new
        // one supersedes, and repeating it would claim an agreement this one
        // never made.
        if msg.method() == Some(method::INITIALIZE) {
            *self
                .protocol_version
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = negotiated_version(msg, &post.messages);
        }
        if post.status == reqwest::StatusCode::NOT_FOUND && session.is_some() {
            // The one thing a `404` on a request carrying a session means: the
            // upstream has ended that session. Every later request on it gets
            // the same, whatever body comes with it (servers often send a
            // JSON-RPC error with a null id), so it is no answer to this request.
            // Only a new `initialize` starts another session.
            return Err(TransportError::SessionExpired);
        }
        if !post.status.is_success() {
            // A modern (2026-07-28) server puts its JSON-RPC error in the body of
            // a 400 or 404 — an unsupported version, a header mismatch, a method
            // it does not implement. That error *is* the upstream's answer to this
            // request, and the client asked for it. Replacing it with a transport
            // failure loses it: the gateway can only report "gateway error" and
            // the reason the upstream stated never reaches whoever can act on it.
            if post.messages.iter().any(Message::is_response) {
                return Ok(post.messages);
            }
            return Err(TransportError::Http(format!(
                "Streamable HTTP POST to {} returned {}",
                self.endpoint, post.status
            )));
        }
        if let Some(id) = post.session_id {
            *self
                .session_id
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(id);
        }
        Ok(post.messages)
    }
}

#[async_trait]
impl Exchange for Streamable {
    async fn exchange(&self, request: &Message) -> Result<Vec<Message>, TransportError> {
        self.post(request).await
    }
}

/// POST one message to a Streamable-HTTP endpoint and parse the reply (single
/// JSON, an SSE stream, or `202`). Reads a body on an error status only when it
/// may be a modern JSON-RPC error, so the probe can tell the eras apart. The
/// certificate the reply came over, whatever its status, goes to `watch`.
///
/// An SSE stream is read as it comes. A 2025-11-25 server may send a request
/// of its own on it, such as an `elicitation/create`, and wait for the answer
/// before it goes on; that is answered at once, with a POST of its own
/// ([`answer_request`]), and returned with the rest.
#[allow(clippy::too_many_arguments)]
async fn post_to(
    client: &reqwest::Client,
    endpoint: &str,
    session_id: Option<&str>,
    protocol_version: Option<&str>,
    auth: Option<&dyn RequestAuth>,
    msg: &Message,
    watch: &TlsWatch,
    params: &ParamHeaders,
) -> Result<ModernPost, TransportError> {
    let headers = post_headers(msg, session_id, protocol_version, params)?;
    let body = msg.to_json_line();
    let resp = send_authorized(auth, endpoint, &|mut sent| {
        sent.extend(headers.clone());
        client.post(endpoint).headers(sent).body(body.clone())
    })
    .await?;
    watch.observe(&resp);

    let status = resp.status();
    let session_id_returned = resp
        .headers()
        .get("Mcp-Session-Id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let mut messages = Vec::new();
    // 2xx, and also the statuses a *modern* (2026-07-28) server uses to carry
    // a JSON-RPC error: `400` for an unsupported version or a header
    // mismatch, `404` for an unknown method. Those bodies used to be dropped,
    // which left the fallback below with nothing to read and no way to tell a
    // modern server from a 2024-11-05 one.
    let carries_body = (status.is_success() && status.as_u16() != 202)
        || matches!(status.as_u16(), 400 | 404 | 405);
    if carries_body && content_type.contains("text/event-stream") {
        // What the server asks, it asks under the session this was sent in.
        let session = session_id_returned.as_deref().or(session_id);
        let mut parser = SseParser::default();
        let mut stream = resp.bytes_stream();
        let mut ended = false;
        while !ended {
            let events = match stream.next().await {
                Some(chunk) => parser.feed(&chunk.map_err(http_error)?),
                // Flush a final unterminated event.
                None => {
                    ended = true;
                    parser.finish()
                }
            };
            for ev in events {
                let read = messages.len();
                push_message(&ev.data, &mut messages);
                for answer in messages[read..].iter().filter_map(answer_request) {
                    let headers = post_headers(&answer, session, protocol_version, params)?;
                    let body = answer.to_json_line();
                    let resp = send_authorized(auth, endpoint, &|mut sent| {
                        sent.extend(headers.clone());
                        client.post(endpoint).headers(sent).body(body.clone())
                    })
                    .await?;
                    watch.observe(&resp);
                }
            }
        }
    } else if carries_body {
        let body = resp.text().await.map_err(http_error)?;
        if status.is_success() {
            let trimmed = body.trim();
            if !trimmed.is_empty() {
                messages.push(
                    Message::from_json_line(trimmed)
                        .map_err(|e| TransportError::Decode(e.to_string()))?,
                );
            }
        } else {
            // Leniently, on an error status. A 2024-11-05 server answers a
            // POST to its SSE URL with a `404` and whatever its framework
            // felt like — Express sends the HTML string `Cannot POST /sse`.
            // Decoding that strictly returns `Err` from here and the caller
            // never reaches the legacy fallback, which breaks every
            // `transport = "streamable-http"` config pointed at such a
            // server. Only a body that really is JSON-RPC is worth keeping,
            // and `push_message` already drops the rest.
            push_message(&body, &mut messages);
        }
    }
    Ok(ModernPost {
        status,
        session_id: session_id_returned,
        messages,
    })
}

/// The headers a POST of `msg` goes with, besides `[server.auth]`'s: the
/// session and the revision it is sent under, and the 2026-07-28 mirrored
/// headers when `msg` is a modern request: the standard ones, and the
/// `Mcp-Param-{Name}` ones its tool's annotations in `params` ask for.
fn post_headers(
    msg: &Message,
    session_id: Option<&str>,
    protocol_version: Option<&str>,
    params: &ParamHeaders,
) -> Result<HeaderMap, TransportError> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/json, text/event-stream"),
    );
    if let Some(sid) = session_id {
        headers.insert(
            HeaderName::from_static("mcp-session-id"),
            header_value(sid)?,
        );
    }
    // The 2026-07-28 mirrored headers, when this message is a modern one.
    //
    // They belong to the Streamable-HTTP binding rather than to the protocol,
    // so this is the right layer for them — and they are derived from the very
    // message being sent, which means a request and its headers cannot
    // disagree by construction. An upstream MUST reject a mismatch, so
    // deriving them here rather than accepting them from a caller is what
    // keeps that impossible. `mirrored_headers` yields nothing for a legacy
    // message, so this is a no-op on the 2025-11-25 wire.
    let mirrored = mirrored_headers(msg);
    // What the 2025-11-25 wire does require: after `initialize`, every
    // request names the revision the handshake settled on, or a server that
    // cannot tell otherwise assumes 2025-03-26. Not on `initialize` itself,
    // which is what settles it, and not on a message declaring its own
    // revision in `_meta`, whose mirrored header below already says which.
    if let Some(version) = protocol_version {
        let declares_its_own = mirrored
            .iter()
            .any(|(name, _)| *name == wire::header::PROTOCOL_VERSION);
        if !declares_its_own && msg.method() != Some(method::INITIALIZE) {
            headers.insert(
                header_name(wire::header::PROTOCOL_VERSION)?,
                header_value(version)?,
            );
        }
    }
    for (name, value) in mirrored {
        headers.insert(header_name(name)?, header_value(&value)?);
    }
    // Derived here, from the message being sent, for the same reason: what
    // goes upstream is what the gateway made of the call, its argument
    // transforms included, and the headers must say what that body does.
    for (name, value) in params.values(msg) {
        headers.insert(header_name(&name)?, header_value(&value)?);
    }
    Ok(headers)
}

/// The headers `[server.auth]` adds to a request, before the transport's own.
async fn auth_headers(auth: Option<&dyn RequestAuth>) -> Result<HeaderMap, TransportError> {
    let mut headers = HeaderMap::new();
    if let Some(auth) = auth {
        auth.apply(&mut headers).await?;
    }
    Ok(headers)
}

/// Send to `url` the request `build` makes from `auth`'s headers, adding the
/// transport's own after them. If the upstream refuses it (`401`) and `auth`
/// has other credentials to give, it goes once more; a second `401`, or none
/// to give, is [`TransportError::Unauthorized`], and the request fails closed.
/// `build` is a `dyn Fn`: one copy of this serves every kind of request.
async fn send_authorized(
    auth: Option<&dyn RequestAuth>,
    url: &str,
    build: &(dyn Fn(HeaderMap) -> reqwest::RequestBuilder + Sync),
) -> Result<reqwest::Response, TransportError> {
    let sent = auth_headers(auth).await?;
    let resp = build(sent.clone()).send().await.map_err(http_error)?;
    if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
        return Ok(resp);
    }
    if let Some(auth) = auth {
        if auth.refresh(&sent).await? {
            let headers = auth_headers(Some(auth)).await?;
            let resp = build(headers).send().await.map_err(http_error)?;
            if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
                return Ok(resp);
            }
        }
    }
    Err(TransportError::Unauthorized(url.to_string()))
}

fn header_name(name: &str) -> Result<HeaderName, TransportError> {
    HeaderName::from_bytes(name.as_bytes())
        .map_err(|e| TransportError::Http(format!("header name {name:?}: {e}")))
}

fn header_value(value: &str) -> Result<HeaderValue, TransportError> {
    HeaderValue::from_str(value).map_err(|e| TransportError::Http(format!("header value: {e}")))
}

/// The revision an `initialize` settled on: the `protocolVersion` of the result
/// answering `sent`, when `sent` is an `initialize` request.
///
/// Kept only if it can go into a header as it is. A server that answered with
/// anything else has not named a revision to repeat, and a value `reqwest`
/// refuses would fail every later request rather than just the header.
fn negotiated_version(sent: &Message, replies: &[Message]) -> Option<String> {
    if sent.method() != Some(method::INITIALIZE) {
        return None;
    }
    let id = sent.id.as_ref()?;
    let reply = replies
        .iter()
        .find(|r| r.is_response() && r.id.as_ref() == Some(id))?;
    let version = reply.result.as_ref()?.get("protocolVersion")?.as_str()?;
    let header_safe = !version.is_empty() && version.bytes().all(|b| b.is_ascii_graphic());
    header_safe.then(|| version.to_string())
}

/// The legacy SSE reader: open `GET url`, emit the POST endpoint, stream inbound
/// messages, and resume with `Last-Event-ID` across a bounded number of
/// reconnects. (Production would use unbounded reconnects with backoff and
/// smarter intended-vs-unexpected close detection.) Each stream it opens
/// leaves the certificate it came over in `watch`.
async fn legacy_sse_loop(
    client: reqwest::Client,
    url: String,
    inbound: UnboundedSender<Inbound>,
    last_event_id: Arc<Mutex<Option<String>>>,
    mut endpoint_tx: Option<oneshot::Sender<String>>,
    auth: Option<Arc<dyn RequestAuth>>,
    watch: TlsWatch,
) {
    const MAX_RECONNECTS: u32 = 4;
    let mut attempts: u32 = 0;
    // The last event id we *delivered upstream* (distinct from the resume cursor
    // in `last_event_id`), used to drop a server's inclusive replay on reconnect.
    let mut last_delivered: Option<String> = None;
    loop {
        let resume = last_event_id
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("text/event-stream"));
        if let Some(id) = &resume {
            match header_value(id) {
                Ok(id) => headers.insert(HeaderName::from_static("last-event-id"), id),
                Err(e) => {
                    let _ = inbound.send(Err(e));
                    return;
                }
            };
        }
        let get = |mut sent: HeaderMap| {
            sent.extend(headers.clone());
            client.get(&url).headers(sent)
        };
        let resp = match send_authorized(auth.as_deref(), &url, &get).await {
            Ok(r) => r,
            Err(e) => {
                let _ = inbound.send(Err(e));
                return;
            }
        };
        watch.observe(&resp);
        if !resp.status().is_success() {
            let _ = inbound.send(Err(TransportError::Http(format!(
                "legacy GET {url} returned {}",
                resp.status()
            ))));
            return;
        }

        let mut stream = resp.bytes_stream();
        let mut parser = SseParser::default();
        while let Some(item) = stream.next().await {
            let bytes = match item {
                Ok(b) => b,
                Err(_) => break,
            };
            for ev in parser.feed(bytes.as_ref()) {
                if let Some(id) = &ev.id {
                    *last_event_id.lock().unwrap_or_else(PoisonError::into_inner) =
                        Some(id.clone());
                }
                if ev.event.as_deref() == Some("endpoint") {
                    let post_url = resolve_url(&url, ev.data.trim());
                    if let Some(tx) = endpoint_tx.take() {
                        let _ = tx.send(post_url);
                    }
                } else {
                    // "message" or a default event → a JSON-RPC frame. Drop a
                    // replayed event after resumption (a server redelivering an
                    // id we already handed up) so recv() never sees a duplicate.
                    if let Some(id) = &ev.id {
                        if is_stale(id, &last_delivered) {
                            continue;
                        }
                        last_delivered = Some(id.clone());
                    }
                    let mut msgs = Vec::new();
                    push_message(&ev.data, &mut msgs);
                    for m in msgs {
                        let _ = inbound.send(Ok(m));
                    }
                }
            }
        }

        // Stream ended. If we already have the endpoint, attempt a bounded
        // resumption with Last-Event-ID; otherwise surface a terminal error so
        // recv() does not block forever on a wedged or reconnect-exhausted stream
        // (the inbound channel would otherwise stay open with no further sends).
        attempts += 1;
        if endpoint_tx.is_none() && attempts < MAX_RECONNECTS {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            continue;
        }
        let _ = inbound.send(Err(TransportError::Closed));
        return;
    }
}

/// Whether `new_id` was already delivered (a resumption replay). Numeric ids
/// compare by value — the common monotonic case; otherwise by exact equality
/// with the last delivered id (catches the inclusive-replay boundary).
fn is_stale(new_id: &str, last_delivered: &Option<String>) -> bool {
    match last_delivered {
        None => false,
        Some(last) => match (new_id.parse::<u64>(), last.parse::<u64>()) {
            (Ok(n), Ok(l)) => n <= l,
            _ => new_id == last,
        },
    }
}

fn push_message(data: &str, out: &mut Vec<Message>) {
    let trimmed = data.trim();
    if trimmed.is_empty() {
        return;
    }
    if let Ok(m) = Message::from_json_line(trimmed) {
        out.push(m);
    }
}

/// Resolve an SSE `endpoint` value against the SSE URL's origin. Absolute URLs
/// pass through; an absolute path replaces the origin's path; anything else is
/// appended.
fn resolve_url(base: &str, endpoint: &str) -> String {
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        return endpoint.to_string();
    }
    if let Some(scheme_end) = base.find("://") {
        let after = &base[scheme_end + 3..];
        let origin_end = after
            .find('/')
            .map(|i| scheme_end + 3 + i)
            .unwrap_or(base.len());
        let origin = &base[..origin_end];
        if endpoint.starts_with('/') {
            return format!("{origin}{endpoint}");
        }
        return format!("{origin}/{endpoint}");
    }
    endpoint.to_string()
}

/// One parsed SSE event.
#[derive(Debug, Default, PartialEq)]
struct SseEvent {
    event: Option<String>,
    data: String,
    id: Option<String>,
}

/// An incremental SSE parser: feed byte chunks, get back complete events.
/// Line endings are normalized; events are separated by a blank line.
#[derive(Default)]
struct SseParser {
    buf: String,
}

impl SseParser {
    fn feed(&mut self, bytes: &[u8]) -> Vec<SseEvent> {
        let chunk = String::from_utf8_lossy(bytes)
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        self.buf.push_str(&chunk);

        let mut events = Vec::new();
        while let Some(pos) = self.buf.find("\n\n") {
            let raw: String = self.buf[..pos].to_string();
            self.buf.drain(..pos + 2);
            if let Some(ev) = parse_event(&raw) {
                events.push(ev);
            }
        }
        events
    }

    /// Flush any buffered, unterminated final event (a body that ends without a
    /// trailing blank line). Returns an empty vec if nothing is buffered — so,
    /// unlike feeding a synthetic `\n\n`, it never emits a spurious empty event.
    fn finish(&mut self) -> Vec<SseEvent> {
        let raw = std::mem::take(&mut self.buf);
        parse_event(&raw).into_iter().collect()
    }
}

fn parse_event(raw: &str) -> Option<SseEvent> {
    let mut ev = SseEvent::default();
    let mut has_field = false;
    for line in raw.split('\n') {
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        has_field = true;
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };
        match field {
            "event" => ev.event = Some(value.to_string()),
            "data" => {
                if !ev.data.is_empty() {
                    ev.data.push('\n');
                }
                ev.data.push_str(value);
            }
            "id" => ev.id = Some(value.to_string()),
            _ => {}
        }
    }
    has_field.then_some(ev)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_parser_splits_events_across_chunks() {
        let mut p = SseParser::default();
        // event split across two feeds
        let mut evs = p.feed(b"event: endpoint\ndata: /mes");
        assert!(evs.is_empty());
        evs = p.feed(b"sages\n\nevent: message\ndata: {\"x\":1}\n\n");
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].event.as_deref(), Some("endpoint"));
        assert_eq!(evs[0].data, "/messages");
        assert_eq!(evs[1].event.as_deref(), Some("message"));
        assert_eq!(evs[1].data, "{\"x\":1}");
    }

    #[test]
    fn sse_parser_handles_crlf_id_and_multiline_data() {
        let mut p = SseParser::default();
        let evs = p.feed(b"id: 7\r\ndata: a\r\ndata: b\r\n\r\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].id.as_deref(), Some("7"));
        assert_eq!(evs[0].data, "a\nb");
    }

    #[test]
    fn resolve_url_forms() {
        assert_eq!(
            resolve_url("http://h:9/sse", "/messages?s=1"),
            "http://h:9/messages?s=1"
        );
        assert_eq!(
            resolve_url("http://h:9/sse", "http://other/x"),
            "http://other/x"
        );
        assert_eq!(resolve_url("http://h:9/sse", "rel"), "http://h:9/rel");
    }

    #[test]
    fn sse_parser_finish_flushes_unterminated_event_without_spurious_empties() {
        let mut p = SseParser::default();
        // No trailing blank line, so feed() yields nothing yet.
        assert!(p.feed(b"event: message\ndata: {\"a\":1}").is_empty());
        let evs = p.finish();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "{\"a\":1}");
        // finish() on an empty buffer must NOT emit a spurious empty event.
        assert!(p.finish().is_empty());
    }

    #[test]
    fn is_stale_dedups_numeric_and_exact_ids() {
        assert!(!is_stale("1", &None));
        assert!(is_stale("1", &Some("1".into()))); // inclusive replay of last id
        assert!(is_stale("1", &Some("2".into()))); // older numeric id
        assert!(!is_stale("3", &Some("2".into()))); // newer numeric id passes
        assert!(is_stale("abc", &Some("abc".into()))); // non-numeric exact match
        assert!(!is_stale("abc", &Some("xyz".into())));
    }

    #[test]
    fn negotiated_version_is_the_servers_answer_to_our_initialize() {
        use mcpdef_core::Id;
        let init = Message::request(Id::Num(0), method::INITIALIZE, None);
        let answer = |id, version: serde_json::Value| {
            Message::result(id, serde_json::json!({ "protocolVersion": version }))
        };

        // The server's answer, even where it differs from what was asked for.
        assert_eq!(
            negotiated_version(&init, &[answer(Id::Num(0), "2025-06-18".into())]),
            Some("2025-06-18".to_string())
        );
        // Only the reply to *this* `initialize` counts, and only a reply: a
        // server request that happens to share its id is not an answer.
        assert_eq!(
            negotiated_version(&init, &[answer(Id::Num(7), "2025-06-18".into())]),
            None
        );
        let server_request = Message::request(Id::Num(0), "sampling/createMessage", None);
        assert_eq!(
            negotiated_version(
                &init,
                &[server_request, answer(Id::Num(0), "2025-06-18".into())]
            ),
            Some("2025-06-18".to_string())
        );
        // A refused `initialize` settles nothing.
        let refused = Message::error(Id::Num(0), -32601, "no such method");
        assert_eq!(negotiated_version(&init, &[refused]), None);
        // Nor does a reply to anything but `initialize`.
        let list = Message::request(Id::Num(0), method::TOOLS_LIST, None);
        assert_eq!(
            negotiated_version(&list, &[answer(Id::Num(0), "2025-06-18".into())]),
            None
        );
        // A value that cannot go into a header is not a revision to repeat.
        for bad in ["", "2025-06-18\r\nX-Injected: 1", "2025 06 18"] {
            assert_eq!(
                negotiated_version(&init, &[answer(Id::Num(0), bad.into())]),
                None,
                "{bad:?}"
            );
        }
        assert_eq!(
            negotiated_version(&init, &[answer(Id::Num(0), 20250618.into())]),
            None
        );
    }
}
