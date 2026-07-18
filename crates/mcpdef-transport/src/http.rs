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
//!   later request.
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

use crate::egress::{self, EgressPolicy};
use crate::{Transport, TransportError};
use async_trait::async_trait;
use futures_util::StreamExt;
use mcpdef_core::Message;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
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

enum State {
    /// Not yet resolved; the first `send` (the `initialize`) decides the mode.
    Init {
        url: String,
        kind: HttpKind,
    },
    Modern {
        endpoint: String,
        session_id: Option<String>,
    },
    Legacy {
        post_url: String,
    },
    Failed,
}

/// An MCP upstream reached over HTTP — Streamable HTTP or the legacy HTTP+SSE
/// bridge. Inbound messages from either mode funnel through one channel that
/// [`recv`](Transport::recv) drains.
pub struct HttpClient {
    client: reqwest::Client,
    /// The egress/SSRF policy enforced before dialing any host.
    policy: EgressPolicy,
    /// DNS pins (host → validated addrs) baked into `client`. The egress guard
    /// resolves a host once and pins the connection to exactly those IPs, so
    /// reqwest cannot re-resolve to a rebind target between check and connect.
    pins: Vec<(String, Vec<SocketAddr>)>,
    state: State,
    inbound_tx: UnboundedSender<Inbound>,
    inbound_rx: UnboundedReceiver<Inbound>,
    last_event_id: Arc<Mutex<Option<String>>>,
}

struct ModernPost {
    status: reqwest::StatusCode,
    session_id: Option<String>,
    messages: Vec<Message>,
}

/// Build a reqwest client with the given DNS pins.
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
fn build_pinned_client(
    pins: &[(String, Vec<SocketAddr>)],
) -> Result<reqwest::Client, TransportError> {
    let mut b = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none());
    for (host, addrs) in pins {
        if !addrs.is_empty() {
            b = b.resolve_to_addrs(host, addrs);
        }
    }
    b.build().map_err(|e| TransportError::Http(e.to_string()))
}

/// `GET` a URL's body as text **through the egress/SSRF guard** (cloud-metadata
/// always blocked, DNS-pinned to the validated IPs). The one-shot fetch the
/// binary uses to retrieve an OAuth `jwks_uri` at startup, so a JWKS URL is
/// subject to the same SSRF defenses as an MCP upstream.
pub async fn fetch_text(url: &str, policy: &EgressPolicy) -> Result<String, TransportError> {
    // One-shot startup fetch (a JWKS): bound the WHOLE operation — DNS resolution
    // (`egress::validate`), connect, and the response read — under one deadline so
    // a wedged resolver or a silent server can't hang process startup. Scoped here
    // so the long-lived SSE client is unaffected.
    const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    // Cap the buffered body so a huge / never-ending response can't exhaust memory
    // at startup (reqwest has no built-in body limit; `resp.text()` would buffer
    // the lot). Matches the listener's inbound cap.
    const MAX_BYTES: usize = 2 * 1024 * 1024;

    let work = async {
        let resolved = egress::validate(url, policy).await?;
        let pins = if resolved.is_domain {
            vec![(resolved.host.clone(), resolved.addrs.clone())]
        } else {
            Vec::new()
        };
        let client = build_pinned_client(&pins)?;
        let resp = client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(TransportError::Http(format!(
                "GET {url} returned {}",
                resp.status()
            )));
        }
        let mut body: Vec<u8> = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| TransportError::Http(e.to_string()))?;
            if body.len() + chunk.len() > MAX_BYTES {
                return Err(TransportError::Http(format!(
                    "response body from {url} exceeds the {MAX_BYTES}-byte cap"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        String::from_utf8(body).map_err(|e| TransportError::Http(e.to_string()))
    };
    match tokio::time::timeout(FETCH_TIMEOUT, work).await {
        Ok(r) => r,
        Err(_) => Err(TransportError::Http(format!(
            "GET {url} timed out after {}s",
            FETCH_TIMEOUT.as_secs()
        ))),
    }
}

impl HttpClient {
    fn new(url: impl Into<String>, kind: HttpKind) -> Result<Self, TransportError> {
        let (inbound_tx, inbound_rx) = unbounded_channel();
        Ok(HttpClient {
            client: build_pinned_client(&[])?,
            policy: EgressPolicy::default(),
            pins: Vec::new(),
            state: State::Init {
                url: url.into(),
                kind,
            },
            inbound_tx,
            inbound_rx,
            last_event_id: Arc::new(Mutex::new(None)),
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

    /// Validate `url` against the egress policy and DNS-pin the client to the
    /// validated addresses. Errors (SSRF block) propagate to the caller before
    /// any request is sent. Re-pinning the same host is a no-op.
    async fn guard_and_pin(&mut self, url: &str) -> Result<(), TransportError> {
        let resolved = egress::validate(url, &self.policy).await?;
        // An IP literal needs no pin (reqwest dials it directly); a domain is
        // pinned so the connect uses the exact IP we just validated.
        if resolved.is_domain && !self.pins.iter().any(|(h, _)| h == &resolved.host) {
            self.pins.push((resolved.host.clone(), resolved.addrs));
            self.client = build_pinned_client(&self.pins)?;
        }
        Ok(())
    }

    /// POST one message in Streamable HTTP mode and parse the reply (single
    /// JSON, an SSE batch, or `202`). Does not read the body on a non-success
    /// status, so the caller can use it as the fallback probe.
    async fn modern_post(
        &self,
        endpoint: &str,
        session_id: Option<&str>,
        msg: &Message,
    ) -> Result<ModernPost, TransportError> {
        let mut rb = self
            .client
            .post(endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(
                reqwest::header::ACCEPT,
                "application/json, text/event-stream",
            );
        if let Some(sid) = session_id {
            rb = rb.header("Mcp-Session-Id", sid);
        }
        let resp = rb
            .body(msg.to_json_line())
            .send()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;

        let status = resp.status();
        let session_id = resp
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
        if status.is_success() && status.as_u16() != 202 {
            let body = resp
                .text()
                .await
                .map_err(|e| TransportError::Http(e.to_string()))?;
            if content_type.contains("text/event-stream") {
                let mut parser = SseParser::default();
                let mut events = parser.feed(body.as_bytes());
                events.extend(parser.finish()); // flush a final unterminated event
                for ev in events {
                    push_message(&ev.data, &mut messages);
                }
            } else {
                let trimmed = body.trim();
                if !trimmed.is_empty() {
                    messages.push(
                        Message::from_json_line(trimmed)
                            .map_err(|e| TransportError::Decode(e.to_string()))?,
                    );
                }
            }
        }
        Ok(ModernPost {
            status,
            session_id,
            messages,
        })
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
        ));
        endpoint_rx
            .await
            .map_err(|_| TransportError::Decode("legacy SSE closed before `endpoint` event".into()))
    }

    async fn legacy_post(&self, post_url: &str, msg: &Message) -> Result<(), TransportError> {
        let resp = self
            .client
            .post(post_url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(msg.to_json_line())
            .send()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(TransportError::Http(format!(
                "legacy POST to {post_url} returned {}",
                resp.status()
            )));
        }
        Ok(())
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
                    let probe = self.modern_post(&url, None, &msg).await?;
                    if probe.status.is_success() {
                        for m in probe.messages {
                            let _ = self.inbound_tx.send(Ok(m));
                        }
                        self.state = State::Modern {
                            endpoint: url,
                            session_id: probe.session_id,
                        };
                    } else if matches!(probe.status.as_u16(), 400 | 404 | 405) {
                        // Fall back to legacy by re-POSTing `initialize` to the
                        // SSE endpoint. This assumes a 400/404/405 means the
                        // upstream did NOT process the probe body (true for these
                        // statuses: bad-request / no-such-route / method-not-
                        // allowed) — so no double-`initialize` side effect.
                        let post_url = self.connect_legacy(&url).await?;
                        // The server NAMES this POST URL — it is untrusted input,
                        // a classic SSRF vector. Guard it before posting.
                        self.guard_and_pin(&post_url).await?;
                        self.legacy_post(&post_url, &msg).await?;
                        self.state = State::Legacy { post_url };
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
                    self.legacy_post(&post_url, &msg).await?;
                    self.state = State::Legacy { post_url };
                }
            }
            return Ok(());
        }

        // Resolved.
        let resolved = match &self.state {
            State::Modern {
                endpoint,
                session_id,
            } => Resolved::Modern(endpoint.clone(), session_id.clone()),
            State::Legacy { post_url } => Resolved::Legacy(post_url.clone()),
            State::Failed => return Err(TransportError::Closed),
            State::Init { .. } => unreachable!("resolved above"),
        };
        match resolved {
            Resolved::Modern(endpoint, session_id) => {
                let post = self
                    .modern_post(&endpoint, session_id.as_deref(), &msg)
                    .await?;
                if !post.status.is_success() {
                    return Err(TransportError::Http(format!(
                        "Streamable HTTP POST to {endpoint} returned {}",
                        post.status
                    )));
                }
                if post.session_id.is_some() {
                    if let State::Modern { session_id, .. } = &mut self.state {
                        *session_id = post.session_id;
                    }
                }
                for m in post.messages {
                    let _ = self.inbound_tx.send(Ok(m));
                }
                Ok(())
            }
            Resolved::Legacy(post_url) => self.legacy_post(&post_url, &msg).await,
        }
    }

    async fn recv(&mut self) -> Result<Option<Message>, TransportError> {
        match self.inbound_rx.recv().await {
            Some(Ok(m)) => Ok(Some(m)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }
}

enum Resolved {
    Modern(String, Option<String>),
    Legacy(String),
}

/// The legacy SSE reader: open `GET url`, emit the POST endpoint, stream inbound
/// messages, and resume with `Last-Event-ID` across a bounded number of
/// reconnects. (Production would use unbounded reconnects with backoff and
/// smarter intended-vs-unexpected close detection.)
async fn legacy_sse_loop(
    client: reqwest::Client,
    url: String,
    inbound: UnboundedSender<Inbound>,
    last_event_id: Arc<Mutex<Option<String>>>,
    mut endpoint_tx: Option<oneshot::Sender<String>>,
) {
    const MAX_RECONNECTS: u32 = 4;
    let mut attempts: u32 = 0;
    // The last event id we *delivered upstream* (distinct from the resume cursor
    // in `last_event_id`), used to drop a server's inclusive replay on reconnect.
    let mut last_delivered: Option<String> = None;
    loop {
        let mut rb = client
            .get(&url)
            .header(reqwest::header::ACCEPT, "text/event-stream");
        let resume = last_event_id.lock().unwrap().clone();
        if let Some(id) = &resume {
            rb = rb.header("Last-Event-ID", id.clone());
        }

        let resp = match rb.send().await {
            Ok(r) => r,
            Err(e) => {
                let _ = inbound.send(Err(TransportError::Http(e.to_string())));
                return;
            }
        };
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
                    *last_event_id.lock().unwrap() = Some(id.clone());
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
}
