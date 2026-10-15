// SPDX-License-Identifier: Apache-2.0
//! An MCP server over HTTPS, for the gateway to dial as an upstream: the
//! Streamable HTTP transport on a TLS listener of its own, which can require a
//! client certificate.
//!
//! It answers like the plain-HTTP mocks in the gateway's tests: `initialize`
//! (with a session id), `202` for a notification, the `echo` and
//! `delete_repo` tools, `ping`, and `-32601` for anything else. It records
//! what a test asks about afterwards: the client certificates it accepted,
//! the handshakes it refused and why, and the methods it was sent.

use crate::pki::{Crl, Leaf, Pki};
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::ServerConfig;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// How long a client has to finish its handshake before it is dropped, so
/// that one which stalls holds up nothing.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// The upstream's crypto provider, named rather than taken from the process,
/// so that the upstream works whatever a test has installed.
fn ring() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[derive(Default)]
struct Seen {
    client_certificates: Mutex<Vec<CertificateDer<'static>>>,
    refusals: Mutex<Vec<String>>,
    methods: Mutex<Vec<String>>,
    protocols: Mutex<Vec<Option<String>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// An MCP upstream on HTTPS, on a loopback port, until it is dropped.
pub struct HttpsUpstream {
    addr: SocketAddr,
    seen: Arc<Seen>,
    accepting: tokio::task::JoinHandle<()>,
}

/// A configuration that serves `server`'s certificate and asks clients for
/// none.
fn plain(server: &Leaf) -> ServerConfig {
    ServerConfig::builder_with_provider(ring())
        .with_safe_default_protocol_versions()
        .expect("TLS 1.2 and 1.3")
        .with_no_client_auth()
        .with_single_cert(server.chain(), server.key_der())
        .expect("the server's certificate and key")
}

/// A configuration that serves `server`'s certificate and requires of every
/// client a certificate that chains to `clients`' root and that none of
/// `crls` revokes.
fn mtls(server: &Leaf, clients: &Pki, crls: &[&Crl]) -> ServerConfig {
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(clients.roots()), ring())
        .with_crls(crls.iter().map(|crl| crl.der().clone()))
        .only_check_end_entity_revocation()
        .build()
        .expect("a client-certificate verifier");
    ServerConfig::builder_with_provider(ring())
        .with_safe_default_protocol_versions()
        .expect("TLS 1.2 and 1.3")
        .with_client_cert_verifier(verifier)
        .with_single_cert(server.chain(), server.key_der())
        .expect("the server's certificate and key")
}

impl HttpsUpstream {
    /// Serve with `server`'s certificate, asking clients for none.
    pub async fn start(server: &Leaf) -> Self {
        Self::serve(plain(server)).await
    }

    /// Serve `app` in place of the MCP mock, with `server`'s certificate and
    /// no client certificate asked for: an identity provider's JWKS, say.
    /// Handshakes are recorded as for the mock; `methods()` stays empty.
    pub async fn start_app(server: &Leaf, app: Router) -> Self {
        Self::listen(plain(server), app, Arc::new(Seen::default())).await
    }

    /// Serve with `server`'s certificate, and require of every client a
    /// certificate that chains to `clients`' root and that none of `crls`
    /// revokes. Revocation is checked for the client's own certificate, so
    /// `crls` are from the CA that issued it; a test that wants the whole
    /// chain checked builds its own configuration and calls [`serve`].
    ///
    /// [`serve`]: HttpsUpstream::serve
    pub async fn start_mtls(server: &Leaf, clients: &Pki, crls: &[&Crl]) -> Self {
        Self::serve(mtls(server, clients, crls)).await
    }

    /// Serve `app` in place of the MCP mock, requiring a client certificate
    /// as [`start_mtls`] does: an upstream that checks more than the
    /// certificate, a bearer token say. Handshakes are recorded as for the
    /// mock; `methods()` stays empty.
    ///
    /// [`start_mtls`]: HttpsUpstream::start_mtls
    pub async fn start_mtls_app(server: &Leaf, clients: &Pki, crls: &[&Crl], app: Router) -> Self {
        Self::listen(mtls(server, clients, crls), app, Arc::new(Seen::default())).await
    }

    /// Serve with `config`, however a test has built it. With no ALPN set,
    /// it offers HTTP/1.1.
    pub async fn serve(config: ServerConfig) -> Self {
        let seen = Arc::new(Seen::default());
        let app = Router::new()
            .route(
                "/mcp",
                post(mcp).get(|| async { StatusCode::METHOD_NOT_ALLOWED }),
            )
            .with_state(Arc::clone(&seen));
        Self::listen(config, app, seen).await
    }

    /// Serve `app` with `config`, however a test has built both: say, a
    /// certificate that changes between connections, and an app that closes
    /// each one after answering. Handshakes are recorded as for the mock;
    /// `methods()` stays empty.
    pub async fn serve_app(config: ServerConfig, app: Router) -> Self {
        Self::listen(config, app, Arc::new(Seen::default())).await
    }

    async fn listen(mut config: ServerConfig, app: Router, seen: Arc<Seen>) -> Self {
        if config.alpn_protocols.is_empty() {
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let addr = listener.local_addr().expect("the port bound");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let accepting = tokio::spawn(accept(listener, acceptor, app, Arc::clone(&seen)));
        HttpsUpstream {
            addr,
            seen,
            accepting,
        }
    }

    /// The MCP endpoint, at the loopback address.
    pub fn url(&self) -> String {
        format!("https://127.0.0.1:{}/mcp", self.addr.port())
    }

    /// The MCP endpoint under `host`, a name the server's certificate
    /// carries, for a client told to dial the loopback address for it.
    pub fn url_for(&self, host: &str) -> String {
        format!("https://{host}:{}/mcp", self.addr.port())
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The certificate each client presented, for every handshake that
    /// completed with one, in order.
    pub fn client_certificates(&self) -> Vec<CertificateDer<'static>> {
        lock(&self.seen.client_certificates).clone()
    }

    /// Why each refused handshake failed, as rustls put it, in order.
    pub fn refusals(&self) -> Vec<String> {
        lock(&self.seen.refusals).clone()
    }

    /// The method of each JSON-RPC message received, in order.
    pub fn methods(&self) -> Vec<String> {
        lock(&self.seen.methods).clone()
    }

    /// The application protocol each completed handshake settled on through
    /// ALPN, in order: `None` where the client offered none.
    pub fn protocols(&self) -> Vec<Option<String>> {
        lock(&self.seen.protocols).clone()
    }
}

impl Drop for HttpsUpstream {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

/// Accept connections until dropped: each gets a task of its own for its
/// handshake, and then for its requests.
async fn accept(listener: TcpListener, acceptor: TlsAcceptor, app: Router, seen: Arc<Seen>) {
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        };
        let (acceptor, app, seen) = (acceptor.clone(), app.clone(), Arc::clone(&seen));
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => {
                    lock(&seen.refusals).push(e.to_string());
                    return;
                }
                Err(_) => {
                    lock(&seen.refusals).push("the handshake timed out".to_string());
                    return;
                }
            };
            let session = tls.get_ref().1;
            if let Some(leaf) = session.peer_certificates().and_then(|c| c.first()) {
                lock(&seen.client_certificates).push(leaf.clone().into_owned());
            }
            let protocol = session
                .alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).into_owned());
            lock(&seen.protocols).push(protocol);
            let service = TowerToHyperService::new(app);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .await;
        });
    }
}

async fn mcp(State(seen): State<Arc<Seen>>, body: String) -> Response {
    let Ok(message) = serde_json::from_str::<Value>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let method = message["method"].as_str().unwrap_or_default().to_string();
    lock(&seen.methods).push(method.clone());
    // A notification: no id, no answer.
    let Some(id) = message.get("id").cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };
    let result = match method.as_str() {
        "initialize" => json!({
            "protocolVersion": "2025-11-25",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "mcpdef-testkit", "version": "0" }
        }),
        "tools/list" => json!({ "tools": [
            { "name": "echo", "description": "echo arguments back", "inputSchema": { "type": "object" } },
            { "name": "delete_repo", "description": "destructive", "inputSchema": { "type": "object" } }
        ]}),
        "tools/call" => {
            let name = message["params"]["name"].as_str().unwrap_or_default();
            let text = format!("{name}:{}", message["params"]["arguments"]);
            json!({ "content": [{ "type": "text", "text": text }], "isError": false })
        }
        "ping" => json!({}),
        _ => {
            let error = json!({ "code": -32601, "message": "method not found" });
            return reply(json!({ "jsonrpc": "2.0", "id": id, "error": error }), false);
        }
    };
    let initialize = method == "initialize";
    reply(
        json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        initialize,
    )
}

fn reply(message: Value, with_session: bool) -> Response {
    let mut response = (
        [(header::CONTENT_TYPE, "application/json")],
        message.to_string(),
    )
        .into_response();
    if with_session {
        let session = HeaderValue::from_static("mcpdef-testkit-session");
        response.headers_mut().insert("mcp-session-id", session);
    }
    response
}
