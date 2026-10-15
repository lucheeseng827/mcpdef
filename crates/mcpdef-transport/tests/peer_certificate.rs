// SPDX-License-Identifier: Apache-2.0
//! The certificate an HTTPS upstream presents, as its transport keeps it for
//! the gateway to report: which one it is, when it expires, and how it was
//! verified. A plain-HTTP upstream has none to show.

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use futures_util::{stream, Stream, StreamExt};
use mcpdef_core::{Id, Message};
use mcpdef_testkit::{HttpsUpstream, Leaf, Pki};
use mcpdef_transport::{HttpClient, Pin, TlsSettings, Transport, Verification};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

fn initialize() -> Message {
    Message::request(Id::Num(1), "initialize", Some(serde_json::json!({})))
}

/// The SHA-256 of `leaf`'s certificate, worked out here rather than by the
/// code under test.
fn fingerprint(leaf: &Leaf) -> String {
    Sha256::digest(leaf.cert_der())
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A profile that trusts `pki`'s root.
fn trusting(pki: &Pki, dir: &Path) -> TlsSettings {
    TlsSettings {
        ca: vec![pki.write_root(dir, "ca")],
        ..TlsSettings::default()
    }
}

fn client(url: &str, tls: &TlsSettings) -> HttpClient {
    HttpClient::streamable(url)
        .unwrap()
        .with_tls(tls.load().unwrap())
        .unwrap()
}

/// An MCP endpoint that answers every request with an empty result. With
/// `close`, each answer closes its connection, so the next request makes
/// another.
fn answering(close: bool) -> Router {
    let answer = move |body: String| async move {
        let request: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        let reply = serde_json::json!({ "jsonrpc": "2.0", "id": request["id"], "result": {} });
        let mut response = (
            [(header::CONTENT_TYPE, "application/json")],
            reply.to_string(),
        )
            .into_response();
        if close {
            let close = header::HeaderValue::from_static("close");
            response.headers_mut().insert(header::CONNECTION, close);
        }
        response
    };
    Router::new().route("/mcp", post(answer))
}

#[tokio::test]
async fn an_https_upstream_shows_the_certificate_it_presented() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let leaf = pki
        .leaf()
        .name("127.0.0.1")
        .server_auth()
        .valid((2020, 1, 1), (2031, 2, 3))
        .issue();
    let upstream = HttpsUpstream::start(&leaf).await;
    let mut client = client(&upstream.url(), &trusting(&pki, dir.path()));

    let watch = client.tls().expect("an HTTPS upstream has a watch");
    assert_eq!(watch.verification(), Verification::Ca);
    assert_eq!(
        watch.certificate(),
        None,
        "nothing is seen before connecting"
    );

    client.send(initialize()).await.unwrap();
    let seen = watch.certificate().expect("the certificate it presented");
    assert_eq!(seen.fingerprint, fingerprint(&leaf));
    assert_eq!(seen.not_after, Some(1_927_843_200));
    assert_eq!(
        seen.not_after_rfc3339().as_deref(),
        Some("2031-02-03T00:00:00Z")
    );
    // Every watch the transport hands out is the one it keeps.
    assert_eq!(client.tls().unwrap().certificate(), Some(seen));
}

#[tokio::test]
async fn a_plain_http_upstream_has_no_certificate_to_show() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, answering(false)).await });
    let mut client = HttpClient::streamable(format!("http://{addr}/mcp")).unwrap();
    assert!(client.tls().is_none());
    client.send(initialize()).await.unwrap();
    assert!(client.tls().is_none());
}

/// A watch says how the certificate it shows was checked: by a CA, by a pin,
/// or not at all. One that was not checked is shown all the same.
#[tokio::test]
async fn the_watch_says_how_the_upstream_was_verified() {
    let leaf = Leaf::self_signed(&["127.0.0.1"]);
    let upstream = HttpsUpstream::start(&leaf).await;

    let pinned = TlsSettings {
        pin_sha256: vec![Pin::of(leaf.cert_der()).unwrap().to_string()],
        ..TlsSettings::default()
    };
    let unverified = TlsSettings {
        insecure_skip_verify: true,
        ..TlsSettings::default()
    };
    for (tls, verification) in [
        (pinned, Verification::Pin),
        (unverified, Verification::Disabled),
    ] {
        let mut client = client(&upstream.url(), &tls);
        client.send(initialize()).await.unwrap();
        let watch = client.tls().unwrap();
        assert_eq!(watch.verification(), verification);
        assert_eq!(
            watch.certificate().map(|seen| seen.fingerprint),
            Some(fingerprint(&leaf)),
            "{verification:?}"
        );
    }

    // By the bundled roots, which do not vouch for it: no response came, so
    // there is nothing to show.
    let mut client = HttpClient::streamable(upstream.url()).unwrap();
    assert!(client.send(initialize()).await.is_err());
    let watch = client.tls().unwrap();
    assert_eq!(watch.verification(), Verification::Ca);
    assert_eq!(watch.certificate(), None);
}

/// Presents whichever certificate it holds now: a server whose certificate
/// is renewed in place.
#[derive(Debug)]
struct Renewable(Mutex<Arc<CertifiedKey>>);

impl ResolvesServerCert for Renewable {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0.lock().unwrap()))
    }
}

fn certified(leaf: &Leaf) -> Arc<CertifiedKey> {
    let key = rustls::crypto::ring::default_provider()
        .key_provider
        .load_private_key(leaf.key_der())
        .unwrap();
    Arc::new(CertifiedKey::new(leaf.chain(), key))
}

/// Every response is looked at, on the side that takes concurrent calls as
/// well, so a certificate renewed on the server shows as soon as a new
/// connection meets it.
///
/// A new connection, that is, with a full handshake. One that resumes an
/// earlier TLS session is vouched for by the certificate that session began
/// with, and the server presents none: the session's is what shows. This
/// server resumes none.
#[tokio::test]
async fn a_renewed_certificate_shows_once_a_new_connection_meets_it() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let (first, renewed) = (pki.server(&["127.0.0.1"]), pki.server(&["127.0.0.1"]));
    let current = Arc::new(Renewable(Mutex::new(certified(&first))));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_cert_resolver(Arc::clone(&current) as Arc<dyn ResolvesServerCert>);
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    let upstream = HttpsUpstream::serve_app(config, answering(true)).await;

    let mut client = client(&upstream.url(), &trusting(&pki, dir.path()));
    client.send(initialize()).await.unwrap();
    let watch = client.tls().unwrap();
    assert_eq!(
        watch.certificate().unwrap().fingerprint,
        fingerprint(&first)
    );

    let exchange = client.concurrent().expect("a Streamable-HTTP endpoint");
    *current.0.lock().unwrap() = certified(&renewed);
    let ping = Message::request(Id::Num(2), "ping", None);
    exchange.exchange(&ping).await.unwrap();
    assert_eq!(upstream.protocols().len(), 2, "a second connection");
    assert_eq!(
        watch.certificate().unwrap().fingerprint,
        fingerprint(&renewed)
    );
}

/// A legacy HTTP+SSE endpoint: `GET /sse` names `/messages` and then carries
/// every answer, and a POST there is answered on the stream.
fn legacy() -> Router {
    let (answers, _) = broadcast::channel::<String>(16);
    async fn events(
        State(answers): State<broadcast::Sender<String>>,
    ) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
        let endpoint =
            stream::once(async { Ok(Event::default().event("endpoint").data("/messages")) });
        let messages = BroadcastStream::new(answers.subscribe()).map(|answer| {
            Ok(Event::default()
                .event("message")
                .data(answer.unwrap_or_default()))
        });
        Sse::new(endpoint.chain(messages))
    }
    async fn messages(State(answers): State<broadcast::Sender<String>>, body: String) -> Response {
        let request: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        let reply = serde_json::json!({ "jsonrpc": "2.0", "id": request["id"], "result": {} });
        let _ = answers.send(reply.to_string());
        StatusCode::ACCEPTED.into_response()
    }
    Router::new()
        .route("/sse", get(events))
        .route("/messages", post(messages))
        .with_state(answers)
}

#[tokio::test]
async fn a_legacy_bridge_shows_the_certificate_its_stream_came_over() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let leaf = pki.server(&["127.0.0.1"]);
    let upstream = HttpsUpstream::start_app(&leaf, legacy()).await;
    let url = format!("https://127.0.0.1:{}/sse", upstream.addr().port());
    let tls = trusting(&pki, dir.path());
    let mut client = HttpClient::legacy_sse(url)
        .unwrap()
        .with_tls(tls.load().unwrap())
        .unwrap();

    client.send(initialize()).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), client.recv())
        .await
        .expect("an answer on the stream")
        .unwrap()
        .unwrap();
    assert_eq!(reply.id, Some(Id::Num(1)));
    let watch = client.tls().unwrap();
    assert_eq!(watch.verification(), Verification::Ca);
    assert_eq!(watch.certificate().unwrap().fingerprint, fingerprint(&leaf));
}
