// SPDX-License-Identifier: Apache-2.0
//! A bearer token by the client credentials grant ([`TokenAuth`]): the request
//! a token endpoint is sent, one fetch however many requests need a token at
//! once, a token fetched again when it expires or is refused, and a failure
//! to get one that fails the request closed, sending nothing.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use mcpdef_core::{Id, Message};
use mcpdef_secrets::{SecretRef, SecretString};
use mcpdef_testkit::{HttpsUpstream, Pki};
use mcpdef_transport::{
    CallError, ClientAuth, ClientCredentials, EgressPolicy, HttpClient, RequestAuth, TlsSettings,
    TokenAuth, Transport, TransportError, UpstreamHandle,
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ── A token endpoint that issues `tok-1`, `tok-2`, … or fails as a test says.

/// A token request, as the endpoint was sent it.
#[derive(Debug, Clone)]
struct Asked {
    authorization: Option<String>,
    content_type: String,
    accept: String,
    form: Vec<(String, String)>,
}

impl Asked {
    fn field(&self, name: &str) -> Option<&str> {
        self.form
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Clone)]
enum Answer {
    /// A new token, and these fields beside it.
    Token(Value),
    /// This status and body, as they are.
    Exactly(StatusCode, Value),
}

struct Issuer {
    asked: Mutex<Vec<Asked>>,
    answer: Mutex<Answer>,
    issued: Mutex<usize>,
    /// How long it takes to answer.
    delay: Mutex<Duration>,
}

impl Issuer {
    fn new() -> Arc<Self> {
        Arc::new(Issuer {
            asked: Mutex::new(Vec::new()),
            answer: Mutex::new(Answer::Token(
                json!({ "token_type": "Bearer", "expires_in": 3600 }),
            )),
            issued: Mutex::new(0),
            delay: Mutex::new(Duration::ZERO),
        })
    }

    /// Issue tokens with these fields beside them.
    fn issues(&self, fields: Value) {
        *self.answer.lock().unwrap() = Answer::Token(fields);
    }

    fn answers(&self, status: StatusCode, body: Value) {
        *self.answer.lock().unwrap() = Answer::Exactly(status, body);
    }

    /// The requests since the last look.
    fn asked(&self) -> Vec<Asked> {
        std::mem::take(&mut *self.asked.lock().unwrap())
    }
}

async fn token_endpoint(
    State(issuer): State<Arc<Issuer>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let text = |name| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    issuer.asked.lock().unwrap().push(Asked {
        authorization: text(header::AUTHORIZATION),
        content_type: text(header::CONTENT_TYPE).unwrap_or_default(),
        accept: text(header::ACCEPT).unwrap_or_default(),
        form: url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect(),
    });
    let delay = *issuer.delay.lock().unwrap();
    tokio::time::sleep(delay).await;
    let answer = issuer.answer.lock().unwrap().clone();
    match answer {
        Answer::Token(mut fields) => {
            let n = {
                let mut issued = issuer.issued.lock().unwrap();
                *issued += 1;
                *issued
            };
            fields["access_token"] = format!("tok-{n}").into();
            Json(fields).into_response()
        }
        Answer::Exactly(status, body) => (status, Json(body)).into_response(),
    }
}

async fn listen(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// The token endpoint's URL.
async fn issuer(issuer: &Arc<Issuer>) -> String {
    let app = Router::new()
        .route("/token", post(token_endpoint))
        .with_state(Arc::clone(issuer));
    format!("{}/token", listen(app).await)
}

fn literal(value: &str) -> SecretRef {
    SecretRef::Literal(SecretString::from(value))
}

fn grant(token_url: &str) -> ClientCredentials {
    ClientCredentials {
        token_url: token_url.to_string(),
        client_id: "mcpdef".to_string(),
        client_secret: literal("s3cret"),
        client_auth: ClientAuth::Basic,
        scopes: Vec::new(),
        resource: None,
    }
}

fn tokens(grant: ClientCredentials) -> Arc<TokenAuth> {
    Arc::new(TokenAuth::new(
        grant,
        EgressPolicy::default(),
        TlsSettings::default(),
    ))
}

/// The `Authorization` value `auth` adds to a request.
async fn applied(auth: &TokenAuth) -> Result<String, TransportError> {
    let mut headers = HeaderMap::new();
    auth.apply(&mut headers).await?;
    let value = &headers[header::AUTHORIZATION];
    assert!(value.is_sensitive());
    Ok(value.to_str().unwrap().to_string())
}

// ── An upstream that takes one token at a time, which the test changes.

#[derive(Default)]
struct Gate {
    wants: Mutex<String>,
    /// The token each request carried, in order.
    seen: Mutex<Vec<String>>,
}

impl Gate {
    fn wants(&self, token: &str) {
        *self.wants.lock().unwrap() = format!("Bearer {token}");
    }

    fn seen(&self) -> Vec<String> {
        let seen = std::mem::take(&mut *self.seen.lock().unwrap());
        seen.into_iter()
            .map(|v| v.trim_start_matches("Bearer ").to_string())
            .collect()
    }
}

async fn mcp(State(gate): State<Arc<Gate>>, headers: HeaderMap, body: String) -> Response {
    let given = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let ok = given == *gate.wants.lock().unwrap();
    gate.seen.lock().unwrap().push(given);
    if !ok {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let message = Message::from_json_line(body.trim()).unwrap();
    let Some(id) = message.id.clone() else {
        return StatusCode::ACCEPTED.into_response();
    };
    let result = match message.method() {
        Some("initialize") => json!({
            "protocolVersion": "2025-11-25",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "gate", "version": "0" }
        }),
        _ => json!({ "content": [{ "type": "text", "text": "done" }], "isError": false }),
    };
    (
        [(header::CONTENT_TYPE, "application/json")],
        Message::result(id, result).to_json_line(),
    )
        .into_response()
}

async fn gate(gate: &Arc<Gate>) -> String {
    let app = Router::new()
        .route("/mcp", post(mcp))
        .with_state(Arc::clone(gate));
    format!("{}/mcp", listen(app).await)
}

/// Open `client` as the gateway does, and hand it to a handle.
async fn open(mut client: HttpClient) -> Result<UpstreamHandle, TransportError> {
    client
        .send(Message::request(Id::Num(0), "initialize", Some(json!({}))))
        .await?;
    client.recv().await?.expect("an initialize reply");
    client
        .send(Message::notification("notifications/initialized", None))
        .await?;
    Ok(UpstreamHandle::spawn("gate", Box::new(client), 64))
}

fn call(id: i64) -> Message {
    Message::request(
        Id::Num(id),
        "tools/call",
        Some(json!({ "name": "t", "arguments": {} })),
    )
}

const WAIT: Option<Duration> = Some(Duration::from_secs(5));

// ── The tests.

#[tokio::test]
async fn the_token_request_is_the_one_rfc_6749_and_rfc_8707_describe() {
    let issuer_ = Issuer::new();
    let url = issuer(&issuer_).await;
    // A secret with characters form encoding changes, and a `:`.
    let secret = "s3:cr+t/=é";
    let basic = ClientCredentials {
        client_id: "mcp def".to_string(),
        client_secret: literal(secret),
        scopes: vec!["mcp:tools".to_string(), "read".to_string()],
        resource: Some("https://mcp.test/mcp".to_string()),
        ..grant(&url)
    };
    assert_eq!(applied(&tokens(basic)).await.unwrap(), "Bearer tok-1");
    let asked = issuer_.asked();
    assert_eq!(asked.len(), 1);
    let asked = &asked[0];
    assert_eq!(asked.content_type, "application/x-www-form-urlencoded");
    assert_eq!(asked.accept, "application/json");
    assert_eq!(
        asked.form,
        [
            ("grant_type".to_string(), "client_credentials".to_string()),
            ("scope".to_string(), "mcp:tools read".to_string()),
            ("resource".to_string(), "https://mcp.test/mcp".to_string()),
        ]
    );
    // client_secret_basic: each form-encoded, then Basic (RFC 6749 §2.3.1).
    let encoded =
        base64::engine::general_purpose::STANDARD.encode("mcp+def:s3%3Acr%2Bt%2F%3D%C3%A9");
    assert_eq!(
        asked.authorization.as_deref(),
        Some(format!("Basic {encoded}").as_str())
    );

    // client_secret_post: in the body, and no header. No scope or resource
    // is sent when none is given.
    let post = ClientCredentials {
        client_secret: literal(secret),
        client_auth: ClientAuth::Post,
        ..grant(&url)
    };
    assert_eq!(applied(&tokens(post)).await.unwrap(), "Bearer tok-2");
    let asked = issuer_.asked();
    assert_eq!(asked[0].authorization, None);
    assert_eq!(
        asked[0].form,
        [
            ("grant_type".to_string(), "client_credentials".to_string()),
            ("client_id".to_string(), "mcpdef".to_string()),
            ("client_secret".to_string(), secret.to_string()),
        ]
    );
}

/// Fifty requests that need a token at once, while the endpoint takes its
/// time, fetch one, and all send it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_that_need_a_token_at_once_fetch_one() {
    let issuer_ = Issuer::new();
    *issuer_.delay.lock().unwrap() = Duration::from_millis(200);
    let auth = tokens(grant(&issuer(&issuer_).await));
    let applying = (0..50).map(|_| {
        let auth = Arc::clone(&auth);
        tokio::spawn(async move { applied(&auth).await })
    });
    for sent in futures_util::future::join_all(applying).await {
        assert_eq!(sent.unwrap().unwrap(), "Bearer tok-1");
    }
    assert_eq!(issuer_.asked().len(), 1);
    // And later requests send it without asking again.
    assert_eq!(applied(&auth).await.unwrap(), "Bearer tok-1");
    assert!(issuer_.asked().is_empty());
}

/// Through an upstream: fifty calls at once send the token the opening
/// fetched, and when it has expired, fifty more fetch one more.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fifty_calls_at_once_fetch_one_token_and_one_more_once_it_expires() {
    let issuer_ = Issuer::new();
    // Sent for half its life: a second.
    issuer_.issues(json!({ "token_type": "bearer", "expires_in": 2 }));
    let gate_ = Arc::new(Gate::default());
    gate_.wants("tok-1");
    let client = HttpClient::streamable(gate(&gate_).await)
        .unwrap()
        .with_auth(tokens(grant(&issuer(&issuer_).await)));
    let fetched = Instant::now();
    let up = open(client).await.unwrap();
    let calls = (1..=50).map(|id| up.call(call(id), WAIT));
    for answer in futures_util::future::join_all(calls).await {
        answer.unwrap();
    }
    assert!(
        fetched.elapsed() < Duration::from_secs(1),
        "too slow to tell"
    );
    assert_eq!(issuer_.asked().len(), 1);
    assert!(gate_.seen().iter().all(|t| t == "tok-1"));

    tokio::time::sleep(Duration::from_millis(1100).saturating_sub(fetched.elapsed())).await;
    gate_.wants("tok-2");
    let calls = (51..=100).map(|id| up.call(call(id), WAIT));
    for answer in futures_util::future::join_all(calls).await {
        answer.unwrap();
    }
    assert_eq!(issuer_.asked().len(), 1);
    let seen = gate_.seen();
    assert_eq!(seen.len(), 50, "none refused: {seen:?}");
    assert!(seen.iter().all(|t| t == "tok-2"), "{seen:?}");
}

/// A token that expires is fetched again: this one lives a second, and is
/// sent for half of it. One whose server does not say when it expires, or
/// says so in a way no clock can hold, is sent until it is refused. (When a
/// longer life ends, 30 s before, is `oauth.rs`'s unit tests'.)
#[tokio::test]
async fn an_expired_token_is_fetched_again() {
    let issuer_ = Issuer::new();
    let url = issuer(&issuer_).await;
    // As a string, as some servers send it.
    issuer_.issues(json!({ "token_type": "Bearer", "expires_in": "1" }));
    let auth = tokens(grant(&url));
    let fetched = Instant::now();
    assert_eq!(applied(&auth).await.unwrap(), "Bearer tok-1");
    assert_eq!(applied(&auth).await.unwrap(), "Bearer tok-1");
    assert!(
        fetched.elapsed() < Duration::from_millis(500),
        "too slow to tell"
    );
    tokio::time::sleep(Duration::from_millis(600).saturating_sub(fetched.elapsed())).await;
    assert_eq!(applied(&auth).await.unwrap(), "Bearer tok-2");
    assert_eq!(issuer_.asked().len(), 2);

    for fields in [
        json!({ "token_type": "Bearer" }),
        json!({ "token_type": "Bearer", "expires_in": 1e300 }),
        json!({ "token_type": "Bearer", "expires_in": -5 }),
        json!({ "token_type": "Bearer", "expires_in": "soon" }),
    ] {
        issuer_.issues(fields.clone());
        let auth = tokens(grant(&url));
        let first = applied(&auth).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(applied(&auth).await.unwrap(), first, "{fields}");
    }
}

/// A refused token is fetched afresh and the request goes once more; a
/// second refusal fails the call closed.
#[tokio::test]
async fn a_refused_token_is_fetched_afresh_once_and_then_the_call_fails_closed() {
    let issuer_ = Issuer::new();
    let gate_ = Arc::new(Gate::default());
    gate_.wants("tok-1");
    let client = HttpClient::streamable(gate(&gate_).await)
        .unwrap()
        .with_auth(tokens(grant(&issuer(&issuer_).await)));
    let up = open(client).await.unwrap();
    up.call(call(1), WAIT).await.unwrap();
    assert_eq!(gate_.seen(), ["tok-1", "tok-1", "tok-1"]);

    // Revoked: refused, fetched afresh, and taken.
    gate_.wants("tok-2");
    up.call(call(2), WAIT).await.unwrap();
    assert_eq!(gate_.seen(), ["tok-1", "tok-2"]);
    assert_eq!(issuer_.asked().len(), 2);

    // Refused with a fresh one too: closed.
    gate_.wants("none of them");
    let refused = up.call(call(3), WAIT).await.unwrap_err();
    assert!(matches!(refused, CallError::Unauthorized(_)), "{refused:?}");
    assert_eq!(gate_.seen(), ["tok-2", "tok-3"]);

    // A server that hands the refused token out again: no second try.
    issuer_.answers(
        StatusCode::OK,
        json!({ "token_type": "Bearer", "access_token": "tok-3" }),
    );
    let refused = up.call(call(4), WAIT).await.unwrap_err();
    assert!(matches!(refused, CallError::Unauthorized(_)), "{refused:?}");
    assert_eq!(gate_.seen(), ["tok-3"]);
}

/// Requests refused at once fetch one fresh token between them, and all go
/// once more with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_refused_at_once_fetch_one_fresh_token() {
    let issuer_ = Issuer::new();
    let gate_ = Arc::new(Gate::default());
    gate_.wants("tok-1");
    let client = HttpClient::streamable(gate(&gate_).await)
        .unwrap()
        .with_auth(tokens(grant(&issuer(&issuer_).await)));
    let up = open(client).await.unwrap();
    issuer_.asked();
    gate_.wants("tok-2");
    let calls = (1..=20).map(|id| up.call(call(id), WAIT));
    for answer in futures_util::future::join_all(calls).await {
        answer.unwrap();
    }
    assert_eq!(issuer_.asked().len(), 1);
}

/// A request refused after another refusal already brought a fresh token
/// goes again with that one, and fetches none.
#[tokio::test]
async fn a_request_refused_late_goes_again_with_the_fresh_token_another_fetched() {
    let issuer_ = Issuer::new();
    let auth = tokens(grant(&issuer(&issuer_).await));
    let mut sent = HeaderMap::new();
    auth.apply(&mut sent).await.unwrap();
    assert!(auth.refresh(&sent).await.unwrap());
    assert!(auth.refresh(&sent).await.unwrap());
    assert_eq!(issuer_.asked().len(), 2, "one to open, one fresh");
    assert_eq!(applied(&auth).await.unwrap(), "Bearer tok-2");
}

/// With no token to send, a request is not sent: the call fails closed and
/// says why. Requests waiting on a fetch that fails share its failure, and a
/// later one fetches again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_endpoint_that_gives_no_token_fails_the_call_closed() {
    let issuer_ = Issuer::new();
    let url = issuer(&issuer_).await;
    let gate_ = Arc::new(Gate::default());
    gate_.wants("tok-1");
    // A second's life: sent for half of it.
    issuer_.issues(json!({ "token_type": "Bearer", "expires_in": 1 }));
    let client = HttpClient::streamable(gate(&gate_).await)
        .unwrap()
        .with_auth(tokens(grant(&url)));
    let up = open(client).await.unwrap();
    gate_.seen();

    issuer_.answers(
        StatusCode::SERVICE_UNAVAILABLE,
        json!({ "error": "temporarily_unavailable" }),
    );
    *issuer_.delay.lock().unwrap() = Duration::from_millis(200);
    tokio::time::sleep(Duration::from_millis(600)).await;
    issuer_.asked();
    let calls = (1..=20).map(|id| up.call(call(id), WAIT));
    for answer in futures_util::future::join_all(calls).await {
        let error = answer.unwrap_err();
        assert!(matches!(error, CallError::NoCredentials(_)), "{error:?}");
        assert_eq!(
            error.to_string(),
            format!(
                "token endpoint {url} answered 503 Service Unavailable: temporarily_unavailable"
            )
        );
    }
    assert_eq!(issuer_.asked().len(), 1, "one fetch for all 20");
    assert!(gate_.seen().is_empty(), "nothing sent without a token");

    // Back: the next call fetches, and is sent.
    *issuer_.delay.lock().unwrap() = Duration::ZERO;
    issuer_.issues(json!({ "token_type": "Bearer", "expires_in": 3600 }));
    gate_.wants("tok-2");
    up.call(call(21), WAIT).await.unwrap();
    assert_eq!(gate_.seen(), ["tok-2"]);
}

/// What a failed fetch says: where it went and what came back, never the
/// secret, even from a server that repeats it.
#[tokio::test]
async fn why_there_is_no_token_is_said_without_a_secret() {
    let issuer_ = Issuer::new();
    let url = issuer(&issuer_).await;
    let failed = |grant: ClientCredentials| async move {
        let error = applied(&tokens(grant)).await.unwrap_err();
        assert!(matches!(error, TransportError::Credentials(_)), "{error:?}");
        error.to_string()
    };

    issuer_.answers(
        StatusCode::UNAUTHORIZED,
        json!({ "error": "invalid_client", "error_description": "wrong secret s3cret" }),
    );
    assert_eq!(
        failed(grant(&url)).await,
        format!("credentials: token endpoint {url} answered 401 Unauthorized: invalid_client")
    );
    // An error code that is not one is left out.
    issuer_.answers(StatusCode::BAD_REQUEST, json!({ "error": "s3cret \"x\"" }));
    assert_eq!(
        failed(grant(&url)).await,
        format!("credentials: token endpoint {url} answered 400 Bad Request")
    );
    for (fields, says) in [
        (json!({ "token_type": "Bearer" }), "answered with no token"),
        (
            json!({ "token_type": "Bearer", "access_token": "" }),
            "answered with no token",
        ),
        (
            json!({ "token_type": "DPoP", "access_token": "s3cret" }),
            "gave a token whose token_type is not Bearer, which MCPdef cannot send",
        ),
        (
            json!({ "token_type": "Bearer", "access_token": "s3cret\nX" }),
            "gave a token no HTTP header can carry",
        ),
    ] {
        issuer_.answers(StatusCode::OK, fields);
        let error = failed(grant(&url)).await;
        assert_eq!(error, format!("credentials: token endpoint {url} {says}"));
    }

    // The secret unreadable: said where, and nothing sent.
    issuer_.asked();
    let unreadable = ClientCredentials {
        client_secret: SecretRef::File("/nonexistent/secret".into()),
        ..grant(&url)
    };
    let error = failed(unreadable).await;
    assert!(
        error.starts_with("credentials: client_secret /nonexistent/secret: "),
        "{error}"
    );
    assert!(issuer_.asked().is_empty());

    // Nothing listening.
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}/token", listener.local_addr().unwrap())
    };
    let error = failed(grant(&closed)).await;
    assert!(
        error.starts_with(&format!("credentials: token endpoint {closed}: http: ")),
        "{error}"
    );
    // And a credential's own Debug holds no literal secret.
    assert!(!format!("{:?}", grant(&url)).contains("s3cret"));
}

/// The token endpoint is behind the egress guard, and follows no redirect.
#[tokio::test]
async fn the_token_endpoint_is_behind_the_egress_guard_and_follows_no_redirect() {
    let error = applied(&tokens(grant("http://169.254.169.254/token")))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.starts_with(
            "credentials: token endpoint http://169.254.169.254/token: egress blocked: "
        ),
        "{error}"
    );

    let issuer_ = Issuer::new();
    let url = issuer(&issuer_).await;
    let private = Arc::new(TokenAuth::new(
        grant(&url),
        EgressPolicy {
            allow_private_network: false,
            ..EgressPolicy::default()
        },
        TlsSettings::default(),
    ));
    let error = applied(&private).await.unwrap_err().to_string();
    assert!(error.contains("egress blocked: "), "{error}");
    assert!(issuer_.asked().is_empty());

    // A redirect is an answer, and not followed.
    let elsewhere = Issuer::new();
    let target = issuer(&elsewhere).await;
    let app = Router::new().route(
        "/token",
        post(move || {
            let target = target.clone();
            async move { (StatusCode::FOUND, [(header::LOCATION, target)]) }
        }),
    );
    let redirecting = format!("{}/token", listen(app).await);
    let error = applied(&tokens(grant(&redirecting)))
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        format!("credentials: token endpoint {redirecting} answered 302 Found")
    );
    assert!(elsewhere.asked().is_empty());
}

/// On a private CA, the token endpoint is reached with the profile that
/// trusts it, and refused without.
#[tokio::test]
async fn a_token_endpoint_on_a_private_ca_is_reached_with_the_profile_that_trusts_it() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let issuer_ = Issuer::new();
    let app = Router::new()
        .route("/token", post(token_endpoint))
        .with_state(Arc::clone(&issuer_));
    let idp = HttpsUpstream::start_app(&pki.server(&["127.0.0.1"]), app).await;
    let url = format!("https://127.0.0.1:{}/token", idp.addr().port());

    let error = applied(&tokens(grant(&url))).await.unwrap_err().to_string();
    assert!(error.contains("UnknownIssuer"), "{error}");

    let trusting = TlsSettings {
        ca: vec![pki.write_root(dir.path(), "ca")],
        ..TlsSettings::default()
    };
    let auth = TokenAuth::new(grant(&url), EgressPolicy::default(), trusting);
    assert_eq!(applied(&auth).await.unwrap(), "Bearer tok-1");
}

/// The client secret is read at each fetch: rotated in its file, it is sent
/// from the next one.
#[tokio::test]
async fn the_client_secret_is_read_at_each_fetch() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret");
    std::fs::write(&secret, "first\n").unwrap();
    let issuer_ = Issuer::new();
    issuer_.issues(json!({ "token_type": "Bearer", "expires_in": 0 }));
    let from_file = ClientCredentials {
        client_secret: SecretRef::File(secret.clone()),
        client_auth: ClientAuth::Post,
        ..grant(&issuer(&issuer_).await)
    };
    let auth = tokens(from_file);
    applied(&auth).await.unwrap();
    std::fs::write(&secret, "second").unwrap();
    applied(&auth).await.unwrap();
    let sent: Vec<String> = issuer_
        .asked()
        .iter()
        .map(|asked| asked.field("client_secret").unwrap().to_string())
        .collect();
    assert_eq!(sent, ["first", "second"]);
}
