// SPDX-License-Identifier: Apache-2.0
//! The console's sign-in, against an identity provider this test serves:
//!   * someone the provider gives a console role signs in: `/login` sends
//!     them to it with PKCE S256, a state and a nonce; `/callback` exchanges
//!     the code, proving the client with its secret, and begins a session the
//!     admin API takes, back on the page they started from;
//!   * an answer that is not right is refused, and recorded: a state not the
//!     cookie's, or no cookie; an `iss` of another provider, or none where the
//!     provider says it sends one; an ID token of another nonce, issuer,
//!     audience or authorized party, expired, issued in the future or not
//!     saying when, or of `alg` `none` or HS256; an answer replayed, and its
//!     code redeemed again;
//!   * someone given no console role sees the claims MCPdef received, escaped,
//!     and gets no session; that too is recorded;
//!   * with `userinfo`, its claims count, and its failure, or its naming
//!     someone else, refuses the sign-in; the secret may be posted instead;
//!   * signing out ends the session, and says where the provider signs them
//!     out too; a page of another origin cannot sign anyone out;
//!   * a provider not found is looked for again a few seconds on, not at each
//!     sign-in; keys it rotates are read again, at most once a minute;
//!   * the client's secret is in no answer and no record.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mcpdef::connect::build_gateway;
use mcpdef::{serve_admin_on, AdminState, Config, Metrics};
use mcpdef_audit::read_all;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TEST_PRIV_PEM: &str = include_str!("../../mcpdef-auth/src/testdata/test_priv.pem");
const TEST_JWKS: &str = include_str!("../../mcpdef-auth/src/testdata/test_jwks.json");
const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");
const CLIENT_ID: &str = "mcpdef-console";
/// The client's secrets: the first console reads its own from a variable,
/// the second from its config. Neither may show.
const SECRET: &str = "cLiEnT-sEcReT-pLaNtEd-5";
const POSTED_SECRET: &str = "pOsTeD-sEcReT-pLaNtEd-6";
const SECRET_VAR: &str = "MCPDEF_SIGN_IN_TEST_SECRET";
const LOGIN_COOKIE: &str = "__Host-mcpdef-login";
const SESSION_COOKIE: &str = "__Host-mcpdef-session";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A task stopped however the test ends.
struct Aborted(tokio::task::JoinHandle<()>);

impl Drop for Aborted {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// How an ID token is signed.
#[derive(Clone, Copy)]
enum Signed {
    /// RS256, by the key the provider's keys hold.
    Rightly,
    /// Not at all: `alg` `none`.
    Unsigned,
    /// HS256, keyed with what anyone may read: the provider's keys.
    Hmac,
    /// ES256, by the key the provider rotates in, naming it by this id.
    Rotated(&'static str),
}

/// What the provider gave a code for, and what redeeming it must show.
struct Grant {
    challenge: String,
    redirect_uri: String,
    id_token: String,
    redeemed: bool,
}

/// A token request: its `Authorization` header, and its form.
type TokenRequest = (Option<String>, HashMap<String, String>);

/// An identity provider: its discovery document, its keys, its token
/// endpoint and userinfo. The authorization endpoint is the test itself,
/// which signs someone in by [`Idp::authorize`].
struct Idp {
    issuer: String,
    /// Whether its discovery document says it sends `iss` with each answer.
    sends_iss: bool,
    /// The secret the client proves itself with.
    secret: &'static str,
    /// While set, its discovery document is not there: it is down.
    down: AtomicBool,
    /// How often its discovery document, and its keys, were asked for.
    looked: AtomicUsize,
    keys_read: AtomicUsize,
    /// The keys it serves: the RSA key, and the EC key once rotated in.
    jwks: Mutex<String>,
    /// The EC key it rotates in, and that key as a JWK.
    ec_pem: String,
    ec_jwk: Value,
    codes: Mutex<HashMap<String, Grant>>,
    token_requests: Mutex<Vec<TokenRequest>>,
    /// What userinfo answers: its status, and its claims.
    userinfo: Mutex<(u16, Value)>,
}

async fn discovery(State(idp): State<Arc<Idp>>) -> Response {
    idp.looked.fetch_add(1, SeqCst);
    if idp.down.load(SeqCst) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let at = |path: &str| format!("{}{path}", idp.issuer);
    Json(json!({
        "issuer": idp.issuer,
        "authorization_endpoint": at("/authorize"),
        "token_endpoint": at("/token"),
        "jwks_uri": at("/jwks"),
        "userinfo_endpoint": at("/userinfo"),
        "end_session_endpoint": at("/logout"),
        "authorization_response_iss_parameter_supported": idp.sends_iss,
        "code_challenge_methods_supported": ["S256"],
    }))
    .into_response()
}

async fn jwks(State(idp): State<Arc<Idp>>) -> Response {
    idp.keys_read.fetch_add(1, SeqCst);
    let keys = idp.jwks.lock().unwrap().clone();
    ([(header::CONTENT_TYPE, "application/json")], keys).into_response()
}

/// The token endpoint, as RFC 6749 §4.1.3 and RFC 7636 §4.6 have it: the
/// client proven, and the code redeemed once, by the verifier its challenge
/// was made from, for the redirect URI it was given to.
async fn token(State(idp): State<Arc<Idp>>, headers: HeaderMap, body: String) -> Response {
    let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    let authorization = headers
        .get(header::AUTHORIZATION)
        .map(|v| v.to_str().unwrap().to_string());
    idp.token_requests
        .lock()
        .unwrap()
        .push((authorization.clone(), form.clone()));
    let refuse =
        |status: StatusCode, error: &str| (status, Json(json!({ "error": error }))).into_response();
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{CLIENT_ID}:{}", idp.secret))
    );
    let posted = form.get("client_id").map(String::as_str) == Some(CLIENT_ID)
        && form.get("client_secret").map(String::as_str) == Some(idp.secret);
    if authorization.as_deref() != Some(basic.as_str()) && !posted {
        return refuse(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    if form.get("grant_type").map(String::as_str) != Some("authorization_code") {
        return refuse(StatusCode::BAD_REQUEST, "unsupported_grant_type");
    }
    let mut codes = idp.codes.lock().unwrap();
    let Some(grant) = form.get("code").and_then(|code| codes.get_mut(code)) else {
        return refuse(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    if grant.redeemed {
        return refuse(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    grant.redeemed = true;
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    if challenge != grant.challenge || form.get("redirect_uri") != Some(&grant.redirect_uri) {
        return refuse(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    Json(json!({
        "access_token": format!("at-{}", form["code"]),
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": grant.id_token,
    }))
    .into_response()
}

/// Userinfo, for the bearer of an access token the token endpoint gave.
async fn userinfo(State(idp): State<Arc<Idp>>, headers: HeaderMap) -> Response {
    let code = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer at-"))
        .map(str::to_string);
    let known = code.is_some_and(|code| idp.codes.lock().unwrap().contains_key(&code));
    if !known {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (status, claims) = idp.userinfo.lock().unwrap().clone();
    (StatusCode::from_u16(status).unwrap(), Json(claims)).into_response()
}

impl Idp {
    async fn start(sends_iss: bool, secret: &'static str) -> (Arc<Idp>, Aborted) {
        let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        // ES256 on P-256: ring's public key is the point, 0x04 ‖ x ‖ y.
        let ec = rcgen::KeyPair::generate().unwrap();
        let point = ec.public_key_raw();
        let ec_jwk = json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "test-key-2",
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
        });
        let idp = Arc::new(Idp {
            issuer: format!("http://{}", bound.local_addr().unwrap()),
            sends_iss,
            secret,
            down: AtomicBool::new(false),
            looked: AtomicUsize::new(0),
            keys_read: AtomicUsize::new(0),
            jwks: Mutex::new(TEST_JWKS.to_string()),
            ec_pem: ec.serialize_pem(),
            ec_jwk,
            codes: Mutex::default(),
            token_requests: Mutex::default(),
            userinfo: Mutex::new((200, json!({}))),
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .route("/userinfo", get(userinfo))
            .with_state(Arc::clone(&idp));
        let serving = Aborted(tokio::spawn(async move {
            axum::serve(bound, app).await.unwrap();
        }));
        (idp, serving)
    }

    /// The provider's answer to the authorization request `started` made: a
    /// code, for an ID token of `claims` over the ones every ID token has (a
    /// claim `null` takes one away), signed as `signed` says.
    fn authorize(&self, started: &Started, claims: Value, signed: Signed) -> String {
        let at = now();
        let mut all = json!({
            "iss": self.issuer,
            "sub": "ann",
            "aud": CLIENT_ID,
            "exp": at + 300,
            "iat": at,
            "nonce": started.asked["nonce"],
        });
        for (name, value) in claims.as_object().unwrap() {
            match value {
                Value::Null => {
                    all.as_object_mut().unwrap().remove(name);
                }
                value => all[name] = value.clone(),
            }
        }
        let id_token = match signed {
            Signed::Rightly => {
                let mut header = Header::new(Algorithm::RS256);
                header.kid = Some("test-key-1".into());
                let key = EncodingKey::from_rsa_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
                encode(&header, &all, &key).unwrap()
            }
            Signed::Unsigned => format!(
                "{}.{}.",
                URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT","kid":"test-key-1"}"#),
                URL_SAFE_NO_PAD.encode(all.to_string())
            ),
            Signed::Hmac => {
                let mut header = Header::new(Algorithm::HS256);
                header.kid = Some("test-key-1".into());
                encode(
                    &header,
                    &all,
                    &EncodingKey::from_secret(TEST_JWKS.as_bytes()),
                )
                .unwrap()
            }
            Signed::Rotated(kid) => {
                let mut header = Header::new(Algorithm::ES256);
                header.kid = Some(kid.into());
                let key = EncodingKey::from_ec_pem(self.ec_pem.as_bytes()).unwrap();
                encode(&header, &all, &key).unwrap()
            }
        };
        let mut codes = self.codes.lock().unwrap();
        let code = format!("code-{}", codes.len());
        codes.insert(
            code.clone(),
            Grant {
                challenge: started.asked["code_challenge"].clone(),
                redirect_uri: started.asked["redirect_uri"].clone(),
                id_token,
                redeemed: false,
            },
        );
        code
    }

    fn token_requests(&self) -> usize {
        self.token_requests.lock().unwrap().len()
    }

    /// Rotate in the EC key: its keys hold it beside the RSA one.
    fn rotate(&self) {
        let mut keys: Value = serde_json::from_str(TEST_JWKS).unwrap();
        keys["keys"]
            .as_array_mut()
            .unwrap()
            .push(self.ec_jwk.clone());
        *self.jwks.lock().unwrap() = keys.to_string();
    }
}

/// An answer of the console.
struct Answer {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: String,
}

impl Answer {
    /// The `Set-Cookie` header that sets the cookie `name`: one at most, as a
    /// browser keeps only the last of several.
    fn set_cookie(&self, name: &str) -> Option<String> {
        let mut set: Vec<String> = self
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .filter(|value| value.starts_with(&format!("{name}=")))
            .collect();
        assert!(set.len() <= 1, "{name} is set {} times: {set:?}", set.len());
        set.pop()
    }

    /// What the answer sets the cookie `name` to: `""` when it clears it.
    fn sets(&self, name: &str) -> Option<String> {
        let set = self.set_cookie(name)?;
        let pair = set.split(';').next().unwrap();
        Some(pair[name.len() + 1..].to_string())
    }

    fn location(&self) -> &str {
        self.headers[header::LOCATION].to_str().unwrap()
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("{e}: {}", self.body))
    }
}

/// What `/login` began: where it sent the browser, with what, and the
/// cookie that holds the sign-in.
struct Started {
    to: url::Url,
    asked: HashMap<String, String>,
    set_cookie: String,
    cookie: String,
}

/// An admin listener that signs people in at an identity provider, and
/// every answer it gave.
struct Console {
    base: String,
    dir: tempfile::TempDir,
    client: reqwest::Client,
    seen: Mutex<Vec<String>>,
    _serving: Aborted,
}

impl Console {
    /// A console signing people in at `idp`, `[gateway.admin.oidc]` holding
    /// `oidc` too, and the config `identity` besides.
    async fn start(idp: &Idp, oidc: &str, identity: &str) -> Console {
        let dir = tempfile::tempdir().unwrap();
        let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", bound.local_addr().unwrap());
        let path = dir.path().join("mcpdef.toml");
        std::fs::write(
            &path,
            format!(
                "[gateway]\nlisten = \"127.0.0.1:7878\"\naudit = {audit:?}\nstate_dir = {state:?}\n\n\
                 [gateway.admin]\nenabled = true\nlisten = \"127.0.0.1:0\"\n\
                 tls = {{ mode = \"off\" }}\npublic_url = {base:?}\n\n\
                 [gateway.admin.oidc]\nissuer = {issuer:?}\nclient_id = {CLIENT_ID:?}\n{oidc}\n\n\
                 {identity}\n\n\
                 [[server]]\nid = \"a\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\n",
                audit = dir.path().join("audit.log"),
                state = dir.path().join("state"),
                issuer = idp.issuer,
            ),
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.validate(), Vec::<String>::new());
        let gw = build_gateway(&cfg).await.unwrap();
        let sessions = mcpdef::admin::session::keys(&cfg).unwrap();
        let state = Arc::new(
            AdminState::new(&cfg, Arc::new(Metrics::new(2)), gw, "test")
                .with_config_path(&path)
                .with_sign_in(&cfg, sessions),
        );
        let serving = Aborted(tokio::spawn(async move {
            serve_admin_on(state, bound, None).await.unwrap();
        }));
        mcpdef_transport::install_crypto_provider();
        Console {
            base,
            dir,
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            seen: Mutex::default(),
            _serving: serving,
        }
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Answer {
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.text().await.unwrap();
        self.seen
            .lock()
            .unwrap()
            .push(format!("{status} {headers:?} {body}"));
        Answer {
            status,
            headers,
            body,
        }
    }

    async fn get(&self, route: &str, cookie: Option<&str>) -> Answer {
        let mut request = self.client.get(format!("{}{route}", self.base));
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        self.send(request).await
    }

    /// A session of `idp`'s for `sub`, holding `roles`, sealed with this
    /// console's key and last sealed longer ago than `RENEW_AFTER`: its next
    /// use seals it again.
    fn old_session(&self, idp: &Idp, sub: &str, roles: &[&str]) -> String {
        let cfg = Config::load(self.dir.path().join("mcpdef.toml")).unwrap();
        let sessions = mcpdef::admin::session::keys(&cfg).unwrap();
        let at = now() - mcpdef::admin::session::RENEW_AFTER.as_secs() - 60;
        let roles = roles.iter().map(|role| role.to_string()).collect();
        let session = sessions.begin(&idp.issuer, sub, None, roles, at);
        format!("{SESSION_COOKIE}={}", sessions.seal(&session))
    }

    /// `POST /logout`, from a page of `origin`.
    async fn logout(&self, cookie: &str, origin: &str) -> Answer {
        let request = self
            .client
            .post(format!("{}/logout", self.base))
            .header(header::COOKIE, cookie)
            .header(header::ORIGIN, origin);
        self.send(request).await
    }

    /// `/login`, as a browser follows a link to it: off to the provider.
    async fn login(&self, then: &str) -> Started {
        let then: String = url::form_urlencoded::byte_serialize(then.as_bytes()).collect();
        let answer = self.get(&format!("/login?then={then}"), None).await;
        Console::started(&answer)
    }

    /// The sign-in `/login` began with `answer`.
    fn started(answer: &Answer) -> Started {
        assert_eq!(answer.status, 302, "{}", answer.body);
        let to = url::Url::parse(answer.location()).unwrap();
        let asked = to.query_pairs().into_owned().collect();
        let set_cookie = answer.set_cookie(LOGIN_COOKIE).unwrap();
        let cookie = format!("{LOGIN_COOKIE}={}", answer.sets(LOGIN_COOKIE).unwrap());
        Started {
            to,
            asked,
            set_cookie,
            cookie,
        }
    }

    /// `/callback`, with `query`, and the cookie `/login` set, if any.
    async fn callback(&self, query: &[(&str, &str)], cookie: Option<&str>) -> Answer {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(query)
            .finish();
        self.get(&format!("/callback?{query}"), cookie).await
    }

    /// The provider's answer to `started` for `code`, as it sends it back:
    /// with its `iss` when `iss`.
    async fn answer(&self, idp: &Idp, started: &Started, code: &str, iss: bool) -> Answer {
        let state = started.asked["state"].as_str();
        let mut query = vec![("code", code), ("state", state)];
        if iss {
            query.push(("iss", idp.issuer.as_str()));
        }
        self.callback(&query, Some(&started.cookie)).await
    }

    /// The sign-in and sign-out records: actor, action, decision and rule.
    fn records(&self) -> Vec<(String, String, String, Option<String>)> {
        read_all(self.dir.path().join("audit.log"))
            .unwrap()
            .into_iter()
            .filter(|r| r.kind.as_deref() == Some("admin"))
            .filter(|r| matches!(r.method.as_deref(), Some("sign-in" | "sign-out")))
            .map(|r| {
                (
                    r.actor.unwrap_or_default(),
                    r.method.unwrap_or_default(),
                    r.decision,
                    r.rule,
                )
            })
            .collect()
    }

    /// That `secrets` are in no answer the console gave, and no record.
    fn shows_none_of(&self, secrets: &[&str]) {
        let ledger = std::fs::read_to_string(self.dir.path().join("audit.log")).unwrap();
        for secret in secrets {
            for seen in self.seen.lock().unwrap().iter() {
                assert!(!seen.contains(secret), "{secret} in {seen}");
            }
            assert!(!ledger.contains(secret), "{secret} in the ledger");
        }
    }
}

/// A refusal of a sign-in: `400`, saying `why`, and no session begun.
#[track_caller]
fn refused(answer: &Answer, why: &str) {
    assert_eq!(answer.status, 400, "{}", answer.body);
    assert!(answer.body.contains("Sign-in refused"), "{}", answer.body);
    assert!(answer.body.contains(why), "{why:?} not in {}", answer.body);
    assert_eq!(
        answer.sets(SESSION_COOKIE),
        None,
        "a refusal begins no session"
    );
    assert_eq!(
        answer.sets(LOGIN_COOKIE).as_deref(),
        Some(""),
        "a refusal clears the sign-in's cookie"
    );
}

type Recorded = (String, String, String, Option<String>);

fn record(actor: &str, action: &str, refused: Option<&str>) -> Recorded {
    (
        actor.to_string(),
        action.to_string(),
        if refused.is_some() { "deny" } else { "allow" }.to_string(),
        refused.map(str::to_string),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_person_signs_in_at_the_identity_provider_and_out() {
    std::env::set_var(SECRET_VAR, SECRET);
    let (idp, _idp) = Idp::start(true, SECRET).await;
    let console = Console::start(
        &idp,
        &format!("client_secret = {{ env = {SECRET_VAR:?} }}"),
        "[identity]\nroles_claims = [\"realm_access.roles\"]",
    )
    .await;
    let mut expected = Vec::new();

    // Not signed in: the session says where to sign in, and the API refuses
    // with 401, saying so.
    let session = console.get("/api/v1/session", None).await;
    assert_eq!(session.status, 200, "{}", session.body);
    assert_eq!(session.json()["sign_in"], "/login");
    assert_eq!(session.json()["actor"], "anonymous");
    assert_eq!(session.json()["role"], Value::Null);
    assert_eq!(session.json().get("sign_out"), None);
    let status = console.get("/api/v1/status", None).await;
    assert_eq!(status.status, 401, "{}", status.body);
    assert_eq!(status.json()["title"], "Not signed in");

    // `/login`: to the provider, with PKCE S256, a state and a nonce, the
    // sign-in sealed in a cookie for ten minutes.
    let started = console.login("/audit?limit=5").await;
    assert_eq!(
        started.to.as_str().split('?').next().unwrap(),
        format!("{}/authorize", idp.issuer)
    );
    let asked = &started.asked;
    assert_eq!(asked["response_type"], "code");
    assert_eq!(asked["client_id"], CLIENT_ID);
    assert_eq!(asked["redirect_uri"], format!("{}/callback", console.base));
    assert_eq!(asked["scope"], "openid profile email");
    assert_eq!(asked["code_challenge_method"], "S256");
    for random in ["state", "nonce", "code_challenge"] {
        assert_eq!(asked[random].len(), 43, "{random}: {}", asked[random]);
    }
    assert_ne!(asked["state"], asked["nonce"]);
    assert!(
        started
            .set_cookie
            .ends_with("; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600"),
        "{}",
        started.set_cookie
    );
    assert!(
        !started.cookie.contains(&asked["state"]),
        "the state is sealed"
    );

    // Signed in: the code exchanged, the client proven by basic auth, and a
    // session begun; back where they started.
    let code = idp.authorize(
        &started,
        json!({ "name": "Ann Example", "realm_access": { "roles": ["console:operator"] } }),
        Signed::Rightly,
    );
    let signed_in = console.answer(&idp, &started, &code, true).await;
    assert_eq!(signed_in.status, 303, "{}", signed_in.body);
    assert_eq!(signed_in.location(), "/audit?limit=5");
    assert_eq!(signed_in.sets(LOGIN_COOKIE).as_deref(), Some(""));
    let set = signed_in.set_cookie(SESSION_COOKIE).unwrap();
    assert!(
        set.ends_with("; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=28800"),
        "{set}"
    );
    let ann = format!(
        "{SESSION_COOKIE}={}",
        signed_in.sets(SESSION_COOKIE).unwrap()
    );
    expected.push(record("user:ann", "sign-in", None));
    {
        let requests = idp.token_requests.lock().unwrap();
        let (authorization, form) = &requests[0];
        let basic = format!("Basic {}", STANDARD.encode(format!("{CLIENT_ID}:{SECRET}")));
        assert_eq!(authorization.as_deref(), Some(basic.as_str()));
        assert_eq!(form.get("client_secret"), None);
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], code);
        assert_eq!(form["redirect_uri"], asked["redirect_uri"]);
        assert_eq!(form["code_verifier"].len(), 43);
    }

    // The API takes the session: an operator's, so not an admin's.
    let session = console.get("/api/v1/session", Some(&ann)).await;
    assert_eq!(session.json()["actor"], "user:ann");
    assert_eq!(session.json()["role"], "console:operator");
    assert_eq!(session.json()["name"], "Ann Example");
    assert_eq!(session.json()["sign_out"], "/logout");
    assert_eq!(session.json().get("sign_in"), None);
    assert_eq!(console.get("/api/v1/status", Some(&ann)).await.status, 200);
    let config = console.get("/api/v1/config", Some(&ann)).await;
    assert_eq!(config.status, 403, "signed in, an operator is forbidden");

    // The same answer again: the sign-in is over, and the provider is not
    // asked again. Its code, under a sign-in of one's own: the provider
    // refuses it.
    refused(
        &console.answer(&idp, &started, &code, true).await,
        "this sign-in was finished already",
    );
    expected.push(record("anonymous", "sign-in", Some("sign-in-state")));
    assert_eq!(idp.token_requests(), 1);
    let own = console.login("/").await;
    refused(
        &console.answer(&idp, &own, &code, true).await,
        "the token endpoint answered 400: invalid_grant",
    );
    expected.push(record("anonymous", "sign-in", Some("sign-in-provider")));
    assert_eq!(idp.token_requests(), 2);

    // An answer that is not this sign-in's: another state, or no cookie.
    let started = console.login("/").await;
    let code = idp.authorize(&started, json!({}), Signed::Rightly);
    let mut forged = started.asked["state"].clone();
    forged.replace_range(0..1, if forged.starts_with('A') { "B" } else { "A" });
    let answer = console
        .callback(
            &[("code", &code), ("state", &forged), ("iss", &idp.issuer)],
            Some(&started.cookie),
        )
        .await;
    refused(&answer, "the answer&#39;s state is not this sign-in&#39;s");
    let answer = console
        .callback(
            &[
                ("code", &code),
                ("state", &started.asked["state"]),
                ("iss", &idp.issuer),
            ],
            None,
        )
        .await;
    refused(&answer, "this sign-in did not start here");
    expected.extend([
        record("anonymous", "sign-in", Some("sign-in-state")),
        record("anonymous", "sign-in", Some("sign-in-state")),
    ]);

    // An answer from another provider, or one that does not say which sent
    // it where this one says it does.
    let started = console.login("/").await;
    let code = idp.authorize(&started, json!({}), Signed::Rightly);
    let answer = console
        .callback(
            &[
                ("code", &code),
                ("state", &started.asked["state"]),
                ("iss", "https://idp.example"),
            ],
            Some(&started.cookie),
        )
        .await;
    refused(&answer, "the answer came from");
    let started = console.login("/").await;
    let code = idp.authorize(&started, json!({}), Signed::Rightly);
    refused(
        &console.answer(&idp, &started, &code, false).await,
        "the answer does not say which provider sent it",
    );
    expected.extend([
        record("anonymous", "sign-in", Some("sign-in-issuer")),
        record("anonymous", "sign-in", Some("sign-in-issuer")),
    ]);
    // The provider refusing, as it says.
    let started = console.login("/").await;
    let answer = console
        .callback(
            &[
                ("error", "access_denied"),
                ("state", &started.asked["state"]),
                ("iss", &idp.issuer),
            ],
            Some(&started.cookie),
        )
        .await;
    refused(&answer, "the identity provider refused it: access_denied");
    expected.push(record("anonymous", "sign-in", Some("sign-in-provider")));
    // None of these reached the token endpoint.
    assert_eq!(idp.token_requests(), 2);

    // ID tokens that are not right.
    let at = now();
    let tokens = [
        (json!({ "nonce": "another" }), Signed::Rightly, "its nonce"),
        (
            json!({ "iss": "https://idp.example" }),
            Signed::Rightly,
            "InvalidIssuer",
        ),
        (
            json!({ "aud": "another-client" }),
            Signed::Rightly,
            "InvalidAudience",
        ),
        (
            json!({ "azp": "another-client" }),
            Signed::Rightly,
            "issued to another client (azp)",
        ),
        (
            json!({ "aud": [CLIENT_ID, "another-client"] }),
            Signed::Rightly,
            "several audiences, and no authorized party",
        ),
        (
            json!({ "exp": at - 3600 }),
            Signed::Rightly,
            "ExpiredSignature",
        ),
        (
            json!({ "iat": at + 3600 }),
            Signed::Rightly,
            "issued in the future",
        ),
        (
            json!({ "iat": null }),
            Signed::Rightly,
            "when it was issued",
        ),
        (json!({}), Signed::Unsigned, "its ID token"),
        (json!({}), Signed::Hmac, "HS256"),
    ];
    for (claims, signed, why) in tokens {
        let started = console.login("/").await;
        let code = idp.authorize(&started, claims.clone(), signed);
        let answer = console.answer(&idp, &started, &code, true).await;
        assert_eq!(answer.status, 400, "{claims}: {}", answer.body);
        refused(&answer, why);
        expected.push(record("anonymous", "sign-in", Some("sign-in-token")));
    }
    // An azp naming this client, with several audiences, is right.
    let started = console.login("//idp.example/").await;
    let code = idp.authorize(
        &started,
        json!({
            "sub": "dee",
            "aud": [CLIENT_ID, "another-client"],
            "azp": CLIENT_ID,
            "realm_access": { "roles": ["console:viewer"] },
        }),
        Signed::Rightly,
    );
    let answer = console.answer(&idp, &started, &code, true).await;
    assert_eq!(answer.status, 303, "{}", answer.body);
    assert_eq!(answer.location(), "/", "back to this console alone");
    expected.push(record("user:dee", "sign-in", None));

    // No console role: a page of the claims received, escaped, for them
    // alone, and no session.
    let started = console.login("/").await;
    let code = idp.authorize(
        &started,
        json!({
            "sub": "cy",
            "name": "<script>alert(1)</script>",
            "realm_access": { "roles": ["mcp-reader"] },
        }),
        Signed::Rightly,
    );
    let answer = console.answer(&idp, &started, &code, true).await;
    assert_eq!(answer.status, 403, "{}", answer.body);
    assert!(answer.body.contains("No console role"), "{}", answer.body);
    assert!(answer.body.contains("mcp-reader"), "{}", answer.body);
    assert!(
        answer.body.contains("&lt;script&gt;") && !answer.body.contains("<script>"),
        "{}",
        answer.body
    );
    assert_eq!(answer.sets(SESSION_COOKIE), None);
    assert!(
        answer.headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("script-src 'self'"),
        "no script written into the page runs"
    );
    expected.push(record("user:cy", "sign-in", Some("no-console-role")));

    // Signing out: never from a page of another origin; from the console's
    // own, the session ends and the provider is where to go next.
    let elsewhere = console.logout(&ann, "https://evil.example").await;
    assert_eq!(elsewhere.status, 403, "{}", elsewhere.body);
    assert_eq!(console.get("/api/v1/status", Some(&ann)).await.status, 200);
    let out = console.logout(&ann, &console.base).await;
    assert_eq!(out.status, 200, "{}", out.body);
    let redirect = url::Url::parse(out.json()["redirect"].as_str().unwrap()).unwrap();
    assert_eq!(
        redirect.as_str().split('?').next().unwrap(),
        format!("{}/logout", idp.issuer)
    );
    let pairs: HashMap<String, String> = redirect.query_pairs().into_owned().collect();
    assert_eq!(pairs["client_id"], CLIENT_ID);
    assert_eq!(
        pairs["post_logout_redirect_uri"],
        format!("{}/", console.base)
    );
    assert_eq!(out.sets(SESSION_COOKIE).as_deref(), Some(""));
    let after = console.get("/api/v1/status", Some(&ann)).await;
    assert_eq!(after.status, 401, "a session signed out of opens no more");
    expected.push(record("user:ann", "sign-out", None));

    assert_eq!(console.records(), expected);
    let basic = STANDARD.encode(format!("{CLIENT_ID}:{SECRET}"));
    console.shows_none_of(&[SECRET, &basic]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn userinfo_adds_its_claims_and_its_failure_refuses_the_sign_in() {
    let (idp, _idp) = Idp::start(false, POSTED_SECRET).await;
    let console = Console::start(
        &idp,
        &format!(
            "client_secret = {POSTED_SECRET:?}\nclient_auth = \"client_secret_post\"\n\
             userinfo = true\nscopes = [\"groups\"]"
        ),
        "[identity]\nsubject_claim = \"email\"\n\n\
         [[identity.role_map]]\nclaim = \"groups\"\nvalue = \"mcp-console\"\nroles = [\"console:admin\"]",
    )
    .await;
    let mut expected = Vec::new();

    // The ID token names no email and no group; userinfo does. The secret
    // is posted, and the provider, which does not say it sends `iss`, need
    // not.
    *idp.userinfo.lock().unwrap() = (
        200,
        json!({ "sub": "ann", "email": "ann@example.com", "groups": ["mcp-console"] }),
    );
    let started = console.login("/").await;
    assert_eq!(started.asked["scope"], "openid groups");
    let code = idp.authorize(&started, json!({}), Signed::Rightly);
    let answer = console.answer(&idp, &started, &code, false).await;
    assert_eq!(answer.status, 303, "{}", answer.body);
    let ann = format!("{SESSION_COOKIE}={}", answer.sets(SESSION_COOKIE).unwrap());
    expected.push(record("user:ann@example.com", "sign-in", None));
    {
        let requests = idp.token_requests.lock().unwrap();
        let (authorization, form) = &requests[0];
        assert_eq!(authorization, &None);
        assert_eq!(form["client_id"], CLIENT_ID);
        assert_eq!(form["client_secret"], POSTED_SECRET);
    }
    let session = console.get("/api/v1/session", Some(&ann)).await;
    assert_eq!(session.json()["actor"], "user:ann@example.com");
    assert_eq!(session.json()["role"], "console:admin");

    // An admin reads the config, its secret masked, and how the console
    // signs people in, its secret said to be set.
    let config = console.get("/api/v1/config", Some(&ann)).await;
    assert_eq!(config.status, 200, "{}", config.body);
    let text = config.json()["text"].as_str().unwrap().to_string();
    assert!(text.contains("client_secret = \"***\""), "{text}");
    let identity = console.get("/api/v1/identity", Some(&ann)).await.json();
    assert_eq!(identity["console"]["signs_in"], json!(["oidc"]));
    let oidc = &identity["console"]["oidc"];
    assert_eq!(oidc["issuer"], idp.issuer.as_str());
    assert_eq!(oidc["client_id"], CLIENT_ID);
    assert_eq!(oidc["client_secret"], true);
    assert_eq!(oidc["client_auth"], "client_secret_post");
    assert_eq!(oidc["scopes"], json!(["openid", "groups"]));
    assert_eq!(oidc["userinfo"], true);
    assert_eq!(
        oidc["redirect_uri"],
        format!("{}/callback", console.base).as_str()
    );
    assert_eq!(identity["console"]["provider"]["found"], true);
    assert_eq!(identity["console"]["provider"]["userinfo"], true);
    assert_eq!(identity["console"]["provider"]["sends_iss"], false);
    assert_eq!(identity["model"]["subject_claim"], "email");
    assert_eq!(identity["model"]["role_map"][0]["value"], "mcp-console");

    // Userinfo naming someone else, failing, or saying nothing of the
    // subject: each refuses the sign-in.
    let cases = [
        (
            (
                200,
                json!({ "sub": "eve", "email": "eve@example.com", "groups": ["mcp-console"] }),
            ),
            "userinfo names another subject",
            "sign-in-userinfo",
        ),
        (
            (500, json!({ "error": "server_error" })),
            "userinfo answered 500",
            "sign-in-userinfo",
        ),
        (
            (200, json!({ "sub": "ann", "groups": ["mcp-console"] })),
            "it has no `email` claim",
            "sign-in-token",
        ),
    ];
    for (said, why, rule) in cases {
        *idp.userinfo.lock().unwrap() = said;
        let started = console.login("/").await;
        let code = idp.authorize(&started, json!({}), Signed::Rightly);
        refused(&console.answer(&idp, &started, &code, false).await, why);
        expected.push(record("anonymous", "sign-in", Some(rule)));
    }
    // An `iss` it was not asked to send is still checked.
    let started = console.login("/").await;
    let code = idp.authorize(&started, json!({}), Signed::Rightly);
    let answer = console
        .callback(
            &[
                ("code", &code),
                ("state", &started.asked["state"]),
                ("iss", "https://idp.example"),
            ],
            Some(&started.cookie),
        )
        .await;
    refused(&answer, "the answer came from");
    expected.push(record("anonymous", "sign-in", Some("sign-in-issuer")));

    assert_eq!(console.records(), expected);
    console.shows_none_of(&[POSTED_SECRET]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_down_is_looked_for_again_and_keys_it_rotates_are_read_again() {
    let (idp, _idp) = Idp::start(false, SECRET).await;
    idp.down.store(true, SeqCst);
    let console = Console::start(
        &idp,
        &format!("client_secret = {SECRET:?}"),
        "[identity]\nroles_claims = [\"realm_access.roles\"]",
    )
    .await;
    let viewer = json!({ "realm_access": { "roles": ["console:viewer"] } });

    // Looked for as the gateway starts, and not found: a sign-in within
    // seconds of that is refused, and the provider not asked again.
    let deadline = Instant::now() + Duration::from_secs(10);
    while idp.looked.load(SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "the provider was never looked for"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for _ in 0..3 {
        let answer = console.get("/login", None).await;
        assert_eq!(answer.status, 503, "{}", answer.body);
        assert!(
            answer.body.contains("Sign-in unavailable"),
            "{}",
            answer.body
        );
    }
    assert_eq!(idp.looked.load(SeqCst), 1);

    // Up again: a sign-in a few seconds on finds it.
    idp.down.store(false, SeqCst);
    let deadline = Instant::now() + Duration::from_secs(20);
    let started = loop {
        let answer = console.get("/login", None).await;
        if answer.status == 302 {
            break Console::started(&answer);
        }
        assert_eq!(answer.status, 503, "{}", answer.body);
        assert!(
            Instant::now() < deadline,
            "the provider was not found again"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    assert!(
        idp.looked.load(SeqCst) <= 4,
        "looked for {} times in some seconds",
        idp.looked.load(SeqCst)
    );
    let code = idp.authorize(&started, viewer.clone(), Signed::Rightly);
    let answer = console.answer(&idp, &started, &code, false).await;
    assert_eq!(answer.status, 303, "{}", answer.body);
    assert_eq!(idp.keys_read.load(SeqCst), 1);

    // It rotates its keys and signs with the new one: they are read again.
    idp.rotate();
    let started = console.login("/").await;
    let code = idp.authorize(&started, viewer.clone(), Signed::Rotated("test-key-2"));
    let answer = console.answer(&idp, &started, &code, false).await;
    assert_eq!(answer.status, 303, "{}", answer.body);
    assert_eq!(idp.keys_read.load(SeqCst), 2);

    // A key it does not hold, within the minute: refused, and its keys not
    // read again for it.
    let started = console.login("/").await;
    let code = idp.authorize(&started, viewer, Signed::Rotated("test-key-9"));
    refused(
        &console.answer(&idp, &started, &code, false).await,
        "test-key-9",
    );
    assert_eq!(idp.keys_read.load(SeqCst), 2);
    assert_eq!(
        console.records(),
        [
            record("user:ann", "sign-in", None),
            record("user:ann", "sign-in", None),
            record("anonymous", "sign-in", Some("sign-in-token")),
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_sealed_again_never_undoes_a_sign_out_or_a_sign_in() {
    std::env::set_var(SECRET_VAR, SECRET);
    let (idp, _idp) = Idp::start(true, SECRET).await;
    let console = Console::start(
        &idp,
        &format!("client_secret = {{ env = {SECRET_VAR:?} }}"),
        "[identity]\nroles_claims = [\"realm_access.roles\"]",
    )
    .await;

    // A session last sealed longer ago than RENEW_AFTER is sealed again as
    // it is used, on an answer no shared cache keeps.
    let ann = console.old_session(&idp, "ann", &["console:operator"]);
    let status = console.get("/api/v1/status", Some(&ann)).await;
    assert_eq!(status.status, 200, "{}", status.body);
    let renewed = status
        .sets(SESSION_COOKIE)
        .expect("an old session is sealed again");
    assert!(!renewed.is_empty());

    // Not on the console's own files, which a cache may keep and hand to
    // whoever asks next.
    let index = console.get("/", Some(&ann)).await;
    assert_eq!(index.status, 200, "{}", index.body);
    assert_eq!(index.set_cookie(SESSION_COOKIE), None);
    let script = index
        .body
        .split('"')
        .find(|s| s.starts_with("/assets/") && s.ends_with(".js"))
        .expect("index.html names its script")
        .to_string();
    let file = console.get(&script, Some(&ann)).await;
    assert_eq!(file.status, 200);
    let caching = file.headers[header::CACHE_CONTROL].to_str().unwrap();
    assert!(caching.starts_with("public"), "{caching}");
    assert_eq!(file.set_cookie(SESSION_COOKIE), None);

    // Signing out clears the cookie, and nothing sets it again after.
    let out = console.logout(&ann, &console.base).await;
    assert_eq!(out.status, 200, "{}", out.body);
    assert_eq!(out.sets(SESSION_COOKIE).as_deref(), Some(""));
    assert_eq!(console.get("/api/v1/status", Some(&ann)).await.status, 401);

    // Signing in again over an old session: the new one is the one kept.
    let bob = console.old_session(&idp, "bob", &["console:viewer"]);
    let started = console.login("/").await;
    let code = idp.authorize(
        &started,
        json!({ "sub": "bob", "realm_access": { "roles": ["console:admin"] } }),
        Signed::Rightly,
    );
    let state = started.asked["state"].clone();
    let both = format!("{}; {bob}", started.cookie);
    let query = [
        ("code", code.as_str()),
        ("state", state.as_str()),
        ("iss", idp.issuer.as_str()),
    ];
    let signed_in = console.callback(&query, Some(&both)).await;
    assert_eq!(signed_in.status, 303, "{}", signed_in.body);
    let fresh = format!(
        "{SESSION_COOKIE}={}",
        signed_in.sets(SESSION_COOKIE).unwrap()
    );
    let session = console.get("/api/v1/session", Some(&fresh)).await;
    assert_eq!(session.json()["actor"], "user:bob");
    assert_eq!(session.json()["role"], "console:admin");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_console_roles_are_sealed_so_a_member_of_many_groups_stays_signed_in() {
    std::env::set_var(SECRET_VAR, SECRET);
    let (idp, _idp) = Idp::start(true, SECRET).await;
    let console = Console::start(
        &idp,
        &format!("client_secret = {{ env = {SECRET_VAR:?} }}"),
        "[identity]\nroles_claims = [\"groups\"]",
    )
    .await;

    // Two hundred groups, as many as an Entra ID token's groups claim holds,
    // and one of them the console's: sealed whole, they would make a cookie
    // twice the 4 KB a browser keeps.
    let mut groups: Vec<String> = (0..200)
        .map(|i| format!("{i:08x}-0000-4000-8000-{i:012x}"))
        .collect();
    groups.push("console:viewer".to_string());
    let started = console.login("/").await;
    let code = idp.authorize(&started, json!({ "groups": groups }), Signed::Rightly);
    let signed_in = console.answer(&idp, &started, &code, true).await;
    assert_eq!(signed_in.status, 303, "{}", signed_in.body);
    let set = signed_in.set_cookie(SESSION_COOKIE).unwrap();
    assert!(set.len() < 1024, "{} bytes: {set}", set.len());
    let ann = format!(
        "{SESSION_COOKIE}={}",
        signed_in.sets(SESSION_COOKIE).unwrap()
    );
    let session = console.get("/api/v1/session", Some(&ann)).await;
    assert_eq!(session.json()["role"], "console:viewer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_sign_ins_past_so_many_a_minute_are_not_each_recorded() {
    std::env::set_var(SECRET_VAR, SECRET);
    let (idp, _idp) = Idp::start(true, SECRET).await;
    let console = Console::start(
        &idp,
        &format!("client_secret = {{ env = {SECRET_VAR:?} }}"),
        "",
    )
    .await;
    // All within one minute, as the refusals are counted.
    let into = now() % 60;
    if into > 45 {
        tokio::time::sleep(Duration::from_secs(61 - into)).await;
    }

    // Anyone who reaches the listener may ask for /callback, and is refused.
    // Twenty a minute are recorded, one each, then one record says the rest
    // are not: the ledger grows by so much at most.
    for _ in 0..50 {
        let answer = console.callback(&[], None).await;
        assert_eq!(answer.status, 400, "{}", answer.body);
    }
    let mut expected = vec![record("anonymous", "sign-in", Some("sign-in-state")); 20];
    expected.push(record(
        "anonymous",
        "sign-in",
        Some("sign-in-refusals-unrecorded"),
    ));
    assert_eq!(console.records(), expected);

    // A sign-in that goes through is recorded all the same.
    let started = console.login("/").await;
    let code = idp.authorize(
        &started,
        json!({ "roles": ["console:viewer"] }),
        Signed::Rightly,
    );
    assert_eq!(
        console.answer(&idp, &started, &code, true).await.status,
        303
    );
    expected.push(record("user:ann", "sign-in", None));
    assert_eq!(console.records(), expected);
}
