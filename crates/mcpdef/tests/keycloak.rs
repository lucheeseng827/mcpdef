// SPDX-License-Identifier: Apache-2.0
//! The console signing people in at Keycloak, and SAML users through
//! Keycloak as their broker: through Keycloak's own pages, as a browser goes
//! through them, to `mcpdef run`, its config the one `mcpdef sso init
//! --write` gives it.
//!
//! These run when `MCPDEF_KEYCLOAK_URL` names a Keycloak, at
//! `http://localhost:8080` (the address the realms' SAML endpoints name), that
//! has imported the realms of `deploy/compose/sso-saml/realms`: `mcpdef`,
//! where the console signs people in, and `corp`, a SAML identity provider
//! `mcpdef` brokers. Without it each test says so and passes, so that `cargo
//! test` needs nothing running; CI runs them in a job of their own.
//!
//!   * someone whose group gives a console role signs in, and the console's
//!     session names them, in that role; an operator's reload is in the
//!     ledger as theirs, and the same request from a page of another origin is
//!     refused; a viewer may not reload; someone in no such group is shown the
//!     claims MCPdef received of them, and given no session;
//!   * signing out ends the session, and the one at Keycloak: signing in again
//!     asks for a password;
//!   * the same through the SAML broker, the people signing in at `corp`, and
//!     out of both realms; and a SAML response altered on its way, a viewer's
//!     group made the admins', is refused by the broker, its signature no
//!     longer the identity provider's, and MCPdef begins no session.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use mcpdef_audit::read_all;
use reqwest::header::{self, HeaderMap};
use reqwest::Method;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const MCPDEF: &str = env!("CARGO_BIN_EXE_mcpdef");
const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");
/// The console's client secret, as the `mcpdef` realm's file sets it.
const SECRET: &str = "mcpdef-console-demo-secret";
const SESSION_COOKIE: &str = "__Host-mcpdef-session";

/// The Keycloak to sign in at; or, said, none.
fn keycloak() -> Option<String> {
    let url = std::env::var("MCPDEF_KEYCLOAK_URL")
        .ok()
        .filter(|url| !url.trim().is_empty());
    if url.is_none() {
        eprintln!("MCPDEF_KEYCLOAK_URL is not set: no Keycloak to sign in at, nothing checked");
    }
    url.map(|url| url.trim_end_matches('/').to_string())
}

/// `mcpdef run`, its console signing people in at Keycloak's `mcpdef` realm.
struct Gateway {
    base: String,
    dir: tempfile::TempDir,
    child: Child,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Gateway {
    /// A gateway with one upstream, signing people in by what `mcpdef sso
    /// init --provider <provider> --write` adds to its config.
    async fn start(keycloak: &str, provider: &str) -> Gateway {
        let dir = tempfile::tempdir().unwrap();
        // The console's port is known before it starts: its public URL names
        // it, and so does the redirect URI Keycloak sends people back to,
        // which takes any port of 127.0.0.1's (RFC 8252).
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let base = format!("http://127.0.0.1:{port}");
        let path = dir.path().join("mcpdef.toml");
        std::fs::write(
            &path,
            format!(
                "[gateway]\nlisten = \"127.0.0.1:0\"\naudit = {audit:?}\nstate_dir = {state:?}\n\n\
                 [gateway.admin]\nenabled = true\nlisten = \"127.0.0.1:{port}\"\n\n\
                 [[server]]\nid = \"alpha\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\n\
                 tools = [\"echo\"]\n",
                audit = dir.path().join("audit.log"),
                state = dir.path().join("state"),
            ),
        )
        .unwrap();
        let issuer = format!("{keycloak}/realms/mcpdef");
        let init = Command::new(MCPDEF)
            .args(["sso", "init", "--provider", provider, "--issuer", &issuer])
            .args(["--public-url", &base, "--write", "--config"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            init.status.success(),
            "sso init: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let log = std::fs::File::create(dir.path().join("gateway.log")).unwrap();
        let child = Command::new(MCPDEF)
            .args(["run", "--http", "--config"])
            .arg(&path)
            .env("MCPDEF_OIDC_CLIENT_SECRET", SECRET)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let gateway = Gateway { base, dir, child };
        mcpdef_transport::install_crypto_provider();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        for _ in 0..100 {
            let health = client.get(format!("{}/health", gateway.base)).send().await;
            if health.is_ok_and(|answer| answer.status().is_success()) {
                return gateway;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the gateway did not start: {}", gateway.log());
    }

    /// What the gateway wrote to its standard error.
    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("gateway.log")).unwrap_or_default()
    }

    /// Each record of a sign-in, a sign-out or a reload: actor, action,
    /// decision and rule.
    fn records(&self) -> Vec<(String, String, String, Option<String>)> {
        read_all(self.dir.path().join("audit.log"))
            .unwrap()
            .into_iter()
            .filter(|r| matches!(r.kind.as_deref(), Some("admin" | "reload")))
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
}

/// A page, and where it was found.
struct Page {
    url: url::Url,
    status: u16,
    body: String,
}

impl Page {
    /// The form on the page that posts to an action holding `to`.
    fn form(&self, to: &str) -> Form {
        forms(&self.body)
            .into_iter()
            .find(|form| form.action.contains(to))
            .unwrap_or_else(|| panic!("no form to {to} on {}: {}", self.url, self.body))
    }

    fn has_form(&self, to: &str) -> bool {
        forms(&self.body)
            .iter()
            .any(|form| form.action.contains(to))
    }
}

/// A form: where it posts, and its inputs' names and values.
#[derive(Clone)]
struct Form {
    action: String,
    fields: Vec<(String, String)>,
}

/// What the browser does to a SAML response before posting it on.
type Alter = Box<dyn Fn(&str) -> String>;

/// A browser, as far as signing in goes: it follows redirects, keeps each
/// host's cookies by path and name, sending them, as browsers do to this
/// machine, over http too, and posts the forms that post themselves (SAML's
/// POST binding).
struct Browser {
    client: reqwest::Client,
    /// `host:port` → (path, name) → value.
    jar: HashMap<String, BTreeMap<(String, String), String>>,
    /// Every request, for a failure to show.
    trail: Vec<String>,
}

impl Browser {
    fn new() -> Browser {
        mcpdef_transport::install_crypto_provider();
        Browser {
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            jar: HashMap::new(),
            trail: Vec::new(),
        }
    }

    fn origin(url: &url::Url) -> String {
        format!(
            "{}:{}",
            url.host_str().unwrap_or_default(),
            url.port_or_known_default().unwrap_or_default()
        )
    }

    /// The `Cookie` header for `url`: the longest paths first.
    fn cookies(&self, url: &url::Url) -> Option<String> {
        let path = url.path();
        let mut sent: Vec<(&String, &String, &String)> = self
            .jar
            .get(&Browser::origin(url))?
            .iter()
            .filter(|((at, _), _)| {
                at == "/"
                    || path == at
                    || path.starts_with(&format!("{}/", at.trim_end_matches('/')))
            })
            .map(|((at, name), value)| (at, name, value))
            .collect();
        sent.sort_by_key(|(at, _, _)| std::cmp::Reverse(at.len()));
        let header: Vec<String> = sent
            .iter()
            .map(|(_, name, value)| format!("{name}={value}"))
            .collect();
        (!header.is_empty()).then(|| header.join("; "))
    }

    /// The cookies an answer from `url` sets, kept; or, expired, dropped.
    fn keep(&mut self, url: &url::Url, headers: &HeaderMap) {
        let jar = self.jar.entry(Browser::origin(url)).or_default();
        for set in headers.get_all(header::SET_COOKIE) {
            let set = set.to_str().unwrap_or_default();
            let mut parts = set.split(';').map(str::trim);
            let Some((name, value)) = parts.next().and_then(|pair| pair.split_once('=')) else {
                continue;
            };
            let mut path = "/".to_string();
            let mut gone = value.is_empty();
            for attribute in parts {
                let (key, val) = attribute.split_once('=').unwrap_or((attribute, ""));
                match key.to_ascii_lowercase().as_str() {
                    "path" => path = val.to_string(),
                    "max-age" => gone |= val.trim() == "0" || val.starts_with('-'),
                    "expires" => gone |= val.contains("1970"),
                    _ => {}
                }
            }
            let key = (path, name.to_string());
            if gone {
                jar.remove(&key);
            } else {
                jar.insert(key, value.to_string());
            }
        }
    }

    fn has_cookie(&self, name: &str) -> bool {
        self.cookie(name).is_some()
    }

    /// The value of the cookie `name`, whichever host set it.
    fn cookie(&self, name: &str) -> Option<String> {
        self.jar
            .values()
            .flat_map(|jar| jar.iter())
            .find(|((_, kept), _)| kept == name)
            .map(|(_, value)| value.clone())
    }

    /// One request, its cookies sent and kept.
    async fn send(
        &mut self,
        method: Method,
        url: url::Url,
        form: Option<&[(String, String)]>,
        headers: &[(&str, &str)],
    ) -> (Page, HeaderMap) {
        let mut request = self.client.request(method.clone(), url.clone());
        if let Some(cookies) = self.cookies(&url) {
            request = request.header(header::COOKIE, cookies);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(form) = form {
            let body = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(form)
                .finish();
            request = request
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(body);
        }
        let answer = request
            .send()
            .await
            .unwrap_or_else(|e| panic!("{method} {url}: {e}\n{}", self.trail()));
        let status = answer.status().as_u16();
        let answered = answer.headers().clone();
        let body = answer.text().await.unwrap_or_default();
        self.keep(&url, &answered);
        self.trail.push(format!("{method} {url} → {status}"));
        (Page { url, status, body }, answered)
    }

    /// A request, and whatever it leads to: redirects followed, and the forms
    /// that post themselves posted, the SAML responses among them altered by
    /// `alter` first.
    async fn go(
        &mut self,
        mut method: Method,
        mut url: url::Url,
        mut form: Option<Vec<(String, String)>>,
        alter: Option<&Alter>,
    ) -> Page {
        for _ in 0..30 {
            let (page, headers) = self
                .send(method.clone(), url.clone(), form.as_deref(), &[])
                .await;
            if matches!(page.status, 301 | 302 | 303 | 307 | 308) {
                let to = headers
                    .get(header::LOCATION)
                    .and_then(|to| to.to_str().ok())
                    .unwrap_or_else(|| panic!("a redirect to nowhere\n{}", self.trail()));
                url = page.url.join(to).unwrap();
                if matches!(page.status, 301..=303) {
                    method = Method::GET;
                    form = None;
                }
                continue;
            }
            let posts_itself = page.status == 200
                && (page.body.contains("SAMLRequest") || page.body.contains("SAMLResponse"));
            if !posts_itself {
                return page;
            }
            let mut posted = forms(&page.body).remove(0);
            if let Some(alter) = alter {
                for (name, value) in posted.fields.iter_mut() {
                    if name == "SAMLResponse" {
                        let compact: String = value.split_whitespace().collect();
                        let xml = String::from_utf8(STANDARD.decode(compact).unwrap()).unwrap();
                        *value = STANDARD.encode(alter(&xml));
                    }
                }
            }
            url = page.url.join(&posted.action).unwrap();
            method = Method::POST;
            form = Some(posted.fields);
        }
        panic!("more than 30 steps\n{}", self.trail());
    }

    async fn get(&mut self, url: &str) -> Page {
        self.go(Method::GET, url::Url::parse(url).unwrap(), None, None)
            .await
    }

    fn trail(&self) -> String {
        self.trail.join("\n")
    }

    /// `user` (whose password is their name) signing in to the console: off
    /// to Keycloak from `/login`, then its form, or, for a SAML user,
    /// `corp`'s, through the broker's link on it. The page they end on.
    async fn sign_in(&mut self, gw: &Gateway, user: &str, saml: bool) -> Page {
        self.signing_in(gw, user, saml, None).await
    }

    async fn signing_in(
        &mut self,
        gw: &Gateway,
        user: &str,
        saml: bool,
        alter: Option<&Alter>,
    ) -> Page {
        let mut page = self
            .get(&format!("{}/login?then=%2F%23servers", gw.base))
            .await;
        assert!(
            page.url
                .path()
                .ends_with("/realms/mcpdef/protocol/openid-connect/auth"),
            "{}\n{}",
            page.body,
            self.trail()
        );
        if saml {
            let to = page.url.join(&link(&page.body, "social-corp")).unwrap();
            page = self.go(Method::GET, to, None, None).await;
            assert!(
                page.url.path().starts_with("/realms/corp/"),
                "not at corp: {}\n{}",
                page.url,
                self.trail()
            );
        }
        let login = page.form("login-actions/authenticate");
        let to = page.url.join(&login.action).unwrap();
        let credentials = vec![
            ("username".to_string(), user.to_string()),
            ("password".to_string(), user.to_string()),
            ("credentialId".to_string(), String::new()),
        ];
        self.go(Method::POST, to, Some(credentials), alter).await
    }

    /// Signing out as the console's button does: `POST /logout`, then where
    /// it says, confirming at Keycloak, which asks when a request to sign out
    /// carries no ID token. The page they end on.
    async fn sign_out(&mut self, gw: &Gateway) -> Page {
        let (status, said) = self.post(gw, "/logout", &gw.base, "same-origin").await;
        assert_eq!(status, 200, "{said}");
        let to = said["redirect"].as_str().unwrap().to_string();
        let asked = self.get(&to).await;
        let confirm = asked.form("logout-confirm");
        let to = asked.url.join(&confirm.action).unwrap();
        self.go(Method::POST, to, Some(confirm.fields), None).await
    }

    /// `GET` an admin API route, as the console's script does.
    async fn api(&mut self, gw: &Gateway, route: &str) -> (u16, Value) {
        let url = url::Url::parse(&format!("{}/api/v1{route}", gw.base)).unwrap();
        let (page, _) = self
            .send(Method::GET, url, None, &[("accept", "application/json")])
            .await;
        (
            page.status,
            serde_json::from_str(&page.body).unwrap_or(Value::Null),
        )
    }

    /// `POST` to `route` from a page of `origin`, the browser saying how it
    /// stands to the console's (`Sec-Fetch-Site`).
    async fn post(&mut self, gw: &Gateway, route: &str, origin: &str, site: &str) -> (u16, Value) {
        let url = url::Url::parse(&format!("{}{route}", gw.base)).unwrap();
        let headers = [
            ("accept", "application/json"),
            ("origin", origin),
            ("sec-fetch-site", site),
        ];
        let (page, _) = self.send(Method::POST, url, None, &headers).await;
        (
            page.status,
            serde_json::from_str(&page.body).unwrap_or(Value::Null),
        )
    }
}

/// Each `<form>` of `html`, and its `<input>`s.
fn forms(html: &str) -> Vec<Form> {
    let mut found = Vec::new();
    let mut rest = html;
    while let Some(at) = rest.find("<form") {
        rest = &rest[at..];
        let tag_end = rest.find('>').unwrap_or(rest.len());
        let tag = &rest[..tag_end];
        let end = rest.find("</form>").unwrap_or(rest.len());
        let body = &rest[tag_end..end];
        let mut fields = Vec::new();
        let mut inputs = body;
        while let Some(at) = inputs.find("<input") {
            inputs = &inputs[at..];
            let input_end = inputs.find('>').unwrap_or(inputs.len());
            let input = &inputs[..input_end];
            if let Some(name) = attribute(input, "name") {
                fields.push((name, attribute(input, "value").unwrap_or_default()));
            }
            inputs = &inputs[input_end..];
        }
        found.push(Form {
            action: attribute(tag, "action").unwrap_or_default(),
            fields,
        });
        rest = &rest[end..];
        if rest.starts_with("</form>") {
            rest = &rest["</form>".len()..];
        }
    }
    found
}

/// The `href` of the element whose `id` is `id`.
fn link(html: &str, id: &str) -> String {
    let at = html
        .find(&format!("id=\"{id}\""))
        .unwrap_or_else(|| panic!("no #{id} on the page: {html}"));
    let start = html[..at].rfind('<').unwrap();
    let end = at + html[at..].find('>').unwrap();
    attribute(&html[start..end], "href").unwrap_or_else(|| panic!("#{id} links nowhere"))
}

/// The value of the attribute `name` of `tag`, unescaped.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let mut from = 0;
    while let Some(at) = tag[from..].find(&needle) {
        let at = from + at;
        let before = tag[..at].chars().last();
        if before.is_some_and(char::is_whitespace) {
            let value = &tag[at + needle.len()..];
            return value.find('"').map(|end| unescape(&value[..end]));
        }
        from = at + needle.len();
    }
    None
}

/// HTML's character references, as they are in attributes.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let Some(end) = rest.find(';').filter(|end| *end <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|n| n.parse().ok()))
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// A record, as `records` gives it.
fn record(
    actor: &str,
    action: &str,
    decision: &str,
    rule: Option<&str>,
) -> (String, String, String, Option<String>) {
    (
        actor.to_string(),
        action.to_string(),
        decision.to_string(),
        rule.map(str::to_string),
    )
}

/// That `user` signed in to the console in `role`, under `name`, as
/// `actor`, on the page they began from.
async fn signed_in(
    browser: &mut Browser,
    gw: &Gateway,
    page: &Page,
    actor: &str,
    name: &str,
    role: &str,
) {
    assert_eq!(
        (page.status, page.url.as_str()),
        (200, format!("{}/#servers", gw.base).as_str()),
        "{}\n{}",
        browser.trail(),
        gw.log()
    );
    let (status, session) = browser.api(gw, "/session").await;
    assert_eq!(status, 200, "{session}");
    assert_eq!(session["actor"], actor, "{session}");
    assert_eq!(session["name"], name, "{session}");
    assert_eq!(session["role"], role, "{session}");
    assert_eq!(session["sign_out"], "/logout", "{session}");
}

/// Who the console takes a browser holding no cookie but the session cookie
/// `sealed` to be: as a cookie copied off someone's machine is sent.
async fn replayed(gw: &Gateway, sealed: &str) -> Value {
    let mut copied = Browser::new();
    let at = url::Url::parse(&gw.base).unwrap();
    copied.jar.entry(Browser::origin(&at)).or_default().insert(
        ("/".to_string(), SESSION_COOKIE.to_string()),
        sealed.to_string(),
    );
    let (status, session) = copied.api(gw, "/session").await;
    assert_eq!(status, 200, "{session}");
    session
}

/// That `nobody` was shown the claims MCPdef received of them, and given no
/// session.
async fn shown_no_role(browser: &mut Browser, gw: &Gateway, page: &Page, subject: &str) {
    assert_eq!(page.status, 403, "{}\n{}", page.body, browser.trail());
    assert!(page.url.path() == "/callback", "{}", page.url);
    assert!(page.body.contains("No console role"), "{}", page.body);
    assert!(page.body.contains(subject), "{}", page.body);
    assert!(!browser.has_cookie(SESSION_COOKIE));
    let (_, session) = browser.api(gw, "/session").await;
    assert_eq!(session["actor"], "anonymous", "{session}");
}

/// People of the `mcpdef` realm, signed in at Keycloak by the config
/// `mcpdef sso init --provider keycloak` writes: the console roles are the
/// client's roles, given to groups.
#[tokio::test]
async fn people_sign_in_at_keycloak_act_and_sign_out() {
    let Some(keycloak) = keycloak() else {
        return;
    };
    let gw = Gateway::start(&keycloak, "keycloak").await;

    let mut admin = Browser::new();
    let page = admin.sign_in(&gw, "ops-admin", false).await;
    signed_in(
        &mut admin,
        &gw,
        &page,
        "user:ops-admin",
        "Ada Admin",
        "console:admin",
    )
    .await;
    // The admin sees how the console signs people in: the provider found.
    let (status, identity) = admin.api(&gw, "/identity").await;
    assert_eq!(status, 200, "{identity}");
    assert_eq!(identity["console"]["provider"]["found"], true, "{identity}");
    assert_eq!(
        identity["console"]["provider"]["sends_iss"], true,
        "{identity}"
    );

    // An operator reloads; from a page of another origin, nothing is done.
    let mut operator = Browser::new();
    let page = operator.sign_in(&gw, "ops-operator", false).await;
    signed_in(
        &mut operator,
        &gw,
        &page,
        "user:ops-operator",
        "Otto Operator",
        "console:operator",
    )
    .await;
    let (status, reload) = operator
        .post(&gw, "/api/v1/reload", &gw.base, "same-origin")
        .await;
    assert_eq!(
        (status, &reload["outcome"]),
        (200, &Value::from("applied")),
        "{reload}"
    );
    for (origin, site) in [
        ("https://evil.example", "cross-site"),
        ("https://evil.example", ""),
    ] {
        let (status, refused) = operator.post(&gw, "/api/v1/reload", origin, site).await;
        assert_eq!(status, 403, "{refused}");
        assert_eq!(
            refused["title"], "Cross-origin request refused",
            "{refused}"
        );
    }

    // A viewer looks, and may not reload.
    let mut viewer = Browser::new();
    let page = viewer.sign_in(&gw, "ops-viewer", false).await;
    signed_in(
        &mut viewer,
        &gw,
        &page,
        "user:ops-viewer",
        "Val Viewer",
        "console:viewer",
    )
    .await;
    let (status, servers) = viewer.api(&gw, "/servers").await;
    assert_eq!(status, 200, "{servers}");
    let (status, refused) = viewer
        .post(&gw, "/api/v1/reload", &gw.base, "same-origin")
        .await;
    assert_eq!(status, 403, "{refused}");

    // Someone in no group.
    let mut nobody = Browser::new();
    let page = nobody.sign_in(&gw, "ops-nobody", false).await;
    shown_no_role(&mut nobody, &gw, &page, "ops-nobody").await;

    // Signing out ends the session, and Keycloak's: signing in again asks.
    // Its cookie, kept from before and sent again, opens nothing either.
    let kept = admin.cookie(SESSION_COOKIE).unwrap();
    assert_eq!(replayed(&gw, &kept).await["actor"], "user:ops-admin");
    let page = admin.sign_out(&gw).await;
    assert_eq!(
        page.url.as_str(),
        format!("{}/", gw.base),
        "{}",
        admin.trail()
    );
    let (_, session) = admin.api(&gw, "/session").await;
    assert_eq!(session["actor"], "anonymous", "{session}");
    assert_eq!(replayed(&gw, &kept).await["actor"], "anonymous");
    let again = admin.get(&format!("{}/login", gw.base)).await;
    assert!(
        again.has_form("login-actions/authenticate"),
        "Keycloak signed them in again without a password\n{}",
        admin.trail()
    );

    let records = gw.records();
    for expected in [
        record("user:ops-admin", "sign-in", "allow", None),
        record("user:ops-operator", "sign-in", "allow", None),
        record("user:ops-operator", "reload", "allow", None),
        record("user:ops-viewer", "sign-in", "allow", None),
        record("user:ops-viewer", "reload", "deny", Some("console-role")),
        record(
            "user:ops-nobody",
            "sign-in",
            "deny",
            Some("no-console-role"),
        ),
        record("user:ops-admin", "sign-out", "allow", None),
    ] {
        assert!(
            records.contains(&expected),
            "{expected:?} not in {records:#?}"
        );
    }
    // The reloads from another origin did nothing: one reload was done.
    let done = records
        .iter()
        .filter(|r| r.1 == "reload" && r.2 == "allow")
        .count();
    assert_eq!(done, 1, "{records:#?}");
}

/// People of the SAML identity provider `corp`, signing in through the
/// `mcpdef` realm as its broker, by the config `mcpdef sso init --provider
/// saml-broker` writes: the console roles are mapped from their groups.
#[tokio::test]
async fn saml_users_sign_in_through_keycloak_as_their_broker() {
    let Some(keycloak) = keycloak() else {
        return;
    };
    let gw = Gateway::start(&keycloak, "saml-broker").await;

    let mut admin = Browser::new();
    let page = admin.sign_in(&gw, "saml-admin", true).await;
    signed_in(
        &mut admin,
        &gw,
        &page,
        "user:saml-admin@corp.example",
        "Sam Admin",
        "console:admin",
    )
    .await;

    let mut operator = Browser::new();
    let page = operator.sign_in(&gw, "saml-operator", true).await;
    signed_in(
        &mut operator,
        &gw,
        &page,
        "user:saml-operator@corp.example",
        "Oli Operator",
        "console:operator",
    )
    .await;
    let (status, reload) = operator
        .post(&gw, "/api/v1/reload", &gw.base, "same-origin")
        .await;
    assert_eq!(
        (status, &reload["outcome"]),
        (200, &Value::from("applied")),
        "{reload}"
    );
    let (status, refused) = operator
        .post(&gw, "/api/v1/reload", "https://evil.example", "cross-site")
        .await;
    assert_eq!(status, 403, "{refused}");

    let mut viewer = Browser::new();
    let page = viewer.sign_in(&gw, "saml-viewer", true).await;
    signed_in(
        &mut viewer,
        &gw,
        &page,
        "user:saml-viewer@corp.example",
        "Sal Viewer",
        "console:viewer",
    )
    .await;
    let (status, refused) = viewer
        .post(&gw, "/api/v1/reload", &gw.base, "same-origin")
        .await;
    assert_eq!(status, 403, "{refused}");

    let mut nobody = Browser::new();
    let page = nobody.sign_in(&gw, "saml-nobody", true).await;
    shown_no_role(&mut nobody, &gw, &page, "saml-nobody@corp.example").await;

    // A viewer's SAML response, altered on its way to the broker to put them
    // in the admins' group: the broker finds the signature no longer the
    // identity provider's, and nobody is signed in.
    let mut forger = Browser::new();
    let promote: Alter = Box::new(|xml: &str| {
        assert!(xml.contains("mcpdef-viewers"), "no group to alter in {xml}");
        xml.replace("mcpdef-viewers", "mcpdef-admins")
    });
    let page = forger
        .signing_in(&gw, "saml-viewer", true, Some(&promote))
        .await;
    assert_eq!(page.status, 400, "{}\n{}", page.body, forger.trail());
    assert!(
        page.url
            .path()
            .ends_with("/realms/mcpdef/broker/corp/endpoint"),
        "{}",
        page.url
    );
    assert!(page.body.contains("Invalid signature"), "{}", page.body);
    assert!(!forger.has_cookie(SESSION_COOKIE));

    // Signing out, of both realms: corp asks for a password again. The
    // session's cookie, sent again, opens nothing.
    let kept = admin.cookie(SESSION_COOKIE).unwrap();
    let page = admin.sign_out(&gw).await;
    assert_eq!(replayed(&gw, &kept).await["actor"], "anonymous");
    assert_eq!(
        page.url.as_str(),
        format!("{}/", gw.base),
        "{}",
        admin.trail()
    );
    assert!(
        admin
            .trail
            .iter()
            .any(|step| step.contains("/realms/corp/protocol/saml")),
        "corp was not asked to sign them out\n{}",
        admin.trail()
    );
    let (_, session) = admin.api(&gw, "/session").await;
    assert_eq!(session["actor"], "anonymous", "{session}");
    let again = admin.get(&format!("{}/login", gw.base)).await;
    let to = again.url.join(&link(&again.body, "social-corp")).unwrap();
    let at_corp = admin.go(Method::GET, to, None, None).await;
    assert!(
        at_corp.url.path().starts_with("/realms/corp/")
            && at_corp.has_form("login-actions/authenticate"),
        "corp signed them in again without a password\n{}",
        admin.trail()
    );

    let records = gw.records();
    for expected in [
        record("user:saml-admin@corp.example", "sign-in", "allow", None),
        record("user:saml-operator@corp.example", "sign-in", "allow", None),
        record("user:saml-operator@corp.example", "reload", "allow", None),
        record("user:saml-viewer@corp.example", "sign-in", "allow", None),
        record(
            "user:saml-viewer@corp.example",
            "reload",
            "deny",
            Some("console-role"),
        ),
        record(
            "user:saml-nobody@corp.example",
            "sign-in",
            "deny",
            Some("no-console-role"),
        ),
        record("user:saml-admin@corp.example", "sign-out", "allow", None),
    ] {
        assert!(
            records.contains(&expected),
            "{expected:?} not in {records:#?}"
        );
    }
    // The altered response reached MCPdef never: one sign-in by the viewer.
    let viewer_sign_ins = records
        .iter()
        .filter(|r| r.0 == "user:saml-viewer@corp.example" && r.1 == "sign-in")
        .count();
    assert_eq!(viewer_sign_ins, 1, "{records:#?}");
}

#[test]
fn forms_links_and_attributes_are_read_as_keycloak_writes_them() {
    let page = r#"<form id="kc-form-login" onsubmit="x" action="http://kc/realms/r/login-actions/authenticate?session_code=a&amp;tab_id=b" method="post">
        <input id="username" name="username" value="" type="text" autofocus>
        <input type="hidden" id="id-hidden-input" name="credentialId" />
      </form>
      <a data-once-link id="social-corp"
         type="button" href="/realms/r/broker/corp/login?client_id=c&amp;tab_id=b">Corp</a>
      <form name="saml-post-binding" method="post" action="http://kc/realms/r/broker/corp/endpoint">
        <input type="hidden" name="SAMLResponse" value="PHg+&#43;/="/>
        <input type="hidden" name="RelayState" value="r&#x26;s"/>
      </form>"#;
    let found = forms(page);
    assert_eq!(found.len(), 2);
    assert_eq!(
        found[0].action,
        "http://kc/realms/r/login-actions/authenticate?session_code=a&tab_id=b"
    );
    assert_eq!(
        found[0].fields,
        [
            ("username".to_string(), String::new()),
            ("credentialId".to_string(), String::new())
        ]
    );
    assert_eq!(
        found[1].fields,
        [
            ("SAMLResponse".to_string(), "PHg++/=".to_string()),
            ("RelayState".to_string(), "r&s".to_string())
        ]
    );
    assert_eq!(
        link(page, "social-corp"),
        "/realms/r/broker/corp/login?client_id=c&tab_id=b"
    );
    // `id` is not `data-id`, nor `name` `data-name`.
    assert_eq!(
        attribute(r#"<a data-id="x" id="y">"#, "id").as_deref(),
        Some("y")
    );
    assert_eq!(attribute(r#"<input data-name="x">"#, "name"), None);
    assert_eq!(
        unescape("a &amp b &lt;c&gt; &#65;&#x42; &unknown;"),
        "a &amp b <c> AB &unknown;"
    );
}

#[test]
fn a_cookie_jar_keeps_cookies_by_path_and_name() {
    let mut browser = Browser::new();
    let at = |url: &str| url::Url::parse(url).unwrap();
    let mut set = HeaderMap::new();
    set.append(
        header::SET_COOKIE,
        "AUTH_SESSION_ID=b; Path=/realms/mcpdef/; HttpOnly"
            .parse()
            .unwrap(),
    );
    browser.keep(&at("http://localhost:8080/realms/mcpdef/x"), &set);
    let mut set = HeaderMap::new();
    set.append(
        header::SET_COOKIE,
        "AUTH_SESSION_ID=a; Path=/realms/corp/".parse().unwrap(),
    );
    set.append(
        header::SET_COOKIE,
        "KC_RESTART=r; Path=/realms/corp/".parse().unwrap(),
    );
    browser.keep(&at("http://localhost:8080/realms/corp/x"), &set);
    assert_eq!(
        browser
            .cookies(&at(
                "http://localhost:8080/realms/mcpdef/broker/corp/endpoint"
            ))
            .as_deref(),
        Some("AUTH_SESSION_ID=b")
    );
    assert_eq!(
        browser
            .cookies(&at("http://localhost:8080/realms/corp/protocol/saml"))
            .as_deref(),
        Some("AUTH_SESSION_ID=a; KC_RESTART=r")
    );
    // Another port is another jar; `/realms/corpx` is not under `/realms/corp/`.
    assert_eq!(
        browser.cookies(&at("http://localhost:8081/realms/corp/")),
        None
    );
    assert_eq!(
        browser.cookies(&at("http://localhost:8080/realms/corpx/")),
        None
    );
    // An expired cookie is dropped.
    let mut set = HeaderMap::new();
    set.append(
        header::SET_COOKIE,
        "KC_RESTART=; Path=/realms/corp/; Max-Age=0"
            .parse()
            .unwrap(),
    );
    browser.keep(&at("http://localhost:8080/realms/corp/x"), &set);
    assert_eq!(
        browser
            .cookies(&at("http://localhost:8080/realms/corp/protocol/saml"))
            .as_deref(),
        Some("AUTH_SESSION_ID=a")
    );
    assert!(browser.has_cookie("AUTH_SESSION_ID"));
    assert!(!browser.has_cookie("KC_RESTART"));
}
