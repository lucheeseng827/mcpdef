// SPDX-License-Identifier: Apache-2.0
//! The gateway's own listener over TLS (`[gateway.tls]`), end to end.
//!
//! First, the quick start's scripted half, with TLS: from a config and a
//! clean state directory to a governed call over HTTPS, through `mcpdef tls
//! init`, `mcpdef connect claude-code` and `mcpdef run --http`, the binary
//! itself, with a client that reaches the URL `connect` wrote into
//! `.mcp.json` and trusts the CA it said to, and nothing else. Then what that
//! stands on: a certificate from files, a handshake that stalls, a
//! certificate renewed in its files and swapped in by a reload (and one that
//! does not read, refused), a self-signed one issued again when it is due,
//! and the CA that stays put until it is replaced on purpose.

use mcpdef::connect::build_gateway;
use mcpdef::listener::serve_https_on;
use mcpdef::reload::{Outcome, Reloader, Snapshot, Trigger};
use mcpdef::tls::local_ca::{LocalCa, Names, Paths};
use mcpdef::tls::{ListenerTls, Serving, TlsListener};
use mcpdef::{Config, HttpConfig};
use mcpdef_core::wire::WireMode;
use mcpdef_testkit::{listening_port, Pki};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");
const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

/// The first line in `log` with `text` in it, once there is one.
async fn line_with(log: &Mutex<Vec<String>>, text: &str) -> String {
    let until = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(line) = log.lock().unwrap().iter().find(|l| l.contains(text)) {
            return line.clone();
        }
        assert!(
            Instant::now() < until,
            "no line with {text:?}: {:#?}",
            log.lock().unwrap()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Kills the gateway however the test ends.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// What the binary run with `args` wrote, stdout and stderr together, and
/// whether it succeeded.
fn mcpdef(args: &[&str]) -> (String, bool) {
    let out = Command::new(BIN).args(args).output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (text, out.status.success())
}

/// A client that trusts `ca`, a PEM certificate, and nothing else, and
/// keeps what each connection's TLS was.
fn trusting(ca: &[u8]) -> reqwest::Client {
    mcpdef_transport::install_crypto_provider();
    let ca = reqwest::Certificate::from_pem(ca).unwrap();
    reqwest::Client::builder()
        .tls_certs_only([ca])
        .tls_info(true)
        .no_proxy()
        .build()
        .unwrap()
}

/// A POST of the JSON-RPC message `body` to `url`.
fn post(client: &reqwest::Client, url: &str, body: &Value) -> reqwest::RequestBuilder {
    client
        .post(url)
        .header("content-type", "application/json")
        .body(body.to_string())
}

/// A JSON-RPC request for `url`, answered.
async fn rpc(client: &reqwest::Client, url: &str, id: u64, method: &str, params: Value) -> Value {
    let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
    let resp = post(client, url, &body).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    serde_json::from_str(&resp.text().await.unwrap()).unwrap()
}

/// The certificate the server at `url` served the connection that answered.
async fn served(client: &reqwest::Client, url: &str) -> Vec<u8> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    let resp = post(client, url, &body).send().await.unwrap();
    resp.extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|tls: &reqwest::tls::TlsInfo| tls.peer_certificate())
        .expect("the connection's certificate")
        .to_vec()
}

fn initialize() -> Value {
    json!({
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": { "name": "listener-tls", "version": "0" }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn from_a_clean_state_to_a_governed_call_over_https_in_under_a_minute() {
    use std::io::BufRead;
    let started = Instant::now();
    let dir = tempfile::tempdir().unwrap();
    // The listener's port: `connect` writes it into the client's config
    // before the gateway runs, so it is held now and let go just before the
    // gateway binds it. The admin listener's is the system's to give.
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = held.local_addr().unwrap().port();
    let audit = dir.path().join("audit.log");
    let config = format!(
        "[gateway]\nlisten = \"127.0.0.1:{listen}\"\naudit = {audit:?}\nstate_dir = {state:?}\n\n\
         [gateway.tls]\nmode = \"self-signed\"\n\n\
         [gateway.admin]\nenabled = true\nlisten = \"127.0.0.1:0\"\n\n\
         [[server]]\nid = \"mock\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\n\
         tools = [\"echo\"]\n",
        state = dir.path().join("state"),
    );
    let path = dir.path().join("mcpdef.toml");
    std::fs::write(&path, config).unwrap();
    let path = path.to_str().unwrap();

    // The CA, the certificate it issues the listener, and how each client
    // comes to trust the CA.
    let (init, ok) = mcpdef(&["tls", "init", "--config", path]);
    assert!(ok, "{init}");
    let reach = format!("https://127.0.0.1:{listen}/mcp");
    for says in [
        "made a local CA",
        "issued the listener certificate",
        "for localhost, 127.0.0.1, ::1",
        "export NODE_EXTRA_CA_CERTS=",
        "export CODEX_CA_CERTIFICATE=",
        "curl --cacert ",
        reach.as_str(),
    ] {
        assert!(init.contains(says), "{says:?}: {init}");
    }
    // Its mode is self-signed already: nothing more to do.
    assert!(!init.contains("Then set"), "{init}");

    // What Claude Code needs, as `mcpdef connect claude-code` gives it: the
    // entry, written into the project's `.mcp.json`, and the CA to trust,
    // said as the variable Claude Code reads.
    let (home, work) = (dir.path().join("home"), dir.path().join("work"));
    for made in [&home, &work] {
        std::fs::create_dir(made).unwrap();
    }
    let connected = Command::new(BIN)
        .args(["connect", "claude-code", "--write", "--config", path])
        .env("HOME", &home)
        .current_dir(&work)
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&connected.stdout).into_owned();
    assert!(connected.status.success(), "{said}{connected:?}");
    let project: Value =
        serde_json::from_str(&std::fs::read_to_string(work.join(".mcp.json")).unwrap()).unwrap();
    let entry = &project["mcpServers"]["mcpdef"];
    assert_eq!(entry["type"], json!("http"), "{project}");
    let url = entry["url"].as_str().unwrap().to_string();
    assert_eq!(url, reach);
    let ca = said
        .split("NODE_EXTRA_CA_CERTS=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no NODE_EXTRA_CA_CERTS: {said}"));
    // The CA's certificate, for the client: that alone, no key with it.
    let ca = std::fs::read(ca).unwrap();
    assert!(ca.starts_with(b"-----BEGIN CERTIFICATE-----"));
    assert!(!String::from_utf8_lossy(&ca).contains("PRIVATE"));

    drop(held);
    let mut child = Command::new(BIN)
        .args(["run", "--http", "--config", path])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let pid = child.id().to_string();
    let _running = Running(child);
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    {
        let log = Arc::clone(&log);
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr)
                .lines()
                .map_while(Result::ok)
            {
                log.lock().unwrap().push(line);
            }
        });
    }
    let ready = line_with(&log, " ready ").await;
    let admin = listening_port(&line_with(&log, "admin/metrics UI on ").await, "UI on ");
    assert!(
        ready.contains(&format!(
            "streamable-http 127.0.0.1:{listen} · tls self-signed"
        )),
        "{ready}"
    );
    // The CA and the certificate `tls init` made were kept.
    assert!(
        !log.lock().unwrap().iter().any(|l| l.contains("made a local CA")
            || l.contains("issued the listener certificate")),
        "{:#?}",
        log.lock().unwrap()
    );

    // A client that trusts the CA it was told to, and nothing else, at the
    // URL in its `.mcp.json`.
    let client = trusting(&ca);
    let opened = rpc(&client, &url, 1, "initialize", initialize()).await;
    assert!(opened["result"]["serverInfo"].is_object(), "{opened}");
    let echoed = rpc(
        &client,
        &url,
        2,
        "tools/call",
        json!({ "name": "echo", "arguments": { "q": "over tls" } }),
    )
    .await;
    assert_eq!(echoed["result"]["isError"], json!(false), "{echoed}");
    assert_eq!(
        echoed["result"]["content"][0]["text"],
        json!("echo: {\"q\":\"over tls\"}")
    );
    let denied = rpc(
        &client,
        &url,
        3,
        "tools/call",
        json!({ "name": "delete_repo", "arguments": {} }),
    )
    .await;
    assert_eq!(denied["result"]["isError"], json!(true), "{denied}");
    // By the name every client on this machine has for it, too.
    let local = format!("https://localhost:{listen}/mcp");
    let opened = rpc(&client, &local, 4, "initialize", initialize()).await;
    assert!(opened["result"]["serverInfo"].is_object(), "{opened}");
    // The admin listener takes the listener's TLS.
    let status = client
        .get(format!("https://127.0.0.1:{admin}/api/v1/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(status.status(), 200);

    // Governed: the ledger holds both calls, each decided.
    let ledger = std::fs::read_to_string(&audit).unwrap();
    let decisions: Vec<String> = ledger
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|r| r["method"] == json!("tools/call"))
        .map(|r| r["decision"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(decisions, ["allow", "deny"]);
    let governed = started.elapsed();

    // A client that does not trust the CA is refused, and so is plain HTTP.
    mcpdef_transport::install_crypto_provider();
    let stranger = reqwest::Client::builder().no_proxy().build().unwrap();
    let body = json!({ "jsonrpc": "2.0", "id": 5, "method": "ping" });
    let refused = post(&stranger, &url, &body).send().await.unwrap_err();
    assert!(
        format!("{refused:?}").contains("UnknownIssuer"),
        "{refused:?}"
    );
    let plain = format!("http://127.0.0.1:{listen}/mcp");
    assert!(post(&stranger, &plain, &body).send().await.is_err());

    // What it serves, as `tls show` says it.
    let (show, ok) = mcpdef(&["tls", "show", "--config", path]);
    assert!(ok, "{show}");
    for says in [
        "tls          : self-signed",
        "names        : DNS:localhost, IP:127.0.0.1, IP:::1",
        "issuer       : MCPdef local CA ",
        "client certs : not asked for",
        "tls          : the listener's",
        "local CA (",
    ] {
        assert!(show.contains(says), "{says:?}: {show}");
    }
    assert!(!show.contains("warnings:"), "{show}");

    // A name the CA was not made for, at a SIGHUP: the reload is refused,
    // saying why and what to run, and the gateway serves on as it was.
    std::fs::write(
        path,
        std::fs::read_to_string(path).unwrap().replace(
            "mode = \"self-signed\"",
            "mode = \"self-signed\"\nhostnames = [\"mcpdef.internal\"]",
        ),
    )
    .unwrap();
    let hup = Command::new("kill").args(["-HUP", &pid]).status().unwrap();
    assert!(hup.success());
    let until = Instant::now() + Duration::from_secs(10);
    let refused = loop {
        let refused = log
            .lock()
            .unwrap()
            .iter()
            .find(|l| l.contains("config reload refused"))
            .cloned();
        if let Some(refused) = refused {
            break refused;
        }
        assert!(
            Instant::now() < until,
            "no reload: {:#?}",
            log.lock().unwrap()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(
        refused.contains("(sighup), invalid-config: ")
            && refused.contains("and not for mcpdef.internal:")
            && refused.contains("mcpdef tls init --new-ca"),
        "{refused}"
    );
    let opened = rpc(&client, &url, 6, "initialize", initialize()).await;
    assert!(opened["result"]["serverInfo"].is_object(), "{opened}");

    // Under a minute: the scripted half of the quick start with TLS.
    eprintln!("from a clean state to a governed call over HTTPS: {governed:?}");
    assert!(governed < Duration::from_secs(60), "{governed:?}");
}

/// A gateway over the stdio mock, its listener on TLS as `tls` says, served
/// on a loopback port, with a reloader for its config.
struct Served {
    url: String,
    dir: PathBuf,
    path: PathBuf,
    reloader: Reloader,
    /// What the listener serves, shared with the reloader.
    tls: ListenerTls,
    _serving: Aborted,
}

/// A task stopped however the test ends.
struct Aborted(tokio::task::JoinHandle<()>);

impl Drop for Aborted {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The config of a gateway over the mock, with `tls` as its `[gateway.tls]`
/// and its state under `dir`.
fn config_text(dir: &Path, tls: &str) -> String {
    format!(
        "[gateway]\naudit = {audit:?}\nstate_dir = {state:?}\n\n[gateway.tls]\n{tls}\n\n\
         [[server]]\nid = \"mock\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\n\
         tools = [\"echo\"]\n",
        audit = dir.join("audit.log"),
        state = dir.join("state"),
    )
}

impl Served {
    async fn start(dir: &Path, tls: &str) -> Served {
        Self::start_at(dir, tls, SystemTime::now()).await
    }

    /// Its TLS started as of `now`.
    async fn start_at(dir: &Path, tls: &str, now: SystemTime) -> Served {
        let path = dir.join("mcpdef.toml");
        std::fs::write(&path, config_text(dir, tls)).unwrap();
        let (cfg, text) = Config::load_text(&path).unwrap();
        assert_eq!(cfg.validate(), Vec::<String>::new());
        let snapshot = Snapshot::take(text.as_bytes(), &cfg);
        let serving = Serving {
            mcp: true,
            admin: false,
        };
        let (listener_tls, _) = ListenerTls::start_at(&cfg, serving, now).unwrap().unwrap();
        let gw = build_gateway(&cfg).await.unwrap();
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let http = HttpConfig {
            listen: addr.to_string(),
            allowed_origins: Vec::new(),
            max_inflight: None,
            wire: WireMode::default(),
        };
        let slot = listener_tls.mcp().unwrap();
        let serving = tokio::spawn({
            let gw = gw.clone();
            async move {
                serve_https_on(tcp, gw, http, None, slot).await.unwrap();
            }
        });
        let reloader =
            Reloader::new(&path, None, gw, cfg, snapshot).with_listener_tls(listener_tls.clone());
        Served {
            url: format!("https://127.0.0.1:{}/mcp", addr.port()),
            dir: dir.to_path_buf(),
            path,
            reloader,
            tls: listener_tls,
            _serving: Aborted(serving),
        }
    }

    /// Change `[gateway.tls]` to `tls` in the config.
    fn rewrite(&self, tls: &str) {
        std::fs::write(&self.path, config_text(&self.dir, tls)).unwrap();
    }
}

#[tokio::test]
async fn a_certificate_from_files_is_served_and_a_renewed_one_from_the_next_connection_on() {
    let dir = tempfile::tempdir().unwrap();
    let pki = Pki::new("mcpdef test CA");
    let first = pki.server(&["127.0.0.1"]);
    let (cert, key) = first.write(dir.path(), "listener");
    let tls = format!("mode = \"files\"\ncert = {cert:?}\nkey = {{ file = {key:?} }}");
    let mut s = Served::start(dir.path(), &tls).await;
    let root = pki.root_pem().as_bytes().to_vec();
    let kept = trusting(&root);
    let opened = rpc(&kept, &s.url, 1, "initialize", initialize()).await;
    assert!(opened["result"]["serverInfo"].is_object(), "{opened}");
    assert_eq!(served(&kept, &s.url).await, first.cert_der().to_vec());
    // HTTP/1.1 is what it speaks, and what it settles on with a client that
    // would rather have HTTP/2.
    assert_eq!(alpn(&pki, &s.url).await.as_deref(), Some(&b"http/1.1"[..]));

    // Renewed in place, a new key with it, as cert-manager renews: a reload
    // serves it from the next connection on.
    let second = pki.server(&["127.0.0.1"]);
    second.write(dir.path(), "listener");
    let outcome = s.reloader.reload(Trigger::Signal).await;
    assert!(matches!(outcome, Outcome::Applied(_)), "{outcome:?}");
    assert_eq!(
        served(&trusting(&root), &s.url).await,
        second.cert_der().to_vec()
    );
    // A connection made before keeps the certificate it was accepted with.
    assert_eq!(served(&kept, &s.url).await, first.cert_der().to_vec());

    // A key that is not the certificate's: the reload is refused, and the
    // certificate before it serves on.
    std::fs::write(&key, pki.server(&["127.0.0.1"]).key_pem()).unwrap();
    match s.reloader.reload(Trigger::Signal).await {
        Outcome::Refused { rule, reasons } => {
            assert_eq!(rule, "invalid-config");
            assert!(
                reasons[0].starts_with("[gateway.tls] key ")
                    && reasons[0].contains("does not match the certificate first in cert"),
                "{reasons:?}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        served(&trusting(&root), &s.url).await,
        second.cert_der().to_vec()
    );
    // Turning TLS off takes a restart: it changes every client's URL.
    s.rewrite("mode = \"off\"");
    match s.reloader.reload(Trigger::Signal).await {
        Outcome::Refused { rule, reasons } => {
            assert_eq!(rule, "restart-required");
            assert_eq!(reasons, ["[gateway.tls] mode (files → off) changed"]);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_self_signed_certificate_is_issued_again_when_due_under_the_same_ca() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = Served::start(dir.path(), "mode = \"self-signed\"").await;
    let paths = Paths::under(dir.path().join("state"));
    let ca = std::fs::read(paths.ca_cert()).unwrap();
    let first = served(&trusting(&ca), &s.url).await;

    // Not due: nothing changes, not even the configuration it is served
    // with.
    let before = s.tls.mcp().unwrap().load_full();
    s.reloader.renew_if_due(SystemTime::now()).await;
    assert!(Arc::ptr_eq(&before, &s.tls.mcp().unwrap().load_full()));
    assert_eq!(served(&trusting(&ca), &s.url).await, first);
    // Due, twenty-one days on: issued again, served from the next
    // connection on, and written where the gateway keeps it.
    let later = SystemTime::now() + Duration::from_secs(21 * 86_400);
    s.reloader.renew_if_due(later).await;
    mcpdef_transport::install_crypto_provider();
    // Valid from an hour before `later`, which no client's clock has
    // reached, so read without a check.
    let unchecked = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .tls_info(true)
        .no_proxy()
        .build()
        .unwrap();
    let renewed = served(&unchecked, &s.url).await;
    assert_ne!(renewed, first);
    let on_disk = std::fs::read(paths.cert()).unwrap();
    let on_disk = rustls::pki_types::pem::PemObject::from_pem_slice(&on_disk)
        .map(|der: rustls::pki_types::CertificateDer<'_>| der.to_vec())
        .unwrap();
    assert_eq!(renewed, on_disk);
    // By the CA the clients already trust.
    let local_ca = LocalCa::load(&paths).unwrap().unwrap();
    assert_eq!(local_ca.cert_der().to_vec(), ca_der(&ca));
    local_ca
        .check(&renewed.clone().into(), &Names::new([] as [&str; 0]), later)
        .unwrap();

    // A name the CA was not made for: the reload is refused, naming it and
    // the way out, and the certificate before it serves on.
    s.rewrite("mode = \"self-signed\"\nhostnames = [\"mcpdef.internal\"]");
    match s.reloader.reload(Trigger::Signal).await {
        Outcome::Refused { rule, reasons } => {
            assert_eq!(rule, "invalid-config");
            assert!(
                reasons[0].contains("and not for mcpdef.internal:")
                    && reasons[0].contains("mcpdef tls init --new-ca"),
                "{reasons:?}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(served(&unchecked, &s.url).await, renewed);
}

/// The application protocol a handshake with the server at `url` settles on,
/// for a client that offers HTTP/2 first, then HTTP/1.1.
async fn alpn(pki: &Pki, url: &str) -> Option<Vec<u8>> {
    let addr = url
        .trim_start_matches("https://")
        .trim_end_matches("/mcp")
        .to_string();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(pki.roots())
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
    let tls = connector.connect(name, tcp).await.unwrap();
    tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec)
}

#[tokio::test]
async fn a_running_gateway_issues_its_certificate_again_when_its_tick_finds_it_due() {
    let dir = tempfile::tempdir().unwrap();
    // Started as of twenty-five days ago: its certificate is due by now.
    let ago = SystemTime::now() - Duration::from_secs(25 * 86_400);
    let Served {
        url,
        reloader,
        _serving,
        ..
    } = Served::start_at(dir.path(), "mode = \"self-signed\"", ago).await;
    let paths = Paths::under(dir.path().join("state"));
    let ca = std::fs::read(paths.ca_cert()).unwrap();
    let first = served(&trusting(&ca), &url).await;
    // The loop `mcpdef run` runs, on a short tick.
    let running = Aborted(tokio::spawn(reloader.run(Duration::from_millis(50))));
    let until = Instant::now() + Duration::from_secs(10);
    let renewed = loop {
        let now = served(&trusting(&ca), &url).await;
        if now != first {
            break now;
        }
        assert!(Instant::now() < until, "not issued again");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    // Issued now, for thirty days, by the CA the clients trust.
    let expires = mcpdef_transport::PeerCertificate::read(&renewed)
        .not_after
        .unwrap();
    let in_29_days = SystemTime::now() + Duration::from_secs(29 * 86_400);
    let secs = in_29_days
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(expires > secs as i64, "{expires}");
    drop(running);
}

fn ca_der(pem: &[u8]) -> Vec<u8> {
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::CertificateDer::from_pem_slice(pem)
        .unwrap()
        .to_vec()
}

#[tokio::test]
async fn a_handshake_that_does_not_finish_in_time_holds_up_no_one_and_is_closed() {
    use tokio::io::AsyncReadExt;
    let pki = Pki::new("mcpdef test CA");
    let leaf = pki.server(&["127.0.0.1"]);
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(leaf.chain(), leaf.key_der())
    .unwrap();
    let slot = Arc::new(arc_swap::ArcSwap::from_pointee(mcpdef::tls::Served::from(
        config,
    )));
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let timeout = Duration::from_secs(3);
    let listener = TlsListener::with_handshake_timeout(tcp, slot, timeout).unwrap();
    let app = axum::Router::new().route("/", axum::routing::get(|| async { "served" }));
    let serving = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // A client that connects and says nothing, first.
    let silent_since = Instant::now();
    let mut silent = tokio::net::TcpStream::connect(addr).await.unwrap();
    // The next is served meanwhile, long before the silent one's time is
    // up: its handshake waits on no other.
    let url = format!("https://127.0.0.1:{}/", addr.port());
    let client = mcpdef_testkit::https_client(&pki, None);
    let body = client.get(&url).send().await.unwrap().text().await.unwrap();
    assert_eq!(body, "served");
    assert!(
        silent_since.elapsed() < timeout / 2,
        "{:?}",
        silent_since.elapsed()
    );
    // And the silent one is closed once its time is up, not before.
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(10), silent.read(&mut byte))
        .await
        .expect("closed within its time");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    assert!(
        silent_since.elapsed() >= timeout,
        "{:?}",
        silent_since.elapsed()
    );
    serving.abort();
}

#[test]
fn tls_init_keeps_its_ca_until_a_new_one_is_asked_for() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    // Its mode still off: the next step is said.
    std::fs::write(&path, config_text(dir.path(), "mode = \"off\"")).unwrap();
    let path = path.to_str().unwrap();
    let ca = || {
        let (pem, ok) = mcpdef(&["tls", "export-ca", "--config", path]);
        assert!(ok, "{pem}");
        pem
    };
    let (none, ok) = mcpdef(&["tls", "export-ca", "--config", path]);
    assert!(!ok);
    assert!(none.contains("there is no local CA in"), "{none}");

    let (init, ok) = mcpdef(&["tls", "init", "--config", path]);
    assert!(ok, "{init}");
    assert!(init.contains("made a local CA"), "{init}");
    assert!(
        init.contains("Then set [gateway.tls] mode = \"self-signed\""),
        "{init}"
    );
    let first = ca();
    // Again: the CA and its certificate are kept.
    let (again, ok) = mcpdef(&["tls", "init", "--config", path]);
    assert!(ok, "{again}");
    assert!(!again.contains("made a local CA"), "{again}");
    assert!(
        !again.contains("issued the listener certificate"),
        "{again}"
    );
    assert_eq!(ca(), first);
    // A new one only when asked for, and the certificate with it.
    let (renewed, ok) = mcpdef(&["tls", "init", "--config", path, "--new-ca"]);
    assert!(ok, "{renewed}");
    assert!(renewed.contains("made a new local CA"), "{renewed}");
    assert!(
        renewed.contains("issued the listener certificate"),
        "{renewed}"
    );
    assert_ne!(ca(), first);
    assert!(!renewed.contains("CRL"), "no CRL to write: {renewed}");

    // Once it has issued a client's certificate, a new CA writes its own
    // CRL, which the gateway's `crl` names.
    let out = dir.path().join("agent");
    let (issued, ok) = mcpdef(&[
        "tls",
        "issue",
        "--client",
        "ci-bot",
        "--out",
        out.to_str().unwrap(),
        "--config",
        path,
    ]);
    assert!(ok, "{issued}");
    let crl = dir.path().join("state/tls/ca.crl");
    let before = std::fs::read(&crl).unwrap();
    let (renewed, ok) = mcpdef(&["tls", "init", "--config", path, "--new-ca"]);
    assert!(ok, "{renewed}");
    assert!(renewed.contains("wrote the new CA's CRL"), "{renewed}");
    assert_ne!(std::fs::read(&crl).unwrap(), before);

    // Certificates from files need no CA.
    let files = config_text(
        dir.path(),
        "mode = \"files\"\ncert = \"/tls.crt\"\nkey = { file = \"/tls.key\" }",
    );
    std::fs::write(path, files).unwrap();
    let (refused, ok) = mcpdef(&["tls", "init", "--config", path]);
    assert!(!ok);
    assert!(
        refused.contains("[gateway.tls] mode is \"files\""),
        "{refused}"
    );
}
