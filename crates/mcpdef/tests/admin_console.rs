// SPDX-License-Identifier: Apache-2.0
//! The console, as the admin listener serves it from `mcpdef-console`:
//!   * `/` is its page, never cached without asking again, and loads its
//!     scripts and styles from files of their own;
//!   * each file comes in the encoding the client prefers of those it has
//!     (brotli, then gzip), with `Vary: accept-encoding`, and is kept for
//!     good when its name changes with its content;
//!   * a client holding a file's entity tag gets `304`;
//!   * a file that is not there is a problem document, not the page.
#![cfg(feature = "console")]

use mcpdef::connect::build_gateway;
use mcpdef::{serve_admin_on, AdminState, Config, Metrics};
use std::io::Read;
use std::sync::Arc;

const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

/// An open admin listener over the stdio mock, on a loopback port.
async fn serve(dir: &std::path::Path) -> (String, tokio::task::JoinHandle<()>) {
    let text = format!(
        "[gateway]\naudit = {audit:?}\nstate_dir = {state:?}\n\n\
         [gateway.admin]\nenabled = true\nlisten = \"127.0.0.1:0\"\n\n\
         [[server]]\nid = \"mock\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\n",
        audit = dir.join("audit.log"),
        state = dir.join("state"),
    );
    let cfg = Config::parse(&text).unwrap();
    let gw = build_gateway(&cfg).await.unwrap();
    let state = Arc::new(AdminState::new(&cfg, Arc::new(Metrics::new(1)), gw, "test"));
    let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", bound.local_addr().unwrap());
    let serving = tokio::spawn(async move {
        serve_admin_on(state, bound, None).await.unwrap();
    });
    (base, serving)
}

/// A client that asks for exactly the encodings a test names, and decodes none.
fn client() -> reqwest::Client {
    mcpdef_transport::install_crypto_provider();
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// The page's script, as the page names it.
fn script(page: &str) -> String {
    let src = page.split("<script").nth(1).unwrap();
    let src = src.split(" src=\"").nth(1).unwrap();
    src[..src.find('"').unwrap()].to_string()
}

#[tokio::test]
async fn the_console_is_served_compressed_tagged_and_cached_as_its_names_allow() {
    let dir = tempfile::tempdir().unwrap();
    let (base, serving) = serve(dir.path()).await;
    let client = client();

    let page = client.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(page.status(), 200);
    assert_eq!(page.headers()["content-type"], "text/html; charset=utf-8");
    assert_eq!(page.headers()["cache-control"], "no-cache");
    assert!(page.headers().contains_key("etag"));
    let page = page.text().await.unwrap();
    assert!(page.contains("<div id=\"root\"></div>"), "{page}");
    let script = format!("{base}{}", script(&page));
    assert!(script.contains("/assets/index-"), "{script}");

    // As the file was built, then each encoding, the preferred first.
    let plain = client.get(&script).send().await.unwrap();
    assert_eq!(plain.headers().get("content-encoding"), None);
    assert_eq!(plain.headers()["vary"], "accept-encoding");
    assert_eq!(
        plain.headers()["cache-control"],
        "public, max-age=31536000, immutable"
    );
    let etag = plain.headers()["etag"].clone();
    let built = plain.bytes().await.unwrap();
    for (accept, coding) in [
        ("gzip, deflate, br", "br"),
        ("gzip", "gzip"),
        ("br;q=0, gzip", "gzip"),
    ] {
        let sent = client
            .get(&script)
            .header("accept-encoding", accept)
            .send()
            .await
            .unwrap();
        assert_eq!(sent.headers()["content-encoding"], coding, "{accept}");
        let body = sent.bytes().await.unwrap();
        assert!(body.len() < built.len(), "{accept}");
        if coding == "gzip" {
            let mut decoded = Vec::new();
            flate2_free_gunzip(&body, &mut decoded);
            assert_eq!(decoded, built, "{accept}");
        }
    }

    // A client that holds it is told so, and sent nothing.
    let held = client
        .get(&script)
        .header("if-none-match", etag.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(held.status(), 304);
    assert_eq!(held.headers()["etag"], etag);
    assert!(held.bytes().await.unwrap().is_empty());

    // HEAD: the headers alone.
    let head = client.head(&script).send().await.unwrap();
    assert_eq!(head.status(), 200);
    assert_eq!(head.headers()["etag"], etag);

    // Not there: a problem, not the page.
    let missing = client
        .get(format!("{base}/assets/nothing.js"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    assert_eq!(
        missing.headers()["content-type"],
        "application/problem+json"
    );
    serving.abort();
}

/// Decode a gzip member with the standard library alone: the stored and
/// fixed-Huffman blocks a test can check are not worth a dependency, so this
/// shells out to `gzip -dc`, which every CI image has.
fn flate2_free_gunzip(body: &[u8], out: &mut Vec<u8>) {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("gzip")
        .arg("-dc")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("gzip on the PATH");
    child.stdin.take().unwrap().write_all(body).unwrap();
    child.stdout.take().unwrap().read_to_end(out).unwrap();
    assert!(child.wait().unwrap().success());
}
