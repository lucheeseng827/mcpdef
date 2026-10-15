// SPDX-License-Identifier: Apache-2.0
//! `mcpdef doctor`, through the real binary.
//!
//! - A gateway with nothing wrong has no problem, and exits 0.
//! - A server that does not start is a problem, and the others are still
//!   checked: one report, not a stop at the first failure.
//! - It keeps nothing a running gateway keeps: no ledger, no pin store, no
//!   state, wherever the config puts them.
//! - What a server offers and no list exposes is named, with what it was
//!   before 0.4.0.
//! - A tool two servers offer, which only running them shows, is named.
//! - The identity provider: its keys are fetched and counted, and a clock off
//!   by more than a token's times allow is a problem, either way.
//! - A config with errors stops at them.

use axum::http::header;
use axum::{routing::get, Router};
use std::process::Output;
use std::time::{Duration, SystemTime};

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");
const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");
const TEST_JWKS: &str = include_str!("../../mcpdef-auth/src/testdata/test_jwks.json");

/// A config in a directory of its own, with its ledger, pin store and state
/// beside it.
struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new(rest: &str) -> Fixture {
        let root = tempfile::tempdir().unwrap();
        let config = format!(
            "[gateway]\naudit = {audit:?}\nstate_dir = {state:?}\npins = {pins:?}\n{rest}",
            audit = root.path().join("audit.log"),
            state = root.path().join("state"),
            pins = root.path().join("pins.toml"),
        );
        std::fs::write(root.path().join("mcpdef.toml"), config).unwrap();
        Fixture { root }
    }

    async fn doctor(&self) -> Output {
        tokio::process::Command::new(BIN)
            .args(["doctor", "--wait", "20", "--config"])
            .arg(self.root.path().join("mcpdef.toml"))
            .env("HOME", self.root.path())
            .current_dir(self.root.path())
            .output()
            .await
            .unwrap()
    }
}

/// The report, and what went to stderr after it, for a failed assertion.
fn report(out: &Output) -> String {
    format!(
        "{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The mock server as `[[server]] id`, its `echo` allowed, run with `flags`.
fn mock(id: &str, flags: &[&str]) -> String {
    let mut command = vec![format!("{MOCK:?}")];
    command.extend(flags.iter().map(|f| format!("{f:?}")));
    format!(
        "\n[[server]]\nid = \"{id}\"\ntransport = \"stdio\"\ncommand = [{}]\ntools = [\"echo\"]\n",
        command.join(", ")
    )
}

const BROKEN: &str =
    "\n[[server]]\nid = \"broken\"\ntransport = \"stdio\"\ncommand = [\"/nonexistent/mcp-server\"]\n";

#[tokio::test]
async fn a_healthy_gateway_has_no_problem() {
    let f = Fixture::new(&mock("mock", &[]));
    let out = f.doctor().await;
    let text = report(&out);
    assert!(out.status.success(), "{text}");
    assert!(
        text.contains("✓ mock: up, 1 of its 2 tools listed"),
        "{text}"
    );
    assert!(text.contains("0 problems, 0 warnings"), "{text}");
}

/// One server down does not end the report: the rest are checked, and the
/// exit says something is broken.
#[tokio::test]
async fn a_server_that_does_not_start_is_a_problem_and_the_rest_are_still_checked() {
    let f = Fixture::new(&format!("{BROKEN}{}", mock("mock", &[])));
    let out = f.doctor().await;
    let text = report(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("✗ broken: down: "), "{text}");
    assert!(text.contains("/nonexistent/mcp-server"), "{text}");
    assert!(text.contains("✓ mock: up"), "{text}");
    assert!(text.contains("1 problem, 0 warnings"), "{text}");
}

/// A server that will not start would be audited, and a tool seen for the
/// first time pinned: doctor opens them as the gateway does, and keeps
/// neither, nor any state.
#[tokio::test]
async fn doctor_keeps_nothing_a_running_gateway_keeps() {
    let f = Fixture::new(&format!("{BROKEN}{}", mock("mock", &[])));
    let out = f.doctor().await;
    assert!(report(&out).contains("✓ mock: up"), "{}", report(&out));
    for kept in ["audit.log", "pins.toml", "state"] {
        assert!(
            !f.root.path().join(kept).exists(),
            "doctor wrote {kept}: {}",
            report(&out)
        );
    }
}

/// Resources and prompts a server offers are exposed only by its lists, so
/// one that offers them and lists none has them dropped: doctor says so, and
/// says what was before.
#[tokio::test]
async fn what_a_server_offers_and_no_list_exposes_is_named() {
    let f = Fixture::new(&mock("files", &["--resources"]));
    let out = f.doctor().await;
    let text = report(&out);
    assert!(
        text.contains("⚠ files offers resources, and no client sees them"),
        "{text}"
    );
    assert!(
        text.contains("⚠ files offers prompts, and no client sees them"),
        "{text}"
    );
    assert!(text.contains("Before 0.4.0"), "{text}");
    // Warnings, not problems: the gateway runs.
    assert!(out.status.success(), "{text}");
}

/// Two servers that allow every tool: the config cannot know they share a
/// name, and running them shows it.
#[tokio::test]
async fn a_tool_two_servers_offer_is_named_once_they_run() {
    let every = |id: &str| {
        format!("\n[[server]]\nid = \"{id}\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\ntools = [\"*\"]\n")
    };
    let f = Fixture::new(&format!("{}{}", every("a"), every("b")));
    let out = f.doctor().await;
    let text = report(&out);
    assert!(
        text.contains("⚠ tool 'echo' is offered by 'a' and 'b'"),
        "{text}"
    );
}

/// An identity provider on a loopback port, serving the test JWKS with its
/// clock `ahead` of this machine's (behind, if negative).
async fn identity_provider(ahead: i64) -> String {
    let date = move || {
        let now = SystemTime::now();
        let off = Duration::from_secs(ahead.unsigned_abs());
        let theirs = if ahead >= 0 { now + off } else { now - off };
        httpdate::fmt_http_date(theirs)
    };
    let app = Router::new().route(
        "/jwks.json",
        get(move || async move { ([(header::DATE, date())], TEST_JWKS) }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/jwks.json")
}

fn signing_in_with(jwks_uri: &str) -> String {
    format!(
        "\n[gateway.auth]\nenabled = true\nissuer = \"https://idp.example.com\"\n\
         resource = \"https://mcpdef.example.com/mcp\"\njwks_uri = \"{jwks_uri}\"\n{}",
        mock("mock", &[])
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn the_identity_providers_keys_and_clock_are_checked() {
    let f = Fixture::new(&signing_in_with(&identity_provider(0).await));
    let out = f.doctor().await;
    let text = report(&out);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("/jwks.json: 1 key(s)"), "{text}");
    assert!(text.contains("✓ this machine's clock is within"), "{text}");
}

/// The classic silent failure of a token: a clock off by more than its times
/// allow. Behind the provider, a fresh token is not valid yet here; ahead of
/// it, every token expires early.
#[tokio::test(flavor = "multi_thread")]
async fn a_clock_off_by_more_than_tokens_allow_is_a_problem_either_way() {
    for (ahead, says) in [
        (600, "behind the identity provider's"),
        (-600, "ahead of the identity provider's"),
    ] {
        let f = Fixture::new(&signing_in_with(&identity_provider(ahead).await));
        let out = f.doctor().await;
        let text = report(&out);
        assert!(!out.status.success(), "{ahead}: {text}");
        assert!(
            text.contains("✗ this machine's clock is 10m"),
            "{ahead}: {text}"
        );
        assert!(text.contains(says), "{ahead}: {text}");
    }
}

/// Keys the gateway cannot fetch are a problem: it does not start without
/// them.
#[tokio::test]
async fn an_unreachable_jwks_uri_is_a_problem() {
    // A port that was free a moment ago, and nothing listens on now.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let f = Fixture::new(&signing_in_with(&format!(
        "http://127.0.0.1:{port}/jwks.json"
    )));
    let out = f.doctor().await;
    let text = report(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("✗ jwks_uri http://127.0.0.1:"), "{text}");
    assert!(text.contains("does not start without them"), "{text}");
}

/// A config with errors is not run, so nothing past it is checked.
#[tokio::test]
async fn a_config_with_errors_stops_at_them() {
    let f = Fixture::new("\n[[server]]\nid = \"x\"\ntransport = \"carrier-pigeon\"\n");
    let out = f.doctor().await;
    let text = report(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("✗ "), "{text}");
    assert!(
        text.contains("the rest is checked once these are fixed"),
        "{text}"
    );
    assert!(!text.contains("\nservers\n"), "{text}");
}
