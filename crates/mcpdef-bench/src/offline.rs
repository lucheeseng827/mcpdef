// SPDX-License-Identifier: Apache-2.0
//! `offline`: what someone does with an installed `mcpdef` on a host with no
//! route out, and whether `mcpdef` reaches past loopback while they do.
//!
//! In a home directory and a project made for it, as `first-call` makes them:
//!
//! 1. README.md's commands to the first governed call: `mcpdef up` with no
//!    config, `mcpdef connect claude-code --write --replace`, and the client's
//!    first tool call through the gateway, answered as the server answers it.
//! 2. `mcpdef validate` and `mcpdef doctor` on the config `up` wrote.
//! 3. Where policy is made, apart from the node: a key (`mcpdef bundle key`),
//!    and the config signed at revision 1 and, with `deny = ["echo"]` on its
//!    server, at revision 2 (`sign`). The key's public half (`jwks`) is the
//!    node's to trust, kept outside the project, as `/etc/mcpdef` would be.
//! 4. The node held to its bundle: revision 1 applied (`mcpdef bundle apply`),
//!    and the gateway started again with `--bundle-trust`. It says it runs
//!    revision 1, and a session opened on it has its call answered.
//! 5. The policy update: revision 2 applied, revision 1, replayed, refused,
//!    and a `SIGHUP`. The gateway says it reloaded. In the session open, the
//!    tool is no longer listed, and a call to it is refused.
//! 6. The tool let back in without the signer: revision 1's config written
//!    over `mcpdef.toml` by hand, then revision 1's bundle put back beside it
//!    too, each followed by a `SIGHUP`. The gateway refuses both, as
//!    `bundle-unverified` and `bundle-older`, and the call stays refused.
//!    Revision 2, applied again, puts its config and its bundle back.
//! 7. `mcpdef hook install`, and the hook Claude Code runs before a call to
//!    the tool: under the same config, it refuses the call too.
//! 8. `mcpdef audit verify`, and the ledger: each call, each bundle applied
//!    or refused, and each reload, applied or refused.
//!
//! With `--strace`, the harness runs itself again under `strace -f`, with every
//! process it starts, and then fails on any address a network call named that
//! is not loopback, and on any call to port 53: a name looked up is a reach
//! outwards, whatever answers it. Run it where there is no route out, as the CI
//! job does, and a step that needed one fails as well.

use crate::first_call::{self, Setup, Up, SERVER, TOOL};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;
use toml_edit::{value, Array, DocumentMut};

/// Run the steps with `mcpdef`, with `mock`, this harness, as the server
/// Claude Code runs: what each showed, a line each, in Markdown.
pub async fn check(mcpdef: &Path, mock: &Path, max: Duration) -> Result<Vec<String>> {
    let scratch = tempfile::tempdir().context("making a scratch directory")?;
    let setup = Setup::new(scratch.path(), mock)?;
    let mut done = Vec::new();

    let mut up = first_call::start_up(&setup, mcpdef, max).await?;
    done.push(format!(
        "`mcpdef up`, with no config: ready in {}, fronting {SERVER}",
        crate::report::fmt_us(first_call::micros(up.took))
    ));
    let (_, url) = first_call::connect(&setup, mcpdef, max).await?;
    done.push(
        "`mcpdef connect claude-code --write --replace`: the gateway alone in `.mcp.json`".into(),
    );
    let client = crate::load::client(max)?;
    first_call::first_tool_call(&client, &url).await?;
    done.push(format!(
        "the client's first call to {TOOL}, through the gateway: answered as the server answers it"
    ));

    first_call::timed(
        setup.mcpdef(mcpdef, &["validate", "--config", "mcpdef.toml"]),
        "mcpdef validate",
        max,
    )
    .await?;
    let (_, doctor) = first_call::timed(
        setup.mcpdef(mcpdef, &["doctor", "--config", "mcpdef.toml"]),
        "mcpdef doctor",
        max,
    )
    .await?;
    ensure!(
        doctor.contains("0 problems"),
        "mcpdef doctor found problems:\n{doctor}"
    );
    done.push("`mcpdef validate` and `mcpdef doctor`: the config is valid, 0 problems".into());

    // Signed where policy is made, apart from the node.
    let config = setup.project.join("mcpdef.toml");
    let text = std::fs::read_to_string(&config)
        .with_context(|| format!("reading {}", config.display()))?;
    let signed = Signed::make(
        scratch.path(),
        &setup,
        mcpdef,
        &[text.clone(), deny(&text, SERVER, TOOL)?],
        max,
    )
    .await?;
    done.push(format!(
        "`mcpdef bundle key`, `jwks` and `sign`, apart from the node: the config `up` wrote at \
         revision 1, and with `deny = [\"{TOOL}\"]` at revision 2"
    ));

    // The node held to its bundle: revision 1 in place, and the gateway
    // started again from it, trusting the key's public half alone.
    signed.apply(&setup, mcpdef, 1, max).await?;
    let _ = up.child.kill().await;
    let trust = signed
        .trust
        .to_str()
        .context("the path of the keys the node trusts is not UTF-8")?;
    let (mut up, said) = first_call::start(
        &setup,
        mcpdef,
        &["up", "--config", "mcpdef.toml", "--bundle-trust", trust],
        max,
    )
    .await?;
    ensure!(
        said.last()
            .is_some_and(|ready| ready.contains(" · bundle r1 · ")),
        "mcpdef up --bundle-trust did not say it runs revision 1:\n{}",
        said.join("\n")
    );
    // The connections the gateway before had are gone with it.
    let client = crate::load::client(max)?;
    let session = first_call::first_tool_call(&client, &url).await?;
    done.push(format!(
        "`mcpdef bundle apply` of revision 1, then `mcpdef up --bundle-trust`: ready at \
         `bundle r1`, and a new session's call to {TOOL} answered"
    ));

    // The policy update, checked by the node that takes it.
    signed.apply(&setup, mcpdef, 2, max).await?;
    signed.replayed(&setup, mcpdef, 1, max).await?;
    done.push(
        "`mcpdef bundle apply` of revision 2, then of revision 1, replayed: refused as older"
            .into(),
    );
    first_call::timed(
        setup.mcpdef(mcpdef, &["validate", "--config", "mcpdef.toml"]),
        "mcpdef validate, after the policy update",
        max,
    )
    .await?;
    let reloaded = hang_up(&setup, &mut up, max).await?;
    ensure!(
        reloaded.starts_with("config reloaded (sighup): ") && reloaded.ends_with(" · bundle r2"),
        "the SIGHUP after revision 2 was applied did not reload it: {reloaded}"
    );
    done.push(format!(
        "revision 2's `deny = [\"{TOOL}\"]`, in `mcpdef.toml` now, and a `SIGHUP`: {reloaded}"
    ));
    let session = session.as_deref();
    still_refused(&client, &url, session, 4, "after the reload").await?;
    done.push(format!(
        "in the session already open, {TOOL} is no longer listed, and a call to it is refused"
    ));

    // The tool let back in by whoever can write the config: by hand, then
    // with the bundle before put back beside it.
    std::fs::write(&config, &text).with_context(|| format!("writing {}", config.display()))?;
    let edited = hang_up(&setup, &mut up, max).await?;
    ensure!(
        edited.starts_with("config reload refused (sighup), bundle-unverified: "),
        "revision 1's config, written by hand, was not refused as unverified: {edited}"
    );
    still_refused(
        &client,
        &url,
        session,
        6,
        "once the config was written by hand",
    )
    .await?;
    done.push(format!(
        "revision 1's config written over `mcpdef.toml` by hand, and a `SIGHUP`: {edited}; \
         {TOOL} still refused"
    ));
    let beside = setup.project.join("mcpdef.toml.bundle");
    std::fs::copy(signed.bundle(1), &beside)
        .with_context(|| format!("writing {}", beside.display()))?;
    let older = hang_up(&setup, &mut up, max).await?;
    ensure!(
        older.starts_with("config reload refused (sighup), bundle-older: "),
        "revision 1's bundle, put back with its config, was not refused as older: {older}"
    );
    still_refused(
        &client,
        &url,
        session,
        8,
        "once revision 1's bundle was put back",
    )
    .await?;
    done.push(format!(
        "revision 1's bundle put back beside it too, and a `SIGHUP`: {older}; {TOOL} still refused"
    ));
    let again = signed.apply(&setup, mcpdef, 2, max).await?;
    ensure!(
        again.contains("(again: what was in place was not this bundle's)"),
        "revision 2, applied again, did not put its config back: {again}"
    );
    done.push(
        "`mcpdef bundle apply` of revision 2 again: its config and its bundle back in place".into(),
    );

    first_call::timed(
        setup.mcpdef(
            mcpdef,
            &["hook", "install", "--config", "mcpdef.toml", "--write"],
        ),
        "mcpdef hook install",
        max,
    )
    .await?;
    let (command, wait) = first_call::installed_hook(&setup)?;
    let (_, out) = first_call::run_hook(&setup, &command, wait.min(max)).await?;
    let answer: Option<Value> = serde_json::from_slice(&out.stdout).ok();
    ensure!(
        out.status.code() == Some(2)
            && answer
                .as_ref()
                .and_then(|a| a.pointer("/hookSpecificOutput/permissionDecision"))
                == Some(&json!("deny")),
        "the hook did not refuse the call ({}):\n{}{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    done.push(format!(
        "`mcpdef hook install`, and the hook before a call to {TOOL}: refused too"
    ));

    let records = first_call::ledger(&setup, mcpdef, max).await?;
    let _ = up.child.kill().await;
    held(&records)?;
    done.push(
        "`mcpdef audit verify`: the chain holds, with each call, each bundle applied or \
         refused, and each reload, applied or refused, in it"
            .into(),
    );
    Ok(done)
}

/// Where policy is made, apart from the node: the key bundles are signed
/// with, and the bundles. And the key's public half, which the node trusts,
/// kept where whoever writes the node's config does not write, as
/// `/etc/mcpdef` would be.
struct Signed {
    dir: PathBuf,
    trust: PathBuf,
}

impl Signed {
    /// A key, its public half for the node, and each of `configs` signed, at
    /// revision 1 and up.
    async fn make(
        scratch: &Path,
        setup: &Setup,
        mcpdef: &Path,
        configs: &[String],
        max: Duration,
    ) -> Result<Signed> {
        let signed = Signed {
            dir: scratch.join("policy"),
            trust: scratch.join("etc").join("bundle-keys.json"),
        };
        for dir in [&signed.dir, &scratch.join("etc")] {
            std::fs::create_dir_all(dir).with_context(|| format!("making {}", dir.display()))?;
        }
        let key = signed.dir.join("signer.jwk");
        let mut made = setup.mcpdef(mcpdef, &["bundle", "key", "--out"]);
        made.arg(&key);
        first_call::timed(made, "mcpdef bundle key", max).await?;
        let mut jwks = setup.mcpdef(mcpdef, &["bundle", "jwks", "--key"]);
        jwks.arg(&key);
        let (_, jwks) = first_call::timed(jwks, "mcpdef bundle jwks", max).await?;
        std::fs::write(&signed.trust, jwks)
            .with_context(|| format!("writing {}", signed.trust.display()))?;
        let policy = signed.dir.join("policy.toml");
        for (revision, config) in (1u64..).zip(configs) {
            std::fs::write(&policy, config)
                .with_context(|| format!("writing {}", policy.display()))?;
            let mut sign = setup.mcpdef(mcpdef, &["bundle", "sign", "--config"]);
            sign.arg(&policy)
                .arg("--key")
                .arg(&key)
                .args(["--revision", &revision.to_string(), "--out"])
                .arg(signed.bundle(revision));
            first_call::timed(sign, "mcpdef bundle sign", max).await?;
        }
        Ok(signed)
    }

    /// The bundle of `revision`.
    fn bundle(&self, revision: u64) -> PathBuf {
        self.dir.join(format!("r{revision}.bundle"))
    }

    /// `mcpdef bundle apply` of `revision`, carried in, in place of the
    /// project's `mcpdef.toml`.
    fn applying(&self, setup: &Setup, mcpdef: &Path, revision: u64) -> Command {
        let mut apply = setup.mcpdef(mcpdef, &["bundle", "apply"]);
        apply
            .arg(self.bundle(revision))
            .arg("--trust")
            .arg(&self.trust)
            .args(["--config", "mcpdef.toml"]);
        apply
    }

    /// `revision` applied: what `apply` said of it.
    async fn apply(
        &self,
        setup: &Setup,
        mcpdef: &Path,
        revision: u64,
        max: Duration,
    ) -> Result<String> {
        let what = format!("mcpdef bundle apply, of revision {revision}");
        let (_, said) =
            first_call::timed(self.applying(setup, mcpdef, revision), &what, max).await?;
        Ok(said)
    }

    /// `revision` applied once a later one was: refused as older.
    async fn replayed(
        &self,
        setup: &Setup,
        mcpdef: &Path,
        revision: u64,
        max: Duration,
    ) -> Result<()> {
        let replayed = tokio::time::timeout(max, self.applying(setup, mcpdef, revision).output())
            .await
            .with_context(|| {
                format!("mcpdef bundle apply, of revision {revision}, did not finish")
            })?
            .context("starting mcpdef bundle apply")?;
        let said = String::from_utf8_lossy(&replayed.stderr);
        ensure!(
            !replayed.status.success()
                && said.contains(&format!("revision {revision} is older than revision")),
            "revision {revision}, replayed after a later one, was not refused as older ({}):\n{said}",
            replayed.status
        );
        Ok(())
    }
}

/// Send `up` a `SIGHUP`: what it then says of the reload, applied or refused.
async fn hang_up(setup: &Setup, up: &mut Up, max: Duration) -> Result<String> {
    let pid = up.child.id().context("mcpdef up has exited")?;
    let mut hup = setup.command("sh");
    hup.args(["-c", "kill -HUP \"$1\"", "sh", &pid.to_string()]);
    first_call::timed(hup, "kill -HUP", max).await?;
    let said = tokio::time::timeout(max, async {
        while let Some(line) = up.said.recv().await {
            if line.contains("config reload") {
                return Some(line);
            }
        }
        None
    })
    .await
    .context("mcpdef up said nothing of the reload")?
    .context("mcpdef up stopped before it said what became of the reload")?;
    Ok(said.trim().trim_start_matches("mcpdef: ").to_string())
}

/// In `session`, `TOOL` is not listed, and a call to it is refused: requests
/// `id` and `id + 1`.
async fn still_refused(
    client: &reqwest::Client,
    url: &str,
    session: Option<&str>,
    id: u64,
    when: &str,
) -> Result<()> {
    let (listed, _) = first_call::post(
        client,
        url,
        session,
        json!({ "jsonrpc": "2.0", "id": id, "method": "tools/list" }),
    )
    .await?;
    let tools = listed
        .as_ref()
        .and_then(|r| r.pointer("/result/tools"))
        .and_then(Value::as_array)
        .with_context(|| format!("tools/list, {when}, was not answered: {listed:?}"))?;
    ensure!(
        !tools.iter().any(|t| t["name"] == TOOL),
        "{when}, tools/list still lists {TOOL}: {listed:?}"
    );
    let (called, _) = first_call::post(
        client,
        url,
        session,
        json!({ "jsonrpc": "2.0", "id": id + 1, "method": "tools/call", "params": {
            "name": TOOL, "arguments": { "text": "mcpdef-bench" },
        } }),
    )
    .await?;
    ensure!(
        refused(called.as_ref()),
        "{when}, the call to {TOOL} was not refused: {called:?}"
    );
    Ok(())
}

/// `text`, an `mcpdef.toml`, with `tool` denied on the server `id`: the
/// smallest policy update there is.
fn deny(text: &str, id: &str, tool: &str) -> Result<String> {
    let mut doc: DocumentMut = text.parse().context("parsing mcpdef.toml")?;
    let server = doc
        .get_mut("server")
        .and_then(|s| s.as_array_of_tables_mut())
        .and_then(|servers| {
            servers
                .iter_mut()
                .find(|s| s.get("id").and_then(|v| v.as_str()) == Some(id))
        })
        .with_context(|| format!("mcpdef.toml has no [[server]] with id = \"{id}\""))?;
    server["deny"] = value([tool].into_iter().collect::<Array>());
    Ok(doc.to_string())
}

/// Whether `answer`, to a `tools/call`, is the gateway's refusal: a result
/// marked an error, saying MCPdef denied it, or a JSON-RPC error.
fn refused(answer: Option<&Value>) -> bool {
    let Some(answer) = answer else {
        return false;
    };
    let result = answer.get("result");
    let denied = result.and_then(|r| r.get("isError")) == Some(&Value::Bool(true))
        && result
            .and_then(|r| r.pointer("/content/0/text"))
            .and_then(Value::as_str)
            .is_some_and(|t| t.starts_with("MCPdef denied"));
    denied || answer.get("error").is_some()
}

/// The ledger holds each step, in order: the call allowed through the first
/// gateway and through the one held to its bundle, then refused three times
/// by it and once by the hook; each bundle applied or refused; and each
/// reload a `SIGHUP` asked for, with the bundle beside the config named.
fn held(records: &[Value]) -> Result<()> {
    let calls: Vec<&Value> = records
        .iter()
        .filter(|r| r["method"] == "tools/call" && r["server"] == SERVER && r["tool"] == TOOL)
        .collect();
    let decisions: Vec<(&str, bool)> = calls
        .iter()
        .map(|r| {
            (
                r["decision"].as_str().unwrap_or_default(),
                r.get("hook").is_some_and(|h| !h.is_null()),
            )
        })
        .collect();
    ensure!(
        decisions
            == [
                ("allow", false),
                ("allow", false),
                ("deny", false),
                ("deny", false),
                ("deny", false),
                ("deny", true)
            ],
        "the ledger does not hold the call allowed twice, then refused three times by the \
         gateway and once by the hook: {records:?}"
    );
    let bundles: Vec<(&str, Option<u64>, Option<&str>)> = records
        .iter()
        .filter(|r| r["method"] == "bundle")
        .map(|r| {
            (
                r["decision"].as_str().unwrap_or_default(),
                r["bundle"]["revision"].as_u64(),
                r["rule"].as_str(),
            )
        })
        .collect();
    ensure!(
        bundles
            == [
                ("allow", Some(1), None),
                ("allow", Some(2), None),
                ("deny", Some(1), Some("bundle-older")),
                ("allow", Some(2), None)
            ],
        "the ledger does not hold revisions 1 and 2 applied, revision 1 refused, then \
         revision 2 applied again: {records:?}"
    );
    let reloads: Vec<(&str, Option<&str>, &str, Option<u64>)> = records
        .iter()
        .filter(|r| r["method"] == "reload")
        .map(|r| {
            (
                r["decision"].as_str().unwrap_or_default(),
                r["rule"].as_str(),
                r["actor"].as_str().unwrap_or_default(),
                r["bundle"]["revision"].as_u64(),
            )
        })
        .collect();
    ensure!(
        reloads
            == [
                ("allow", None, "sighup", Some(2)),
                ("deny", Some("bundle-unverified"), "sighup", Some(2)),
                ("deny", Some("bundle-older"), "sighup", Some(1))
            ],
        "the ledger does not hold revision 2 reloaded, then the config written by hand and \
         revision 1 put back each refused: {records:?}"
    );
    Ok(())
}

/// What a traced run did on the network, from `strace -f -e trace=%network`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Traced {
    /// The network calls made, by every process traced.
    pub calls: usize,
    /// Each one that reached past loopback, as strace wrote it.
    pub outward: Vec<String>,
}

impl Traced {
    pub fn read(trace: &str) -> Traced {
        let mut traced = Traced::default();
        for line in trace.lines() {
            // `+++ exited`, `--- SIGCHLD`, and a call resumed: not a call of its own.
            let call = line
                .split_once(char::is_whitespace)
                .map_or(line, |(_, rest)| rest)
                .trim_start();
            if call.starts_with("+++") || call.starts_with("---") || call.starts_with("<...") {
                continue;
            }
            if call.contains('(') {
                traced.calls += 1;
            }
            if reaches_out(line) {
                traced.outward.push(line.trim().to_string());
            }
        }
        traced
    }

    /// Markdown: the one line the run adds.
    pub fn render(&self) -> String {
        let mut s = String::new();
        let _ = write!(
            s,
            "under `strace -f`: {} network call(s) in all, ",
            self.calls
        );
        match self.outward.is_empty() {
            true => s.push_str("none to an address past loopback, and no name looked up"),
            false => {
                let _ = write!(s, "{} past loopback:", self.outward.len());
                for line in &self.outward {
                    let _ = write!(s, "\n  - `{line}`");
                }
            }
        }
        s
    }
}

/// Whether one line of strace's names an address past loopback, a port 53, or
/// a local resolver's socket.
fn reaches_out(line: &str) -> bool {
    let v4 = quoted(line, "inet_addr(\"").any(|a| {
        a.parse::<Ipv4Addr>()
            .map_or(true, |ip| !(ip.is_loopback() || ip.is_unspecified()))
    });
    let v6 = quoted(line, "inet_pton(AF_INET6, \"").any(|a| {
        a.parse::<Ipv6Addr>().map_or(true, |ip| {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()))
        })
    });
    let dns = ["sin_port=htons(53)", "sin6_port=htons(53)"]
        .iter()
        .any(|p| line.contains(p));
    let resolver =
        quoted(line, "sun_path=\"").any(|p| p.contains("nscd") || p.contains("io.systemd.Resolve"));
    v4 || v6 || dns || resolver
}

/// Each string in `line` that starts right after `open` and ends at the next
/// double quote.
fn quoted<'a>(line: &'a str, open: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    line.match_indices(open).filter_map(move |(at, _)| {
        let rest = &line[at + open.len()..];
        rest.find('"').map(|end| &rest[..end])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRACE: &str = r#"4291  socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 9
4291  bind(9, {sa_family=AF_INET, sin_port=htons(7878), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
4291  listen(9, 128)                    = 0
4286  connect(10, {sa_family=AF_INET, sin_port=htons(7878), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS (Operation now in progress)
4291  accept4(9, {sa_family=AF_INET, sin_port=htons(34538), sin_addr=inet_addr("127.0.0.1")}, [128 => 16], SOCK_CLOEXEC|SOCK_NONBLOCK) = 11
4297  socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0, [6, 7]) = 0
4300  bind(3, {sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0
4288  --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=4297, si_uid=0, si_status=0} ---
4293  +++ killed by SIGKILL +++
"#;

    #[test]
    fn loopback_alone_reaches_nothing() {
        let traced = Traced::read(TRACE);
        assert_eq!(traced.calls, 7, "{traced:?}");
        assert!(traced.outward.is_empty(), "{traced:?}");
        assert!(traced
            .render()
            .contains("7 network call(s) in all, none to an address past loopback"));
    }

    #[test]
    fn an_address_past_loopback_or_a_name_looked_up_is_named() {
        for line in [
            r#"77  connect(12, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("140.82.112.3")}, 16) = -1 ENETUNREACH (Network is unreachable)"#,
            r#"77  connect(12, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2606:50c0:8000::153", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH (Network is unreachable)"#,
            r#"77  sendto(5, "\x12\x34", 2, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, 16) = 2"#,
            r#"77  connect(4, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)"#,
            r#"77  connect(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("not an address")}, 16) = 0"#,
        ] {
            let traced = Traced::read(&format!("{TRACE}{line}\n"));
            assert_eq!(traced.outward, [line.to_string()], "{line}");
            assert!(traced.render().contains("1 past loopback"), "{line}");
        }
    }

    #[test]
    fn a_mapped_loopback_and_the_unspecified_address_stay_home() {
        for line in [
            r#"5  connect(3, {sa_family=AF_INET6, sin6_port=htons(7878), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::ffff:127.0.0.1", &sin6_addr), sin6_scope_id=0}, 28) = 0"#,
            r#"5  bind(3, {sa_family=AF_INET, sin_port=htons(7878), sin_addr=inet_addr("0.0.0.0")}, 16) = 0"#,
            r#"5  bind(3, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("127.4.5.6")}, 16) = 0"#,
        ] {
            assert!(Traced::read(line).outward.is_empty(), "{line}");
        }
    }

    #[test]
    fn the_policy_update_denies_the_tool_on_its_server_alone() {
        let text = "[gateway]\nlisten = \"127.0.0.1:7878\"\n\n# From Claude Code.\n[[server]]\n\
                    id = \"demo\"\ntransport = \"stdio\"\n\n[[server]]\nid = \"other\"\n\
                    transport = \"stdio\"\n";
        let updated = deny(text, "demo", "echo").unwrap();
        let doc: DocumentMut = updated.parse().unwrap();
        let servers = doc["server"].as_array_of_tables().unwrap();
        let denied: Vec<Option<String>> = servers
            .iter()
            .map(|s| s.get("deny").map(|d| d.to_string().trim().to_string()))
            .collect();
        assert_eq!(denied, [Some("[\"echo\"]".to_string()), None]);
        assert!(updated.contains("# From Claude Code."), "{updated}");
        assert!(deny(text, "absent", "echo").is_err());
    }

    #[test]
    fn a_refusal_is_known_by_its_answer() {
        let denied = json!({ "jsonrpc": "2.0", "id": 5, "result": {
            "isError": true,
            "content": [{ "type": "text", "text": "MCPdef denied: tool 'echo' is not allowed" }],
        } });
        let error =
            json!({ "jsonrpc": "2.0", "id": 5, "error": { "code": -32602, "message": "no" } });
        let answered = json!({ "jsonrpc": "2.0", "id": 5, "result": {
            "isError": false, "content": [{ "type": "text", "text": "ok" }],
        } });
        let failed = json!({ "jsonrpc": "2.0", "id": 5, "result": {
            "isError": true, "content": [{ "type": "text", "text": "the server failed" }],
        } });
        assert!(refused(Some(&denied)));
        assert!(refused(Some(&error)));
        assert!(!refused(Some(&answered)));
        assert!(!refused(Some(&failed)));
        assert!(!refused(None));
    }

    #[test]
    fn the_ledger_must_hold_each_step_in_order() {
        let call = |decision: &str, hook: Option<&str>| {
            json!({ "method": "tools/call", "server": SERVER, "tool": TOOL,
                    "decision": decision, "hook": hook })
        };
        let reload = |decision: &str, rule: Option<&str>, revision: u64| {
            json!({ "method": "reload", "server": "(config)", "decision": decision,
                    "rule": rule, "actor": "sighup", "bundle": { "revision": revision } })
        };
        let bundle = |decision: &str, revision: u64, rule: Option<&str>| {
            json!({ "method": "bundle", "server": "(config)", "decision": decision,
                    "rule": rule, "bundle": { "revision": revision } })
        };
        let good = || {
            vec![
                call("allow", None),
                bundle("allow", 1, None),
                call("allow", None),
                bundle("allow", 2, None),
                bundle("deny", 1, Some("bundle-older")),
                reload("allow", None, 2),
                call("deny", None),
                reload("deny", Some("bundle-unverified"), 2),
                call("deny", None),
                reload("deny", Some("bundle-older"), 1),
                call("deny", None),
                bundle("allow", 2, None),
                call("deny", Some("claude-code")),
            ]
        };
        held(&good()).unwrap();
        // The config written by hand, taken: the lock let it in.
        let mut taken = good();
        taken[7] = reload("allow", None, 2);
        assert!(held(&taken).is_err());
        // The bundle before, put back, taken.
        let mut rolled_back = good();
        rolled_back[9] = reload("allow", None, 1);
        assert!(held(&rolled_back).is_err());
        // The older revision applied, not refused: a rollback `apply` let in.
        let mut applied = good();
        applied[4] = bundle("allow", 1, None);
        assert!(held(&applied).is_err());
        let mut hook_allowed = good();
        *hook_allowed.last_mut().unwrap() = call("allow", Some("claude-code"));
        assert!(held(&hook_allowed).is_err());
        let no_reload: Vec<Value> = good()
            .into_iter()
            .filter(|r| r["method"] != "reload")
            .collect();
        assert!(held(&no_reload).is_err());
    }
}
