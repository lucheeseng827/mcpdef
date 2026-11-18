// SPDX-License-Identifier: Apache-2.0
//! `first-call`: how long it takes, from an installed `mcpdef`, to the first
//! governed call, by the commands README.md gives someone whose Claude Code
//! already runs an MCP server.
//!
//! Two paths, each in a home directory and a project made for it:
//!
//! * **The gateway.** `mcpdef up` with no config, then `mcpdef connect
//!   claude-code --write --replace`, then the client's first tool call, through
//!   the gateway.
//! * **The hook.** `mcpdef import --out mcpdef.toml`, then `mcpdef hook install
//!   --config mcpdef.toml --write`, then the hook Claude Code runs before its
//!   first MCP tool call.
//!
//! The project's `.mcp.json` runs this harness's stdio mock, and the home's
//! `.claude.json` says Claude Code was told to run it in the project: only then
//! does `up` front a server that only a directory's own files name. The harness
//! stands in for Claude Code. Its client calls the URL in the entry `connect`
//! wrote, and it runs the hook `hook install` wrote, through the shell, with the
//! event Claude Code sends. A call counts once its record is in the ledger and
//! the ledger verifies: through the gateway, once it is answered as the mock
//! answers it; through the hook, once the hook lets it through.
//!
//! Not timed: the person reading and typing between the commands, and the
//! client itself, starting up and asking whether to use what changed. Nor,
//! through the hook, the call the client then makes to the server itself:
//! MCPdef is not in its path, and it takes what it would take without MCPdef.

use crate::report::{fmt_us, Machine};
use anyhow::{bail, ensure, Context, Result};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

/// Bumped when a field changes meaning.
pub const SCHEMA: u32 = 1;

/// The server the project's `.mcp.json` runs, by the name the client gives it.
pub(crate) const SERVER: &str = "demo";
/// Its one tool.
pub(crate) const TOOL: &str = "echo";
/// The revision the client asks for: the gateway's default era.
const PROTOCOL_VERSION: &str = "2025-11-25";

/// What `first-call` measured, and where.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub schema: u32,
    pub generated_at_unix: u64,
    /// First line of `mcpdef version` for the binary that was measured.
    pub mcpdef_version: String,
    pub commit: Option<String>,
    pub note: Option<String>,
    pub machine: Machine,
    /// A path that took longer than this failed the run.
    pub max_ms: u64,
    pub runs: Vec<Run>,
}

/// Both paths, once each, in fresh directories.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Run {
    pub gateway: GatewayPath,
    pub hook: HookPath,
}

/// The gateway path, each step's wall time in microseconds.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct GatewayPath {
    /// From starting `mcpdef up` until it says it is ready.
    pub up_us: u64,
    /// `mcpdef connect claude-code --write --replace`.
    pub connect_us: u64,
    /// The client's `initialize`, `tools/list` and first `tools/call`, until
    /// the call is answered.
    pub call_us: u64,
}

impl GatewayPath {
    pub fn total_us(&self) -> u64 {
        self.up_us + self.connect_us + self.call_us
    }
}

/// The hook path, each step's wall time in microseconds.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct HookPath {
    /// `mcpdef import --out mcpdef.toml`.
    pub import_us: u64,
    /// `mcpdef hook install --config mcpdef.toml --write`.
    pub install_us: u64,
    /// The hook, from the shell's start until it exits.
    pub hook_us: u64,
}

impl HookPath {
    pub fn total_us(&self) -> u64 {
        self.import_us + self.install_us + self.hook_us
    }
}

/// Run both paths `runs` times with `mcpdef`, with `mock`, this harness, as the
/// server Claude Code runs. A step that does not do what README.md says, or a
/// command that takes longer than `max`, is an error.
pub async fn measure(mcpdef: &Path, mock: &Path, runs: usize, max: Duration) -> Result<Vec<Run>> {
    let scratch = tempfile::tempdir().context("making a scratch directory")?;
    let mut out = Vec::with_capacity(runs);
    for n in 1..=runs {
        let gateway = gateway_path(
            mcpdef,
            mock,
            &scratch.path().join(format!("{n}-gateway")),
            max,
        )
        .await
        .with_context(|| format!("run {n} of {runs}, through the gateway"))?;
        let hook = hook_path(mcpdef, mock, &scratch.path().join(format!("{n}-hook")), max)
            .await
            .with_context(|| format!("run {n} of {runs}, through the hook"))?;
        out.push(Run { gateway, hook });
    }
    Ok(out)
}

/// A home directory and a project, as Claude Code leaves them once it was told
/// to run the project's server: the project's `.mcp.json` names the server,
/// and the home's `.claude.json` approves it for the project.
pub(crate) struct Setup {
    pub(crate) home: PathBuf,
    pub(crate) project: PathBuf,
}

impl Setup {
    pub(crate) fn new(dir: &Path, mock: &Path) -> Result<Setup> {
        let home = dir.join("home");
        let project = dir.join("project");
        for d in [&home, &project] {
            std::fs::create_dir_all(d).with_context(|| format!("making {}", d.display()))?;
        }
        // `.claude.json` keys a project by its path as a process in it sees
        // it, past any symlink above it, such as macOS's /var.
        let home = std::fs::canonicalize(&home)?;
        let project = std::fs::canonicalize(&project)?;
        write_json(
            &project.join(".mcp.json"),
            &json!({ "mcpServers": { SERVER: {
                "command": mock.to_string_lossy(),
                "args": ["mock-stdio", "--tool", TOOL],
            } } }),
        )?;
        let key = project.to_string_lossy().into_owned();
        write_json(
            &home.join(".claude.json"),
            &json!({ "projects": { key: { "enabledMcpjsonServers": [SERVER] } } }),
        )?;
        Ok(Setup { home, project })
    }

    /// `program`, run in the project, as the user whose home this is: every
    /// client's files are read from it, Claude Desktop's too, which on Linux
    /// follows `XDG_CONFIG_HOME` when that is set.
    pub(crate) fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut cmd = Command::new(program);
        cmd.current_dir(&self.project)
            .env("HOME", &self.home)
            .env_remove("XDG_CONFIG_HOME")
            .stdin(Stdio::null())
            .kill_on_drop(true);
        cmd
    }

    pub(crate) fn mcpdef(&self, mcpdef: &Path, args: &[&str]) -> Command {
        let mut cmd = self.command(mcpdef);
        cmd.args(args);
        cmd
    }
}

async fn gateway_path(
    mcpdef: &Path,
    mock: &Path,
    dir: &Path,
    max: Duration,
) -> Result<GatewayPath> {
    let setup = Setup::new(dir, mock)?;
    let mut up = start_up(&setup, mcpdef, max).await?;
    let (connect_took, url) = connect(&setup, mcpdef, max).await?;

    let client = crate::load::client(max)?;
    let started = Instant::now();
    first_tool_call(&client, &url).await?;
    let call_took = started.elapsed();

    let records = ledger(&setup, mcpdef, max).await?;
    one_allowed_call(&records, None)?;
    let _ = up.child.kill().await;
    Ok(GatewayPath {
        up_us: micros(up.took),
        connect_us: micros(connect_took),
        call_us: micros(call_took),
    })
}

/// `mcpdef up`, running in a project, once it said it was ready.
pub(crate) struct Up {
    pub(crate) child: tokio::process::Child,
    /// From its start until it said it was ready.
    pub(crate) took: Duration,
    /// Each line it says on stderr from then on.
    pub(crate) said: tokio::sync::mpsc::UnboundedReceiver<String>,
}

/// Start `mcpdef up` with no config in `setup`'s project, and wait for it to
/// be ready and to say it fronts the server Claude Code runs.
pub(crate) async fn start_up(setup: &Setup, mcpdef: &Path, max: Duration) -> Result<Up> {
    let (up, said) = start(setup, mcpdef, &["up"], max).await?;
    let fronted = format!("{SERVER}: ");
    ensure!(
        said.iter().any(|l| l.trim_start().starts_with(&fronted)),
        "mcpdef up did not front {SERVER}, the server Claude Code runs:\n{}",
        said.join("\n")
    );
    Ok(up)
}

/// Start `mcpdef` with `args`, `up` and what follows it, in `setup`'s
/// project, and wait for it to be ready: it, and what it said until then,
/// its ready line last.
pub(crate) async fn start(
    setup: &Setup,
    mcpdef: &Path,
    args: &[&str],
    max: Duration,
) -> Result<(Up, Vec<String>)> {
    let started = Instant::now();
    let mut child = setup
        .mcpdef(mcpdef, args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting mcpdef up")?;
    let mut lines = BufReader::new(child.stderr.take().context("mcpdef up's stderr")?).lines();
    let mut said = Vec::new();
    let ready = tokio::time::timeout(max, async {
        while let Some(line) = lines.next_line().await? {
            let ready = line.contains(" ready · ");
            said.push(line);
            if ready {
                return Ok(true);
            }
        }
        Ok::<_, std::io::Error>(false)
    })
    .await;
    let took = started.elapsed();
    match ready {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => bail!(
            "mcpdef up stopped before it was ready (it listens on 127.0.0.1:7878, which must \
             be free):\n{}",
            said.join("\n")
        ),
        Ok(Err(e)) => return Err(e).context("reading what mcpdef up says"),
        Err(_) => bail!(
            "mcpdef up was not ready after {max:?}:\n{}",
            said.join("\n")
        ),
    }
    // Go on reading what it says, so that it never waits on a full pipe,
    // whether or not anyone listens.
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            let _ = tx.send(line);
        }
    });
    let up = Up {
        child,
        took,
        said: rx,
    };
    Ok((up, said))
}

/// `mcpdef connect claude-code --write --replace`, timed, and the URL of the
/// one entry it left in `.mcp.json`: the gateway's.
pub(crate) async fn connect(
    setup: &Setup,
    mcpdef: &Path,
    max: Duration,
) -> Result<(Duration, String)> {
    let (took, out) = timed(
        setup.mcpdef(mcpdef, &["connect", "claude-code", "--write", "--replace"]),
        "mcpdef connect",
        max,
    )
    .await?;
    ensure!(
        out.contains(&format!("took {SERVER} out of .mcp.json")),
        "mcpdef connect did not take {SERVER} out of .mcp.json:\n{out}"
    );
    let entries = read_json(&setup.project.join(".mcp.json"))?;
    let entries = entries
        .get("mcpServers")
        .and_then(Value::as_object)
        .context(".mcp.json has no mcpServers")?;
    let names: Vec<&str> = entries.keys().map(String::as_str).collect();
    ensure!(
        names == ["mcpdef"],
        "after mcpdef connect, .mcp.json names {names:?}, where the gateway alone should be left"
    );
    let url = entries["mcpdef"]
        .get("url")
        .and_then(Value::as_str)
        .context("the gateway's entry in .mcp.json has no url")?
        .to_string();
    Ok((took, url))
}

/// What a client does once it is pointed at the gateway: `initialize`, then
/// `tools/list`, then a call to the tool it found. The session the gateway
/// gave, if it gave one.
pub(crate) async fn first_tool_call(client: &reqwest::Client, url: &str) -> Result<Option<String>> {
    let (init, session) = post(
        client,
        url,
        None,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "mcpdef-bench", "version": env!("CARGO_PKG_VERSION") },
        } }),
    )
    .await?;
    ensure!(
        init.as_ref()
            .and_then(|r| r.pointer("/result/protocolVersion"))
            .is_some(),
        "initialize was not answered: {init:?}"
    );
    let given = session;
    let session = given.as_deref();
    post(
        client,
        url,
        session,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    )
    .await?;
    let (listed, _) = post(
        client,
        url,
        session,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
    )
    .await?;
    let tools = listed
        .as_ref()
        .and_then(|r| r.pointer("/result/tools"))
        .and_then(Value::as_array);
    ensure!(
        tools.is_some_and(|t| t.iter().any(|t| t["name"] == TOOL)),
        "tools/list does not list {TOOL}: {listed:?}"
    );
    let (called, _) = post(
        client,
        url,
        session,
        json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": TOOL, "arguments": { "text": "mcpdef-bench" },
        } }),
    )
    .await?;
    let result = called.as_ref().and_then(|r| r.get("result"));
    ensure!(
        result.and_then(|r| r.get("isError")) == Some(&Value::Bool(false))
            && result.and_then(|r| r.pointer("/content/0/text")) == Some(&json!("ok")),
        "the call to {TOOL} was not answered as the server answers it: {called:?}"
    );
    Ok(given)
}

/// POST one JSON-RPC message as a Streamable HTTP client does: in `session`,
/// the one the gateway gave, if it gave one. The reply to a request, from a
/// JSON body or from an event stream, and the session the answer names.
pub(crate) async fn post(
    client: &reqwest::Client,
    url: &str,
    session: Option<&str>,
    msg: Value,
) -> Result<(Option<Value>, Option<String>)> {
    let method = msg["method"].as_str().unwrap_or_default().to_string();
    let mut request = client
        .post(url)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json, text/event-stream")
        .header("mcp-protocol-version", PROTOCOL_VERSION);
    if let Some(session) = session {
        request = request.header("mcp-session-id", session);
    }
    let resp = request
        .body(msg.to_string())
        .send()
        .await
        .with_context(|| format!("sending {method}"))?;
    let status = resp.status();
    let named = resp
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let stream = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|t| t.starts_with("text/event-stream"));
    let body = resp
        .text()
        .await
        .with_context(|| format!("reading the answer to {method}"))?;
    ensure!(
        status.is_success(),
        "{method} was answered {status}: {body}"
    );
    if msg.get("id").is_none() {
        return Ok((None, named));
    }
    let reply = match stream {
        false => serde_json::from_str(&body).with_context(|| format!("the answer to {method}"))?,
        true => body
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .filter_map(|data| serde_json::from_str::<Value>(data.trim()).ok())
            .find(|m| m.get("id") == msg.get("id"))
            .with_context(|| format!("the event stream answering {method} holds no answer"))?,
    };
    Ok((Some(reply), named))
}

async fn hook_path(mcpdef: &Path, mock: &Path, dir: &Path, max: Duration) -> Result<HookPath> {
    let setup = Setup::new(dir, mock)?;

    let (import_took, _) = timed(
        setup.mcpdef(mcpdef, &["import", "--out", "mcpdef.toml"]),
        "mcpdef import",
        max,
    )
    .await?;
    ensure!(
        setup.project.join("mcpdef.toml").is_file(),
        "mcpdef import wrote no mcpdef.toml"
    );
    let (install_took, _) = timed(
        setup.mcpdef(
            mcpdef,
            &["hook", "install", "--config", "mcpdef.toml", "--write"],
        ),
        "mcpdef hook install",
        max,
    )
    .await?;

    let (command, wait) = installed_hook(&setup)?;
    let (hook_took, out) = run_hook(&setup, &command, wait.min(max)).await?;
    // An allowed call gets no answer, so that the client goes on as it would.
    ensure!(
        out.status.success() && out.stdout.iter().all(u8::is_ascii_whitespace),
        "the hook did not let the call through ({}):\n{}{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let records = ledger(&setup, mcpdef, max).await?;
    one_allowed_call(&records, Some("claude-code"))?;
    Ok(HookPath {
        import_us: micros(import_took),
        install_us: micros(install_took),
        hook_us: micros(hook_took),
    })
}

/// The hook Claude Code would run before a call to the server's tool, from
/// the settings `hook install` wrote, and how long Claude Code waits for it.
pub(crate) fn installed_hook(setup: &Setup) -> Result<(String, Duration)> {
    let tool = format!("mcp__{SERVER}__{TOOL}");
    let settings = read_json(&setup.project.join(".claude").join("settings.local.json"))?;
    let groups = settings
        .pointer("/hooks/PreToolUse")
        .and_then(Value::as_array)
        .context("the settings hook install wrote have no PreToolUse hook")?;
    let hook = groups
        .iter()
        .filter(|g| g["matcher"].as_str().is_some_and(|m| matches(m, &tool)))
        .filter_map(|g| g["hooks"].as_array())
        .flatten()
        .find(|h| h["type"] == "command")
        .with_context(|| format!("no PreToolUse hook runs a command before {tool}: {settings}"))?;
    let command = hook["command"]
        .as_str()
        .context("the hook has no command")?;
    // Claude Code's own wait for a hook that names none is ten minutes.
    let wait = hook["timeout"]
        .as_u64()
        .map_or(Duration::from_secs(600), Duration::from_secs);
    Ok((command.to_string(), wait))
}

/// Run `command` through the shell, as Claude Code runs a hook, with the event
/// it sends before a call to the server's tool, timed: what the hook answered.
pub(crate) async fn run_hook(
    setup: &Setup,
    command: &str,
    wait: Duration,
) -> Result<(Duration, std::process::Output)> {
    let event = json!({
        "session_id": "mcpdef-bench",
        "transcript_path": setup.project.join(".claude").join("transcript.jsonl"),
        "cwd": setup.project,
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": format!("mcp__{SERVER}__{TOOL}"),
        "tool_input": { "text": "mcpdef-bench" },
    });
    let started = Instant::now();
    let mut child = setup
        .command("sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting the hook")?;
    let mut stdin = child.stdin.take().context("the hook's stdin")?;
    stdin.write_all(event.to_string().as_bytes()).await?;
    drop(stdin);
    let out = tokio::time::timeout(wait, child.wait_with_output())
        .await
        .with_context(|| format!("the hook did not answer in {wait:?}"))??;
    Ok((started.elapsed(), out))
}

/// Whether a Claude Code hook `matcher` takes `tool`: every tool for `*` or
/// none, else one of its `|` alternatives, each a name, or a prefix and `.*`.
/// A matcher written any other way is not judged, and takes nothing.
fn matches(matcher: &str, tool: &str) -> bool {
    if matcher.is_empty() || matcher == "*" {
        return true;
    }
    let plain = |s: &str| !s.contains(|c: char| "\\^$.|?*+()[]{}".contains(c));
    matcher.split('|').any(|alt| match alt.strip_suffix(".*") {
        Some(prefix) if plain(prefix) => tool.starts_with(prefix),
        _ => plain(alt) && alt == tool,
    })
}

/// The project's ledger, by `mcpdef audit tail`, once `mcpdef audit verify`
/// has checked its chain.
pub(crate) async fn ledger(setup: &Setup, mcpdef: &Path, max: Duration) -> Result<Vec<Value>> {
    timed(
        setup.mcpdef(mcpdef, &["audit", "verify", "--config", "mcpdef.toml"]),
        "mcpdef audit verify",
        max,
    )
    .await?;
    let (_, out) = timed(
        setup.mcpdef(
            mcpdef,
            &[
                "audit",
                "tail",
                "--config",
                "mcpdef.toml",
                "--format",
                "json",
                "-n",
                "100",
            ],
        ),
        "mcpdef audit tail",
        max,
    )
    .await?;
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).with_context(|| format!("a ledger record: {l}")))
        .collect()
}

/// The ledger holds one tool call, the one made, allowed, and judged by the
/// hook of `hook` when it is given.
fn one_allowed_call(records: &[Value], hook: Option<&str>) -> Result<()> {
    let calls: Vec<&Value> = records
        .iter()
        .filter(|r| r["method"] == "tools/call")
        .collect();
    let made = |r: &Value| {
        r["server"] == SERVER
            && r["tool"] == TOOL
            && r["decision"] == "allow"
            && hook.is_none_or(|h| r["hook"] == h)
    };
    ensure!(
        calls.len() == 1 && made(calls[0]),
        "the ledger does not hold the one call, allowed{}: {records:?}",
        hook.map(|h| format!(", from the {h} hook"))
            .unwrap_or_default()
    );
    Ok(())
}

/// Run `cmd` to its end, timed, and give back what it printed on stdout. An
/// error, with all it printed, unless it succeeds within `max`.
pub(crate) async fn timed(
    mut cmd: Command,
    what: &str,
    max: Duration,
) -> Result<(Duration, String)> {
    let started = Instant::now();
    let out = tokio::time::timeout(max, cmd.output())
        .await
        .with_context(|| format!("{what} did not finish in {max:?}"))?
        .with_context(|| format!("starting {what}"))?;
    let took = started.elapsed();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    ensure!(
        out.status.success(),
        "{what} failed ({}):\n{stdout}{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    Ok((took, stdout))
}

pub(crate) fn read_json(path: &Path) -> Result<Value> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")
        .with_context(|| format!("writing {}", path.display()))
}

pub(crate) fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

impl Report {
    /// The paths that took longer than the report's `max_ms`, by run.
    pub fn over(&self) -> Vec<String> {
        let max_us = self.max_ms.saturating_mul(1000);
        let mut over = Vec::new();
        for (n, run) in self.runs.iter().enumerate() {
            for (path, total) in [
                ("the gateway", run.gateway.total_us()),
                ("the hook", run.hook.total_us()),
            ] {
                if total > max_us {
                    over.push(format!(
                        "run {}, through {path}: {}, over {}",
                        n + 1,
                        fmt_us(total),
                        fmt_us(max_us)
                    ));
                }
            }
        }
        over
    }

    /// Markdown: each step's range over the runs, for people and for a CI job
    /// summary.
    pub fn render(&self) -> String {
        let mut s = String::new();
        let m = &self.machine;
        let _ = writeln!(s, "## mcpdef-bench first-call — {}", self.mcpdef_version);
        let _ = writeln!(
            s,
            "\n{} {} · {} CPUs{}{} · {} run(s)",
            m.os,
            m.arch,
            m.cpus,
            m.cpu_model
                .as_deref()
                .map(|c| format!(" ({c})"))
                .unwrap_or_default(),
            self.commit
                .as_deref()
                .map(|c| format!(" · commit `{}`", c.chars().take(12).collect::<String>()))
                .unwrap_or_default(),
            self.runs.len(),
        );
        if let Some(note) = &self.note {
            let _ = writeln!(s, "\n> {note}");
        }
        let _ = writeln!(
            s,
            "\n### The first governed call, from an installed mcpdef\n"
        );
        let _ = writeln!(s, "| Path | Step | Time |");
        let _ = writeln!(s, "|---|---|---|");
        let rows: [(&str, &str, Step); 8] = [
            (
                "gateway",
                "`mcpdef up`, with no config, until it is ready",
                |r| r.gateway.up_us,
            ),
            ("", "`mcpdef connect claude-code --write --replace`", |r| {
                r.gateway.connect_us
            }),
            (
                "",
                "the client's `initialize`, `tools/list` and first `tools/call`, answered",
                |r| r.gateway.call_us,
            ),
            ("", "**all three**", |r| r.gateway.total_us()),
            ("hook", "`mcpdef import --out mcpdef.toml`", |r| {
                r.hook.import_us
            }),
            (
                "",
                "`mcpdef hook install --config mcpdef.toml --write`",
                |r| r.hook.install_us,
            ),
            (
                "",
                "the hook Claude Code runs before the first MCP tool call",
                |r| r.hook.hook_us,
            ),
            ("", "**all three**", |r| r.hook.total_us()),
        ];
        for (path, step, time_of) in rows {
            let time = fmt_range(&self.runs.iter().map(time_of).collect::<Vec<_>>());
            let time = match step.starts_with("**") {
                true => format!("**{time}**"),
                false => time,
            };
            let _ = writeln!(s, "| {path} | {step} | {time} |");
        }
        let _ = writeln!(
            s,
            "\nEach time is the range over the runs, from a fresh home directory and project each \
             time. Through the gateway, each call was answered as the server answers it; through \
             the hook, the hook let it through, and the client then makes it to the server \
             itself, untimed. Each was recorded in the ledger, and the ledger verified. A path \
             fails the run past {}.",
            fmt_us(self.max_ms.saturating_mul(1000))
        );
        s
    }
}

/// One step's time, or one path's, in a run.
type Step = fn(&Run) -> u64;

/// `values`' smallest and largest, as one range.
fn fmt_range(values: &[u64]) -> String {
    let (Some(lo), Some(hi)) = (values.iter().min(), values.iter().max()) else {
        return "—".into();
    };
    match lo == hi {
        true => fmt_us(*lo),
        false => format!("{}–{}", fmt_us(*lo), fmt_us(*hi)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(runs: &[(u64, u64)]) -> Report {
        Report {
            schema: SCHEMA,
            generated_at_unix: 0,
            mcpdef_version: "mcpdef 0.0.0".into(),
            commit: None,
            note: Some("a test".into()),
            machine: Machine {
                os: "linux".into(),
                arch: "x86_64".into(),
                cpus: 4,
                cpu_model: None,
                mem_total_kb: None,
            },
            max_ms: 60_000,
            runs: runs
                .iter()
                .map(|&(gateway, hook)| Run {
                    gateway: GatewayPath {
                        up_us: gateway,
                        connect_us: 1_000,
                        call_us: 2_000,
                    },
                    hook: HookPath {
                        import_us: hook,
                        install_us: 1_000,
                        hook_us: 2_000,
                    },
                })
                .collect(),
        }
    }

    #[test]
    fn a_path_is_the_sum_of_its_steps() {
        let run = report(&[(30_000, 4_000)]).runs[0];
        assert_eq!(run.gateway.total_us(), 33_000);
        assert_eq!(run.hook.total_us(), 7_000);
    }

    #[test]
    fn a_path_past_the_limit_is_named() {
        assert!(report(&[(30_000, 4_000)]).over().is_empty());
        let over = report(&[(30_000, 4_000), (61_000_000, 4_000)]).over();
        assert_eq!(over.len(), 1, "{over:?}");
        assert!(
            over[0].starts_with("run 2, through the gateway: 61.00 s"),
            "{over:?}"
        );
    }

    #[test]
    fn the_report_gives_each_steps_range() {
        let md = report(&[(30_000, 4_000), (35_000, 5_000)]).render();
        assert!(
            md.contains(
                "| gateway | `mcpdef up`, with no config, until it is ready | 30.00 ms–35.00 ms |"
            ),
            "{md}"
        );
        assert!(
            md.contains("|  | **all three** | **33.00 ms–38.00 ms** |"),
            "{md}"
        );
        assert!(
            md.contains("| hook | `mcpdef import --out mcpdef.toml` | 4.00 ms–5.00 ms |"),
            "{md}"
        );
        assert!(
            md.contains("|  | **all three** | **7.00 ms–8.00 ms** |"),
            "{md}"
        );
        assert!(md.contains("linux x86_64 · 4 CPUs · 2 run(s)"), "{md}");
        assert!(md.contains("\n> a test\n"), "{md}");
        let one = report(&[(30_000, 4_000)]).render();
        assert!(one.contains("| 30.00 ms |"), "{one}");
    }

    /// The reports behind docs/PERFORMANCE.md, ten runs of each build.
    #[test]
    fn the_committed_reports_still_load() {
        for text in [
            include_str!("../baselines/first-call-static-musl.json"),
            include_str!("../baselines/first-call-glibc.json"),
        ] {
            let report: Report = serde_json::from_str(text).unwrap();
            assert_eq!(report.schema, SCHEMA);
            assert_eq!(report.runs.len(), 10);
            assert!(report.over().is_empty(), "{:?}", report.over());
            assert!(report.render().contains("**all three**"));
        }
    }

    #[test]
    fn a_matcher_is_read_as_claude_code_reads_it() {
        let tool = "mcp__demo__echo";
        for takes in ["", "*", "mcp__.*", "mcp__demo__.*", "Bash|mcp__.*", tool] {
            assert!(matches(takes, tool), "{takes:?}");
        }
        for not in [
            "mcp__other__.*",
            "Bash",
            "mcp__demo__echo2",
            "mcp__d.mo__.*",
            "^mcp__.*",
        ] {
            assert!(!matches(not, tool), "{not:?}");
        }
    }
}
