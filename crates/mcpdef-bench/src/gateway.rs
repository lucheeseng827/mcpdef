// SPDX-License-Identifier: Apache-2.0
//! The gateway under test: the real `mcpdef` binary, run as a child process with a
//! generated config, exactly as an operator would run it.
//!
//! Measuring the shipped binary rather than the library in-process keeps the
//! numbers honest — its own Tokio runtime, its own allocator, its own startup —
//! and means the harness needs nothing from the engine crates to build.

use anyhow::{anyhow, bail, Context, Result};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};

/// How long a gateway may take to come up. Stdio upstreams are spawned and
/// handshaken before the listener binds, so this covers all of them.
const READY_TIMEOUT: Duration = Duration::from_secs(60);

/// One upstream in the generated `mcpdef.toml`, with the tools it allowlists.
#[derive(Clone, Debug)]
pub enum Upstream {
    Http {
        id: String,
        url: String,
        allow: Vec<String>,
    },
    Stdio {
        id: String,
        command: Vec<String>,
        allow: Vec<String>,
    },
}

/// Resident memory of a process, in KiB.
#[derive(Clone, Copy, Debug)]
pub struct Memory {
    pub rss_kb: u64,
    /// Peak resident set (`VmHWM`). Linux only.
    pub hwm_kb: Option<u64>,
    /// The anonymous part of the resident set (`RssAnon`): heap and stacks, the
    /// memory the process allocated. Linux only.
    pub anon_kb: Option<u64>,
    /// The file-backed part (`RssFile`): mostly clean pages of the executable,
    /// which the kernel faults in and drops as its page cache sees fit, so it
    /// moves between runs of the same binary. Linux only.
    pub file_kb: Option<u64>,
}

/// A running `mcpdef run --http`, fronting the upstreams it was started with.
/// The child is killed when this is dropped.
pub struct Gateway {
    child: Child,
    /// The MCP endpoint clients POST to.
    pub url: String,
    /// The admin listener's base URL, when the gateway was started with the
    /// console on.
    pub admin: Option<String>,
    pub pid: u32,
    log: PathBuf,
}

impl Gateway {
    /// Write a config for `upstreams` into `dir`, start `mcpdef` on it, and wait
    /// until it answers a `ping`. With `console`, its admin listener is on too,
    /// serving the console.
    pub async fn start(
        mcpdef: &Path,
        dir: &Path,
        upstreams: &[Upstream],
        console: bool,
        client: &reqwest::Client,
    ) -> Result<Gateway> {
        // The free port is found by binding and releasing it, so something else can
        // take it before mcpdef binds. Rare, and a retry on a new port settles it.
        let mut last_err = None;
        for attempt in 0..3 {
            let port = free_port()?;
            let admin = if console { Some(free_port()?) } else { None };
            let config = dir.join("mcpdef.toml");
            std::fs::write(&config, render_config(dir, port, admin, upstreams))
                .with_context(|| format!("writing {}", config.display()))?;
            let log = dir.join(format!("mcpdef-{attempt}.log"));
            let child = Command::new(mcpdef)
                .arg("run")
                .arg("--http")
                .arg("--config")
                .arg(&config)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(std::fs::File::create(&log)?)
                .kill_on_drop(true)
                .spawn()
                .with_context(|| format!("starting {}", mcpdef.display()))?;
            let pid = child.id().context("mcpdef exited as it started")?;
            let mut gateway = Gateway {
                child,
                url: format!("http://127.0.0.1:{port}/mcp"),
                admin: admin.map(|port| format!("http://127.0.0.1:{port}")),
                pid,
                log,
            };
            match gateway.wait_ready(client).await {
                Ok(()) => return Ok(gateway),
                Err(e) => {
                    gateway.stop().await;
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("mcpdef did not start")))
    }

    async fn wait_ready(&mut self, client: &reqwest::Client) -> Result<()> {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait()? {
                bail!(
                    "mcpdef exited ({status}) before it was ready:\n{}",
                    self.log_tail()
                );
            }
            let ping = client
                .post(&self.url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(r#"{"jsonrpc":"2.0","id":0,"method":"ping"}"#)
                .send()
                .await;
            if matches!(&ping, Ok(resp) if resp.status().is_success()) {
                return Ok(());
            }
            if Instant::now() > deadline {
                bail!(
                    "mcpdef was not ready after {READY_TIMEOUT:?}:\n{}",
                    self.log_tail()
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// The last lines of the gateway's stderr, for an error message.
    pub fn log_tail(&self) -> String {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(20)..].join("\n")
    }

    /// Resident memory of the gateway process itself — not its stdio children.
    pub fn memory(&self) -> Option<Memory> {
        read_memory(self.pid)
    }

    pub async fn stop(&mut self) {
        let _ = self.child.kill().await;
    }
}

/// The first line of `mcpdef version`, recorded in the report.
pub fn version(mcpdef: &Path) -> Result<String> {
    let out = std::process::Command::new(mcpdef)
        .arg("version")
        .output()
        .with_context(|| format!("running {} version", mcpdef.display()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text.lines().next().unwrap_or_default().trim().to_string())
}

fn free_port() -> Result<u16> {
    Ok(std::net::TcpListener::bind(("127.0.0.1", 0))?
        .local_addr()?
        .port())
}

/// The `mcpdef.toml` for one run: a loopback listener, a ledger in the scratch
/// directory, the admin listener on `admin` when there is one, and one
/// `[[server]]` per upstream with its allowlist. Everything else stays at its
/// default, so what is measured is the default gateway.
pub fn render_config(dir: &Path, port: u16, admin: Option<u16>, upstreams: &[Upstream]) -> String {
    let audit = dir.join("audit").join("audit.log");
    let mut s = String::new();
    let _ = writeln!(s, "[gateway]");
    let _ = writeln!(s, "listen = {}", toml_str(&format!("127.0.0.1:{port}")));
    let _ = writeln!(s, "audit = {}", toml_str(&audit.to_string_lossy()));
    if let Some(admin) = admin {
        let _ = writeln!(
            s,
            "state_dir = {}",
            toml_str(&dir.join("state").to_string_lossy())
        );
        let _ = writeln!(s, "\n[gateway.admin]\nenabled = true");
        let _ = writeln!(s, "listen = {}", toml_str(&format!("127.0.0.1:{admin}")));
    }
    for upstream in upstreams {
        let _ = writeln!(s, "\n[[server]]");
        match upstream {
            Upstream::Http { id, url, allow } => {
                let _ = writeln!(s, "id = {}", toml_str(id));
                let _ = writeln!(s, "transport = \"streamable-http\"");
                let _ = writeln!(s, "url = {}", toml_str(url));
                let _ = writeln!(s, "tools = {}", toml_list(allow));
            }
            Upstream::Stdio { id, command, allow } => {
                let _ = writeln!(s, "id = {}", toml_str(id));
                let _ = writeln!(s, "transport = \"stdio\"");
                let _ = writeln!(s, "command = {}", toml_list(command));
                let _ = writeln!(s, "tools = {}", toml_list(allow));
            }
        }
    }
    s
}

/// A TOML basic string.
fn toml_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn toml_list(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|i| toml_str(i)).collect();
    format!("[{}]", inner.join(", "))
}

fn read_memory(pid: u32) -> Option<Memory> {
    if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
        let field = |name: &str| -> Option<u64> {
            status
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        };
        return Some(Memory {
            rss_kb: field("VmRSS:")?,
            hwm_kb: field("VmHWM:"),
            anon_kb: field("RssAnon:"),
            file_kb: field("RssFile:"),
        });
    }
    // Not Linux: `ps` reports RSS in KiB on macOS and the BSDs.
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let rss_kb = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
    Some(Memory {
        rss_kb,
        hwm_kb: None,
        anon_kb: None,
        file_kb: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_strings_escape_what_toml_requires() {
        assert_eq!(toml_str("plain"), "\"plain\"");
        assert_eq!(toml_str(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(toml_str("tab\there"), "\"tab\\there\"");
        assert_eq!(toml_str("bell\u{7}"), "\"bell\\u0007\"");
    }

    #[test]
    fn the_config_names_every_upstream_and_its_allowlist() {
        let dir = Path::new("/tmp/x");
        let cfg = render_config(
            dir,
            7000,
            None,
            &[
                Upstream::Http {
                    id: "h".into(),
                    url: "http://127.0.0.1:1/mcp".into(),
                    allow: vec!["echo".into()],
                },
                Upstream::Stdio {
                    id: "s".into(),
                    command: vec!["/bin/mock".into(), "mock-stdio".into()],
                    allow: vec!["t1".into(), "t2".into()],
                },
            ],
        );
        assert!(cfg.contains("listen = \"127.0.0.1:7000\""));
        assert!(cfg.contains("transport = \"streamable-http\""));
        assert!(cfg.contains("url = \"http://127.0.0.1:1/mcp\""));
        assert!(cfg.contains("command = [\"/bin/mock\", \"mock-stdio\"]"));
        assert!(cfg.contains("tools = [\"t1\", \"t2\"]"));
        assert_eq!(cfg.matches("[[server]]").count(), 2);
        assert!(!cfg.contains("[gateway.admin]"));
        let with_console = render_config(Path::new("/tmp/run"), 7000, Some(7001), &[]);
        assert!(
            with_console.contains("[gateway.admin]\nenabled = true\nlisten = \"127.0.0.1:7001\"")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_has_a_resident_set() {
        let m = read_memory(std::process::id()).expect("readable /proc status");
        assert!(m.rss_kb > 0);
        assert!(m.hwm_kb.unwrap_or(0) >= m.rss_kb);
        let (anon, file) = (m.anon_kb.unwrap(), m.file_kb.unwrap());
        assert!(anon > 0 && file > 0);
        // The two are parts of the resident set (with shared memory, `RssShmem`,
        // the third), read in the same instant.
        assert!(anon + file <= m.rss_kb);
    }
}
