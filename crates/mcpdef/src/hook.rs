// SPDX-License-Identifier: Apache-2.0
//! `mcpdef hook`: MCPdef as an agent client's pre-tool-call hook, with no
//! proxy in the path.
//!
//! The client asks, before each MCP tool call, and MCPdef judges the call by
//! the same config a gateway would: the server's allowlist and the active
//! profile, the transform rules and the policy rules, over the arguments the
//! client is about to send. It writes the decision to the same ledger, so a
//! team that starts with the hook and later puts the gateway in the path keeps
//! its history, and `mcpdef receipts export` signs the hook's decisions as it
//! signs the gateway's.
//!
//! What only the path can see, a hook cannot judge: the definitions a server
//! lists (pins, the injection scan), what a call returns (result transforms,
//! the result scan), the caller's credentials (RBAC) and how often calls come
//! (rate limits, which would need state across the hook's processes).

use crate::clients::{backup_path, shell_line, write_like, Wrote};
use crate::config::Config;
use anyhow::{anyhow, bail, Context as _};
use mcpdef_audit::{Attrs, Durability, Entry, Ledger, Record};
use mcpdef_core::{method, Decision};
use mcpdef_policy::{PolicyContext, Target};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// The tool names the hook is asked about: every MCP tool. A server the
/// config does not name is refused, as the gateway refuses one. Both clients
/// read a matcher as a regular expression over the tool's name.
pub const MATCHER: &str = "mcp__.*";

/// How long a client waits for the hook before it gives up on it, in seconds,
/// unless `mcpdef hook install --timeout` says otherwise. Both clients wait 600
/// seconds for a hook that names no timeout, so a hook that hung would hold
/// each MCP call for ten minutes. MCPdef answers in milliseconds; the rest is
/// room for a cold start and a turn on the ledger's lock behind other writers.
pub const DEFAULT_TIMEOUT_SECS: u32 = 10;

/// An agent client that asks a hook before each tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    /// Claude Code's `PreToolUse` hook.
    ClaudeCode,
    /// Codex's `PreToolUse` hook, which reads and answers as Claude Code's
    /// does for what MCPdef sends and reads.
    Codex,
}

impl Client {
    /// The `--client` values, as an error names them.
    pub const NAMES: &'static str = "claude-code or codex";

    /// The client a `--client` value names.
    pub fn parse(name: &str) -> Option<Client> {
        match name {
            "claude-code" => Some(Client::ClaudeCode),
            "codex" => Some(Client::Codex),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Client::ClaudeCode => "claude-code",
            Client::Codex => "codex",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Client::ClaudeCode => "Claude Code",
            Client::Codex => "Codex",
        }
    }

    /// The settings a hook goes in, unless told otherwise: the project's own.
    /// Claude Code's are the user's alone and not shared with the repository.
    /// Codex has no such file: its project hooks are the repository's
    /// `.codex/hooks.json`, which it runs once the project is trusted.
    pub fn settings(self) -> PathBuf {
        match self {
            Client::ClaudeCode => PathBuf::from(".claude").join("settings.local.json"),
            Client::Codex => PathBuf::from(".codex").join("hooks.json"),
        }
    }

    /// The hook that asks `program`, judging by the config at `config`, before
    /// each MCP tool call: a `PreToolUse` matcher group, which the client gives
    /// up on after `timeout` seconds.
    ///
    /// What a client does with a hook that fails, its program gone, killed or
    /// out of time, differs. Claude Code goes on with the call unless the hook
    /// says `"onFailure": "block"`, which this one does. Codex has no such
    /// setting and goes on with it: there, only a refusal MCPdef gets to make
    /// stops a call, which is why the timeout is short.
    ///
    /// Codex runs a hook through `$SHELL -lc` on Unix and `%COMSPEC% /C` on
    /// Windows, where it takes `commandWindows` over `command`. So a Codex hook
    /// carries both: the POSIX line, and the line `cmd.exe` reads. Where a path
    /// cannot be put to `cmd.exe` safely there is no Windows line, and on
    /// Windows, where Codex would run the POSIX line and fail open, no hook.
    ///
    /// With `bundle_trust`, the keys a bundle may be signed with, the hook
    /// judges only by a config the signed bundle beside it holds
    /// (`mcpdef hook --bundle-trust`).
    pub fn hook(
        self,
        program: &Path,
        config: &Path,
        timeout: u32,
        bundle_trust: Option<&Path>,
    ) -> Result<Value, String> {
        self.hook_on(program, config, timeout, bundle_trust, cfg!(windows))
    }

    fn hook_on(
        self,
        program: &Path,
        config: &Path,
        timeout: u32,
        bundle_trust: Option<&Path>,
        windows: bool,
    ) -> Result<Value, String> {
        let program = simplified(&program.to_string_lossy());
        let config = simplified(&config.to_string_lossy());
        let mut args = vec!["hook".to_string()];
        if self != Client::ClaudeCode {
            // `mcpdef hook` takes its client to be Claude Code unless told.
            args.extend(["--client".to_string(), self.name().to_string()]);
        }
        args.extend(["--config".to_string(), config]);
        if let Some(keys) = bundle_trust {
            args.extend([
                "--bundle-trust".to_string(),
                simplified(&keys.to_string_lossy()),
            ]);
        }
        let command = shell_line(&program, &args);
        let handler = match self {
            Client::ClaudeCode => json!({
                "type": "command",
                "command": command,
                "timeout": timeout,
                "onFailure": "block",
            }),
            Client::Codex => {
                let mut handler = json!({
                    "type": "command",
                    "command": command,
                    "timeout": timeout,
                });
                match cmd_line(&program, &args) {
                    Ok(line) => handler["commandWindows"] = Value::String(line),
                    Err(why) if windows => {
                        return Err(format!(
                            "{why}: Codex on Windows would run the hook through cmd.exe, \
                             which cannot be given that safely, and goes on with a call \
                             whose hook did not run. Move the file, or put the gateway in \
                             the path (`mcpdef connect codex`)"
                        ))
                    }
                    Err(_) => {}
                }
                handler
            }
        };
        Ok(json!({ "matcher": MATCHER, "hooks": [handler] }))
    }

    /// The event the client sent, from `text`. Both clients send the fields
    /// MCPdef reads under the same names, among others it does not read.
    pub fn event(self, text: &str) -> anyhow::Result<Event> {
        let event: HookEvent = serde_json::from_str(text)
            .with_context(|| format!("not a {} hook event", self.title()))?;
        Ok(Event {
            client: self,
            pre_tool_use: event.hook_event_name == "PreToolUse",
            tool_name: event.tool_name,
            args: event.tool_input,
            agent: format!("agent:{}", self.name()),
        })
    }

    /// What the client is told of `verdict` on standard output: a refusal,
    /// with why, or nothing, so that the client goes on as it would. MCPdef
    /// never answers a call is allowed: that would pass over the user's own
    /// permissions, and any other hook's. A refusal also exits with status 2,
    /// which blocks the call whatever the client makes of the answer. Both
    /// clients read the same refusal.
    pub fn answer(self, event: &Event, verdict: &Verdict) -> Option<String> {
        let refusal = verdict.refusal()?;
        let _ = event;
        Some(
            json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": refusal,
                }
            })
            .to_string(),
        )
    }
}

/// A client's hook event, for what MCPdef reads of it.
#[derive(Deserialize)]
struct HookEvent {
    hook_event_name: String,
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_input: Value,
}

/// An event a client's hook sent.
#[derive(Debug, Clone)]
pub struct Event {
    client: Client,
    pre_tool_use: bool,
    tool_name: String,
    args: Value,
    agent: String,
}

impl Event {
    /// The tool call the client is about to make, if this is one.
    pub fn call(&self) -> Option<Call<'_>> {
        let _ = self.client;
        (self.pre_tool_use && self.tool_name.starts_with("mcp__")).then(|| Call {
            agent: &self.agent,
            tool_name: &self.tool_name,
            args: &self.args,
        })
    }
}

/// Merge `hook` into the client's settings at `file`, in place of any hook
/// that runs `mcpdef hook` there already, keeping a `.bak` of what was there,
/// readable by whom the settings are. Every other hook stays as it is.
pub fn install(hook: &Value, file: &Path) -> anyhow::Result<Wrote> {
    let before = match std::fs::read_to_string(file) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("reading {}", file.display())),
    };
    let mut doc: Value = match before.as_deref() {
        None => json!({}),
        Some(text) if text.trim().is_empty() => json!({}),
        Some(text) => serde_json::from_str(text).map_err(|e| {
            anyhow!(
                "{} is not plain JSON ({e}), so it is left as it is: add the hook above by hand",
                file.display()
            )
        })?,
    };
    let Some(top) = doc.as_object_mut() else {
        bail!(
            "{} does not hold a JSON object: left as it is",
            file.display()
        );
    };
    let hooks = top.entry("hooks").or_insert_with(|| json!({}));
    let Some(hooks) = hooks.as_object_mut() else {
        bail!(
            "`hooks` in {} is not an object: left as it is",
            file.display()
        );
    };
    let groups = hooks.entry("PreToolUse").or_insert_with(|| json!([]));
    let Some(groups) = groups.as_array_mut() else {
        bail!(
            "`hooks.PreToolUse` in {} is not a list: left as it is",
            file.display()
        );
    };
    for group in groups.iter_mut() {
        if let Some(list) = group.get_mut("hooks").and_then(Value::as_array_mut) {
            list.retain(|h| !runs_mcpdef_hook(h));
        }
    }
    groups.retain(|g| {
        g.get("hooks")
            .and_then(Value::as_array)
            .is_none_or(|list| !list.is_empty())
    });
    groups.push(hook.clone());
    if let Some(text) = &before {
        if serde_json::from_str::<Value>(text).ok().as_ref() == Some(&doc) {
            return Ok(Wrote::Unchanged);
        }
    }
    let after = serde_json::to_string_pretty(&doc)? + "\n";
    if let Some(parent) = file.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let wrote = match &before {
        Some(old) => {
            let backup = backup_path(file);
            write_like(&backup, old, file)
                .with_context(|| format!("writing the backup {}", backup.display()))?;
            Wrote::Updated { backup }
        }
        None => Wrote::Created,
    };
    std::fs::write(file, after).with_context(|| format!("writing {}", file.display()))?;
    Ok(wrote)
}

/// Whether a hook entry runs `mcpdef hook`: its command's program is named
/// `mcpdef` and its next word is `hook`. Either line of it counts, read as
/// the shell that runs it reads it: `command` as a POSIX shell does, and
/// Codex's `commandWindows` as `cmd.exe` does.
fn runs_mcpdef_hook(hook: &Value) -> bool {
    let line = |key: &str| hook.get(key).and_then(Value::as_str);
    line("command").is_some_and(|l| names_mcpdef_hook(&shell_words(l)))
        || line("commandWindows").is_some_and(|l| names_mcpdef_hook(&cmd_words(l)))
}

/// Whether `words` run `mcpdef hook`: `mcpdef`, or `mcpdef.exe` as Windows
/// names it, by a path with either separator, then `hook`.
fn names_mcpdef_hook(words: &[String]) -> bool {
    let named = words.first().is_some_and(|program| {
        let file = program.rsplit(['/', '\\']).next().unwrap_or(program);
        let file = Path::new(file);
        file.file_stem().is_some_and(|stem| stem == "mcpdef")
            && file
                .extension()
                .is_none_or(|ext| ext.eq_ignore_ascii_case("exe"))
    });
    named && words.get(1).map(String::as_str) == Some("hook")
}

/// `program` and `args` as one line `cmd.exe /C` runs as they are, the way
/// Codex hands it a hook's command on Windows (`/C "<line>"`). A word that
/// is more than letters, digits, `-`, `_` and `.` goes in double quotes,
/// inside which `cmd.exe` takes `&`, `|`, `<`, `>`, `^` and parentheses as
/// they are; a Windows path holds no `"`. What a word cannot hold is what
/// `cmd.exe` expands even in quotes: `%` (a variable), `!` (one, under
/// delayed expansion), and a line break. Such a word is no line at all.
fn cmd_line(program: &str, args: &[String]) -> Result<String, String> {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .map(|word| {
            if let Some(c) = word
                .chars()
                .find(|c| matches!(c, '"' | '%' | '!') || c.is_control())
            {
                return Err(format!("'{word}' holds {c:?}"));
            }
            let plain = !word.is_empty()
                && word
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
            Ok(if plain {
                word.to_string()
            } else {
                format!("\"{word}\"")
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|words| words.join(" "))
}

/// The words of a line as `cmd.exe` hands them to a program: whitespace
/// between words, and double quotes around one that has whitespace in it.
/// A backslash is a path's separator, not an escape.
fn cmd_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut quoted = false;
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                word.get_or_insert_with(String::new);
            }
            c if c.is_whitespace() && !quoted => words.extend(word.take()),
            c => word.get_or_insert_with(String::new).push(c),
        }
    }
    words.extend(word);
    words
}

/// `path` without the `\\?\` a Windows path is given by `canonicalize`, as
/// one a shell may be handed: `\\?\C:\x` is `C:\x`, and `\\?\UNC\host\share`
/// is `\\host\share`. Any other path is as it is.
fn simplified(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    match path.strip_prefix(r"\\?\") {
        Some(rest)
            if rest.as_bytes().get(1) == Some(&b':')
                && rest.as_bytes().first().is_some_and(u8::is_ascii_alphabetic) =>
        {
            rest.to_string()
        }
        _ => path.to_string(),
    }
}

/// The words of a POSIX shell command line, as far as quoting goes: single
/// quotes, double quotes, and a backslash outside single quotes. Nothing is
/// expanded.
fn shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word: Option<String> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => words.extend(word.take()),
            '\'' => {
                let w = word.get_or_insert_with(String::new);
                w.extend(chars.by_ref().take_while(|&c| c != '\''));
            }
            '"' => {
                let w = word.get_or_insert_with(String::new);
                while let Some(c) = chars.next() {
                    match c {
                        '"' => break,
                        '\\' => w.extend(chars.next()),
                        c => w.push(c),
                    }
                }
            }
            '\\' => word.get_or_insert_with(String::new).extend(chars.next()),
            c => word.get_or_insert_with(String::new).push(c),
        }
    }
    words.extend(word);
    words
}

/// What MCPdef makes of a tool call a client is about to make.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Not an MCP tool, or not one for MCPdef: the client goes on as it
    /// would, and nothing is recorded.
    NotMine,
    /// Allowed: the client goes on as it would, its own permissions included.
    Allowed,
    /// Refused, by `rule`, for `reason`.
    Denied { rule: String, reason: String },
}

impl Verdict {
    /// Why the call is refused, as the agent is told, when it is.
    pub fn refusal(&self) -> Option<String> {
        match self {
            Verdict::Denied { rule, reason } => Some(format!("MCPdef denied ({rule}): {reason}")),
            Verdict::NotMine | Verdict::Allowed => None,
        }
    }
}

/// A tool call the client is about to make, as its hook names it.
#[derive(Debug, Clone)]
pub struct Call<'a> {
    /// The agent the records name, `agent:<client>` as a stdio gateway names
    /// that client: per-agent rules judge it as they would there.
    pub agent: &'a str,
    /// The client's name for the tool: `mcp__<server>__<tool>`.
    pub tool_name: &'a str,
    /// The arguments the client is about to send.
    pub args: &'a Value,
}

/// The server and the tool `tool_name` names, among `cfg`'s servers, as a
/// client names them: `mcp__<server>__<tool>`, each part with every character
/// other than an ASCII letter, a digit, `_` and `-` as `_`. The longest server
/// id that fits wins, so `mcp__a__b__c` is `b__c` on `a` unless a server is
/// named `a__b`. `None` when it is no MCP tool; `Some((None, tool))` when it is
/// one on a server the config does not name.
pub fn split<'c, 't>(cfg: &'c Config, tool_name: &'t str) -> Option<(Option<&'c str>, &'t str)> {
    let rest = tool_name.strip_prefix("mcp__")?;
    let server = cfg
        .servers
        .iter()
        .map(|s| s.id.as_str())
        .filter(|id| {
            let named = normal(id);
            rest.len() > named.len() + 2
                && rest.starts_with(named.as_str())
                && rest[named.len()..].starts_with("__")
        })
        .max_by_key(|id| id.len());
    match server {
        Some(id) => Some((Some(id), &rest[normal(id).len() + 2..])),
        None => Some((None, rest.split_once("__").map_or(rest, |(_, tool)| tool))),
    }
}

/// `name` as an agent client writes it into a tool's name: every character
/// other than an ASCII letter, a digit, `_` and `-` as `_`.
pub fn normal(name: &str) -> String {
    name.chars()
        .map(
            |c| match c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                true => c,
                false => '_',
            },
        )
        .collect()
}

/// Judge `call` by `cfg`, as the gateway would judge it in the path, for what
/// a hook can see.
pub fn judge(cfg: &Config, call: &Call<'_>) -> (Verdict, Option<String>, Vec<String>) {
    let Some((server, tool)) = split(cfg, call.tool_name) else {
        return (Verdict::NotMine, None, Vec::new());
    };
    let Some(server) = server else {
        let named = call
            .tool_name
            .strip_prefix("mcp__")
            .and_then(|rest| rest.split_once("__"))
            .map_or(call.tool_name, |(server, _)| server);
        return (
            Verdict::Denied {
                rule: "unknown-server".into(),
                reason: format!(
                    "no [[server]] in the config is named '{named}': add it, or run \
                     `mcpdef import` again"
                ),
            },
            None,
            Vec::new(),
        );
    };
    let deny = |d: Decision| match d {
        Decision::Deny { rule, reason } => Some(Verdict::Denied { rule, reason }),
        Decision::Allow => None,
    };
    let at = Some(server.to_string());
    if let Some(denied) = deny(cfg.to_policy().decide_tool(server, tool)) {
        return (denied, at, Vec::new());
    }
    let rules = cfg.policy_rules();
    let mut args = call.args.clone();
    let transformed = match rules.transforms() {
        true => rules.transform(call.agent, server, tool, &mut args),
        false => Default::default(),
    };
    if let Some(denied) = transformed.refused.and_then(deny) {
        return (denied, at, transformed.fired);
    }
    if transformed.changed {
        // A hook can let a call through or stop it, not change what it sends.
        let rule = transformed.fired.last().cloned().unwrap_or_default();
        return (
            Verdict::Denied {
                reason: format!(
                    "transform rule '{rule}' changes the arguments of '{tool}' on '{server}', \
                     which a hook cannot do: put the gateway in the path for it"
                ),
                rule,
            },
            at,
            transformed.fired,
        );
    }
    let ctx = PolicyContext {
        agent: call.agent,
        server,
        target: Target::Tool(tool),
        args: &args,
    };
    match deny(rules.evaluate(&ctx)) {
        Some(denied) => (denied, at, transformed.fired),
        None => (Verdict::Allowed, at, transformed.fired),
    }
}

/// Judge `call` and record the decision in `cfg`'s ledger, as one writer
/// among others: the hook runs in a process of its own for each call, many at
/// once, and maybe beside a gateway on the same ledger. `client` is the
/// hook's client, as the record names it. What was not MCPdef's to judge is
/// not recorded.
pub fn decide(
    cfg: &Config,
    client: &str,
    call: &Call<'_>,
) -> (Verdict, Option<anyhow::Result<Record>>) {
    let started = Instant::now();
    let (verdict, server, transforms) = judge(cfg, call);
    let decision = match &verdict {
        Verdict::NotMine => return (verdict, None),
        Verdict::Allowed => Decision::Allow,
        Verdict::Denied { rule, reason } => Decision::Deny {
            rule: rule.clone(),
            reason: reason.clone(),
        },
    };
    let tool = split(cfg, call.tool_name).map(|(_, tool)| tool.to_string());
    let entry = Entry {
        agent: call.agent.to_string(),
        server: server.unwrap_or_else(|| "(unrouted)".to_string()),
        method: Some(method::TOOLS_CALL.to_string()),
        tool,
        decision,
        latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        attrs: Attrs {
            transforms,
            hook: Some(client.to_string()),
            ..Attrs::default()
        },
    };
    (verdict, Some(record(cfg, entry)))
}

/// Append `entry` to `cfg`'s ledger, taking turns with any other writer.
pub(crate) fn record(cfg: &Config, entry: Entry) -> anyhow::Result<Record> {
    use anyhow::Context as _;
    let path = std::path::Path::new(&cfg.gateway.audit);
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).ok();
    }
    let durability = match cfg.gateway.audit_fsync {
        true => Durability::Fsync,
        false => Durability::Os,
    };
    let mut ledger = Ledger::attach(path, durability)
        .with_context(|| format!("opening the audit ledger {}", path.display()))?;
    ledger
        .append(entry)
        .with_context(|| format!("writing to the audit ledger {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: &str) -> Config {
        Config::parse(&format!(
            "[gateway]\n\n\
             [[server]]\nid = \"github\"\ntransport = \"stdio\"\ncommand = [\"gh\"]\n\
             tools = [\"list_*\"]\n\n\
             [[server]]\nid = \"my.files\"\ntransport = \"stdio\"\ncommand = [\"fs\"]\n\n\
             [[server]]\nid = \"a\"\ntransport = \"stdio\"\ncommand = [\"a\"]\n\n\
             [[server]]\nid = \"a__b\"\ntransport = \"stdio\"\ncommand = [\"ab\"]\n\
             {extra}"
        ))
        .unwrap()
    }

    #[test]
    fn a_tool_name_splits_into_the_server_and_its_tool() {
        let cfg = config("");
        assert_eq!(
            split(&cfg, "mcp__github__list_issues"),
            Some((Some("github"), "list_issues"))
        );
        // The client writes `my.files` as `my_files`.
        assert_eq!(
            split(&cfg, "mcp__my_files__read"),
            Some((Some("my.files"), "read"))
        );
        // The longest server id that fits.
        assert_eq!(split(&cfg, "mcp__a__b__c"), Some((Some("a__b"), "c")));
        assert_eq!(split(&cfg, "mcp__a__c"), Some((Some("a"), "c")));
        assert_eq!(split(&cfg, "mcp__slack__post"), Some((None, "post")));
        assert_eq!(split(&cfg, "mcp__github__"), Some((None, "")));
        assert_eq!(split(&cfg, "Bash"), None);
    }

    #[test]
    fn a_call_is_judged_as_the_gateway_judges_it() {
        let cfg = config(
            "\n[[policy]]\nname = \"no-prod\"\neffect = \"deny\"\ntools = [\"list_*\"]\n\
             args = [{ path = \"repo\", equals = \"prod\" }]\n",
        );
        let judge = |tool: &str, args: Value| {
            judge(
                &cfg,
                &Call {
                    agent: "agent:claude-code",
                    tool_name: tool,
                    args: &args,
                },
            )
            .0
        };
        assert_eq!(
            judge("mcp__github__list_issues", json!({})),
            Verdict::Allowed
        );
        let rule = |v: Verdict| match v {
            Verdict::Denied { rule, .. } => rule,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            rule(judge("mcp__github__list_issues", json!({ "repo": "prod" }))),
            "no-prod"
        );
        assert_eq!(
            rule(judge("mcp__github__delete_repo", json!({}))),
            "not-on-allowlist"
        );
        assert_eq!(rule(judge("mcp__slack__post", json!({}))), "unknown-server");
        assert_eq!(judge("Read", json!({})), Verdict::NotMine);
    }

    /// A hook cannot change what a call sends: a transform that would is a
    /// refusal, and one that leaves the arguments as they are is not.
    #[test]
    fn a_transform_that_would_change_the_arguments_refuses_the_call() {
        let cfg = config(
            "\n[[policy]]\nname = \"page-size\"\neffect = \"transform\"\ntools = [\"list_*\"]\n\
             set_args = [{ path = \"per_page\", clamp = { min = 1, max = 100 } }]\n",
        );
        let call = |args: Value| {
            judge(
                &cfg,
                &Call {
                    agent: "agent:claude-code",
                    tool_name: "mcp__github__list_issues",
                    args: &args,
                },
            )
        };
        let (verdict, _, fired) = call(json!({ "per_page": 500 }));
        assert!(
            matches!(&verdict, Verdict::Denied { rule, reason }
                if rule == "page-size" && reason.contains("which a hook cannot do")),
            "{verdict:?}"
        );
        assert_eq!(fired, ["page-size"]);
        assert_eq!(call(json!({ "per_page": 50 })).0, Verdict::Allowed);
    }

    #[test]
    fn only_a_refusal_is_answered() {
        // As each client sends it: Codex adds a turn, a call id and its model.
        let events = [
            (
                Client::ClaudeCode,
                r#"{"hook_event_name":"PreToolUse","tool_name":"mcp__a__b","tool_input":{}}"#,
            ),
            (
                Client::Codex,
                r#"{"session_id":"s","transcript_path":null,"cwd":"/p","model":"m",
                    "permission_mode":"default","turn_id":"t","tool_use_id":"c",
                    "hook_event_name":"PreToolUse","tool_name":"mcp__a__b","tool_input":{}}"#,
            ),
        ];
        for (client, text) in events {
            let event = client.event(text).unwrap();
            let call = event.call().unwrap();
            assert_eq!(call.agent, format!("agent:{}", client.name()));
            assert_eq!(client.answer(&event, &Verdict::Allowed), None);
            assert_eq!(client.answer(&event, &Verdict::NotMine), None);
            let denied = Verdict::Denied {
                rule: "r".into(),
                reason: "why".into(),
            };
            assert_eq!(denied.refusal().as_deref(), Some("MCPdef denied (r): why"));
            let answer: Value =
                serde_json::from_str(&client.answer(&event, &denied).unwrap()).unwrap();
            assert_eq!(answer["hookSpecificOutput"]["hookEventName"], "PreToolUse");
            assert_eq!(answer["hookSpecificOutput"]["permissionDecision"], "deny");
            assert_eq!(
                answer["hookSpecificOutput"]["permissionDecisionReason"],
                "MCPdef denied (r): why"
            );
            // Another event of the hook's is not a call.
            let post = client
                .event(r#"{"hook_event_name":"PostToolUse","tool_name":"mcp__a__b"}"#)
                .unwrap();
            assert!(post.call().is_none());
        }
    }

    /// Each client's hook runs `mcpdef hook` as that client, gives up after
    /// the timeout rather than the clients' ten minutes, and on Claude Code
    /// refuses the call when it fails. Codex has no such setting.
    #[test]
    fn each_client_s_hook_names_its_client_and_a_timeout() {
        let program = Path::new("/opt/bin/mcpdef");
        let config = Path::new("/p/mcpdef.toml");

        let claude = Client::ClaudeCode.hook(program, config, 10, None).unwrap();
        assert_eq!(claude["matcher"], MATCHER);
        let handler = &claude["hooks"][0];
        assert_eq!(handler["type"], "command");
        assert_eq!(
            handler["command"],
            "/opt/bin/mcpdef hook --config /p/mcpdef.toml"
        );
        assert_eq!(handler["timeout"], 10);
        assert_eq!(handler["onFailure"], "block");
        // Claude Code reads only `command`, through bash.
        assert!(handler.get("commandWindows").is_none(), "{handler}");

        let codex = Client::Codex.hook(program, config, 7, None).unwrap();
        assert_eq!(codex["matcher"], MATCHER);
        let handler = &codex["hooks"][0];
        assert_eq!(
            handler["command"],
            "/opt/bin/mcpdef hook --client codex --config /p/mcpdef.toml"
        );
        assert_eq!(
            handler["commandWindows"],
            r#""/opt/bin/mcpdef" hook --client codex --config "/p/mcpdef.toml""#
        );
        assert_eq!(handler["timeout"], 7);
        assert!(handler.get("onFailure").is_none(), "{handler}");

        // Either is taken for an earlier MCPdef hook, so `install` replaces it.
        assert!(runs_mcpdef_hook(&claude["hooks"][0]));
        assert!(runs_mcpdef_hook(&codex["hooks"][0]));
        assert_eq!(Client::parse("codex"), Some(Client::Codex));
        assert_eq!(Client::parse("cursor"), None);
        assert_eq!(Client::Codex.settings(), Path::new(".codex/hooks.json"));
    }

    /// On Windows Codex runs `commandWindows` through `cmd.exe /C`: paths in
    /// double quotes, the `\\?\` that `canonicalize` gives one taken off, and
    /// a word `cmd.exe` would expand even in quotes no line at all. On Windows
    /// such a hook is not written, since Codex would run the POSIX line and
    /// go on with every call; elsewhere it is written without the Windows line.
    #[test]
    fn a_codex_hook_carries_the_line_cmd_exe_reads() {
        let program = Path::new(r"C:\Program Files\mcpdef\mcpdef.exe");
        let config = Path::new(r"\\?\C:\Users\me\my proj\mcpdef.toml");
        for windows in [true, false] {
            let hook = Client::Codex
                .hook_on(program, config, 10, None, windows)
                .unwrap();
            assert_eq!(
                hook["hooks"][0]["commandWindows"],
                r#""C:\Program Files\mcpdef\mcpdef.exe" hook --client codex --config "C:\Users\me\my proj\mcpdef.toml""#
            );
        }
        // cmd.exe takes these as they are inside quotes.
        assert_eq!(
            cmd_line(r"D:\a&b (x86)\^c\mcpdef.exe", &["hook".to_string()]).unwrap(),
            r#""D:\a&b (x86)\^c\mcpdef.exe" hook"#
        );
        assert_eq!(
            simplified(r"\\?\UNC\host\share\mcpdef.toml"),
            r"\\host\share\mcpdef.toml"
        );
        assert_eq!(simplified("/opt/mcpdef.toml"), "/opt/mcpdef.toml");

        // These it would expand, quotes or not.
        for bad in [
            r"C:\100%\mcpdef.toml",
            r"C:\wow!\mcpdef.toml",
            "C:\\a\nb\\mcpdef.toml",
        ] {
            let why = Client::Codex
                .hook_on(program, Path::new(bad), 10, None, true)
                .unwrap_err();
            assert!(why.contains("cmd.exe"), "{why}");
            let hook = Client::Codex
                .hook_on(program, Path::new(bad), 10, None, false)
                .unwrap();
            assert!(hook["hooks"][0].get("commandWindows").is_none(), "{hook}");
            assert!(hook["hooks"][0]["command"].is_string());
        }
        // Claude Code runs hooks through bash on every platform.
        assert!(Client::ClaudeCode
            .hook_on(program, Path::new(r"C:\100%\mcpdef.toml"), 10, None, true)
            .is_ok());
    }

    /// A hook held to its bundle names the keys on each line its client may
    /// run, quoted as that shell reads them, and is still taken for an MCPdef
    /// hook, so `install` puts it in place of one that is not held.
    #[test]
    fn a_hook_held_to_its_bundle_names_its_keys() {
        let program = Path::new("/opt/bin/mcpdef");
        let config = Path::new("/p/mcpdef.toml");
        let keys = Path::new("/etc/mcpdef/bundle keys.json");
        let claude = Client::ClaudeCode
            .hook(program, config, 10, Some(keys))
            .unwrap();
        let handler = &claude["hooks"][0];
        assert_eq!(
            handler["command"],
            "/opt/bin/mcpdef hook --config /p/mcpdef.toml --bundle-trust '/etc/mcpdef/bundle keys.json'"
        );
        assert_eq!(
            shell_words(handler["command"].as_str().unwrap())[4..],
            ["--bundle-trust", "/etc/mcpdef/bundle keys.json"]
        );
        assert!(runs_mcpdef_hook(handler));

        let program = Path::new(r"C:\Program Files\mcpdef\mcpdef.exe");
        let config = Path::new(r"C:\p\mcpdef.toml");
        let keys = Path::new(r"\\?\C:\ProgramData\mcpdef\keys.json");
        let codex = Client::Codex
            .hook_on(program, config, 10, Some(keys), true)
            .unwrap();
        let handler = &codex["hooks"][0];
        assert_eq!(
            handler["commandWindows"],
            r#""C:\Program Files\mcpdef\mcpdef.exe" hook --client codex --config "C:\p\mcpdef.toml" --bundle-trust "C:\ProgramData\mcpdef\keys.json""#
        );
        assert!(runs_mcpdef_hook(handler));
        // Keys cmd.exe cannot be handed safely: on Windows no hook, as for a
        // config.
        let why = Client::Codex
            .hook_on(
                program,
                config,
                10,
                Some(Path::new(r"C:\100%\keys.json")),
                true,
            )
            .unwrap_err();
        assert!(why.contains("cmd.exe"), "{why}");
    }

    #[test]
    fn only_mcpdef_hook_is_taken_for_an_earlier_mcpdef_hook() {
        let runs = |command: &str| runs_mcpdef_hook(&json!({ "command": command }));
        assert!(runs("/usr/local/bin/mcpdef hook --config /x/mcpdef.toml"));
        assert!(runs("'/opt/my tools/mcpdef' hook --config '/x/y.toml'"));
        assert!(!runs("/usr/local/bin/slop-hook"));
        assert!(!runs("mcpdef up --config x"));
        assert!(!runs("/bin/mcpdef-other hook"));
        assert!(runs(
            "'/opt/mcpdef/mcpdef.exe' hook --config /x/mcpdef.toml"
        ));
        assert!(runs("/opt/mcpdef/mcpdef.EXE hook"));
        assert!(!runs("/opt/mcpdef/mcpdef.sh hook"));
        // As `shell_line` writes a path with a quote in it.
        assert!(runs(r"'/opt/it'\''s/mcpdef' hook"));
        assert_eq!(
            shell_words(r#"a 'b c' "d \"e\"" f\ g"#),
            ["a", "b c", r#"d "e""#, "f g"]
        );

        // A Windows line, read as cmd.exe reads it: backslashes are separators.
        let windows = |line: &str| runs_mcpdef_hook(&json!({ "commandWindows": line }));
        assert!(windows(
            r#""C:\Program Files\mcpdef\mcpdef.exe" hook --client codex --config "C:\p\m.toml""#
        ));
        assert!(windows(r"C:\tools\mcpdef.exe hook"));
        assert!(!windows(r#""C:\tools\mcpdef.exe" up"#));
        assert!(!windows(r#""C:\tools\other.exe" hook"#));
        // And a POSIX line naming a Windows path, as Git Bash would run it.
        assert!(runs(
            r"'C:\Users\me\.cargo\bin\mcpdef.exe' hook --config 'C:\p\m.toml'"
        ));
        assert_eq!(
            cmd_words(r#""C:\a b\c.exe" hook "" x"#),
            [r"C:\a b\c.exe", "hook", "", "x"]
        );
    }
}
