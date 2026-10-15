// SPDX-License-Identifier: Apache-2.0
//! `mcpdef connect <client>`: the exact entry an MCP client needs to reach
//! this gateway, in that client's own format.
//!
//! Every client keeps its MCP servers somewhere different, under a different
//! root key, with a different way to name a secret: `mcpServers` in Claude
//! Code's `.mcp.json`, Cursor's `mcp.json` and Claude Desktop's config, with
//! `${VAR}` in one and `${env:VAR}` in another; `servers` in VS Code's, whose
//! secrets are `inputs`; `[mcp_servers.<name>]` in Codex's TOML. This writes
//! the one each needs, and `--write` merges it into that file, keeping a
//! `.bak` of what was there.
//!
//! A client whose config can only run a command gets a `mcpdef bridge` entry
//! instead: a stdio server that carries the CA, the certificate and the token
//! for it. That is Claude Desktop, whose config file runs local commands
//! only, and any client when a client certificate is asked for, which none of
//! them is documented to present itself.

use crate::config::{ClientAuthMode, Config, ListenerTlsMode};
use crate::tls::local_ca;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// A client `connect` writes an entry for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    ClaudeCode,
    ClaudeDesktop,
    Cursor,
    VsCode,
    Codex,
    Generic,
}

impl Client {
    pub const ALL: [Client; 6] = [
        Client::ClaudeCode,
        Client::ClaudeDesktop,
        Client::Cursor,
        Client::VsCode,
        Client::Codex,
        Client::Generic,
    ];

    /// The name `mcpdef connect` takes.
    pub fn name(self) -> &'static str {
        match self {
            Client::ClaudeCode => "claude-code",
            Client::ClaudeDesktop => "claude-desktop",
            Client::Cursor => "cursor",
            Client::VsCode => "vscode",
            Client::Codex => "codex",
            Client::Generic => "generic",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Client::ClaudeCode => "Claude Code",
            Client::ClaudeDesktop => "Claude Desktop",
            Client::Cursor => "Cursor",
            Client::VsCode => "VS Code",
            Client::Codex => "Codex",
            Client::Generic => "Any MCP client",
        }
    }
}

impl std::str::FromStr for Client {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Client> {
        Client::ALL
            .into_iter()
            .find(|c| c.name() == s)
            .ok_or_else(|| {
                let names: Vec<_> = Client::ALL.iter().map(|c| c.name()).collect();
                anyhow!("no client called {s:?}: one of {}", names.join(", "))
            })
    }
}

/// What a client has to know about the gateway it connects to.
#[derive(Debug, Clone)]
pub struct Target {
    /// The MCP endpoint, as a client on this machine reaches it.
    pub url: String,
    /// The CA a client has to trust, when the gateway's certificate is from
    /// its own local CA. `None` for a certificate from files: whoever issued
    /// it decides who trusts it, and the config does not say who that was.
    pub ca: Option<PathBuf>,
    /// The gateway asks for a token. A client that can sign in does so on
    /// first use; the gateway's `401` tells it where (RFC 9728).
    pub sign_in: bool,
    /// The gateway asks for a client certificate.
    pub needs_certificate: bool,
}

impl Target {
    /// The gateway `cfg` describes.
    pub fn of(cfg: &Config) -> Target {
        let g = &cfg.gateway;
        Target {
            url: listener_url(&g.listen, g.tls.mode.is_on()),
            ca: (g.tls.mode == ListenerTlsMode::SelfSigned).then(|| {
                let ca = local_ca::Paths::under(&g.state_dir).ca_cert();
                std::path::absolute(&ca).unwrap_or(ca)
            }),
            sign_in: g.auth.enabled,
            needs_certificate: g.tls.client_auth.mode == ClientAuthMode::Required,
        }
    }
}

/// How the entry is asked for.
#[derive(Debug, Clone)]
pub struct Ask {
    /// The entry's name in the client.
    pub name: String,
    /// An environment variable holding a bearer token, for a client that
    /// sends the header itself. The entry names the variable, never its value.
    pub token_env: Option<String>,
    /// A file holding a bearer token, for a bridge entry.
    pub token_file: Option<PathBuf>,
    /// A client certificate and its key: the client gets a bridge entry.
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    /// This binary, for a bridge entry. Absolute, because a desktop app does
    /// not inherit the shell's `PATH`.
    pub mcpdef: PathBuf,
}

/// The file format a client keeps its servers in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Format {
    /// JSON, the servers under `root`.
    Json { root: &'static str },
    /// TOML, each server a `[mcp_servers.<name>]` table.
    Toml,
}

/// One client's entry for the gateway.
#[derive(Debug, Clone)]
pub struct Entry {
    pub client: Client,
    pub name: String,
    /// The gateway's MCP endpoint.
    pub url: String,
    pub format: Format,
    /// The server entry itself, before it is put in the client's file.
    pub server: Value,
    /// VS Code's top-level `inputs` the entry refers to.
    pub inputs: Vec<Value>,
    /// Where `--write` merges it, unless told otherwise. `None` for a client
    /// with no file of its own.
    pub file: Option<PathBuf>,
    /// A command that adds the same entry, for a client that has one.
    pub command: Option<String>,
    /// What else the client needs: the CA to trust, how to sign in.
    pub notes: Vec<String>,
}

/// The entry `client` needs for `target`. `home` locates per-user files.
pub fn entry(client: Client, target: &Target, ask: &Ask, home: Option<&Path>) -> Result<Entry> {
    if ask.cert.is_some() != ask.key.is_some() {
        bail!("a client certificate is presented with its key: give --cert and --key together");
    }
    let bridged = client == Client::ClaudeDesktop || ask.cert.is_some();
    if bridged && ask.token_env.is_some() && ask.token_file.is_none() {
        bail!(
            "{} gets a `mcpdef bridge` entry, and a bridge reads its token from a file: \
             give --token-file",
            client.title()
        );
    }
    if !bridged && ask.token_file.is_some() && ask.token_env.is_none() {
        bail!(
            "{} sends the token itself, from its environment: give --token-env, the variable \
             that holds it",
            client.title()
        );
    }

    let mut notes = Vec::new();
    let mut inputs = Vec::new();
    let mut command = None;

    let server = if bridged {
        let args = bridge_args(target, ask);
        if target.sign_in && ask.token_file.is_none() && ask.cert.is_none() {
            notes.push(
                "⚠ The gateway asks for a token, and a bridge cannot sign in: give --token-file."
                    .to_string(),
            );
        }
        if let Some(ca) = &target.ca {
            notes.push(format!(
                "The bridge trusts the gateway's CA itself ({}): nothing to add to the system.",
                ca.display()
            ));
        }
        let mcpdef = ask.mcpdef.display().to_string();
        match client {
            Client::ClaudeDesktop => json!({ "command": mcpdef, "args": args }),
            Client::Codex => json!({ "command": mcpdef, "args": args }),
            Client::Generic => Value::Null,
            _ => json!({ "type": "stdio", "command": mcpdef, "args": args }),
        }
    } else {
        if target.needs_certificate {
            notes.push(format!(
                "⚠ The gateway asks for a client certificate, which {} is not documented to \
                 present. Give --cert and --key, and this becomes a `mcpdef bridge` entry that \
                 presents it.",
                client.title()
            ));
        }
        let mut server = match client {
            Client::ClaudeCode | Client::VsCode => json!({ "type": "http", "url": target.url }),
            Client::Cursor | Client::Codex | Client::Generic => json!({ "url": target.url }),
            Client::ClaudeDesktop => unreachable!("Claude Desktop is always bridged"),
        };
        if let Some(var) = &ask.token_env {
            match client {
                Client::ClaudeCode => {
                    server["headers"] = json!({ "Authorization": format!("Bearer ${{{var}}}") })
                }
                Client::Cursor => {
                    server["headers"] = json!({ "Authorization": format!("Bearer ${{env:{var}}}") })
                }
                Client::VsCode => {
                    // VS Code's documented secret is an input: asked for once,
                    // kept in its secret storage, never in the file.
                    let id = format!("{}-token", ask.name);
                    server["headers"] =
                        json!({ "Authorization": format!("Bearer ${{input:{id}}}") });
                    inputs.push(json!({
                        "type": "promptString",
                        "id": id,
                        "description": format!("Bearer token for {}", ask.name),
                        "password": true,
                    }));
                    notes.push(format!(
                        "VS Code asks for the token once and keeps it in its secret storage; \
                         ${var} is not read."
                    ));
                }
                Client::Codex => server["bearer_token_env_var"] = json!(var),
                Client::Generic => notes.push(format!(
                    "Send `Authorization: Bearer <the token in ${var}>` with each request."
                )),
                Client::ClaudeDesktop => unreachable!(),
            }
        } else if target.sign_in {
            notes.push(match client {
                Client::ClaudeCode => format!(
                    "The gateway asks for a token: run /mcp in Claude Code, or `claude mcp login \
                     {}`, to sign in.",
                    ask.name
                ),
                Client::Codex => format!(
                    "The gateway asks for a token: `codex mcp login {}` signs in.",
                    ask.name
                ),
                _ => "The gateway asks for a token: the client signs in when it is first asked."
                    .to_string(),
            });
        }
        if let Some(ca) = &target.ca {
            notes.extend(trust(client, ca, &target.url));
        }
        command = match client {
            // A `--header` on this command line is expanded by the shell and
            // stored as the token itself, so it is offered only without one.
            Client::ClaudeCode if ask.token_env.is_none() => Some(format!(
                "claude mcp add --transport http --scope user {} {}",
                ask.name, target.url
            )),
            Client::Codex if ask.token_env.is_none() && !target.sign_in => {
                Some(format!("codex mcp add {} --url {}", ask.name, target.url))
            }
            _ => None,
        };
        if client == Client::Generic {
            Value::Null
        } else {
            server
        }
    };
    // Whatever else a generic client is told, a client that can only run a
    // command needs the bridge line.
    if client == Client::Generic {
        command = Some(shell_line(
            &ask.mcpdef.display().to_string(),
            &bridge_args(target, ask),
        ));
    }

    Ok(Entry {
        client,
        name: ask.name.clone(),
        url: target.url.clone(),
        format: match client {
            Client::VsCode => Format::Json { root: "servers" },
            Client::Codex => Format::Toml,
            _ => Format::Json { root: "mcpServers" },
        },
        server,
        inputs,
        file: default_file(client, home),
        command,
        notes,
    })
}

/// `mcpdef bridge`'s arguments for this target.
fn bridge_args(target: &Target, ask: &Ask) -> Vec<String> {
    let mut args = vec!["bridge".to_string(), target.url.clone()];
    if let Some(ca) = &target.ca {
        args.extend(["--ca".to_string(), ca.display().to_string()]);
    }
    if let (Some(cert), Some(key)) = (&ask.cert, &ask.key) {
        args.extend([
            "--cert".to_string(),
            cert.display().to_string(),
            "--key".to_string(),
            key.display().to_string(),
        ]);
    }
    if let Some(token) = &ask.token_file {
        args.extend(["--token-file".to_string(), token.display().to_string()]);
    }
    args
}

/// How `client` comes to trust the gateway's CA at `ca`.
fn trust(client: Client, ca: &Path, url: &str) -> Vec<String> {
    let ca_shown = ca.display();
    match client {
        Client::ClaudeCode => vec![format!(
            "The gateway's certificate is from its own CA. Before starting Claude Code: export \
             NODE_EXTRA_CA_CERTS={ca_shown}"
        )],
        Client::Codex => vec![format!(
            "The gateway's certificate is from its own CA. Before starting Codex: export \
             CODEX_CA_CERTIFICATE={ca_shown}"
        )],
        Client::Generic => vec![
            format!("The gateway's certificate is from its own CA: trust {ca_shown}."),
            format!("  curl --cacert {ca_shown} {url}"),
        ],
        Client::Cursor | Client::VsCode => {
            let mut lines = vec![format!(
                "The gateway's certificate is from its own CA. {} trusts the system's store, so \
                 add it there:",
                client.title()
            )];
            lines.extend(system_store(ca).into_iter().map(|l| format!("  {l}")));
            lines
        }
        Client::ClaudeDesktop => Vec::new(),
    }
}

/// Where each client keeps its servers, when `--write` is not told.
///
/// Claude Code's is the project's `.mcp.json`: its per-user file also holds
/// its history and projects, and is better left to `claude mcp add`. VS
/// Code's per-user file moves with the profile, so its workspace file is the
/// one written. Claude Desktop documents macOS and Windows; on Linux its
/// config directory is taken to be the XDG one.
pub fn default_file(client: Client, home: Option<&Path>) -> Option<PathBuf> {
    match client {
        Client::ClaudeCode => Some(PathBuf::from(".mcp.json")),
        Client::VsCode => Some(PathBuf::from(".vscode").join("mcp.json")),
        Client::Cursor => home.map(|h| h.join(".cursor").join("mcp.json")),
        Client::Codex => home.map(|h| h.join(".codex").join("config.toml")),
        Client::ClaudeDesktop => {
            let file = "claude_desktop_config.json";
            if cfg!(target_os = "macos") {
                home.map(|h| h.join("Library/Application Support/Claude").join(file))
            } else if cfg!(windows) {
                std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("Claude").join(file))
            } else {
                std::env::var_os("XDG_CONFIG_HOME")
                    .filter(|d| !d.is_empty())
                    .map(PathBuf::from)
                    .or_else(|| home.map(|h| h.join(".config")))
                    .map(|d| d.join("Claude").join(file))
            }
        }
        Client::Generic => None,
    }
}

impl Entry {
    /// The entry as it sits in the client's file, to show or to paste.
    pub fn render(&self) -> String {
        match &self.format {
            Format::Json { root } => {
                let mut doc = json!({ *root: { self.name.clone(): self.server } });
                if !self.inputs.is_empty() {
                    doc["inputs"] = Value::Array(self.inputs.clone());
                }
                serde_json::to_string_pretty(&doc).unwrap_or_default()
            }
            Format::Toml => {
                let mut doc = toml_edit::DocumentMut::new();
                put_toml(&mut doc, &self.name, &self.server);
                doc.to_string().trim_end().to_string()
            }
        }
    }

    /// What `mcpdef connect` prints.
    pub fn report(&self) -> String {
        let mut out = String::new();
        let title = self.client.title();
        if self.client == Client::Generic {
            out.push_str(&format!(
                "# {title}
Streamable HTTP: {}
",
                self.url
            ));
        } else {
            let place = self
                .file
                .as_ref()
                .map(|f| format!("merge into {}", f.display()))
                .unwrap_or_else(|| "add to its MCP config".to_string());
            out.push_str(&format!(
                "# {title}: {place} (`mcpdef connect {} --write` does it)\n",
                self.client.name()
            ));
            out.push_str(&self.render());
            out.push('\n');
        }
        if let Some(command) = &self.command {
            let lead = match self.client {
                Client::Generic => "for a client that can only run a command",
                // `--write` writes this project's `.mcp.json`; the command
                // adds the entry for every project. Said, so the two are not
                // taken for the same thing.
                Client::ClaudeCode => "or, for every project rather than this one",
                _ => "or",
            };
            out.push_str(&format!("\n# {lead}:\n{command}\n"));
        }
        for note in &self.notes {
            out.push_str(&format!("\n{note}"));
        }
        if !self.notes.is_empty() {
            out.push('\n');
        }
        out
    }
}

/// What `--write` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wrote {
    /// The file did not exist; it does now.
    Created,
    /// The file changed; what it held before is in `backup`.
    Updated { backup: PathBuf },
    /// The file already held exactly this entry. Nothing was written, and an
    /// earlier backup is left as it was.
    Unchanged,
}

/// Merge `entry` into `file`.
///
/// Only this entry, and for VS Code its input, is touched; everything else
/// in the file is kept. A file that is not valid JSON — VS Code's may hold
/// comments — is refused and left exactly as it was, never rewritten from a
/// guess. JSON comes back with its keys in order; the `.bak` holds the file
/// as it was. TOML keeps its comments and layout.
pub fn write(entry: &Entry, file: &Path) -> Result<Wrote> {
    if entry.server.is_null() {
        bail!(
            "{} has no file to write to: add the entry it shows by hand",
            entry.client.title()
        );
    }
    let before = match std::fs::read_to_string(file) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("reading {}", file.display())),
    };
    let after = match &entry.format {
        Format::Json { root } => merge_json(entry, root, before.as_deref(), file)?,
        Format::Toml => merge_toml(entry, before.as_deref(), file)?,
    };
    if before.as_deref() == Some(after.as_str()) {
        return Ok(Wrote::Unchanged);
    }
    if let Some(parent) = file.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let wrote = match &before {
        Some(old) => {
            let backup = backup_path(file);
            std::fs::write(&backup, old)
                .with_context(|| format!("writing the backup {}", backup.display()))?;
            Wrote::Updated { backup }
        }
        None => Wrote::Created,
    };
    std::fs::write(file, after).with_context(|| format!("writing {}", file.display()))?;
    Ok(wrote)
}

fn backup_path(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(".bak");
    PathBuf::from(name)
}

fn merge_json(entry: &Entry, root: &str, before: Option<&str>, file: &Path) -> Result<String> {
    let mut doc: Value = match before {
        None => json!({}),
        Some(text) if text.trim().is_empty() => json!({}),
        Some(text) => serde_json::from_str(text).map_err(|e| {
            anyhow!(
                "{} is not plain JSON ({e}), so it is left as it is — a file with comments \
                 cannot be rewritten without losing them. Add the entry above by hand.",
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
    let servers = top.entry(root).or_insert_with(|| json!({}));
    let Some(servers) = servers.as_object_mut() else {
        bail!(
            "`{root}` in {} is not an object: left as it is",
            file.display()
        );
    };
    servers.insert(entry.name.clone(), entry.server.clone());
    if !entry.inputs.is_empty() {
        let inputs = top.entry("inputs").or_insert_with(|| json!([]));
        let Some(inputs) = inputs.as_array_mut() else {
            bail!(
                "`inputs` in {} is not a list: left as it is",
                file.display()
            );
        };
        for input in &entry.inputs {
            let id = &input["id"];
            inputs.retain(|i| &i["id"] != id);
            inputs.push(input.clone());
        }
    }
    // An unchanged document comes back byte for byte, so `write` can tell it
    // has nothing to do; a changed one is written out in full.
    if let Some(text) = before {
        if serde_json::from_str::<Value>(text).ok().as_ref() == Some(&doc) {
            return Ok(text.to_string());
        }
    }
    Ok(serde_json::to_string_pretty(&doc)? + "\n")
}

fn merge_toml(entry: &Entry, before: Option<&str>, file: &Path) -> Result<String> {
    let mut doc: toml_edit::DocumentMut = before
        .unwrap_or_default()
        .parse()
        .with_context(|| format!("{} is not TOML: left as it is", file.display()))?;
    let unchanged = doc.to_string();
    put_toml(&mut doc, &entry.name, &entry.server);
    let after = doc.to_string();
    // The same entry written again renders identically: hand back the file's
    // own text, so `write` sees nothing to do.
    match before {
        Some(text) if after == unchanged => Ok(text.to_string()),
        _ => Ok(after),
    }
}

/// `[mcp_servers.<name>]`, set from the server entry.
fn put_toml(doc: &mut toml_edit::DocumentMut, name: &str, server: &Value) {
    let servers = doc
        .entry("mcp_servers")
        .or_insert_with(|| {
            let mut t = toml_edit::Table::new();
            t.set_implicit(true);
            toml_edit::Item::Table(t)
        })
        .as_table_mut();
    let Some(servers) = servers else { return };
    let mut table = toml_edit::Table::new();
    if let Some(fields) = server.as_object() {
        for (key, value) in fields {
            if let Some(v) = toml_value(value) {
                table.insert(key, toml_edit::Item::Value(v));
            }
        }
    }
    servers.insert(name, toml_edit::Item::Table(table));
}

fn toml_value(v: &Value) -> Option<toml_edit::Value> {
    match v {
        Value::String(s) => Some(s.as_str().into()),
        Value::Bool(b) => Some((*b).into()),
        Value::Array(items) => {
            let mut array = toml_edit::Array::new();
            for item in items {
                array.push(toml_value(item)?);
            }
            Some(toml_edit::Value::Array(array))
        }
        Value::Object(map) => {
            let mut table = toml_edit::InlineTable::new();
            for (k, item) in map {
                table.insert(k, toml_value(item)?);
            }
            Some(toml_edit::Value::InlineTable(table))
        }
        _ => None,
    }
}

/// A command line, with each argument quoted when it has to be.
fn shell_line(program: &str, args: &[String]) -> String {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .map(|a| {
            if !a.is_empty()
                && a.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c))
            {
                a.to_string()
            } else {
                format!("'{}'", a.replace('\'', r"'\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The URL a client on this machine reaches the MCP listener at.
pub fn listener_url(listen: &str, tls: bool) -> String {
    let (host, port) = listen.rsplit_once(':').unwrap_or((listen, "443"));
    let host = match host.trim_matches(['[', ']']) {
        "0.0.0.0" | "::" | "" => "localhost".to_string(),
        v6 if v6.contains(':') => format!("[{v6}]"),
        host => host.to_string(),
    };
    let scheme = if tls { "https" } else { "http" };
    format!("{scheme}://{host}:{port}/mcp")
}

/// How to add `ca` to this system's store of trusted CAs.
pub fn system_store(ca: &Path) -> Vec<String> {
    let ca = ca.display();
    if cfg!(target_os = "macos") {
        vec![format!(
            "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {ca}"
        )]
    } else if cfg!(windows) {
        vec![format!(
            "certutil -addstore -f ROOT {ca}   (as an administrator)"
        )]
    } else {
        vec![
            format!(
                "sudo cp {ca} /usr/local/share/ca-certificates/mcpdef-local-ca.crt && sudo \
                 update-ca-certificates   (Debian, Ubuntu)"
            ),
            format!(
                "sudo cp {ca} /etc/pki/ca-trust/source/anchors/mcpdef-local-ca.crt && sudo \
                 update-ca-trust   (Fedora, RHEL)"
            ),
        ]
    }
}
