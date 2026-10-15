// SPDX-License-Identifier: Apache-2.0
//! Hot reload: the config read again, on `SIGHUP` or when its content changes,
//! and applied to the running gateway without dropping a call in flight.
//!
//! A reload applies whole or not at all. A config that does not parse or
//! validate, or with `[gateway] strict` has anything to warn about, is refused
//! as `invalid-config`, and so is one whose listener certificate does not
//! read. One that changes what only a restart can change (the HTTP listener
//! and its settings, the admin listener, TLS turned on or off on either, the
//! ledger, the auth settings or the wire mode) is refused as
//! `restart-required`, never half applied. Either way the gateway keeps
//! serving the configuration it had. Every reload, applied or refused, is
//! audited.
//!
//! A reload also reads the listeners' certificates again, and serves them
//! from the next connection on: a certificate renewed in its files, with
//! `watch_config` or a `SIGHUP`. And at each tick of the watch, whether it
//! watches or not, a self-signed certificate that is due is issued again.

use crate::config::{Config, GatewayConfig};
use crate::connect::supervised;
use crate::gateway::{Gateway, Planned, Reconfig, Reconfigured};
use crate::redact::redact_urls;
use crate::tls::{Built, ListenerTls};
use mcpdef_pin::PinStore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{mpsc, oneshot};

/// How often `[gateway] watch_config` reads the config and the files it names.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(30);

/// What asked for a reload: the `actor` of its audit record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// `SIGHUP`.
    Signal,
    /// `[gateway] watch_config` saw the content change.
    Watch,
    /// The admin API, for a caller: who, as the console names it, and the
    /// address it called from.
    Admin { actor: String, peer: Option<String> },
}

impl Trigger {
    /// Who asked, as the record's `actor` names it: `sighup`, `watch`, or the
    /// admin API's caller.
    pub fn actor(&self) -> &str {
        match self {
            Trigger::Signal => "sighup",
            Trigger::Watch => "watch",
            Trigger::Admin { actor, .. } => actor,
        }
    }

    /// Where the admin API's caller called from.
    pub fn peer(&self) -> Option<&str> {
        match self {
            Trigger::Admin { peer, .. } => peer.as_deref(),
            _ => None,
        }
    }

    /// What the log line says asked.
    fn said(&self) -> String {
        match self {
            Trigger::Admin { actor, .. } => format!("admin API, {actor}"),
            other => other.actor().to_string(),
        }
    }
}

/// A reload the admin API asked for, and where its outcome goes.
struct Asked {
    actor: String,
    peer: Option<String>,
    reply: oneshot::Sender<Outcome>,
}

/// Asks a running [`Reloader`] for a reload, and waits for what became of it:
/// the admin API's end of [`channel`].
#[derive(Clone, Debug)]
pub struct Reloads(mpsc::Sender<Asked>);

/// The reloader's end of [`channel`], which [`Reloader::with_requests`] takes.
#[derive(Debug)]
pub struct Requests(mpsc::Receiver<Asked>);

impl std::fmt::Debug for Asked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Asked").field("actor", &self.actor).finish()
    }
}

/// A channel for the admin API to ask a reloader for reloads. A few wait at
/// once at most: each is a whole reload, and they run one at a time.
pub fn channel() -> (Reloads, Requests) {
    let (asks, requests) = mpsc::channel(4);
    (Reloads(asks), Requests(requests))
}

impl Reloads {
    /// Reload the config for `actor`, calling from `peer`, and return what
    /// became of it; `None` when no reloader takes requests any more.
    pub async fn reload(&self, actor: String, peer: Option<String>) -> Option<Outcome> {
        let (reply, outcome) = oneshot::channel();
        self.0.send(Asked { actor, peer, reply }).await.ok()?;
        outcome.await.ok()
    }
}

/// What became of a reload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The gateway runs the configuration it read.
    Applied(Reconfigured),
    /// The gateway keeps the configuration it had. `rule` says why, as the
    /// ledger records it: `invalid-config` or `restart-required`.
    Refused {
        rule: &'static str,
        reasons: Vec<String>,
    },
}

/// Keeps a running gateway on the config at a path.
pub struct Reloader {
    path: PathBuf,
    /// A `--profile` given at launch, which every reload applies again.
    profile: Option<String>,
    gateway: Gateway,
    applied: Applied,
    /// The digest the watch last acted on, applied or refused, so that a
    /// config refused once is not refused again every 30 s.
    seen: String,
    on_applied: Option<OnApplied>,
    /// The TLS the listeners serve, which a reload builds again.
    tls: Option<ListenerTls>,
    /// Reloads the admin API asks for, which [`Reloader::run`] takes too.
    requests: Option<Requests>,
}

/// Called with each configuration applied.
type OnApplied = Box<dyn Fn(&Config) + Send + Sync>;

/// The configuration in effect, and what it was read from.
struct Applied {
    config: Config,
    snapshot: Snapshot,
}

/// A config as a reload read it.
struct Read {
    config: Result<Config, Vec<String>>,
    snapshot: Snapshot,
}

/// What a config was read from: its text, and the files it names, each as it
/// was when read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    digest: String,
    /// The digest of each file the config names, by its path, so that a change
    /// to one counts even when the config itself did not change.
    files: HashMap<String, String>,
}

impl Snapshot {
    /// The snapshot of a config read as `text`, which parsed as `config`, with
    /// the files it names read now. Take it before the gateway reads them: a
    /// file that changes in between then shows up as a change at the next
    /// reload, where one taken after would hide it.
    pub fn take(text: &[u8], config: &Config) -> Self {
        Self::of(Some(text), Some(config))
    }

    /// `text` is `None` for a config that could not be read, which hashes
    /// differently from every one that could, and `config` for one that did
    /// not parse, which names no files.
    fn of(text: Option<&[u8]>, config: Option<&Config>) -> Self {
        let mut h = Sha256::new();
        h.update(b"mcpdef-config/1");
        part(&mut h, text);
        let mut files = HashMap::new();
        for path in config.map(Config::referenced_files).unwrap_or_default() {
            let file = file_digest(&path);
            part(&mut h, Some(path.as_bytes()));
            part(&mut h, Some(file.as_bytes()));
            files.insert(path, file);
        }
        Snapshot {
            digest: format!("sha256:{}", hex::encode(h.finalize())),
            files,
        }
    }

    /// `sha256:<hex>` over the config's text and the content of each file it
    /// names, each part length-prefixed so that no two inputs share a digest.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The digest of a file the config names, as it was read.
    fn file(&self, path: Option<&str>) -> Option<&str> {
        self.files.get(path?).map(String::as_str)
    }
}

impl Reloader {
    /// A reloader for `gateway`, which runs `applied`, read from `path` with
    /// `profile` (a `--profile` given at launch) on top. `snapshot` is what
    /// `applied` was read from.
    pub fn new(
        path: impl Into<PathBuf>,
        profile: Option<String>,
        gateway: Gateway,
        applied: Config,
        snapshot: Snapshot,
    ) -> Self {
        Reloader {
            path: path.into(),
            profile,
            gateway,
            seen: snapshot.digest.clone(),
            applied: Applied {
                config: applied,
                snapshot,
            },
            on_applied: None,
            tls: None,
            requests: None,
        }
    }

    /// Call `f` with each configuration applied.
    pub fn on_applied(mut self, f: impl Fn(&Config) + Send + Sync + 'static) -> Self {
        self.on_applied = Some(Box::new(f));
        self
    }

    /// Build what `tls`'s listeners serve again at each reload, which is
    /// refused if it does not build, and issue its self-signed certificate
    /// again when that is due.
    pub fn with_listener_tls(mut self, tls: ListenerTls) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Take the reloads the admin API asks for, through `requests`, besides
    /// `SIGHUP` and the watch: [`Reloader::run`] answers each with its outcome.
    pub fn with_requests(mut self, requests: Requests) -> Self {
        self.requests = Some(requests);
        self
    }

    /// The digest of the configuration in effect: `sha256:<hex>` over the
    /// config and the files it names.
    pub fn digest(&self) -> &str {
        self.applied.snapshot.digest()
    }

    /// Read the config again and apply it, or refuse it. The outcome is logged
    /// and audited.
    pub async fn reload(&mut self, trigger: Trigger) -> Outcome {
        let read = self.read().await;
        self.apply(read, trigger).await
    }

    /// Listen for `SIGHUP` from now on, and return the loop that reloads on
    /// one, and, while `[gateway] watch_config` is on, whenever the digest of
    /// the config and the files it names changes, checked every `interval`.
    /// The loop runs until it is dropped. A `SIGHUP` that comes before it is
    /// first polled waits for it, where it would otherwise end the process.
    pub fn run(mut self, interval: Duration) -> impl Future<Output = ()> + Send + 'static {
        let mut hangups = hangups();
        let mut requests = self.requests.take();
        async move {
            let start = tokio::time::Instant::now() + interval;
            let mut tick = tokio::time::interval_at(start, interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Each reload is boxed, so the loop, which nearly always waits,
            // holds no room for one in progress.
            loop {
                tokio::select! {
                    () = hangup(&mut hangups) => {
                        Box::pin(self.reload(Trigger::Signal)).await;
                    }
                    asked = asked(&mut requests) => {
                        let trigger = Trigger::Admin { actor: asked.actor, peer: asked.peer };
                        let outcome = Box::pin(self.reload(trigger)).await;
                        // The caller may have given up waiting: the reload
                        // stands, and is audited, all the same.
                        let _ = asked.reply.send(outcome);
                    }
                    _ = tick.tick() => {
                        Box::pin(self.renew_if_due(SystemTime::now())).await;
                        if !self.applied.config.gateway.watch_config {
                            continue;
                        }
                        let read = self.read().await;
                        if read.snapshot.digest != self.seen {
                            Box::pin(self.apply(read, Trigger::Watch)).await;
                        }
                    }
                }
            }
        }
    }

    /// Read the config, off the async workers: every file it names is hashed,
    /// wasm modules included.
    async fn read(&self) -> Read {
        let (path, profile) = (self.path.clone(), self.profile.clone());
        match tokio::task::spawn_blocking(move || read(&path, profile.as_deref())).await {
            Ok(read) => read,
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            // The runtime is shutting down.
            Err(_) => std::future::pending().await,
        }
    }

    async fn apply(&mut self, read: Read, trigger: Trigger) -> Outcome {
        let started = Instant::now();
        let Read { config, snapshot } = read;
        self.seen = snapshot.digest.clone();
        let from = self.applied.snapshot.digest.clone();
        let to = snapshot.digest.clone();
        let outcome = match config {
            Err(reasons) => Outcome::Refused {
                rule: "invalid-config",
                reasons,
            },
            Ok(config) => match restart_required(&self.applied, &config, &snapshot) {
                reasons if !reasons.is_empty() => Outcome::Refused {
                    rule: "restart-required",
                    reasons,
                },
                _ => match plan(&self.applied, &config, &snapshot) {
                    Err(reason) => Outcome::Refused {
                        rule: "invalid-config",
                        reasons: vec![reason],
                    },
                    Ok(reconfig) => match self.build_tls(&config, SystemTime::now()).await {
                        Err(reason) => Outcome::Refused {
                            rule: "invalid-config",
                            reasons: vec![reason],
                        },
                        Ok(built) => {
                            let report = self.gateway.reconfigure(reconfig).await;
                            // The client keys too: one removed opens nothing
                            // from now on.
                            self.gateway.set_keys(config.issued_keys());
                            self.install_tls(built);
                            if let Some(f) = &self.on_applied {
                                f(&config);
                            }
                            self.applied = Applied { config, snapshot };
                            Outcome::Applied(report)
                        }
                    },
                },
            },
        };
        let latency = started.elapsed();
        let said = trigger.said();
        match &outcome {
            Outcome::Applied(report) => {
                eprintln!(
                    "mcpdef: config reloaded ({said}): {}; now {}",
                    summary(report),
                    short(&to)
                );
                // What it does that it should not have to, as at startup.
                crate::connect::warn(&self.applied.config);
                for finding in crate::connect::tool_findings(&self.applied.config, &self.gateway) {
                    eprintln!("mcpdef: warning — {finding}");
                }
            }
            Outcome::Refused { rule, reasons } => eprintln!(
                "mcpdef: config reload refused ({said}), {rule}: {}; still serving {}",
                reasons.join("; "),
                short(&from)
            ),
        }
        let refused = match &outcome {
            Outcome::Applied(_) => None,
            Outcome::Refused { rule, .. } => Some(*rule),
        };
        self.gateway
            .audit_reload(trigger.actor(), trigger.peer(), refused, from, to, latency)
            .await;
        outcome
    }

    /// What the listeners that serve TLS would serve under `config`, at
    /// `now`, built off the async workers: a key can come from a command.
    /// `None` when none serves TLS.
    async fn build_tls(&self, config: &Config, now: SystemTime) -> Result<Option<Built>, String> {
        let Some(tls) = self.tls.clone() else {
            return Ok(None);
        };
        let config = config.clone();
        match tokio::task::spawn_blocking(move || tls.prepare(&config, now)).await {
            Ok(built) => built.map(Some),
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            // The runtime is shutting down.
            Err(_) => std::future::pending().await,
        }
    }

    /// Serve what `built` holds from the next connection on.
    fn install_tls(&self, built: Option<Built>) {
        if let (Some(tls), Some(built)) = (&self.tls, built) {
            for note in &built.notes {
                eprintln!("mcpdef: {note}");
            }
            tls.install(built);
        }
    }

    /// Issue the self-signed certificate again if it is due at `now`, and
    /// serve it from the next connection on. One that cannot be issued is
    /// logged, and tried again at the next tick: the one in use is still
    /// good for days.
    pub async fn renew_if_due(&mut self, now: SystemTime) {
        if !self.tls.as_ref().is_some_and(|tls| tls.renewal_due(now)) {
            return;
        }
        let config = self.applied.config.clone();
        match self.build_tls(&config, now).await {
            Ok(built) => self.install_tls(built),
            Err(e) => eprintln!("mcpdef: renewing the listener certificate: {e}"),
        }
    }
}

/// Read the config at `path` as the gateway would run it: parsed, with
/// `profile` on top, and checked as its `[gateway] strict` says.
fn read(path: &Path, profile: Option<&str>) -> Read {
    let text = std::fs::read(path);
    let parsed = match &text {
        Err(e) => Err(format!("reading {}: {e}", path.display())),
        Ok(bytes) => std::str::from_utf8(bytes)
            .map_err(|e| e.to_string())
            // A parse error quotes the line at fault, which may hold a URL.
            .and_then(|text| {
                Config::parse(text).map_err(|e| redact_urls(&format!("{e:#}")).into_owned())
            })
            .map_err(|e| format!("parsing {}: {e}", path.display())),
    };
    let parsed = parsed.map(|mut config| {
        if let Some(profile) = profile {
            config.gateway.profile = Some(profile.to_string());
        }
        config
    });
    let snapshot = Snapshot::of(text.as_deref().ok(), parsed.as_ref().ok());
    let config = match parsed {
        Err(e) => Err(vec![e]),
        // Checked as it asks: with `[gateway] strict`, a warning refuses it.
        Ok(config) => match config.check(false).errors {
            errs if errs.is_empty() => Ok(config),
            errs => Err(errs),
        },
    };
    Read { config, snapshot }
}

fn part(h: &mut Sha256, bytes: Option<&[u8]>) {
    match bytes {
        Some(bytes) => {
            h.update([1]);
            h.update((bytes.len() as u64).to_be_bytes());
            h.update(bytes);
        }
        None => h.update([0]),
    }
}

/// The digest of a file's content, or of its absence.
fn file_digest(path: &str) -> String {
    let mut h = Sha256::new();
    part(&mut h, std::fs::read(path).ok().as_deref());
    hex::encode(h.finalize())
}

/// What in `new` only a restart can apply, named for the log.
fn restart_required(old: &Applied, new: &Config, snapshot: &Snapshot) -> Vec<String> {
    let (a, b) = (&old.config.gateway, &new.gateway);
    let mut why = Vec::new();
    if a.listen != b.listen {
        why.push(format!("[gateway] listen ({} → {})", a.listen, b.listen));
    }
    if a.allowed_origins != b.allowed_origins {
        why.push("[gateway] allowed_origins".to_string());
    }
    if a.max_inflight != b.max_inflight {
        why.push("[gateway] max_inflight".to_string());
    }
    if a.wire != b.wire {
        why.push("[gateway] wire".to_string());
    }
    if a.audit != b.audit {
        why.push(format!("[gateway] audit ({} → {})", a.audit, b.audit));
    }
    // Its certificate is swapped at a reload; its address is not.
    if a.admin.enabled != b.admin.enabled || a.admin.listen != b.admin.listen {
        why.push("[gateway.admin]".to_string());
    }
    // TLS turned on or off changes the URL every client has.
    let mode = |tls: &crate::config::ListenerTlsConfig| tls.mode;
    if mode(&a.tls).is_on() != mode(&b.tls).is_on() {
        why.push(format!(
            "[gateway.tls] mode ({} → {})",
            a.tls.mode.as_str(),
            b.tls.mode.as_str()
        ));
    }
    let admin = |g: &GatewayConfig| g.admin.enabled && g.admin_tls().mode.is_on();
    let own = a.admin.tls.is_some() || b.admin.tls.is_some();
    if own && admin(a) != admin(b) {
        why.push(format!(
            "the admin listener's TLS ({} → {})",
            mode(a.admin_tls()).as_str(),
            mode(b.admin_tls()).as_str()
        ));
    }
    // A proxy trusted, or none: the MCP listener's slot holds what it
    // forwards, and a plain listener has none without it. Its `cidrs` and
    // its header are swapped at a reload with the slot.
    let proxy = |g: &GatewayConfig| match g.trusted_proxy {
        Some(_) => "on",
        None => "off",
    };
    if proxy(a) != proxy(b) {
        why.push(format!(
            "[gateway.trusted_proxy] ({} → {})",
            proxy(a),
            proxy(b)
        ));
    }
    let jwks = |auth: &crate::config::AuthConfig, s: &Snapshot| {
        s.file(auth.jwks_file()).map(str::to_string)
    };
    if a.auth != b.auth || jwks(&a.auth, &old.snapshot) != jwks(&b.auth, snapshot) {
        why.push("[gateway.auth]".to_string());
    }
    // How a token names its caller is the verifier's, and how the console's
    // sign-in and its API tokens name theirs is the sign-in's: the start
    // builds both.
    let model = |c: &Config| c.identity.model();
    if (b.auth.enabled || b.admin.oidc.is_some()) && model(&old.config) != model(new) {
        why.push("[identity] subject_claim, roles_claims or role_map".to_string());
    }
    // The console's sign-in is set up as the admin listener starts.
    if a.admin.oidc != b.admin.oidc
        || a.admin.session != b.admin.session
        || (b.admin.oidc.is_some() && a.admin.public_url != b.admin.public_url)
    {
        why.push("[gateway.admin.oidc], [gateway.admin.session] or public_url".to_string());
    }
    why.iter_mut().for_each(|w| w.push_str(" changed"));
    why
}

/// The reconfiguration that takes the gateway from `old` to `new`.
fn plan(old: &Applied, new: &Config, snapshot: &Snapshot) -> Result<Reconfig, String> {
    let (a, b) = (&old.config.gateway, &new.gateway);
    let egress_changed = a.egress != b.egress;
    let upstreams = new
        .servers
        .iter()
        .map(|s| {
            let changed = match old.config.servers.iter().find(|o| o.id == s.id) {
                None => true,
                Some(o) => {
                    o.connection() != s.connection()
                        || old.snapshot.file(o.wasm_path()) != snapshot.file(s.wasm_path())
                        || (egress_changed && s.is_http())
                        || (s.is_https() && tls_changed((old, o), (new, s), snapshot))
                        // Its token fetches' profile. They read its files
                        // each time.
                        || (s.fetches_tokens() && a.upstream_tls != b.upstream_tls)
                        || (s.transport == "stdio" && env_changed(old, s, snapshot))
                }
            };
            Planned {
                server: supervised(new, s),
                changed,
            }
        })
        .collect();
    let pins = match &b.pins {
        Some(path) => {
            let store =
                PinStore::load(path).map_err(|e| format!("loading pin store {path}: {e}"))?;
            Some((store, PathBuf::from(path)))
        }
        None => None,
    };
    Ok(Reconfig {
        policy: new.to_policy(),
        rbac: new.rbac(),
        rules: new.policy_rules(),
        upstream_timeout: b.upstream_timeout(),
        rate_limit: (a.rate_limit != b.rate_limit).then(|| b.rate_limit_settings()),
        inspect: (a.inspect != b.inspect).then(|| b.inspect_scanner()),
        pins,
        tool_prefixes: new.tool_prefixes(),
        upstreams,
    })
}

/// Whether a file `s`'s `[server.env]` reads a value from changed since `old`
/// was read. Its entry is the same in both, or `connection()` said so already.
fn env_changed(old: &Applied, s: &crate::config::ServerConfig, snapshot: &Snapshot) -> bool {
    s.env_files()
        .any(|file| old.snapshot.file(Some(file)) != snapshot.file(Some(file)))
}

/// Whether an upstream's TLS profile changed from `old` to `new`: its
/// settings, `[gateway.upstream_tls]` under them included, or the content of
/// a file they name. A certificate renewed in place is such a change, so the
/// upstream reconnects with it.
fn tls_changed(
    (old, o): (&Applied, &crate::config::ServerConfig),
    (new, s): (&Config, &crate::config::ServerConfig),
    snapshot: &Snapshot,
) -> bool {
    let (before, after) = (old.config.upstream_tls(o), new.upstream_tls(s));
    before != after
        || after.files().iter().any(|file| {
            let file = file.to_str();
            old.snapshot.file(file) != snapshot.file(file)
        })
}

fn summary(report: &Reconfigured) -> String {
    let list = |what: &str, ids: &[String]| {
        (!ids.is_empty()).then(|| format!("{what} {}", ids.join(", ")))
    };
    let failed: Vec<String> = report.failed.iter().map(|(id, _)| id.clone()).collect();
    let parts: Vec<String> = [
        list("added", &report.added),
        list("removed", &report.removed),
        list("reconnected", &report.reconnected),
        list("failed to open", &failed),
    ]
    .into_iter()
    .flatten()
    .collect();
    if parts.is_empty() {
        "no upstream changed".to_string()
    } else {
        parts.join("; ")
    }
}

/// A digest shortened for a log line.
fn short(digest: &str) -> &str {
    &digest[..digest.len().min("sha256:".len() + 12)]
}

#[cfg(unix)]
type Hangups = Option<tokio::signal::unix::Signal>;
#[cfg(not(unix))]
type Hangups = ();

#[cfg(unix)]
fn hangups() -> Hangups {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::hangup()) {
        Ok(signal) => Some(signal),
        Err(e) => {
            eprintln!(
                "mcpdef: cannot listen for SIGHUP ({e}); reloads come from watch_config only"
            );
            None
        }
    }
}

#[cfg(not(unix))]
fn hangups() -> Hangups {}

/// The next `SIGHUP`; never, where there is none to listen for.
#[cfg(unix)]
async fn hangup(hangups: &mut Hangups) {
    match hangups {
        Some(signal) => {
            if signal.recv().await.is_none() {
                *hangups = None;
                std::future::pending::<()>().await;
            }
        }
        None => std::future::pending().await,
    }
}

#[cfg(not(unix))]
async fn hangup(_: &mut Hangups) {
    std::future::pending().await
}

/// The next reload the admin API asks for; never, when it can ask none.
async fn asked(requests: &mut Option<Requests>) -> Asked {
    if let Some(Requests(receiver)) = requests {
        if let Some(asked) = receiver.recv().await {
            return asked;
        }
        // Every sender is gone: nothing more will be asked.
        *requests = None;
    }
    std::future::pending().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(text: &str) -> Config {
        Config::parse(text).unwrap()
    }

    const BASE: &str = r#"
[gateway]
listen = "127.0.0.1:7878"

[[server]]
id = "a"
transport = "stdio"
command = ["srv"]
tools = ["x"]
"#;

    fn applied(text: &str) -> Applied {
        let config = config(text);
        Applied {
            snapshot: Snapshot::take(text.as_bytes(), &config),
            config,
        }
    }

    #[test]
    fn a_change_to_how_a_token_names_its_caller_needs_a_restart() {
        let base = "[gateway]\n[gateway.auth]\nenabled = true\nissuer = \"https://i\"\nresource = \"https://r\"\n\
                    jwks = \"{}\"\n\n[[server]]\nid = \"a\"\ntransport = \"stdio\"\ncommand = [\"x\"]\n";
        let old = applied(base);
        let roles = format!("{base}\n[identity]\nroles_claims = [\"groups\"]\n");
        assert_eq!(
            restart_required(&old, &config(&roles), &old.snapshot),
            ["[identity] subject_claim, roles_claims or role_map changed"]
        );
        // A certificate's roles are read at each request: no restart.
        let certs = format!(
            "{base}\n[[identity.cert_map]]\nidentity = \"spiffe://x/*\"\nroles = [\"r\"]\n"
        );
        assert!(restart_required(&old, &config(&certs), &old.snapshot).is_empty());
    }

    #[test]
    fn a_change_to_how_the_console_names_who_signs_in_needs_a_restart() {
        // The console signs people in, and [gateway.auth] is off: a role
        // taken away by a reload would still be given until a restart.
        let base = "[gateway]\n[gateway.admin]\nenabled = true\npublic_url = \"https://console.example\"\n\n\
                    [gateway.admin.oidc]\nissuer = \"https://idp.example\"\nclient_id = \"c\"\n\n\
                    [[server]]\nid = \"a\"\ntransport = \"stdio\"\ncommand = [\"x\"]\n";
        let granted = format!(
            "{base}\n[[identity.role_map]]\nclaim = \"groups\"\nvalue = \"ops\"\nroles = [\"console:admin\"]\n"
        );
        let old = applied(&granted);
        assert_eq!(
            restart_required(&old, &config(base), &old.snapshot),
            ["[identity] subject_claim, roles_claims or role_map changed"]
        );
        // With no one signed in at the console, nothing reads it but the
        // identity view.
        let unsigned = |text: &str| {
            text.replace(
                "[gateway.admin.oidc]\nissuer = \"https://idp.example\"\nclient_id = \"c\"\n",
                "",
            )
        };
        let old = applied(&unsigned(&granted));
        assert!(restart_required(&old, &config(&unsigned(base)), &old.snapshot).is_empty());
    }

    #[test]
    fn what_only_a_restart_can_change_is_named() {
        let old = applied(BASE);
        let same = config(BASE);
        assert!(restart_required(&old, &same, &old.snapshot).is_empty());
        let moved = config(&BASE.replace("7878", "7979"));
        assert_eq!(
            restart_required(&old, &moved, &old.snapshot),
            ["[gateway] listen (127.0.0.1:7878 → 127.0.0.1:7979) changed"]
        );
        let text = BASE.replace(
            "[[server]]",
            "audit = \"/tmp/other.log\"\n[gateway.auth]\nenabled = false\nissuer = \"x\"\n\n[[server]]",
        );
        let reasons = restart_required(&old, &config(&text), &old.snapshot);
        assert_eq!(reasons.len(), 2, "{reasons:?}");
        assert!(reasons[0].starts_with("[gateway] audit"));
        assert_eq!(reasons[1], "[gateway.auth] changed");
    }

    #[test]
    fn turning_a_trusted_proxy_on_or_off_needs_a_restart_and_its_ranges_do_not() {
        let with = |tables: &str| BASE.replace("[[server]]", &format!("{tables}\n\n[[server]]"));
        let proxy = "[gateway.trusted_proxy]\ncidrs = [\"10.0.0.0/8\"]";
        let off = applied(BASE);
        assert_eq!(
            restart_required(&off, &config(&with(proxy)), &off.snapshot),
            ["[gateway.trusted_proxy] (off → on) changed"]
        );
        let on = applied(&with(proxy));
        assert_eq!(
            restart_required(&on, &config(BASE), &on.snapshot),
            ["[gateway.trusted_proxy] (on → off) changed"]
        );
        // Its addresses, and its header: swapped with the listener's slot.
        let moved = config(&with(
            "[gateway.trusted_proxy]\ncidrs = [\"192.0.2.0/24\"]\n\
             client_cert_header = \"x-forwarded-client-cert\"",
        ));
        assert!(restart_required(&on, &moved, &on.snapshot).is_empty());
    }

    #[test]
    fn turning_tls_on_or_off_needs_a_restart_and_the_rest_does_not() {
        let with = |tables: &str| BASE.replace("[[server]]", &format!("{tables}\n\n[[server]]"));
        let self_signed = "[gateway.tls]\nmode = \"self-signed\"";
        let off = applied(BASE);
        let on = config(&with(self_signed));
        assert_eq!(
            restart_required(&off, &on, &off.snapshot),
            ["[gateway.tls] mode (off → self-signed) changed"]
        );
        let on = applied(&with(self_signed));
        assert_eq!(
            restart_required(&on, &config(BASE), &on.snapshot),
            ["[gateway.tls] mode (self-signed → off) changed"]
        );
        // From one certificate to another, or to more names: swapped whole
        // at the reload.
        for other in [
            "[gateway.tls]\nmode = \"files\"\ncert = \"/c\"\nkey = { file = \"/k\" }",
            "[gateway.tls]\nmode = \"self-signed\"\nhostnames = [\"mcpdef.internal\"]",
            "state_dir = \"/elsewhere\"\n[gateway.tls]\nmode = \"self-signed\"",
        ] {
            let new = config(&with(other));
            assert!(
                restart_required(&on, &new, &on.snapshot).is_empty(),
                "{other}"
            );
        }
        // The admin listener: its address needs a restart, and so does its
        // own TLS turned on or off; its certificate does not.
        let admin = "[gateway.admin]\nenabled = true";
        let old = applied(&with(admin));
        let moved = config(&with(
            "[gateway.admin]\nenabled = true\nlisten = \"127.0.0.1:7979\"",
        ));
        assert_eq!(
            restart_required(&old, &moved, &old.snapshot),
            ["[gateway.admin] changed"]
        );
        let own_on = config(&with(&format!(
            "{admin}\n[gateway.admin.tls]\nmode = \"self-signed\""
        )));
        assert_eq!(
            restart_required(&old, &own_on, &old.snapshot),
            ["the admin listener's TLS (off → self-signed) changed"]
        );
        let own_off = config(&with(&format!(
            "{admin}\n[gateway.admin.tls]\nmode = \"off\""
        )));
        assert!(restart_required(&old, &own_off, &old.snapshot).is_empty());
        let both = applied(&with(&format!("{admin}\n{self_signed}")));
        let own_files = config(&with(&format!(
            "{admin}\n{self_signed}\n[gateway.admin.tls]\nmode = \"files\"\ncert = \"/c\"\n\
             key = {{ file = \"/k\" }}"
        )));
        assert!(restart_required(&both, &own_files, &both.snapshot).is_empty());
    }

    #[test]
    fn a_policy_change_reconnects_nothing_and_a_command_change_reconnects_its_server() {
        let old = applied(BASE);
        let policy = config(&BASE.replace("tools = [\"x\"]", "tools = [\"x\", \"y\"]"));
        let plan_for = |c: &Config| plan(&old, c, &Snapshot::take(b"", c)).unwrap();
        assert!(!plan_for(&policy).upstreams[0].changed);
        let command = config(&BASE.replace("[\"srv\"]", "[\"srv\", \"--v2\"]"));
        assert!(plan_for(&command).upstreams[0].changed);
        let env = config(&format!("{BASE}\n[server.env]\nTOKEN = \"t\"\n"));
        assert!(plan_for(&env).upstreams[0].changed);
    }

    #[test]
    fn the_digest_covers_the_config_and_the_files_it_names() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("m.wasm");
        std::fs::write(&module, b"one").unwrap();
        let text = format!(
            "{BASE}\n[[server]]\nid = \"w\"\ntransport = \"wasm\"\nwasm = {:?}\n",
            module.to_string_lossy()
        );
        let c = config(&text);
        let digest = || Snapshot::take(text.as_bytes(), &c).digest;
        let first = digest();
        assert!(first.starts_with("sha256:") && first.len() == 7 + 64);
        assert_eq!(first, digest());
        std::fs::write(&module, b"two").unwrap();
        assert_ne!(first, digest(), "the module changed");
        std::fs::remove_file(&module).unwrap();
        assert_ne!(first, digest(), "the module is gone");
        assert_ne!(
            Snapshot::of(Some(b""), None),
            Snapshot::of(None, None),
            "an unreadable config is not an empty one"
        );
    }

    #[test]
    fn a_module_that_changed_reconnects_its_server_alone() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("m.wasm");
        std::fs::write(&module, b"one").unwrap();
        let text = format!(
            "{BASE}\n[[server]]\nid = \"w\"\ntransport = \"wasm\"\nwasm = {:?}\n",
            module.to_string_lossy()
        );
        let (old, new) = (applied(&text), config(&text));
        let changed = || -> Vec<bool> {
            let snapshot = Snapshot::take(text.as_bytes(), &new);
            let plan = plan(&old, &new, &snapshot).unwrap();
            plan.upstreams.iter().map(|p| p.changed).collect()
        };
        assert_eq!(changed(), [false, false]);
        std::fs::write(&module, b"two").unwrap();
        assert_eq!(changed(), [false, true]);
    }

    #[test]
    fn an_env_file_that_changed_reconnects_its_server_alone() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("token");
        std::fs::write(&token, "one").unwrap();
        let text = format!(
            "{BASE}\n[[server]]\nid = \"e\"\ntransport = \"stdio\"\ncommand = [\"srv\"]\n\
             [server.env]\nTOKEN = {{ file = {:?} }}\n",
            token.to_string_lossy()
        );
        let (old, new) = (applied(&text), config(&text));
        let changed = || -> Vec<bool> {
            let snapshot = Snapshot::take(text.as_bytes(), &new);
            let plan = plan(&old, &new, &snapshot).unwrap();
            plan.upstreams.iter().map(|p| p.changed).collect()
        };
        assert_eq!(changed(), [false, false]);
        // A watched config sees it too.
        let before = Snapshot::take(text.as_bytes(), &new);
        std::fs::write(&token, "two").unwrap();
        assert_eq!(changed(), [false, true]);
        assert_ne!(
            before.digest(),
            Snapshot::take(text.as_bytes(), &new).digest()
        );
    }

    #[test]
    fn a_jwks_file_that_changed_needs_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let jwks = dir.path().join("jwks.json");
        std::fs::write(&jwks, r#"{"keys":[]}"#).unwrap();
        let auth = format!(
            "[gateway.auth]\nenabled = true\nissuer = \"https://as.example\"\n\
             resource = \"https://gw.example\"\njwks = {:?}\n\n[[server]]",
            jwks.to_string_lossy()
        );
        let text = BASE.replace("[[server]]", &auth);
        let (old, new) = (applied(&text), config(&text));
        let why = || restart_required(&old, &new, &Snapshot::take(text.as_bytes(), &new));
        assert!(why().is_empty());
        std::fs::write(&jwks, r#"{"keys":[{"kty":"OKP"}]}"#).unwrap();
        assert_eq!(why(), ["[gateway.auth] changed"]);
    }

    #[test]
    fn a_new_fetch_profile_reconnects_the_servers_that_fetch_tokens_alone() {
        let servers = "[[server]]\nid = \"tokens\"\ntransport = \"streamable-http\"\n\
                       url = \"http://127.0.0.1:9/mcp\"\n[server.auth]\nkind = \"oauth2\"\n\
                       token_url = \"https://idp.test/token\"\nclient_id = \"c\"\n\
                       client_secret = { env = \"S\" }\n\n\
                       [[server]]\nid = \"bearer\"\ntransport = \"streamable-http\"\n\
                       url = \"http://127.0.0.1:9/mcp\"\n[server.auth]\nkind = \"bearer\"\n\
                       token = { env = \"T\" }\n";
        let text = format!("{BASE}\n{servers}");
        let old = applied(&text);
        let changed = |text: &str| -> Vec<bool> {
            let new = config(text);
            let plan = plan(&old, &new, &Snapshot::take(text.as_bytes(), &new)).unwrap();
            plan.upstreams.iter().map(|p| p.changed).collect()
        };
        assert_eq!(changed(&text), [false, false, false]);
        let system = text.replacen(
            "[[server]]",
            "[gateway.upstream_tls]\nroots = \"system\"\n\n[[server]]",
            1,
        );
        assert_eq!(changed(&system), [false, true, false]);
    }
    #[test]
    fn under_strict_a_config_with_a_warning_is_read_as_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcpdef.toml");
        let literal = format!("{BASE}[server.env]\nGITHUB_TOKEN = \"t\"\n");
        std::fs::write(&path, &literal).unwrap();
        assert!(read(&path, None).config.is_ok(), "a warning, not an error");
        std::fs::write(
            &path,
            literal.replace("[gateway]\n", "[gateway]\nstrict = true\n"),
        )
        .unwrap();
        let reasons = read(&path, None).config.unwrap_err();
        assert_eq!(reasons.len(), 1, "{reasons:?}");
        assert!(
            reasons[0].starts_with("strict: server 'a': [server.env] GITHUB_TOKEN is a secret"),
            "{reasons:?}"
        );
    }

    #[test]
    fn a_config_that_does_not_parse_is_refused_without_a_secret_its_url_holds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcpdef.toml");
        std::fs::write(
            &path,
            "[gateway]\n\n[[server]]\nid = \"x\"\ntransport = \"streamable-http\"\n\
             url = \"https://mcpdef:s3cret@mcp.test/mcp?api_key=s3cret-key\" oops\n",
        )
        .unwrap();
        let reasons = read(&path, None).config.unwrap_err();
        assert_eq!(reasons.len(), 1, "{reasons:?}");
        assert!(
            reasons[0].contains("https://***:***@mcp.test/mcp?api_key=***"),
            "the line at fault, masked: {reasons:?}"
        );
        assert!(!reasons[0].contains("s3cret"), "{reasons:?}");
    }
}
