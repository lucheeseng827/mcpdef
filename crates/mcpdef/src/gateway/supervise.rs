// SPDX-License-Identifier: Apache-2.0
//! Keeping upstreams up: each one's health, a start that opens them all at once,
//! and a task per upstream that starts it again whenever it goes down.

use super::{lock, open_within, Budget, Gateway, Inner, Listed, Opened, Slot, UpstreamOptions};
use crate::redact::redact_urls;
use anyhow::Result;
use mcpdef_transport::{rfc3339, DownWatch, PeerCertificate, TlsWatch, Transport, TransportError};
use serde::Serialize;
use std::future::Future;
use std::hash::{BuildHasher, Hasher};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;

/// Opens a new transport to one upstream. Its first start and every restart run
/// it, so a stdio server is spawned afresh and gets its environment afresh.
pub type Connect = Arc<dyn Fn() -> ConnectFuture + Send + Sync>;

/// What a [`Connect`] returns.
pub type ConnectFuture = Pin<Box<dyn Future<Output = Result<Box<dyn Transport>>> + Send>>;

/// An upstream the gateway keeps running: how to reach it, and how to treat it.
pub struct Supervised {
    pub id: String,
    pub connect: Connect,
    pub options: UpstreamOptions,
}

/// One upstream's claim on its place in the gateway, held by the place and by
/// whatever watches it. Retiring it stops that keeper or watcher, and a
/// connection opened under it afterwards is not installed. A reload that
/// replaces or removes an upstream retires its tenure; the place, if it stays,
/// gets a new one.
pub(super) struct Tenure {
    retired: watch::Sender<bool>,
}

impl Tenure {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Tenure {
            retired: watch::channel(false).0,
        })
    }

    pub(super) fn retire(&self) {
        self.retired.send_replace(true);
    }

    fn subscribe(&self) -> watch::Receiver<bool> {
        self.retired.subscribe()
    }
}

/// Resolves once `retired` says so, or its tenure is gone.
async fn retirement(retired: &mut watch::Receiver<bool>) {
    let _ = retired.wait_for(|retired| *retired).await;
}

/// What [`Gateway::start_supervised`] does about an upstream that does not start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Startup {
    /// Start without it, and keep trying it in the background.
    #[default]
    Degraded,
    /// Fail the whole start.
    FailFast,
}

/// Where an upstream stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthState {
    /// Opening, at startup or on a restart.
    Starting,
    /// Open, and its last call got a reply.
    Up,
    /// Open, but its last call failed or timed out.
    Degraded,
    /// Not open: it never started, its connection went, or too many calls in a
    /// row failed. A supervised upstream is started again.
    Down,
}

/// The last thing that went wrong with an upstream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LastError {
    pub message: String,
    pub at_unix_ms: u64,
}

/// When something last went right.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct LastOk {
    pub at_unix_ms: u64,
}

/// A tool name more than one server offers. It is listed once, from the
/// first of them in config order, and a call to it goes there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ToolCollision {
    /// The name as `tools/list` gives it.
    pub tool: String,
    /// The servers that offer it, in config order.
    pub servers: Vec<String>,
}

impl std::fmt::Display for ToolCollision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let quoted: Vec<String> = self.servers.iter().map(|s| format!("'{s}'")).collect();
        let offered_by = match quoted.split_last() {
            Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
            _ => quoted.concat(),
        };
        let first = quoted.first().map_or("", String::as_str);
        write!(
            f,
            "tool '{}' is offered by {offered_by}: it is listed once, from {first}, and a call \
             to it goes there",
            self.tool
        )
    }
}

/// One upstream's health, as [`Gateway::upstream_status`] reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UpstreamStatus {
    pub id: String,
    pub health: HealthState,
    /// How many times it was started again after going down, whether or not
    /// it came up.
    pub restarts: u64,
    pub last_error: Option<LastError>,
    /// For an HTTPS upstream that has opened, what its connection showed of
    /// its server's certificate. None for any other.
    pub tls: Option<TlsStatus>,
    /// How the credentials MCPdef sends it fare, for an upstream it sends
    /// some (`[server.auth]`). None for any other.
    pub credential: Option<CredentialStatus>,
    /// Times it refused MCPdef's credentials, or MCPdef had none to send it.
    pub auth_failures: u64,
    /// The tool names it offers that another server offers too.
    pub tool_collisions: Vec<ToolCollision>,
    /// What it said it offers when its connection opened. None until one
    /// has.
    pub offers: Option<Offers>,
}

/// What an upstream said it offers when its connection opened: the
/// capabilities its `initialize` reply declared, or its `server/discover`
/// reply did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Offers {
    /// Resources (`capabilities.resources`).
    pub resources: bool,
    /// Prompts (`capabilities.prompts`).
    pub prompts: bool,
    /// It says when its tools change (`capabilities.tools.listChanged`).
    pub tools_list_changed: bool,
}

impl Offers {
    /// Read from a reply's `capabilities`. A capability not declared, or
    /// declared `null` or `false`, is not offered.
    pub(super) fn of(reply: Option<&serde_json::Value>) -> Offers {
        let capabilities = reply.and_then(|reply| reply.get("capabilities"));
        let declared = |name: &str| {
            capabilities.and_then(|c| c.get(name)).is_some_and(|c| {
                !matches!(c, serde_json::Value::Null | serde_json::Value::Bool(false))
            })
        };
        Offers {
            resources: declared("resources"),
            prompts: declared("prompts"),
            tools_list_changed: capabilities
                .and_then(|c| c.pointer("/tools/listChanged"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        }
    }
}

/// How the credentials MCPdef sends an upstream fare.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CredentialStatus {
    /// The last time the upstream took them: it answered a request that
    /// carried them.
    pub last_ok: Option<LastOk>,
    /// The last time it refused them, or MCPdef had none to send, and why.
    pub last_error: Option<LastError>,
    /// When the credentials it is sent now expire, in RFC 3339: an OAuth
    /// token's, from its `expires_in`. None until one is fetched, after a
    /// fetch failed, and for credentials that do not say.
    pub expires_at: Option<String>,
    /// The same, in seconds since the Unix epoch.
    #[serde(skip)]
    pub expires_at_unix: Option<i64>,
}

/// The certificate an HTTPS upstream's server presented, as its connection
/// last saw it, and how it was checked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TlsStatus {
    /// `ca`, `pin` or `disabled`.
    pub verify: &'static str,
    /// The SHA-256 of the certificate, in the colon-separated hex
    /// `openssl x509 -fingerprint -sha256` prints.
    pub fingerprint: Option<String>,
    /// When it expires, in RFC 3339.
    pub not_after: Option<String>,
    /// The same, in seconds since the Unix epoch.
    #[serde(skip)]
    pub not_after_unix: Option<i64>,
    /// When the certificate MCPdef presents to the server expires, in RFC
    /// 3339, if it presents one (`client_cert`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_not_after: Option<String>,
    /// The same, in seconds since the Unix epoch.
    #[serde(skip)]
    pub client_not_after_unix: Option<i64>,
}

impl TlsStatus {
    /// What `watch` shows now.
    pub(super) fn of(watch: &TlsWatch) -> TlsStatus {
        let certificate = watch.certificate();
        let client_not_after = watch.client_not_after();
        TlsStatus {
            verify: watch.verification().as_str(),
            fingerprint: certificate.as_ref().map(|c| c.fingerprint.clone()),
            not_after: certificate
                .as_ref()
                .and_then(PeerCertificate::not_after_rfc3339),
            not_after_unix: certificate.and_then(|c| c.not_after),
            client_not_after: client_not_after.map(rfc3339),
            client_not_after_unix: client_not_after,
        }
    }
}

/// One upstream's health, kept across its connections.
#[derive(Default)]
pub(super) struct Health {
    starting: AtomicBool,
    restarts: AtomicU64,
    last_error: Mutex<Option<LastError>>,
    /// When the upstream last took the credentials MCPdef sent it, in
    /// milliseconds since the Unix epoch; 0 for never.
    credential_ok: AtomicU64,
    /// Times it refused them, or MCPdef had none to send it.
    auth_failures: AtomicU64,
    /// The last of those, and why.
    credential_error: Mutex<Option<LastError>>,
    /// Asks its keeper to open it again now.
    kick: tokio::sync::Notify,
}

impl Health {
    /// The health of an upstream about to open for the first time.
    pub(super) fn starting() -> Self {
        Health {
            starting: AtomicBool::new(true),
            ..Health::default()
        }
    }

    pub(super) fn is_starting(&self) -> bool {
        self.starting.load(Ordering::Relaxed)
    }

    pub(super) fn settle(&self) {
        self.starting.store(false, Ordering::Relaxed);
    }

    fn begin_restart(&self) {
        self.restarts.fetch_add(1, Ordering::Relaxed);
        self.starting.store(true, Ordering::Relaxed);
    }

    /// Ask its keeper to open it again now, its backoff reset. A keeper not
    /// waiting yet takes the ask when it next waits.
    pub(super) fn kick(&self) {
        self.kick.notify_one();
    }

    /// Resolves when its keeper is asked to open it again.
    async fn kicked(&self) {
        self.kick.notified().await;
    }

    pub(super) fn record(&self, message: String) {
        *lock(&self.last_error) = Some(LastError {
            message,
            at_unix_ms: now_ms(),
        });
    }

    /// Record why the upstream went down, and return it as the log says it:
    /// with any secret a URL in it holds masked.
    pub(super) fn record_down(&self, reason: &str) -> String {
        let reason = redact_urls(reason).into_owned();
        self.record(reason.clone());
        reason
    }

    /// Record why the upstream did not open, and return it as the log says
    /// it. A refusal of MCPdef's credentials, or none to send, is theirs too.
    pub(super) fn record_failure(&self, e: &anyhow::Error) -> String {
        let message = describe(e);
        if credentials_failed(e) {
            self.credential_failed(message.clone());
        }
        self.record(message.clone());
        message
    }

    /// The upstream answered a request that carried MCPdef's credentials.
    pub(super) fn credential_taken(&self) {
        self.credential_ok.store(now_ms(), Ordering::Relaxed);
    }

    /// The upstream refused MCPdef's credentials, or MCPdef had none to send
    /// it: `message` says which, and why.
    pub(super) fn credential_failed(&self, message: String) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
        *lock(&self.credential_error) = Some(LastError {
            message,
            at_unix_ms: now_ms(),
        });
    }

    pub(super) fn auth_failures(&self) -> u64 {
        self.auth_failures.load(Ordering::Relaxed)
    }

    /// How its credentials fare, those it is sent now expiring at
    /// `expires_at` (seconds since the Unix epoch), if they say.
    pub(super) fn credential(&self, expires_at: Option<i64>) -> CredentialStatus {
        let at_unix_ms = self.credential_ok.load(Ordering::Relaxed);
        CredentialStatus {
            last_ok: (at_unix_ms > 0).then_some(LastOk { at_unix_ms }),
            last_error: lock(&self.credential_error).clone(),
            expires_at: expires_at.map(rfc3339),
            expires_at_unix: expires_at,
        }
    }

    pub(super) fn restarts(&self) -> u64 {
        self.restarts.load(Ordering::Relaxed)
    }

    pub(super) fn last_error(&self) -> Option<LastError> {
        lock(&self.last_error).clone()
    }
}

/// The first wait before starting a downed upstream again. It doubles with
/// each failed start, up to [`MAX_BACKOFF`].
const FIRST_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(10);

/// An upstream that stayed up this long before going down starts again from
/// [`FIRST_BACKOFF`], not from where its last run of failures left off.
const STABLE_AFTER: Duration = Duration::from_secs(30);

/// The waits between starts: 500 ms, doubling to 10 s, each with up to a
/// quarter more at random, so upstreams that went down together do not all
/// come back at the same instant.
pub(super) struct Backoff {
    next: Duration,
}

impl Backoff {
    pub(super) fn new() -> Self {
        Backoff {
            next: FIRST_BACKOFF,
        }
    }

    fn reset(&mut self) {
        self.next = FIRST_BACKOFF;
    }

    pub(super) fn next_delay(&mut self) -> Duration {
        let base = self.next;
        self.next = (base * 2).min(MAX_BACKOFF);
        base + jitter(base / 4)
    }
}

/// A random duration from zero to `max`. The standard library's hasher keys are
/// random per process and move on with every use, which is all jitter needs.
fn jitter(max: Duration) -> Duration {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    );
    let span = u64::try_from(max.as_nanos()).unwrap_or(u64::MAX);
    Duration::from_nanos(hasher.finish() % span.saturating_add(1))
}

pub(super) fn secs(d: Duration) -> String {
    format!("{:.1}s", d.as_secs_f64())
}

/// Now, in milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// An error and its causes, each once, with any secret a URL among them holds
/// masked. Some errors already name their cause in their own message, and
/// anyhow's `{:#}` would then repeat it.
pub(super) fn describe(e: &anyhow::Error) -> String {
    let mut out = String::new();
    for cause in e.chain() {
        let text = cause.to_string();
        if out.contains(&text) {
            continue;
        }
        if !out.is_empty() {
            out.push_str(": ");
        }
        out.push_str(&text);
    }
    redact_urls(&out).into_owned()
}

/// Whether `e` is the upstream refusing MCPdef's credentials, or MCPdef
/// having none to send it.
fn credentials_failed(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<TransportError>(),
            Some(TransportError::Unauthorized(_) | TransportError::Credentials(_))
        )
    })
}

/// Futures run together on the task that awaits them, each result taken as it
/// is ready.
///
/// Startup opens every upstream this way rather than on a task apiece: what it
/// waits on, it waits on at once, and the little work between the waits stays
/// on one thread instead of touching every worker's.
pub(super) struct Together<'a, T> {
    pending: Vec<Option<Pin<Box<dyn Future<Output = T> + Send + 'a>>>>,
}

impl<'a, T> Together<'a, T> {
    pub(super) fn new(
        futures: impl IntoIterator<Item = impl Future<Output = T> + Send + 'a>,
    ) -> Self {
        Together {
            pending: futures
                .into_iter()
                .map(|f| Some(Box::pin(f) as Pin<Box<dyn Future<Output = T> + Send + 'a>>))
                .collect(),
        }
    }

    /// The next result to be ready, with the position of its future; `None`
    /// once every future has given its result.
    pub(super) async fn next(&mut self) -> Option<(usize, T)> {
        std::future::poll_fn(|cx| {
            let mut waiting = false;
            for (i, slot) in self.pending.iter_mut().enumerate() {
                let Some(future) = slot else { continue };
                if let Poll::Ready(out) = future.as_mut().poll(cx) {
                    *slot = None;
                    return Poll::Ready(Some((i, out)));
                }
                waiting = true;
            }
            if waiting {
                Poll::Pending
            } else {
                Poll::Ready(None)
            }
        })
        .await
    }
}

/// What a keeper does next.
pub(super) enum Next {
    /// Wait for this connection to go down, then start the upstream again.
    Watch(DownWatch),
    /// Wait this long, then start it.
    Retry(Duration),
}

impl Gateway {
    /// Start upstreams the gateway keeps running.
    ///
    /// They open at once, so startup takes about as long as the slowest, and
    /// this returns when each has opened or failed to. Each takes its place in
    /// the order given before any opens, so a tool two of them list goes to the
    /// earlier one whichever opens first.
    ///
    /// With [`Startup::Degraded`], one that fails to open starts
    /// [down](HealthState::Down), its failure is logged and audited, and it is
    /// tried again in the background. With [`Startup::FailFast`], its failure
    /// fails the start, and none of these upstreams is kept.
    ///
    /// From then on, each one that goes down is started again, 500 ms later at
    /// first and up to 10 s later after repeated failures. A restart opens it
    /// afresh, checks its tools against the pins again, and routes calls to it
    /// again.
    pub async fn start_supervised(&self, servers: Vec<Supervised>, startup: Startup) -> Result<()> {
        let healths: Vec<Arc<Health>> = servers
            .iter()
            .map(|_| Arc::new(Health::starting()))
            .collect();
        let tenures: Vec<Arc<Tenure>> = servers.iter().map(|_| Tenure::new()).collect();
        self.govern(|g| {
            for ((s, health), tenure) in servers.iter().zip(&healths).zip(&tenures) {
                let (health, tenure) = (Arc::clone(health), Arc::clone(tenure));
                let credentials = s.options.credentials;
                let slot = Slot::new(s.id.clone(), health, tenure, true, credentials);
                g.upstreams.push(slot);
            }
        });

        let mut openings = Together::new(
            servers
                .iter()
                .map(|s| self.open_fresh(&s.id, &s.connect, s.options)),
        );
        let mut backoffs: Vec<Backoff> = servers.iter().map(|_| Backoff::new()).collect();
        let mut next: Vec<Option<Next>> = servers.iter().map(|_| None).collect();
        while let Some((i, opened)) = openings.next().await {
            let id = &servers[i].id;
            match opened {
                Ok(opened) => {
                    next[i] = self.install(id, &tenures[i], opened).map(Next::Watch);
                    healths[i].settle();
                }
                Err(e) if startup == Startup::FailFast => {
                    // Dropping the other openings closes what they opened; the
                    // places made above go too, with anything already in them.
                    self.govern(|g| {
                        g.upstreams
                            .retain(|slot| !healths.iter().any(|h| Arc::ptr_eq(h, &slot.health)));
                        g.reroute();
                    });
                    return Err(e.context(format!("initializing upstream '{id}'")));
                }
                Err(e) => {
                    let delay = backoffs[i].next_delay();
                    let message = healths[i].record_failure(&e);
                    eprintln!(
                        "mcpdef: upstream '{id}' did not start: {message}; next attempt in {}",
                        secs(delay)
                    );
                    healths[i].settle();
                    self.audit_upstream(id, UpstreamEvent::Down).await;
                    next[i] = Some(Next::Retry(delay));
                }
            }
        }

        drop(openings);
        let started = servers.into_iter().zip(healths).zip(tenures).zip(backoffs);
        for ((((s, health), tenure), backoff), next) in started.zip(next) {
            let Some(next) = next else { continue };
            self.keep(s, health, tenure, backoff, next, None);
        }
        Ok(())
    }

    /// Hand an upstream to a keeper of its own.
    ///
    /// `replacing` watches the connection its place still holds, opened under
    /// earlier settings, which serves until one on the new settings opens.
    pub(super) fn keep(
        &self,
        server: Supervised,
        health: Arc<Health>,
        tenure: Arc<Tenure>,
        backoff: Backoff,
        next: Next,
        replacing: Option<DownWatch>,
    ) {
        let keeper = Keeper {
            me: Arc::downgrade(&self.inner),
            id: server.id,
            connect: server.connect,
            options: server.options,
            health,
            retired: tenure.subscribe(),
            tenure,
            backoff,
            replacing,
            shutdown: self.inner.shutdown.subscribe(),
            asked: false,
        };
        tokio::spawn(keeper.run(next));
    }

    /// Open a new connection to an upstream and judge its tools.
    async fn open_fresh(
        &self,
        id: &str,
        connect: &Connect,
        options: UpstreamOptions,
    ) -> Result<Opened> {
        let client = Arc::clone(&self.inner.client_info);
        let budget = self.opening_budget(options.spec);
        let (transport, listed) = reach(id, connect, options, &client, &budget).await?;
        Ok(self.admit(id, transport, listed, options).await)
    }

    /// Note when an upstream the gateway does not keep running goes down.
    pub(super) fn watch_unsupervised(
        &self,
        id: String,
        health: Arc<Health>,
        tenure: &Tenure,
        watch: DownWatch,
    ) {
        let mut shutdown = self.inner.shutdown.subscribe();
        let mut retired = tenure.subscribe();
        tokio::spawn(async move {
            tokio::select! {
                reason = watch.down() => {
                    let reason = health.record_down(&reason);
                    eprintln!("mcpdef: upstream '{id}' is down: {reason}");
                }
                _ = shutdown.changed() => {}
                () = retirement(&mut retired) => {}
            }
        });
    }

    /// The gateway `me` points to, if it is still there.
    pub(super) fn upgrade(me: &Weak<Inner>) -> Option<Gateway> {
        me.upgrade().map(|inner| Gateway { inner })
    }
}

/// What an upstream's life in the ledger records: it went down, came back,
/// or was connected without its certificate checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UpstreamEvent {
    Down,
    Up,
    Unverified,
}

/// Why the upstream `watch` watches went down, once it does; with none,
/// never.
async fn until_down(watch: Option<&DownWatch>) -> Arc<str> {
    match watch {
        Some(watch) => watch.down().await,
        None => std::future::pending().await,
    }
}

/// Open a new transport to an upstream and run its opening.
pub(super) async fn reach(
    id: &str,
    connect: &Connect,
    options: UpstreamOptions,
    client: &serde_json::Value,
    budget: &Budget,
) -> Result<(Box<dyn Transport>, Listed)> {
    let mut transport = connect().await?;
    let listed = open_within(id, &mut *transport, options.spec, client, budget).await?;
    Ok((transport, listed))
}

/// Keeps one upstream running until the gateway is dropped, or until a reload
/// retires its tenure.
///
/// It holds the gateway only by a weak reference, and only upgrades it for the
/// moments it changes it. Dropping the gateway therefore closes every
/// connection at once, even while a keeper waits or an upstream opens.
struct Keeper {
    me: Weak<Inner>,
    id: String,
    connect: Connect,
    options: UpstreamOptions,
    health: Arc<Health>,
    tenure: Arc<Tenure>,
    retired: watch::Receiver<bool>,
    backoff: Backoff,
    /// Opening new settings while a connection on older ones still serves,
    /// watched here: an attempt is no restart, and a failed one leaves the
    /// upstream serving.
    replacing: Option<DownWatch>,
    /// Closes when the gateway is dropped.
    shutdown: watch::Receiver<()>,
    /// Opening it again because the admin API asked, while the connection it
    /// replaces serves.
    asked: bool,
}

/// What woke a keeper waiting on a connection.
enum Woke {
    Down(Arc<str>),
    Asked,
    Gone,
}

impl Keeper {
    async fn run(mut self, mut next: Next) {
        loop {
            let delay = match next {
                Next::Watch(watch) => match self.wait_down(watch).await {
                    Some(delay) => delay,
                    None => return,
                },
                Next::Retry(delay) => delay,
            };
            if self.wait(delay).await.is_none() {
                return;
            }
            // Boxed, so a keeper that waits, as nearly all do nearly always,
            // holds no room for an opening in progress.
            next = match Box::pin(self.restart()).await {
                Some(next) => next,
                None => return,
            };
        }
    }

    /// Wait `delay` before the next attempt. A connection on older settings
    /// that goes down meanwhile is down like any other: logged, audited, and
    /// no longer replaced but restarted. `None` once the gateway, or this
    /// upstream's place in it, is gone.
    async fn wait(&mut self, delay: Duration) -> Option<()> {
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        loop {
            let serving = self.replacing.clone();
            tokio::select! {
                () = &mut sleep => return Some(()),
                _ = self.shutdown.changed() => return None,
                () = retirement(&mut self.retired) => return None,
                () = self.health.kicked() => {
                    self.backoff.reset();
                    return Some(());
                }
                reason = until_down(serving.as_ref()) => {
                    self.replacing = None;
                    let gw = Gateway::upgrade(&self.me)?;
                    let left = sleep.deadline() - tokio::time::Instant::now();
                    let reason = self.health.record_down(&reason);
                    eprintln!(
                        "mcpdef: upstream '{}' is down: {reason}; its new settings are tried \
                         again in {}",
                        self.id,
                        secs(left)
                    );
                    gw.audit_upstream(&self.id, UpstreamEvent::Down).await;
                }
            }
        }
    }

    /// Wait for the connection to go down. Then say so, and return how long to
    /// wait before starting it again. `None` once the gateway is gone.
    async fn wait_down(&mut self, watch: DownWatch) -> Option<Duration> {
        let up_at = Instant::now();
        let woke = tokio::select! {
            reason = watch.down() => Woke::Down(reason),
            _ = self.shutdown.changed() => Woke::Gone,
            () = retirement(&mut self.retired) => Woke::Gone,
            () = self.health.kicked() => Woke::Asked,
        };
        let reason = match woke {
            Woke::Down(reason) => reason,
            Woke::Gone => return None,
            Woke::Asked => {
                // Opened again now, the connection serving until the new one
                // opens, as a reload's new settings are.
                eprintln!(
                    "mcpdef: upstream '{}': opening it again, as the admin API asked",
                    self.id
                );
                self.health.restarts.fetch_add(1, Ordering::Relaxed);
                self.backoff.reset();
                self.replacing = Some(watch);
                self.asked = true;
                return Some(Duration::ZERO);
            }
        };
        let gw = Gateway::upgrade(&self.me)?;
        if up_at.elapsed() >= STABLE_AFTER {
            self.backoff.reset();
        }
        let delay = self.backoff.next_delay();
        let reason = self.health.record_down(&reason);
        eprintln!(
            "mcpdef: upstream '{}' is down: {reason}; restarting in {}",
            self.id,
            secs(delay)
        );
        gw.audit_upstream(&self.id, UpstreamEvent::Down).await;
        Some(delay)
    }

    /// Start the upstream again. `None` once the gateway, or this upstream's
    /// place in it, is gone.
    async fn restart(&mut self) -> Option<Next> {
        if self.replacing.is_none() {
            self.health.begin_restart();
        }
        let (client, budget) = {
            let gw = Gateway::upgrade(&self.me)?;
            (
                Arc::clone(&gw.inner.client_info),
                gw.opening_budget(self.options.spec),
            )
        };
        // No hold on the gateway while the upstream opens, however long that
        // takes: dropping the gateway must still close everything at once.
        let reached = tokio::select! {
            reached = reach(&self.id, &self.connect, self.options, &client, &budget) => reached,
            _ = self.shutdown.changed() => return None,
            () = retirement(&mut self.retired) => return None,
        };
        let gw = Gateway::upgrade(&self.me)?;
        match reached {
            Ok((transport, listed)) => {
                let opened = gw.admit(&self.id, transport, listed, self.options).await;
                let watch = gw.install(&self.id, &self.tenure, opened)?;
                // What the opening pinned is on disk before the upstream is
                // said to be up: one that serves is one whose pins are kept.
                if let Err(e) = gw.write_pins() {
                    eprintln!("mcpdef: saving the pin store: {e:#}");
                }
                self.health.settle();
                if self.replacing.take().is_some() {
                    match std::mem::take(&mut self.asked) {
                        true => eprintln!("mcpdef: upstream '{}' is open again", self.id),
                        false => {
                            eprintln!("mcpdef: upstream '{}' now runs its new settings", self.id)
                        }
                    }
                } else {
                    eprintln!("mcpdef: upstream '{}' is up again", self.id);
                    gw.audit_upstream(&self.id, UpstreamEvent::Up).await;
                }
                Some(Next::Watch(watch))
            }
            Err(e) => {
                let delay = self.backoff.next_delay();
                let message = self.health.record_failure(&e);
                if self.replacing.is_some() {
                    let what = match self.asked {
                        true => "it did not open again",
                        false => "its new settings did not start",
                    };
                    eprintln!(
                        "mcpdef: upstream '{}': {what}: {message}; it keeps its old \
                         connection; next attempt in {}",
                        self.id,
                        secs(delay)
                    );
                } else {
                    eprintln!(
                        "mcpdef: upstream '{}' did not start: {message}; next attempt in {}",
                        self.id,
                        secs(delay)
                    );
                }
                self.health.settle();
                Some(Next::Retry(delay))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What an upstream offers is what its reply's `capabilities` declares,
    /// whether that is an `initialize` reply or a `server/discover` one.
    #[test]
    fn offers_are_read_from_the_capabilities_a_reply_declares() {
        let reply = serde_json::json!({ "capabilities": {
            "tools": { "listChanged": true }, "resources": {}
        } });
        assert_eq!(
            Offers::of(Some(&reply)),
            Offers {
                resources: true,
                prompts: false,
                tools_list_changed: true
            }
        );
        let reply = serde_json::json!({ "capabilities": {
            "tools": {}, "prompts": { "listChanged": false }, "resources": null
        } });
        assert_eq!(
            Offers::of(Some(&reply)),
            Offers {
                resources: false,
                prompts: true,
                tools_list_changed: false
            }
        );
        // A reply that declares nothing offers nothing.
        assert_eq!(Offers::of(Some(&serde_json::json!({}))), Offers::default());
        assert_eq!(Offers::of(None), Offers::default());
    }

    #[test]
    fn the_backoff_doubles_to_its_cap_with_up_to_a_quarter_more() {
        let mut backoff = Backoff::new();
        let mut bases = Vec::new();
        for _ in 0..8 {
            let base = backoff.next;
            let delay = backoff.next_delay();
            assert!(
                delay >= base && delay <= base + base / 4,
                "{delay:?} from {base:?}"
            );
            bases.push(base.as_millis());
        }
        assert_eq!(bases, [500, 1000, 2000, 4000, 8000, 10000, 10000, 10000]);
        backoff.reset();
        assert_eq!(backoff.next, FIRST_BACKOFF);
    }

    #[test]
    fn jitter_spreads_and_stays_in_bounds() {
        let max = Duration::from_millis(125);
        let draws: Vec<Duration> = (0..64).map(|_| jitter(max)).collect();
        assert!(draws.iter().all(|d| *d <= max));
        let distinct: std::collections::HashSet<_> = draws.iter().collect();
        assert!(
            distinct.len() > 32,
            "only {} distinct draws",
            distinct.len()
        );
        assert_eq!(jitter(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn an_error_names_each_cause_once() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        // A cause its own message already carries is not repeated...
        let spawn = anyhow::Error::new(mcpdef_transport::TransportError::Spawn {
            cmd: "srv".into(),
            source: io,
        });
        assert_eq!(describe(&spawn), "spawn 'srv': no such file");
        // ...and one it does not carry is added.
        let wrapped = anyhow::anyhow!("refused").context("opening 'x'");
        assert_eq!(describe(&wrapped), "opening 'x': refused");
    }

    /// Once a reload hands an upstream's place to a new tenure, a connection
    /// opened under the old one, by a keeper not yet stopped, stays out of it.
    #[tokio::test]
    async fn only_the_tenure_holding_a_place_installs_in_it() {
        use crate::gateway::HealthState;
        let dir = tempfile::tempdir().unwrap();
        let ledger = mcpdef_audit::Ledger::open(dir.path().join("audit.log")).unwrap();
        let gw = Gateway::new(mcpdef_policy::Policy::new(), ledger, "agent:test");
        let (holder, retired) = (Tenure::new(), Tenure::new());
        let place = Slot::new("a".into(), Arc::default(), Arc::clone(&holder), true, false);
        gw.govern(|g| g.upstreams.push(place.clone()));
        let mut peers = Vec::new();
        let mut open = || {
            let (ours, theirs) = mcpdef_transport::duplex_pair();
            peers.push(theirs);
            let listed = Listed {
                spec: Default::default(),
                tools: Vec::new(),
                changed: false,
                offers: Offers::default(),
            };
            gw.admit("a", Box::new(ours), listed, UpstreamOptions::default())
        };

        let stale = open().await;
        assert!(gw.install("a", &retired, stale).is_none());
        assert_eq!(gw.upstream_status()[0].health, HealthState::Down);
        let current = open().await;
        assert!(gw.install("a", &holder, current).is_some());
        assert_eq!(gw.upstream_status()[0].health, HealthState::Up);
    }

    #[test]
    fn health_keeps_the_last_error_and_counts_restarts() {
        let health = Health::starting();
        assert!(health.is_starting());
        health.record("connection refused".into());
        health.settle();
        assert!(!health.is_starting());
        health.begin_restart();
        health.begin_restart();
        assert!(health.is_starting());
        assert_eq!(health.restarts(), 2);
        let last = health.last_error().unwrap();
        assert_eq!(last.message, "connection refused");
        assert!(last.at_unix_ms > 1_700_000_000_000);
    }
}
