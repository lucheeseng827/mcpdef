// SPDX-License-Identifier: Apache-2.0
//! TLS on MCPdef's own listeners: the MCP listener (`[gateway.tls]`) and the
//! admin listener (`[gateway.admin.tls]`, or the MCP listener's when it sets
//! none).
//!
//! **Where the certificate comes from.** `files`: the certificate and key a
//! config names, read by the rules an upstream client certificate is read by,
//! as cert-manager or certbot writes them. `self-signed`: one issued by a local
//! CA of MCPdef's own, kept under `[gateway] state_dir` (see [`local_ca`]).
//!
//! **Swapped whole.** Each listener's `ServerConfig` sits behind an
//! [`ArcSwap`], and the accept loop loads it for each connection. A reload
//! builds new ones from the new config and its files, and stores them only if
//! every one builds: a certificate that does not read leaves the old one
//! serving, and the reload refused. A connection keeps the certificate it was
//! accepted with. Only turning TLS on or off needs a restart: that changes
//! the URL every client has.
//!
//! **The accept loop** takes each TCP connection, runs its handshake on a
//! task of its own under [`HANDSHAKE_TIMEOUT`], and hands those that finish to
//! `axum::serve` through its `Listener` trait, which serves them as it serves
//! plain ones. A client that connects and says nothing holds up no one.
//!
//! **mTLS** (`client_auth`): a listener that asks for a client's certificate
//! checks it at the handshake, and its connection keeps it, for the requests
//! on it to read who the client is (see [`client_auth`]). A certificate the
//! check refuses is logged; one that is never presented is not.
//!
//! **Behind a trusted proxy** (`[gateway.trusted_proxy]`): the MCP listener
//! reads each client's certificate from the header the proxy forwards it in,
//! on a connection from the proxy alone, and checks it as `client_auth` says
//! (see [`forwarded`]). It may then serve plain HTTP, the proxy terminating
//! TLS in front of it: its slot holds its check of client certificates, and
//! the proxy, and no TLS configuration.

pub mod client_auth;
pub mod forwarded;
pub mod issued;
pub mod local_ca;

use crate::config::{Config, ListenerTlsConfig, ListenerTlsMode};
use arc_swap::ArcSwap;
use client_auth::{ClientCerts, Presented};
use forwarded::TrustedProxy;
use local_ca::{Names, Paths};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// How long a client has to finish its TLS handshake before its connection
/// is dropped.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// What a listener serves: its rustls configuration, what it asks of a
/// client's certificate, and the proxy it trusts in front of it to forward
/// one. Swapped whole when a reload changes any.
pub struct Served {
    /// `None` on a listener that serves plain HTTP behind a trusted proxy.
    pub config: Option<Arc<ServerConfig>>,
    /// `None` when the listener asks for no client certificate.
    pub clients: Option<Arc<ClientCerts>>,
    /// The proxy whose forwarded certificates the listener reads
    /// (`[gateway.trusted_proxy]`): the MCP listener's alone.
    pub proxy: Option<TrustedProxy>,
}

impl From<ServerConfig> for Served {
    /// A configuration, however it was built, with no client certificate
    /// asked for by MCPdef's own check.
    fn from(config: ServerConfig) -> Self {
        Served {
            config: Some(Arc::new(config)),
            clients: None,
            proxy: None,
        }
    }
}

/// What a listener serves, as [`Served`] says, swapped whole when it
/// changes.
pub type TlsSlot = Arc<ArcSwap<Served>>;

/// Which of the listeners have a slot in this process: the MCP listener when
/// it serves HTTP with `[gateway.tls]` on, or behind a
/// `[gateway.trusted_proxy]`; the admin listener when it is enabled with its
/// TLS on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Serving {
    pub mcp: bool,
    pub admin: bool,
}

impl Serving {
    /// What `cfg` has slots for, with the MCP listener serving HTTP if
    /// `http`.
    pub fn of(cfg: &Config, http: bool) -> Serving {
        let g = &cfg.gateway;
        Serving {
            mcp: http && (g.tls.mode.is_on() || g.trusted_proxy.is_some()),
            admin: g.admin.enabled && g.admin_tls().mode.is_on(),
        }
    }

    fn any(self) -> bool {
        self.mcp || self.admin
    }
}

/// What the listeners that serve TLS serve, as a config says: built, not yet
/// in use.
pub struct Built {
    mcp: Option<Arc<Served>>,
    admin: Option<Arc<Served>>,
    /// When the self-signed certificate is to be issued again, if one is
    /// served and issuing it again would help.
    renew_at: Option<SystemTime>,
    /// What an operator should hear: a CA made, a certificate issued.
    pub notes: Vec<String>,
}

/// Build what `cfg` says the listeners in `serving` serve: each one's
/// certificate read or issued, the CAs and CRLs its clients' certificates
/// are checked against read, its `ServerConfig` if it serves TLS, and the
/// MCP listener's trusted proxy. The self-signed
/// certificate is one, for every listener that serves it, and is issued
/// only when the one in `state_dir` will not do (see [`local_ca::ensure`]).
/// A local CA is made if there is none and `make_ca` says so.
pub fn build(
    cfg: &Config,
    serving: Serving,
    now: SystemTime,
    make_ca: bool,
) -> Result<Built, String> {
    let g = &cfg.gateway;
    let mcp = serving.mcp.then_some(("[gateway.tls]", &g.tls));
    let admin = serving.admin.then(|| (g.admin_tls_table(), g.admin_tls()));
    // The listeners that serve the self-signed certificate: its names are
    // theirs alone.
    let signs = |listener: &Option<(&str, &ListenerTlsConfig)>| {
        listener
            .as_ref()
            .is_some_and(|(_, table)| table.mode == ListenerTlsMode::SelfSigned)
    };
    let self_signed = if signs(&mcp) || signs(&admin) {
        let names = self_signed_names(cfg, signs(&mcp), signs(&admin));
        let paths = Paths::under(&g.state_dir);
        Some(local_ca::ensure(&paths, &names, now, make_ca)?)
    } else {
        None
    };
    let serve = |listener: Option<(&str, &ListenerTlsConfig)>,
                 proxy: Option<&crate::config::TrustedProxyConfig>|
     -> Result<_, String> {
        let Some((table, tls)) = listener else {
            return Ok(None);
        };
        let client_auth = format!("{}.client_auth]", table.trim_end_matches(']'));
        let clients = ClientCerts::build(&client_auth, &tls.client_auth)?;
        let certified = match (tls.mode, &self_signed) {
            (ListenerTlsMode::Off, _) => None,
            (ListenerTlsMode::SelfSigned, Some(ensured)) => Some(ensured.certified.clone()),
            _ => Some(served_files(table, tls)?),
        };
        let config = certified
            .map(|certified| server_config(certified, clients.as_deref()))
            .transpose()?;
        let proxy = proxy.map(TrustedProxy::build).transpose()?;
        Ok(Some(Arc::new(Served {
            config,
            clients,
            proxy,
        })))
    };
    let (mcp, admin) = (serve(mcp, g.trusted_proxy.as_ref())?, serve(admin, None)?);
    let (renew_at, notes) = match self_signed {
        Some(ensured) => (ensured.renew_at, ensured.notes),
        None => (None, Vec::new()),
    };
    Ok(Built {
        mcp,
        admin,
        renew_at,
        notes,
    })
}

/// A `files` listener's certificate and key, read.
fn served_files(table: &str, tls: &ListenerTlsConfig) -> Result<CertifiedKey, String> {
    let files = tls
        .served_files()
        .ok_or_else(|| format!("{table} mode = \"files\" needs `cert` and `key`"))?;
    mcpdef_transport::read_served(&files).map_err(|e| {
        let e = match e {
            mcpdef_transport::TransportError::Tls(e) => e,
            e => e.to_string(),
        };
        format!("{table} {e}")
    })
}

/// A listener's configuration for `certified`: TLS 1.2 and 1.3 on ring, a
/// client's certificate asked for and checked as `clients` says, or none
/// asked for without it, and HTTP/1.1 offered, which is what the listener
/// speaks.
fn server_config(
    certified: CertifiedKey,
    clients: Option<&ClientCerts>,
) -> Result<Arc<ServerConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("the listener's TLS configuration: {e}"))?;
    let builder = match clients {
        Some(clients) => builder.with_client_cert_verifier(clients.verifier()),
        None => builder.with_no_client_auth(),
    };
    let mut config = builder.with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// What the self-signed certificate is for: `localhost`, `127.0.0.1` and
/// `::1`; the address each listener that serves it binds to, when that is
/// one host; and each such listener's `hostnames`. `mcp` and `admin` say
/// which listeners count.
pub fn self_signed_names(cfg: &Config, mcp: bool, admin: bool) -> Names {
    let g = &cfg.gateway;
    let mut listeners = Vec::new();
    if mcp {
        listeners.push((&g.listen, &g.tls));
    }
    if admin {
        listeners.push((&g.admin.listen, g.admin_tls()));
    }
    let names = listeners.into_iter().flat_map(|(listen, tls)| {
        listen_host(listen)
            .into_iter()
            .chain(tls.hostnames.iter().cloned())
    });
    Names::new(names)
}

/// The one host a `host:port` binds to: none for the unspecified addresses,
/// which are every address and so no name.
fn listen_host(listen: &str) -> Option<String> {
    let (host, _) = listen.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) if ip.is_unspecified() => None,
        Ok(ip) => Some(ip.to_string()),
        Err(_) => (!host.is_empty()).then(|| host.to_string()),
    }
}

/// The TLS of this process's listeners: what each serves now, and when the
/// self-signed certificate is to be issued again. Clones share it.
#[derive(Clone)]
pub struct ListenerTls {
    serving: Serving,
    mcp: Option<TlsSlot>,
    admin: Option<TlsSlot>,
    renew_at: Arc<Mutex<Option<SystemTime>>>,
}

impl ListenerTls {
    /// The TLS the listeners in `serving` serve, as `cfg` says, with a local
    /// CA made if self-signed wants one and there is none; and what an
    /// operator should hear of it. `None` when no listener has a slot.
    pub fn start(
        cfg: &Config,
        serving: Serving,
    ) -> Result<Option<(ListenerTls, Vec<String>)>, String> {
        Self::start_at(cfg, serving, SystemTime::now())
    }

    /// [`start`](Self::start), as of `now`.
    pub fn start_at(
        cfg: &Config,
        serving: Serving,
        now: SystemTime,
    ) -> Result<Option<(ListenerTls, Vec<String>)>, String> {
        if !serving.any() {
            return Ok(None);
        }
        let built = build(cfg, serving, now, true)?;
        let slot = |served: Option<Arc<Served>>| served.map(|s| Arc::new(ArcSwap::new(s)));
        let tls = ListenerTls {
            serving,
            mcp: slot(built.mcp),
            admin: slot(built.admin),
            renew_at: Arc::new(Mutex::new(built.renew_at)),
        };
        Ok(Some((tls, built.notes)))
    }

    /// The MCP listener's slot, if it serves TLS or reads a trusted proxy's
    /// forwarded certificates.
    pub fn mcp(&self) -> Option<TlsSlot> {
        self.mcp.clone()
    }

    /// The admin listener's slot, if it serves TLS.
    pub fn admin(&self) -> Option<TlsSlot> {
        self.admin.clone()
    }

    /// Build what `cfg` says these listeners serve, at `now`, never making a
    /// CA: for a reload, and a renewal. Nothing is in use until
    /// [`install`](Self::install).
    pub fn prepare(&self, cfg: &Config, now: SystemTime) -> Result<Built, String> {
        build(cfg, self.serving, now, false)
    }

    /// Serve what `built` holds from the next connection on, and check
    /// clients' certificates as it says from the next request on.
    pub fn install(&self, built: Built) {
        let pairs = [(&self.mcp, built.mcp), (&self.admin, built.admin)];
        for (slot, served) in pairs {
            if let (Some(slot), Some(served)) = (slot, served) {
                slot.store(served);
            }
        }
        *self.renew_at.lock().unwrap_or_else(PoisonError::into_inner) = built.renew_at;
    }

    /// Whether the self-signed certificate is due to be issued again.
    pub fn renewal_due(&self, now: SystemTime) -> bool {
        let renew_at = *self.renew_at.lock().unwrap_or_else(PoisonError::into_inner);
        renew_at.is_some_and(|at| now >= at)
    }
}

/// A TLS listener for `axum::serve`. TCP connections are accepted on a task
/// of its own; each handshake runs on a task of its own, and those that
/// finish in time are handed on through [`accept`](axum::serve::Listener::accept).
/// The configuration is loaded from its slot at each connection.
pub struct TlsListener {
    local: SocketAddr,
    handshaken: mpsc::Receiver<(TlsConnection, SocketAddr)>,
    accepting: tokio::task::JoinHandle<()>,
}

/// A connection a [`TlsListener`] accepted: its stream, and the certificate
/// the client presented at the handshake, on a listener that asked for one.
pub struct TlsConnection {
    stream: TlsStream<TcpStream>,
    presented: Option<Arc<Presented>>,
}

impl TlsConnection {
    /// The certificate the client presented, if the listener asked for one
    /// and it presented one.
    pub fn presented(&self) -> Option<&Arc<Presented>> {
        self.presented.as_ref()
    }
}

impl AsyncRead for TlsConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

impl TlsListener {
    /// Serve TLS on `tcp`, as `tls` says at each connection, with
    /// [`HANDSHAKE_TIMEOUT`] for each handshake.
    pub fn new(tcp: TcpListener, tls: TlsSlot) -> std::io::Result<TlsListener> {
        Self::with_handshake_timeout(tcp, tls, HANDSHAKE_TIMEOUT)
    }

    /// As [`new`](Self::new), with `timeout` for each handshake.
    pub fn with_handshake_timeout(
        tcp: TcpListener,
        tls: TlsSlot,
        timeout: Duration,
    ) -> std::io::Result<TlsListener> {
        let local = tcp.local_addr()?;
        let (done, handshaken) = mpsc::channel(32);
        let accepting = tokio::spawn(accept(tcp, tls, timeout, done));
        Ok(TlsListener {
            local,
            handshaken,
            accepting,
        })
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsConnection;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.handshaken.recv().await {
            Some(connection) => connection,
            // The accepting task is gone, and nothing more will come.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local)
    }
}

/// Accept connections on `tcp` until dropped, each handshake on a task of
/// its own. One that fails, or does not finish within `timeout`, is closed
/// and forgotten: a port scan, a health check that only connects, a client
/// that does not trust the certificate. One that fails on the certificate
/// the client presented is logged, with why.
async fn accept(
    tcp: TcpListener,
    tls: TlsSlot,
    timeout: Duration,
    done: mpsc::Sender<(TlsConnection, SocketAddr)>,
) {
    loop {
        let (stream, peer) = match tcp.accept().await {
            Ok(connection) => connection,
            Err(e) if is_connection_error(&e) => continue,
            // Out of file descriptors, say: wait for some to close, as
            // `axum::serve` does.
            Err(e) => {
                eprintln!("mcpdef: accepting a TLS connection: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        // Loaded here: what a reload stored serves every connection after it.
        let served = tls.load_full();
        // A listener that serves TLS has a configuration for as long as it
        // runs: only a restart turns its TLS off.
        let Some(config) = served.config.clone() else {
            continue;
        };
        let acceptor = TlsAcceptor::from(config);
        let done = done.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(timeout, acceptor.accept(stream)).await {
                Ok(Ok(stream)) => {
                    let presented = served.clients.as_ref().and_then(|clients| {
                        clients.presented(stream.get_ref().1.peer_certificates())
                    });
                    let _ = done.send((TlsConnection { stream, presented }, peer)).await;
                }
                Ok(Err(e)) => {
                    if let Some(why) = refused_certificate(&e) {
                        eprintln!("mcpdef: refused the client certificate {peer} presented: {why}");
                    }
                }
                Err(_) => {}
            }
        });
    }
}

/// Why the handshake that failed with `e` refused the certificate the client
/// presented, if that is why it failed.
fn refused_certificate(e: &std::io::Error) -> Option<String> {
    match e.get_ref()?.downcast_ref::<rustls::Error>()? {
        refused @ rustls::Error::InvalidCertificate(_) => Some(refused.to_string()),
        _ => None,
    }
}

fn is_connection_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{ConnectionAborted, ConnectionRefused, ConnectionReset};
    matches!(
        e.kind(),
        ConnectionRefused | ConnectionAborted | ConnectionReset
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listener_binds_one_host_or_every_one() {
        assert_eq!(listen_host("127.0.0.1:7878").as_deref(), Some("127.0.0.1"));
        assert_eq!(listen_host("[::1]:7878").as_deref(), Some("::1"));
        assert_eq!(listen_host("10.1.2.3:443").as_deref(), Some("10.1.2.3"));
        assert_eq!(
            listen_host("mcpdef.internal:443").as_deref(),
            Some("mcpdef.internal")
        );
        assert_eq!(listen_host("0.0.0.0:7878"), None);
        assert_eq!(listen_host("[::]:7878"), None);
        assert_eq!(listen_host("7878"), None);
    }

    #[test]
    fn a_listener_serves_tls_when_it_serves_and_its_table_says_so() {
        let cfg = |text: &str| Config::parse(text).unwrap();
        let on = cfg(
            "[gateway]\n[gateway.tls]\nmode = \"self-signed\"\n[gateway.admin]\nenabled = true\n",
        );
        assert_eq!(
            Serving::of(&on, true),
            Serving {
                mcp: true,
                admin: true
            }
        );
        // Over stdio the MCP listener serves nothing; the admin one still does.
        assert_eq!(
            Serving::of(&on, false),
            Serving {
                mcp: false,
                admin: true
            }
        );
        let own_off = cfg(
            "[gateway]\n[gateway.tls]\nmode = \"self-signed\"\n[gateway.admin]\nenabled = true\n\
             [gateway.admin.tls]\nmode = \"off\"\n",
        );
        assert_eq!(
            Serving::of(&own_off, true),
            Serving {
                mcp: true,
                admin: false
            }
        );
        let own_on = cfg(
            "[gateway]\n[gateway.admin]\nenabled = true\n[gateway.admin.tls]\nmode = \"self-signed\"\n",
        );
        assert_eq!(
            Serving::of(&own_on, true),
            Serving {
                mcp: false,
                admin: true
            }
        );
        let disabled = cfg("[gateway]\n[gateway.tls]\nmode = \"self-signed\"\n");
        assert_eq!(
            Serving::of(&disabled, true),
            Serving {
                mcp: true,
                admin: false
            }
        );
    }

    #[test]
    fn a_listener_on_files_adds_no_name_to_the_self_signed_certificate() {
        use rustls::pki_types::pem::PemObject;
        let dir = tempfile::tempdir().unwrap();
        let pki = mcpdef_testkit::Pki::new("mcpdef test CA");
        let (cert, key) = pki.server(&["10.9.9.9"]).write(dir.path(), "admin");
        let state = dir.path().join("state");
        let cfg = Config::parse(&format!(
            "[gateway]\nlisten = \"127.0.0.1:7878\"\nstate_dir = {state:?}\n\
             [gateway.tls]\nmode = \"self-signed\"\n\
             [gateway.admin]\nenabled = true\nlisten = \"10.9.9.9:7879\"\n\
             [gateway.admin.tls]\nmode = \"files\"\ncert = {cert:?}\nkey = {{ file = {key:?} }}\n",
        ))
        .unwrap();
        let serving = Serving::of(&cfg, true);
        assert_eq!(
            serving,
            Serving {
                mcp: true,
                admin: true
            }
        );
        let built = build(&cfg, serving, SystemTime::now(), true).unwrap();
        assert!(built.mcp.is_some() && built.admin.is_some());
        // The admin listener's address is its files' business.
        let issued =
            rustls::pki_types::CertificateDer::from_pem_file(Paths::under(&state).cert()).unwrap();
        assert_eq!(
            mcpdef_transport::CertificateNames::read(&issued).alt_names,
            ["DNS:localhost", "IP:127.0.0.1", "IP:::1"]
        );
    }

    #[test]
    fn the_self_signed_names_are_those_of_the_listeners_that_serve_it() {
        let cfg = Config::parse(
            "[gateway]\nlisten = \"10.1.2.3:443\"\n\
             [gateway.tls]\nmode = \"self-signed\"\nhostnames = [\"mcpdef.internal\"]\n\
             [gateway.admin]\nenabled = true\nlisten = \"192.168.1.5:7879\"\n",
        )
        .unwrap();
        assert_eq!(
            self_signed_names(&cfg, true, true).to_string(),
            "localhost, 127.0.0.1, ::1, 10.1.2.3, mcpdef.internal, 192.168.1.5"
        );
        assert_eq!(
            self_signed_names(&cfg, false, true).to_string(),
            "localhost, 127.0.0.1, ::1, 192.168.1.5, mcpdef.internal"
        );
        assert_eq!(
            self_signed_names(&cfg, false, false).to_string(),
            "localhost, 127.0.0.1, ::1"
        );
    }
}
