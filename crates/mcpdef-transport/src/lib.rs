// SPDX-License-Identifier: Apache-2.0
//! `mcpdef-transport` — the [`Transport`] seam every MCPdef peer speaks, plus the
//! Phase-1 implementations: a stdio child-process transport ([`StdioChild`]) and
//! an in-memory [`Duplex`] pair for tests/mocks.
//!
//! The trait is intentionally minimal (`send` / `recv` of a normalized
//! [`Message`]) so the later transports from the ROADMAP — Streamable HTTP
//! (Phase 1) and the legacy HTTP+SSE bridge (Phase 1.5) — slot in behind it
//! without re-plumbing the gateway.
//!
//! [`UpstreamHandle`] shares one upstream transport between many concurrent
//! calls.

use async_trait::async_trait;
use mcpdef_core::wire::{error_code, SPEC_2026_07_28};
use mcpdef_core::{method, Message};
use mcpdef_secrets::{ExposeSecret, SecretString};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{ChildStdin, ChildStdout};

mod auth;
mod cert;
mod egress;
mod http;
mod mux;
mod oauth;
mod pin;
mod tls;
pub use self::auth::{read_secret, Credential, StaticAuth};
pub use self::cert::{
    certificate_serial, rfc3339, CertificateNames, PeerCertificate, TlsWatch, Verification,
};
pub use self::egress::{check_connect_to, check_socket_ip, EgressPolicy};
pub use self::http::{
    fetch_dated, fetch_text, get_bearer, post_form, Dated, HttpClient, HttpKind, ParamHeaders,
    Replied, RequestAuth,
};
pub use self::mux::{CallError, DownWatch, HandleOptions, UpstreamHandle, DEFAULT_MAX_INFLIGHT};
pub use self::oauth::{ClientAuth, ClientCredentials, TokenAuth};
pub use self::pin::{presented_certificate, Pin, PresentedCertificate};
pub use self::tls::{
    install_crypto_provider, read_client_trust, read_served, ClientTrust, IdentityFiles,
    MinVersion, Roots, TlsProfile, TlsSettings,
};

/// What MCPdef answers a request its upstream sends it, or `None` for any
/// other message.
///
/// A 2025-11-25 server asks its client for things with requests of its own
/// (`elicitation/create`, `sampling/createMessage`, `roots/list`) and waits
/// for the answer. MCPdef does not pass them on to its clients, so it answers
/// each at once with `-32601`, saying so. Left unanswered, the server would
/// hold the call it was making until `upstream_timeout_ms`, or for good. A
/// `ping` it answers itself. A 2026-07-28 server asks in its result instead,
/// and that is passed on.
pub(crate) fn answer_request(request: &Message) -> Option<Message> {
    if !request.is_request() {
        return None;
    }
    let id = request.id.clone()?;
    let method = request.method()?;
    Some(if method == method::PING {
        Message::result(id, serde_json::json!({}))
    } else {
        Message::error(
            id,
            error_code::METHOD_NOT_FOUND,
            format!(
                "MCPdef does not relay `{method}` to its clients: through it, a server asks \
                 for input in its result, on the {SPEC_2026_07_28} wire"
            ),
        )
    })
}

/// Tell the operator that `upstream` asked its client for something MCPdef
/// refused ([`answer_request`]). A `ping` goes unsaid.
pub(crate) fn note_refused(upstream: &str, request: &Message) {
    if let Some(method) = request.method().filter(|m| *m != method::PING) {
        eprintln!(
            "mcpdef: upstream '{upstream}' asked its client for `{method}`, which MCPdef \
             does not relay; it was refused"
        );
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("decode: {0}")]
    Decode(String),
    #[error("http: {0}")]
    Http(String),
    #[error("egress blocked: {0}")]
    Egress(String),
    /// A TLS profile's file is missing, unreadable, or holds the wrong thing.
    #[error("tls: {0}")]
    Tls(String),
    #[error("sandbox: {0}")]
    Sandbox(String),
    #[error("spawn '{cmd}': {source}")]
    Spawn {
        cmd: String,
        #[source]
        source: std::io::Error,
    },
    #[error("transport closed")]
    Closed,
    /// A Streamable-HTTP upstream answered `404` to a request carrying its
    /// `Mcp-Session-Id`: it has ended that session, and only a new
    /// `initialize` starts another.
    #[error("the upstream ended its session (HTTP 404 for its Mcp-Session-Id)")]
    SessionExpired,
    /// The URL answered `401 Unauthorized`: the upstream refused the
    /// credentials the request carried, read again once, or wants some it was
    /// not sent.
    #[error("{0} answered 401 Unauthorized")]
    Unauthorized(String),
    /// A credential for the upstream could not be read, or could not go in a
    /// header. The message says where it comes from, never what it is.
    #[error("credentials: {0}")]
    Credentials(String),
}

/// Run `f` on tokio's blocking pool and wait for it, off the async workers:
/// for reading a secret, which can take a command seconds. A panic in `f`
/// resumes here. If the runtime shuts down first, this never returns.
pub(crate) async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    match tokio::task::spawn_blocking(f).await {
        Ok(done) => done,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        // The runtime is shutting down.
        Err(_) => std::future::pending().await,
    }
}

/// A bidirectional stream of normalized JSON-RPC messages to/from one peer — a
/// downstream client or an upstream server.
#[async_trait]
pub trait Transport: Send {
    /// Send one message to the peer.
    async fn send(&mut self, msg: Message) -> Result<(), TransportError>;

    /// Receive the next message, or `Ok(None)` at a clean end-of-stream.
    ///
    /// Must be cancel-safe: dropping the future before it completes must lose no
    /// message. [`UpstreamHandle`]'s actor races it against new requests and
    /// drops it whenever a request wins.
    async fn recv(&mut self) -> Result<Option<Message>, TransportError>;

    /// Release the peer (kill a child, drop a socket). Best-effort.
    async fn close(&mut self) -> Result<(), TransportError> {
        Ok(())
    }

    /// Whether each reply is produced by the [`send`](Transport::send) that
    /// carries its request, rather than arriving on its own.
    ///
    /// When `true`, `send` runs the request to completion and queues what it
    /// produced, and [`recv`](Transport::recv) only drains that queue: `Ok(None)`
    /// means nothing is queued, not that the peer has gone. The in-process
    /// sandboxes work this way. [`UpstreamHandle`] needs to know, to tell an
    /// empty queue from a closed connection.
    fn replies_inline(&self) -> bool {
        false
    }

    /// The side of this transport that takes concurrent requests, if it has one.
    ///
    /// [`UpstreamHandle::spawn`] asks once the transport is open. If one comes
    /// back, every call goes straight to it from its caller's task, and the rest
    /// of the transport is dropped. Otherwise a task of the handle's own shares
    /// the transport between calls. A Streamable-HTTP endpoint has such a side;
    /// a pipe or a single stream does not.
    fn concurrent(&self) -> Option<Arc<dyn Exchange>> {
        None
    }

    /// What this transport's TLS connections show, if it makes any: how its
    /// server is verified, and the certificate it presented last. An HTTPS
    /// upstream has them; stdio, a sandbox and plain HTTP do not.
    ///
    /// The watch goes on being kept after this returns, by the transport and
    /// by the side [`concurrent`](Transport::concurrent) hands out, so one
    /// taken when the transport opens follows it for as long as it runs.
    fn tls(&self) -> Option<TlsWatch> {
        None
    }

    /// The credentials it adds to what it sends upstream, if it adds any: an
    /// HTTP upstream's `[server.auth]`. Shared with the transport, so one taken
    /// when it opens says what it sends for as long as it runs.
    fn auth(&self) -> Option<Arc<dyn RequestAuth>> {
        None
    }

    /// Where it learns what each `tools/call` mirrors into `Mcp-Param-{Name}`
    /// headers, if it sends any: a Streamable-HTTP upstream's. Shared with the
    /// transport, so one taken when it opens is the one it sends by for as
    /// long as it runs, through the side [`concurrent`](Transport::concurrent)
    /// hands out too. stdio and a sandbox have no headers to put them in.
    fn param_headers(&self) -> Option<ParamHeaders> {
        None
    }
}

/// A peer that answers many requests at once, each on its own: a
/// Streamable-HTTP endpoint, where every POST carries one request and its
/// response carries that request's answer.
#[async_trait]
pub trait Exchange: Send + Sync {
    /// Send one request, and return what came back for it, in order: its reply,
    /// and any notifications the peer sent along the way.
    ///
    /// A request the peer sends along the way is answered here, as
    /// [`answer_request`] says, while the peer waits for the answer, and is
    /// returned with the rest.
    ///
    /// Must be cancel-safe: a caller that times out drops the future, and any
    /// other call in flight must be unaffected.
    async fn exchange(&self, request: &Message) -> Result<Vec<Message>, TransportError>;
}

/// An upstream MCP server spoken to over stdio: newline-delimited UTF-8 JSON-RPC
/// on the child's stdin/stdout, with stderr inherited for the child's own logs
/// (per the MCP stdio transport).
///
/// A send keeps reading while it writes. A child that handles one line at a
/// time stops reading its stdin while it writes a reply, until that reply is
/// read; a send that only wrote would then wait for the child while the child
/// waited for it, once both pipes filled. The lines read meanwhile are kept, in
/// order, for [`recv`](Transport::recv).
pub struct StdioChild {
    child: tokio::process::Child,
    stdin: ChildStdin,
    stdout: Lines<BufReader<ChildStdout>>,
    /// What sends read from stdout while writing, in order: lines, and the end
    /// of the stream or an error if one came.
    ahead: VecDeque<std::io::Result<Option<String>>>,
}

/// How many lines a send reads ahead while it waits to write. Past this it only
/// writes, so a child that floods stdout without reading stdin cannot grow the
/// buffer without bound.
const READ_AHEAD: usize = 1024;

impl StdioChild {
    /// Spawn `command[0]` with `command[1..]` as args, piping stdin/stdout.
    pub fn spawn(command: &[String]) -> Result<Self, TransportError> {
        Self::spawn_with_env(command, &[])
    }

    /// Spawn the child with extra environment variables — the OSS token-broker
    /// path: MCPdef injects an upstream's brokered credentials into its process
    /// environment (the spec's mechanism for stdio servers), so the server never
    /// holds long-lived creds in its own config and the client's token is never
    /// passed through.
    pub fn spawn_with_env(
        command: &[String],
        env: &[(String, String)],
    ) -> Result<Self, TransportError> {
        let env = env
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()));
        Self::spawn_from(command, env, &[])
    }

    /// Spawn the child with `env`, whose values are secrets, and none of
    /// `withheld` passes from MCPdef's own environment to the child's: the
    /// variables MCPdef reads secrets from. One that `env` sets is set all the
    /// same. The values are exposed to the child's environment alone, though
    /// the standard library keeps a copy of each until the spawn returns.
    pub fn spawn_withholding(
        command: &[String],
        env: &[(String, SecretString)],
        withheld: &[String],
    ) -> Result<Self, TransportError> {
        let env = env
            .iter()
            .map(|(name, value)| (name.as_str(), value.expose_secret()));
        Self::spawn_from(command, env, withheld)
    }

    fn spawn_from<'a>(
        command: &[String],
        env: impl Iterator<Item = (&'a str, &'a str)>,
        withheld: &[String],
    ) -> Result<Self, TransportError> {
        let prog = command
            .first()
            .ok_or_else(|| TransportError::Decode("empty stdio command".into()))?;
        let mut cmd = tokio::process::Command::new(prog);
        for name in withheld {
            cmd.env_remove(name);
        }
        cmd.args(&command[1..])
            .envs(env)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|source| TransportError::Spawn {
            cmd: prog.clone(),
            source,
        })?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        Ok(StdioChild {
            child,
            stdin,
            stdout: BufReader::new(stdout).lines(),
            ahead: VecDeque::new(),
        })
    }
}

#[async_trait]
impl Transport for StdioChild {
    async fn send(&mut self, msg: Message) -> Result<(), TransportError> {
        let mut line = msg.to_json_line();
        line.push('\n');
        let StdioChild {
            stdin,
            stdout,
            ahead,
            ..
        } = self;
        let write = async {
            stdin.write_all(line.as_bytes()).await?;
            stdin.flush().await
        };
        tokio::pin!(write);
        loop {
            let ended = matches!(ahead.back(), Some(Ok(None) | Err(_)));
            let reading = !ended && ahead.len() < READ_AHEAD;
            tokio::select! {
                biased;
                written = &mut write => return Ok(written?),
                read = stdout.next_line(), if reading => ahead.push_back(read),
            }
        }
    }

    async fn recv(&mut self) -> Result<Option<Message>, TransportError> {
        // Skip blank keep-alive lines; a None means the child closed stdout.
        loop {
            let next = match self.ahead.pop_front() {
                Some(read) => read,
                None => self.stdout.next_line().await,
            };
            match next? {
                Some(line) if line.trim().is_empty() => continue,
                Some(line) => {
                    return Message::from_json_line(&line)
                        .map(Some)
                        .map_err(|e| TransportError::Decode(e.to_string()));
                }
                None => return Ok(None),
            }
        }
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        let _ = self.child.start_kill();
        Ok(())
    }
}

/// One end of an in-memory, unbounded, bidirectional channel — used to mock a
/// peer in tests without spawning a process or opening a socket.
pub struct Duplex {
    tx: tokio::sync::mpsc::UnboundedSender<Message>,
    rx: tokio::sync::mpsc::UnboundedReceiver<Message>,
}

/// Create two connected [`Duplex`] ends. A message `send`-ed on one is `recv`-ed
/// on the other.
pub fn duplex_pair() -> (Duplex, Duplex) {
    let (a_tx, a_rx) = tokio::sync::mpsc::unbounded_channel();
    let (b_tx, b_rx) = tokio::sync::mpsc::unbounded_channel();
    (Duplex { tx: a_tx, rx: b_rx }, Duplex { tx: b_tx, rx: a_rx })
}

#[async_trait]
impl Transport for Duplex {
    async fn send(&mut self, msg: Message) -> Result<(), TransportError> {
        self.tx.send(msg).map_err(|_| TransportError::Closed)
    }

    async fn recv(&mut self) -> Result<Option<Message>, TransportError> {
        // None once every sender on the far end has dropped.
        Ok(self.rx.recv().await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpdef_core::Id;

    #[tokio::test]
    async fn duplex_carries_messages_both_ways() {
        let (mut a, mut b) = duplex_pair();
        a.send(Message::request(Id::Num(1), "ping", None))
            .await
            .unwrap();
        let got = b.recv().await.unwrap().unwrap();
        assert_eq!(got.method(), Some("ping"));

        b.send(Message::result(Id::Num(1), serde_json::json!({})))
            .await
            .unwrap();
        let resp = a.recv().await.unwrap().unwrap();
        assert!(resp.is_response());
    }

    #[tokio::test]
    async fn recv_returns_none_when_peer_dropped() {
        let (mut a, b) = duplex_pair();
        drop(b);
        assert!(a.recv().await.unwrap().is_none());
    }
}
