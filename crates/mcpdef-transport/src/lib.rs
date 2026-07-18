// SPDX-License-Identifier: Apache-2.0
//! `mcpdef-transport` — the [`Transport`] seam every MCPdef peer speaks, plus the
//! Phase-1 implementations: a stdio child-process transport ([`StdioChild`]) and
//! an in-memory [`Duplex`] pair for tests/mocks.
//!
//! The trait is intentionally minimal (`send` / `recv` of a normalized
//! [`Message`]) so the later transports from the ROADMAP — Streamable HTTP
//! (Phase 1) and the legacy HTTP+SSE bridge (Phase 1.5) — slot in behind it
//! without re-plumbing the gateway.

use async_trait::async_trait;
use mcpdef_core::Message;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{ChildStdin, ChildStdout};

mod egress;
mod http;
pub use self::egress::{check_socket_ip, EgressPolicy};
pub use self::http::{fetch_text, HttpClient, HttpKind};

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
}

/// A bidirectional stream of normalized JSON-RPC messages to/from one peer — a
/// downstream client or an upstream server.
#[async_trait]
pub trait Transport: Send {
    /// Send one message to the peer.
    async fn send(&mut self, msg: Message) -> Result<(), TransportError>;

    /// Receive the next message, or `Ok(None)` at a clean end-of-stream.
    async fn recv(&mut self) -> Result<Option<Message>, TransportError>;

    /// Release the peer (kill a child, drop a socket). Best-effort.
    async fn close(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

/// An upstream MCP server spoken to over stdio: newline-delimited UTF-8 JSON-RPC
/// on the child's stdin/stdout, with stderr inherited for the child's own logs
/// (per the MCP stdio transport).
pub struct StdioChild {
    child: tokio::process::Child,
    stdin: ChildStdin,
    stdout: Lines<BufReader<ChildStdout>>,
}

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
        let prog = command
            .first()
            .ok_or_else(|| TransportError::Decode("empty stdio command".into()))?;
        let mut cmd = tokio::process::Command::new(prog);
        cmd.args(&command[1..])
            .envs(env.iter().map(|(k, v)| (k, v)))
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
        })
    }
}

#[async_trait]
impl Transport for StdioChild {
    async fn send(&mut self, msg: Message) -> Result<(), TransportError> {
        let line = msg.to_json_line();
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<Message>, TransportError> {
        // Skip blank keep-alive lines; a None means the child closed stdout.
        loop {
            match self.stdout.next_line().await? {
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
