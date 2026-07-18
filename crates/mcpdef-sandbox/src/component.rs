// SPDX-License-Identifier: Apache-2.0
//! The **component-model** sandbox path: run an untrusted MCP server that is a
//! `wasm32-wasip2` **component** exporting the [`mcpdef:server`](../wit/server.wit)
//! world, under a **capability-scoped WASI**. This is the richer sibling of
//! [`WasmUpstream`](crate::WasmUpstream) (the no-WASI core-module path):
//!
//! * The guest is a real component — it speaks MCP over a typed
//!   `handle(string) -> string` interface (no hand-rolled `alloc`/memory ABI), so
//!   it can be written in any language that targets `wasm32-wasip2`.
//! * It runs against a [`wasmtime_wasi`] context that grants **nothing by default**
//!   — no preopened directories (no filesystem), no inherited stdio. The one host
//!   capability it can be given is **outbound TCP**, and that is gated by a
//!   **per-destination egress allowlist** ([`EgressAllow`]): a connection is
//!   permitted only if its resolved address is explicitly listed *and* passes the
//!   same IP classification as the HTTP egress guard (cloud-metadata / link-local /
//!   special-use are always blocked). Default is **deny-all** — the guest gets no
//!   network unless the operator opts specific destinations in.
//! * The same fuel (CPU), memory, and optional epoch wall-clock bounds as the
//!   core-module path apply.
//!
//! The engine runs in **async** mode so the guest's WASI calls (including outbound
//! sockets) integrate with the gateway's Tokio runtime without blocking a worker
//! thread; instantiation and each `handle` call are therefore `async`.

use async_trait::async_trait;
use mcpdef_core::Message;
use mcpdef_transport::{check_socket_ip, EgressPolicy, Transport, TransportError};
use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::{deadline_ticks, sandbox_err, EpochTicker, SandboxLimits};

// Host bindings for the `mcpdef:server` world (generated from wit/server.wit at the
// crate root). Gives `Server::instantiate_async` + `…handler().call_handle(..)`.
wasmtime::component::bindgen!({
    world: "server",
    path: "wit",
    // wasmtime 36 replaced the `async: true` shorthand with per-function config;
    // the guest's exported `handle` is driven async so it composes with the Tokio
    // runtime (WASI socket imports are added async via p2::add_to_linker_async).
    exports: { default: async },
});

/// A per-destination **egress allowlist** for a sandboxed component's outbound
/// sockets. Default is **deny-all**: a connection is permitted only if its
/// resolved `SocketAddr` is in `allowed` **and** the IP passes [`check_socket_ip`]
/// (so a mis-listed metadata/special-use address is still blocked).
#[derive(Clone)]
pub struct EgressAllow {
    allowed: Arc<HashSet<SocketAddr>>,
    policy: EgressPolicy,
}

impl EgressAllow {
    /// Grant outbound TCP to exactly `allowed`, classified under `policy`.
    pub fn new(allowed: impl IntoIterator<Item = SocketAddr>, policy: EgressPolicy) -> Self {
        EgressAllow {
            allowed: Arc::new(allowed.into_iter().collect()),
            policy,
        }
    }

    /// Deny all outbound network access (the default for a sandboxed module).
    pub fn deny_all() -> Self {
        EgressAllow::new(std::iter::empty(), EgressPolicy::default())
    }

    /// True if a socket to `addr` is permitted: explicitly allowlisted *and* not in
    /// an always-blocked IP class.
    fn permits(&self, addr: &SocketAddr) -> bool {
        self.allowed.contains(addr) && check_socket_ip(addr.ip(), &self.policy).is_ok()
    }
}

/// Per-`Store` host state for the component path: the WASI context + resource
/// table, plus the memory limiter.
struct CompState {
    table: ResourceTable,
    wasi: WasiCtx,
    limits: StoreLimits,
}

impl WasiView for CompState {
    // wasmtime 36 collapsed the split `table()` + `ctx()` accessors into a single
    // `ctx()` returning a `WasiCtxView` that bundles both.
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

/// An MCP upstream that is a `wasm32-wasip2` **component** run under Wasmtime with
/// capability-scoped WASI, fuel/memory/epoch caps, and an egress allowlist.
/// Implements [`Transport`] with the same request/response model as
/// [`WasmUpstream`](crate::WasmUpstream): each [`send`](Transport::send) runs the
/// component's `handle` and queues the response for [`recv`](Transport::recv).
pub struct WasmComponentUpstream {
    store: Store<CompState>,
    bindings: Server,
    limits: SandboxLimits,
    inbox: VecDeque<Message>,
    _ticker: Option<EpochTicker>,
}

impl WasmComponentUpstream {
    /// Load and instantiate a component from `path` with the given limits and
    /// egress allowlist.
    pub async fn from_file(
        path: impl AsRef<Path>,
        limits: SandboxLimits,
        egress: EgressAllow,
    ) -> Result<Self, TransportError> {
        let bytes = std::fs::read(path.as_ref()).map_err(TransportError::Io)?;
        Self::from_bytes(&bytes, limits, egress).await
    }

    /// Instantiate a component from its component **binary** bytes.
    pub async fn from_bytes(
        wasm: &[u8],
        limits: SandboxLimits,
        egress: EgressAllow,
    ) -> Result<Self, TransportError> {
        let mut config = Config::new();
        config.async_support(true);
        config.consume_fuel(true);
        if limits.deadline.is_some() {
            config.epoch_interruption(true);
        }
        let engine = Engine::new(&config).map_err(sandbox_err)?;
        let component = Component::new(&engine, wasm).map_err(|e| {
            TransportError::Sandbox(format!(
                "loading wasm component (must be a `wasm32-wasip2` component, not a core module): {e}"
            ))
        })?;

        let mut linker: Linker<CompState> = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_async(&mut linker).map_err(sandbox_err)?;

        // Capability-scoped WASI: no preopened dirs (no filesystem), no inherited
        // stdio. Outbound TCP is allowed at the API level but every connection is
        // gated by the egress allowlist; UDP and DNS name lookup stay off (the
        // allowlist is by resolved IP — no rebinding surface).
        let mut builder = WasiCtxBuilder::new();
        builder
            .allow_tcp(true)
            .allow_udp(false)
            .allow_ip_name_lookup(false)
            .socket_addr_check(move |addr, _use| {
                let egress = egress.clone();
                Box::pin(async move { egress.permits(&addr) })
            });
        let wasi = builder.build();

        let store_limits = StoreLimitsBuilder::new()
            .memory_size(limits.max_memory_bytes)
            .build();
        let mut store = Store::new(
            &engine,
            CompState {
                table: ResourceTable::new(),
                wasi,
                limits: store_limits,
            },
        );
        store.limiter(|s| &mut s.limits);
        store.set_fuel(limits.fuel_per_call).map_err(sandbox_err)?;
        if limits.deadline.is_some() {
            // A finite deadline for the (rare) instantiation work; re-armed per call.
            store.set_epoch_deadline(u64::MAX);
        }

        let bindings = Server::instantiate_async(&mut store, &component, &linker)
            .await
            .map_err(|e| {
                TransportError::Sandbox(format!("instantiating `mcpdef:server` component: {e}"))
            })?;

        let ticker = limits.deadline.map(|_| EpochTicker::spawn(&engine));

        Ok(WasmComponentUpstream {
            store,
            bindings,
            limits,
            inbox: VecDeque::new(),
            _ticker: ticker,
        })
    }

    /// Run the component's `handle` over one request line, returning the response
    /// line (empty = the component produced no response, e.g. a notification).
    async fn run(&mut self, request: &str) -> Result<String, TransportError> {
        // Fresh per-call CPU + wall-clock budget.
        self.store
            .set_fuel(self.limits.fuel_per_call)
            .map_err(sandbox_err)?;
        if let Some(d) = self.limits.deadline {
            self.store.set_epoch_deadline(deadline_ticks(d));
        }
        self.bindings
            .mcpdef_server_handler()
            .call_handle(&mut self.store, request)
            .await
            .map_err(sandbox_err)
    }
}

#[async_trait]
impl Transport for WasmComponentUpstream {
    async fn send(&mut self, msg: Message) -> Result<(), TransportError> {
        let line = msg.to_json_line();
        let out = self.run(&line).await?;
        let out = out.trim();
        if out.is_empty() {
            return Ok(()); // notification / no response
        }
        let resp =
            Message::from_json_line(out).map_err(|e| TransportError::Decode(e.to_string()))?;
        self.inbox.push_back(resp);
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<Message>, TransportError> {
        Ok(self.inbox.pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpdef_core::{method, Id};

    /// The committed `wasm32-wasip2` component fixture (built from
    /// tests/fixtures/echo-component; see that crate's Cargo.toml to rebuild).
    fn fixture() -> Vec<u8> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/echo_component.wasm"
        ))
        .expect("the committed echo_component.wasm fixture must exist")
    }

    fn req(id: i64, method: &str, params: Option<serde_json::Value>) -> Message {
        Message::request(Id::Num(id), method, params)
    }

    async fn roundtrip(up: &mut WasmComponentUpstream, m: Message) -> Message {
        up.send(m).await.unwrap();
        up.recv().await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn component_speaks_the_mcp_lifecycle() {
        let mut up = WasmComponentUpstream::from_bytes(
            &fixture(),
            SandboxLimits::default(),
            EgressAllow::deny_all(),
        )
        .await
        .unwrap();

        let init = roundtrip(&mut up, req(0, method::INITIALIZE, None)).await;
        assert_eq!(
            init.result.unwrap()["serverInfo"]["name"],
            serde_json::json!("echo-component")
        );

        // The notification produces no response.
        up.send(Message::notification(method::INITIALIZED, None))
            .await
            .unwrap();
        assert!(up.recv().await.unwrap().is_none());

        let list = roundtrip(&mut up, req(1, method::TOOLS_LIST, None)).await;
        let names: Vec<String> = list.result.unwrap()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str().map(String::from))
            .collect();
        assert!(names.contains(&"echo".to_string()));

        let call = roundtrip(
            &mut up,
            req(
                2,
                method::TOOLS_CALL,
                Some(serde_json::json!({ "name": "echo", "arguments": { "x": 1 } })),
            ),
        )
        .await;
        assert_eq!(call.id, Some(Id::Num(2)));
        assert_eq!(call.result.unwrap()["isError"], serde_json::json!(false));
    }

    /// Drive a `fetch` tools/call (which makes the guest attempt a TCP connect to
    /// `addr`) and return the tool's text result.
    async fn fetch(up: &mut WasmComponentUpstream, addr: &str) -> String {
        let call = roundtrip(
            up,
            req(
                7,
                method::TOOLS_CALL,
                Some(serde_json::json!({ "name": "fetch", "arguments": { "addr": addr } })),
            ),
        )
        .await;
        call.result.unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn egress_denied_by_default() {
        let mut up = WasmComponentUpstream::from_bytes(
            &fixture(),
            SandboxLimits::default(),
            EgressAllow::deny_all(),
        )
        .await
        .unwrap();
        // Nothing is allowlisted → the guest's connect is refused at the host gate.
        let text = fetch(&mut up, "10.0.0.1:80").await;
        assert!(
            text.starts_with("egress-error:"),
            "deny-all must block the connect, got: {text}"
        );
    }

    #[tokio::test]
    async fn egress_allows_a_listed_destination() {
        // A real loopback listener the guest is allowed to reach.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let egress = EgressAllow::new([addr], EgressPolicy::default());
        let mut up =
            WasmComponentUpstream::from_bytes(&fixture(), SandboxLimits::default(), egress)
                .await
                .unwrap();
        let text = fetch(&mut up, &addr.to_string()).await;
        assert_eq!(text, "connected", "an allowlisted destination must connect");
    }

    #[tokio::test]
    async fn metadata_is_blocked_even_when_listed() {
        // Operator mis-lists the cloud-metadata address: the IP classification
        // safety net must still block it (it's never a valid egress target).
        let meta: SocketAddr = "169.254.169.254:80".parse().unwrap();
        let egress = EgressAllow::new([meta], EgressPolicy::default());
        let mut up =
            WasmComponentUpstream::from_bytes(&fixture(), SandboxLimits::default(), egress)
                .await
                .unwrap();
        let text = fetch(&mut up, "169.254.169.254:80").await;
        assert!(
            text.starts_with("egress-error:"),
            "metadata must be blocked even if allowlisted, got: {text}"
        );
    }

    #[tokio::test]
    async fn a_core_module_is_rejected_by_the_component_path() {
        // A plain core module (not a component) must fail to load here.
        let core = wat::parse_str("(module)").unwrap();
        let res = WasmComponentUpstream::from_bytes(
            &core,
            SandboxLimits::default(),
            EgressAllow::deny_all(),
        )
        .await;
        assert!(matches!(res, Err(TransportError::Sandbox(_))));
    }
}
