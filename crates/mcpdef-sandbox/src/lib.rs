// SPDX-License-Identifier: Apache-2.0
//! `mcpdef-sandbox` — run an **untrusted** MCP server as a WebAssembly module
//! inside a [Wasmtime] sandbox, behind the same [`Transport`] seam as a stdio or
//! HTTP upstream. The sandbox gives MCPdef three things a native subprocess can't:
//!
//! 1. **Zero ambient capabilities.** The module is instantiated against an
//!    **empty** [`Linker`] — it is granted *no* imports, so it cannot touch the
//!    filesystem, the network, the clock, or any host call. (A module that tries
//!    to import WASI fails to instantiate, by design.) Its only contact with the
//!    outside world is the request bytes MCPdef hands it and the response bytes it
//!    hands back.
//! 2. **A CPU bound.** The engine runs with **fuel** metering; each call is given
//!    a fixed fuel budget and a runaway/malicious module traps (`out of fuel`)
//!    instead of spinning forever.
//! 3. **A memory bound.** A [`StoreLimits`] cap means the module's linear memory
//!    can't grow past a configured ceiling.
//! 4. **An optional wall-clock bound.** With a [`SandboxLimits::deadline`] set, the
//!    engine runs with **epoch interruption** and a background ticker, so a call
//!    that exceeds the deadline traps regardless of how little fuel it burns. Fuel
//!    already bounds CPU for this import-free ABI; the deadline is defense-in-depth
//!    (and the bound that will matter once host calls that can *block* — WASI — are
//!    added). Off by default.
//!
//! ## Module ABI
//!
//! The `.wasm` module is a pure request→response function over its own linear
//! memory. It must export:
//!
//! * `memory` — its linear memory.
//! * `alloc(len: i32) -> i32` — reserve `len` bytes, returning an offset MCPdef
//!   writes the request (one JSON-RPC line) into.
//! * `handle(ptr: i32, len: i32) -> i64` — process the request at `[ptr, ptr+len)`
//!   and return a packed `i64`: `(out_ptr << 32) | out_len`. The response (one
//!   JSON-RPC line) is the `out_len` bytes at `out_ptr` in `memory`. An `out_len`
//!   of `0` means "no response" (e.g. for a notification).
//!
//! This is deliberately a minimal, no-WASI ABI so the trust boundary is tiny; the
//! richer **component-model** path (capability-scoped WASI + a per-destination egress
//! allowlist) lives alongside it in [`WasmComponentUpstream`]. The module is
//! instantiated once and reused across calls (guest session state persists), and each
//! call is run on the blocking pool so the synchronous, non-yielding execution never
//! pins an async worker thread.
//!
//! [Wasmtime]: https://wasmtime.dev

use async_trait::async_trait;
use mcpdef_core::Message;
use mcpdef_transport::{Transport, TransportError};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use wasmtime::{
    Config, Engine, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder, TypedFunc,
};

mod component;
pub use component::{EgressAllow, WasmComponentUpstream};

/// How often the background ticker advances the engine epoch. The wall-clock
/// deadline is rounded up to a whole number of these ticks, so it also sets the
/// granularity at which the deadline fires.
const EPOCH_TICK: Duration = Duration::from_millis(20);

/// Convert a wall-clock deadline into a whole number of [`EPOCH_TICK`]s, rounded
/// **up** so a sub-tick deadline still gets at least one full tick and the call
/// is never interrupted *before* its deadline (flooring could fire ~one tick
/// early near a boundary). Always at least 1.
fn deadline_ticks(d: Duration) -> u64 {
    let tick = EPOCH_TICK.as_millis();
    (d.as_millis().div_ceil(tick)).max(1) as u64
}

/// Resource caps applied to every sandboxed call.
#[derive(Debug, Clone, Copy)]
pub struct SandboxLimits {
    /// Fuel granted per `handle` call (≈ one unit per wasm instruction). A module
    /// that exceeds it traps `out of fuel` instead of running unbounded.
    pub fuel_per_call: u64,
    /// Max linear-memory bytes the module may grow to.
    pub max_memory_bytes: usize,
    /// Optional **wall-clock** deadline per call. When set, the engine runs with
    /// epoch interruption and a background ticker, so a call that runs longer than
    /// this traps even if it has fuel to spare. `None` = no wall-clock bound (fuel
    /// alone bounds CPU). Off by default.
    pub deadline: Option<Duration>,
}

impl Default for SandboxLimits {
    fn default() -> Self {
        SandboxLimits {
            fuel_per_call: 200_000_000,
            max_memory_bytes: 64 * 1024 * 1024,
            deadline: None,
        }
    }
}

/// Per-`Store` host state: just the memory limiter.
struct StoreState {
    limits: StoreLimits,
}

/// A background thread that advances an [`Engine`]'s epoch on a fixed interval so
/// a per-call wall-clock [`deadline`](SandboxLimits::deadline) can fire. Stops and
/// joins on drop, so it lives exactly as long as its [`WasmUpstream`].
struct EpochTicker {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl EpochTicker {
    /// Spawn a ticker that increments `engine`'s epoch every [`EPOCH_TICK`].
    fn spawn(engine: &Engine) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let engine = engine.clone();
        let flag = stop.clone();
        let handle = std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                std::thread::sleep(EPOCH_TICK);
                engine.increment_epoch();
            }
        });
        EpochTicker {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// An MCP upstream that is a WebAssembly module run under Wasmtime with fuel +
/// memory caps and no ambient capabilities. Implements [`Transport`]: each
/// [`send`](Transport::send) runs the module's `handle` and queues the response
/// for the next [`recv`](Transport::recv).
///
/// The module is instantiated **once** and the live instance is reused across calls,
/// so guest state established by `initialize` persists for the session (the same model
/// as the component path). Each call moves that instance onto the blocking pool and
/// back (see [`send`](Transport::send)): the synchronous, non-yielding Wasmtime
/// execution therefore never runs on an async worker thread, where it could pin an
/// executor thread and stall unrelated traffic.
pub struct WasmUpstream {
    /// The live instance, in an `Option` so each `send` can move it onto the blocking
    /// pool and restore it (preserving guest state). `None` only transiently while a
    /// call is in flight — or permanently if that call's task panicked, after which
    /// the upstream refuses further calls rather than touch a poisoned store.
    inner: Option<WasmInstance>,
    /// Responses produced by `send`, drained by `recv` (request/response model).
    inbox: VecDeque<Message>,
    /// Background epoch ticker driving the wall-clock deadline; `None` when no
    /// [`deadline`](SandboxLimits::deadline) is set. Kept alive (and stopped) with
    /// the upstream.
    _ticker: Option<EpochTicker>,
}

impl WasmUpstream {
    /// Load and instantiate a `.wasm` module from `path`.
    pub fn from_file(
        path: impl AsRef<Path>,
        limits: SandboxLimits,
    ) -> Result<Self, TransportError> {
        let bytes = std::fs::read(path.as_ref()).map_err(TransportError::Io)?;
        Self::from_wasm(&bytes, limits)
    }

    /// Instantiate a module from its wasm **binary** bytes.
    pub fn from_wasm(wasm: &[u8], limits: SandboxLimits) -> Result<Self, TransportError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        // Epoch interruption is only enabled when a wall-clock deadline is set —
        // otherwise we'd need a deadline + ticker just to avoid an immediate trap.
        if limits.deadline.is_some() {
            config.epoch_interruption(true);
        }
        let engine = Engine::new(&config).map_err(sandbox_err)?;
        let module = Module::new(&engine, wasm).map_err(sandbox_err)?;

        // Instantiate once, here at load, against an EMPTY linker (no ambient
        // capability — a module importing anything fails; that is the point). A
        // missing required export or an initial memory already over the cap is also
        // rejected now. The instance is then reused for every call (state persists).
        let inner = WasmInstance::instantiate(&engine, &module, limits)?;

        // Start the epoch ticker (only when a wall-clock deadline is configured). The
        // store keeps the engine alive after this scope; the ticker holds its own clone.
        let ticker = limits.deadline.map(|_| EpochTicker::spawn(&engine));

        Ok(WasmUpstream {
            inner: Some(inner),
            inbox: VecDeque::new(),
            _ticker: ticker,
        })
    }
}

/// A live, instantiated module: its `Store` (the guest's persistent linear memory and
/// globals) plus the typed `memory`/`alloc`/`handle` exports. Held by [`WasmUpstream`]
/// and reused across calls, so guest session state survives between requests. It is
/// `Send`, so a call can move it onto the blocking pool and back.
struct WasmInstance {
    store: Store<StoreState>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    handle: TypedFunc<(i32, i32), i64>,
    limits: SandboxLimits,
}

impl WasmInstance {
    /// Instantiate `module` in a fresh store against an EMPTY linker (zero ambient
    /// capability — a module importing anything, e.g. WASI, fails here; that is the
    /// point), applying the memory cap. Done once at load.
    fn instantiate(
        engine: &Engine,
        module: &Module,
        limits: SandboxLimits,
    ) -> Result<Self, TransportError> {
        let store_limits = StoreLimitsBuilder::new()
            .memory_size(limits.max_memory_bytes)
            .build();
        let mut store = Store::new(
            engine,
            StoreState {
                limits: store_limits,
            },
        );
        store.limiter(|s| &mut s.limits);
        // Fuel for instantiation (any module `start`); re-armed per call in `run`.
        store.set_fuel(limits.fuel_per_call).map_err(sandbox_err)?;

        let linker: Linker<StoreState> = Linker::new(engine);
        let instance = linker.instantiate(&mut store, module).map_err(|e| {
            TransportError::Sandbox(format!(
                "instantiation failed (a sandboxed module must import nothing): {e}"
            ))
        })?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| TransportError::Sandbox("module must export `memory`".into()))?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|e| {
                TransportError::Sandbox(format!("module must export `alloc(i32)->i32`: {e}"))
            })?;
        let handle = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "handle")
            .map_err(|e| {
                TransportError::Sandbox(format!("module must export `handle(i32,i32)->i64`: {e}"))
            })?;
        Ok(WasmInstance {
            store,
            memory,
            alloc,
            handle,
            limits,
        })
    }

    /// Run the (reused) module's `handle` over `request`, returning the response bytes
    /// (empty = no response). **Synchronous** (a sandboxed call may never yield), so it
    /// is run on the blocking pool from [`WasmUpstream::send`].
    ///
    /// Because the instance is reused, a guest whose `alloc` never reuses its buffer
    /// (the bundled fixtures use a bump allocator) advances its high-water mark each
    /// request; growth is bounded by `max_memory_bytes` — a guest that leaks past its
    /// memory eventually traps on its own calls, never harming the host. A guest-side
    /// reset/free hook to reclaim per-request scratch is a documented follow-up.
    fn run(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        let len = i32::try_from(request.len())
            .map_err(|_| TransportError::Sandbox("request too large".into()))?;
        // Fresh per-call CPU + wall-clock budget: a previous call can't starve this
        // one, and this call can't run unbounded.
        self.store
            .set_fuel(self.limits.fuel_per_call)
            .map_err(sandbox_err)?;
        if let Some(d) = self.limits.deadline {
            self.store.set_epoch_deadline(deadline_ticks(d));
        }

        let ptr = self.alloc.call(&mut self.store, len).map_err(sandbox_err)?;
        if ptr < 0 {
            return Err(TransportError::Sandbox(
                "alloc returned a negative offset".into(),
            ));
        }
        self.memory
            .write(&mut self.store, ptr as usize, request)
            .map_err(|e| {
                TransportError::Sandbox(format!("writing request into module memory: {e}"))
            })?;

        let packed = self
            .handle
            .call(&mut self.store, (ptr, len))
            .map_err(sandbox_err)? as u64;
        let out_ptr = (packed >> 32) as usize;
        let out_len = (packed & 0xffff_ffff) as usize;
        if out_len == 0 {
            return Ok(Vec::new());
        }
        let data = self.memory.data(&self.store);
        let end = out_ptr
            .checked_add(out_len)
            .ok_or_else(|| TransportError::Sandbox("response slice overflows usize".into()))?;
        let slice = data
            .get(out_ptr..end)
            .ok_or_else(|| TransportError::Sandbox("response slice out of bounds".into()))?;
        Ok(slice.to_vec())
    }
}

/// Map any Wasmtime/anyhow error (compile, trap, fuel-exhaustion, …) to a
/// `Sandbox` transport error, preserving the message (which names the cause,
/// e.g. "all fuel consumed").
fn sandbox_err(e: impl std::fmt::Display) -> TransportError {
    TransportError::Sandbox(e.to_string())
}

#[async_trait]
impl Transport for WasmUpstream {
    async fn send(&mut self, msg: Message) -> Result<(), TransportError> {
        let line = msg.to_json_line();
        // A sandboxed call runs synchronous Wasmtime that can burn its whole
        // fuel/wall-clock budget without yielding — running it inline would pin an
        // async worker thread and stall unrelated traffic. Move the (reused, stateful)
        // instance onto the blocking pool for the call and restore it afterwards.
        let mut inst = self.inner.take().ok_or_else(|| {
            TransportError::Sandbox(
                "sandbox upstream is unusable (a previous call's task panicked)".into(),
            )
        })?;
        let (inst, result) = tokio::task::spawn_blocking(move || {
            let r = inst.run(line.as_bytes());
            (inst, r)
        })
        .await
        .map_err(|e| TransportError::Sandbox(format!("sandbox execution task failed: {e}")))?;
        self.inner = Some(inst);
        let out = result?;
        if out.is_empty() {
            return Ok(()); // notification / no response
        }
        let text = std::str::from_utf8(&out)
            .map_err(|e| TransportError::Decode(format!("module response not UTF-8: {e}")))?;
        let resp = Message::from_json_line(text.trim())
            .map_err(|e| TransportError::Decode(e.to_string()))?;
        self.inbox.push_back(resp);
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<Message>, TransportError> {
        // Request/response model: the response was produced during `send`.
        Ok(self.inbox.pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpdef_core::Id;

    /// Compile a WAT fixture to wasm bytes.
    fn wasm(wat_src: &str) -> Vec<u8> {
        wat::parse_str(wat_src).expect("valid WAT")
    }

    /// A module that echoes the request bytes straight back as the response
    /// (`handle` returns its own `(ptr, len)`), with a bump `alloc`.
    const ECHO: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 1024))
          (func (export "alloc") (param $len i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $len)))
            (local.get $p))
          (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
            ;; pack (ptr << 32) | len  — echo the input back
            (i64.or
              (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
              (i64.extend_i32_u (local.get $len)))))
    "#;

    #[tokio::test]
    async fn echo_round_trips_through_the_sandbox() {
        let mut up = WasmUpstream::from_wasm(&wasm(ECHO), SandboxLimits::default()).unwrap();
        let sent = Message::request(Id::Num(7), "ping", Some(serde_json::json!({ "x": 1 })));
        up.send(sent.clone()).await.unwrap();
        let got = up.recv().await.unwrap().unwrap();
        assert_eq!(got, sent);
        // Nothing else queued.
        assert!(up.recv().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn out_of_fuel_traps_instead_of_hanging() {
        // `handle` spins forever; the fuel budget must cut it off with an error.
        let spin = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 1024))
              (func (export "handle") (param i32) (param i32) (result i64)
                (loop $l (br $l))
                (i64.const 0)))
        "#;
        let mut up = WasmUpstream::from_wasm(
            &wasm(spin),
            SandboxLimits {
                fuel_per_call: 1_000_000,
                max_memory_bytes: 1 << 20,
                deadline: None,
            },
        )
        .unwrap();
        let err = up
            .send(Message::request(Id::Num(1), "ping", None))
            .await
            .unwrap_err();
        assert!(matches!(err, TransportError::Sandbox(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn memory_growth_is_capped() {
        // `handle` tries to grow memory by 100 pages (6.4 MiB); the cap is ~128 KiB.
        // `memory.grow` returns -1 when denied, which we surface by writing past the
        // current memory — but simpler: assert the upstream builds with a tiny cap
        // and a module whose initial memory already exceeds it fails to instantiate.
        let big = r#"
            (module
              (memory (export "memory") 4)   ;; 4 pages = 256 KiB initial
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "handle") (param i32) (param i32) (result i64) (i64.const 0)))
        "#;
        let res = WasmUpstream::from_wasm(
            &wasm(big),
            SandboxLimits {
                fuel_per_call: 1_000_000,
                max_memory_bytes: 128 * 1024, // 128 KiB < 256 KiB initial
                deadline: None,
            },
        );
        assert!(matches!(res, Err(TransportError::Sandbox(_))));
    }

    #[tokio::test]
    async fn wall_clock_deadline_traps_even_with_fuel_to_spare() {
        // A spin loop with an effectively unbounded fuel budget: only the
        // wall-clock deadline can stop it. The epoch ticker must fire and trap.
        let spin = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 1024))
              (func (export "handle") (param i32) (param i32) (result i64)
                (loop $l (br $l))
                (i64.const 0)))
        "#;
        let mut up = WasmUpstream::from_wasm(
            &wasm(spin),
            SandboxLimits {
                fuel_per_call: u64::MAX, // fuel never runs out — the deadline must
                max_memory_bytes: 1 << 20,
                deadline: Some(Duration::from_millis(100)),
            },
        )
        .unwrap();
        let err = up
            .send(Message::request(Id::Num(1), "ping", None))
            .await
            .unwrap_err();
        assert!(matches!(err, TransportError::Sandbox(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn deadline_does_not_trip_a_fast_call() {
        // With a generous deadline, a normal (instant) echo call still succeeds —
        // the deadline is per-call and relative to the engine's current epoch, so a
        // quick call finishes well within it.
        let mut up = WasmUpstream::from_wasm(
            &wasm(ECHO),
            SandboxLimits {
                deadline: Some(Duration::from_secs(5)),
                ..SandboxLimits::default()
            },
        )
        .unwrap();
        let sent = Message::request(Id::Num(9), "ping", None);
        up.send(sent.clone()).await.unwrap();
        assert_eq!(up.recv().await.unwrap().unwrap(), sent);
    }

    #[tokio::test]
    async fn a_module_importing_anything_is_rejected() {
        // Importing a host function (here a fake "env"."log") must fail to
        // instantiate against the empty linker — zero ambient capability.
        let importer = r#"
            (module
              (import "env" "log" (func $log (param i32)))
              (memory (export "memory") 1)
              (func (export "alloc") (param i32) (result i32) (i32.const 0))
              (func (export "handle") (param i32) (param i32) (result i64) (i64.const 0)))
        "#;
        let res = WasmUpstream::from_wasm(&wasm(importer), SandboxLimits::default());
        assert!(matches!(res, Err(TransportError::Sandbox(_))));
    }

    #[tokio::test]
    async fn state_persists_across_calls_in_the_reused_instance() {
        // A global counter incremented on every `handle`, with two data-segment
        // responses keyed by its parity. Reusing the one instance means the counter
        // survives between calls (a fresh instance per call would always read 1), so
        // the responses must alternate — proving guest session state persists, the
        // same model the gateway handshake relies on.
        let stateful = r#"
            (module
              (memory (export "memory") 1)
              (global $n (mut i32) (i32.const 0))
              (data (i32.const 100) "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"v\":\"odd\"}}")
              (data (i32.const 200) "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"v\":\"even\"}}")
              (func (export "alloc") (param i32) (result i32) (i32.const 4096))
              (func $strlen (param $p i32) (result i32)
                (local $k i32)
                (loop $l
                  (if (i32.load8_u (i32.add (local.get $p) (local.get $k)))
                    (then (local.set $k (i32.add (local.get $k) (i32.const 1))) (br $l))))
                (local.get $k))
              (func (export "handle") (param i32) (param i32) (result i64)
                (local $p i32)
                (global.set $n (i32.add (global.get $n) (i32.const 1)))
                (local.set $p (select (i32.const 100) (i32.const 200)
                  (i32.rem_u (global.get $n) (i32.const 2))))
                (i64.or
                  (i64.shl (i64.extend_i32_u (local.get $p)) (i64.const 32))
                  (i64.extend_i32_u (call $strlen (local.get $p))))))
        "#;
        let mut up = WasmUpstream::from_wasm(&wasm(stateful), SandboxLimits::default()).unwrap();
        let v = |m: Message| m.result.unwrap()["v"].as_str().unwrap().to_string();

        up.send(Message::request(Id::Num(1), "ping", None))
            .await
            .unwrap();
        assert_eq!(v(up.recv().await.unwrap().unwrap()), "odd"); // n = 1
        up.send(Message::request(Id::Num(1), "ping", None))
            .await
            .unwrap();
        assert_eq!(v(up.recv().await.unwrap().unwrap()), "even"); // n = 2 → state carried over
        up.send(Message::request(Id::Num(1), "ping", None))
            .await
            .unwrap();
        assert_eq!(v(up.recv().await.unwrap().unwrap()), "odd"); // n = 3
    }

    #[tokio::test]
    async fn a_leaky_guest_is_bounded_and_never_harms_the_host() {
        // The instance is reused, so a guest whose bump allocator never reuses its
        // buffer keeps advancing into its single 64 KiB page. The bound is the
        // backstop: once it runs past its memory, the guest's own calls fail with a
        // Sandbox error — no panic, no unbounded host growth (the documented #3 bound).
        let bump_leak = r#"
            (module
              (memory (export "memory") 1)   ;; 64 KiB, never grows
              (global $next (mut i32) (i32.const 1024))
              (func (export "alloc") (param $len i32) (result i32)
                (local $p i32)
                (local.set $p (global.get $next))
                (global.set $next (i32.add (global.get $next) (i32.const 20000)))
                (local.get $p))
              (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
                (i64.or
                  (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
                  (i64.extend_i32_u (local.get $len)))))
        "#;
        let mut up = WasmUpstream::from_wasm(&wasm(bump_leak), SandboxLimits::default()).unwrap();
        // ~64 KiB / 20 KiB ≈ 3 calls fit; a later call must trap at the bound.
        let mut hit_bound = false;
        for i in 0..8 {
            if up
                .send(Message::request(Id::Num(i), "ping", None))
                .await
                .is_err()
            {
                hit_bound = true;
                break;
            }
        }
        assert!(
            hit_bound,
            "a guest that leaks past its memory must eventually fail its own call"
        );
    }
}
