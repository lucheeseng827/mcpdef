# mcpdef-bench

A load harness for the `mcpdef` gateway. It runs the **real release binary** as a
child process in front of mock MCP upstreams it hosts itself, drives it with
concurrent clients, and reports what it measured as JSON and as Markdown.

It is a measurement tool, not part of the engine: `publish = false`, and it adds
no third-party crate to the workspace. What it measured on a named machine is in
[docs/PERFORMANCE.md](../../docs/PERFORMANCE.md).

## Scenarios

| Scenario | What it measures | Why |
|---|---|---|
| `allowed` | An allowlisted `tools/call`, through the gateway **and** straight to the same upstream, at 1 and 16 clients | The difference is what the gateway adds to a call. Measured in the same run, so the machine cancels out |
| `allowed-bearer` | The `allowed` call through a second gateway, one with `[gateway.auth]` on, that checks an RS256 bearer token on every call against keys pinned in its config | What checking a token adds. The keys are in memory, as a fetched JWKS is once cached, and no token is cached: each call's signature and claims are checked |
| `allowed-bearer-fsync` | The `allowed-bearer` call through a third gateway, one with `[gateway] audit_fsync` on, so that each audit record is on disk before the reply | What a reply that means "recorded on disk" costs. Mostly the disk's: an `fsync` takes what the storage underneath takes |
| `denied` | A call the allowlist refuses | The short-circuit path: no upstream involved |
| `slow-neighbour` | 20 upstreams, one of which takes 5 s to answer; the latency of calls to the other 19 from 8 clients (`--neighbour-concurrency` sets another count), with and without that slow call in flight. Run over HTTP upstreams and over stdio upstreams | Whether one slow server holds up calls to every other one. A gateway that keeps upstreams independent shows a ratio near **1×** |
| `wasm-instantiate` | A WASM component (by default the sandbox's `echo` fixture) compiled once, then a fresh instance of it made 3,000 times, each with a store, a memory and a WASI context of its own, as the gateway makes one. Timed in the harness's own process through the sandbox's API, and only in a harness built with the `wasm` feature | What a fresh, isolated instance would cost per session or per call. The gateway makes one instance per server today, so no call through it would time this |
| `idle-rss` | Memory of the gateway process (not its children) fronting 10 stdio upstreams with the console on, its page and its overview's API loaded, idle and after a burst of calls: the resident set, and its anonymous and file-backed parts | The footprint of running it, as it is run |

Every reply is checked, not just timed: a call counts only if it came back the
way the scenario expects (a result, or a tool error for a denial). A gateway
that got faster by answering wrongly shows up as errors, not as a speed-up.

## Running it

```sh
make bench          # full run: ~3 minutes, report in target/bench-report.json
make bench QUICK=1  # CI-sized: the slow neighbour at 1 s, fewer calls, ~30 s
```

Or directly, after `cargo build --release --locked -p mcpdef -p mcpdef-bench --features
mcpdef-bench/wasm` (leave out the feature, and with it Wasmtime, to build the harness
without `wasm-instantiate`):

```sh
./target/release/mcpdef-bench run --out report.json [--quick] \
    [--scenarios allowed,allowed-bearer,allowed-bearer-fsync,denied,slow-neighbour,idle-rss,wasm-instantiate] \
    [--slow-ms 5000] [--wasm-component path/to/component.wasm] \
    [--concurrency 1,16] [--neighbour-concurrency 8] [--requests 3000] \
    [--mcpdef path/to/mcpdef] [--note "…"]
```

By default it measures the `mcpdef` binary that sits beside it in
`target/release/`. The stdio upstreams are the harness binary itself, run by the
gateway as `mcpdef-bench mock-stdio --tool <name> [--delay-ms N]`.

### Isolation under heavy load

The slow-neighbour scenario runs 8 clients by default. To check that a slow
upstream holds no one up under heavy load, run it at 200, and hold both
transports to 10 %:

```sh
./target/release/mcpdef-bench run --scenarios slow-neighbour \
    --neighbour-concurrency 200 --out heavy.json
./target/release/mcpdef-bench compare --current heavy.json \
    --baseline crates/mcpdef-bench/baselines/serialized-200-clients.json \
    --max slow_neighbour.http.ratio_p99=1.1 --max slow_neighbour.stdio.ratio_p99=1.1
```

On a 4-vCPU machine, the fast calls' p99 rises to 15–22 ms at 200 clients,
nearly all of it spent queueing, and the slow call leaves it where it was. Over
three runs the p99 ratio measured 0.95–1.00 over HTTP and 0.95–1.03 over
stdio. The gateway before calls ran concurrently measured 88× over HTTP and
161× over stdio. Its ratio is lower than at 8 clients (1,515× and 2,190×) only
because queueing lengthens the p99 of the calls made with nothing slow in
flight.

The warm-up makes at least twice as many calls as there are clients, so the
timed calls find their connections already open. At 200 clients the gateway and
the harness each hold about 450 open files. Where the limit is lower, as
macOS's default of 256 is, raise it first: `ulimit -n 1024`.

## The first governed call

`first-call` times something other than what a call costs: the commands
[README.md](../../README.md) gives someone whose Claude Code already runs an MCP
server, from an installed `mcpdef` to its first governed call.

```sh
./target/release/mcpdef-bench first-call [--runs 3] [--max-seconds 60] \
    [--mcpdef path/to/mcpdef] [--out first-call.json] [--note "…"]
```

It runs two paths, each from a home directory and a project made for it:

- **The gateway:** `mcpdef up` with no config, then `mcpdef connect claude-code
  --write --replace`, then the client's `initialize`, `tools/list` and first
  `tools/call`, through the gateway.
- **The hook:** `mcpdef import --out mcpdef.toml`, then `mcpdef hook install
  --config mcpdef.toml --write`, then the hook Claude Code runs before its first
  MCP tool call.

The project's `.mcp.json` runs the harness's stdio mock, and the home's
`.claude.json` says Claude Code was told to run it there. The harness stands in
for Claude Code. Its client calls the URL in the entry `connect` wrote, and it
runs the hook `hook install` wrote, through `sh`, with the event Claude Code
sends. Each step is checked as well as timed:

- `up` fronts the server, and `connect` leaves the gateway alone in `.mcp.json`;
- the call is answered as the mock answers it, and the hook lets it through;
- the ledger holds that one call, allowed, and `mcpdef audit verify` passes.

It fails when a step does not do that, or when a path takes longer than
`--max-seconds`. It needs port 7878 free, where `mcpdef up` with no config
listens, and runs on Linux and macOS.

## With no route out

`offline` runs the gateway path's commands, then a policy update, as someone
would on an air-gapped host, and checks what `mcpdef` does on the network
meanwhile. Nothing is timed.

```sh
./target/release/mcpdef-bench offline [--mcpdef path/to/mcpdef] [--max-seconds 60] [--strace]
```

From a home directory and a project made for it, as `first-call`'s:

1. `mcpdef up` with no config, `mcpdef connect claude-code --write --replace`,
   and the client's first call, answered as the mock answers it;
2. `mcpdef validate` and `mcpdef doctor` on the config `up` wrote, with
   0 problems;
3. the policy update: `deny = ["echo"]` on the server in that config, `mcpdef
   validate` again, and a `SIGHUP`, after which the gateway says it reloaded;
4. in the session already open, the tool no longer listed and a call to it
   refused; then `mcpdef hook install`, and the hook refusing the call too;
5. `mcpdef audit verify`, and a ledger holding the call, the reload `sighup`
   asked for, and both refusals, in that order.

With `--strace`, the harness runs itself again under `strace -f -e
trace=%network`, with every process it starts, and fails on any network call
that names an address past loopback, or port 53, or a local resolver's socket:
a name looked up is a reach outwards, whatever answers it. Run where there is
no route out, a step that needed one fails too.

mcpdef CI's `offline` job runs it on every pull request that changes the
module. It packs the static build with its checksum, as the release packs
them, then installs and runs it in a container started with `--network none`
that holds nothing else, not even a CA bundle. `--strace` needs Linux; without
it, `offline` runs on macOS too.

## Comparing against a baseline

```sh
./target/release/mcpdef-bench compare --current report.json \
    --baseline crates/mcpdef-bench/baselines/serialized.json \
    [--max slow_neighbour.http.ratio_p99=1.5] [--require-comparable] [--fail-on-regression]
```

- **Several runs of one build can be given a side.** Repeat `--current`, and
  `--baseline`. Each metric is then judged on its best (lowest) value on each
  side, and a `--max` limit is checked on its best current value: what disturbs
  a run only ever makes it slower. The runs of one side must be comparable with
  each other, or only the first is shown and nothing is judged.
- **A ratio of the gateway over a direct call is judged by its parts.** Its
  best is the gateway's lowest percentile over the direct call's lowest, each
  over the side's runs, not the lowest of the runs' ratios. A direct call never
  passes through the gateway: a run whose direct calls were slowed reads a low
  ratio for a gateway that was no faster, and the lowest ratio is that run's.
  On the gate's runner one run read an allowed call's p99 as 0.89×, the gateway
  faster than a call that skips it. A slow-neighbour ratio is still its best
  run's, since both its parts pass through one gateway in one run.
- **Only ratios measured within one run are compared.** These are gateway over
  direct for an allowed call, denied over direct, and beside-the-slow-one over
  alone. Both sides of each ratio share a machine, a moment and a load. Memory
  is the one absolute number, because it does not depend on how busy the
  machine was.
- **Memory is judged by its anonymous part.** The resident set is anonymous
  memory (heap and stacks, what the gateway allocated) plus file-backed pages,
  mostly the executable's own. The kernel faults those in and drops them with
  its page cache, so between runs of one binary the resident set moves by up
  to 16 % while idle anonymous memory moves by 2.5 %. The report shows both
  parts. Anonymous memory is read on Linux only, and baselines recorded before
  it was measured lack it: `compare` leaves a metric missing from the baseline
  unjudged rather than calling it a regression. Idle memory measured with the
  console open in one report and closed in the other, as in baselines recorded
  before the scenario opened it, is left unjudged too, and the comparison says
  why.
- **Two reports are compared only when they are comparable.** That means the
  same schema, OS, architecture, CPU count and CPU model, and the same run
  parameters. A quick run is never judged against a full one. Otherwise the
  comparison says why it will not judge, naming any parameters that differ,
  and does not guess.
- **A metric regresses** when it rises above its baseline by more than its
  tolerance. The tolerances were calibrated by running one binary repeatedly
  on one 4-vCPU machine: twice for the ratios, 40 times (20 full runs and 20
  quick ones) for memory. The 16-client p99 ratios' tolerance was set again from
  the gate's own runner, a GitHub runner with two vCPUs, over 26 of its jobs:

  | Metric | Tolerance | Swing between runs of one binary |
  |---|---|---|
  | Single-client p50 ratios | 25 % | up to 11 % |
  | Idle anonymous memory | 5 % | up to 2.5 % |
  | Anonymous memory after the burst of calls | 20 % | up to 12 %, because the allocator's footprint depends on how the concurrent calls interleaved. 20 % of it is about 320 KB, against about 1.8 MB for the resident set |
  | Resident memory | 20 % | up to 16 %, all of it file-backed |
  | Single-client p99 and 16-client p50 ratios | 50 % | up to 24 % in a full run, up to 68 % in a quick one (its p99 rests on a handful of samples). On the gate's runner, under +22 % |
  | 16-client p99 ratios | 100 % | on the gate's runner, up to +83 %: one base run's tail was 1.67 ms where its other three runs took about 3 ms. The clients, the gateway and the upstream share two vCPUs there. So the gate catches a 16-client tail twice as slow, not less |
  | Slow-neighbour ratios | 50 % | up to 19 %; the change that matters there is thousands against about one |

  Regressions are warnings unless `--fail-on-regression` is set. Judge a change
  on full runs: quick runs are for smoke checks.
- **`--max metric=limit` is a hard limit**, checked with or without a baseline.
  A limit on a metric that is missing from the report fails too: a gate that
  checks nothing is not a gate.

Metric keys are:
- `allowed.c<N>.ratio_p50` and `allowed.c<N>.ratio_p99`, and the same under
  `allowed_bearer.` and `allowed_bearer_fsync.`;
- `denied.c<N>.ratio_p50_vs_direct`;
- `slow_neighbour.<http|stdio>.ratio_p50` and `slow_neighbour.<http|stdio>.ratio_p99`;
- `idle_rss.idle_anon_kb` and `idle_rss.after_load_anon_kb` (Linux only);
- `idle_rss.idle_rss_kb` and `idle_rss.after_load_rss_kb`.

## The gate on every pull request

A pull request that changes the engine is measured against the code it changes.
The gate builds the release `mcpdef` at the PR's base and at its merge result.
It measures both with the merge result's harness, in one job on one runner,
twice each and alternating: base, head, base, head. Then it runs `compare` with
both runs of each side and `--require-comparable --fail-on-regression`.

- **No stored baseline is needed.** Both sides come from the same machine,
  minutes apart, so runner noise hits both alike.
- **Each metric is judged on its best run on each side.** What disturbs a run
  only ever makes it slower. With one run a side, base was measured straight
  after the builds and read the same binary up to 29 % slower than head did
  minutes later. So the gate syncs the builds to disk first, and no single
  disturbed run decides. A gateway-over-direct ratio is judged by its parts,
  as above.
- **All three of its false failures were the 16-client p99.** Until that tail
  was judged by its parts and given 100 %, unchanged code failed the gate in 2
  of 26 jobs, and once more on the change that added `first-call`. Re-pairing
  those 26 jobs' runs, two a side, the 16-client p99 ratios moved by up to
  +101 % judged by the lowest ratio, and by up to +49 % judged by their parts.
- **It also fails on three hard limits:** idle memory over 30 MB, a
  slow-neighbour p99 ratio over 1.5, and a release binary more than 10 % bigger
  than base's.
- **And it runs `first-call`** with the merge result's build, three times. It
  fails when a path takes longer than 60 s, or when a command does not do what
  README.md says.
- **It runs full runs, not `--quick`.** Two quick runs of one binary moved p99
  ratios by more than their 50 % tolerance.
- **It leaves out `allowed-bearer-fsync`.** What an `fsync` costs is the
  runner's disk more than the gateway. And a gateway ignores a `[gateway]` key
  it does not know, so a base from before `audit_fsync` would run that scenario
  without an `fsync` and make the change look slow. A scenario that needs a new
  key joins the gate's list only once base has the key.

## Baselines

Baselines live in [`baselines/`](./baselines). Each one is only comparable with
runs on the same kind of machine:

| File | What it is |
|---|---|
| `serialized.json`, `serialized-quick.json` | The gateway as it was before calls ran concurrently. Measured on a 4-vCPU cloud container. They record that design's head-of-line blocking, a slow-neighbour ratio in the thousands where the concurrent gateway measures about 1×. Later runs on the same machine type are judged against them |
| `serialized-200-clients.json` | The same gateway, the slow-neighbour scenario alone at 200 clients (`--scenarios slow-neighbour --neighbour-concurrency 200`), on the same machine type. The baseline for the heavy-load run above |
| `release-build-glibc.json`, `release-build-static-musl.json` | The gateway after 0.4.0, as the release builds it (`opt-level = "s"` with Wasmtime's largest crates at `"z"`, and the static build on mimalloc), for `x86_64-unknown-linux-gnu` and for `x86_64-unknown-linux-musl`. Every scenario in a full run on a 4-vCPU cloud VM (Intel Xeon @ 2.10 GHz), the glibc one with `wasm-instantiate` too. Each is the median of three runs. The numbers behind [docs/PERFORMANCE.md](../../docs/PERFORMANCE.md) |
| `0.4.0-glibc.json`, `0.4.0-static-musl.json` | 0.4.0's gateway, built for `x86_64-unknown-linux-gnu` and for `x86_64-unknown-linux-musl`, every scenario in a full run on another VM of the same type. Each is the median of three runs. The numbers behind 0.4.0's page |
| `audit-fsync-and-wasm-glibc.json`, `audit-fsync-static-musl.json`, `wasm-instantiate-static-musl.json` | The fsync and WASM rows, measured on the change that adds them, on the VM 0.4.0's numbers came from. In order: the glibc build with `allowed-bearer`, `allowed-bearer-fsync` and `wasm-instantiate`; the static gateway with the first two; and the harness itself built static, for `wasm-instantiate`, since the sandbox runs in the harness. Each is the median of three runs |
| `first-call-static-musl.json`, `first-call-glibc.json` | `first-call`, ten runs each, of the gateway after 0.4.0 as the release builds it, for `x86_64-unknown-linux-musl` and for `x86_64-unknown-linux-gnu`, on a 4-vCPU cloud VM (Intel Xeon @ 2.80 GHz). The numbers behind [docs/PERFORMANCE.md](../../docs/PERFORMANCE.md#the-first-governed-call)'s first governed call. `compare` does not read them |
| `ci-ubuntu-24.04.json` | *Not yet recorded.* The baseline for the scheduled CI run. To create it, run the **mcpdef bench** workflow once by hand, download its `mcpdef-bench` artifact, and commit its `bench.json` under this name |

To refresh a baseline after an intended change, run the same command on the same
machine type and commit the new report in place, with a note saying why.
