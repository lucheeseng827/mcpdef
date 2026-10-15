# mcpdef-bench

A load harness for the `mcpdef` gateway. It runs the **real release binary** as a
child process in front of mock MCP upstreams it hosts itself, drives it with
concurrent clients, and reports what it measured as JSON and as Markdown.

It is a measurement tool, not part of the engine: `publish = false`, and it adds
no third-party crate to the workspace.

## Scenarios

| Scenario | What it measures | Why |
|---|---|---|
| `allowed` | An allowlisted `tools/call`, through the gateway **and** straight to the same upstream, at 1 and 16 clients | The difference is what the gateway adds to a call. Measured in the same run, so the machine cancels out |
| `denied` | A call the allowlist refuses | The short-circuit path: no upstream involved |
| `slow-neighbour` | 20 upstreams, one of which takes 5 s to answer; the latency of calls to the other 19 from 8 clients (`--neighbour-concurrency` sets another count), with and without that slow call in flight. Run over HTTP upstreams and over stdio upstreams | Whether one slow server holds up calls to every other one. A gateway that keeps upstreams independent shows a ratio near **1×** |
| `idle-rss` | Memory of the gateway process (not its children) fronting 10 stdio upstreams with the console on, its page and its overview's API loaded, idle and after a burst of calls: the resident set, and its anonymous and file-backed parts | The footprint of running it, as it is run |

Every reply is checked, not just timed: a call counts only if it came back the
way the scenario expects (a result, or a tool error for a denial). A gateway
that got faster by answering wrongly shows up as errors, not as a speed-up.

## Running it

```sh
make bench          # full run: ~1.5 minutes, report in target/bench-report.json
make bench QUICK=1  # CI-sized: the slow neighbour at 1 s, fewer calls, ~20 s
```

Or directly, after `cargo build --release --locked -p mcpdef -p mcpdef-bench`:

```sh
./target/release/mcpdef-bench run --out report.json [--quick] \
    [--scenarios allowed,denied,slow-neighbour,idle-rss] [--slow-ms 5000] \
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

## Comparing against a baseline

```sh
./target/release/mcpdef-bench compare --current report.json \
    --baseline crates/mcpdef-bench/baselines/serialized.json \
    [--max slow_neighbour.http.ratio_p99=1.5] [--require-comparable] [--fail-on-regression]
```

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
  quick ones) for memory:

  | Metric | Tolerance | Swing between runs of one binary |
  |---|---|---|
  | Single-client p50 ratios | 25 % | up to 11 % |
  | Idle anonymous memory | 5 % | up to 2.5 % |
  | Anonymous memory after the burst of calls | 20 % | up to 12 %, because the allocator's footprint depends on how the concurrent calls interleaved. 20 % of it is about 320 KB, against about 1.8 MB for the resident set |
  | Resident memory | 20 % | up to 16 %, all of it file-backed |
  | p99 and 16-client ratios | 50 % | up to 24 % in a full run, up to 68 % in a quick one (its p99 rests on a handful of samples) |
  | Slow-neighbour ratios | 50 % | up to 19 %; the change that matters there is thousands against about one |

  Regressions are warnings unless `--fail-on-regression` is set. Judge a change
  on full runs: quick runs are for smoke checks.
- **`--max metric=limit` is a hard limit**, checked with or without a baseline.
  A limit on a metric that is missing from the report fails too: a gate that
  checks nothing is not a gate.

Metric keys are:
- `allowed.c<N>.ratio_p50` and `allowed.c<N>.ratio_p99`;
- `denied.c<N>.ratio_p50_vs_direct`;
- `slow_neighbour.<http|stdio>.ratio_p50` and `slow_neighbour.<http|stdio>.ratio_p99`;
- `idle_rss.idle_anon_kb` and `idle_rss.after_load_anon_kb` (Linux only);
- `idle_rss.idle_rss_kb` and `idle_rss.after_load_rss_kb`.

## Baselines

Baselines live in [`baselines/`](./baselines). Each one is only comparable with
runs on the same kind of machine:

| File | What it is |
|---|---|
| `serialized.json`, `serialized-quick.json` | The gateway as it was before calls ran concurrently. Measured on a 4-vCPU cloud container. They record that design's head-of-line blocking, a slow-neighbour ratio in the thousands where the concurrent gateway measures about 1×. Later runs on the same machine type are judged against them |
| `serialized-200-clients.json` | The same gateway, the slow-neighbour scenario alone at 200 clients (`--scenarios slow-neighbour --neighbour-concurrency 200`), on the same machine type. The baseline for the heavy-load run above |
| `ci-ubuntu-24.04.json` | *Not yet recorded.* The baseline for the scheduled CI run. To create it, run the **mcpdef bench** workflow once by hand, download its `mcpdef-bench` artifact, and commit its `bench.json` under this name |

To refresh a baseline after an intended change, run the same command on the same
machine type and commit the new report in place, with a note saying why.
