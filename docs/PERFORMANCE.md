# MCPdef performance

What the gateway adds to a tool call, measured on a named machine. This page also gives the
bar the project holds itself to, row by row, including the rows it does not meet yet, where a
call's time goes, how long it takes from installing MCPdef to its first governed call, and how
to measure it yourself. Every number comes from
[`mcpdef-bench`](../crates/mcpdef-bench/README.md), except the profile in
[Where the time goes](#where-the-time-goes) and the install times in
[The first governed call](#the-first-governed-call), which say how they were made. The harness
runs the real release binary in front of mock upstreams and checks every reply as well as
timing it.

## In short

The gateway as of [the build changes](#the-build) made after 0.4.0, on a 4-vCPU cloud VM. The
client, the gateway and the upstream all run on that one machine, with one client calling:

| Added to a call | allowed | allowed, with a bearer token checked | refused by the allowlist |
|---|---|---|---|
| static musl build, p50 | +109–143 µs | +169–190 µs | 0 to +21 µs |
| static musl build, p99 | +400–552 µs | +382–489 µs | +14 to +34 µs |
| glibc build, p50 | +113–128 µs | +154–212 µs | +6 to +15 µs |
| glibc build, p99 | +246–460 µs | +395–804 µs | −23 to +92 µs |

For scale, a direct call to the same upstream took 71–95 µs at the median and 165–240 µs at
p99. A refusal comes back about as fast as a direct call to the server would have.

Idle, fronting ten servers, the gateway holds 8.6–8.7 MiB resident (static musl) or
9.8–10.2 MiB (glibc). The release tarballs and the container image carry the static musl
build.

**The bar for an allowed call with cached keys is 500 µs added at p99. The static musl build
met it in all three runs, at +382–489 µs. The glibc build went over in one run of three.**
Each of those runs times 3,000 calls, as every table on this page does. Over runs ten times
as long, both builds sit at the bar rather than under it: +440–675 µs (static musl) and
+495–529 µs (glibc), where the builds before the changes measured +751–813 µs and
+547–598 µs. [Where the time goes](#where-the-time-goes) says why the rest of the tail is
hard to move from inside the gateway.

The bar's other four rows are met: refused calls and idle memory, above, and these two:

- **The fsync mode.** With `[gateway] audit_fsync` on, an answer means its audit record is on
  disk. The same call then costs another 0.28–0.39 ms at the median, and most of that is the
  disk's own `fdatasync`. This VM's disk is faster than the one 0.4.0's numbers came from,
  where the row was not met.
- **A fresh WASM instance.** One instance of a compiled component takes 19–20 µs at the
  median and 39–50 µs at p99.

**This is not the VM 0.4.0's numbers came from**, though it is of the same type. 0.4.0's own
build, measured here, adds 145–211 µs at the median and 261–584 µs at p99 to a call with a
token, over 17 runs, where that VM measured 225–294 µs and 901–1,444 µs. Most of the
difference from 0.4.0's numbers is the machine. [The build](#the-build) measures each change
against the build before it, on this VM. 0.4.0's reports stay committed.

**From installing MCPdef to its first governed call** takes about 2 s from the release
tarball, nearly all of it the download: README.md's commands take 9–14 ms after it.
`cargo install mcpdef` takes four and a half minutes, compiling. From 0.5.0, `cargo binstall
mcpdef` installs the release binary instead.
[The first governed call](#the-first-governed-call) has the steps, and what they leave out.

## How it was measured

- **Machine.** A 4-vCPU cloud VM under Firecracker: an Intel Xeon Processor @ 2.10 GHz,
  15.7 GiB of memory, Linux 6.18. The host is shared, so a busy neighbour can move the tail.
- **Binaries.** Both builds are of the gateway's code after 0.4.0, at the change that made
  [the build changes](#the-build). Each used Rust 1.94.1 and the workspace's release profile:
  `opt-level = "s"` with Wasmtime's largest crates at `"z"`, LTO, one codegen unit, stripped.
  - **glibc** (`x86_64-unknown-linux-gnu`) is what a build from a checkout of the source gives
    on most Linux distributions. `cargo install mcpdef` is not that build: a crate from
    crates.io does not carry the workspace's profile, so cargo builds it with its own
    defaults, which this page does not measure.
  - **static musl** (`x86_64-unknown-linux-musl`) is what the release tarballs and the
    container image carry. It allocates with mimalloc ([The build](#the-build)).
- **Topology.** The harness's clients, the gateway and the mock upstream run on one machine.
  They talk HTTP over loopback, with no TLS. The upstream answers at once, so what is timed
  is the gateway, not a server.
- **What the gateway does on each call:**
  - checks the call against the server's tool allowlist;
  - forwards it over Streamable HTTP;
  - writes one record to the hash-linked audit ledger before it replies. The record is
    written and flushed to the operating system, not fsynced.

  No `[[policy]]` rules, rate limits, inline inspection, transforms or pins are configured.
- **The bearer token.**
  - `[gateway.auth]` is on, with the key set pinned in the config. The keys are in memory,
    as a fetched JWKS is once it is cached.
  - Each call carries an RS256 token signed with a 2048-bit key.
  - Every call's signature and claims are checked. MCPdef caches no validated token.
- **Calls.** Each measurement makes 300 warm-up calls and then 3,000 timed ones, at one
  client and at sixteen concurrent clients. A call counts only if its reply is the one the
  scenario expects. A gateway that got faster by answering wrongly shows up as errors. There
  were none.
- **"Added".** Take the gateway's percentile, and subtract the same percentile of a call
  straight to the same upstream, measured in the same run just before. The result is a
  difference of two percentiles, not a percentile of per-call differences.
  - A refused call never reaches an upstream. For it, "added" is how much longer the refusal
    took than the direct call. A negative number means the refusal was quicker.
- **Ranges.** Each build ran three times in full (`mcpdef-bench run`, without `--quick`).
  Each number here is the range over those three runs. No run was discarded. The longer
  runs took 30,000 calls instead (`--requests 30000`), three times for each build, with one
  client.
- **The fsync row.** The ledgers lived on the VM's root filesystem: ext4 on a virtio disk
  that reports a write-back cache, so each `fsync` reaches the host.

## Where the time goes

This is the one section whose numbers do not come from `mcpdef-bench` alone. The gateway
was built with timers around each step of a call, which no release carries, and run under
the harness three times, with one client, on the VM above. It was the build from before
[the build changes](#the-build) (`opt-level = "z"`).

| Step of an allowed call | p50 | p99 |
|---|---|---|
| Checking the request before the gateway step: its origin, the in-flight cap, parsing it | 1 µs | 8–13 µs |
| With a bearer token, checking it: decoding it, its RS256 signature, its claims | 42–45 µs | 85–102 µs |
| The gateway step, from the allowlist to the ledger record | 104–111 µs | 241–329 µs |
| of which the call to the upstream, until its answer | 87–94 µs | 210–279 µs |
| of which writing the ledger record | 9–13 µs | 33–44 µs |

The token's row comes from the runs with a token, the others from the runs without one. The
timers cover the 300 warm-up calls too. In the runs with a token they kept 2,073–2,537 of
the 3,300 calls, since their last second was not written out before the gateway stopped.

What follows from it:

- **The gateway's own work is small.** At the median it is about 18 µs for an allowed call,
  and about 65 µs with a bearer token, most of that the signature.
- **The rest of what it adds is a second HTTP round trip.** A direct call makes one, from
  the client to the upstream. A call through the gateway makes two: the client's to the
  gateway, then the gateway's to the upstream. On this VM such a round trip takes about
  80 µs at the median, which is about what the gateway adds beyond its own work.
- **The tail is in the round trips too.** The gateway's call to the upstream took
  210–279 µs at p99, where the harness's own call to the same upstream, in the same runs,
  took 174–185 µs. The gateway's own steps stay under about 45 µs at p99, the token's check
  aside. The likely reason is the VM's: a vCPU with nothing to run halts, and waking a
  thread on it goes through the hypervisor.

So the code the gateway runs can buy back only a part of the tail. These were tried, and
not taken:

- **One worker thread instead of one per vCPU** (`TOKIO_WORKER_THREADS=1`). In one session
  it took an allowed call's p99 from 240 to 116 µs. In a second, alternating with the
  default, the difference was inside the runs' own spread, and sixteen clients got 40 %
  fewer calls with a token through. The runtime keeps a thread per vCPU.
- **`opt-level = 3`.** It took 43 µs off a call with a token at the median, where
  [the build](#the-build) takes 16–45 µs off, for a binary 64 % bigger. The bench gate
  allows 10 %.
- **Caching validated tokens.** It would take most of the token's 42–45 µs off a call that
  repeats a token. MCPdef checks every call's signature and claims instead, and this page's
  numbers include that check.

## The build

Two changes to how the release is built. Each was measured against the build before it, on
this VM, in alternating runs with one harness.

**The optimization level.** The release was built at `opt-level = "z"`, the smallest. It is
now built at `"s"`, except for Wasmtime's compiler, parser and WASI, which stay at `"z"`.
They are about half of the code the binary links, and on a call's path only when its
server runs in the sandbox.

| glibc gateway, built at | allowed, added p50 | with a token, added p50 | with a token, calls a second, sixteen clients | binary |
|---|---|---|---|---|
| `"z"` | 119 µs | 205 µs | 12,568 | 13.7 MB |
| `"s"`, Wasmtime's largest crates at `"z"` | 100 µs | 160 µs | 12,874 | 14.3 MB, +4.6 % |

These are medians of seven runs each. Over four such sessions, the change took 16–45 µs
off a call with a token at the median, and 3–19 µs off one without. At p99 it moved less
than the runs' own spread, except in the longer runs, where a call with a token went from
+547–598 µs to +495–529 µs. `"s"` for every crate would make the binary 12 % bigger, and
`opt-level = 3` 64 % bigger. The bench gate fails a binary that grows by more than 10 %.

**The static build's allocator.** A static musl build allocated with musl's own allocator.
It now allocates with [mimalloc](https://github.com/microsoft/mimalloc). Other builds keep
the system's.

| static musl gateway, at `"s"`, allocating with | allowed, added p50 | with a token, added p50 | calls a second, sixteen clients: allowed, with a token | resident, idle |
|---|---|---|---|---|
| musl's allocator | 162 µs | 276 µs | 8,560, 7,696 | 7.7 MiB |
| mimalloc | 123 µs | 197 µs | 17,285, 14,489 | 8.6–8.7 MiB |

These are medians of seven runs each. With musl's allocator, the static build was the slower
of the two, and with sixteen clients it got about half as many calls through as the glibc
build. With mimalloc it gets more through than the glibc build does.

mimalloc is built without transparent huge pages, by its `no_thp` feature:

- **With them,** on a kernel that hands them out when a program asks (`madvise`, as on this VM
  and on Ubuntu), an idle gateway held 17–19 MiB, 2 MiB at a time.
- **On a kernel set to `always`,** they come back anyway: 19.2 MiB idle, in a run with this
  VM switched to `always`, where the build before the changes, on musl's allocator, held
  10.3 MiB. `MIMALLOC_ALLOW_THP=0` turns them off for the gateway's process, and for the
  processes it starts: 8.6 MiB.

On the glibc build, mimalloc made little difference with one client, 5–8 µs at the median.
With sixteen it got 12–25 % more calls through, for 1 MiB more resident. The glibc build
keeps glibc's allocator.

## Sixteen clients

With sixteen clients, the clients, the gateway and the upstream all compete for four vCPUs.
These numbers therefore say as much about the machine as about the gateway. They are
published because contention is where a regression in locking or allocation shows first.

| | glibc build | static musl build |
|---|---|---|
| Allowed, added p50 | +611–702 µs | +403–579 µs |
| Allowed, added p99 | +1.74–1.97 ms | +1.31–2.80 ms |
| Allowed, calls per second through the gateway | 15,300–16,500 | 17,000–19,700 |
| Allowed with a bearer token, added p50 | +832–986 µs | +573–762 µs |
| Allowed with a bearer token, added p99 | +2.00–3.48 ms | +1.95–3.35 ms |
| Allowed with a bearer token, calls per second | 11,100–13,500 | 13,100–16,500 |
| Refused, calls per second | 27,900–31,000 | 25,200–29,600 |

Direct calls to the upstream ran at 51,000–59,600 a second.

## Memory and isolation

| | glibc build | static musl build |
|---|---|---|
| Resident, idle, fronting 10 servers, console on | 9.8–10.2 MiB | 8.6–8.7 MiB |
| of which anonymous (heap and stacks) | 1.5 MiB | 2.1 MiB |
| Resident after 1,000 calls | 10.6–11.1 MiB | 9.6 MiB |

These figures are for the gateway process alone. The ten stdio servers it starts run as
processes of their own and are not counted. The rest of the resident set is file-backed,
mostly the executable's own pages.

**Isolation.** In this test, one of 20 upstreams takes 5 s to answer. Eight clients call
the other 19. Their p99 was 0.89–1.08 times what it was with nothing slow in flight. That
holds over HTTP and over stdio, on both builds. A ratio of 1 means the slow server holds no
one up. A gateway that queues calls behind a slow one shows a ratio in the thousands: the
gateway before calls ran concurrently measured 1,515× over HTTP and 2,190× over stdio.

## The first governed call

How long it takes from installing MCPdef to its first governed call: a call MCPdef judged and
its ledger holds. The person already runs an MCP server in Claude Code, and follows
[README.md](../README.md). The project's bar is under a minute.

| On a 4-vCPU cloud VM (Intel Xeon @ 2.80 GHz) | Time |
|---|---|
| Installing from the release tarball: downloading 6.1 MB, checking its SHA-256, unpacking it | 0.97–1.89 s |
| *or* `cargo install mcpdef --locked`, with nothing in cargo's cache | 268.6 s |
| Then, through the gateway: `mcpdef up`, `mcpdef connect claude-code --write --replace`, and the client's first call | 8.8–11.7 ms |
| *or* through a hook: `mcpdef import --out mcpdef.toml`, `mcpdef hook install --config mcpdef.toml --write`, and the hook before the first MCP tool call | 9.3–13.6 ms |

The install rows are 0.4.0's, the newest release, and the command rows the gateway's after
it: 0.4.0 has no `mcpdef up` without a config, so the rows are not yet one procedure. The
commands' times are the static musl build's, which the tarball carries. The glibc build
took 10.4–14.3 ms through the gateway and 11.7–17.6 ms through a hook. On a GitHub-hosted
runner with two vCPUs (AMD EPYC 7763), the tarball took 0.7 s, `cargo install` 501.2 s, and
the commands 6.5–7.0 ms through either path.

**From the release tarball, the machine's share of the minute is about 2 s. From
`cargo install` it is four and a half minutes, so that way in cannot meet the bar, however
fast the person is.** Homebrew installs the same tarball, after updating itself, and from 0.5.0
so does `cargo binstall mcpdef`: the crate names the release archives in its
`[package.metadata.binstall]`. The container
image runs MCPdef as a service, not as this start, and is not timed.

- **The gateway, step by step.** `mcpdef up`, in a project with no `mcpdef.toml`, writes one
  that fronts the server Claude Code runs there, and is ready in 4.3–5.6 ms. `mcpdef connect
  claude-code --write --replace` points Claude Code at the gateway and takes the server out of
  `.mcp.json`: 2.7–4.0 ms. The client's `initialize`, `tools/list` and first `tools/call`
  through the gateway: 1.9–2.8 ms.
- **The hook, step by step.** `mcpdef import --out mcpdef.toml`: 2.5–4.5 ms. `mcpdef hook
  install --config mcpdef.toml --write`: 2.6–5.8 ms. The hook Claude Code runs before the first
  MCP tool call, from its start until it lets the call through: 4.2–5.0 ms.
- **`cargo install`** fetched the crates.io index and 286 crates, 28 MB, and compiled 267 of
  them on the VM's four vCPUs, with cargo's own release profile. Compiling took nearly all of
  its 268.6 s.

How it was measured:

- **The commands.** `mcpdef-bench first-call` ran both paths ten times with each build, each
  time from a home directory and a project of its own. The project's `.mcp.json` runs the
  harness's stdio mock. The home's `.claude.json` says Claude Code was told to run it there, as
  `mcpdef up` asks before it fronts a server that only a directory's own files name.
- **The client.** The harness stands in for Claude Code. Its client calls the URL in the entry
  `connect` wrote. It runs the hook `hook install` wrote through `sh`, with the event Claude Code
  sends.
- **A call counts** once its record is in the ledger and `mcpdef audit verify` passes: through
  the gateway, once it is answered as the mock answers it; through a hook, once the hook lets
  it through.
- **Which versions.** The commands are those of the gateway after 0.4.0, as this page's other
  numbers are: 0.4.0, the newest release, has no `mcpdef up` without a config. The install times
  are 0.4.0's: its tarball three times, and `cargo install` once, from an empty cargo home. The VM
  reaches the network through a proxy.

What it leaves out:

- **The person.** Reading, typing two commands, and a second shell for `connect` while `up`
  runs.
- **The client.** Claude Code reads a new server or hook when it starts. It asks before it uses
  a server that is new in `.mcp.json`, and the gateway's entry is one.
- **Through a hook, the call itself.** Once the hook lets a call through, the client makes it
  to the server itself, with MCPdef not in its path, so it takes what it would take without
  MCPdef.
- **A real server's start.** The mock answers at once. `mcpdef up` starts each server it fronts
  before it is ready, so a server that takes seconds to start adds those seconds. One that `npx`
  or `uvx` fetches the first time it runs is such a server.
- **Other networks.** The tarball is 6.1 MB, and `cargo install` fetches 28 MB.

## The bar

The bar measures p99 added overhead, except for the memory row. It is the project's own
bar. The rows MCPdef does not meet are listed as not met, not left out.

| Path | Bar | glibc build | static musl build | Status |
|---|---|---|---|---|
| Allowed `tools/call`, cached keys, ledger record flushed without fsync | < 500 µs | +395–804 µs | +382–489 µs | **Met on the static build.** glibc went over in one run of three, and over longer runs both are at the bar |
| The same, with an fsync per ledger record | < 3 ms | +1.08–1.53 ms | +0.86–1.48 ms | **Met** on this VM's disk |
| Refused call | < 100 µs | −23 to +92 µs | +14 to +34 µs | **Met** |
| Cold instantiation of a WASM component | < 1 ms | 39–50 µs | 55–63 µs | **Met** |
| Resident memory, idle, 10 servers fronted | < 30 MB | 9.8–10.2 MiB | 8.6–8.7 MiB | **Met** |

- **First row.** At the median, MCPdef adds 169–190 µs to that call on the static build and
  154–212 µs on glibc.
  - The p99 of 3,000 calls moves from run to run by more than the build changes moved it.
    Over 30,000 calls the spread is narrower, and both builds sit at the bar: +440–675 µs
    (static) and +495–529 µs (glibc).
  - Most of that tail is the second round trip's and the VM's, not the gateway's own work
    ([Where the time goes](#where-the-time-goes)).
- **Second row.** With `[gateway] audit_fsync` on, each ledger record is `fsync`ed before the
  answer.
  - At the median that adds 0.45–0.56 ms to the call, 0.28–0.39 ms more than the same call
    without it.
  - Most of it is the disk's. On this VM, a bare `write` and `fdatasync` of one ledger line,
    once a millisecond as the single client's calls arrive, takes 0.31–0.34 ms at p50 and
    0.92–1.13 ms at p99 by itself. On the VM 0.4.0's numbers came from, the same took
    0.42 ms and 3.6 ms, and the row was not met there. The row belongs to the disk as much as
    to MCPdef.
  - With sixteen clients, the `fsync`s overlap and share the disk's time. The gateway still
    answers 6,500–7,900 calls a second, against 11,100–16,500 without the mode.
- **Fourth row.** `mcpdef-sandbox` compiles a component once: 463–518 ms (glibc) for the
  201 KiB `echo` fixture. Each instance after that gets a store, a memory and a WASI context
  of its own.
  - Each instance takes 19–20 µs at p50 and 39–50 µs at p99. The first one after compiling
    takes 156–189 µs.
  - Dropping an instance is not timed.
  - This is measured in the harness's own process, through the sandbox's API. The gateway
    itself still makes one instance per server, when it starts the server, and reuses it.
    So the row says what a fresh instance per session, or per call, would cost.
  - The static column was measured before the build changes, on the VM 0.4.0's numbers came
    from, with the harness itself built static. The crates the sandbox runs in stay at
    `"z"`.

## What these numbers do not cover

- **TLS.** The listener served plain HTTP on loopback. TLS adds a handshake on each new
  connection and encryption on each message.
- **The rest of the governance step.** No policy rules, rate limits, inline inspection,
  transforms or pins were configured. Each one adds its own work to the calls it applies to.
- **Real servers and real networks.** The mock upstream answers at once, over loopback. A
  real server's own latency, often milliseconds to seconds, comes on top. That makes the
  gateway's share of the total smaller.
- **Other disks.** The fsync row belongs to this VM's disk. A laptop's NVMe drive, a network
  volume or a disk without a write cache will each give a different number.
- **A call into a WASM server.** Making an instance is measured; running a call in one is not.
- **A build from crates.io.** `cargo install mcpdef` builds with cargo's default release
  profile, not the workspace's.
- **Other machines.** Absolute numbers belong to the machine they were measured on, as the
  difference from 0.4.0's VM shows. To compare two machines, use ratios measured within one
  run, as `mcpdef-bench compare` does.

## Run it yourself

From a checkout of the source:

```sh
cargo build --release --locked -p mcpdef -p mcpdef-bench --features mcpdef-bench/wasm
./target/release/mcpdef-bench run --out glibc.json --note "what this machine is"
```

The `wasm` feature links the sandbox into the harness, for `wasm-instantiate`. Leave it out
to skip that scenario and build without Wasmtime. A full run takes about three minutes. It writes the JSON report to the `--out` file and prints
the Markdown report. To measure the static musl build as well:

```sh
# needs musl-gcc as well: the musl-tools package on Debian and Ubuntu
rustup target add x86_64-unknown-linux-musl
cargo build --release --locked -p mcpdef --target x86_64-unknown-linux-musl
./target/release/mcpdef-bench run --mcpdef target/x86_64-unknown-linux-musl/release/mcpdef \
    --out musl.json --note "static musl build"
```

To compare two reports from the same machine, for example before and after a change:

```sh
./target/release/mcpdef-bench compare --baseline before.json --current after.json \
    --require-comparable
```

To time README.md's commands to the first governed call, through the gateway and through a
hook, with the `mcpdef` beside the harness or the one `--mcpdef` names:

```sh
./target/release/mcpdef-bench first-call --runs 10 --out first-call.json
```

It needs port 7878 free: `mcpdef up` with no config listens there.

## How a change is held to it

In CI, every pull request that changes the engine is measured against the code it changes.
One job on one runner does this:

1. It builds the release `mcpdef` at the pull request's base and at its merge result.
2. It measures both with the merge result's harness, twice each and alternating: base, head,
   base, head.
3. It judges each metric on its best run on each side, since what disturbs a run only ever
   makes it slower. A ratio of the gateway over a direct call is judged by its parts: the
   gateway's best percentile over the direct call's best. A run whose direct calls were
   slowed would otherwise read a low ratio for a gateway that was no faster.
4. It fails the pull request if any of these happens:
   - a ratio regresses past its tolerance (the tolerances, and the run-to-run swing they were
     set from, are in the [harness's README](../crates/mcpdef-bench/README.md)). The
     16-client p99 ratios' tolerance is 100 %: on the gate's runner, two vCPUs shared by the
     clients, the gateway and the upstream, it moved by up to 83 % between runs of unchanged
     code;
   - idle resident memory exceeds 30 MB;
   - a slow neighbour's p99 ratio exceeds 1.5;
   - the release binary grows by more than 10 %.

All four runs come from the same runner, minutes apart, so the runner's speed cancels out.
The gate compares each change with the code before it, not with this page. A CI runner is
not the machine above. A change that is slower but within tolerance still passes.

The same job then runs `mcpdef-bench first-call` with the merge result's build. It fails the
pull request when a path takes longer than 60 s, or when a command does not do what README.md
says it does.

## The reports behind this page

The median run of each build is committed. Each report holds every percentile, the machine
and the run's parameters:

- `crates/mcpdef-bench/baselines/release-build-glibc.json`, every row but the static WASM one
- `crates/mcpdef-bench/baselines/release-build-static-musl.json`, the static gateway
- `crates/mcpdef-bench/baselines/wasm-instantiate-static-musl.json`, the WASM row with the
  harness itself built static, since the sandbox runs in the harness

The median run is the one whose added p99 for an allowed call with a token, with one client,
was the middle of the three.

[The first governed call](#the-first-governed-call)'s ten runs of each build are committed
whole: `first-call-static-musl.json` and `first-call-glibc.json`, in the same directory.

0.4.0's reports, from the VM its numbers came from, stay committed for the record:
`0.4.0-glibc.json` and `0.4.0-static-musl.json`, and the fsync and WASM rows' first
measurements, `audit-fsync-and-wasm-glibc.json` and `audit-fsync-static-musl.json`.
