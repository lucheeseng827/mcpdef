// SPDX-License-Identifier: Apache-2.0
//! The context tax. Every agent that lists the tools reads the `tools/list`
//! answer into its context. `mcpdef tools list --cost` and the admin servers
//! view say what each server adds to it: how many of its tools are listed,
//! and the bytes they take up there, as the gateway lists them. That is after
//! the allowlist, the profile, the pins and the scanner, and with the name
//! each is listed by.

use mcpdef::connect::build_gateway;
use mcpdef::{
    serve_admin_on, AdminState, Config, Connect, Gateway, Metrics, Startup, Supervised, ToolCost,
    UpstreamOptions,
};
use mcpdef_audit::Ledger;
use mcpdef_core::wire::{meta_key, SPEC_2026_07_28};
use mcpdef_core::{method, Id, Message};
use mcpdef_pin::{tool_hash, PinStore};
use mcpdef_transport::{duplex_pair, Duplex, Transport};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_mcpdef");
const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

/// How long a test waits for the gateway. Far past what it needs, so a slow
/// machine does not fail a test that is right.
const PATIENCE: Duration = Duration::from_secs(10);

/// The definition an upstream lists for `name`.
fn tool(name: &str) -> Value {
    json!({
        "name": name,
        "description": format!("does {name}"),
        "inputSchema": { "type": "object" },
    })
}

/// An upstream that lists `tools`.
fn spawn(label: &str, tools: Vec<Value>) -> Duplex {
    let label = label.to_string();
    let (near, mut far) = duplex_pair();
    tokio::spawn(async move {
        while let Ok(Some(msg)) = far.recv().await {
            let Some(id) = msg.id.clone() else { continue };
            let reply = match msg.method().unwrap_or_default() {
                method::INITIALIZE => Message::result(
                    id,
                    json!({
                        "protocolVersion": "2025-11-25",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": label, "version": "0" },
                    }),
                ),
                method::TOOLS_LIST => Message::result(id, json!({ "tools": tools })),
                _ => Message::error(id, -32601, "method not found"),
            };
            if far.send(reply).await.is_err() {
                break;
            }
        }
    });
    near
}

/// Opens [`spawn`]'s upstream, listing the tools named, afresh for every
/// start.
fn serving(label: &str, names: &[&str]) -> Connect {
    let label = label.to_string();
    let tools: Vec<Value> = names.iter().map(|name| tool(name)).collect();
    Arc::new(move || {
        let up = spawn(&label, tools.clone());
        Box::pin(async move { Ok(Box::new(up) as Box<dyn Transport>) })
    })
}

/// An upstream that never opens.
fn refused() -> Connect {
    Arc::new(|| {
        Box::pin(async { Err::<Box<dyn Transport>, _>(anyhow::anyhow!("connection refused")) })
    })
}

/// A `[[server]]` table: a stdio server that is never started here, with
/// `extra` lines.
fn server(id: &str, extra: &str) -> String {
    format!("[[server]]\nid = {id:?}\ntransport = \"stdio\"\ncommand = [\"unused\"]\n{extra}\n\n")
}

fn cost(id: &str, offered: usize, listed: usize, bytes: usize) -> ToolCost {
    ToolCost {
        id: id.into(),
        offered,
        listed,
        bytes,
    }
}

struct Setup {
    gw: Gateway,
    cfg: Config,
    _dir: TempDir,
}

impl Setup {
    /// A gateway as `build_gateway` makes it from `[gateway]` and `config`,
    /// over in-process upstreams. One that does not open is left down.
    async fn new(config: &str, upstreams: Vec<(&str, Connect)>) -> Self {
        Self::pinned(config, upstreams, None).await
    }

    async fn pinned(config: &str, upstreams: Vec<(&str, Connect)>, pins: Option<PinStore>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcpdef.toml");
        std::fs::write(&path, format!("[gateway]\n{config}")).unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.validate(), Vec::<String>::new());
        let ledger = Ledger::open(dir.path().join("audit.log")).unwrap();
        let mut gw = Gateway::new(cfg.to_policy(), ledger, "agent:test")
            .with_rbac(Some(cfg.rbac()))
            .with_policy_rules(cfg.policy_rules())
            .with_tool_prefixes(cfg.tool_prefixes());
        if let Some(store) = pins {
            let path = dir.path().join("pins.toml");
            store.save(&path).unwrap();
            gw = gw.with_pins(PinStore::load(&path).unwrap(), path);
        }
        let servers = upstreams
            .into_iter()
            .map(|(id, connect)| Supervised {
                id: id.into(),
                connect,
                options: UpstreamOptions::default(),
            })
            .collect();
        gw.start_supervised(servers, Startup::Degraded)
            .await
            .unwrap();
        Setup { gw, cfg, _dir: dir }
    }

    /// The gateway's answer to `tools/list`.
    async fn list(&self) -> Message {
        list(&self.gw, None).await
    }
}

async fn list(gw: &Gateway, params: Option<Value>) -> Message {
    gw.handle(Message::request(Id::Num(7), method::TOOLS_LIST, params))
        .await
        .unwrap()
        .unwrap()
}

/// The tools in a `tools/list` answer.
fn tools(answer: &Message) -> &Vec<Value> {
    answer.result.as_ref().expect("a list")["tools"]
        .as_array()
        .expect("tools")
}

/// What each server's tools come to in `answer` as it is sent: (server, how
/// many, their bytes), by the server each names. The bytes are each entry's
/// in the answer as it is serialized, which this checks.
fn carried(answer: &Message) -> Vec<(String, usize, usize)> {
    let entries: Vec<String> = tools(answer).iter().map(Value::to_string).collect();
    // The answer as a client gets it holds each entry, serialized so, and
    // nothing between them but commas.
    assert!(
        answer
            .to_json_line()
            .contains(&format!("\"tools\":[{}]", entries.join(","))),
        "{}",
        answer.to_json_line()
    );
    let mut out: Vec<(String, usize, usize)> = Vec::new();
    for (tool, entry) in tools(answer).iter().zip(&entries) {
        let server = tool["_meta"]["mcpdef/server"].as_str().unwrap().to_string();
        match out.iter_mut().find(|(id, ..)| *id == server) {
            Some((_, listed, bytes)) => {
                *listed += 1;
                *bytes += entry.len();
            }
            None => out.push((server, 1, entry.len())),
        }
    }
    out
}

/// The listed count and bytes of each server `tool_costs` names that lists
/// anything, as [`carried`] gives them.
fn counted(costs: &[ToolCost]) -> Vec<(String, usize, usize)> {
    costs
        .iter()
        .filter(|cost| cost.listed > 0)
        .map(|cost| (cost.id.clone(), cost.listed, cost.bytes))
        .collect()
}

/// The serialized size of what `answer` lists as `name`.
fn size_of(answer: &Message, name: &str) -> usize {
    tools(answer)
        .iter()
        .find(|t| t["name"] == name)
        .unwrap_or_else(|| panic!("'{name}' is not listed"))
        .to_string()
        .len()
}

#[tokio::test]
async fn each_servers_bytes_are_its_tools_as_the_answer_carries_them() {
    let config = server("gh", "")
        + &server("fs", "tools = [\"read_*\"]")
        + &server("wiki", "tools = [\"none_*\"]")
        + &server("down", "");
    let s = Setup::new(
        &config,
        vec![
            ("gh", serving("gh", &["create_issue", "list_issues"])),
            (
                "fs",
                serving("fs", &["read_file", "write_file", "read_dir"]),
            ),
            ("wiki", serving("wiki", &["search"])),
            ("down", refused()),
        ],
    )
    .await;
    let answer = s.list().await;
    let carried = carried(&answer);

    let costs = s.gw.tool_costs();
    assert_eq!(counted(&costs), carried);
    assert_eq!(
        costs,
        [
            cost("gh", 2, 2, carried[0].2),
            cost("fs", 3, 2, carried[1].2),
            cost("wiki", 1, 0, 0),
            cost("down", 0, 0, 0),
        ]
    );
    // All of them, with the brackets and the commas between, are the list.
    let listed = serde_json::to_string(tools(&answer)).unwrap().len();
    let bytes: usize = costs.iter().map(|cost| cost.bytes).sum();
    assert_eq!(listed, bytes + 2 + (4 - 1));
    // Each entry names its server, so it costs more than the upstream's own
    // definition.
    assert!(size_of(&answer, "read_file") > tool("read_file").to_string().len());
}

#[tokio::test]
async fn a_profile_cuts_what_each_server_adds() {
    let profile = "[profile.readonly]\ntools = [\"get_*\", \"list_*\"]\n\n";
    let servers = server("gh", "") + &server("fs", "");
    let upstreams = || {
        vec![
            (
                "gh",
                serving(
                    "gh",
                    &["get_issue", "list_issues", "create_issue", "delete_repo"],
                ),
            ),
            ("fs", serving("fs", &["list_files", "write_file"])),
        ]
    };
    let whole = Setup::new(&format!("{profile}{servers}"), upstreams()).await;
    let cut = Setup::new(
        &format!("profile = \"readonly\"\n{profile}{servers}"),
        upstreams(),
    )
    .await;
    let (before, after) = (whole.gw.tool_costs(), cut.gw.tool_costs());
    let listed = whole.list().await;

    assert_eq!(counted(&after), carried(&cut.list().await));
    // Each offers what it did. The profile takes the tools it does not name
    // out of the list, and their bytes out of the count.
    assert_eq!(
        after,
        [
            cost(
                "gh",
                4,
                2,
                before[0].bytes
                    - size_of(&listed, "create_issue")
                    - size_of(&listed, "delete_repo")
            ),
            cost("fs", 2, 1, before[1].bytes - size_of(&listed, "write_file")),
        ]
    );
    assert_eq!(
        before,
        [
            cost("gh", 4, 4, before[0].bytes),
            cost("fs", 2, 2, before[1].bytes)
        ]
    );
}

#[tokio::test]
async fn a_tool_is_counted_by_the_name_it_is_listed_by() {
    let servers = server("gh", "") + &server("fs", "prefix = \"files\"");
    let upstreams = || {
        vec![
            ("gh", serving("gh", &["create_issue", "search"])),
            ("fs", serving("fs", &["read_file"])),
        ]
    };
    let plain = Setup::new(&servers, upstreams()).await;
    let prefixed = Setup::new(
        &format!("tool_namespace = \"prefix\"\n\n{servers}"),
        upstreams(),
    )
    .await;
    let (before, after) = (plain.gw.tool_costs(), prefixed.gw.tool_costs());

    assert_eq!(counted(&after), carried(&prefixed.list().await));
    assert_eq!(after[0].bytes, before[0].bytes + 2 * "gh__".len());
    assert_eq!(after[1].bytes, before[1].bytes + "files__".len());
}

#[tokio::test]
async fn a_name_listed_from_another_server_is_counted_there_only() {
    let config = server("a", "") + &server("b", "");
    let s = Setup::new(
        &config,
        vec![
            ("a", serving("a", &["echo", "a_only"])),
            ("b", serving("b", &["echo", "b_only"])),
        ],
    )
    .await;
    let answer = s.list().await;

    let costs = s.gw.tool_costs();
    assert_eq!(counted(&costs), carried(&answer));
    assert_eq!(
        costs,
        [
            cost(
                "a",
                2,
                2,
                size_of(&answer, "echo") + size_of(&answer, "a_only")
            ),
            cost("b", 2, 1, size_of(&answer, "b_only")),
        ]
    );
}

#[tokio::test]
async fn a_tool_hidden_for_drifting_from_its_pin_is_not_counted() {
    let mut pins = PinStore::default();
    pins.record(
        "a",
        "echo",
        tool_hash(&json!({ "name": "echo", "description": "before" })),
    );
    let s = Setup::pinned(
        &server("a", ""),
        vec![("a", serving("a", &["echo", "lookup"]))],
        Some(pins),
    )
    .await;
    let answer = s.list().await;

    assert_eq!(s.gw.drift_count(), 1);
    assert_eq!(
        s.gw.tool_costs(),
        [cost("a", 2, 1, size_of(&answer, "lookup"))]
    );
}

/// A 2026-07-28 client's answer carries more than the tools, but the tools
/// themselves are the same bytes.
#[tokio::test]
async fn a_2026_07_28_client_is_listed_the_same_tools() {
    let s = Setup::new(&server("a", ""), vec![("a", serving("a", &["echo"]))]).await;
    let legacy = s.list().await;
    let modern = list(
        &s.gw,
        Some(json!({ "_meta": { meta_key::PROTOCOL_VERSION: SPEC_2026_07_28 } })),
    )
    .await;

    assert_eq!(modern.result.as_ref().unwrap()["resultType"], "complete");
    assert_eq!(tools(&modern), tools(&legacy));
    assert_eq!(counted(&s.gw.tool_costs()), carried(&modern));
}

/// The gateway from `config` as `mcpdef run` builds it: the mock, listing
/// every tool it has, adds `add_tool`, which adds a tool to what it lists.
#[tokio::test]
async fn the_count_follows_a_re_list() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcpdef.toml");
    let audit = dir.path().join("audit.log");
    std::fs::write(
        &path,
        format!(
            "[gateway]\naudit = {audit:?}\n\n[[server]]\nid = \"mock\"\ntransport = \
             \"stdio\"\ncommand = [{MOCK:?}, \"--grows\"]\n"
        ),
    )
    .unwrap();
    let gw = build_gateway(&Config::load(&path).unwrap()).await.unwrap();
    let before = gw.tool_costs();
    assert_eq!(counted(&before), carried(&list(&gw, None).await));
    assert_eq!((before[0].offered, before[0].listed), (3, 3));

    let reply = gw
        .handle(Message::request(
            Id::Num(8),
            method::TOOLS_CALL,
            Some(json!({ "name": "add_tool", "arguments": { "name": "fresh" } })),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        reply.result.as_ref().unwrap()["isError"],
        false,
        "{reply:?}"
    );
    let until = Instant::now() + PATIENCE;
    while gw.tool_costs() == before {
        assert!(Instant::now() < until, "the tools were not listed again");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let answer = list(&gw, None).await;
    assert_eq!(
        gw.tool_costs(),
        [cost(
            "mock",
            4,
            4,
            before[0].bytes + size_of(&answer, "fresh")
        )]
    );
    assert_eq!(counted(&gw.tool_costs()), carried(&answer));
}

/// `GET /api/v1/servers` from an admin listener over `s`'s gateway.
async fn admin_servers(s: &Setup) -> Value {
    let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap().to_string();
    let state = Arc::new(AdminState::new(
        &s.cfg,
        Arc::new(Metrics::new(s.cfg.servers.len() as u64)),
        s.gw.clone(),
        "test",
    ));
    tokio::spawn(serve_admin_on(state, bound, None));
    mcpdef_transport::install_crypto_provider();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        match client
            .get(format!("http://{listen}/api/v1/servers"))
            .send()
            .await
        {
            Ok(response) => return serde_json::from_str(&response.text().await.unwrap()).unwrap(),
            Err(e) if Instant::now() > until => panic!("{e}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
}

#[tokio::test]
async fn the_admin_servers_view_carries_what_each_server_adds() {
    let config = server("gh", "tools = [\"list_*\"]") + &server("down", "");
    let s = Setup::new(
        &config,
        vec![
            ("gh", serving("gh", &["list_issues", "delete_repo"])),
            ("down", refused()),
        ],
    )
    .await;
    let answer = s.list().await;
    let view = admin_servers(&s).await;

    assert_eq!(
        view[0]["listing"],
        json!({ "offered": 2, "listed": 1, "bytes": size_of(&answer, "list_issues") })
    );
    assert_eq!(
        view[1]["listing"],
        json!({ "offered": 0, "listed": 0, "bytes": 0 })
    );
}

/// A config in `dir` whose servers are the mock: `[gateway]` holds `gateway`,
/// and each server is (id, the mock's flags, extra lines).
fn mock_config(dir: &Path, gateway: &str, servers: &[(&str, &[&str], &str)]) -> PathBuf {
    let audit = dir.join("audit.log");
    let mut text = format!("[gateway]\naudit = {audit:?}\n{gateway}\n\n");
    for (id, flags, extra) in servers {
        let command: Vec<String> = std::iter::once(MOCK)
            .chain(flags.iter().copied())
            .map(|arg| format!("{arg:?}"))
            .collect();
        text += &format!(
            "[[server]]\nid = {id:?}\ntransport = \"stdio\"\ncommand = [{}]\n{extra}\n\n",
            command.join(", ")
        );
    }
    let path = dir.join("mcpdef.toml");
    std::fs::write(&path, text).unwrap();
    path
}

/// `mcpdef` run with `args`: its standard output, having checked it
/// succeeded.
fn mcpdef(args: &[&str], config: &Path) -> String {
    let out = Command::new(BIN)
        .args(args)
        .arg("--config")
        .arg(config)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// Each row of `tools list --cost`: (server, tools, bytes, tokens).
fn cost_rows(stdout: &str) -> Vec<(String, String, usize, String)> {
    stdout
        .lines()
        .filter_map(
            |line| match line.split_whitespace().collect::<Vec<_>>().as_slice() {
                [server, listed, "of", offered, bytes, tokens] => Some((
                    server.to_string(),
                    format!("{listed} of {offered}"),
                    bytes.parse().ok()?,
                    tokens.to_string(),
                )),
                _ => None,
            },
        )
        .collect()
}

/// Each line `from` writes, as it comes.
fn lines_of(from: impl std::io::Read + Send + 'static) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(from).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// A child process, killed once the test is done with it, pass or fail.
struct Running(std::process::Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The line `mcpdef run` sends a stdio client that lists the tools, as it
/// is sent.
fn listed_over_stdio(config: &Path) -> String {
    let mut child = Command::new(BIN)
        .args(["run", "--config"])
        .arg(config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = lines_of(child.stdout.take().unwrap());
    let stderr = lines_of(child.stderr.take().unwrap());
    let _running = Running(child);
    let mut answer = |msg: Message| {
        writeln!(stdin, "{}", msg.to_json_line()).unwrap();
        stdin.flush().unwrap();
        let Some(id) = msg.id.clone() else {
            return String::new();
        };
        loop {
            let line = stdout.recv_timeout(PATIENCE).unwrap_or_else(|_| {
                panic!(
                    "no answer from the gateway; it said {:?}",
                    stderr.try_iter().collect::<Vec<_>>()
                )
            });
            if Message::from_json_line(&line).unwrap().id == Some(id.clone()) {
                return line;
            }
        }
    };
    answer(Message::request(
        Id::Num(1),
        method::INITIALIZE,
        Some(json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "cost", "version": "0" },
        })),
    ));
    answer(Message::notification(method::INITIALIZED, None));
    answer(Message::request(Id::Num(2), method::TOOLS_LIST, None))
}

/// The bytes `--cost` prints for each server are what its tools take up in
/// the line `mcpdef run` sends a client.
#[test]
fn the_cli_counts_the_bytes_run_sends() {
    let dir = tempfile::tempdir().unwrap();
    let config = mock_config(
        dir.path(),
        "",
        &[
            ("a", &[], ""),
            ("b", &["--tool-prefix", "b_"], "tools = [\"b_echo\"]"),
        ],
    );
    let line = listed_over_stdio(&config);
    let sent = carried(&Message::from_json_line(&line).unwrap());
    // Re-serialized, the answer is the line as sent, byte for byte.
    assert_eq!(Message::from_json_line(&line).unwrap().to_json_line(), line);

    let stdout = mcpdef(&["tools", "list", "--cost"], &config);
    let (a, b) = (sent[0].2, sent[1].2);
    let tokens = |bytes: usize| format!("~{}", (bytes + 2) / 4);
    assert_eq!(
        cost_rows(&stdout),
        [
            ("a".to_string(), "2 of 2".to_string(), a, tokens(a)),
            ("b".to_string(), "1 of 2".to_string(), b, tokens(b)),
            (
                "total".to_string(),
                "3 of 4".to_string(),
                a + b,
                tokens(a + b)
            ),
        ],
        "{stdout}"
    );
    assert!(
        stdout.contains("~TOKENS is BYTES ÷ 4, an estimate"),
        "{stdout}"
    );
}

#[test]
fn the_cli_shows_a_profiles_cut() {
    let dir = tempfile::tempdir().unwrap();
    let config = mock_config(
        dir.path(),
        "\n[profile.safe]\ntools = [\"echo\"]",
        &[("mock", &[], "")],
    );
    // What the mock lists, each as the gateway sends it.
    let entry = |name: &str, description: &str| {
        json!({
            "name": name,
            "description": description,
            "inputSchema": { "type": "object" },
            "_meta": { "mcpdef/server": "mock" },
        })
        .to_string()
        .len()
    };
    let echo = entry("echo", "echo arguments back");
    let delete_repo = entry("delete_repo", "destructive");

    let whole = mcpdef(&["tools", "list", "--cost"], &config);
    let cut = mcpdef(&["tools", "list", "--cost", "--profile", "safe"], &config);
    assert_eq!(
        whole.lines().take(2).collect::<Vec<_>>(),
        [
            "SERVER       TOOLS           BYTES   ~TOKENS".to_string(),
            format!(
                "mock         2 of 2       {:>8} {:>9}",
                echo + delete_repo,
                format!("~{}", (echo + delete_repo + 2) / 4)
            ),
        ],
        "{whole}"
    );
    assert_eq!(
        cut.lines().nth(1),
        Some(
            format!(
                "mock         1 of 2       {echo:>8} {:>9}",
                format!("~{}", (echo + 2) / 4)
            )
            .as_str()
        ),
        "{cut}"
    );
    assert!(!whole.contains("listed under"), "{whole}");
    assert!(
        cut.contains("listed under the gateway profile 'safe'"),
        "{cut}"
    );

    // The list itself is cut the same.
    let listed = mcpdef(&["tools", "list", "--profile", "safe"], &config);
    assert_eq!(
        listed.lines().take(3).collect::<Vec<_>>(),
        ["SERVER       TOOL", "mock         echo", "1 tool(s) listed"],
        "{listed}"
    );
}

#[test]
fn the_cli_lists_each_tool_by_the_name_it_is_listed_by() {
    let dir = tempfile::tempdir().unwrap();
    let config = mock_config(
        dir.path(),
        "tool_namespace = \"prefix\"",
        &[("mock", &[], "prefix = \"m\"\ndeny = [\"delete_*\"]")],
    );
    assert_eq!(
        mcpdef(&["tools", "list"], &config),
        "SERVER       TOOL\nmock         m__echo\n1 tool(s) listed\n"
    );
}

#[test]
fn the_cli_names_a_server_that_did_not_open() {
    let dir = tempfile::tempdir().unwrap();
    let config = mock_config(dir.path(), "", &[("mock", &[], "")]);
    let missing = dir.path().join("no-such-server");
    let text = std::fs::read_to_string(&config).unwrap()
        + &format!(
            "[[server]]\nid = \"gone\"\ntransport = \"stdio\"\ncommand = [{:?}]\n",
            missing.display().to_string()
        );
    std::fs::write(&config, text).unwrap();

    let stdout = mcpdef(&["tools", "list", "--cost"], &config);
    let rows = cost_rows(&stdout);
    assert_eq!(rows[1], ("gone".into(), "0 of 0".into(), 0, "~0".into()));
    assert!(stdout.contains("server 'gone' is down\n"), "{stdout}");
    assert!(!stdout.contains("server 'mock' is"), "{stdout}");
}
