// SPDX-License-Identifier: Apache-2.0
//! The audit API, against a running admin listener:
//!   * `GET /api/v1/audit` pages the ledger newest first, a cursor at a time,
//!     each record once, and filters it; `?limit` alone keeps the bare list;
//!   * `GET /api/v1/audit/{seq}` is one record;
//!   * `GET /api/v1/audit/verify` finds a record changed, records removed from
//!     the end, and a ledger replaced, and checks a seal kept elsewhere;
//!   * `GET /api/v1/audit/export` streams the formats `mcpdef audit tail`
//!     writes;
//!   * `GET /api/v1/audit/stream` sends records as they are appended, and
//!     resumes after `Last-Event-ID` without a gap or a repeat.

use mcpdef::connect::build_gateway;
use mcpdef::gateway::Gateway;
use mcpdef::{serve_admin_on, AdminState, Config, Metrics};
use mcpdef_audit::{Attrs, Entry, Kind, Ledger, Record};
use mcpdef_core::Decision;
use serde_json::Value;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const MOCK: &str = env!("CARGO_BIN_EXE_mock_mcp_server");

/// A task stopped however the test ends.
struct Aborted(tokio::task::JoinHandle<()>);

impl Drop for Aborted {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Record `i` of a test ledger: every third denied under `rule-<i % 2>`,
/// servers `a` to `c` in turn, tools `t0` to `t4`, every fifth an admin
/// record.
fn entry(i: u64) -> Entry {
    let admin = i % 5 == 4;
    Entry {
        agent: if admin { "mcpdef" } else { "agent:x" }.into(),
        server: ["a", "b", "c"][(i % 3) as usize].into(),
        method: Some("tools/call".into()),
        tool: Some(format!("t{}", i % 5)),
        decision: if i % 3 == 2 {
            Decision::Deny {
                rule: format!("rule-{}", i % 2),
                reason: String::new(),
            }
        } else {
            Decision::Allow
        },
        latency_ms: i,
        attrs: Attrs {
            kind: if admin { Kind::Admin } else { Kind::Call },
            ..Attrs::default()
        },
    }
}

/// A gateway whose ledger in `dir` already holds `records` records, and its
/// admin listener on a loopback port.
async fn start(dir: &Path, records: u64) -> (String, Gateway, Aborted) {
    let audit = dir.join("audit.log");
    let mut ledger = Ledger::open(&audit).unwrap();
    for i in 0..records {
        ledger.append(entry(i)).unwrap();
    }
    drop(ledger);
    let text = format!(
        "[gateway]\naudit = {audit:?}\nstate_dir = {state:?}\n\n\
         [gateway.admin]\nenabled = true\nlisten = \"127.0.0.1:0\"\n\n\
         [[server]]\nid = \"a\"\ntransport = \"stdio\"\ncommand = [{MOCK:?}]\ntools = [\"echo\"]\n",
        state = dir.join("state"),
    );
    std::fs::write(dir.join("mcpdef.toml"), text).unwrap();
    let cfg = Config::load(dir.join("mcpdef.toml")).unwrap();
    assert_eq!(cfg.validate(), Vec::<String>::new());
    let gw = build_gateway(&cfg).await.unwrap();
    let state = Arc::new(AdminState::new(
        &cfg,
        Arc::new(Metrics::new(1)),
        gw.clone(),
        "test",
    ));
    let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = bound.local_addr().unwrap();
    let serving = Aborted(tokio::spawn(async move {
        serve_admin_on(state, bound, None).await.unwrap();
    }));
    (format!("http://{addr}"), gw, serving)
}

fn client() -> reqwest::Client {
    mcpdef_transport::install_crypto_provider();
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// A GET's status, content type and body as JSON (or as a string).
async fn get(url: &str) -> (u16, String, Value) {
    let response = client().get(url).send().await.unwrap();
    let status = response.status().as_u16();
    let kind = response
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    let text = response.text().await.unwrap();
    let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, kind, body)
}

fn seqs(records: &Value) -> Vec<u64> {
    records
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["seq"].as_u64().unwrap())
        .collect()
}

/// Appends `n` records through the running gateway, as its admin API does.
async fn append(gw: &Gateway, n: u64, refused: Option<&str>) {
    for i in 0..n {
        gw.audit_admin(
            "local",
            "127.0.0.1:1",
            "test",
            &format!("s{i}"),
            None,
            refused,
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ten_thousand_records_page_over_http_each_once() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _gw, _serving) = start(dir.path(), 10_000).await;
    let (mut seen, mut cursor, mut pages) = (Vec::new(), String::new(), 0);
    loop {
        let (status, _, page) =
            get(&format!("{base}/api/v1/audit?cursor={cursor}&limit=500")).await;
        assert_eq!(status, 200, "{page}");
        seen.extend(seqs(&page["records"]));
        pages += 1;
        match page["next_cursor"].as_str() {
            Some(next) => cursor = next.to_string(),
            None => break,
        }
    }
    assert_eq!(pages, 20);
    assert_eq!(seen, (0..10_000).rev().collect::<Vec<_>>());

    // The first page by default is 50, and `limit` alone keeps the bare list.
    let (_, _, page) = get(&format!("{base}/api/v1/audit?cursor=")).await;
    assert_eq!(
        seqs(&page["records"]),
        (9950..10_000).rev().collect::<Vec<_>>()
    );
    let (_, _, list) = get(&format!("{base}/api/v1/audit?limit=3")).await;
    assert_eq!(seqs(&list), [9999, 9998, 9997]);
    let (_, _, list) = get(&format!("{base}/api/v1/audit")).await;
    assert_eq!(seqs(&list).len(), 100);
    let (_, _, list) = get(&format!("{base}/api/v1/audit?limit=5000")).await;
    assert_eq!(seqs(&list).len(), 1000);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_filter_takes_only_its_records() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _gw, _serving) = start(dir.path(), 60).await;
    // Each query, and which of the records `entry` makes it should take.
    type Wants = fn(u64) -> bool;
    let cases: [(&str, Wants); 8] = [
        ("decision=deny", |i| i % 3 == 2),
        ("server=b", |i| i % 3 == 1),
        ("tool=t3", |i| i % 5 == 3),
        ("agent=mcpdef", |i| i % 5 == 4),
        ("rule=rule-1", |i| i % 3 == 2 && i % 2 == 1),
        ("kind=admin", |i| i % 5 == 4),
        ("kind=call", |i| i % 5 != 4),
        ("decision=deny&server=c&tool=t0", |i| i % 15 == 5),
    ];
    for (query, wanted) in cases {
        let expected: Vec<u64> = (0..60).rev().filter(|i| wanted(*i)).collect();
        assert!(!expected.is_empty(), "{query}");
        // Five to a page, so that a filtered page goes on from its cursor.
        let (mut seen, mut cursor) = (Vec::new(), String::new());
        loop {
            let (status, _, page) = get(&format!(
                "{base}/api/v1/audit?{query}&limit=5&cursor={cursor}"
            ))
            .await;
            assert_eq!(status, 200, "{query}: {page}");
            seen.extend(seqs(&page["records"]));
            match page["next_cursor"].as_str() {
                Some(next) => cursor = next.to_string(),
                None => break,
            }
        }
        assert_eq!(seen, expected, "{query}");
    }
    // A filter alone pages too; the time filters bound by `ts_unix_ms`.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (_, _, page) = get(&format!("{base}/api/v1/audit?since={}", now + 3_600_000)).await;
    assert_eq!(seqs(&page["records"]), Vec::<u64>::new());
    assert!(page["next_cursor"].is_null());
    let (_, _, page) = get(&format!("{base}/api/v1/audit?until={}", now + 3_600_000)).await;
    assert_eq!(seqs(&page["records"]), (10..60).rev().collect::<Vec<_>>());
    let (_, _, page) = get(&format!("{base}/api/v1/audit?until=1")).await;
    assert_eq!(seqs(&page["records"]), Vec::<u64>::new());

    // What is not a query is refused, saying why.
    for query in [
        "decision=maybe",
        "since=yesterday",
        "until=-1",
        "cursor=nonsense",
        "cursor=3.4",
        "cursor=&limit=0",
        "cursor=&limit=501",
        "limit=many",
    ] {
        let (status, kind, problem) = get(&format!("{base}/api/v1/audit?{query}")).await;
        assert_eq!(
            (status, kind.as_str()),
            (400, "application/problem+json"),
            "{query}: {problem}"
        );
        assert!(problem["detail"].as_str().is_some(), "{query}: {problem}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_record_by_its_seq() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _gw, _serving) = start(dir.path(), 40).await;
    for seq in [0, 17, 39] {
        let (status, _, record) = get(&format!("{base}/api/v1/audit/{seq}")).await;
        assert_eq!((status, record["seq"].as_u64()), (200, Some(seq)));
        serde_json::from_value::<Record>(record).unwrap();
    }
    let (status, _, problem) = get(&format!("{base}/api/v1/audit/40")).await;
    assert_eq!(status, 404, "{problem}");
    assert_eq!(problem["detail"], "the ledger holds no record 40");
    let (status, _, _) = get(&format!("{base}/api/v1/audit/forty")).await;
    assert_eq!(status, 400);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verify_finds_a_change_a_cut_and_a_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let (base, gw, _serving) = start(dir.path(), 30).await;
    append(&gw, 2, None).await;
    let audit = dir.path().join("audit.log");
    let verify_url = format!("{base}/api/v1/audit/verify");
    let verify = || get(&verify_url);

    let (status, _, intact) = verify().await;
    assert_eq!(status, 200, "{intact}");
    assert_eq!(intact["ok"], true, "{intact}");
    assert_eq!(intact["records"], 32);
    assert_eq!(intact["against"]["kind"], "written");
    assert_eq!(intact["against"]["records"], 32);
    assert!(intact["reason"].is_null());
    let (head, original) = (
        intact["head"].as_str().unwrap().to_string(),
        std::fs::read_to_string(&audit).unwrap(),
    );

    // A seal from before the last two records still holds; a wrong one does
    // not, and half a seal is refused.
    let lines: Vec<&str> = original.lines().collect();
    let sealed: Value = serde_json::from_str(lines[29]).unwrap();
    let (_, _, report) = get(&format!(
        "{base}/api/v1/audit/verify?head={}&count=30",
        sealed["hash"].as_str().unwrap()
    ))
    .await;
    assert_eq!(
        (report["ok"].clone(), report["against"]["kind"].clone()),
        (true.into(), "seal".into()),
        "{report}"
    );
    let (_, _, report) = get(&format!("{base}/api/v1/audit/verify?head={head}&count=30")).await;
    assert_eq!(report["ok"], false, "{report}");
    assert_eq!(report["broken_at"], 29);
    assert_eq!(
        report["reason"],
        "record 29 is not the one the seal names: the ledger was replaced"
    );
    let (status, _, _) = get(&format!("{base}/api/v1/audit/verify?head={head}")).await;
    assert_eq!(status, 400);

    // One record changed.
    let changed = original.replacen("\"tool\":\"t2\"", "\"tool\":\"tX\"", 1);
    assert_ne!(changed, original);
    std::fs::write(&audit, &changed).unwrap();
    let (_, _, report) = verify().await;
    assert_eq!(
        (report["ok"].clone(), report["broken_at"].clone()),
        (false.into(), 2.into()),
        "{report}"
    );
    assert_eq!(report["reason"], "the chain breaks at record 2");

    // The last record removed: the chain holds, and the gateway knows better.
    let cut: String = lines[..31].iter().map(|l| format!("{l}\n")).collect();
    std::fs::write(&audit, cut).unwrap();
    let (_, _, report) = verify().await;
    assert_eq!(report["ok"], false, "{report}");
    assert_eq!(report["broken_at"], 31);
    assert_eq!(
        report["reason"],
        "the file holds 31 records, and this gateway wrote 32: records were removed from its end"
    );

    // Replaced by another chain as long.
    let other = tempfile::tempdir().unwrap();
    let mut forged = Ledger::open(other.path().join("audit.log")).unwrap();
    for i in 0..32 {
        forged.append(entry(i + 1)).unwrap();
    }
    std::fs::copy(other.path().join("audit.log"), &audit).unwrap();
    let (_, _, report) = verify().await;
    assert_eq!(report["ok"], false, "{report}");
    assert_eq!(
        report["reason"],
        "record 31 is not the one this gateway wrote: the ledger was replaced"
    );

    // Put back, it verifies again.
    std::fs::write(&audit, &original).unwrap();
    let (_, _, report) = verify().await;
    assert_eq!(report["ok"], true, "{report}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn export_streams_each_format() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _gw, _serving) = start(dir.path(), 25).await;
    let response = client()
        .get(format!("{base}/api/v1/audit/export?format=json"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let headers = response.headers().clone();
    assert_eq!(headers["content-type"], "application/x-ndjson");
    assert_eq!(
        headers["content-disposition"],
        "attachment; filename=\"mcpdef-audit.jsonl\""
    );
    let text = response.text().await.unwrap();
    let exported: Vec<Record> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(
        exported,
        mcpdef_audit::read_all(dir.path().join("audit.log")).unwrap()
    );

    let lines = |format: &str, query: &str| {
        let url = format!("{base}/api/v1/audit/export?format={format}{query}");
        async move {
            let text = client()
                .get(url)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            text.lines().map(str::to_string).collect::<Vec<_>>()
        }
    };
    let denied = lines("json", "&decision=deny").await;
    assert_eq!(denied.len(), 8);
    assert!(denied.iter().all(|l| l.contains("\"decision\":\"deny\"")));
    let cef = lines("cef", "").await;
    assert_eq!(cef.len(), 25);
    assert!(cef.iter().all(|l| l.starts_with("CEF:0|")), "{cef:?}");
    let syslog = lines("syslog", "").await;
    assert!(syslog.iter().all(|l| l.starts_with('<')), "{syslog:?}");
    let ocsf = lines("ocsf", "&server=a").await;
    assert_eq!(ocsf.len(), 9);
    for line in &ocsf {
        let event: Value = serde_json::from_str(line).unwrap();
        assert_eq!(event["class_uid"], 6003, "{event}");
    }
    let (status, _, problem) = get(&format!("{base}/api/v1/audit/export?format=pdf")).await;
    assert_eq!(status, 400);
    assert_eq!(
        problem["detail"],
        "format is one of json, ocsf, cef, syslog"
    );
}

/// Events from an SSE response, until `want` of them carry data or `wait`
/// passes: each as its `id` and its data, if any.
async fn events(
    response: &mut reqwest::Response,
    want: usize,
    wait: Duration,
) -> Vec<(Option<String>, Option<String>)> {
    let mut out: Vec<(Option<String>, Option<String>)> = Vec::new();
    let mut buffer = String::new();
    let deadline = tokio::time::Instant::now() + wait;
    while out.iter().filter(|(_, data)| data.is_some()).count() < want {
        let chunk = match tokio::time::timeout_at(deadline, response.chunk()).await {
            Ok(Ok(Some(chunk))) => chunk,
            _ => break,
        };
        buffer.push_str(std::str::from_utf8(&chunk).unwrap());
        while let Some(end) = buffer.find("\n\n") {
            let block: String = buffer.drain(..end + 2).collect();
            let (mut id, mut data) = (None, None);
            for line in block.lines() {
                if let Some(v) = line.strip_prefix("id:") {
                    id = Some(v.trim().to_string());
                } else if let Some(v) = line.strip_prefix("data:") {
                    data = Some(v.trim().to_string());
                }
            }
            if id.is_some() || data.is_some() {
                out.push((id, data));
            }
        }
    }
    out
}

fn ids(events: &[(Option<String>, Option<String>)]) -> Vec<u64> {
    events
        .iter()
        .filter(|(_, data)| data.is_some())
        .map(|(id, _)| id.as_deref().unwrap().parse().unwrap())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_stream_resumes_without_a_gap_or_a_repeat() {
    let dir = tempfile::tempdir().unwrap();
    let (base, gw, _serving) = start(dir.path(), 10).await;
    let wait = Duration::from_secs(10);

    // From the end: only what is appended after.
    let mut live = client()
        .get(format!("{base}/api/v1/audit/stream"))
        .send()
        .await
        .unwrap();
    assert_eq!(live.status().as_u16(), 200);
    assert_eq!(live.headers()["content-type"], "text/event-stream");
    append(&gw, 3, None).await;
    let first = events(&mut live, 3, wait).await;
    assert_eq!(ids(&first), [10, 11, 12]);
    for (id, data) in &first {
        if let Some(data) = data {
            let record: Record = serde_json::from_str(data).unwrap();
            assert_eq!(Some(record.seq.to_string()), *id);
        }
    }
    drop(live);

    // Gone a while, then back with the last id it had.
    append(&gw, 4, None).await;
    let mut back = client()
        .get(format!("{base}/api/v1/audit/stream"))
        .header("last-event-id", "12")
        .send()
        .await
        .unwrap();
    let missed = events(&mut back, 4, wait).await;
    assert_eq!(ids(&missed), [13, 14, 15, 16]);
    append(&gw, 2, None).await;
    assert_eq!(ids(&events(&mut back, 2, wait).await), [17, 18]);
    drop(back);

    // `?after=` is where a page left off, for a browser's first connection.
    let mut after = client()
        .get(format!("{base}/api/v1/audit/stream?after=7"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        ids(&events(&mut after, 11, wait).await),
        (8..19).collect::<Vec<_>>()
    );

    // Filtered: only refusals carry data, and the id still moves past the
    // rest, so coming back skips them rather than missing anything.
    let mut denials = client()
        .get(format!("{base}/api/v1/audit/stream?decision=deny"))
        .send()
        .await
        .unwrap();
    append(&gw, 1, Some("console-role")).await;
    append(&gw, 2, None).await;
    let mut seen = events(&mut denials, 1, wait).await;
    assert_eq!(ids(&seen), [19]);
    // The records passed over move the id on, without data.
    seen.extend(events(&mut denials, 1, Duration::from_millis(500)).await);
    assert_eq!(ids(&seen), [19]);
    let last = seen.iter().rev().find_map(|(id, _)| id.clone());
    assert_eq!(last.as_deref(), Some("21"), "{seen:?}");

    let (status, _, problem) = client_get_with(
        "last-event-id",
        "twelve",
        &format!("{base}/api/v1/audit/stream"),
    )
    .await;
    assert_eq!(status, 400, "{problem}");
}

async fn client_get_with(name: &str, value: &str, url: &str) -> (u16, String, Value) {
    let response = client().get(url).header(name, value).send().await.unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    (
        status,
        String::new(),
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}
