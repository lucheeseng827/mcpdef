// SPDX-License-Identifier: Apache-2.0
/* MCPdef console — Audit log. The ledger a page at a time, newest first,
 * filtered by the gateway; a record's detail; the chain verified by the
 * gateway; an export of what the filters take; and the live tail, each record
 * as it is appended. (/audit, /audit/{seq}, /audit/verify, /audit/export,
 * /audit/stream) */
import React from "react";
import { Card, DataTable, Badge, Tag, Input, Select, Switch, Button, Modal, TokenPill, PageHeader, Icon, EmptyState } from "../ds";
import * as H from "../helpers.js";
import { auditPage, auditRecord, exportUrl, streamUrl, verifyLedger, record } from "../api/client.js";

const KINDS = ["all", "call", "admin", "reload", "upstream"];
const FORMATS = [["json", "JSON lines"], ["ocsf", "OCSF"], ["cef", "CEF"], ["syslog", "syslog"]];
/** The most records the live tail keeps on screen. */
const TAIL_KEPT = 500;

/** The filters a text box edits, applied once typing stops. */
function useSettled(value, ms = 350) {
  const [settled, setSettled] = React.useState(value);
  React.useEffect(() => {
    const id = setTimeout(() => setSettled(value), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return settled;
}

export default function AuditLog({ data }) {
  const D = data;
  const [decision, setDecision] = React.useState("all");
  const [server, setServer] = React.useState("all");
  const [kind, setKind] = React.useState("all");
  const [agentText, setAgent] = React.useState("");
  const [toolText, setTool] = React.useState("");
  const [ruleText, setRule] = React.useState("");
  const agent = useSettled(agentText.trim());
  const tool = useSettled(toolText.trim());
  const rule = useSettled(ruleText.trim());
  const filters = React.useMemo(
    () => ({ decision, server, kind, agent, tool, rule }),
    [decision, server, kind, agent, tool, rule]
  );

  const [rows, setRows] = React.useState([]);
  const [next, setNext] = React.useState(null);
  const [loading, setLoading] = React.useState(true);
  const [failed, setFailed] = React.useState(null);
  const [live, setLive] = React.useState(false);
  const [sel, setSel] = React.useState(null);
  const [verified, setVerified] = React.useState(null);
  const [exporting, setExporting] = React.useState(false);

  // The first page, again each time the filters change.
  React.useEffect(() => {
    let current = true;
    setLoading(true);
    setFailed(null);
    auditPage(filters)
      .then((page) => { if (current) { setRows(page.records); setNext(page.next); } })
      .catch((e) => { if (current) setFailed(e.detail || e.message || String(e)); })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [filters]);

  // The newest record on screen: the live tail goes on from it. Kept as rows
  // are committed, not as they render, which React may do and throw away;
  // this runs before the tail's effect in the same commit.
  const newest = React.useRef(null);
  React.useEffect(() => {
    newest.current = rows.length ? rows[0].seq : null;
  }, [rows]);

  // The live tail: each record the filters take, as it is appended after the
  // newest on screen, so that none written since the page was read is
  // missed. It opens once the page is read, and again after each page.
  React.useEffect(() => {
    if (!live || loading) return undefined;
    const stream = new EventSource(streamUrl(filters, newest.current ?? undefined));
    stream.onmessage = (e) => {
      if (!e.data) return;
      const r = record(JSON.parse(e.data));
      setRows((now) => (now.some((x) => x.seq === r.seq) ? now : [r, ...now].slice(0, TAIL_KEPT)));
    };
    return () => stream.close();
  }, [live, filters, loading]);

  const older = () => {
    setLoading(true);
    auditPage(filters, next)
      .then((page) => {
        setRows((now) => [...now, ...page.records.filter((r) => !now.some((x) => x.seq === r.seq))]);
        setNext(page.next);
      })
      .catch((e) => setFailed(e.detail || e.message || String(e)))
      .finally(() => setLoading(false));
  };

  const open = (r) => {
    setSel({ record: r, pending: true });
    auditRecord(r.seq)
      .then((full) => setSel({ record: full }))
      .catch((e) => setSel({ record: r, error: e.detail || e.message || String(e) }));
  };

  const verify = () => {
    setVerified({ pending: true });
    verifyLedger()
      .then((report) => setVerified({ report }))
      .catch((e) => setVerified({ error: e.detail || e.message || String(e) }));
  };

  return (
    <div>
      <PageHeader
        title="Audit log"
        sub={D.info
          ? <>{H.grouped(D.info.chainRecords)} records · head <span className="mono">{D.info.chainHead}</span></>
          : "the gateway's tamper-evident ledger"}
        actions={<>
          <Switch checked={live} onChange={setLive} label="Live tail" />
          <Button size="sm" icon={<Icon name="shield" />} onClick={verify}>Verify</Button>
          <Button size="sm" variant="primary" icon={<Icon name="external" />} onClick={() => setExporting(true)}>Export</Button>
        </>}
      />

      <Card style={{ marginBottom: 14 }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, alignItems: "end" }}>
          <Select label="Decision" value={decision} onChange={(e) => setDecision(e.target.value)} options={["all", "allow", "deny"]} />
          <Select label="Kind" value={kind} onChange={(e) => setKind(e.target.value)} options={KINDS} />
          <Select label="Server" value={server} onChange={(e) => setServer(e.target.value)}
            options={["all", ...D.servers.map((s) => s.id), "(console)", "(config)"]} />
          <Input label="Agent" placeholder="sub:ann, key:ci-bot…" mono value={agentText} onChange={(e) => setAgent(e.target.value)} />
          <Input label="Tool" placeholder="list_issues" mono value={toolText} onChange={(e) => setTool(e.target.value)} />
          <Input label="Rule" placeholder="allowlist, rug-pull…" mono value={ruleText} onChange={(e) => setRule(e.target.value)} />
        </div>
        {live && (
          <div role="status" style={{ marginTop: 12, display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "var(--eg-muted)" }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: "var(--eg-good)", boxShadow: "0 0 0 3px var(--eg-good-fill)" }} />
            Streaming from <span className="mono">/audit/stream</span>: each record the filters take appears on top as it is written.
          </div>
        )}
      </Card>

      <Card padded={false}>
        {failed ? (
          <div style={{ padding: 24 }}>
            <EmptyState icon={<Icon name="alert-triangle" size={20} />} title="Couldn't read the ledger">{failed}</EmptyState>
          </div>
        ) : !loading && rows.length === 0 ? (
          <div style={{ padding: 24 }}>
            <EmptyState icon={<Icon name="list" size={20} />} title="No records match">Clear a filter to widen the view.</EmptyState>
          </div>
        ) : (
          <DataTable
            columns={[
              { header: "seq", width: "64px", cell: (r) => <span className="mono" style={{ color: "var(--eg-muted)" }}>{r.seq}</span> },
              { header: "time", width: "160px", cell: (r) => <span className="mono" style={{ fontSize: 12, color: "var(--eg-faint)" }}>{H.fmtTime(r.ts)}</span> },
              { header: "kind", width: "76px", cell: (r) => <span className="mono" style={{ fontSize: 12, color: "var(--eg-muted)" }}>{r.kind || "call"}</span> },
              { header: "who", cell: (r) => <span className="mono" style={{ fontSize: 12 }}>{r.kind === "admin" || r.kind === "reload" ? r.actor || r.agent : r.agent}</span> },
              { header: "what", width: "1.4fr", cell: (r) => <What r={r} /> },
              { header: "rule", cell: (r) => r.rule ? <span className="mono" style={{ color: r.decision === "deny" ? "var(--eg-danger)" : "var(--eg-muted)", fontSize: 12 }}>{r.rule}</span> : <span style={{ color: "var(--eg-faint)" }}>—</span> },
              { header: "decision", width: "92px", align: "right", cell: (r) => <Decision value={r.decision} /> },
            ]}
            rows={rows}
            rowKey={(r) => r.seq}
            onRowClick={open}
          />
        )}
        {next && !failed && (
          <div style={{ padding: 12, display: "flex", justifyContent: "center", borderTop: "1px solid var(--eg-border-soft)" }}>
            <Button size="sm" icon={<Icon name="clock" />} onClick={older} disabled={loading}>{loading ? "Reading…" : "Older records"}</Button>
          </div>
        )}
      </Card>

      {sel && <RecordDetail sel={sel} onClose={() => setSel(null)} />}

      {exporting && (
        <Modal open onClose={() => setExporting(false)} width={460} title="Export the records these filters take"
          footer={<Button onClick={() => setExporting(false)}>Close</Button>}>
          <div style={{ fontSize: 13, color: "var(--eg-muted)", marginBottom: 12 }}>
            Every record, first to last, as <span className="mono">mcpdef audit tail --format</span> writes it.
          </div>
          <div style={{ display: "grid", gap: 8 }}>
            {FORMATS.map(([format, label]) => (
              <a key={format} href={exportUrl(format, filters)} download className="mono"
                style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--eg-fg)", fontSize: 13 }}>
                <Icon name="external" size={14} /> {label}
              </a>
            ))}
          </div>
        </Modal>
      )}

      {verified && (
        <Modal open onClose={() => setVerified(null)} width={480}
          title={verified.pending ? "Verifying the ledger…" : verified.report && verified.report.ok ? "Ledger verified" : "Ledger not verified"}
          footer={<Button variant="primary" onClick={() => setVerified(null)}>Done</Button>}>
          {verified.report && (
            <>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
                <span style={{ color: verified.report.ok ? "var(--eg-good)" : "var(--eg-danger)", display: "inline-flex" }}>
                  <Icon name={verified.report.ok ? "check" : "alert-triangle"} size={20} />
                </span>
                <span style={{ fontSize: 14 }}>
                  {verified.report.ok
                    ? <>Chain intact: {H.grouped(verified.report.records)} records, and every record this gateway wrote is there</>
                    : verified.report.reason}
                </span>
              </div>
              <TokenPill value={`head=${(verified.report.head || "").slice(0, 16)}… · records=${verified.report.records}`} />
            </>
          )}
          {verified.error && <div style={{ fontSize: 14 }}>{verified.error}</div>}
          <div style={{ fontSize: 12, color: "var(--eg-faint)", marginTop: 10 }}>
            The gateway checks every record's hash and link, as <span className="mono">mcpdef audit verify</span> does, and that the file still holds what it wrote.
          </div>
        </Modal>
      )}
    </div>
  );
}

/** Allow or deny, by icon and word, never colour alone. */
export function Decision({ value }) {
  const deny = value === "deny";
  return (
    <Badge tone={deny ? "danger" : "good"}>
      <Icon name={deny ? "x" : "check"} size={12} style={{ verticalAlign: "-2px", marginRight: 4 }} />
      {value}
    </Badge>
  );
}

/** What a record is about: a call's server and tool, a read's URI, an
 * action and its target; and the transform rules that fired. */
function What({ r }) {
  const subject = r.uri ? <span className="mono" style={{ fontSize: 12 }}>{r.uri}</span>
    : r.tool ? <Tag>{r.tool}</Tag>
    : <span className="mono" style={{ fontSize: 12 }}>{r.method || "—"}</span>;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
      <span style={{ color: "var(--eg-faint)" }}>{r.server} · </span>
      {subject}
      {(r.transforms || []).map((t) => <Tag key={t} tone="brand" title="a transform rule that fired">{t}</Tag>)}
    </span>
  );
}

function RecordDetail({ sel, onClose }) {
  const r = sel.record;
  const changes = r.tool_changes;
  return (
    <Modal open onClose={onClose} width={600}
      title={<span>Record <span className="mono" style={{ color: "var(--eg-muted)", fontWeight: 500 }}>#{r.seq}</span></span>}
      footer={<Button onClick={onClose}>Close</Button>}>
      <div style={{ display: "flex", gap: 8, margin: "2px 0 14px", flexWrap: "wrap" }}>
        <Decision value={r.decision} />
        {r.rule && <Badge tone={r.decision === "deny" ? "danger" : "default"}>{r.rule}</Badge>}
        <Badge tone="default">{r.kind || "call"}</Badge>
        {sel.pending && <Badge tone="default">reading…</Badge>}
      </div>
      {sel.error && <div style={{ fontSize: 13, color: "var(--eg-danger)", marginBottom: 10 }}>{sel.error}</div>}
      <Field k="agent" v={r.agent} mono />
      {r.actor && <Field k="actor" v={r.actor} mono />}
      {r.peer && <Field k="peer" v={r.peer} mono />}
      <Field k="server" v={r.server} mono />
      {r.method && <Field k="method" v={r.method} mono />}
      {r.tool && <Field k="tool" v={r.tool} mono />}
      {r.uri && <Field k="uri" v={r.uri} mono />}
      {r.transforms && <Field k="transforms" v={r.transforms.join(", ")} mono />}
      {r.config_from && <Field k="config" v={`${r.config_from} → ${r.config_to}`} mono />}
      {changes && <Field k="tools changed" v={`+${changes.added} −${changes.removed} ~${changes.changed} · ${changes.drifted} drifted`} mono />}
      <Field k="latency" v={`${r.latency_ms}ms`} />
      <Field k="time" v={H.fmtTime(r.ts)} mono />
      <div style={{ margin: "14px 0 6px", fontSize: 12, color: "var(--eg-muted)" }}>Hash chain</div>
      <TokenPill value={`prev ${r.prev_hash}  →  ${r.hash}`} />
    </Modal>
  );
}

function Field({ k, v, mono }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "120px 1fr", gap: 12, padding: "5px 0", borderBottom: "1px solid var(--eg-border-soft)" }}>
      <span style={{ fontSize: 12, color: "var(--eg-muted)" }}>{k}</span>
      <span style={{ fontSize: 13, color: "var(--eg-fg)", fontFamily: mono ? "var(--font-mono)" : "var(--font-sans)", wordBreak: "break-all" }}>{v}</span>
    </div>
  );
}
