// SPDX-License-Identifier: Apache-2.0
/* MCPdef console — Overview. The gateway, its calls in figures, the rules
 * that denied them, the most-called tools, and the latest denials; for an
 * operator, the config read again. (/info, /metrics, /audit, /reload) */
import React from "react";
import { Card, Kpi, Badge, Sparkline, MeterBar, DataTable, Tag, PageHeader, Button, Icon, Modal } from "../ds";
import * as H from "../helpers.js";
import { reloadConfig, holds } from "../api/client.js";
import { Decision } from "./AuditLog.jsx";

export default function Overview({ data, session, onChanged, onOpenAudit }) {
  const D = data;
  const m = D.metrics, info = D.info;
  const denials = D.records.filter((r) => r.decision === "deny" && (r.kind || "call") === "call").slice(0, 6);
  const rules = Object.entries(m.denyByRule).sort((a, b) => b[1] - a[1]);
  const denyMax = Math.max(1, ...rules.map(([, n]) => n));
  const share = m.calls > 0 ? `${((m.allow / m.calls) * 100).toFixed(1)}% of calls` : "no calls yet";
  const ms = (v) => (v == null ? "—" : `${Math.round(v)}ms`);
  return (
    <div>
      <PageHeader
        title="Overview"
        sub={<>Gateway <span className="mono">{info.listen}</span> · v{info.version} · spec {info.specTarget} · up {uptime(m.uptime)}</>}
        actions={<>
          <Badge tone="good"><Icon name="check" size={12} style={{ verticalAlign: "-2px", marginRight: 4 }} />gateway up</Badge>
          <Badge tone="brand">inspect: {info.inspectMode}</Badge>
          {holds(session, "console:operator") && <Reload onChanged={onChanged} />}
        </>}
      />

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 14 }}>
        <Kpi label="Calls" value={H.grouped(m.calls)} foot={<Sparkline data={m.callTrend} width={140} height={26} tone="brand" />} />
        <Kpi label="Allowed" value={H.grouped(m.allow)} foot={share} accent />
        <Kpi label="Denied" value={H.grouped(m.deny)} foot={<Sparkline data={m.denyTrend} width={140} height={26} tone="danger" />} />
        <Kpi label="p95 latency" value={ms(m.latency.p95)} foot={`p50 ${ms(m.latency.p50)} · p99 ${ms(m.latency.p99)}`} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1.1fr 1fr", gap: 14, marginTop: 14 }}>
        <Card title="Denied, by rule">
          <div style={{ display: "grid", gap: 14 }}>
            {rules.length === 0 && <span style={{ fontSize: 13, color: "var(--eg-faint)" }}>Nothing denied since the gateway started.</span>}
            {rules.map(([rule, n]) => (
              <MeterBar key={rule} label={<span className="mono">{rule}</span>} value={n} max={denyMax} valueLabel={H.grouped(n)} tone="danger" />
            ))}
            <div style={{ display: "flex", gap: 18, marginTop: 4, fontSize: 12, color: "var(--eg-muted)" }}>
              <span>Rate-limited <b style={{ color: "var(--eg-fg)" }}>{m.rateLimited}</b></span>
              <span>Inspect-blocked <b style={{ color: "var(--eg-fg)" }}>{m.inspectBlocked}</b></span>
            </div>
          </div>
        </Card>

        <Card title="Most-called tools">
          <div style={{ display: "grid", gap: 12 }}>
            {m.topTools.length === 0 && <span style={{ fontSize: 13, color: "var(--eg-faint)" }}>No calls yet.</span>}
            {m.topTools.map((t) => (
              <div key={`${t.server}-${t.tool}`} style={{ display: "grid", gridTemplateColumns: "170px 1fr 60px", gap: 10, alignItems: "center" }}>
                <span><span style={{ color: "var(--eg-faint)", fontSize: 12 }}>{t.server} · </span><Tag>{t.tool}</Tag></span>
                <MeterBar value={t.count} max={m.topTools[0].count} tone="brand" height={6} />
                <span className="mono" style={{ fontSize: 12, color: "var(--eg-muted)", textAlign: "right" }}>{H.grouped(t.count)}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card title="Latest denials" actions={<Button size="sm" icon={<Icon name="arrow-right" />} onClick={onOpenAudit}>Open the audit log</Button>}
        style={{ marginTop: 14 }} padded={false}>
        <DataTable
          empty="No call denied among the latest records."
          columns={[
            { header: "seq", width: "70px", cell: (r) => <span className="mono" style={{ color: "var(--eg-muted)" }}>{r.seq}</span> },
            { header: "tool", cell: (r) => r.tool ? <Tag>{r.tool}</Tag> : <span className="mono" style={{ fontSize: 12 }}>{r.uri || r.method}</span> },
            { header: "server", cell: (r) => <span style={{ color: "var(--eg-muted)" }}>{r.server}</span> },
            { header: "rule", cell: (r) => <span className="mono" style={{ fontSize: 12 }}>{r.rule}</span> },
            { header: "agent", cell: (r) => <span className="mono" style={{ fontSize: 12, color: "var(--eg-muted)" }}>{r.agent}</span> },
            { header: "when", width: "90px", align: "right", cell: (r) => <span style={{ color: "var(--eg-muted)", fontSize: 12 }}>{H.fmtRel(r.ts, D.now)}</span> },
            { header: "", width: "90px", align: "right", cell: (r) => <Decision value={r.decision} /> },
          ]}
          rows={denials}
          rowKey={(r) => r.seq}
          onRowClick={onOpenAudit}
        />
      </Card>
    </div>
  );
}

function uptime(seconds) {
  if (seconds == null) return "—";
  const h = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return h > 0 ? `${h}h ${mins}m` : `${mins}m`;
}

/** Read the config again, as SIGHUP does: confirmed, and what came of it. */
function Reload({ onChanged }) {
  const [asking, setAsking] = React.useState(false);
  const [outcome, setOutcome] = React.useState(null);
  const go = async () => {
    setOutcome({ pending: true });
    try {
      const said = await reloadConfig();
      setOutcome({ said });
      onChanged();
    } catch (e) {
      setOutcome({ error: e.detail || e.message || String(e) });
    }
  };
  const said = outcome && outcome.said;
  const applied = said && said.outcome === "applied";
  return (
    <>
      <Button size="sm" icon={<Icon name="route" />} onClick={() => { setOutcome(null); setAsking(true); }}>Reload config</Button>
      {asking && (
        <Modal open onClose={() => setAsking(false)} width={520}
          title={!outcome ? "Reload the config?" : outcome.pending ? "Reloading…" : applied ? "Reloaded" : "Not reloaded"}
          footer={outcome && !outcome.pending
            ? <Button variant="primary" onClick={() => setAsking(false)}>Done</Button>
            : <>
              <Button onClick={() => setAsking(false)}>Cancel</Button>
              <Button variant="primary" disabled={!!outcome} onClick={go}>Reload</Button>
            </>}>
          {!outcome && <div style={{ fontSize: 14, color: "var(--eg-muted)" }}>MCPdef reads its config file again and applies it, as <span className="mono">SIGHUP</span> does. One it would refuse leaves the config in force serving. It is recorded, with you as its actor.</div>}
          {applied && (
            <div style={{ fontSize: 13, display: "grid", gap: 6 }}>
              <Line label="added" items={said.added} />
              <Line label="removed" items={said.removed} />
              <Line label="reconnected" items={said.reconnected} />
              {said.failed.map((f) => <div key={f.server}><span className="mono">{f.server}</span>: {f.error}</div>)}
            </div>
          )}
          {said && !applied && (
            <div style={{ fontSize: 13 }}>
              <div style={{ marginBottom: 6 }}>Refused under <span className="mono">{said.rule}</span>; the config in force keeps serving.</div>
              <ul style={{ margin: 0, paddingLeft: 18 }}>{(said.reasons || []).map((r, i) => <li key={i} className="mono" style={{ fontSize: 12 }}>{r}</li>)}</ul>
            </div>
          )}
          {outcome && outcome.error && <div style={{ fontSize: 13 }}>{outcome.error}</div>}
        </Modal>
      )}
    </>
  );
}

function Line({ label, items }) {
  return (
    <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
      <span style={{ color: "var(--eg-muted)", width: 90 }}>{label}</span>
      {items.length ? items.map((i) => <Tag key={i}>{i}</Tag>) : <span style={{ color: "var(--eg-faint)" }}>none</span>}
    </div>
  );
}
