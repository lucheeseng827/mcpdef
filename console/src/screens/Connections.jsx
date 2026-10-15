// SPDX-License-Identifier: Apache-2.0
/* MCPdef console — Connections: the TLS of the gateway's own listeners and
 * the client certificates they ask for; the local CA; how each HTTPS
 * upstream's certificate was checked; how the credentials MCPdef sends each
 * upstream fare; and every expiry among them, soonest first.
 * (/tls, /credentials, /servers) */
import React from "react";
import { Card, Badge, Tag, DataTable, PageHeader, Icon, TokenPill } from "../ds";
import * as H from "../helpers.js";
import { BASE } from "../api/client.js";

const DAY = 24 * 60 * 60 * 1000;

/** Days from `now` to `when` (RFC 3339), or null. */
function daysLeft(when, now) {
  if (!when) return null;
  const at = Date.parse(when);
  return Number.isNaN(at) ? null : Math.floor((at - now) / DAY);
}

/** How soon: by word and icon, never colour alone. */
export function Expiry({ when, now }) {
  const days = daysLeft(when, now);
  if (days == null) return <span style={{ color: "var(--eg-faint)" }}>—</span>;
  const [tone, icon, said] = days < 0 ? ["danger", "x", `expired ${-days}d ago`]
    : days < 7 ? ["danger", "alert-triangle", `${days}d left`]
    : days < 30 ? ["warn", "alert-triangle", `${days}d left`]
    : ["good", "check", `${days}d left`];
  return (
    <span style={{ display: "inline-flex", gap: 8, alignItems: "center" }}>
      <span className="mono" style={{ fontSize: 12, color: "var(--eg-muted)" }}>{when.slice(0, 10)}</span>
      <Badge tone={tone}><Icon name={icon} size={12} style={{ verticalAlign: "-2px", marginRight: 4 }} />{said}</Badge>
    </span>
  );
}

export default function Connections({ data }) {
  const D = data;
  const now = D.now;
  const tls = D.tls;
  const upstreams = D.servers.filter((s) => s.tls);
  const expiries = [
    tls.mcp.certificate && { what: "MCP listener's certificate", when: tls.mcp.certificate.not_after },
    tls.admin && tls.admin.certificate && { what: "admin listener's certificate", when: tls.admin.certificate.not_after },
    tls.local_ca && { what: "local CA", when: tls.local_ca.not_after },
    ...upstreams.map((s) => ({ what: `${s.id}'s certificate`, when: s.tls.not_after })),
    ...upstreams.filter((s) => s.tls.client_not_after).map((s) => ({ what: `the client certificate MCPdef presents ${s.id}`, when: s.tls.client_not_after })),
    ...D.credentials.filter((c) => c.credential && c.credential.expires_at).map((c) => ({ what: `${c.server}'s ${c.kind} credentials`, when: c.credential.expires_at })),
  ].filter((e) => e && e.when).sort((a, b) => Date.parse(a.when) - Date.parse(b.when));

  return (
    <div>
      <PageHeader title="Connections" sub="TLS on the gateway's listeners and towards its upstreams, and the credentials it sends them" />

      <Card title="Expiring, soonest first" style={{ marginBottom: 14 }}>
        {expiries.length === 0
          ? <span style={{ fontSize: 13, color: "var(--eg-faint)" }}>Nothing here expires: no certificate is served, and no credential says when it expires.</span>
          : expiries.map((e) => (
            <div key={e.what} style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 12, padding: "7px 0", borderBottom: "1px solid var(--eg-border-soft)", alignItems: "center" }}>
              <span style={{ fontSize: 13 }}>{e.what}</span>
              <Expiry when={e.when} now={now} />
            </div>
          ))}
      </Card>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
        <Listener title="MCP listener" listener={tls.mcp} now={now} />
        {tls.admin ? <Listener title="Admin listener" listener={tls.admin} now={now} /> : (
          <Card title="Admin listener"><span style={{ fontSize: 13, color: "var(--eg-faint)" }}>Off.</span></Card>
        )}
      </div>

      {tls.local_ca && (
        <Card title="Local CA" style={{ marginBottom: 14 }}
          actions={<a href={`${BASE}/ca.pem`} download="mcpdef-ca.pem" style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--eg-fg)" }}><Icon name="external" size={13} />Download ca.pem</a>}>
          <Certificate cert={tls.local_ca} now={now} />
          <div style={{ fontSize: 12, color: "var(--eg-faint)", marginTop: 10 }}>The CA that issues the listeners' certificates with <span className="mono">mode = "self-signed"</span>: a client trusts it to reach them.</div>
        </Card>
      )}

      <Card title="Upstreams over HTTPS" padded={false} style={{ marginBottom: 14 }}>
        <DataTable
          empty="No HTTPS upstream has opened."
          columns={[
            { header: "server", cell: (s) => <b style={{ fontWeight: 600 }}>{s.id}</b> },
            { header: "checked by", width: "120px", cell: (s) => <Badge tone={s.tls.verify === "disabled" ? "danger" : "good"}>{s.tls.verify}</Badge> },
            { header: "its certificate", cell: (s) => <Expiry when={s.tls.not_after} now={now} /> },
            { header: "ours to it", cell: (s) => <Expiry when={s.tls.client_not_after} now={now} /> },
          ]}
          rows={upstreams}
          rowKey={(s) => s.id}
        />
      </Card>

      <Card title="Credentials sent upstream" padded={false}>
        <DataTable
          empty="No upstream is sent credentials ([server.auth])."
          columns={[
            { header: "server", cell: (c) => <b style={{ fontWeight: 600 }}>{c.server}</b> },
            { header: "kind", width: "90px", cell: (c) => <span className="mono" style={{ fontSize: 12 }}>{c.kind}</span> },
            { header: "last taken", cell: (c) => c.credential && c.credential.last_ok ? <span className="mono" style={{ fontSize: 12 }}>{H.fmtTime(c.credential.last_ok.at_unix_ms)}</span> : <span style={{ color: "var(--eg-faint)" }}>not yet</span> },
            { header: "last refused", width: "1.4fr", cell: (c) => c.credential && c.credential.last_error ? <span style={{ fontSize: 12 }}>{c.credential.last_error.message}</span> : <span style={{ color: "var(--eg-faint)" }}>never</span> },
            { header: "failures", width: "80px", align: "right", cell: (c) => <span className="mono">{c.auth_failures}</span> },
            { header: "expires", cell: (c) => <Expiry when={c.credential && c.credential.expires_at} now={now} /> },
          ]}
          rows={D.credentials}
          rowKey={(c) => c.server}
        />
      </Card>
    </div>
  );
}

function Listener({ title, listener, now }) {
  const auth = listener.client_auth;
  return (
    <Card title={title}>
      <Row label="TLS"><Badge tone={listener.mode === "off" ? "default" : "good"}>{listener.mode}</Badge></Row>
      {listener.hostnames.length > 0 && <Row label="Names">{listener.hostnames.map((h) => <Tag key={h}>{h}</Tag>)}</Row>}
      {listener.certificate && <Certificate cert={listener.certificate} now={now} />}
      <Row label="Client certificates"><Badge tone={auth.mode === "required" ? "good" : "default"}>{auth.mode}</Badge>{auth.identity && <span className="mono" style={{ fontSize: 12 }}>identity: {auth.identity}</span>}</Row>
      {auth.trust_domains.length > 0 && <Row label="Trust domains">{auth.trust_domains.map((d) => <Tag key={d}>{d}</Tag>)}</Row>}
      {auth.ca.map((ca) => <Certificate key={ca.path} cert={ca} now={now} label="Client CA" />)}
    </Card>
  );
}

function Certificate({ cert, now, label = "Certificate" }) {
  if (cert.error) {
    return <Row label={label}><span style={{ fontSize: 12, color: "var(--eg-danger)" }}><span className="mono">{cert.path}</span>: {cert.error}</span></Row>;
  }
  return (
    <>
      <Row label={label}><span className="mono" style={{ fontSize: 12 }}>{cert.subject || cert.path}</span></Row>
      {cert.names && cert.names.length > 0 && <Row label="For">{cert.names.map((n) => <Tag key={n}>{n}</Tag>)}</Row>}
      {cert.issuer && <Row label="Issued by"><span className="mono" style={{ fontSize: 12 }}>{cert.issuer}</span></Row>}
      <Row label="Expires"><Expiry when={cert.not_after} now={now} /></Row>
      {cert.sha256 && <div style={{ marginTop: 6 }}><TokenPill value={`sha256 ${cert.sha256}`} /></div>}
    </>
  );
}

function Row({ label, children }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "130px 1fr", gap: 12, padding: "7px 0", borderBottom: "1px solid var(--eg-border-soft)", alignItems: "center" }}>
      <span style={{ fontSize: 12, color: "var(--eg-muted)" }}>{label}</span>
      <span style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>{children}</span>
    </div>
  );
}
