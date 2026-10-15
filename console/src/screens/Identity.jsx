// SPDX-License-Identifier: Apache-2.0
/* MCPdef console — Identity: who you are to the console; and, for an admin,
 * who the gateway takes its callers to be: how the console signs people in,
 * whether its identity provider was found, how a token's claims name its
 * caller and give its roles, the certificates and client keys it maps, and
 * the MCP listener's tokens. (/session, /identity) */
import React from "react";
import { Card, Badge, Tag, DataTable, PageHeader, Icon } from "../ds";

/** How the session's actor came to be named. */
function how(actor) {
  if (actor.startsWith("user:")) return "signed in at the identity provider";
  if (actor.startsWith("cert:")) return "named by a client certificate";
  if (actor.startsWith("token:")) return "a token the identity provider issued for the admin API";
  if (actor === "break-glass") return "the break-glass token";
  if (actor === "local") return "on this machine, where nothing signs callers in";
  return "anyone, as the listener lets them in";
}

export default function Identity({ data, session }) {
  const id = data.identity;
  return (
    <div>
      <PageHeader title="Identity" sub="Who you are to the console, and who the gateway takes its callers to be" />

      <Card title="You" style={{ marginBottom: 14 }}>
        <Row label="Name">{session.name ? <span>{session.name}</span> : <span style={{ color: "var(--eg-faint)" }}>—</span>}</Row>
        <Row label="Recorded as"><span className="mono">{session.actor}</span></Row>
        <Row label="By">{how(session.actor)}</Row>
        <Row label="Console roles">{session.roles.length ? session.roles.map((r) => <Tag key={r}>{r}</Tag>) : <span style={{ color: "var(--eg-faint)" }}>none</span>}</Row>
      </Card>

      {!id ? (
        <Card><span style={{ fontSize: 13, color: "var(--eg-muted)" }}>How the gateway names its callers is for <span className="mono">console:admin</span> to see.</span></Card>
      ) : (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
            <SignIn console={id.console} />
            <Model model={id.model} />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
            <Bearer mcp={id.mcp} />
            <Card title="Client keys">
              {id.keys.length === 0
                ? <span style={{ fontSize: 13, color: "var(--eg-faint)" }}>No [[key]]: the gateway issued none.</span>
                : id.keys.map((k) => <Mapped key={k.name} from={<span className="mono">key:{k.name}</span>} roles={k.roles} />)}
            </Card>
          </div>
          <Card title="Client certificates">
            {id.cert_map.length === 0
              ? <span style={{ fontSize: 13, color: "var(--eg-faint)" }}>No [[identity.cert_map]]: a certificate holds no role.</span>
              : id.cert_map.map((m) => <Mapped key={m.identity} from={<span className="mono">{m.identity}</span>} roles={m.roles} />)}
          </Card>
        </>
      )}
    </div>
  );
}

function SignIn({ console: c }) {
  const p = c.provider;
  return (
    <Card title="Signing in to the console">
      <Row label="By">{c.signs_in.length ? c.signs_in.map((s) => <Tag key={s}>{s}</Tag>) : <span style={{ color: "var(--eg-muted)" }}>nothing: {c.allow_unauthenticated ? "a proxy in front, as allow_unauthenticated says" : "open to this machine"}</span>}</Row>
      {c.oidc && (
        <>
          <Row label="Provider"><span className="mono" style={{ fontSize: 12 }}>{c.oidc.issuer}</span></Row>
          <Row label="Found">{p && p.found
            ? <Badge tone="good"><Icon name="check" size={12} style={{ verticalAlign: "-2px", marginRight: 4 }} />yes</Badge>
            : <span style={{ display: "inline-flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}><Badge tone="danger"><Icon name="x" size={12} style={{ verticalAlign: "-2px", marginRight: 4 }} />no</Badge>{p && p.error && <span style={{ fontSize: 12 }}>{p.error}</span>}</span>}</Row>
          <Row label="Client"><span className="mono" style={{ fontSize: 12 }}>{c.oidc.client_id}</span><span style={{ fontSize: 12, color: "var(--eg-muted)" }}>{c.oidc.client_auth}{c.oidc.client_secret ? ", its secret set" : ", no secret"}</span></Row>
          <Row label="Scopes">{c.oidc.scopes.map((s) => <Tag key={s}>{s}</Tag>)}</Row>
          <Row label="Redirect URI"><span className="mono" style={{ fontSize: 12 }}>{c.oidc.redirect_uri}</span></Row>
          {c.oidc.api_audience && <Row label="API audience"><span className="mono" style={{ fontSize: 12 }}>{c.oidc.api_audience}</span></Row>}
        </>
      )}
      <Row label="Break-glass">{c.break_glass ? <Badge tone="warn">set</Badge> : <span style={{ color: "var(--eg-faint)" }}>not set</span>}</Row>
      {c.public_url && <Row label="Public URL"><span className="mono" style={{ fontSize: 12 }}>{c.public_url}</span></Row>}
    </Card>
  );
}

function Model({ model }) {
  return (
    <Card title="How a token names its caller">
      <Row label="Subject"><span className="mono">{model.subject_claim}</span></Row>
      <Row label="Roles from">{model.roles_claims.length ? model.roles_claims.map((c) => <Tag key={c}>{c}</Tag>) : <span style={{ color: "var(--eg-faint)" }}>no claim</span>}</Row>
      {model.role_map.length > 0 && (
        <div style={{ marginTop: 10 }}>
          <DataTable
            columns={[
              { header: "claim", cell: (m) => <span className="mono" style={{ fontSize: 12 }}>{m.claim}</span> },
              { header: "holding", cell: (m) => <span className="mono" style={{ fontSize: 12 }}>{m.value}</span> },
              { header: "gives", cell: (m) => <span style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>{m.roles.map((r) => <Tag key={r}>{r}</Tag>)}</span> },
            ]}
            rows={model.role_map}
            rowKey={(m) => `${m.claim}=${m.value}`}
          />
        </div>
      )}
    </Card>
  );
}

function Bearer({ mcp }) {
  const b = mcp.bearer;
  return (
    <Card title="The MCP listener's callers">
      <Row label="Auth">{b.enabled ? b.methods.map((m) => <Tag key={m}>{m}</Tag>) : <span style={{ color: "var(--eg-muted)" }}>off: callers are not asked who they are</span>}</Row>
      {b.issuer && <Row label="Issuer"><span className="mono" style={{ fontSize: 12 }}>{b.issuer}</span></Row>}
      {b.resource && <Row label="Resource"><span className="mono" style={{ fontSize: 12 }}>{b.resource}</span></Row>}
      {b.audiences && b.audiences.length > 0 && <Row label="Also for">{b.audiences.map((a) => <Tag key={a}>{a}</Tag>)}</Row>}
      {b.discovery && <Row label="Keys">found from the issuer's metadata</Row>}
      <Row label="Certificates"><span className="mono" style={{ fontSize: 12 }}>{mcp.client_certificates}</span></Row>
    </Card>
  );
}

function Mapped({ from, roles }) {
  return (
    <div style={{ display: "flex", gap: 8, alignItems: "center", padding: "6px 0", borderBottom: "1px solid var(--eg-border-soft)", flexWrap: "wrap" }}>
      {from}
      <Icon name="arrow-right" size={12} style={{ color: "var(--eg-faint)" }} />
      {roles.map((r) => <Tag key={r}>{r}</Tag>)}
    </div>
  );
}

function Row({ label, children }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "120px 1fr", gap: 12, padding: "7px 0", borderBottom: "1px solid var(--eg-border-soft)", alignItems: "center", fontSize: 13 }}>
      <span style={{ fontSize: 12, color: "var(--eg-muted)" }}>{label}</span>
      <span style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>{children}</span>
    </div>
  );
}
