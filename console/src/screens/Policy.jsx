// SPDX-License-Identifier: Apache-2.0
/* MCPdef console — Policy, as the gateway runs it: the transform rules, which
 * rewrite a call's arguments before the others judge it and its result after;
 * then the allow and deny rules, the first that matches deciding; the RBAC
 * roles and the certificates they are given to; the profiles. Read-only: the
 * config file is the source of truth. (/policy/rules, /policy/rbac,
 * /policy/profiles) */
import React from "react";
import { Card, Badge, Tag, PageHeader, Tabs, Icon, EmptyState } from "../ds";

export default function Policy({ data }) {
  const D = data;
  const [tab, setTab] = React.useState("rules");
  const rules = D.rules.transform.length + D.rules.admission.length;
  return (
    <div>
      <PageHeader title="Policy" sub="Read-only · the config file is the source of truth" />
      <Tabs active={tab} onSelect={setTab} items={[
        { key: "rules", label: "Rules", badge: rules },
        { key: "rbac", label: "RBAC", badge: D.roles.length },
        { key: "profiles", label: "Profiles", badge: Object.keys(D.profiles.all).length },
      ]} />
      <div style={{ marginTop: 16 }}>
        {tab === "rules" && <Rules rules={D.rules} />}
        {tab === "rbac" && <Rbac roles={D.roles} certMap={D.certMap || []} />}
        {tab === "profiles" && <Profiles profiles={D.profiles} />}
      </div>
    </div>
  );
}

function Rules({ rules }) {
  if (rules.transform.length + rules.admission.length === 0) {
    return <EmptyState icon={<Icon name="shield" size={20} />} title="No [[policy]] rules">Each server's allowlist alone decides.</EmptyState>;
  }
  return (
    <div style={{ display: "grid", gap: 22 }}>
      {rules.transform.length > 0 && (
        <section>
          <Heading icon="route">Transform: run first, on every call they match, rewriting its arguments, and its result after</Heading>
          <div style={{ display: "grid", gap: 10 }}>
            {rules.transform.map((r, i) => <Rule key={r.name} rule={r} n={i + 1} />)}
          </div>
        </section>
      )}
      <section>
        <Heading icon="list">Allow and deny: in order, <b style={{ color: "var(--eg-fg)" }}>the first that matches decides</b>; none matching, the allowlist does</Heading>
        <div style={{ display: "grid", gap: 10 }}>
          {rules.admission.map((r, i) => <Rule key={r.name} rule={r} n={i + 1} />)}
        </div>
      </section>
    </div>
  );
}

function Heading({ icon, children }) {
  return (
    <div style={{ fontSize: 12, color: "var(--eg-muted)", marginBottom: 12, display: "flex", alignItems: "center", gap: 8 }}>
      <Icon name={icon} size={14} /> <span>{children}</span>
    </div>
  );
}

function Rule({ rule: r, n }) {
  const tone = r.effect === "deny" ? "danger" : r.effect === "transform" ? "brand" : "good";
  const icon = r.effect === "deny" ? "x" : r.effect === "transform" ? "route" : "check";
  return (
    <Card style={{ borderLeft: `3px solid var(--eg-${tone === "brand" ? "brand" : tone})` }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
        <span className="mono" style={{ fontSize: 12, color: "var(--eg-faint)", width: 20 }}>{String(n).padStart(2, "0")}</span>
        <Badge tone={tone}><Icon name={icon} size={12} style={{ verticalAlign: "-2px", marginRight: 4 }} />{r.effect}</Badge>
        <b style={{ fontSize: 14 }} className="mono">{r.name}</b>
        {r.on_error && <span style={{ fontSize: 12, color: "var(--eg-faint)", marginLeft: "auto" }}>on error: <span className="mono">{r.on_error}</span></span>}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "90px 1fr", gap: "6px 12px", fontSize: 13, alignItems: "center" }}>
        <Match label="agents" globs={r.agents} />
        <Match label="servers" globs={r.servers} />
        <Match label="tools" globs={r.tools} />
        {r.uris && <Match label="uris" globs={r.uris} />}
        {r.prompts && <Match label="prompts" globs={r.prompts} />}
        {r.args.length > 0 && (
          <List label="args">{r.args.map((a, ai) => <Tag key={ai} tone="brand">{a.path} {a.op} "{a.val}"</Tag>)}</List>
        )}
        {(r.set_args || []).length > 0 && (
          <List label="sets">{r.set_args.map((a, ai) => <Tag key={ai}>{a.op} {a.path}{a.min != null || a.max != null ? ` [${a.min ?? "…"}, ${a.max ?? "…"}]` : ""}</Tag>)}</List>
        )}
        {(r.result || []).length > 0 && (
          <List label="result">{r.result.map((a, ai) => <Tag key={ai}>{a.op}{a.arg ? ` ${a.arg}` : ""}</Tag>)}</List>
        )}
      </div>
    </Card>
  );
}

function List({ label, children }) {
  return (
    <>
      <span style={{ fontSize: 12, color: "var(--eg-muted)" }}>{label}</span>
      <span style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>{children}</span>
    </>
  );
}

function Match({ label, globs }) {
  return (
    <List label={label}>
      {globs ? globs.map((g) => <Tag key={g}>{g}</Tag>) : <span style={{ color: "var(--eg-faint)" }}>any</span>}
    </List>
  );
}

function Rbac({ roles, certMap }) {
  if (roles.length === 0) {
    return <EmptyState icon={<Icon name="users" size={20} />} title="No [[role]]">Each server's allowlist alone decides what an authenticated caller may call.</EmptyState>;
  }
  return (
    <div style={{ display: "grid", gap: 10 }}>
      {roles.map((role) => (
        <Card key={role.name}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
            <Icon name="users" size={16} style={{ color: "var(--eg-brand)" }} />
            <b style={{ fontSize: 14 }} className="mono">{role.name}</b>
            <span style={{ fontSize: 12, color: "var(--eg-faint)", marginLeft: "auto" }}>{role.grants.length} tool grants</span>
          </div>
          <Grants label="tools" grants={role.grants} />
          {(role.resource_grants || []).length > 0 && <Grants label="resources" grants={role.resource_grants} />}
          {(role.prompt_grants || []).length > 0 && <Grants label="prompts" grants={role.prompt_grants} />}
        </Card>
      ))}
      {certMap.length > 0 && (
        <Card title="Client certificates">
          {certMap.map((m) => (
            <div key={m.identity} style={{ display: "flex", gap: 8, alignItems: "center", padding: "5px 0", flexWrap: "wrap" }}>
              <span className="mono" style={{ fontSize: 12 }}>{m.identity}</span>
              <Icon name="arrow-right" size={12} style={{ color: "var(--eg-faint)" }} />
              {m.roles.map((r) => <Tag key={r}>{r}</Tag>)}
            </div>
          ))}
        </Card>
      )}
      <div style={{ fontSize: 12, color: "var(--eg-faint)" }}>
        A caller holds a role when its token's roles or scopes name it, as <span className="mono">[identity]</span> reads them, when its client key holds it, or when <span className="mono">[[identity.cert_map]]</span> gives it to its certificate. Grants are <span className="mono">server-glob:tool-glob</span>.
      </div>
    </div>
  );
}

function Grants({ label, grants }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "80px 1fr", gap: 10, alignItems: "center", marginTop: 6 }}>
      <span style={{ fontSize: 12, color: "var(--eg-muted)" }}>{label}</span>
      <span style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>{grants.map((g) => <Tag key={g}>{g}</Tag>)}</span>
    </div>
  );
}

function Profiles({ profiles }) {
  const all = Object.entries(profiles.all);
  if (all.length === 0) {
    return <EmptyState icon={<Icon name="layers" size={20} />} title="No [profile.*]">Each server's own allowlist applies.</EmptyState>;
  }
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
      {all.map(([name, p]) => (
        <Card key={name} title={<span className="mono">{name}</span>}
          actions={profiles.active === name ? <Badge tone="brand"><Icon name="check" size={12} style={{ verticalAlign: "-2px", marginRight: 4 }} />active</Badge> : null}>
          <div style={{ fontSize: 12, color: "var(--eg-muted)", marginBottom: 6 }}>allow</div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
            {(p.tools || []).length ? p.tools.map((g) => <Tag key={g}>{g}</Tag>) : <span style={{ color: "var(--eg-faint)", fontSize: 13 }}>—</span>}
          </div>
          <div style={{ fontSize: 12, color: "var(--eg-muted)", marginBottom: 6 }}>deny</div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {(p.deny || []).length ? p.deny.map((g) => <Tag key={g}>{g}</Tag>) : <span style={{ color: "var(--eg-faint)", fontSize: 13 }}>—</span>}
          </div>
        </Card>
      ))}
    </div>
  );
}
