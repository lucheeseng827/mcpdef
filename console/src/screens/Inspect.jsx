// SPDX-License-Identifier: Apache-2.0
/* MCPdef console — Inspect: how `[gateway.inspect]` is set, and what it found
 * lately, with no secret: an injection's own words, and for a secret only its
 * rule. Read-only: the config file is the source of truth.
 * (/inspect/config, /inspect/findings) */
import React from "react";
import { Card, Badge, Tag, DataTable, EmptyState, PageHeader, Icon } from "../ds";
import * as H from "../helpers.js";

const MODES = {
  off: "Nothing is scanned, and nothing found is kept.",
  warn: "Findings are logged, recorded and kept here, and calls still pass.",
  enforce: "A poisoned tool is hidden, and a result that leaks a secret or carries injected instructions is refused before it reaches the model.",
  redact: "As enforce, but a secret in a result is masked in place, and the result passes.",
};

const OUTCOMES = { blocked: ["danger", "x"], redacted: ["warn", "check"], warned: ["default", "alert-triangle"] };

export default function Inspect({ data }) {
  const D = data;
  const config = D.inspect || { mode: D.info.inspectMode, injection_phrases: [], secret_substrings: 0 };
  const mode = config.mode;
  const findings = D.findings;

  return (
    <div>
      <PageHeader title="Inspect"
        sub="Scanning what tools say into the model's context, for injected instructions and leaked secrets" />

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
        <Card title="Mode">
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
            <Badge tone={mode === "off" ? "default" : mode === "warn" ? "warn" : "brand"}>{mode}</Badge>
            <span className="mono" style={{ fontSize: 12, color: "var(--eg-muted)" }}>[gateway.inspect] mode</span>
          </div>
          <div style={{ fontSize: 13, color: "var(--eg-muted)" }}>{MODES[mode] || ""}</div>
        </Card>

        <Card title="What it looks for">
          <Pack name="built-in" desc="injection phrasing; AWS, Slack, GitHub and Stripe keys; private keys" />
          <Pack name="injection_phrases" desc={config.injection_phrases.length
            ? config.injection_phrases.map((p) => <Tag key={p}>{p}</Tag>)
            : "none of the config's own"} />
          <Pack name="secret_substrings" desc={`${config.secret_substrings} of the config's own, not shown`} />
        </Card>
      </div>

      <Card title={`Found lately (the last ${findings.length})`} padded={false}>
        {findings.length === 0 ? (
          <div style={{ padding: 24 }}>
            <EmptyState icon={<Icon name="spark" size={20} />} title="Nothing found">
              {mode === "off" ? "Scanning is off." : "Nothing tripped the scanner since the gateway started."}
            </EmptyState>
          </div>
        ) : (
          <DataTable
            columns={[
              { header: "category", width: "100px", cell: (f) => <span className="mono" style={{ fontSize: 12 }}>{f.category}</span> },
              { header: "rule", width: "150px", cell: (f) => <span className="mono" style={{ fontSize: 12 }}>{f.rule}</span> },
              { header: "where", width: "130px", cell: (f) => <span style={{ fontSize: 12, color: "var(--eg-muted)" }}>{f.surface}</span> },
              { header: "server · target", cell: (f) => <span><span style={{ color: "var(--eg-muted)" }}>{f.server} · </span><Tag>{f.tool}</Tag></span> },
              { header: "matched", cell: (f) => <span className="mono" style={{ fontSize: 12 }}>{f.excerpt}</span> },
              { header: "outcome", width: "110px", cell: (f) => <Outcome value={f.outcome} /> },
              { header: "when", width: "80px", align: "right", cell: (f) => <span style={{ fontSize: 12, color: "var(--eg-muted)" }}>{H.fmtRel(f.ts, D.now)}</span> },
            ]}
            rows={findings}
            rowKey={(f, i) => `${f.ts}-${i}`}
          />
        )}
      </Card>
    </div>
  );
}

function Outcome({ value }) {
  const [tone, icon] = OUTCOMES[value] || ["default", "alert-triangle"];
  return <Badge tone={tone}><Icon name={icon} size={12} style={{ verticalAlign: "-2px", marginRight: 4 }} />{value}</Badge>;
}

function Pack({ name, desc }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "150px 1fr", gap: 12, padding: "9px 0", borderBottom: "1px solid var(--eg-border-soft)", alignItems: "center" }}>
      <span className="mono" style={{ fontSize: 12, color: "var(--eg-fg)" }}>{name}</span>
      <span style={{ fontSize: 12, color: "var(--eg-muted)", display: "flex", gap: 6, flexWrap: "wrap" }}>{desc}</span>
    </div>
  );
}
