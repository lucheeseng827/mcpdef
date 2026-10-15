// SPDX-License-Identifier: Apache-2.0
/* MCPdef console — Config, for an admin: the config file the gateway was
 * started from, as it is on disk now, each secret masked; and a config
 * checked as `mcpdef validate` checks one, never applied. (/config,
 * /config/validate) */
import React from "react";
import { Card, Badge, Tag, Button, Textarea, PageHeader, Icon, Toast } from "../ds";
import { validateConfig } from "../api/client.js";

export default function Config({ data }) {
  const D = data;
  const [draft, setDraft] = React.useState("");
  const [result, setResult] = React.useState(null); // {valid, problems}
  const [busy, setBusy] = React.useState(false);

  async function validate() {
    setBusy(true);
    try {
      setResult(await validateConfig(draft));
    } catch (e) {
      setResult({ valid: false, problems: [`Could not check it: ${e.detail || e.message || e}`] });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <PageHeader title="Config"
        sub={<><span className="mono">{D.configPath || "mcpdef.toml"}</span>, as it is on disk now: a change no reload has applied shows here first</>}
        actions={<Badge tone="brand">{D.redacted.length} secret{D.redacted.length === 1 ? "" : "s"} masked</Badge>} />

      <div style={{ display: "grid", gridTemplateColumns: "1.3fr 1fr", gap: 14, alignItems: "start" }}>
        <Card title={<span><Icon name="file" size={14} style={{ verticalAlign: "-2px", marginRight: 6 }} />the config file, masked</span>}
          actions={<Button size="sm" icon={<Icon name="external" />} onClick={() => navigator.clipboard.writeText(D.configText)}>Copy</Button>} padded={false}>
          <pre tabIndex={0} aria-label="The config file, masked" style={{ margin: 0, padding: 16, fontFamily: "var(--font-mono)", fontSize: 12.5, lineHeight: 1.7, color: "var(--eg-fg)", overflowX: "auto" }}>
            {highlight(D.configText)}
          </pre>
          <div style={{ padding: "10px 16px", borderTop: "1px solid var(--eg-border-soft)", display: "flex", gap: 8, flexWrap: "wrap" }}>
            {D.redacted.map((p) => (
              <Tag key={p} style={{ color: "var(--eg-warn)", borderColor: "var(--eg-warn-border)" }}>{p}</Tag>
            ))}
          </div>
        </Card>

        <div style={{ display: "grid", gap: 14 }}>
          <Card title="Validate a candidate config">
            <Textarea rows={8} value={draft} onChange={(e) => setDraft(e.target.value)}
              placeholder={'[gateway]\nlisten = "127.0.0.1:7878"\naudit  = "./mcpdef-audit/audit.log"'} />
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 12 }}>
              <span style={{ fontSize: 12, color: "var(--eg-faint)" }}>Checked as <span className="mono">mcpdef validate</span> checks one: nothing it names is read or run, and nothing is applied.</span>
              <Button variant="primary" size="sm" icon={<Icon name="check" />} onClick={validate} disabled={busy}>{busy ? "Validating…" : "Validate"}</Button>
            </div>
          </Card>

          {result && (
            result.valid ? (
              <Toast tone="good" icon={<Icon name="check" />} title="Valid" onClose={() => setResult(null)}>
                No problems: the gateway would take this config.
              </Toast>
            ) : (
              <Toast tone="danger" icon={<Icon name="alert-triangle" />} title={`${result.problems.length} problem${result.problems.length > 1 ? "s" : ""}`} onClose={() => setResult(null)}>
                <ul style={{ margin: "4px 0 0", paddingLeft: 16 }}>
                  {result.problems.map((p, i) => <li key={i} className="mono" style={{ fontSize: 12 }}>{p}</li>)}
                </ul>
              </Toast>
            )
          )}
        </div>
      </div>
    </div>
  );
}

// very light TOML colorizer for the read-only viewer
function highlight(text) {
  return text.split("\n").map((line, i) => {
    let el;
    if (/^\s*\[/.test(line)) el = <span style={{ color: "var(--eg-brand)" }}>{line}</span>;
    else if (/\*\*\*/.test(line)) {
      // A masked secret: said so in words too, not by colour alone.
      el = <span><span style={{ color: "var(--eg-muted)" }}>{line}</span> <span style={{ color: "var(--eg-warn)", fontFamily: "var(--font-sans)", fontSize: 11 }}>masked</span></span>;
    } else if (/=/.test(line)) {
      const idx = line.indexOf("=");
      el = <span><span style={{ color: "var(--eg-muted)" }}>{line.slice(0, idx + 1)}</span><span style={{ color: "var(--eg-fg)" }}>{line.slice(idx + 1)}</span></span>;
    } else el = <span>{line}</span>;
    return <div key={i}>{el || " "}</div>;
  });
}
