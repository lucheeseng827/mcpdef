// SPDX-License-Identifier: Apache-2.0
/* MCPdef console — Connect: the entry each MCP client needs to reach this
 * gateway, as `mcpdef connect` writes it; the local CA to trust, when the
 * listener's certificate is its; and a request to try from the client's
 * machine. (/clients/{client}/snippet, /ca.pem) */
import React from "react";
import { Card, Button, Input, Select, PageHeader, Icon, EmptyState } from "../ds";
import { snippet, BASE } from "../api/client.js";

const CLIENTS = [
  ["claude-code", "Claude Code"],
  ["claude-desktop", "Claude Desktop"],
  ["cursor", "Cursor"],
  ["vscode", "VS Code"],
  ["codex", "Codex"],
  ["generic", "Another client"],
];

export default function Connect({ data }) {
  const auth = data.info.auth;
  const asksToken = auth.enabled && (auth.methods.includes("bearer") || auth.methods.includes("key"));
  const [client, setClient] = React.useState("claude-code");
  const [name, setName] = React.useState("mcpdef");
  const [tokenEnv, setTokenEnv] = React.useState(asksToken ? "MCPDEF_TOKEN" : "");
  const [entry, setEntry] = React.useState(null);
  const [failed, setFailed] = React.useState(null);

  React.useEffect(() => {
    let current = true;
    setFailed(null);
    const id = setTimeout(() => {
      snippet(client, name.trim(), tokenEnv.trim())
        .then((e) => { if (current) setEntry(e); })
        .catch((e) => { if (current) { setEntry(null); setFailed(e.detail || e.message || String(e)); } });
    }, 250);
    return () => { current = false; clearTimeout(id); };
  }, [client, name, tokenEnv]);

  const ca = data.tls && data.tls.local_ca;
  const test = entry && [
    "curl -sS",
    ca ? "--cacert mcpdef-ca.pem" : null,
    "-H 'content-type: application/json'",
    "-H 'accept: application/json, text/event-stream'",
    asksToken ? `-H "authorization: Bearer $${tokenEnv.trim() || "MCPDEF_TOKEN"}"` : null,
    `-d '{"jsonrpc":"2.0","id":1,"method":"ping"}'`,
    entry.url,
  ].filter(Boolean).join(" \\\n  ");

  return (
    <div>
      <PageHeader title="Connect" sub="The entry each MCP client needs to reach this gateway, as mcpdef connect writes it" />

      <Card style={{ marginBottom: 14 }}>
        <div style={{ display: "grid", gridTemplateColumns: asksToken ? "1fr 1fr 1fr" : "1fr 1fr", gap: 12, alignItems: "end" }}>
          <Select label="Client" value={client} onChange={(e) => setClient(e.target.value)}
            options={CLIENTS.map(([value, label]) => ({ value, label }))} />
          <Input label="Entry name" mono value={name} onChange={(e) => setName(e.target.value)} />
          {asksToken && <Input label="Token variable" hint="The entry names it, never its value." mono value={tokenEnv} onChange={(e) => setTokenEnv(e.target.value)} />}
        </div>
      </Card>

      {failed ? (
        <EmptyState icon={<Icon name="alert-triangle" size={20} />} title="No entry for it">{failed}</EmptyState>
      ) : !entry ? (
        <div role="status" style={{ color: "var(--eg-muted)", fontSize: 13 }}>Writing the entry…</div>
      ) : (
        <div style={{ display: "grid", gap: 14 }}>
          <Card title={<span>For {CLIENTS.find(([v]) => v === client)[1]}</span>}
            actions={<Button size="sm" icon={<Icon name="file" />} onClick={() => navigator.clipboard.writeText(entry.report)}>Copy</Button>} padded={false}>
            <pre tabIndex={0} aria-label="The client's entry" style={{ margin: 0, padding: 16, fontFamily: "var(--font-mono)", fontSize: 12.5, lineHeight: 1.6, color: "var(--eg-fg)", overflowX: "auto", whiteSpace: "pre-wrap" }}>{entry.report}</pre>
          </Card>

          {ca && (
            <Card title="Trust the local CA"
              actions={<a href={`${BASE}/ca.pem`} download="mcpdef-ca.pem" style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--eg-fg)" }}><Icon name="external" size={13} />Download ca.pem</a>}>
              <div style={{ fontSize: 13, color: "var(--eg-muted)" }}>The listener's certificate is the local CA's: a client trusts that CA to reach it. <span className="mono">mcpdef tls init</span> prints how each operating system and runtime is told to.</div>
            </Card>
          )}

          <Card title="Try it from the client's machine" padded={false}
            actions={<Button size="sm" icon={<Icon name="file" />} onClick={() => navigator.clipboard.writeText(test)}>Copy</Button>}>
            <pre tabIndex={0} aria-label="A request to try" style={{ margin: 0, padding: 16, fontFamily: "var(--font-mono)", fontSize: 12.5, lineHeight: 1.6, color: "var(--eg-fg)", overflowX: "auto" }}>{test}</pre>
            <div style={{ padding: "0 16px 14px", fontSize: 12, color: "var(--eg-muted)" }}>
              It answers <span className="mono">{`{"jsonrpc":"2.0","id":1,"result":{}}`}</span> when the client reaches the gateway{asksToken ? ", and the gateway takes its token" : ""}.
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
