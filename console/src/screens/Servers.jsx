// SPDX-License-Identifier: Apache-2.0
/* MCPdef console — Servers & tools. Each upstream with its health, what it
 * lists of what it offers, its pins and the tools two servers offer; a
 * server's tools, why `tools/list` hides one, its resources and prompts, its
 * connection; and, for an operator, restart, test and approve drift, each
 * confirmed. (/servers, /servers/{id}/tools, /servers/{id}/restart,
 * /servers/{id}/test, /servers/{id}/pins) */
import React from "react";
import { Card, DataTable, Badge, Tag, Button, PageHeader, Tabs, Modal, Icon, EmptyState, Toast } from "../ds";
import * as H from "../helpers.js";
import { serverTools, restartServer, testServer, approveDrift, holds } from "../api/client.js";

export default function Servers({ data, session, onChanged }) {
  const D = data;
  const [openId, setOpenId] = React.useState(null);
  const server = D.servers.find((s) => s.id === openId);

  if (server) {
    return <Detail server={server} session={session} onChanged={onChanged} onBack={() => setOpenId(null)} />;
  }

  const collisions = D.servers.flatMap((s) => s.collisions.map((c) => ({ ...c, from: s.id })));
  return (
    <div>
      <PageHeader title="Servers & tools"
        sub={`${D.servers.length} upstreams governed · deny-by-default · declared in the config file`} />
      <Card padded={false}>
        <DataTable
          columns={[
            { header: "server", cell: (s) => (
              <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                <Icon name={s.transport.startsWith("wasm") ? "cpu" : "server"} size={15} style={{ color: "var(--eg-faint)" }} />
                <b style={{ fontWeight: 600 }}>{s.id}</b>
              </span>
            ) },
            { header: "transport", cell: (s) => <span className="mono" style={{ fontSize: 12, color: "var(--eg-muted)" }}>{H.TRANSPORT[s.transport] || s.transport}</span> },
            { header: "tools", width: "110px", cell: (s) => <span className="mono" title="listed of offered">{s.listed} / {s.offered}</span> },
            { header: "drifted", width: "84px", cell: (s) => s.drifted > 0 ? <Badge tone="warn"><Icon name="alert-triangle" size={12} style={{ verticalAlign: "-2px", marginRight: 4 }} />{s.drifted}</Badge> : <span style={{ color: "var(--eg-faint)" }}>0</span> },
            { header: "poisoned", width: "90px", cell: (s) => s.poisoned > 0 ? <Badge tone="danger"><Icon name="alert-triangle" size={12} style={{ verticalAlign: "-2px", marginRight: 4 }} />{s.poisoned}</Badge> : <span style={{ color: "var(--eg-faint)" }}>0</span> },
            { header: "restarts", width: "80px", align: "right", cell: (s) => <span className="mono" style={{ color: "var(--eg-muted)" }}>{s.restarts ?? 0}</span> },
            { header: "health", width: "110px", align: "right", cell: (s) => <Health value={s.status} /> },
          ]}
          rows={D.servers}
          rowKey={(s) => s.id}
          onRowClick={(s) => setOpenId(s.id)}
        />
      </Card>
      {collisions.length > 0 && (
        <Card title="Tools two servers offer" style={{ marginTop: 14 }}>
          <div style={{ fontSize: 12, color: "var(--eg-muted)", marginBottom: 10 }}>
            Each is listed once, from the first server in config order, and a call to it goes there.
          </div>
          {collisions.map((c) => (
            <div key={`${c.from}-${c.tool}`} style={{ display: "flex", gap: 8, alignItems: "center", padding: "5px 0" }}>
              <Tag>{c.tool}</Tag>
              <span style={{ fontSize: 13, color: "var(--eg-muted)" }}>offered by {c.servers.join(", ")}</span>
            </div>
          ))}
        </Card>
      )}
    </div>
  );
}

/** Up, starting, degraded or down: by word and icon, not colour alone. */
function Health({ value }) {
  const icon = value === "up" ? "check" : value === "down" ? "x" : "clock";
  return (
    <Badge tone={H.statusTone(value)}>
      <Icon name={icon} size={12} style={{ verticalAlign: "-2px", marginRight: 4 }} />
      {value}
    </Badge>
  );
}

function Detail({ server, session, onChanged, onBack }) {
  const [tab, setTab] = React.useState("tools");
  const [tools, setTools] = React.useState(null);
  const [toolsFailed, setToolsFailed] = React.useState(null);
  const [asking, setAsking] = React.useState(null); // the action awaiting confirmation
  const [said, setSaid] = React.useState(null); // what the last action came to
  const operator = holds(session, "console:operator");

  const readTools = React.useCallback(() => {
    serverTools(server.id)
      .then((t) => { setTools(t); setToolsFailed(null); })
      .catch((e) => setToolsFailed(e.detail || e.message || String(e)));
  }, [server.id]);
  React.useEffect(readTools, [readTools]);

  // The drifted tools, each with the hash of the definition shown here: an
  // approval names it, and takes nothing that changed since.
  const driftedTools = (tools || []).filter((t) => t.pin === "drift");
  const drifted = driftedTools.map((t) => t.name);

  const act = async (action) => {
    setAsking(null);
    try {
      if (action === "restart") {
        await restartServer(server.id);
        setSaid({ tone: "good", title: "Restarting", text: `${server.id} is opened again; its connection serves until the new one opens.` });
      } else if (action === "test") {
        const r = await testServer(server.id);
        setSaid(r.ok
          ? { tone: "good", title: "Answered", text: `${server.id} answered a ping in ${r.latency_ms}ms.` }
          : { tone: "danger", title: "No answer", text: r.error || "it did not answer" });
      } else if (action === "approve") {
        const r = await approveDrift(server.id, Object.fromEntries(driftedTools.map((t) => [t.name, t.hash])));
        setSaid({ tone: "good", title: "Drift approved", text: `${r.approved.length} tool${r.approved.length === 1 ? "" : "s"} pinned as they are now, and served again.` });
        readTools();
      }
      onChanged();
    } catch (e) {
      setSaid({ tone: "danger", title: "Refused", text: e.detail || e.message || String(e) });
      readTools();
    }
  };

  const ACTIONS = {
    restart: { title: `Restart ${server.id}?`, text: "MCPdef opens it again now: a stdio server is started as a new process. Its connection keeps serving until the new one opens, and if that fails.", confirm: "Restart", variant: "danger" },
    test: { title: `Test ${server.id}?`, text: "MCPdef sends it a ping over its live connection, and waits for the answer.", confirm: "Test", variant: "primary" },
    approve: { title: `Approve ${drifted.length} drifted tool${drifted.length === 1 ? "" : "s"}?`, text: `The definitions shown here, as ${server.id} offers them now, become their pins, saved to the pin store, and they are served again at once: ${driftedTools.map((t) => `${t.name} (${t.hash.slice(0, 12)}…)`).join(", ")}. If one changes before you approve, nothing is approved. Review what changed first (mcpdef diff-tools).`, confirm: "Approve", variant: "danger" },
  };

  return (
    <div>
      <PageHeader back={{ label: "Servers & tools", onClick: onBack }} title={server.id}
        sub={<><span className="mono">{H.TRANSPORT[server.transport] || server.transport}</span>{server.url && <> · <span className="mono">{server.url}</span></>}</>}
        actions={<>
          <Health value={server.status} />
          {operator && <Button size="sm" icon={<Icon name="activity" />} onClick={() => setAsking("test")}>Test</Button>}
          {operator && <Button size="sm" icon={<Icon name="route" />} onClick={() => setAsking("restart")}>Restart</Button>}
          {operator && drifted.length > 0 && <Button size="sm" variant="danger" icon={<Icon name="check" />} onClick={() => setAsking("approve")}>Approve drift</Button>}
        </>} />

      {said && (
        <Toast tone={said.tone} title={said.title} onClose={() => setSaid(null)} style={{ marginBottom: 14 }}
          icon={<Icon name={said.tone === "good" ? "check" : "alert-triangle"} />}>{said.text}</Toast>
      )}

      <Tabs active={tab} onSelect={setTab} items={[
        { key: "tools", label: "Tools", badge: tools ? tools.length : undefined },
        { key: "exposes", label: "Resources & prompts" },
        { key: "policy", label: "Resolved policy" },
        { key: "connection", label: "Connection" },
      ]} />

      <div style={{ marginTop: 16 }}>
        {tab === "tools" && (
          toolsFailed ? <EmptyState icon={<Icon name="alert-triangle" size={20} />} title="Couldn't read its tools">{toolsFailed}</EmptyState>
          : !tools ? <div role="status" style={{ color: "var(--eg-muted)", fontSize: 13 }}>Reading its tools…</div>
          : (
            <Card padded={false}>
              <DataTable
                empty="Its connection has not opened, or it offers no tools."
                columns={[
                  { header: "tool", cell: (t) => <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}><Tag>{t.name}</Tag>{t.listed_as !== t.name && <span className="mono" style={{ fontSize: 11, color: "var(--eg-faint)" }}>as {t.listed_as}</span>}</span> },
                  { header: "description", width: "2fr", cell: (t) => <span style={{ color: "var(--eg-muted)", fontSize: 12 }}>{t.description}</span> },
                  { header: "pin", width: "84px", cell: (t) => t.pin === "off" ? <span style={{ color: "var(--eg-faint)" }}>off</span> : <Badge tone={t.pin === "drift" ? "warn" : "good"}>{t.pin}</Badge> },
                  { header: "listed", width: "120px", align: "right", cell: (t) => t.hidden
                    ? <Badge tone={t.hidden === "allowlist" ? "default" : "danger"} title="why tools/list hides it"><Icon name="x" size={12} style={{ verticalAlign: "-2px", marginRight: 4 }} />{t.hidden}</Badge>
                    : <Badge tone="good"><Icon name="check" size={12} style={{ verticalAlign: "-2px", marginRight: 4 }} />listed</Badge> },
                ]}
                rows={tools}
                rowKey={(t) => t.name}
              />
            </Card>
          )
        )}
        {tab === "exposes" && (
          <Card title="What it may expose">
            <Row label="Resources">{server.resources.length ? server.resources.map((g) => <Tag key={g}>{g}</Tag>) : <span style={{ color: "var(--eg-faint)" }}>none</span>}</Row>
            <Row label="Templates">{server.templates.length ? server.templates.map((g) => <Tag key={g}>{g}</Tag>) : <span style={{ color: "var(--eg-faint)" }}>none</span>}</Row>
            <Row label="Prompts">{server.prompts.length ? server.prompts.map((g) => <Tag key={g}>{g}</Tag>) : <span style={{ color: "var(--eg-faint)" }}>none</span>}</Row>
            <div style={{ fontSize: 12, color: "var(--eg-faint)", marginTop: 12 }}>A server exposes resources and prompts only through its allowlists: what they do not name, it does not expose.</div>
          </Card>
        )}
        {tab === "policy" && (
          <Card title="Effective allow / deny">
            <Row label="Profile">{server.profile ? <Tag tone="brand">{server.profile}</Tag> : <span style={{ color: "var(--eg-faint)" }}>none</span>}</Row>
            <Row label="Allow globs">
              {server.allowTools ? server.allowTools.map((g) => <Tag key={g}>{g}</Tag>) : <span style={{ color: "var(--eg-muted)", fontSize: 13 }}>allow all (subject to deny)</span>}
            </Row>
            <Row label="Deny globs">
              {server.deny.length ? server.deny.map((g) => <Tag key={g}>{g}</Tag>) : <span style={{ color: "var(--eg-faint)" }}>—</span>}
            </Row>
            <div style={{ fontSize: 12, color: "var(--eg-faint)", marginTop: 12 }}>Deny wins over allow. Anything not matched is denied by default, and audited.</div>
          </Card>
        )}
        {tab === "connection" && <Connection server={server} />}
      </div>

      {asking && (
        <Modal open onClose={() => setAsking(null)} width={480} title={ACTIONS[asking].title}
          footer={<>
            <Button onClick={() => setAsking(null)}>Cancel</Button>
            <Button variant={ACTIONS[asking].variant} onClick={() => act(asking)}>{ACTIONS[asking].confirm}</Button>
          </>}>
          <div style={{ fontSize: 14, color: "var(--eg-muted)" }}>{ACTIONS[asking].text}</div>
          <div style={{ fontSize: 12, color: "var(--eg-faint)", marginTop: 10 }}>It is recorded in the ledger, with you as its actor.</div>
        </Modal>
      )}
    </div>
  );
}

function Connection({ server }) {
  const error = server.last_error;
  const credential = server.credential;
  return (
    <Card title="Its connection">
      <Row label="Health"><Health value={server.status} /></Row>
      <Row label="Restarts"><span className="mono">{server.restarts ?? 0}</span></Row>
      <Row label="Last error">{error ? <span style={{ fontSize: 13 }}><span className="mono">{H.fmtTime(error.at_unix_ms)}</span> · {error.message}</span> : <span style={{ color: "var(--eg-faint)" }}>none</span>}</Row>
      {server.tls && (
        <>
          <Row label="TLS">
            <Badge tone={server.tls.verify === "disabled" ? "danger" : "good"}>{server.tls.verify}</Badge>
            {server.tls.not_after && <span style={{ fontSize: 12, color: "var(--eg-muted)" }}>certificate until <span className="mono">{server.tls.not_after}</span></span>}
          </Row>
          {server.tls.fingerprint && <Row label="Fingerprint"><span className="mono" style={{ fontSize: 11, wordBreak: "break-all" }}>{server.tls.fingerprint}</span></Row>}
        </>
      )}
      {credential && (
        <Row label="Credentials">
          {credential.last_error
            ? <span style={{ fontSize: 13 }}><Badge tone="danger">refused</Badge> {credential.last_error.message}</span>
            : credential.last_ok ? <Badge tone="good">taken</Badge> : <span style={{ color: "var(--eg-faint)" }}>not used yet</span>}
          {credential.expires_at && <span style={{ fontSize: 12, color: "var(--eg-muted)" }}>expires <span className="mono">{credential.expires_at}</span></span>}
        </Row>
      )}
    </Card>
  );
}

function Row({ label, children }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "120px 1fr", gap: 12, padding: "9px 0", borderBottom: "1px solid var(--eg-border-soft)", alignItems: "center" }}>
      <span style={{ fontSize: 12, color: "var(--eg-muted)" }}>{label}</span>
      <span style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>{children}</span>
    </div>
  );
}
