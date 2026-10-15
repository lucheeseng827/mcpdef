// SPDX-License-Identifier: Apache-2.0
/* MCPdef console — app shell. Asks the gateway who the caller is, sends one
 * who could sign in and has not to sign in, then fetches each dataset on its
 * own and hands them to the screens. A screen whose data the gateway does not
 * serve, or will not show this caller, says so; the rest of the console
 * carries on. The screen is in the URL's fragment, so a sign-in comes back to
 * it. */
import React from "react";
import { Sidebar, Button, Icon, EmptyState, Avatar, Select } from "./ds";
import { THEMES, storedTheme, chooseTheme } from "./theme.js";
import { loadData, getSession, signIn, signOut, BASE } from "./api/client.js";
import Overview from "./screens/Overview.jsx";
import AuditLog from "./screens/AuditLog.jsx";
import Servers from "./screens/Servers.jsx";
import Policy from "./screens/Policy.jsx";
import Inspect from "./screens/Inspect.jsx";
import Config from "./screens/Config.jsx";
import Connections from "./screens/Connections.jsx";
import Identity from "./screens/Identity.jsx";
import Connect from "./screens/Connect.jsx";

const GOVERN = [
  { key: "overview", label: "Overview", icon: <Icon name="grid" /> },
  { key: "audit", label: "Audit log", icon: <Icon name="list" /> },
  { key: "servers", label: "Servers & tools", icon: <Icon name="layers" /> },
  { key: "policy", label: "Policy", icon: <Icon name="shield" /> },
  { key: "inspect", label: "Inspect", icon: <Icon name="spark" /> },
  { key: "config", label: "Config", icon: <Icon name="settings" /> },
];
const REACH = [
  { key: "connections", label: "Connections", icon: <Icon name="lock" /> },
  { key: "identity", label: "Identity", icon: <Icon name="users" /> },
  { key: "connect", label: "Connect", icon: <Icon name="send" /> },
];
const NAV = [...GOVERN, ...REACH];

// The datasets each screen needs, as loadData names them.
const NEEDS = {
  overview: ["metrics", "info", "records"],
  audit: ["servers"],
  servers: ["servers"],
  policy: ["rules", "roles", "profiles"],
  inspect: ["findings", "info"],
  config: ["config"],
  connections: ["tls", "credentials", "servers"],
  identity: [],
  connect: ["info"],
};

function screenOf(hash) {
  const key = hash.replace(/^#\/?/, "");
  return NAV.some((n) => n.key === key) ? key : "overview";
}

function Centered({ children }) {
  return <div style={{ minHeight: 320, display: "grid", placeItems: "center" }}>{children}</div>;
}

/** What a screen lacks: the role it needs, the endpoints that failed, or the
 * ones it waits on. */
function Unavailable({ missing, onRetry }) {
  const forbidden = missing.filter((m) => m.status === 403);
  const unserved = missing.filter((m) => m.status === 404 || m.status === 405);
  const failed = missing.filter((m) => !forbidden.includes(m) && !unserved.includes(m));
  const title = forbidden.length ? "Not for your role"
    : failed.length ? "Couldn't load this view"
    : "Not served by this gateway yet";
  const retry = failed.length
    ? <Button variant="primary" icon={<Icon name="route" />} onClick={onRetry}>Retry</Button>
    : undefined;
  return (
    <Centered>
      <EmptyState icon={<Icon name="alert-triangle" size={22} />} title={title} action={retry}>
        {forbidden.map((m) => <div key={m.path}>{m.detail}</div>)}
        {failed.map((m) => <div key={m.path}><span className="mono">{m.path}</span>: {m.detail}</div>)}
        {unserved.length > 0 && (
          <div>This view reads {unserved.map((m, i) => <span key={m.path}>{i > 0 && ", "}<span className="mono">{m.path}</span></span>)}, which this gateway's admin API does not serve yet.</div>
        )}
      </EmptyState>
    </Centered>
  );
}

/** A screen that fails to draw says so, and the rest of the console carries
 * on: a new screen, or a retry, draws afresh. */
class ScreenBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { failed: null };
  }

  static getDerivedStateFromError(error) {
    return { failed: error.message || String(error) };
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <Centered>
        <EmptyState icon={<Icon name="alert-triangle" size={22} />} title="This view failed to draw"
          action={<Button variant="primary" icon={<Icon name="route" />} onClick={this.props.onRetry}>Retry</Button>}>
          <div>{this.state.failed}</div>
        </EmptyState>
      </Centered>
    );
  }
}

/** A caller the gateway knows, holding no console role. */
function NoRole({ session }) {
  return (
    <Centered>
      <EmptyState icon={<Icon name="lock" size={22} />} title="No console role">
        <div>You are <span className="mono">{session.actor}</span>, which holds no console role.</div>
        <div style={{ marginTop: 8 }}>Ask for <span className="mono">console:viewer</span>, <span className="mono">console:operator</span> or <span className="mono">console:admin</span>.</div>
      </EmptyState>
    </Centered>
  );
}

/** Said at the top of every screen when nothing signs callers in. */
function OpenBanner() {
  return (
    <div role="status" style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", marginBottom: 18, borderRadius: 8, border: "1px solid var(--eg-warn-border)", background: "var(--eg-warn-fill)", fontSize: 13, color: "var(--eg-fg)" }}>
      <Icon name="alert-triangle" size={15} style={{ color: "var(--eg-warn)" }} />
      <span>No sign-in: whoever reaches this listener uses the console as <span className="mono">console:admin</span>.</span>
    </div>
  );
}

/** Light, dark, or as the system prefers; kept in this browser. */
function ThemeChoice() {
  const [theme, setTheme] = React.useState(storedTheme);
  return (
    <Select label="Theme" value={theme}
      onChange={(e) => { chooseTheme(e.target.value); setTheme(e.target.value); }}
      options={THEMES.map((t) => ({ value: t, label: t === "system" ? "as the system" : t }))} />
  );
}

/** Who is using the console, and, for one signed in, signing out. */
function Who({ session }) {
  const [leaving, setLeaving] = React.useState(false);
  const name = session.name || session.actor;
  return (
    <div style={{ display: "grid", gap: 8, padding: 8 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
        <Avatar name={name} />
        <div style={{ overflow: "hidden" }}>
          <div style={{ fontSize: 13, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", color: "var(--eg-fg)" }} title={session.actor}>{name}</div>
          <small style={{ color: "var(--eg-faint)" }}>{session.role || "no console role"}</small>
        </div>
      </div>
      {session.sign_out && (
        <Button size="sm" icon={<Icon name="lock" />} disabled={leaving}
          onClick={() => { setLeaving(true); signOut().catch(() => setLeaving(false)); }}>
          {leaving ? "Signing out…" : "Sign out"}
        </Button>
      )}
      <ThemeChoice />
    </div>
  );
}

export default function App() {
  const [session, setSession] = React.useState(null);
  const [screen, setScreen] = React.useState(() => screenOf(window.location.hash));
  const [data, setData] = React.useState(null);
  const [error, setError] = React.useState(null);
  // Data is fetched again after a change; a screen is drawn afresh only
  // when it failed and is retried.
  const [reloadKey, setReloadKey] = React.useState(0);
  const [retries, setRetries] = React.useState(0);
  const refresh = React.useCallback(() => setReloadKey((k) => k + 1), []);
  const retry = () => { setRetries((n) => n + 1); refresh(); };

  React.useEffect(() => {
    const follow = () => setScreen(screenOf(window.location.hash));
    window.addEventListener("hashchange", follow);
    return () => window.removeEventListener("hashchange", follow);
  }, []);
  const select = (key) => { window.location.hash = key; setScreen(key); };

  React.useEffect(() => {
    let live = true;
    setError(null);
    getSession()
      .then((s) => {
        if (!live) return;
        // One who could sign in and has not is sent to, and back here after.
        if (s.sign_in && !s.role) signIn(s.sign_in);
        else setSession(s);
      })
      .catch((e) => { if (live && e.status !== 401) setError(e.message || String(e)); });
    return () => { live = false; };
  }, [reloadKey]);

  React.useEffect(() => {
    if (!session || !session.role) return undefined;
    let live = true;
    loadData()
      .then((d) => { if (live) setData(d); })
      .catch((e) => { if (live) setError(e.message || String(e)); });
    return () => { live = false; };
  }, [session, reloadKey]);

  const govern = GOVERN.map((n) => (n.key === "inspect" && data && data.findings ? { ...n, badge: data.findings.length } : n));

  let body;
  if (error) {
    body = (
      <Centered>
        <EmptyState icon={<Icon name="alert-triangle" size={22} />} title="Can't reach the admin API"
          action={<Button variant="primary" icon={<Icon name="route" />} onClick={retry}>Retry</Button>}>
          <div>{error}</div>
        </EmptyState>
      </Centered>
    );
  } else if (session && !session.role) {
    body = <NoRole session={session} />;
  } else if (!session || !data) {
    body = (
      <Centered>
        <div role="status" style={{ display: "flex", alignItems: "center", gap: 10, color: "var(--eg-muted)", fontSize: 14 }}>
          <span style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--eg-brand)", boxShadow: "0 0 0 3px var(--eg-brand-fill)" }} />
          Connecting to <span className="mono">{BASE}</span> …
        </div>
      </Centered>
    );
  } else {
    const have = { ...data, config: data.configText };
    const missing = NEEDS[screen]
      .filter((key) => have[key] == null)
      .map((key) => data.unavailable[key] || { path: key, status: 404 });
    const props = { data, session, onChanged: refresh };
    const screens = {
      overview: () => <Overview {...props} onOpenAudit={() => select("audit")} />,
      audit: () => <AuditLog {...props} />,
      servers: () => <Servers {...props} />,
      policy: () => <Policy {...props} />,
      inspect: () => <Inspect {...props} />,
      config: () => <Config {...props} />,
      connections: () => <Connections {...props} />,
      identity: () => <Identity {...props} />,
      connect: () => <Connect {...props} />,
    };
    body = missing.length
      ? <Unavailable missing={missing} onRetry={retry} />
      : <ScreenBoundary key={`${screen}-${retries}`} onRetry={retry}>{screens[screen]()}</ScreenBoundary>;
  }

  return (
    <div style={{ display: "grid", gridTemplateColumns: "230px 1fr", minHeight: "100vh" }}>
      <Sidebar
        active={screen}
        onSelect={select}
        sectionLabel="Govern"
        sub="GOVERNANCE"
        sections={[{ label: "Govern", items: govern }, { label: "Reach", items: REACH }]}
        footer={session ? <Who session={session} /> : <div style={{ padding: 8 }}><ThemeChoice /></div>}
      />
      <main style={{ padding: "28px 32px", maxWidth: 1200, width: "100%", margin: "0 auto" }}>
        {session && session.open && <OpenBanner />}
        {body}
      </main>
    </div>
  );
}
