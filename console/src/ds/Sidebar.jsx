// SPDX-License-Identifier: Apache-2.0
import React from "react";
import { BrandMark } from "./BrandMark";
import { Avatar } from "./Avatar";

/**
 * MCPdef Sidebar — the fixed 230px nav rail. Brand lockup on top, one or more
 * labeled nav groups, a user chip at the foot. Active item gets a panel fill +
 * an inset brand rail on its leading edge. Icons are 16px.
 */
export function Sidebar({ items = [], sections = null, active, onSelect, sectionLabel = "Govern", sub = "GOVERNANCE", user, footer, style = {} }) {
  const groups = sections && sections.length ? sections : [{ label: sectionLabel, items }];
  return (
    <nav
      style={{
        background: "var(--eg-bg-elev)",
        borderRight: "1px solid var(--eg-border)",
        display: "flex",
        flexDirection: "column",
        padding: "18px 14px",
        width: "var(--sidebar-w, 230px)",
        minHeight: "100%",
        fontFamily: "var(--font-sans)",
        boxSizing: "border-box",
        ...style,
      }}
    >
      <div style={{ padding: "4px 8px 16px", flex: "none" }}>
        <BrandMark sub={sub} />
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 4, overflowY: "auto", flex: 1, minHeight: 0, margin: "0 -4px", padding: "0 4px" }}>
        {groups.map((g, gi) => (
          <React.Fragment key={gi}>
            {g.label && (
              <div style={{ fontSize: 10, color: "var(--eg-faint)", letterSpacing: "1.2px", textTransform: "uppercase", padding: gi === 0 ? "10px 8px 6px" : "16px 8px 6px" }}>
                {g.label}
              </div>
            )}
            {g.items.map((it) => (
              <NavItem key={it.key} item={it} active={active === it.key} onSelect={onSelect} />
            ))}
          </React.Fragment>
        ))}
      </div>

      <div style={{ paddingTop: 12, marginTop: 8, borderTop: "1px solid var(--eg-border-soft)", flex: "none" }}>
        {footer ||
          (user && (
            <div style={{ display: "flex", alignItems: "center", gap: 9, padding: 8, borderRadius: 8 }}>
              <Avatar name={user.name} email={user.email} />
              <div style={{ overflow: "hidden" }}>
                <div style={{ fontSize: 13, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", color: "var(--eg-fg)" }}>{user.email || user.name}</div>
                {user.role && <small style={{ color: "var(--eg-faint)" }}>{user.role}</small>}
              </div>
            </div>
          ))}
      </div>
    </nav>
  );
}

function NavItem({ item, active, onSelect }) {
  const [hover, setHover] = React.useState(false);
  return (
    <a
      href={item.href || `#${item.key}`}
      aria-current={active ? "page" : undefined}
      onClick={(e) => { if (onSelect) { e.preventDefault(); onSelect(item.key); } }}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: "8px 10px",
        borderRadius: "var(--radius-ctrl, 8px)",
        color: active || hover ? "var(--eg-fg)" : "var(--eg-muted)",
        background: active ? "var(--eg-panel)" : hover ? "var(--eg-border-soft)" : "transparent",
        boxShadow: active ? "inset 2px 0 0 var(--eg-brand)" : "none",
        fontWeight: 500,
        fontSize: 14,
        textDecoration: "none",
        transition: "background var(--dur-fast,120ms) ease, color var(--dur-fast,120ms) ease",
      }}
    >
      {item.icon && <span style={{ width: 16, height: 16, display: "inline-flex", flex: "none" }}>{item.icon}</span>}
      <span style={{ flex: 1 }}>{item.label}</span>
      {item.badge != null && item.badge !== 0 && (
        <span style={{ fontSize: 11, fontWeight: 600, color: "var(--eg-danger)" }}>{item.badge}</span>
      )}
    </a>
  );
}
