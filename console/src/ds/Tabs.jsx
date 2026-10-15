// SPDX-License-Identifier: Apache-2.0
import React from "react";

/** MCPdef Tabs — an underline tab bar. Active tab gets brand-blue text + a 2px
 * underline; an optional mono badge (a count) trails each label. Used to switch
 * views within a screen (e.g. Rules / RBAC / Profiles on Policy). */
export function Tabs({ items, active, onSelect, style = {} }) {
  return (
    <div role="tablist" style={{ display: "flex", gap: 4, borderBottom: "1px solid var(--eg-border)", fontFamily: "var(--font-sans)", ...style }}>
      {items.map((it) => {
        const on = active === it.key;
        return (
          <button
            key={it.key}
            type="button"
            role="tab"
            aria-selected={on}
            onClick={() => onSelect && onSelect(it.key)}
            style={{
              background: "none",
              border: "none",
              cursor: "pointer",
              padding: "10px 12px",
              marginBottom: -1,
              fontSize: 13,
              fontWeight: 500,
              fontFamily: "var(--font-sans)",
              color: on ? "var(--eg-fg)" : "var(--eg-muted)",
              borderBottom: `2px solid ${on ? "var(--eg-brand)" : "transparent"}`,
              display: "inline-flex",
              alignItems: "center",
              gap: 7,
              transition: "color var(--dur-fast,120ms) ease",
            }}
          >
            {it.label}
            {it.badge != null && it.badge !== 0 && (
              <span style={{ fontSize: 11, color: "var(--eg-muted)", fontFamily: "var(--font-mono)" }}>{it.badge}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}
