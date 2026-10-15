// SPDX-License-Identifier: Apache-2.0
import React from "react";

/**
 * MCPdef PageHeader — the title block: optional back link, H1 (negative-tracked),
 * a muted sub-line, and right-aligned actions. Top of every screen.
 */
export function PageHeader({ title, sub, back, actions, style = {} }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "space-between",
        gap: 16,
        marginBottom: 22,
        fontFamily: "var(--font-sans)",
        ...style,
      }}
    >
      <div style={{ minWidth: 0 }}>
        {back && (
          <a
            href={back.href || "#"}
            onClick={back.onClick ? (e) => { e.preventDefault(); back.onClick(); } : undefined}
            style={{ fontSize: 13, color: "var(--eg-faint)", textDecoration: "none" }}
          >
            ← {back.label || "Back"}
          </a>
        )}
        <h1 style={{ fontSize: 22, fontWeight: 700, letterSpacing: "-0.4px", margin: back ? "4px 0 0" : 0, color: "var(--eg-fg)" }}>{title}</h1>
        {sub && <div style={{ color: "var(--eg-muted)", marginTop: 4 }}>{sub}</div>}
      </div>
      {actions && <div style={{ display: "flex", gap: 10, alignItems: "center", flex: "none" }}>{actions}</div>}
    </div>
  );
}
