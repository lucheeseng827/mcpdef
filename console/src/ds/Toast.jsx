// SPDX-License-Identifier: Apache-2.0
import React from "react";

/**
 * MCPdef Toast — a bordered notice with a tone rail on its leading edge. Optional
 * icon + title + body + dismiss. For transient confirmations ("Chain verified")
 * and warnings ("Backend unreachable").
 */
export function Toast({ tone = "default", title, children, onClose, icon = null, style = {} }) {
  const color =
    tone === "good" ? "var(--eg-good)" :
    tone === "warn" ? "var(--eg-warn)" :
    tone === "danger" ? "var(--eg-danger)" :
    "var(--eg-brand)";
  return (
    <div
      role="status"
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: 10,
        background: "var(--eg-panel)",
        border: "1px solid var(--eg-border)",
        borderRadius: "var(--radius-ctrl, 8px)",
        boxShadow: "var(--shadow-overlay)",
        padding: "12px 14px",
        minWidth: 260,
        maxWidth: 380,
        fontFamily: "var(--font-sans)",
        borderLeft: `3px solid ${color}`,
        ...style,
      }}
    >
      {icon && <span style={{ color, display: "inline-flex", marginTop: 1 }}>{icon}</span>}
      <div style={{ flex: 1, minWidth: 0 }}>
        {title && <div style={{ fontSize: 13, fontWeight: 600, color: "var(--eg-fg)" }}>{title}</div>}
        {children && <div style={{ fontSize: 12, color: "var(--eg-muted)", marginTop: title ? 2 : 0 }}>{children}</div>}
      </div>
      {onClose && (
        <button onClick={onClose} aria-label="Dismiss" style={{ background: "none", border: "none", color: "var(--eg-faint)", cursor: "pointer", fontSize: 15, lineHeight: 1, padding: 0 }}>×</button>
      )}
    </div>
  );
}
