// SPDX-License-Identifier: Apache-2.0
import React from "react";

/** MCPdef EmptyState — dashed-border placeholder for "nothing here yet": a fresh
 * gateway with zero audit records, inspect off, no findings. Optional icon,
 * title, body, and a single call-to-action. */
export function EmptyState({ icon = null, title, children, action = null, style = {} }) {
  return (
    <div
      style={{
        textAlign: "center",
        color: "var(--eg-faint)",
        padding: 40,
        border: "1px dashed var(--eg-border)",
        borderRadius: "var(--radius, 10px)",
        fontFamily: "var(--font-sans)",
        ...style,
      }}
    >
      {icon && <div style={{ display: "inline-flex", color: "var(--eg-faint)", marginBottom: 10 }}>{icon}</div>}
      {title && <div style={{ color: "var(--eg-muted)", fontSize: 14, marginBottom: 4 }}>{title}</div>}
      {children && <div style={{ fontSize: 13 }}>{children}</div>}
      {action && <div style={{ marginTop: 16, display: "flex", justifyContent: "center" }}>{action}</div>}
    </div>
  );
}
