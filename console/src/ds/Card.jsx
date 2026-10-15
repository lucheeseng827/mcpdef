// SPDX-License-Identifier: Apache-2.0
import React from "react";

/**
 * MCPdef Card — the flat, bordered surface everything sits on. Optional header
 * strip (title + actions) divided by a hairline. No shadow.
 */
export function Card({ title, actions, children, padded = true, style = {}, headStyle = {}, ...rest }) {
  const hasHead = title || actions;
  return (
    <div
      style={{
        background: "var(--eg-panel)",
        border: "1px solid var(--eg-border)",
        borderRadius: "var(--radius, 10px)",
        overflow: "hidden",
        ...style,
      }}
      {...rest}
    >
      {hasHead && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 12,
            padding: "12px 16px",
            borderBottom: "1px solid var(--eg-border-soft)",
            ...headStyle,
          }}
        >
          <div style={{ fontSize: 14, fontWeight: 600, color: "var(--eg-fg)", fontFamily: "var(--font-sans)" }}>{title}</div>
          {actions && <div style={{ display: "flex", gap: 8, alignItems: "center" }}>{actions}</div>}
        </div>
      )}
      <div style={{ padding: padded ? 18 : 0 }}>{children}</div>
    </div>
  );
}
