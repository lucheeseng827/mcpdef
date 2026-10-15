// SPDX-License-Identifier: Apache-2.0
import React from "react";

/** MCPdef KPI — a big metric with a label above and a footnote below. `accent`
 * tints the value green (a healthy/positive figure). The overview stat tile. */
export function Kpi({ label, value, foot, accent = false, size = "lg", style = {} }) {
  const valSize = size === "sm" ? 22 : 28;
  return (
    <div
      style={{
        background: "var(--eg-panel)",
        border: "1px solid var(--eg-border)",
        borderRadius: "var(--radius, 10px)",
        padding: "16px 18px",
        fontFamily: "var(--font-sans)",
        ...style,
      }}
    >
      <div style={{ color: "var(--eg-muted)", fontSize: 12 }}>{label}</div>
      <div
        style={{
          fontSize: valSize,
          fontWeight: 700,
          letterSpacing: "-0.6px",
          marginTop: 6,
          color: accent ? "var(--eg-good)" : "var(--eg-fg)",
        }}
      >
        {value}
      </div>
      {foot && <div style={{ color: "var(--eg-faint)", fontSize: 12, marginTop: 6 }}>{foot}</div>}
    </div>
  );
}
