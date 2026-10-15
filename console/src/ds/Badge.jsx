// SPDX-License-Identifier: Apache-2.0
import React from "react";

const TONES = {
  default: { color: "var(--eg-muted)", border: "var(--eg-border)", dot: "var(--eg-muted)" },
  good: { color: "var(--eg-good)", border: "var(--eg-good-border)", dot: "var(--eg-good)" },
  warn: { color: "var(--eg-warn)", border: "var(--eg-warn-border)", dot: "var(--eg-warn)" },
  danger: { color: "var(--eg-danger)", border: "var(--eg-danger-border)", dot: "var(--eg-danger)" },
  brand: { color: "var(--eg-brand)", border: "var(--eg-brand-border)", dot: "var(--eg-brand)" },
};

/** MCPdef Badge — a pill carrying status. Tones tint text + border, never a solid
 * fill. Optional leading status dot. allow=good, deny=danger, drift=warn. */
export function Badge({ children, tone = "default", dot = false, style = {} }) {
  const t = TONES[tone] || TONES.default;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: "2px 9px",
        borderRadius: "var(--radius-pill, 999px)",
        fontSize: 12,
        fontWeight: 500,
        fontFamily: "var(--font-sans)",
        border: `1px solid ${t.border}`,
        color: t.color,
        whiteSpace: "nowrap",
        ...style,
      }}
    >
      {dot && <span style={{ width: 7, height: 7, borderRadius: "50%", background: t.dot, flex: "none" }} />}
      {children}
    </span>
  );
}
