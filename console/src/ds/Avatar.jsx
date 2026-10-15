// SPDX-License-Identifier: Apache-2.0
import React from "react";

/** MCPdef Avatar — initials in a brand-dim square (≥30px) or circle. Identity for
 * an operator/agent principal in the sidebar chip and audit rows. */
export function Avatar({ name, email, size = 26, style = {} }) {
  const src = name || email || "?";
  const initial = src.trim().slice(0, 1).toUpperCase();
  return (
    <span
      style={{
        width: size,
        height: size,
        borderRadius: size >= 30 ? "var(--radius-mark,7px)" : "50%",
        background: "var(--eg-brand-dim)",
        color: "var(--eg-fg)",
        display: "grid",
        placeItems: "center",
        fontSize: Math.round(size * 0.46),
        fontWeight: 600,
        fontFamily: "var(--font-sans)",
        flex: "none",
        ...style,
      }}
    >
      {initial}
    </span>
  );
}
