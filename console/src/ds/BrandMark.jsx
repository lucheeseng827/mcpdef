// SPDX-License-Identifier: Apache-2.0
import React from "react";

/**
 * MCPdef BrandMark — the gradient (blue→violet) rounded square paired with the
 * "MCPdef" wordmark and an UPPERCASE tracked sub-line. NOTE: MCPdef ships no
 * official logo (none exists in the source repo); the square is the design
 * system's generic lockup motif, inherited from the eggrd console DS, and the
 * wordmark is plain type. Swap the mark for a real logo asset if one lands.
 */
export function BrandMark({ sub = "GOVERNANCE", size = 26, markOnly = false, wordmark = "MCPdef", glyph = "M", style = {} }) {
  const mark = (
    <span
      aria-hidden="true"
      style={{
        width: size,
        height: size,
        borderRadius: "var(--radius-mark, 7px)",
        background: "var(--eg-gradient, linear-gradient(135deg,#4f8cff,#8b6cff))",
        display: "grid",
        placeItems: "center",
        color: "#fff",
        fontWeight: 700,
        fontSize: Math.round(size * 0.5),
        fontFamily: "var(--font-mono)",
        letterSpacing: "-0.5px",
        flex: "none",
      }}
    >
      {glyph}
    </span>
  );
  if (markOnly) return mark;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, ...style }}>
      {mark}
      <div style={{ lineHeight: 1.1 }}>
        <div style={{ fontWeight: 700, letterSpacing: "-0.2px", fontFamily: "var(--font-sans)", color: "var(--eg-fg)", fontSize: 16 }}>{wordmark}</div>
        {sub && <div style={{ fontSize: 10, color: "var(--eg-faint)", letterSpacing: "1.5px", textTransform: "uppercase" }}>{sub}</div>}
      </div>
    </div>
  );
}
