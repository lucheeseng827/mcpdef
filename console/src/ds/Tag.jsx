// SPDX-License-Identifier: Apache-2.0
import React from "react";

/** MCPdef Tag — a small mono label for tool names, config keys, metadata.
 * Optionally removable (filter chips). Mono because it names literal data. */
export function Tag({ children, removable = false, onRemove, tone = "default", style = {} }) {
  const color = tone === "brand" ? "var(--eg-brand)" : "var(--eg-muted)";
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: "2px 8px",
        borderRadius: "var(--radius-ctrl, 8px)",
        fontSize: 12,
        fontFamily: "var(--font-mono)",
        background: "var(--eg-bg)",
        border: "1px solid var(--eg-border)",
        color,
        whiteSpace: "nowrap",
        ...style,
      }}
    >
      {children}
      {removable && (
        <button
          onClick={onRemove}
          aria-label="Remove tag"
          style={{ background: "none", border: "none", color: "var(--eg-faint)", cursor: "pointer", padding: 0, lineHeight: 1, fontSize: 13, display: "inline-flex" }}
        >
          ×
        </button>
      )}
    </span>
  );
}
