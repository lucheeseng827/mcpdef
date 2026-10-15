// SPDX-License-Identifier: Apache-2.0
import React from "react";

/**
 * MCPdef text input. Optional label + mono mode (ids/tokens/paths). Focus swaps
 * the border to brand blue — no ring, no glow. `invalid` swaps to danger.
 */
export function Input({ label, hint, mono = false, invalid = false, id, style = {}, ...rest }) {
  const [focus, setFocus] = React.useState(false);
  const inputId = id || (label ? `in-${label.replace(/\s+/g, "-").toLowerCase()}` : undefined);
  return (
    <div>
      {label && (
        <label
          htmlFor={inputId}
          style={{ display: "block", fontSize: 12, color: "var(--eg-muted)", margin: "0 0 5px", fontFamily: "var(--font-sans)" }}
        >
          {label}
          {hint && <span style={{ color: "var(--eg-faint)" }}> · {hint}</span>}
        </label>
      )}
      <input
        id={inputId}
        onFocus={() => setFocus(true)}
        onBlur={() => setFocus(false)}
        style={{
          width: "100%",
          background: "var(--eg-bg)",
          color: "var(--eg-fg)",
          border: `1px solid ${
            invalid
              ? "var(--eg-danger)"
              : focus
              ? "var(--eg-brand)"
              : "var(--eg-border)"
          }`,
          borderRadius: "var(--radius-ctrl, 8px)",
          padding: "9px 11px",
          fontSize: 13,
          fontFamily: mono ? "var(--font-mono)" : "var(--font-sans)",
          outline: "none",
          transition: "border-color var(--dur-fast,120ms) ease",
          ...style,
        }}
        {...rest}
      />
    </div>
  );
}
