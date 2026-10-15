// SPDX-License-Identifier: Apache-2.0
import React from "react";

/** MCPdef multi-line text. Used for policy/config bodies and pasted TOML to
 * validate; mono by default so structure lines up. Vertical resize only. */
export function Textarea({ label, mono = true, rows = 5, id, style = {}, ...rest }) {
  const [focus, setFocus] = React.useState(false);
  const taId = id || (label ? `ta-${label.replace(/\s+/g, "-").toLowerCase()}` : undefined);
  return (
    <div>
      {label && (
        <label
          htmlFor={taId}
          style={{ display: "block", fontSize: 12, color: "var(--eg-muted)", margin: "0 0 5px", fontFamily: "var(--font-sans)" }}
        >
          {label}
        </label>
      )}
      <textarea
        id={taId}
        rows={rows}
        {...rest}
        onFocus={(e) => { setFocus(true); rest.onFocus?.(e); }}
        onBlur={(e) => { setFocus(false); rest.onBlur?.(e); }}
        style={{
          width: "100%",
          background: "var(--eg-bg)",
          color: "var(--eg-fg)",
          border: `1px solid ${focus ? "var(--eg-brand)" : "var(--eg-border)"}`,
          borderRadius: "var(--radius-ctrl, 8px)",
          padding: "9px 11px",
          fontSize: 13,
          lineHeight: 1.6,
          fontFamily: mono ? "var(--font-mono)" : "var(--font-sans)",
          outline: "none",
          resize: "vertical",
          transition: "border-color var(--dur-fast,120ms) ease",
          ...style,
        }}
      />
    </div>
  );
}
