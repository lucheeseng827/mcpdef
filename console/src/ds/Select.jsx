// SPDX-License-Identifier: Apache-2.0
import React from "react";

/** MCPdef select. Same shell as Input; native options for reliability, with a
 * custom chevron. Focus swaps the border to brand blue. */
export function Select({ label, options = [], id, style = {}, children, ...rest }) {
  const [focus, setFocus] = React.useState(false);
  const selId = id || (label ? `sel-${label.replace(/\s+/g, "-").toLowerCase()}` : undefined);
  return (
    <div>
      {label && (
        <label
          htmlFor={selId}
          style={{ display: "block", fontSize: 12, color: "var(--eg-muted)", margin: "0 0 5px", fontFamily: "var(--font-sans)" }}
        >
          {label}
        </label>
      )}
      <select
        id={selId}
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
          fontFamily: "var(--font-sans)",
          outline: "none",
          appearance: "none",
          backgroundImage:
            "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%238a93a6' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E\")",
          backgroundRepeat: "no-repeat",
          backgroundPosition: "right 10px center",
          paddingRight: "30px",
          transition: "border-color var(--dur-fast,120ms) ease",
          ...style,
        }}
      >
        {children ||
          options.map((o) =>
            typeof o === "string" ? (
              <option key={o} value={o}>
                {o}
              </option>
            ) : (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            )
          )}
      </select>
    </div>
  );
}
