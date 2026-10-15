// SPDX-License-Identifier: Apache-2.0
import React from "react";

/**
 * MCPdef Button. Three intents (default / primary / danger), optional leading
 * icon, optional full-width. 8px radius, 8x14 padding, 13px medium text.
 * Flat: border + fill only, hover shifts border/background, no shadow.
 */
export function Button({
  children,
  variant = "default",
  size = "md",
  icon = null,
  fullWidth = false,
  disabled = false,
  type = "button",
  style = {},
  ...rest
}) {
  const [hover, setHover] = React.useState(false);
  const pad = size === "sm" ? "6px 11px" : "8px 14px";
  const font = size === "sm" ? "12px" : "13px";

  const base = {
    display: "inline-flex",
    alignItems: "center",
    justifyContent: fullWidth ? "center" : "flex-start",
    gap: "7px",
    padding: pad,
    borderRadius: "var(--radius-ctrl, 8px)",
    border: "1px solid var(--eg-border)",
    background: "var(--eg-bg-elev)",
    color: "var(--eg-fg)",
    fontFamily: "var(--font-sans)",
    fontWeight: 500,
    fontSize: font,
    lineHeight: 1.2,
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.5 : 1,
    width: fullWidth ? "100%" : "auto",
    transition:
      "border-color var(--dur-fast,120ms) ease, background var(--dur-fast,120ms) ease",
    whiteSpace: "nowrap",
  };

  const variants = {
    default: {},
    primary: {
      background: "var(--eg-brand)",
      borderColor: "var(--eg-brand)",
      color: "var(--eg-brand-ink)",
    },
    danger: {
      color: "var(--eg-danger)",
      borderColor: "var(--eg-danger-border)",
    },
  };

  const hoverStyle =
    !disabled && hover
      ? variant === "primary"
        ? { background: "var(--eg-brand-hover)" }
        : variant === "default"
        ? { borderColor: "var(--eg-faint)" }
        : { borderColor: "var(--eg-danger)" }
      : {};

  const { onMouseEnter, onMouseLeave, ...restProps } = rest;
  return (
    <button
      type={type}
      disabled={disabled}
      onMouseEnter={(e) => { setHover(true); onMouseEnter?.(e); }}
      onMouseLeave={(e) => { setHover(false); onMouseLeave?.(e); }}
      style={{ ...base, ...variants[variant], ...hoverStyle, ...style }}
      {...restProps}
    >
      {icon && (
        <span style={{ display: "inline-flex", width: 16, height: 16 }}>{icon}</span>
      )}
      {children}
    </button>
  );
}
