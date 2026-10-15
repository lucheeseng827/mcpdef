// SPDX-License-Identifier: Apache-2.0
import React from "react";

/** MCPdef toggle switch. Brand-blue when on; calm gray track when off. The knob
 * eases across; the track cross-fades. For boolean settings (inspect on/off,
 * live-tail). */
export function Switch({ checked = false, onChange, label, disabled = false, id }) {
  const track = {
    width: 36,
    height: 20,
    borderRadius: 999,
    background: checked ? "var(--eg-brand)" : "var(--eg-border)",
    border: `1px solid ${checked ? "var(--eg-brand)" : "var(--eg-border)"}`,
    position: "relative",
    transition: "background var(--dur-base,180ms) ease",
    flex: "none",
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.5 : 1,
  };
  const knob = {
    position: "absolute",
    top: 2,
    left: checked ? 18 : 2,
    width: 14,
    height: 14,
    borderRadius: "50%",
    background: "#fff",
    transition: "left var(--dur-base,180ms) var(--ease-standard, ease)",
  };
  // One button, its label its name: clicking either the track or the label
  // toggles it, and Enter and Space do, as for any button.
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      id={id}
      disabled={disabled}
      onClick={() => onChange && onChange(!checked)}
      style={{ display: "inline-flex", alignItems: "center", gap: 10, background: "none", border: 0, padding: 0, color: "inherit", cursor: disabled ? "not-allowed" : "pointer", fontFamily: "var(--font-sans)" }}
    >
      <span aria-hidden="true" style={track}>
        <span style={knob} />
      </span>
      {label && <span style={{ fontSize: 13, color: "var(--eg-fg)" }}>{label}</span>}
    </button>
  );
}
