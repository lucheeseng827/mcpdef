// SPDX-License-Identifier: Apache-2.0
import React from "react";

/**
 * MCPdef MeterBar — a value-vs-max bar. Auto-tints by fill ratio (good → warn
 * ≥75% → danger ≥100%), or force a tone. For rate-limit headroom, quota use,
 * deny-by-rule share. Optional label + mono value on top.
 */
export function MeterBar({ value = 0, max = 100, tone, label, valueLabel, height = 8, style = {} }) {
  const pct = Math.max(0, Math.min(100, max ? (value / max) * 100 : 0));
  const auto = pct >= 100 ? "danger" : pct >= 75 ? "warn" : "good";
  const t = tone || auto;
  const color =
    t === "danger" ? "var(--eg-danger)" :
    t === "warn" ? "var(--eg-warn)" :
    t === "brand" ? "var(--eg-brand)" :
    "var(--eg-good)";
  return (
    <div style={{ fontFamily: "var(--font-sans)", ...style }}>
      {(label || valueLabel) && (
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6, fontSize: 12 }}>
          {label && <span style={{ color: "var(--eg-muted)" }}>{label}</span>}
          {valueLabel && <span style={{ color: "var(--eg-faint)", fontFamily: "var(--font-mono)" }}>{valueLabel}</span>}
        </div>
      )}
      <div style={{ height, borderRadius: 999, background: "var(--eg-bg)", border: "1px solid var(--eg-border)", overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 999, transition: "width var(--dur-slow,240ms) var(--ease-standard,ease)" }} />
      </div>
    </div>
  );
}
