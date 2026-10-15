// SPDX-License-Identifier: Apache-2.0
import React from "react";

/**
 * MCPdef Sparkline — a tiny inline metric chart. SVG line with an optional soft
 * area fill, tinted by tone. No axes, no grid — it's a glance, not a chart.
 * Call volume / deny trend inside a KPI or table cell.
 */
export function Sparkline({ data, width = 120, height = 32, tone = "brand", area = true, strokeWidth = 1.5, style = {} }) {
  const color =
    tone === "good" ? "var(--eg-good)" :
    tone === "warn" ? "var(--eg-warn)" :
    tone === "danger" ? "var(--eg-danger)" :
    "var(--eg-brand)";

  const reactId = React.useId();
  if (!data.length) return <svg width={width} height={height} style={style} />;

  const max = Math.max(...data);
  const min = Math.min(...data);
  const span = max - min || 1;
  const stepX = width / (data.length - 1 || 1);
  const pts = data.map((v, i) => {
    const x = i * stepX;
    const y = height - ((v - min) / span) * (height - strokeWidth * 2) - strokeWidth;
    return [x, y];
  });
  const line = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
  const fill = `${line} L${width} ${height} L0 ${height} Z`;
  const gid = "sp" + reactId.replace(/:/g, "");

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} style={{ display: "block", ...style }}>
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.22" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      {area && <path d={fill} fill={`url(#${gid})`} stroke="none" />}
      <path d={line} fill="none" stroke={color} strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
