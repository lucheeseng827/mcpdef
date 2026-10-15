// SPDX-License-Identifier: Apache-2.0
import React from "react";

/**
 * MCPdef DataTable — a CSS-grid table (not a real <table>), with a table's
 * roles, so assistive technology reads it as one. Columns define the grid
 * template, header, alignment, and a cell renderer. Rows are clickable when
 * onRowClick is given (audit row → detail drawer): the table is then a grid
 * whose rows take focus and open on Enter or Space. The workhorse of the
 * audit log, servers list, policy rules, and findings screens.
 */
export function DataTable({ columns, rows, onRowClick, rowKey, empty = "Nothing here yet.", style = {} }) {
  const template = columns.map((c) => c.width || "1fr").join(" ");
  const interactive = !!onRowClick;
  return (
    <div
      role={interactive ? "grid" : "table"}
      style={{
        display: "grid",
        border: "1px solid var(--eg-border)",
        borderRadius: "var(--radius, 10px)",
        overflow: "hidden",
        fontFamily: "var(--font-sans)",
        ...style,
      }}
    >
      <div
        role="row"
        style={{
          display: "grid",
          gridTemplateColumns: template,
          alignItems: "center",
          gap: 12,
          padding: "11px 16px",
          background: "var(--eg-bg-elev)",
          color: "var(--eg-muted)",
          fontSize: 12,
          textTransform: "uppercase",
          letterSpacing: "0.5px",
          borderBottom: "1px solid var(--eg-border-soft)",
        }}
      >
        {columns.map((c, i) => (
          <div key={c.key ?? i} role="columnheader" style={{ textAlign: c.align || "left" }}>{c.header}</div>
        ))}
      </div>
      {rows.length === 0 ? (
        <div role="row"><div role="cell" style={{ padding: 28, textAlign: "center", color: "var(--eg-faint)", fontSize: 13 }}>{empty}</div></div>
      ) : (
        rows.map((r, ri) => (
          <Row
            key={rowKey ? rowKey(r, ri) : ri}
            row={r}
            ri={ri}
            columns={columns}
            template={template}
            last={ri === rows.length - 1}
            onRowClick={onRowClick}
          />
        ))
      )}
    </div>
  );
}

function Row({ row, ri, columns, template, last, onRowClick }) {
  const [hover, setHover] = React.useState(false);
  const clickable = !!onRowClick;
  return (
    <div
      role="row"
      tabIndex={clickable ? 0 : undefined}
      onClick={clickable ? () => onRowClick(row, ri) : undefined}
      onKeyDown={clickable ? (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onRowClick(row, ri); }
      } : undefined}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        display: "grid",
        gridTemplateColumns: template,
        alignItems: "center",
        gap: 12,
        padding: "11px 16px",
        borderBottom: last ? "none" : "1px solid var(--eg-border-soft)",
        cursor: clickable ? "pointer" : "default",
        background: hover && clickable ? "var(--eg-bg-elev)" : "transparent",
        transition: "background var(--dur-fast,120ms) ease",
        fontSize: 13,
      }}
    >
      {columns.map((c, ci) => (
        <div key={c.key ?? ci} role={clickable ? "gridcell" : "cell"} style={{ textAlign: c.align || "left", minWidth: 0 }}>
          {c.cell ? c.cell(row, ri) : c.key ? row[c.key] : null}
        </div>
      ))}
    </div>
  );
}
