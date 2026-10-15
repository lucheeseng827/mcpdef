// SPDX-License-Identifier: Apache-2.0
import React from "react";

/** MCPdef TokenPill — a mono, word-breaking box for a literal string shown for
 * copy: a chain hash, an attestation digest, a redacted config pointer, a
 * brokered token surface. Copy button flips to a green "copied" confirmation. */
export function TokenPill({ value, copyable = true, style = {} }) {
  const [copied, setCopied] = React.useState(false);
  function copy() {
    // writeText is async — chain a rejection handler so a failed/blocked copy
    // doesn't flip to "copied" or surface an unhandled rejection.
    navigator.clipboard.writeText(value).then(
      () => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1400);
      },
      () => {
        /* clipboard unavailable */
      }
    );
  }
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        fontFamily: "var(--font-mono)",
        background: "var(--eg-bg)",
        border: "1px solid var(--eg-border)",
        borderRadius: "var(--radius-ctrl, 8px)",
        padding: "9px 11px",
        fontSize: 12,
        color: "var(--eg-fg)",
        ...style,
      }}
    >
      <span style={{ wordBreak: "break-all", flex: 1 }}>{value}</span>
      {copyable && (
        <button
          onClick={copy}
          style={{ background: "none", border: "none", color: copied ? "var(--eg-good)" : "var(--eg-faint)", cursor: "pointer", fontSize: 12, fontFamily: "var(--font-sans)", flex: "none" }}
        >
          {copied ? "copied" : "copy"}
        </button>
      )}
    </div>
  );
}
