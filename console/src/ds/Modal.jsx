// SPDX-License-Identifier: Apache-2.0
import React from "react";

/**
 * MCPdef Modal — centered dialog over a 55%-black scrim (no blur). Click-scrim to
 * close, optional title + footer. The only floating surface in the system
 * (carries the one shadow). Rises 8px on open; reduced-motion collapses it.
 */
export function Modal({ open = false, onClose, title, children, footer, width = 460, style = {} }) {
  const titleId = React.useId();
  const box = React.useRef(null);
  // Escape closes the dialog (keyboard users have no mouse to hit the scrim).
  React.useEffect(() => {
    if (!open) return undefined;
    function onKeyDown(e) {
      if (e.key === "Escape") onClose?.();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);
  // Focus moves into the dialog as it opens, and back to what had it as it
  // closes.
  React.useEffect(() => {
    if (!open) return undefined;
    const before = document.activeElement;
    box.current?.focus();
    return () => { if (before && before.focus) before.focus(); };
  }, [open]);
  if (!open) return null;
  return (
    <div
      onClick={onClose}
      style={{ position: "fixed", inset: 0, background: "var(--eg-scrim)", display: "grid", placeItems: "center", zIndex: 50, padding: 20, animation: "egFade var(--dur-slow,240ms) ease" }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        ref={box}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? titleId : undefined}
        style={{
          background: "var(--eg-panel)",
          border: "1px solid var(--eg-border)",
          borderRadius: 12,
          boxShadow: "var(--shadow-overlay)",
          width: "100%",
          maxWidth: width,
          padding: 22,
          fontFamily: "var(--font-sans)",
          animation: "egRise var(--dur-slow,240ms) var(--ease-standard,ease)",
          ...style,
        }}
      >
        {title && <h2 id={titleId} style={{ fontSize: 18, fontWeight: 700, letterSpacing: "-0.3px", margin: "0 0 6px", color: "var(--eg-fg)" }}>{title}</h2>}
        <div>{children}</div>
        {footer && <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 18 }}>{footer}</div>}
      </div>
    </div>
  );
}
