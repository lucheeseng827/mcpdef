// SPDX-License-Identifier: Apache-2.0
// The console's theme: the system's preference, or light or dark as the
// viewer chooses, kept in this browser. Applied as <html data-theme>, which
// ds/tokens/colors.css reads; "system" sets none.

const KEY = "mcpdef-theme";
export const THEMES = ["system", "light", "dark"];

/** The theme this browser keeps, or "system". */
export function storedTheme() {
  try {
    const kept = window.localStorage.getItem(KEY);
    return THEMES.includes(kept) ? kept : "system";
  } catch (_) {
    return "system";
  }
}

/** Show `theme` now. */
export function applyTheme(theme) {
  const root = document.documentElement;
  if (theme === "light" || theme === "dark") root.dataset.theme = theme;
  else delete root.dataset.theme;
}

/** Show `theme`, and keep it for the next visit. */
export function chooseTheme(theme) {
  applyTheme(theme);
  try {
    window.localStorage.setItem(KEY, theme);
  } catch (_) {
    // A browser that keeps nothing still shows it now.
  }
}
