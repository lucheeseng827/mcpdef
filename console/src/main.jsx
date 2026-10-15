// SPDX-License-Identifier: Apache-2.0
import React from "react";
import { createRoot } from "react-dom/client";
// The design system, its fonts among it (ds/tokens/fonts.css).
import "./ds/styles.css";
import App from "./App.jsx";
import { applyTheme, storedTheme } from "./theme.js";

// The theme the viewer chose, before anything is drawn.
applyTheme(storedTheme());

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
