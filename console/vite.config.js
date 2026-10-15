// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The console talks to the gateway's admin API at /api/v1, on its own origin.
// In dev, Vite proxies /api to MCPDEF_ADMIN: the mock backend
// (server/mcpdef-mock.mjs, :7879) by default, or a gateway's admin listener.
//
// The build goes into the mcpdef-console crate, which the gateway embeds, and
// scripts/embed.mjs then writes each file's compressed forms and the table the
// crate serves them from: `cargo build` needs no Node.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // The API, and signing in and out, which a gateway that signs people in
    // serves beside it.
    proxy: Object.fromEntries(
      ["/api", "/login", "/callback", "/logout"].map((path) => [
        path,
        { target: process.env.MCPDEF_ADMIN || "http://127.0.0.1:7879", changeOrigin: true },
      ])
    ),
  },
  build: {
    outDir: "../crates/mcpdef-console/assets",
    emptyOutDir: true,
    // Never a data: URI: the content security policy takes fonts from the
    // gateway alone.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    reportCompressedSize: false,
  },
});
