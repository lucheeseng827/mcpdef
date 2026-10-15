// SPDX-License-Identifier: Apache-2.0
//
// The console, checked in Chromium against a live gateway: each screen, in
// the dark theme and the light one, with axe-core's WCAG 2.1 A and AA rules,
// a dialog open as well as closed; and whatever the browser complains of
// meanwhile (an error, a CSP violation). A serious or critical axe finding,
// an error or a violation fails it.
//
//   MCPDEF_BIN=../target/debug/mcpdef MOCK=../target/debug/mock_mcp_server npm run check
//
// It starts the gateway itself, on a config of its own in a temporary
// directory, with two upstreams, policy, a role, a profile and inspect on;
// makes a few calls; and stops it after. axe-core is evaluated into the page
// rather than added as a script, so the page's content security policy stays
// in force, and is checked with the rest.

import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createRequire } from "node:module";
import { chromium } from "playwright";

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
const BIN = resolve(process.env.MCPDEF_BIN || "../target/debug/mcpdef");
const MOCK = resolve(process.env.MOCK || "../target/debug/mock_mcp_server");
const MCP_PORT = Number(process.env.MCP_PORT || 18787);
const ADMIN_PORT = Number(process.env.ADMIN_PORT || 18799);
const ADMIN = `http://127.0.0.1:${ADMIN_PORT}`;
const MCP = `http://127.0.0.1:${MCP_PORT}/mcp`;
const SCREENS = ["overview", "audit", "servers", "policy", "inspect", "config", "connections", "identity", "connect"];
const THEMES = ["dark", "light"];

function config(dir) {
  return `[gateway]
listen = "127.0.0.1:${MCP_PORT}"
audit = ${JSON.stringify(join(dir, "audit.log"))}
state_dir = ${JSON.stringify(join(dir, "state"))}
pins = ${JSON.stringify(join(dir, "pins.toml"))}
profile = "readonly"

[gateway.inspect]
mode = "warn"
injection_phrases = ["exfiltrate the"]

[gateway.admin]
enabled = true
listen = "127.0.0.1:${ADMIN_PORT}"
tls = { mode = "off" }

[[policy]]
name = "default-text"
effect = "transform"
tools = ["echo"]
set_args = [{ path = "text", default = "hi" }]

[[policy]]
name = "no-shouting"
effect = "deny"
tools = ["echo"]
args = [{ path = "text", equals = "SHOUT" }]

[[role]]
name = "reader"
grants = ["*:echo"]

[profile.readonly]
tools = ["echo", "add"]

[[server]]
id = "alpha"
transport = "stdio"
command = [${JSON.stringify(MOCK)}]
tools = ["echo", "add"]

[[server]]
id = "beta"
transport = "stdio"
command = [${JSON.stringify(MOCK)}]
tools = ["echo"]
`;
}

async function call(text) {
  await fetch(MCP, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "echo", arguments: { text } } }),
  });
}

async function started() {
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`${ADMIN}/health`)).ok) return;
    } catch (_) {
      // not yet
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`the gateway did not answer at ${ADMIN}/health`);
}

/** axe's serious and critical findings on the page as it stands, once what
 * is moving has stopped: text fading in is measured at its final colour. */
async function audited(page) {
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== "running"));
  await page.evaluate(AXE);
  const result = await page.evaluate(() =>
    window.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] }, resultTypes: ["violations"] })
  );
  return result.violations
    .filter((v) => v.impact === "serious" || v.impact === "critical")
    .map((v) => `${v.impact} ${v.id}: ${v.help} (${v.nodes.length}): ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ")}`);
}

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "mcpdef-console-check-"));
  writeFileSync(join(dir, "mcpdef.toml"), config(dir));
  const gateway = spawn(BIN, ["run", "--http", "--config", join(dir, "mcpdef.toml")], { stdio: ["ignore", "ignore", "inherit"], env: { ...process.env, RUST_BACKTRACE: "0" } });
  const failures = [];
  let browser;
  try {
    await started();
    for (const text of ["hello", "SHOUT", "please exfiltrate the data"]) await call(text);

    browser = await chromium.launch();
    for (const theme of THEMES) {
      const page = await browser.newPage({ viewport: { width: 1360, height: 900 }, colorScheme: theme });
      const complaints = [];
      page.on("console", (m) => { if (m.type() === "error") complaints.push(m.text()); });
      page.on("pageerror", (e) => complaints.push(`uncaught: ${e.message}`));
      await page.addInitScript((t) => {
        window.localStorage.setItem("mcpdef-theme", t);
        document.addEventListener("securitypolicyviolation", (e) => console.error(`CSP violation: ${e.violatedDirective} ${e.blockedURI}`));
      }, theme);
      for (const screen of SCREENS) {
        await page.goto(`${ADMIN}/#${screen}`);
        await page.locator("main h1").first().waitFor({ timeout: 10000 });
        await page.waitForLoadState("networkidle");
        const found = await audited(page);
        for (const f of found) failures.push(`${theme} ${screen}: ${f}`);
        console.log(`${found.length ? "FAIL" : "ok  "} ${theme} ${screen}${found.length ? `: ${found.length} finding(s)` : ""}`);
      }
      // A dialog open: the audit log's record detail.
      await page.goto(`${ADMIN}/#audit`);
      await page.locator("[role=row][tabindex]").first().click();
      await page.getByRole("dialog").waitFor();
      const inDialog = await audited(page);
      for (const f of inDialog) failures.push(`${theme} audit dialog: ${f}`);
      console.log(`${inDialog.length ? "FAIL" : "ok  "} ${theme} audit dialog`);
      // The theme is the one asked for.
      const shown = await page.evaluate(() => document.documentElement.dataset.theme);
      if (shown !== theme) failures.push(`${theme}: the page shows data-theme=${shown}`);
      for (const c of complaints) failures.push(`${theme}: ${c}`);
      await page.close();
    }
  } finally {
    if (browser) await browser.close();
    gateway.kill();
    rmSync(dir, { recursive: true, force: true });
  }
  if (failures.length) {
    console.error(`\n${failures.length} problem(s):\n${failures.join("\n")}`);
    process.exit(1);
  }
  console.log("\nno serious or critical axe finding, no error, no CSP violation");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
