# mcpdef-console

The [MCPdef](https://github.com/lucheeseng827/mcpdef) console's built files,
embedded for the gateway's admin listener to serve: HTML, scripts, styles and
fonts, each text file with its brotli and gzip forms.

The console's source is the repository's `console/` directory, a Vite + React
app. `npm run build` there writes this crate's `assets/` and `src/assets.rs`, so
building the crate, and the gateway, needs no Node.

Licensed under Apache-2.0. What the build bundles carries its own licenses, in
`licenses/`: IBM Plex Sans and Mono under the SIL Open Font License 1.1, and
React under MIT.
