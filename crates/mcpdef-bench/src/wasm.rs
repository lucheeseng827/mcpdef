//! `wasm-instantiate`: how long a fresh instance of a compiled WASM component
//! takes to make. In-process, through `mcpdef-sandbox` itself: the gateway makes
//! one instance per server when it starts it, so no call through it would time
//! this.

use crate::load::Samples;
use crate::report::WasmInstantiate;
use crate::stats::summarize;
use anyhow::{Context, Result};
use mcpdef_sandbox::{ComponentTemplate, EgressAllow, SandboxLimits};
use std::path::Path;
use std::time::Instant;

/// Compile `component` once, then make and drop `warmup` instances, then time
/// `requests` more. Each is made as the gateway makes one: the default limits,
/// no egress, a store, a memory and a WASI context of its own. Dropping one is
/// not timed.
pub async fn wasm_instantiate(
    component: &Path,
    warmup: usize,
    requests: usize,
) -> Result<WasmInstantiate> {
    let wasm = std::fs::read(component).with_context(|| {
        format!(
            "reading {} (the echo fixture is built from crates/mcpdef-sandbox/tests/fixtures/echo-component)",
            component.display()
        )
    })?;
    let started = Instant::now();
    let template = ComponentTemplate::compile(&wasm, SandboxLimits::default())
        .context("compiling the component")?;
    let compile_us = started.elapsed().as_micros() as u64;
    let started = Instant::now();
    drop(
        template
            .instantiate(EgressAllow::deny_all())
            .await
            .context("instantiating the component")?,
    );
    let first_us = started.elapsed().as_micros() as u64;

    for _ in 0..warmup {
        drop(template.instantiate(EgressAllow::deny_all()).await?);
    }
    let mut samples = Samples::default();
    let wall = Instant::now();
    for _ in 0..requests {
        let started = Instant::now();
        let instance = template.instantiate(EgressAllow::deny_all()).await?;
        samples.micros.push(started.elapsed().as_micros() as u64);
        drop(instance);
    }
    samples.wall = wall.elapsed();

    Ok(WasmInstantiate {
        component: component.file_name().map_or_else(
            || component.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        ),
        component_bytes: wasm.len() as u64,
        compile_us,
        first_us,
        instantiate: summarize(&samples),
    })
}
