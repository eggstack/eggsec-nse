//! NSE Executor - Synchronous Lua VM wrapper with rule execution
//!
//! Wraps ExecutorCore and adds NSE rule evaluation (prerule, hostrule,
//! portrule, postrule) and category management.

use mlua::{Lua, Result as LuaResult, Table, Value};
use rustc_hash::FxHashMap;
use std::path::PathBuf;

use crate::executor_core::ExecutorCore;
use crate::limits::{NseCancellationToken, NseExecutionLimits, NseExecutionStats};
use crate::profile::{NseExecutionProfileKind, NseModulePolicy, NseNetworkPolicy, NseScriptPolicy};
use crate::report::NseRuleEvaluationReport;
use crate::SandboxMetrics;

pub struct NseExecutor {
    core: ExecutorCore,
}

impl NseExecutor {
    /// Create an executor with default (manual-permissive) limits.
    ///
    /// # Manual-only
    ///
    /// This constructor uses permissive defaults suitable for interactive
    /// CLI/TUI use. Automated surfaces (agent, MCP, REST, daemon, CI) must
    /// use [`NseExecutor::with_policy`] or [`NseExecutor::with_profile`]
    /// with an appropriate non-manual profile.
    pub fn new() -> LuaResult<Self> {
        Ok(Self {
            core: ExecutorCore::new()?,
        })
    }

    /// Create an executor with a sandbox config and default (manual-permissive) limits.
    ///
    /// # Manual-only
    ///
    /// This constructor uses permissive defaults suitable for interactive
    /// CLI/TUI use. Automated surfaces must use [`NseExecutor::with_policy`]
    /// or [`NseExecutor::with_profile`].
    pub fn with_sandbox(sandbox: crate::SandboxConfig) -> LuaResult<Self> {
        Ok(Self {
            core: ExecutorCore::with_sandbox(sandbox)?,
        })
    }

    /// Create an executor with a target and default (manual-permissive) limits.
    ///
    /// # Manual-only
    ///
    /// This constructor uses permissive defaults suitable for interactive
    /// CLI/TUI use. Automated surfaces must use [`NseExecutor::with_policy`]
    /// or [`NseExecutor::with_profile`].
    pub fn with_target(target: &str) -> LuaResult<Self> {
        let mut exec = Self::new()?;
        if let Err(e) = exec.set_target(target) {
            tracing::warn!("Failed to set NSE target '{}': {}", target, e);
        }
        Ok(exec)
    }

    /// Create an executor with explicit execution limits and cancellation token.
    ///
    /// # Manual-only capability context
    ///
    /// This constructor hardcodes `ManualPermissive` profile kind and
    /// `AllowAllManual` network policy in the capability context. It is
    /// intended for manual CLI/TUI surfaces where the operator is trusted to
    /// scope behavior interactively.
    ///
    /// Automated surfaces (MCP, agent, REST, daemon, CI) MUST use
    /// [`NseExecutor::with_full_policy`] or [`NseExecutor::with_profile`]
    /// so the capability engine enforces the resolved profile's
    /// `profile_kind` and `network_policy`.
    pub fn with_policy(
        sandbox: crate::SandboxConfig,
        limits: NseExecutionLimits,
        cancellation: NseCancellationToken,
        script_policy: NseScriptPolicy,
        module_policy: NseModulePolicy,
    ) -> LuaResult<Self> {
        Ok(Self {
            core: ExecutorCore::with_policy(
                sandbox,
                limits,
                cancellation,
                script_policy,
                module_policy,
            )?,
        })
    }

    /// Create an executor with explicit profile kind and network policy.
    ///
    /// This is the canonical constructor for automated surfaces. It accepts
    /// the full capability policy set (`profile_kind`, `network_policy`,
    /// sandbox, limits, script/module policies) and threads them through to
    /// the `NseCapabilityContext` so capability decisions match the resolved
    /// profile.
    ///
    /// Automated surfaces should prefer [`NseExecutor::with_profile`] (which
    /// derives these fields from a `ResolvedNseExecutionProfile`) and use
    /// this constructor only when the policy fields are constructed
    /// independently of a full profile.
    pub fn with_full_policy(
        sandbox: crate::SandboxConfig,
        limits: NseExecutionLimits,
        cancellation: NseCancellationToken,
        script_policy: NseScriptPolicy,
        module_policy: NseModulePolicy,
        profile_kind: NseExecutionProfileKind,
        network_policy: NseNetworkPolicy,
    ) -> LuaResult<Self> {
        Ok(Self {
            core: ExecutorCore::with_full_policy(
                sandbox,
                limits,
                cancellation,
                script_policy,
                module_policy,
                profile_kind,
                network_policy,
            )?,
        })
    }

    /// Create an executor from a resolved execution profile.
    ///
    /// This is the preferred constructor when a profile is available.
    /// It threads the profile's `kind` and `network_policy` into the capability
    /// context so capability decisions match the resolved profile.
    pub fn with_profile(profile: &crate::profile::ResolvedNseExecutionProfile) -> LuaResult<Self> {
        Ok(Self {
            core: ExecutorCore::with_profile(profile)?,
        })
    }

    // Delegate core accessors
    pub fn lua(&self) -> &Lua {
        self.core.lua()
    }
    pub fn target(&self) -> &str {
        self.core.target()
    }
    pub fn set_target(&mut self, target: &str) -> Result<(), String> {
        self.core.set_target(target)
    }
    pub fn add_scripts_path(&self, path: PathBuf) {
        self.core.add_scripts_path(path);
    }
    pub fn add_default_scripts_path(&self) {
        self.core.add_default_scripts_path();
    }
    pub fn set_script_args(&mut self, args: &str) -> Result<(), String> {
        self.core.set_script_args(args)
    }
    pub fn add_output(&self, output: String) -> Result<(), String> {
        self.core.add_output(output)
    }
    pub fn get_output(&self) -> Result<Vec<String>, String> {
        Ok(self.core.get_output())
    }
    pub fn get_script_output(&self) -> Result<String, String> {
        self.core.get_script_output()
    }
    pub fn run_script(&self, script: &str) -> LuaResult<String> {
        self.core.run_script(script)
    }

    /// Run a script with the configured execution limits.
    ///
    /// This is the primary execution method. Limits are enforced during
    /// execution via a Lua debug hook (instruction budget, wall-clock)
    /// and pre-execution checks (script size, cancellation).
    pub fn run_script_with_limits(&self, script: &str) -> LuaResult<String> {
        self.core.run_script(script)
    }

    /// Run a script with a wall-clock timeout.
    ///
    /// This method is **deprecated** in favor of `run_script_with_limits()`.
    /// The timeout is now enforced via the execution limits model, which
    /// actually interrupts the Lua VM when the timeout expires (unlike the
    /// old behavior where a spawned thread continued running).
    ///
    /// For new code, use `NseExecutor::with_policy()` with
    /// `NseExecutionLimits { wall_clock_timeout: Some(timeout), .. }` and
    /// call `run_script_with_limits()`.
    #[deprecated(
        since = "0.2.0",
        note = "Use with_policy() + run_script_with_limits() for real cancellation"
    )]
    pub fn run_script_with_timeout(
        &self,
        script: &str,
        timeout: std::time::Duration,
    ) -> LuaResult<String> {
        let limits = NseExecutionLimits {
            wall_clock_timeout: Some(timeout),
            ..NseExecutionLimits::default()
        };
        let cancellation = self.core.cancellation_token().clone();
        let mut exec = NseExecutor::with_policy(
            self.core.sandbox.clone(),
            limits,
            cancellation,
            self.core.script_policy.clone(),
            self.core.module_policy.clone(),
        )?;
        if let Err(e) = exec.set_target(self.target()) {
            tracing::warn!("Failed to set NSE target '{}': {}", self.target(), e);
        }
        for path in self.core.scripts_path.lock().iter() {
            exec.add_scripts_path(path.clone());
        }
        exec.run_script_with_limits(script)
    }

    /// Get the execution stats from the last `run_script` or `run_script_with_limits` call.
    pub fn execution_stats(&self) -> NseExecutionStats {
        self.core.execution_stats()
    }

    /// Get a reference to the cancellation token.
    pub fn cancellation_token(&self) -> &NseCancellationToken {
        self.core.cancellation_token()
    }

    /// Get a reference to the execution limits.
    pub fn limits(&self) -> &NseExecutionLimits {
        self.core.limits()
    }
    pub fn load_script(&self, name: &str) -> LuaResult<String> {
        self.core.load_script(name)
    }
    pub fn set_host_info(
        &mut self,
        hostname: Option<String>,
        ip: String,
        mac: Option<String>,
        status: Option<String>,
    ) -> Result<(), String> {
        self.core.set_host_info(hostname, ip, mac, status)
    }
    pub fn add_port(
        &mut self,
        port: u16,
        protocol: &str,
        state: &str,
        service: Option<String>,
    ) -> Result<(), String> {
        self.core.add_port(port, protocol, state, service)
    }
    pub fn get_sandbox_metrics(&self) -> SandboxMetrics {
        self.core.get_sandbox_metrics()
    }
    pub fn required_modules(&self) -> Vec<crate::report::NseRequiredModuleReport> {
        self.core.required_modules()
    }
    pub fn library_reports(&self) -> Vec<crate::report::NseLibraryUseReport> {
        self.core.library_reports()
    }

    pub fn capability_events(&self) -> Vec<crate::capabilities::NseCapabilityEvent> {
        self.core.capability_context().events()
    }

    /// Get a reference to the executor's capability context.
    ///
    /// The capability context carries the resolved execution profile's
    /// `profile_kind` and `network_policy`, which determine how the
    /// capability engine responds to filesystem, network, process, DNS,
    /// time, randomness, environment, crypto, and compression requests.
    pub fn capability_context(&self) -> &crate::capabilities::NseCapabilityContext {
        self.core.capability_context()
    }

    // Executor-specific: rule execution

    pub fn run_script_with_rules(
        &mut self,
        script: &str,
    ) -> LuaResult<(String, Vec<String>, Vec<NseRuleEvaluationReport>)> {
        self.core.clear_library_reports();
        self.lua().load(script).eval::<Value>()?;
        let globals = self.lua().globals();
        let mut outputs = Vec::new();
        let mut rule_reports = Vec::new();

        // Build centralized host context from executor target
        let target = self.target().to_string();
        let host_ctx = crate::context::NseHostContext::synthetic(&target);
        let host_table = host_ctx.to_table(self.lua())?;

        // prerule
        if let Ok(prerule) = globals.get::<mlua::Function>("prerule") {
            let report = crate::report::evaluate_rule("prerule", prerule.call::<Value>(()));
            if report.evaluated || report.error.is_some() {
                rule_reports.push(report);
            }
        }

        // hostrule — receives structured host table
        let hostrule_matched = if let Ok(hostrule) = globals.get::<mlua::Function>("hostrule") {
            let result = hostrule.call::<Value>(host_table.clone());
            let report =
                crate::report::evaluate_rule_with_context("hostrule", result, &host_ctx, None);
            let matched = report.matched;
            if report.evaluated || report.error.is_some() {
                rule_reports.push(report);
            }
            if matched {
                if let Ok(action) = globals.get::<mlua::Function>("action") {
                    match action.call::<Value>((host_table.clone(), self.lua().create_table()?)) {
                        Ok(v) if !v.is_nil() => outputs.push(format!("action: {:?}", v)),
                        Err(e) => outputs.push(format!("action error: {}", e)),
                        _ => {}
                    }
                }
                true
            } else {
                false
            }
        } else {
            false
        };

        // portrule — receives (host_table, port_table) matching Nmap signature
        let ports = globals.get::<Table>("nmap")?.get::<Table>("_ports")?;
        let mut portrule_matched = false;

        for (_, port_info) in ports.pairs::<String, Table>().flatten() {
            if let Ok(portrule) = globals.get::<mlua::Function>("portrule") {
                // Build port context from the Lua port table
                let port_num: u16 = port_info.get("number").unwrap_or(0);
                let port_proto: String = port_info.get("protocol").unwrap_or_default();
                let port_state: String = port_info.get("state").unwrap_or_default();
                let port_svc: Option<String> = port_info.get("service").ok();
                let port_ver: Option<String> = port_info.get("version").ok();

                let svc_ctx = if port_svc.is_some() || port_ver.is_some() {
                    Some(crate::context::NseServiceContext {
                        name: port_svc,
                        product: None,
                        version: port_ver,
                        tunnel: None,
                        confidence: None,
                    })
                } else {
                    None
                };

                let port_ctx = crate::context::NsePortContext {
                    port: port_num,
                    protocol: port_proto,
                    state: port_state,
                    service: svc_ctx,
                    source: crate::context::NseContextSource::Synthetic,
                };

                let port_table = port_ctx.to_table(self.lua())?;

                let result = portrule.call::<Value>((host_table.clone(), port_table.clone()));
                let report = crate::report::evaluate_rule_with_context(
                    "portrule",
                    result,
                    &host_ctx,
                    Some(&port_ctx),
                );
                let matched = report.matched;
                if report.evaluated || report.error.is_some() {
                    rule_reports.push(report);
                }
                if matched {
                    if let Ok(action) = globals.get::<mlua::Function>("action") {
                        match action.call::<Value>((host_table.clone(), port_table)) {
                            Ok(v) if !v.is_nil() => outputs.push(format!("action: {:?}", v)),
                            Err(e) => outputs.push(format!("action error: {}", e)),
                            _ => {}
                        }
                    }
                    portrule_matched = true;
                    break;
                }
            }
        }

        // postrule
        if let Ok(postrule) = globals.get::<mlua::Function>("postrule") {
            let report = crate::report::evaluate_rule("postrule", postrule.call::<Value>(()));
            if report.evaluated || report.error.is_some() {
                rule_reports.push(report);
            }
        }

        if let Ok(script_output) = self.get_script_output() {
            if !script_output.is_empty() {
                outputs.push(script_output);
            }
        }

        if outputs.is_empty() && !hostrule_matched && !portrule_matched {
            outputs.push("No rules matched or no output generated".to_string());
        }

        Ok((outputs.join("\n"), outputs, rule_reports))
    }

    pub fn evaluate_rule_value(
        &mut self,
        kind: &str,
        rule_source: Option<&str>,
        arg: Value,
    ) -> NseRuleEvaluationReport {
        let globals = self.lua().globals();

        if let Some(rule) = rule_source {
            if !rule.is_empty() {
                if let Ok(f) = self.lua().load(rule).eval::<mlua::Function>() {
                    return crate::report::evaluate_rule(kind, f.call::<Value>(arg.clone()));
                }
            }
        }

        if let Ok(f) = globals.get::<mlua::Function>(kind) {
            return crate::report::evaluate_rule(kind, f.call::<Value>(arg));
        }

        NseRuleEvaluationReport {
            kind: kind.to_string(),
            evaluated: false,
            matched: false,
            exactness: "not_present".to_string(),
            error: None,
            summary: format!("{} function not defined", kind),
            unsupported: None,
            host_context_source: None,
            port_context_source: None,
            service_context_available: None,
            fidelity_reason: None,
        }
    }

    pub fn check_portrule(
        &mut self,
        portrule: Option<&str>,
        port: u16,
        protocol: &str,
        state: &str,
        service: Option<&str>,
    ) -> LuaResult<bool> {
        let svc_ctx = service.map(|s| crate::context::NseServiceContext {
            name: Some(s.to_string()),
            product: None,
            version: None,
            tunnel: None,
            confidence: None,
        });

        let port_ctx = crate::context::NsePortContext {
            port,
            protocol: protocol.to_string(),
            state: state.to_string(),
            service: svc_ctx,
            source: crate::context::NseContextSource::Synthetic,
        };
        let port_table = port_ctx.to_table(self.lua())?;

        let report = self.evaluate_rule_value("portrule", portrule, Value::Table(port_table));
        Ok(report.matched)
    }

    pub fn check_hostrule(&mut self, hostrule: Option<&str>) -> LuaResult<bool> {
        let target = self.target().to_string();
        let host_ctx = crate::context::NseHostContext::synthetic(&target);
        let host_table = host_ctx.to_table(self.lua())?;
        let report = self.evaluate_rule_value("hostrule", hostrule, Value::Table(host_table));
        Ok(report.matched)
    }

    pub fn get_prerule_result(&self) -> Option<String> {
        let f = self.lua().globals().get::<mlua::Function>("prerule").ok()?;
        let r = f.call::<Value>(()).ok()?;
        Some(format!("{:?}", r))
    }

    pub fn get_postrule_result(&self) -> Option<String> {
        let f = self
            .lua()
            .globals()
            .get::<mlua::Function>("postrule")
            .ok()?;
        let r = f.call::<Value>(()).ok()?;
        Some(format!("{:?}", r))
    }

    pub fn run_script_with_output(&self, script: &str) -> LuaResult<(String, Vec<String>)> {
        self.lua().load(script).eval::<Value>()?;
        let output = self.core.get_output();
        Ok(("Script executed successfully".to_string(), output))
    }

    pub fn run_script_file(&self, path: &std::path::Path) -> LuaResult<String> {
        // Route script-file loading through ScriptResolver. The resolver
        // enforces policy (including empty-roots ManualPermissive semantics),
        // existence, extension, and (when configured) canonical root
        // containment with symlink-escape rejection. Use the resolver's
        // loaded content so checks and reads stay in one place.
        let mut resolver = crate::resolver::ScriptResolver::new(
            self.core.script_policy.clone(),
            self.core.module_policy.clone(),
            self.core.limits.clone(),
        );
        let source = crate::resolver::NseScriptSource::File {
            path: path.to_path_buf(),
        };
        let resolved = resolver
            .resolve_script(source)
            .map_err(|e| mlua::Error::RuntimeError(format!("Script file rejected: {}", e)))?;
        self.run_script(&resolved.content)
    }

    pub fn run_script_file_with_output(
        &self,
        path: &std::path::Path,
    ) -> LuaResult<(String, Vec<String>)> {
        // See `run_script_file`: route through ScriptResolver and use the
        // resolver's loaded content so policy and read paths stay aligned.
        let mut resolver = crate::resolver::ScriptResolver::new(
            self.core.script_policy.clone(),
            self.core.module_policy.clone(),
            self.core.limits.clone(),
        );
        let source = crate::resolver::NseScriptSource::File {
            path: path.to_path_buf(),
        };
        let resolved = resolver
            .resolve_script(source)
            .map_err(|e| mlua::Error::RuntimeError(format!("Script file rejected: {}", e)))?;
        self.run_script_with_output(&resolved.content)
    }

    pub fn check_script_category(&self, script_name: &str, category: &str) -> bool {
        let categories = self.parse_all_script_categories();
        if let Some(cats) = categories.get(script_name) {
            return cats.contains(&category.to_string());
        }
        matches!(category, "default" | "safe")
    }

    pub fn get_script_categories(&self, script_name: &str) -> Vec<String> {
        let categories = self.parse_all_script_categories();
        categories
            .get(script_name)
            .cloned()
            .unwrap_or_else(|| vec!["default".to_string()])
    }

    pub fn get_category_scripts(&self, category: &str) -> Vec<String> {
        self.parse_all_script_categories()
            .into_iter()
            .filter(|(_, cats)| cats.contains(&category.to_string()))
            .map(|(name, _)| name)
            .collect()
    }

    fn parse_all_script_categories(&self) -> FxHashMap<String, Vec<String>> {
        let mut categories = FxHashMap::default();
        let paths = self.core.scripts_path.lock();

        for dir in paths.iter() {
            if !dir.exists() {
                continue;
            }
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map(|e| e == "nse").unwrap_or(false) {
                        if let Some(script_name) = path.file_stem().and_then(|s| s.to_str()) {
                            let cats = parse_nse_categories(&path);
                            if !cats.is_empty() {
                                categories.insert(script_name.to_string(), cats);
                            }
                        }
                    }
                }
            }
        }

        categories
    }

    /// Build a structured run report from post-execution state.
    ///
    /// Call this after `run_script_with_limits()` or `run_script_with_rules()`
    /// to assemble a machine-readable report. The caller provides the profile,
    /// script source, output, and resolver diagnostics that were used during
    /// execution.
    pub fn build_report(
        &self,
        profile: &crate::profile::ResolvedNseExecutionProfile,
        script_source: &crate::resolver::NseScriptSource,
        output: &str,
        diagnostics: &[crate::resolver::NseLoadDiagnostic],
    ) -> crate::report::NseRunReport {
        let stats = self.execution_stats();
        let script_name = match script_source {
            crate::resolver::NseScriptSource::Builtin { name } => name.clone(),
            crate::resolver::NseScriptSource::TrustedRegistry { name } => name.clone(),
            crate::resolver::NseScriptSource::File { path } => path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string(),
            crate::resolver::NseScriptSource::InlineManual { label, .. } => label.clone(),
        };
        crate::report::NseRunReport::new(self.target(), &script_name)
            .with_profile(profile)
            .with_script_source(script_source)
            .with_stats(&stats)
            .with_resolver_diagnostics(diagnostics)
            .with_libraries(self.library_reports())
            .with_capability_events(self.core.capability_context().events())
            .with_output(output)
            .compute_compatibility()
    }
}

fn parse_nse_categories(path: &std::path::Path) -> Vec<String> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("categories") && trimmed.contains('{') {
            // Extract values between { and }
            if let Some(start) = trimmed.find('{') {
                if let Some(end) = trimmed.find('}') {
                    let inner = &trimmed[start + 1..end];
                    return inner
                        .split(',')
                        .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
            }
        }
    }

    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_creation() {
        let executor = NseExecutor::new();
        assert!(executor.is_ok());
    }
}
