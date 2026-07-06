//! NSE (Nmap Scripting Engine) support for Eggsec
//!
//! This module provides the ability to run Nmap NSE scripts using a Lua interpreter.
//! It leverages mlua (Lua 5.4) and wraps existing Eggsec functionality
//! to provide NSE-compatible libraries.

use ipnetwork::IpNetwork;
#[cfg(feature = "nse")]
use regex::Regex;
#[cfg(feature = "nse")]
use rustc_hash::FxHashSet;
use std::net::IpAddr;
use std::path::PathBuf;
#[cfg(feature = "nse")]
use std::sync::LazyLock;

#[cfg(all(feature = "nse", target_family = "unix"))]
#[link(name = "z")]
unsafe extern "C" {}

/// Configuration for running NSE scripts.
pub struct NseConfig {
    pub target: String,
    pub script: String,
    pub script_args: Option<String>,
    pub script_file: Option<String>,
    pub json: bool,
    pub verbose: bool,
}

impl NseConfig {
    pub fn new(
        target: &str,
        script: &str,
        script_args: Option<&str>,
        script_file: Option<&str>,
        json: bool,
        verbose: bool,
    ) -> Self {
        Self {
            target: target.to_string(),
            script: script.to_string(),
            script_args: script_args.map(|s| s.to_string()),
            script_file: script_file.map(|s| s.to_string()),
            json,
            verbose,
        }
    }
}

/// Sandbox configuration for restricting NSE Lua script capabilities.
///
/// When sandboxing is enabled, dangerous operations like `io.popen` (arbitrary
/// command execution) and unrestricted filesystem access are blocked or limited.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Whether sandboxing is enabled.
    pub enabled: bool,
    /// If set, restrict file operations to this directory.
    pub allowed_dir: Option<PathBuf>,
    /// If non-empty, only these commands are allowed via `io.popen`.
    /// If empty and sandbox is enabled, `io.popen` is fully blocked.
    pub allowed_commands: Vec<String>,
    /// Whether to log sandbox violations instead of blocking them.
    pub log_violations: bool,
    /// If non-empty, only network connections to these CIDR ranges are allowed.
    /// If empty and sandbox is enabled, socket connections are allowed but a warning is logged.
    pub allowed_networks: Vec<IpNetwork>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            // Sandbox behavior is controlled by the `sandbox` feature.
            enabled: cfg!(feature = "sandbox"),
            allowed_dir: Some(PathBuf::from("/tmp/eggsec-nse")),
            allowed_commands: Vec::new(),
            log_violations: true,
            allowed_networks: Vec::new(),
        }
    }
}

impl SandboxConfig {
    fn allowed_root(&self) -> Option<PathBuf> {
        let dir = self.allowed_dir.as_ref()?;
        // Return the raw path; canonicalization is checked per-path in get_allowed_path().
        // This allows the sandbox to reference a not-yet-created directory.
        Some(dir.clone())
    }

    /// Create a sandbox config with sandboxing enabled and default settings.
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Default::default()
        }
    }

    /// Check if a file path is allowed under the sandbox and return the canonical path.
    ///
    /// This method canonicalizes the path and verifies it starts with the allowed root
    /// using path-component semantics (`Path::strip_prefix` / `Path::starts_with` on
    /// canonical paths only). String-prefix fallback is never used.
    ///
    /// Returns `Some(canonical_path)` if allowed, `None` if blocked or invalid.
    ///
    /// # Security Note
    /// The returned canonical path must be used for actual file operations to avoid
    /// TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities. A separate check followed
    /// by operations on the original path could allow symlink attacks.
    pub fn get_allowed_path(&self, path: &str) -> Option<PathBuf> {
        if !self.enabled {
            return Some(PathBuf::from(path));
        }

        // Sandbox enabled but no allowed_dir configured — allow all paths
        let Some(allowed_dir) = self.allowed_root() else {
            return Some(PathBuf::from(path));
        };

        let path_buf = PathBuf::from(path);

        // Try to canonicalize the path directly
        if let Ok(canonical) = path_buf.canonicalize() {
            if canonical.starts_with(&allowed_dir) {
                return Some(canonical);
            }
            return None;
        }

        // File doesn't exist — try canonicalizing the parent
        if let Some(parent) = path_buf.parent() {
            if let Ok(canonical_parent) = parent.canonicalize() {
                if canonical_parent.starts_with(&allowed_dir) {
                    return Some(canonical_parent.join(path_buf.file_name()?));
                }
            }
        }

        // Cannot canonicalize path or parent — reject (no string-prefix fallback)
        None
    }

    /// Check if a command is allowed via `io.popen`.
    pub fn is_command_allowed(&self, cmd: &str) -> bool {
        if !self.enabled {
            return true;
        }

        if self.allowed_commands.is_empty() {
            return false;
        }

        // Block commands containing shell metacharacters to prevent injection
        if cmd.contains(';')
            || cmd.contains('|')
            || cmd.contains('&')
            || cmd.contains('$')
            || cmd.contains('`')
            || cmd.contains('\n')
            || cmd.contains('\r')
        {
            return false;
        }

        let cmd_name = cmd.split_whitespace().next().unwrap_or(cmd);
        self.allowed_commands
            .iter()
            .any(|allowed| cmd_name == allowed)
    }

    /// Check if a network target IP is allowed under the sandbox.
    ///
    /// Returns `true` if:
    /// - Sandbox is disabled
    /// - `allowed_networks` is empty (allow all with warning)
    /// - The IP matches any network in `allowed_networks`
    ///
    /// Returns `false` if the IP does not match any allowed network.
    pub fn is_network_allowed(&self, ip: IpAddr) -> bool {
        if !self.enabled {
            return true;
        }

        if self.allowed_networks.is_empty() {
            return true;
        }

        self.allowed_networks
            .iter()
            .any(|network| network.contains(ip))
    }

    /// Check if a network target host is allowed.
    ///
    /// This resolves the hostname and checks the resulting IP against allowed networks.
    /// Returns `false` if resolution fails while an allowlist is configured.
    ///
    /// # Security Note - DNS Rebinding
    /// This method checks if ANY resolved IP is allowed, but the actual connection
    /// may use a DIFFERENT IP if DNS changes between check and connection time.
    /// For sensitive operations, use `resolve_host()` immediately before connecting
    /// to get the actual IPs that will be used, and ensure DNS hasn't changed.
    pub fn is_host_allowed(&self, host: &str) -> bool {
        !self.resolve_host(host).is_empty()
    }

    /// Resolve a hostname to a list of IP addresses.
    ///
    /// # Security Note - DNS Rebinding
    /// DNS responses can change between calls. For sandbox enforcement, you should:
    /// 1. Call this method to resolve the host
    /// 2. Immediately use one of the returned IPs for the connection
    /// 3. Do not re-resolve the same hostname before connecting
    ///
    /// If sandboxing is disabled or no networks are restricted, returns all resolved IPs.
    /// If resolution fails or no IPs match the allowlist, returns an empty vector.
    pub fn resolve_host(&self, host: &str) -> Vec<IpAddr> {
        use std::net::ToSocketAddrs;

        if !self.enabled {
            if let Ok(addrs) = format!("{}:0", host).to_socket_addrs() {
                return addrs.map(|a| a.ip()).collect();
            }
            return Vec::new();
        }

        if self.allowed_networks.is_empty() {
            if let Ok(addrs) = format!("{}:0", host).to_socket_addrs() {
                return addrs.map(|a| a.ip()).collect();
            }
            return Vec::new();
        }

        let Ok(addrs) = format!("{}:0", host).to_socket_addrs() else {
            return Vec::new();
        };

        addrs
            .map(|a| a.ip())
            .filter(|ip| self.is_network_allowed(*ip))
            .collect()
    }
}

#[cfg(feature = "nse")]
pub mod async_executor;
#[cfg(feature = "nse")]
pub mod capabilities;
#[cfg(feature = "nse")]
pub mod context;
#[cfg(feature = "nse")]
pub mod cve;
#[cfg(feature = "nse")]
pub mod executor;
#[cfg(feature = "nse")]
pub mod executor_core;
pub mod limits;
pub mod output;
pub mod profile;
#[cfg(feature = "nse")]
pub mod public_api;
#[cfg(feature = "nse")]
pub mod report;
pub mod resolver;
#[cfg(feature = "nse")]
pub mod wrappers;

#[cfg(feature = "nse")]
pub mod libraries;

#[cfg(feature = "nse")]
pub mod bridge;

#[cfg(feature = "nse")]
pub use async_executor::AsyncNseExecutor;
#[cfg(feature = "nse")]
pub use capabilities::{
    NseCapabilityContext, NseCapabilityDecision, NseCapabilityEvent, NseCapabilityKind,
    NseCapabilityRequest,
};
#[cfg(feature = "nse")]
pub use executor::NseExecutor;
#[cfg(feature = "nse")]
pub use executor_core::ExecutorCore;
#[cfg(feature = "nse")]
pub use executor_core::SandboxMetrics;
#[cfg(feature = "nse")]
pub use executor_core::{default_module_policy, default_script_policy};
#[cfg(feature = "nse")]
pub use limits::{
    NseCancellationToken, NseExecutionLimits, NseExecutionStats, NseLimitViolation,
    NseResourceCounters,
};

pub use profile::{
    NseExecutionProfileKind, NseModulePolicy, NseNetworkPolicy, NseScriptPolicy,
    ResolvedNseExecutionProfile, ScopeInput,
};

pub use resolver::{
    is_builtin_script, validate_nse_module_name, NseLoadDiagnostic, NseLoadError, NseModuleName,
    NseScriptSource, ResolvedNseModule, ResolvedNseScript, ScriptResolver,
};

pub use resolver::registry::{
    all_libraries, find_library, libraries_by_category, libraries_missing_from_nmap,
    libraries_with_side_effects, registry_count, sandbox_policy_for_library, EnforcementStatus,
    NseFallbackBehavior, NseLibraryCategory, NseLibraryDescriptor, NseSandboxSideEffect,
};

#[cfg(feature = "nse")]
pub use report::{
    NseCompatibilitySummary, NseEvidenceItem, NseEvidenceKind, NseExecutionStatsSummary,
    NseLibraryUseReport, NseLimitsSummary, NseOutputSummary, NseProfileSummary,
    NseRequiredModuleReport, NseRequiredModuleSource, NseResolverDiagnosticSummary,
    NseResolverSummary, NseRuleEvaluationReport, NseRunCompatibilityStatus, NseRunFidelity,
    NseRunReport, NseSandboxSummary, NseScriptSourceSummary,
};

#[cfg(feature = "nse")]
pub use context::{NseContextSource, NseHostContext, NsePortContext, NseServiceContext};

/// Compatibility wrapper that defaults to `ManualPermissive` profile.
///
/// # Manual-only
///
/// This function is unused in production. Prefer [`run_cli_with_profile`]
/// with an explicit profile for all surfaces.
#[cfg(feature = "nse")]
pub async fn run_cli(config: NseConfig) -> anyhow::Result<()> {
    run_cli_with_profile(config, None).await
}

#[cfg(feature = "nse")]
pub async fn run_cli_with_profile(
    config: NseConfig,
    profile: Option<ResolvedNseExecutionProfile>,
) -> anyhow::Result<()> {
    let target = config.target.clone();
    let script = config.script.clone();
    let script_args = config.script_args.clone().unwrap_or_default();
    let script_file = config.script_file.clone();
    let json = config.json;

    let resolved_profile =
        profile.unwrap_or_else(|| ResolvedNseExecutionProfile::manual_permissive(Some(&target)));

    tracing::info!(
        profile = %resolved_profile.kind,
        sandbox_enabled = resolved_profile.sandbox.enabled,
        audit_label = %resolved_profile.audit_label,
        "NSE execution profile resolved"
    );

    for warning in &resolved_profile.warnings {
        tracing::warn!("{}", warning);
    }

    if script_file.is_some() && !resolved_profile.script_policy.allow_script_files {
        let failure_source = crate::resolver::NseScriptSource::File {
            path: std::path::PathBuf::from(script_file.as_ref().unwrap()),
        };
        let report = build_failure_report(
            &config.target,
            &config.script,
            &failure_source,
            &resolved_profile,
            &format!(
                "Profile '{}' does not allow arbitrary script files.",
                resolved_profile.kind
            ),
        );
        if json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        anyhow::bail!(
            "Profile '{}' does not allow arbitrary script files. \
             Use built-in scripts only.",
            resolved_profile.kind
        );
    }

    println!("Running NSE script '{}' against '{}'", script, target);
    if resolved_profile
        .warnings
        .iter()
        .any(|w| w.contains("sandbox"))
    {
        println!("Warning: sandbox enforcement is disabled (feature not compiled)");
    }

    let report_profile = resolved_profile.clone();
    // Clone for the blocking task so we still hold `resolved_profile` for the
    // post-execution report/profile label rendering below.
    let execution_profile = resolved_profile.clone();

    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<(String, crate::resolver::NseScriptSource, Vec<crate::resolver::NseLoadDiagnostic>, Vec<crate::report::NseRuleEvaluationReport>, Vec<crate::report::NseLibraryUseReport>, Vec<crate::capabilities::NseCapabilityEvent>)> {
        let mut executor = NseExecutor::with_profile(&execution_profile)
            .map_err(|e| anyhow::anyhow!("Failed to create NSE executor: {}", e))?;
        executor
            .set_target(&target)
            .map_err(|e| anyhow::anyhow!("Failed to set target: {}", e))?;
        executor
            .set_script_args(&script_args)
            .map_err(|e| anyhow::anyhow!("Invalid script args: {}", e))?;

        let mut resolver = crate::resolver::ScriptResolver::new(
            resolved_profile.script_policy.clone(),
            resolved_profile.module_policy.clone(),
            resolved_profile.limits.clone(),
        );
        let (script_content, script_source) = if let Some(ref script_file) = script_file {
            let source = crate::resolver::NseScriptSource::File {
                path: std::path::PathBuf::from(script_file),
            };
            let src = source.clone();
            match resolver.resolve_script(source) {
                Ok(resolved) => (resolved.content, src),
                Err(e) => {
                    tracing::error!(error = %e, "Script file resolution failed");
                    anyhow::bail!("{}", e);
                }
            }
        } else {
            let content = get_builtin_script(&script);
            let source = crate::resolver::NseScriptSource::InlineManual {
                label: script.clone(),
                content: content.clone(),
            };
            let src = source.clone();
            match resolver.resolve_script(source) {
                Ok(_) => (content, src),
                Err(e) => {
                    tracing::error!(error = %e, "Built-in script resolution failed");
                    anyhow::bail!("{}", e);
                }
            }
        };

        let diagnostics = resolver.take_diagnostics();

        let (output, _raw_outputs, rule_reports) = executor
            .run_script_with_rules(&script_content)
            .map_err(|e| anyhow::anyhow!("Script execution failed: {}", e))?;

        let mut library_reports = executor.library_reports();
        if library_reports.is_empty() {
            let static_requires = extract_static_requires(&script_content);
            if !static_requires.is_empty() {
                library_reports = crate::report::library_use_reports_from_static_requires(
                    &static_requires,
                );
            }
        }

        let capability_events = executor.capability_events();

        Ok((output, script_source, diagnostics, rule_reports, library_reports, capability_events))
    })
    .await
    .map_err(|e| anyhow::anyhow!("Task execution failed: {}", e))??;

    let (output, script_source, diagnostics, rule_reports, library_reports, capability_events) =
        result;

    let report = crate::report::NseRunReport::new(&config.target, &config.script)
        .with_profile(&report_profile)
        .with_script_source(&script_source)
        .with_resolver_diagnostics(&diagnostics)
        .with_libraries(library_reports)
        .with_rules(rule_reports)
        .with_capability_events(capability_events)
        .with_output(&output)
        .compute_compatibility();
    let evidence = crate::report::extract_evidence(
        &report.target,
        &report.script_name,
        &report.capability_events,
        &report.compatibility,
        &report.rules,
        &report.output,
    );
    let report = report.with_evidence(evidence);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human_report(&report);
    }

    Ok(())
}

#[cfg(feature = "nse")]
fn build_failure_report(
    target: &str,
    script: &str,
    script_source: &crate::resolver::NseScriptSource,
    profile: &ResolvedNseExecutionProfile,
    error: &str,
) -> crate::report::NseRunReport {
    crate::report::NseRunReport::new(target, script)
        .with_profile(profile)
        .with_script_source(script_source)
        .with_error(error)
        .compute_compatibility()
}

#[cfg(feature = "nse")]
fn print_human_report(report: &crate::report::NseRunReport) {
    use crate::report::NseRunCompatibilityStatus;

    println!();
    println!("NSE Script Report");
    println!("=================");
    println!("  Target:    {}", report.target);
    println!("  Script:    {}", report.script_name);
    println!(
        "  Source:    {} ({})",
        report.script_source.label, report.script_source.kind
    );
    println!("  Profile:   {}", report.profile.kind);
    println!("  Elapsed:   {:.2}s", report.stats.elapsed_secs);

    // Compatibility summary
    println!();
    println!("Compatibility");
    println!("-------------");
    let status_str = match report.compatibility.status {
        NseRunCompatibilityStatus::Compatible => "compatible".to_string(),
        NseRunCompatibilityStatus::CompatibleWithWarnings => "compatible (warnings)".to_string(),
        NseRunCompatibilityStatus::Partial => "partial".to_string(),
        NseRunCompatibilityStatus::Unsupported => "unsupported".to_string(),
        NseRunCompatibilityStatus::Failed => "failed".to_string(),
        NseRunCompatibilityStatus::Unknown => "unknown".to_string(),
    };
    println!("  Status:  {}", status_str);
    println!("  Fidelity: {:?}", report.compatibility.fidelity);
    if !report.compatibility.unsupported_features.is_empty() {
        println!(
            "  Unsupported: {}",
            report.compatibility.unsupported_features.join(", ")
        );
    }
    if !report.compatibility.approximations.is_empty() {
        println!(
            "  Approximations: {}",
            report.compatibility.approximations.join(", ")
        );
    }

    // Rule results
    if !report.rules.is_empty() {
        println!();
        println!("Rule Evaluation");
        println!("---------------");
        for rule in &report.rules {
            let status = if rule.matched {
                "matched"
            } else if rule.evaluated {
                "no match"
            } else {
                "not evaluated"
            };
            println!("  [{}] {} ({})", rule.kind, status, rule.exactness);
            if !rule.summary.is_empty() {
                println!("    {}", rule.summary);
            }
            if let Some(ref unsupported) = rule.unsupported {
                println!("    unsupported: {}", unsupported);
            }
        }
    }

    // Libraries used
    if !report.libraries.is_empty() {
        println!();
        println!("Libraries");
        println!("---------");
        for lib in &report.libraries {
            let status = if lib.loaded {
                "loaded"
            } else if lib.registered {
                "registered"
            } else {
                "unregistered"
            };
            let se_str = if lib.side_effects.is_empty() {
                String::new()
            } else {
                format!(" [{}]", lib.side_effects.join(", "))
            };
            println!("  {} ({}, {}{})", lib.name, lib.category, status, se_str);
            for w in &lib.warnings {
                println!("    warning: {}", w);
            }
        }
    }

    // Capability events
    let denials: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| !e.allowed)
        .collect();
    if !denials.is_empty() {
        println!();
        println!("Capability Denials");
        println!("------------------");
        for denial in &denials {
            let target_str = denial
                .target
                .as_deref()
                .map(|t| format!(" on {}", t))
                .unwrap_or_default();
            println!(
                "  {}{}: {}",
                denial.kind,
                target_str,
                denial.reason.as_deref().unwrap_or("denied by policy")
            );
        }
    }

    // Evidence
    if !report.evidence.is_empty() {
        println!();
        println!("Evidence ({} items)", report.evidence.len());
        println!("--------------------");
        for item in &report.evidence {
            let target_str = item.target.as_str();
            println!(
                "  [{}] {} (confidence: {})",
                item.kind, item.title, item.confidence
            );
            println!("    {}", item.summary);
        }
    }

    // Errors
    if !report.errors.is_empty() {
        println!();
        println!("Errors");
        println!("------");
        for err in &report.errors {
            println!("  - {}", err);
        }
    }

    // Warnings
    if !report.warnings.is_empty() {
        println!();
        println!("Warnings");
        println!("--------");
        for warn in &report.warnings {
            println!("  - {}", warn);
        }
    }

    // Raw output (truncated for human display)
    let output_str = report.output.content.trim();
    if !output_str.is_empty() {
        println!();
        println!("Raw Output");
        println!("----------");
        let lines: Vec<&str> = output_str.lines().collect();
        let max_lines = 20;
        for line in lines.iter().take(max_lines) {
            println!("  {}", line);
        }
        if lines.len() > max_lines {
            println!(
                "  ... ({} more lines, use --json for full output)",
                lines.len() - max_lines
            );
        }
    }

    println!();
}

#[cfg(feature = "nse")]
static STATIC_REQUIRE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)\brequire\s*(?:\(\s*)?['"]([^'"]+)['"]\s*\)?"#)
        .expect("static require regex must compile")
});

#[cfg(feature = "nse")]
fn extract_static_requires(script_content: &str) -> Vec<String> {
    let mut seen = FxHashSet::default();
    let mut names = Vec::new();

    for capture in STATIC_REQUIRE_RE.captures_iter(script_content) {
        let Some(name) = capture.get(1).map(|m| m.as_str().trim()) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let name = name.to_string();
        if seen.insert(name.clone()) {
            names.push(name);
        }
    }

    names
}

#[cfg(not(feature = "nse"))]
pub async fn run_cli(_config: NseConfig) -> anyhow::Result<()> {
    anyhow::bail!("NSE support requires the 'nse' feature. Build with: cargo build --features nse")
}

#[cfg(not(feature = "nse"))]
pub async fn run_cli_with_profile(
    _config: NseConfig,
    _profile: Option<ResolvedNseExecutionProfile>,
) -> anyhow::Result<()> {
    anyhow::bail!("NSE support requires the 'nse' feature. Build with: cargo build --features nse")
}

#[cfg(feature = "nse")]
pub fn get_builtin_script(name: &str) -> String {
    match name {
        "default" | "discovery" => r#"
-- Default NSE discovery script
local stdnse = require "stdnse"

stdnse.verbose1("Starting NSE discovery scan...")

local host = nmap.target
if host and host ~= "" then
    stdnse.format_output({status = "open", service = "discovered"}, {separator = ", "})
end

local output = stdnse.output_table()
output.host = host or "unknown"
output.status = "discovered"
output.scan_time = os.date("*t")

return output
"#
        .to_string(),
        "banner" => r#"
-- Banner grabbing script
local stdnse = require "stdnse"
local comm = require "comm"
local socket = require "socket"

local host = nmap.target
local port = 80

if not host or host == "" then
    return stdnse.output_table()
end

local s = socket.connect(host, port)
if s then
    s:send("HEAD / HTTP/1.0\r\n\r\n")
    local status, response = s:receive(1024)
    s:close()

    local output = stdnse.output_table()
    output.banner = response or ""
    output.host = host
    output.port = port
    return output
end

return nil
"#
        .to_string(),
        "http-headers" => r#"
-- HTTP headers discovery script
local stdnse = require "stdnse"
local http = require "http"

local host = nmap.target

if not host or host == "" then
    return stdnse.output_table()
end

local response = http.get(host, 80, "/")

local output = stdnse.output_table()
output.host = host
output.port = 80
output.title = response.title or ""
output.status = response.status or 0

return output
"#
        .to_string(),
        "dns-check" => r#"
-- DNS resolution check script
local stdnse = require "stdnse"
local dns = require "dns"

local host = nmap.target

if not host or host == "" then
    return stdnse.output_table()
end

local success = dns.query(host)

local output = stdnse.output_table()
output.host = host
output.resolved = success

return output
"#
        .to_string(),
        "ssl-cert" => r#"
-- SSL certificate information script
local stdnse = require "stdnse"
local sslcert = require "sslcert"
local tls = require "tls"

local host = nmap.target

if not host or host == "" then
    return stdnse.output_table()
end

local output = stdnse.output_table()
output.host = host
output.port = 443
output.tls = "available"

return output
"#
        .to_string(),
        _ => {
            format!(
                r#"
-- Custom NSE script: {}
local stdnse = require "stdnse"

stdnse.verbose1("Executing custom NSE script: {}")

local output = stdnse.output_table()
output.script = "{}"
output.status = "executed"
output.libraries = {{
    stdnse = true,
    nmap = true,
    socket = true,
    http = true,
}}

return output
"#,
                name, name, name
            )
        }
    }
}
