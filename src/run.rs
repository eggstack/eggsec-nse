//! Canonical NSE execution pipeline.
//!
//! This module owns the single authoritative runtime path from an
//! [`NseRunRequest`] (target, script source, profile, optional host/port
//! context, explicit limit/cancellation overrides) through script resolution,
//! executor setup, rule/action execution, and complete [`NseRunReport`]
//! assembly.
//!
//! Production surfaces (runtime CLI helper, Eggsec dispatch/TUI, Python
//! bindings) must select a request/profile and render the returned report.
//! They must not reproduce this orchestration.
//!
//! NSE runtime capability policy (profile-gated script/module/network
//! behavior) remains distinct from Eggsec operation authorization, which
//! stays outside `eggsec-nse`.

use std::fmt;
use std::sync::LazyLock;

use regex::Regex;
use rustc_hash::FxHashSet;

use crate::context::{NseHostContext, NsePortContext};
use crate::executor::NseExecutor;
use crate::limits::{NseCancellationToken, NseExecutionLimits};
use crate::profile::ResolvedNseExecutionProfile;
use crate::report::{extract_evidence, library_use_reports_from_static_requires, NseRunReport};
use crate::resolver::{NseLoadDiagnostic, NseLoadError, NseScriptSource, ScriptResolver};

/// Canonical runtime-owned execution request.
///
/// Prefer constructing this value over positional executor calls. The
/// resolved execution profile carries sandbox, limits, script/module
/// policy, and network policy; `limits_override` and `cancellation` are
/// the only explicit per-run override seams.
#[derive(Debug, Clone)]
pub struct NseRunRequest {
    /// Target host or URL as supplied by the caller.
    pub target: String,
    /// Script source identity (built-in, registry, file, inline/manual).
    pub script: NseScriptSource,
    /// Optional comma-separated script arguments.
    pub script_args: Option<String>,
    /// Resolved execution profile governing this run.
    pub profile: ResolvedNseExecutionProfile,
    /// Optional host context applied to the executor before execution.
    pub host_context: Option<NseHostContext>,
    /// Optional port context applied to the executor before execution.
    pub port_context: Option<NsePortContext>,
    /// Optional per-run limits replacing `profile.limits`.
    pub limits_override: Option<NseExecutionLimits>,
    /// Optional per-run cancellation token. A fresh token is created when
    /// absent.
    pub cancellation: Option<NseCancellationToken>,
}

impl NseRunRequest {
    /// Build a request with no arguments, context, or overrides.
    pub fn new(
        target: &str,
        script: NseScriptSource,
        profile: ResolvedNseExecutionProfile,
    ) -> Self {
        Self {
            target: target.to_string(),
            script,
            script_args: None,
            profile,
            host_context: None,
            port_context: None,
            limits_override: None,
            cancellation: None,
        }
    }

    /// Attach script arguments.
    pub fn with_script_args(mut self, args: &str) -> Self {
        self.script_args = Some(args.to_string());
        self
    }

    /// Attach host context applied to the executor before execution.
    pub fn with_host_context(mut self, ctx: NseHostContext) -> Self {
        self.host_context = Some(ctx);
        self
    }

    /// Attach port context applied to the executor before execution.
    pub fn with_port_context(mut self, ctx: NsePortContext) -> Self {
        self.port_context = Some(ctx);
        self
    }

    /// Replace the profile limits for this run only.
    pub fn with_limits_override(mut self, limits: NseExecutionLimits) -> Self {
        self.limits_override = Some(limits);
        self
    }

    /// Use a caller-owned cancellation token for this run.
    pub fn with_cancellation(mut self, token: NseCancellationToken) -> Self {
        self.cancellation = Some(token);
        self
    }

    /// Effective limits: explicit override wins over profile limits.
    pub fn effective_limits(&self) -> NseExecutionLimits {
        self.limits_override
            .clone()
            .unwrap_or_else(|| self.profile.limits.clone())
    }

    /// Effective cancellation token: caller token or a fresh one.
    pub fn effective_cancellation(&self) -> NseCancellationToken {
        self.cancellation.clone().unwrap_or_default()
    }

    /// Script display name derived from the source identity.
    pub fn script_name(&self) -> String {
        script_name_for_source(&self.script)
    }
}

/// Script display name derived from the source identity.
///
/// Used for `NseRunReport.script_name` so every surface reports the same
/// name for the same source.
pub fn script_name_for_source(source: &NseScriptSource) -> String {
    match source {
        NseScriptSource::Builtin { name } => name.clone(),
        NseScriptSource::TrustedRegistry { name } => name.clone(),
        NseScriptSource::File { path } => path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string(),
        NseScriptSource::InlineManual { label, .. } => label.clone(),
    }
}

/// Machine-readable failure kind for a canonical run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NseRunErrorKind {
    /// Script resolution failed (policy, missing file, oversized, ...).
    Resolution,
    /// Executor construction failed.
    ExecutorInit,
    /// Target was rejected by the executor.
    TargetRejected,
    /// Script arguments were rejected by the executor.
    ScriptArgsRejected,
    /// Script execution failed.
    Execution,
    /// Cancellation was requested before or during execution.
    Cancelled,
}

impl fmt::Display for NseRunErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolution => write!(f, "resolution"),
            Self::ExecutorInit => write!(f, "executor-init"),
            Self::TargetRejected => write!(f, "target-rejected"),
            Self::ScriptArgsRejected => write!(f, "script-args-rejected"),
            Self::Execution => write!(f, "execution"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Typed failure from the canonical pipeline.
///
/// Carries the request context required to build a failure report where
/// current caller behavior requires one (see [`NseRunError::failure_report`]).
/// Cancellation is never converted into an ordinary successful empty report.
#[derive(Debug, Clone)]
pub struct NseRunError {
    /// Failure kind.
    pub kind: NseRunErrorKind,
    /// Human-readable cause.
    pub message: String,
    /// Request target.
    pub target: String,
    /// Request script name.
    pub script_name: String,
    /// Request script source.
    pub script_source: NseScriptSource,
    /// Effective profile (limits override applied).
    pub profile: ResolvedNseExecutionProfile,
    /// Resolver diagnostics collected before the failure.
    pub diagnostics: Vec<NseLoadDiagnostic>,
}

impl NseRunError {
    fn new(
        kind: NseRunErrorKind,
        message: String,
        request: &NseRunRequest,
        effective_profile: &ResolvedNseExecutionProfile,
        diagnostics: Vec<NseLoadDiagnostic>,
    ) -> Self {
        Self {
            kind,
            message,
            target: request.target.clone(),
            script_name: request.script_name(),
            script_source: request.script.clone(),
            profile: effective_profile.clone(),
            diagnostics,
        }
    }

    /// Build a failure `NseRunReport` preserving profile, source,
    /// resolver diagnostics, and the error.
    ///
    /// Mirrors the pre-convergence failure-report behavior: the report
    /// carries `Failed` compatibility once computed.
    pub fn failure_report(&self) -> NseRunReport {
        NseRunReport::new(&self.target, &self.script_name)
            .with_profile(&self.profile)
            .with_script_source(&self.script_source)
            .with_resolver_diagnostics(&self.diagnostics)
            .with_error(&self.message)
            .compute_compatibility()
    }
}

impl fmt::Display for NseRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NSE {} failed: {}", self.kind, self.message)
    }
}

impl std::error::Error for NseRunError {}

static STATIC_REQUIRE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)\brequire\s*(?:\(\s*)?['"]([^'"]+)['"]\s*\)?"#)
        .expect("static require regex must compile")
});

/// Runtime-owned static `require()` fallback.
///
/// Used only when dynamic require tracking produced no library reports.
/// Entries are labeled `loaded: false` with a static-detection warning via
/// [`library_use_reports_from_static_requires`]; this function is the single
/// owner of that fallback (callers must not duplicate it).
pub fn extract_static_requires(script_content: &str) -> Vec<String> {
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

/// Execute one canonical NSE run: resolve, execute, assemble, report.
///
/// This is the single owner of the resolver-first execution sequence:
/// 1. resolve the supplied [`NseScriptSource`] using [`ScriptResolver`]
///    and profile policy;
/// 2. initialize the executor with the resolved (effective) profile;
/// 3. set target/script args/optional host-port context;
/// 4. execute NSE rule evaluation and action semantics;
/// 5. gather final execution stats;
/// 6. gather dynamic library-use data plus the runtime-owned static
///    fallback when tracking produced nothing;
/// 7. gather capability events;
/// 8. preserve resolver diagnostics;
/// 9. build the report;
/// 10. compute compatibility/fidelity once;
/// 11. extract evidence once;
/// 12. return the complete report.
///
/// Synchronous and blocking: async callers must run it inside
/// `spawn_blocking` (or an equivalent bounded blocking task). Per-run
/// report state is never shared across concurrent executions.
pub fn execute_nse_run(request: NseRunRequest) -> Result<NseRunReport, NseRunError> {
    let script_name = request.script_name();
    let mut effective_profile = request.profile.clone();
    if let Some(ref limits) = request.limits_override {
        effective_profile.limits = limits.clone();
    }
    let cancellation = request.effective_cancellation();

    if cancellation.is_cancelled() {
        return Err(NseRunError::new(
            NseRunErrorKind::Cancelled,
            "cancellation requested before execution".to_string(),
            &request,
            &effective_profile,
            Vec::new(),
        ));
    }

    // 1. Resolver-first script resolution under profile policy.
    let mut resolver = ScriptResolver::new(
        effective_profile.script_policy.clone(),
        effective_profile.module_policy.clone(),
        effective_profile.limits.clone(),
    );
    let fail = |kind: NseRunErrorKind, message: String, resolver: &mut ScriptResolver| {
        NseRunError::new(
            kind,
            message,
            &request,
            &effective_profile,
            resolver.take_diagnostics(),
        )
    };

    let resolved_content = match &request.script {
        NseScriptSource::Builtin { name } => {
            // Policy/diag check first; content is the shipped built-in.
            if let Err(e) = resolver.resolve_script(request.script.clone()) {
                return Err(fail(
                    NseRunErrorKind::Resolution,
                    format!(
                        "built-in script resolution failed: {}",
                        load_error_message(&e)
                    ),
                    &mut resolver,
                ));
            }
            let content = crate::get_builtin_script(name);
            enforce_builtin_size(&content, &request, &effective_profile, &mut resolver)?;
            content
        }
        NseScriptSource::File { .. } => match resolver.resolve_script(request.script.clone()) {
            Ok(resolved) => resolved.content,
            Err(e) => {
                // Preserve the historical CLI denial message for profile-gated
                // file sources so manual surfaces keep their UX.
                let message = match &e {
                    NseLoadError::BlockedByPolicy { .. } => format!(
                        "Profile '{}' does not allow arbitrary script files. \
                         Use built-in scripts only.",
                        effective_profile.kind
                    ),
                    _ => format!("script resolution failed: {}", load_error_message(&e)),
                };
                return Err(fail(NseRunErrorKind::Resolution, message, &mut resolver));
            }
        },
        NseScriptSource::TrustedRegistry { .. } | NseScriptSource::InlineManual { .. } => {
            match resolver.resolve_script(request.script.clone()) {
                Ok(resolved) => resolved.content,
                Err(e) => {
                    return Err(fail(
                        NseRunErrorKind::Resolution,
                        format!("script resolution failed: {}", load_error_message(&e)),
                        &mut resolver,
                    ));
                }
            }
        }
    };

    // 2. Executor with the effective profile (never a manual-only default).
    let mut executor = match NseExecutor::with_full_policy(
        effective_profile.sandbox.clone(),
        effective_profile.limits.clone(),
        cancellation.clone(),
        effective_profile.script_policy.clone(),
        effective_profile.module_policy.clone(),
        effective_profile.kind,
        effective_profile.network_policy.clone(),
    ) {
        Ok(executor) => executor,
        Err(e) => {
            return Err(fail(
                NseRunErrorKind::ExecutorInit,
                format!("failed to create NSE executor: {}", e),
                &mut resolver,
            ));
        }
    };

    // 3. Target, script args, and optional host/port context.
    if let Err(e) = executor.set_target(&request.target) {
        return Err(fail(
            NseRunErrorKind::TargetRejected,
            format!("failed to set target: {}", e),
            &mut resolver,
        ));
    }
    if let Some(ref args) = request.script_args {
        if let Err(e) = executor.set_script_args(args) {
            return Err(fail(
                NseRunErrorKind::ScriptArgsRejected,
                format!("invalid script args: {}", e),
                &mut resolver,
            ));
        }
    }
    apply_context(&mut executor, &request, &mut resolver)?;

    // 4. Rule evaluation and action semantics.
    let (output, _raw_outputs, rule_reports) =
        match executor.run_script_with_rules(&resolved_content) {
            Ok(result) => result,
            Err(e) => {
                if cancellation.is_cancelled() {
                    return Err(fail(
                        NseRunErrorKind::Cancelled,
                        format!("execution cancelled: {}", e),
                        &mut resolver,
                    ));
                }
                return Err(fail(
                    NseRunErrorKind::Execution,
                    format!("script execution failed: {}", e),
                    &mut resolver,
                ));
            }
        };
    if cancellation.is_cancelled() {
        return Err(fail(
            NseRunErrorKind::Cancelled,
            "cancellation requested during execution".to_string(),
            &mut resolver,
        ));
    }

    // 5-7. Stats, library-use (dynamic + one static fallback), capability events.
    let stats = executor.execution_stats();
    let mut library_reports = executor.library_reports();
    if library_reports.is_empty() {
        let static_requires = extract_static_requires(&resolved_content);
        if !static_requires.is_empty() {
            library_reports = library_use_reports_from_static_requires(&static_requires);
        }
    }
    let capability_events = executor.capability_events();

    // 8-11. Diagnostics, report, compatibility, evidence — each exactly once.
    let diagnostics = resolver.take_diagnostics();
    let report = NseRunReport::new(&request.target, &script_name)
        .with_profile(&effective_profile)
        .with_script_source(&request.script)
        .with_stats(&stats)
        .with_resolver_diagnostics(&diagnostics)
        .with_libraries(library_reports)
        .with_rules(rule_reports)
        .with_capability_events(capability_events)
        .with_output(&output)
        .compute_compatibility();
    let evidence = extract_evidence(
        &report.target,
        &report.script_name,
        &report.capability_events,
        &report.compatibility,
        &report.rules,
        &report.output,
    );

    // 12. Complete report.
    Ok(report.with_evidence(evidence))
}

/// Enforce script-size policy on shipped built-in content.
///
/// The resolver's built-in path validates policy but does not measure the
/// injected content; apply the same size gates used for file/inline
/// sources so built-ins cannot bypass them.
fn enforce_builtin_size(
    content: &str,
    request: &NseRunRequest,
    effective_profile: &ResolvedNseExecutionProfile,
    resolver: &mut ScriptResolver,
) -> Result<(), NseRunError> {
    let size = content.len();
    let limit = effective_profile
        .limits
        .max_script_bytes
        .or(effective_profile.script_policy.max_script_bytes);
    if let Some(limit) = limit {
        if size > limit {
            let diagnostics = resolver.take_diagnostics();
            let mut error = NseRunError::new(
                NseRunErrorKind::Resolution,
                format!(
                    "built-in script '{}' exceeds size limit ({} > {} bytes)",
                    request.script_name(),
                    size,
                    limit
                ),
                request,
                effective_profile,
                diagnostics,
            );
            error
                .diagnostics
                .push(NseLoadDiagnostic::OversizedRejected {
                    source: request.script.clone(),
                    size,
                    limit,
                });
            return Err(error);
        }
    }
    Ok(())
}

/// Apply optional host/port context to the executor.
///
/// Absent context preserves the executor's synthetic-context behavior;
/// supplied context is injected via the existing host/port setters so rule
/// evaluation observes caller-provided data.
fn apply_context(
    executor: &mut NseExecutor,
    request: &NseRunRequest,
    resolver: &mut ScriptResolver,
) -> Result<(), NseRunError> {
    let fail = |message: String, resolver: &mut ScriptResolver| {
        NseRunError::new(
            NseRunErrorKind::TargetRejected,
            message,
            request,
            &request.profile,
            resolver.take_diagnostics(),
        )
    };

    if let Some(ref host) = request.host_context {
        if let Err(e) = executor.set_host_info(host.hostname.clone(), host.ip.clone(), None, None) {
            tracing::warn!("NSE host context rejected: {}", e);
            return Err(fail(format!("host context rejected: {}", e), resolver));
        }
    }
    if let Some(ref port) = request.port_context {
        let service = port.service.as_ref().and_then(|s| s.name.clone());
        if let Err(e) = executor.add_port(port.port, &port.protocol, &port.state, service) {
            tracing::warn!("NSE port context rejected: {}", e);
            return Err(fail(format!("port context rejected: {}", e), resolver));
        }
    }
    Ok(())
}

/// Render a resolver failure without requiring `Debug` on the error type.
fn load_error_message(e: &NseLoadError) -> String {
    e.to_string()
}
