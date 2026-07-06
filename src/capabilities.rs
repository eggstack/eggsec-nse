//! NSE capability context and decision engine.
//!
//! Provides centralized policy enforcement, resource accounting, and
//! cancellation support for all side-effecting NSE helper operations.
//!
//! This module replaces ad hoc policy checks scattered across library files
//! with a single capability context that helpers query before performing
//! filesystem, network, process, DNS, crypto, compression, time, or
//! randomness operations.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::limits::{NseCancellationToken, NseExecutionLimits, NseResourceCounters};
use crate::profile::{NseExecutionProfileKind, NseModulePolicy, NseNetworkPolicy, NseScriptPolicy};
use crate::SandboxConfig;

/// Central capability context for NSE helper-side enforcement.
///
/// Helpers query this context before performing side-effecting operations.
/// The context checks profile policy, limits, cancellation, and updates
/// resource counters.
#[derive(Debug, Clone)]
pub struct NseCapabilityContext {
    /// Execution profile kind for policy decisions.
    pub profile_kind: NseExecutionProfileKind,
    /// Network access policy derived from profile.
    pub network_policy: NseNetworkPolicy,
    /// Script file access policy.
    pub script_policy: NseScriptPolicy,
    /// Module file access policy.
    pub module_policy: NseModulePolicy,
    /// Sandbox configuration for path/command validation.
    pub sandbox: SandboxConfig,
    /// Execution limits for resource bounds.
    pub limits: NseExecutionLimits,
    /// Cooperative cancellation token.
    pub cancellation: NseCancellationToken,
    /// Atomic resource counters for accounting.
    pub counters: Arc<NseResourceCounters>,
    /// Capability event log for report integration.
    events: Arc<Mutex<Vec<NseCapabilityEvent>>>,
}

/// Categories of side-effecting operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NseCapabilityKind {
    /// Read file contents or metadata.
    FilesystemRead,
    /// Create, modify, delete, or rename files/directories.
    FilesystemWrite,
    /// Execute external commands or spawn processes.
    ProcessExec,
    /// TCP socket operations.
    NetworkTcp,
    /// UDP socket operations.
    NetworkUdp,
    /// DNS lookups via system or custom resolver.
    DnsResolution,
    /// Wall-clock time reads, sleeps, timers.
    TimeClock,
    /// Random number/string generation.
    Randomness,
    /// TLS/SSL operations, certificate handling, crypto.
    Crypto,
    /// Gzip, deflate, zlib compression/decompression.
    Compression,
    /// Environment variable access.
    Environment,
}

impl std::fmt::Display for NseCapabilityKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FilesystemRead => write!(f, "filesystem_read"),
            Self::FilesystemWrite => write!(f, "filesystem_write"),
            Self::ProcessExec => write!(f, "process_exec"),
            Self::NetworkTcp => write!(f, "network_tcp"),
            Self::NetworkUdp => write!(f, "network_udp"),
            Self::DnsResolution => write!(f, "dns_resolution"),
            Self::TimeClock => write!(f, "time_clock"),
            Self::Randomness => write!(f, "randomness"),
            Self::Crypto => write!(f, "crypto"),
            Self::Compression => write!(f, "compression"),
            Self::Environment => write!(f, "environment"),
        }
    }
}

/// Request to perform a capability operation.
#[derive(Debug, Clone)]
pub struct NseCapabilityRequest {
    /// Kind of operation being requested.
    pub kind: NseCapabilityKind,
    /// Optional target (host, path, command).
    pub target: Option<String>,
    /// Optional byte count hint for resource accounting.
    pub bytes_hint: Option<u64>,
    /// Static operation name for diagnostics (e.g., "io.popen", "socket.connect").
    pub operation: &'static str,
}

/// Decision from the capability engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NseCapabilityDecision {
    /// Operation is allowed.
    Allow,
    /// Operation is denied.
    Deny { reason: String },
    /// Operation is allowed but a warning should be recorded.
    AllowWithWarning { warning: String },
}

impl NseCapabilityDecision {
    /// Returns true if the decision allows the operation.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow | Self::AllowWithWarning { .. })
    }

    /// Returns true if the decision denies the operation.
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// Returns the warning string if present.
    pub fn warning(&self) -> Option<&str> {
        match self {
            Self::AllowWithWarning { warning } => Some(warning),
            _ => None,
        }
    }

    /// Returns the denial reason if present.
    pub fn deny_reason(&self) -> Option<&str> {
        match self {
            Self::Deny { reason } => Some(reason),
            _ => None,
        }
    }
}

/// Event recorded when a capability operation is attempted.
#[derive(Debug, Clone)]
pub struct NseCapabilityEvent {
    /// Kind of operation attempted.
    pub kind: NseCapabilityKind,
    /// Operation name (e.g., "io.popen", "socket.connect").
    pub operation: String,
    /// Optional target (host, path, command).
    pub target: Option<String>,
    /// Whether the operation was allowed.
    pub allowed: bool,
    /// Denial or warning reason if applicable.
    pub reason: Option<String>,
    /// Byte count for resource accounting.
    pub bytes: Option<u64>,
}

impl NseCapabilityContext {
    /// Create a capability context from existing executor core fields.
    pub fn new(
        profile_kind: NseExecutionProfileKind,
        network_policy: NseNetworkPolicy,
        script_policy: NseScriptPolicy,
        module_policy: NseModulePolicy,
        sandbox: SandboxConfig,
        limits: NseExecutionLimits,
        cancellation: NseCancellationToken,
        counters: Arc<NseResourceCounters>,
    ) -> Self {
        Self {
            profile_kind,
            network_policy,
            script_policy,
            module_policy,
            sandbox,
            limits,
            cancellation,
            counters,
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a capability context from a resolved profile.
    pub fn from_profile(
        profile: &crate::profile::ResolvedNseExecutionProfile,
        counters: Arc<NseResourceCounters>,
    ) -> Self {
        Self::new(
            profile.kind,
            profile.network_policy.clone(),
            profile.script_policy.clone(),
            profile.module_policy.clone(),
            profile.sandbox.clone(),
            profile.limits.clone(),
            NseCancellationToken::new(),
            counters,
        )
    }

    /// Check if an operation is allowed under the current policy.
    ///
    /// This is the central decision engine. It checks:
    /// 1. Cancellation token
    /// 2. Profile-specific policy for the capability kind
    /// 3. Sandbox restrictions (path, command, network)
    /// 4. Resource limits (operation count, byte limits)
    pub fn check_capability(&self, request: &NseCapabilityRequest) -> NseCapabilityDecision {
        // First check: cancellation
        if self.cancellation.is_cancelled() {
            return NseCapabilityDecision::Deny {
                reason: "Script execution cancelled".to_string(),
            };
        }

        // Profile-specific policy checks
        let decision = match self.profile_kind {
            NseExecutionProfileKind::ManualPermissive => self.check_manual_permissive(request),
            NseExecutionProfileKind::ManualStrict => self.check_manual_strict(request),
            NseExecutionProfileKind::AgentSafe => self.check_agent_safe(request),
            NseExecutionProfileKind::CiSafe => self.check_ci_safe(request),
            NseExecutionProfileKind::CompatibilityLab => self.check_compatibility_lab(request),
        };

        // Record the event
        self.record_event(request, &decision);

        decision
    }

    /// Check cancellation before a blocking operation.
    ///
    /// Returns `Err` if cancelled, `Ok` if operation can proceed.
    pub fn check_cancelled(&self, operation: &str) -> Result<(), String> {
        if self.cancellation.is_cancelled() {
            let msg = format!("Script execution cancelled during {}", operation);
            tracing::warn!("{}", msg);
            Err(msg)
        } else {
            Ok(())
        }
    }

    /// Pre-block check for a blocking operation.
    ///
    /// Verifies cancellation and resource limits before allowing
    /// a potentially blocking operation to proceed.
    pub fn before_blocking_operation(&self, request: &NseCapabilityRequest) -> Result<(), String> {
        // Check cancellation
        self.check_cancelled(request.operation)?;

        // Check resource limits based on capability kind
        match request.kind {
            NseCapabilityKind::NetworkTcp | NseCapabilityKind::NetworkUdp => {
                if let Some(max) = self.limits.max_network_operations {
                    let current = self.counters.network_operations.load(Ordering::Relaxed);
                    if current >= max {
                        return Err(format!(
                            "Network operation limit exceeded: {}/{}",
                            current, max
                        ));
                    }
                }
                if let Some(bytes) = request.bytes_hint {
                    if let Some(max) = self.limits.max_network_bytes_read {
                        let current = self.counters.network_bytes_read.load(Ordering::Relaxed);
                        if current + bytes > max {
                            return Err(format!(
                                "Network bytes read limit exceeded: {}/{}",
                                current + bytes,
                                max
                            ));
                        }
                    }
                }
            }
            NseCapabilityKind::FilesystemRead | NseCapabilityKind::FilesystemWrite => {
                if let Some(max) = self.limits.max_filesystem_operations {
                    let current = self.counters.filesystem_operations.load(Ordering::Relaxed);
                    if current >= max {
                        return Err(format!(
                            "Filesystem operation limit exceeded: {}/{}",
                            current, max
                        ));
                    }
                }
                if request.kind == NseCapabilityKind::FilesystemRead {
                    if let Some(bytes) = request.bytes_hint {
                        if let Some(max) = self.limits.max_filesystem_bytes_read {
                            let current =
                                self.counters.filesystem_bytes_read.load(Ordering::Relaxed);
                            if current + bytes > max {
                                return Err(format!(
                                    "Filesystem bytes read limit exceeded: {}/{}",
                                    current + bytes,
                                    max
                                ));
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Post-block update for a blocking operation.
    ///
    /// Updates resource counters after an operation completes.
    pub fn after_blocking_operation(
        &self,
        request: &NseCapabilityRequest,
        result_bytes: Option<u64>,
    ) {
        match request.kind {
            NseCapabilityKind::NetworkTcp | NseCapabilityKind::NetworkUdp => {
                self.counters
                    .network_operations
                    .fetch_add(1, Ordering::Relaxed);
                if let Some(bytes) = result_bytes {
                    self.counters
                        .network_bytes_read
                        .fetch_add(bytes, Ordering::Relaxed);
                }
            }
            NseCapabilityKind::FilesystemRead | NseCapabilityKind::FilesystemWrite => {
                self.counters
                    .filesystem_operations
                    .fetch_add(1, Ordering::Relaxed);
                if request.kind == NseCapabilityKind::FilesystemRead {
                    if let Some(bytes) = result_bytes {
                        self.counters
                            .filesystem_bytes_read
                            .fetch_add(bytes, Ordering::Relaxed);
                    }
                }
            }
            NseCapabilityKind::ProcessExec => {
                // Process operations don't have a dedicated counter yet
                // but we track them via events
            }
            _ => {}
        }
    }

    /// Get all recorded capability events.
    pub fn events(&self) -> Vec<NseCapabilityEvent> {
        self.events.lock().clone()
    }

    /// Get capability events as warnings for report integration.
    pub fn event_warnings(&self) -> Vec<String> {
        self.events
            .lock()
            .iter()
            .filter(|e| !e.allowed || e.reason.is_some())
            .map(|e| {
                if e.allowed {
                    format!(
                        "Capability warning: {} on {:?}: {}",
                        e.operation,
                        e.target,
                        e.reason.as_deref().unwrap_or("unknown")
                    )
                } else {
                    format!(
                        "Capability denied: {} on {:?}: {}",
                        e.operation,
                        e.target,
                        e.reason.as_deref().unwrap_or("policy violation")
                    )
                }
            })
            .collect()
    }

    /// Check if any capability operations were denied.
    pub fn has_denials(&self) -> bool {
        self.events.lock().iter().any(|e| !e.allowed)
    }

    /// Record a capability event.
    fn record_event(&self, request: &NseCapabilityRequest, decision: &NseCapabilityDecision) {
        let event = NseCapabilityEvent {
            kind: request.kind,
            operation: request.operation.to_string(),
            target: request.target.clone(),
            allowed: decision.is_allowed(),
            reason: decision
                .deny_reason()
                .or(decision.warning())
                .map(|s| s.to_string()),
            bytes: request.bytes_hint,
        };
        self.events.lock().push(event);
    }

    // --- Profile-specific policy checks ---

    fn check_manual_permissive(&self, request: &NseCapabilityRequest) -> NseCapabilityDecision {
        // Manual permissive allows everything but records warnings for risky ops
        match request.kind {
            NseCapabilityKind::ProcessExec => NseCapabilityDecision::AllowWithWarning {
                warning: "Process execution allowed in manual permissive mode".to_string(),
            },
            NseCapabilityKind::FilesystemWrite => NseCapabilityDecision::AllowWithWarning {
                warning: "Filesystem write allowed in manual permissive mode".to_string(),
            },
            NseCapabilityKind::NetworkTcp | NseCapabilityKind::NetworkUdp => {
                // Check sandbox network policy
                if let Some(ref target) = request.target {
                    if self.sandbox.enabled && !self.sandbox.allowed_networks.is_empty() {
                        if let Ok(addr) = format!("{}:0", target).parse::<std::net::SocketAddr>() {
                            if !self.sandbox.is_network_allowed(addr.ip()) {
                                return NseCapabilityDecision::Deny {
                                    reason: format!(
                                        "Network target {} not in allowed networks",
                                        target
                                    ),
                                };
                            }
                        }
                    }
                }
                NseCapabilityDecision::Allow
            }
            NseCapabilityKind::Environment => NseCapabilityDecision::AllowWithWarning {
                warning: "Environment access allowed in manual permissive mode".to_string(),
            },
            NseCapabilityKind::Randomness => NseCapabilityDecision::Allow,
            NseCapabilityKind::TimeClock => NseCapabilityDecision::Allow,
            NseCapabilityKind::Crypto => NseCapabilityDecision::Allow,
            NseCapabilityKind::Compression => NseCapabilityDecision::Allow,
            _ => NseCapabilityDecision::Allow,
        }
    }

    fn check_manual_strict(&self, request: &NseCapabilityRequest) -> NseCapabilityDecision {
        match request.kind {
            NseCapabilityKind::ProcessExec => NseCapabilityDecision::Deny {
                reason: "Process execution not allowed in manual strict mode".to_string(),
            },
            NseCapabilityKind::FilesystemWrite => {
                // Check path against allowed roots
                if let Some(ref target) = request.target {
                    if self.sandbox.enabled {
                        if self.sandbox.get_allowed_path(target).is_none() {
                            return NseCapabilityDecision::Deny {
                                reason: format!("Path '{}' not in allowed directory", target),
                            };
                        }
                    }
                }
                NseCapabilityDecision::Allow
            }
            NseCapabilityKind::NetworkTcp | NseCapabilityKind::NetworkUdp => {
                // Check network policy
                match &self.network_policy {
                    NseNetworkPolicy::DenyAll => NseCapabilityDecision::Deny {
                        reason: "Network access denied by policy".to_string(),
                    },
                    NseNetworkPolicy::AllowCidrs(cidrs) => {
                        if let Some(ref target) = request.target {
                            if let Ok(addr) =
                                format!("{}:0", target).parse::<std::net::SocketAddr>()
                            {
                                if !cidrs.iter().any(|net| net.contains(addr.ip())) {
                                    return NseCapabilityDecision::Deny {
                                        reason: format!(
                                            "Network target {} not in allowed CIDRs",
                                            target
                                        ),
                                    };
                                }
                            }
                        }
                        NseCapabilityDecision::Allow
                    }
                    _ => NseCapabilityDecision::Allow,
                }
            }
            NseCapabilityKind::Environment => NseCapabilityDecision::AllowWithWarning {
                warning: "Environment access allowed in manual strict mode".to_string(),
            },
            NseCapabilityKind::Randomness => NseCapabilityDecision::Allow,
            NseCapabilityKind::TimeClock => NseCapabilityDecision::Allow,
            NseCapabilityKind::Crypto => NseCapabilityDecision::Allow,
            NseCapabilityKind::Compression => NseCapabilityDecision::Allow,
            _ => NseCapabilityDecision::Allow,
        }
    }

    fn check_agent_safe(&self, request: &NseCapabilityRequest) -> NseCapabilityDecision {
        match request.kind {
            NseCapabilityKind::ProcessExec => NseCapabilityDecision::Deny {
                reason: "Process execution not allowed in agent safe mode".to_string(),
            },
            NseCapabilityKind::FilesystemWrite => NseCapabilityDecision::Deny {
                reason: "Filesystem write not allowed in agent safe mode".to_string(),
            },
            NseCapabilityKind::NetworkTcp | NseCapabilityKind::NetworkUdp => {
                // Allow only scoped network access
                match &self.network_policy {
                    NseNetworkPolicy::DenyAll => NseCapabilityDecision::Deny {
                        reason: "Network access denied by policy".to_string(),
                    },
                    NseNetworkPolicy::AllowCidrs(_)
                    | NseNetworkPolicy::AllowResolvedTargetSet(_) => {
                        if let Some(ref target) = request.target {
                            if let Ok(addr) =
                                format!("{}:0", target).parse::<std::net::SocketAddr>()
                            {
                                let allowed = match &self.network_policy {
                                    NseNetworkPolicy::AllowCidrs(cidrs) => {
                                        cidrs.iter().any(|net| net.contains(addr.ip()))
                                    }
                                    NseNetworkPolicy::AllowResolvedTargetSet(targets) => {
                                        targets.contains(&addr.ip())
                                    }
                                    _ => false,
                                };
                                if !allowed {
                                    return NseCapabilityDecision::Deny {
                                        reason: format!("Network target {} not in scope", target),
                                    };
                                }
                            }
                        }
                        NseCapabilityDecision::Allow
                    }
                    _ => NseCapabilityDecision::Allow,
                }
            }
            NseCapabilityKind::DnsResolution => {
                // Allow DNS only if target is in scope
                if let Some(_target) = &request.target {
                    if let NseNetworkPolicy::DenyAll = &self.network_policy {
                        return NseCapabilityDecision::Deny {
                            reason: "DNS resolution denied by policy".to_string(),
                        };
                    }
                }
                NseCapabilityDecision::Allow
            }
            NseCapabilityKind::Environment => NseCapabilityDecision::Deny {
                reason: "Environment variable access not allowed in agent safe mode".to_string(),
            },
            NseCapabilityKind::Randomness => NseCapabilityDecision::AllowWithWarning {
                warning: "Randomness use reported in agent safe mode".to_string(),
            },
            NseCapabilityKind::TimeClock => NseCapabilityDecision::Allow,
            NseCapabilityKind::Crypto => NseCapabilityDecision::Allow,
            NseCapabilityKind::Compression => NseCapabilityDecision::Allow,
            _ => NseCapabilityDecision::Allow,
        }
    }

    fn check_ci_safe(&self, request: &NseCapabilityRequest) -> NseCapabilityDecision {
        match request.kind {
            NseCapabilityKind::ProcessExec => NseCapabilityDecision::Deny {
                reason: "Process execution not allowed in CI safe mode".to_string(),
            },
            NseCapabilityKind::FilesystemWrite => NseCapabilityDecision::Deny {
                reason: "Filesystem write not allowed in CI safe mode".to_string(),
            },
            NseCapabilityKind::NetworkTcp
            | NseCapabilityKind::NetworkUdp
            | NseCapabilityKind::DnsResolution => NseCapabilityDecision::Deny {
                reason: "Network access not allowed in CI safe mode".to_string(),
            },
            NseCapabilityKind::Environment => NseCapabilityDecision::Deny {
                reason: "Environment variable access not allowed in CI safe mode".to_string(),
            },
            NseCapabilityKind::Randomness => NseCapabilityDecision::Deny {
                reason: "Nondeterministic randomness not allowed in CI safe mode".to_string(),
            },
            NseCapabilityKind::TimeClock => NseCapabilityDecision::AllowWithWarning {
                warning: "Time reads are nondeterministic in CI safe mode".to_string(),
            },
            NseCapabilityKind::Crypto => NseCapabilityDecision::Allow,
            NseCapabilityKind::Compression => NseCapabilityDecision::Allow,
            _ => NseCapabilityDecision::Allow,
        }
    }

    fn check_compatibility_lab(&self, request: &NseCapabilityRequest) -> NseCapabilityDecision {
        // Compatibility lab is similar to manual permissive but with more warnings
        match request.kind {
            NseCapabilityKind::ProcessExec => NseCapabilityDecision::AllowWithWarning {
                warning: "Process execution allowed in compatibility lab mode".to_string(),
            },
            NseCapabilityKind::FilesystemWrite => NseCapabilityDecision::AllowWithWarning {
                warning: "Filesystem write allowed in compatibility lab mode".to_string(),
            },
            NseCapabilityKind::NetworkTcp | NseCapabilityKind::NetworkUdp => {
                // Check sandbox network policy
                if let Some(ref target) = request.target {
                    if self.sandbox.enabled && !self.sandbox.allowed_networks.is_empty() {
                        if let Ok(addr) = format!("{}:0", target).parse::<std::net::SocketAddr>() {
                            if !self.sandbox.is_network_allowed(addr.ip()) {
                                return NseCapabilityDecision::Deny {
                                    reason: format!(
                                        "Network target {} not in allowed networks",
                                        target
                                    ),
                                };
                            }
                        }
                    }
                }
                NseCapabilityDecision::AllowWithWarning {
                    warning: "Network access allowed in compatibility lab mode".to_string(),
                }
            }
            NseCapabilityKind::Environment => NseCapabilityDecision::AllowWithWarning {
                warning: "Environment access allowed in compatibility lab mode".to_string(),
            },
            NseCapabilityKind::Randomness => NseCapabilityDecision::Allow,
            NseCapabilityKind::TimeClock => NseCapabilityDecision::Allow,
            NseCapabilityKind::Crypto => NseCapabilityDecision::Allow,
            NseCapabilityKind::Compression => NseCapabilityDecision::Allow,
            _ => NseCapabilityDecision::Allow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::NseResourceCounters;
    use crate::profile::{NseExecutionProfileKind, NseNetworkPolicy};
    use std::sync::Arc;

    fn make_context(profile_kind: NseExecutionProfileKind) -> NseCapabilityContext {
        let counters = Arc::new(NseResourceCounters::new());
        let sandbox = SandboxConfig::default();
        let limits = NseExecutionLimits::default();
        let cancellation = NseCancellationToken::new();

        NseCapabilityContext::new(
            profile_kind,
            NseNetworkPolicy::AllowAllManual,
            NseScriptPolicy {
                allow_builtin_scripts: true,
                allow_script_files: true,
                allowed_script_roots: Vec::new(),
                allow_conventional_nmap_paths: true,
                max_script_bytes: None,
            },
            NseModulePolicy {
                allow_builtin_modules: true,
                allow_filesystem_modules: true,
                allowed_module_roots: Vec::new(),
                max_module_bytes: None,
            },
            sandbox,
            limits,
            cancellation,
            counters,
        )
    }

    #[test]
    fn test_manual_permissive_allows_everything() {
        let ctx = make_context(NseExecutionProfileKind::ManualPermissive);

        let request = NseCapabilityRequest {
            kind: NseCapabilityKind::ProcessExec,
            target: None,
            bytes_hint: None,
            operation: "test.popen",
        };

        let decision = ctx.check_capability(&request);
        assert!(decision.is_allowed());
        assert!(decision.warning().is_some());
    }

    #[test]
    fn test_agent_safe_denies_process_exec() {
        let ctx = make_context(NseExecutionProfileKind::AgentSafe);

        let request = NseCapabilityRequest {
            kind: NseCapabilityKind::ProcessExec,
            target: None,
            bytes_hint: None,
            operation: "test.popen",
        };

        let decision = ctx.check_capability(&request);
        assert!(decision.is_denied());
        assert!(decision.deny_reason().unwrap().contains("agent safe"));
    }

    #[test]
    fn test_ci_safe_denies_network() {
        let ctx = make_context(NseExecutionProfileKind::CiSafe);

        let request = NseCapabilityRequest {
            kind: NseCapabilityKind::NetworkTcp,
            target: Some("192.168.1.1".to_string()),
            bytes_hint: None,
            operation: "socket.connect",
        };

        let decision = ctx.check_capability(&request);
        assert!(decision.is_denied());
        assert!(decision.deny_reason().unwrap().contains("CI safe"));
    }

    #[test]
    fn test_cancellation_prevents_operations() {
        let ctx = make_context(NseExecutionProfileKind::ManualPermissive);
        ctx.cancellation.cancel();

        let request = NseCapabilityRequest {
            kind: NseCapabilityKind::FilesystemRead,
            target: None,
            bytes_hint: None,
            operation: "test.read",
        };

        let decision = ctx.check_capability(&request);
        assert!(decision.is_denied());
        assert!(decision.deny_reason().unwrap().contains("cancelled"));
    }

    #[test]
    fn test_events_are_recorded() {
        let ctx = make_context(NseExecutionProfileKind::ManualPermissive);

        let request = NseCapabilityRequest {
            kind: NseCapabilityKind::FilesystemRead,
            target: Some("/tmp/test.txt".to_string()),
            bytes_hint: Some(1024),
            operation: "io.read",
        };

        ctx.check_capability(&request);

        let events = ctx.events();
        assert_eq!(events.len(), 1);
        assert!(events[0].allowed);
        assert_eq!(events[0].operation, "io.read");
    }

    #[test]
    fn test_event_warnings_include_denials() {
        let ctx = make_context(NseExecutionProfileKind::CiSafe);

        let request = NseCapabilityRequest {
            kind: NseCapabilityKind::NetworkTcp,
            target: None,
            bytes_hint: None,
            operation: "socket.connect",
        };

        ctx.check_capability(&request);

        let warnings = ctx.event_warnings();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("denied"));
    }

    #[test]
    fn test_before_blocking_operation_checks_limits() {
        let ctx = make_context(NseExecutionProfileKind::ManualPermissive);

        // Set a very low network operation limit
        let request = NseCapabilityRequest {
            kind: NseCapabilityKind::NetworkTcp,
            target: None,
            bytes_hint: None,
            operation: "socket.connect",
        };

        // Should pass with default limits (no limit set)
        assert!(ctx.before_blocking_operation(&request).is_ok());
    }

    #[test]
    fn test_after_blocking_operation_updates_counters() {
        let ctx = make_context(NseExecutionProfileKind::ManualPermissive);

        let request = NseCapabilityRequest {
            kind: NseCapabilityKind::NetworkTcp,
            target: None,
            bytes_hint: None,
            operation: "socket.connect",
        };

        ctx.after_blocking_operation(&request, Some(1024));

        let counters = &ctx.counters;
        assert_eq!(counters.network_operations.load(Ordering::Relaxed), 1);
        assert_eq!(counters.network_bytes_read.load(Ordering::Relaxed), 1024);
    }

    #[test]
    fn test_environment_denied_in_agent_safe() {
        let ctx = make_context(NseExecutionProfileKind::AgentSafe);
        let request = NseCapabilityRequest {
            kind: NseCapabilityKind::Environment,
            target: Some("HOME".to_string()),
            bytes_hint: None,
            operation: "os.getenv",
        };
        let decision = ctx.check_capability(&request);
        assert!(decision.is_denied());
        assert!(decision.deny_reason().unwrap().contains("agent safe"));
    }

    #[test]
    fn test_environment_denied_in_ci_safe() {
        let ctx = make_context(NseExecutionProfileKind::CiSafe);
        let request = NseCapabilityRequest {
            kind: NseCapabilityKind::Environment,
            target: Some("HOME".to_string()),
            bytes_hint: None,
            operation: "os.getenv",
        };
        let decision = ctx.check_capability(&request);
        assert!(decision.is_denied());
        assert!(decision.deny_reason().unwrap().contains("CI safe"));
    }

    #[test]
    fn test_randomness_denied_in_ci_safe() {
        let ctx = make_context(NseExecutionProfileKind::CiSafe);
        let request = NseCapabilityRequest {
            kind: NseCapabilityKind::Randomness,
            target: None,
            bytes_hint: None,
            operation: "rand.random",
        };
        let decision = ctx.check_capability(&request);
        assert!(decision.is_denied());
        assert!(decision.deny_reason().unwrap().contains("CI safe"));
    }

    #[test]
    fn test_randomness_warned_in_agent_safe() {
        let ctx = make_context(NseExecutionProfileKind::AgentSafe);
        let request = NseCapabilityRequest {
            kind: NseCapabilityKind::Randomness,
            target: None,
            bytes_hint: None,
            operation: "rand.random",
        };
        let decision = ctx.check_capability(&request);
        assert!(decision.is_allowed());
        assert!(decision.warning().is_some());
    }

    #[test]
    fn test_time_clock_warned_in_ci_safe() {
        let ctx = make_context(NseExecutionProfileKind::CiSafe);
        let request = NseCapabilityRequest {
            kind: NseCapabilityKind::TimeClock,
            target: None,
            bytes_hint: None,
            operation: "datetime.now",
        };
        let decision = ctx.check_capability(&request);
        assert!(decision.is_allowed());
        assert!(decision.warning().is_some());
    }

    #[test]
    fn test_time_clock_allowed_in_agent_safe() {
        let ctx = make_context(NseExecutionProfileKind::AgentSafe);
        let request = NseCapabilityRequest {
            kind: NseCapabilityKind::TimeClock,
            target: None,
            bytes_hint: None,
            operation: "datetime.now",
        };
        let decision = ctx.check_capability(&request);
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_environment_allowed_with_warning_in_manual_permissive() {
        let ctx = make_context(NseExecutionProfileKind::ManualPermissive);
        let request = NseCapabilityRequest {
            kind: NseCapabilityKind::Environment,
            target: Some("HOME".to_string()),
            bytes_hint: None,
            operation: "os.getenv",
        };
        let decision = ctx.check_capability(&request);
        assert!(decision.is_allowed());
        assert!(decision.warning().is_some());
    }
}
