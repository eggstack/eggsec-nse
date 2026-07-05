//! NSE helper wrappers routed through capability context.
//!
//! Each wrapper checks the capability context before performing the operation,
//! records the event, and returns the result or an error.
//!
//! This module is the pilot for Milestone 3 Phase 02. Future phases will
//! migrate additional helpers (filesystem, network, process, DNS) to use
//! these wrappers.

use crate::capabilities::{
    NseCapabilityContext, NseCapabilityDecision, NseCapabilityKind, NseCapabilityRequest,
};

/// Check a time/clock capability and return the decision.
///
/// Callers should check `decision.is_allowed()` before proceeding.
/// If denied, return the denial reason to Lua as an error.
pub fn check_time_clock(
    ctx: &NseCapabilityContext,
    operation: &'static str,
) -> NseCapabilityDecision {
    ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::TimeClock,
        target: None,
        bytes_hint: None,
        operation,
    })
}

/// Check a filesystem read capability and return the decision.
pub fn check_fs_read(
    ctx: &NseCapabilityContext,
    path: &str,
    operation: &'static str,
) -> NseCapabilityDecision {
    ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::FilesystemRead,
        target: Some(path.to_string()),
        bytes_hint: None,
        operation,
    })
}

/// Check a filesystem write capability and return the decision.
pub fn check_fs_write(
    ctx: &NseCapabilityContext,
    path: &str,
    operation: &'static str,
) -> NseCapabilityDecision {
    ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::FilesystemWrite,
        target: Some(path.to_string()),
        bytes_hint: None,
        operation,
    })
}

/// Check a network TCP capability and return the decision.
pub fn check_network_tcp(
    ctx: &NseCapabilityContext,
    host: &str,
    operation: &'static str,
) -> NseCapabilityDecision {
    ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::NetworkTcp,
        target: Some(host.to_string()),
        bytes_hint: None,
        operation,
    })
}

/// Check a process execution capability and return the decision.
pub fn check_process_exec(
    ctx: &NseCapabilityContext,
    command: &str,
    operation: &'static str,
) -> NseCapabilityDecision {
    ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::ProcessExec,
        target: Some(command.to_string()),
        bytes_hint: None,
        operation,
    })
}

/// Check a DNS resolution capability and return the decision.
pub fn check_dns(
    ctx: &NseCapabilityContext,
    hostname: &str,
    operation: &'static str,
) -> NseCapabilityDecision {
    ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::DnsResolution,
        target: Some(hostname.to_string()),
        bytes_hint: None,
        operation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{NseCancellationToken, NseResourceCounters};
    use crate::profile::{
        NseExecutionProfileKind, NseModulePolicy, NseNetworkPolicy, NseScriptPolicy,
    };
    use crate::SandboxConfig;
    use std::sync::Arc;

    fn make_ctx(profile: NseExecutionProfileKind) -> NseCapabilityContext {
        let counters = Arc::new(NseResourceCounters::new());
        NseCapabilityContext::new(
            profile,
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
            SandboxConfig::default(),
            crate::limits::NseExecutionLimits::default(),
            NseCancellationToken::new(),
            counters,
        )
    }

    #[test]
    fn test_time_clock_allowed_in_all_profiles() {
        for profile in [
            NseExecutionProfileKind::ManualPermissive,
            NseExecutionProfileKind::ManualStrict,
            NseExecutionProfileKind::AgentSafe,
            NseExecutionProfileKind::CiSafe,
            NseExecutionProfileKind::CompatibilityLab,
        ] {
            let ctx = make_ctx(profile);
            let decision = check_time_clock(&ctx, "os.clock");
            assert!(
                decision.is_allowed(),
                "time clock should be allowed in {:?}",
                profile
            );
        }
    }

    #[test]
    fn test_process_exec_denied_in_agent_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::AgentSafe);
        let decision = check_process_exec(&ctx, "id -u", "nmap.is_admin");
        assert!(decision.is_denied());
    }

    #[test]
    fn test_process_exec_denied_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let decision = check_process_exec(&ctx, "id -u", "nmap.is_admin");
        assert!(decision.is_denied());
    }

    #[test]
    fn test_process_exec_allowed_with_warning_in_manual() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let decision = check_process_exec(&ctx, "id -u", "nmap.is_admin");
        assert!(decision.is_allowed());
        assert!(decision.warning().is_some());
    }

    #[test]
    fn test_network_tcp_denied_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let decision = check_network_tcp(&ctx, "192.168.1.1", "socket.connect");
        assert!(decision.is_denied());
    }

    #[test]
    fn test_fs_read_allowed_in_manual() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let decision = check_fs_read(&ctx, "/tmp/test.txt", "io.read");
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_fs_write_denied_in_agent_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::AgentSafe);
        let decision = check_fs_write(&ctx, "/tmp/test.txt", "io.write");
        assert!(decision.is_denied());
    }

    #[test]
    fn test_dns_denied_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let decision = check_dns(&ctx, "example.com", "dns.resolve");
        assert!(decision.is_denied());
    }
}
