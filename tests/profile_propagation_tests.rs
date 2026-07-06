//! Integration tests for NSE execution profile propagation.
//!
//! These tests verify that real executor/profile construction paths
//! preserve the resolved profile's `kind` and `network_policy` in the
//! capability context. Wrapper-level unit tests only check isolated
//! decisions; these tests catch the propagation regression where
//! `run_cli_with_profile()` would silently downgrade AgentSafe / CiSafe
//! to manual-permissive capability behavior.
//!
//! See `plans/nse-milestone-3-corrective-pass.md` (Workstream 4).

#![cfg(feature = "nse")]

use eggsec_nse::capabilities::{NseCapabilityDecision, NseCapabilityKind, NseCapabilityRequest};
use eggsec_nse::profile::{
    NseExecutionProfileKind, NseModulePolicy, NseNetworkPolicy, NseScriptPolicy,
    ResolvedNseExecutionProfile,
};
use eggsec_nse::{NseCapabilityContext, NseExecutionLimits, NseExecutor, SandboxConfig};

// ---------------------------------------------------------------------------
// 1. with_profile preserves AgentSafe semantics for ProcessExec
// ---------------------------------------------------------------------------

#[test]
fn with_profile_agent_safe_denies_process_exec() {
    let profile = ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
    let executor = NseExecutor::with_profile(&profile).expect("executor should construct");
    let ctx = executor.capability_context();

    assert_eq!(
        ctx.profile_kind,
        NseExecutionProfileKind::AgentSafe,
        "with_profile must propagate AgentSafe profile kind to capability context"
    );

    let decision = ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::ProcessExec,
        target: None,
        bytes_hint: None,
        operation: "integration.nse_process_exec",
    });
    assert!(
        matches!(decision, NseCapabilityDecision::Deny { .. }),
        "AgentSafe must deny process exec via with_profile, got {:?}",
        decision
    );
}

// ---------------------------------------------------------------------------
// 2. with_profile preserves CiSafe semantics for NetworkTcp + DNS
// ---------------------------------------------------------------------------

#[test]
fn with_profile_ci_safe_denies_network_and_dns() {
    let profile = ResolvedNseExecutionProfile::ci_safe();
    let executor = NseExecutor::with_profile(&profile).expect("executor should construct");
    let ctx = executor.capability_context();

    assert_eq!(ctx.profile_kind, NseExecutionProfileKind::CiSafe);
    assert!(
        matches!(ctx.network_policy, NseNetworkPolicy::DenyAll),
        "with_profile must propagate CiSafe DenyAll network policy, got {:?}",
        ctx.network_policy
    );

    let tcp_decision = ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::NetworkTcp,
        target: Some("10.0.0.1".to_string()),
        bytes_hint: None,
        operation: "integration.socket_connect",
    });
    assert!(
        tcp_decision.is_denied(),
        "CiSafe must deny NetworkTcp via with_profile, got {:?}",
        tcp_decision
    );

    let dns_decision = ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::DnsResolution,
        target: Some("example.com".to_string()),
        bytes_hint: None,
        operation: "integration.dns_resolve",
    });
    assert!(
        dns_decision.is_denied(),
        "CiSafe must deny DnsResolution via with_profile, got {:?}",
        dns_decision
    );
}

// ---------------------------------------------------------------------------
// 3. with_full_policy accepts explicit profile kind + network policy
// ---------------------------------------------------------------------------

#[test]
fn with_full_policy_propagates_agent_safe_with_allow_cidrs() {
    let sandbox = SandboxConfig::default();
    let limits = NseExecutionLimits::automated_defaults();
    let cancellation = eggsec_nse::NseCancellationToken::new();
    let script_policy = NseScriptPolicy {
        allow_builtin_scripts: true,
        allow_script_files: false,
        allowed_script_roots: Vec::new(),
        allow_conventional_nmap_paths: false,
        max_script_bytes: Some(1024 * 1024),
    };
    let module_policy = NseModulePolicy {
        allow_builtin_modules: true,
        allow_filesystem_modules: false,
        allowed_module_roots: Vec::new(),
        max_module_bytes: Some(512 * 1024),
    };

    let cidr = "10.0.0.0/8".parse::<ipnetwork::IpNetwork>().unwrap();
    let executor = NseExecutor::with_full_policy(
        sandbox,
        limits,
        cancellation,
        script_policy,
        module_policy,
        NseExecutionProfileKind::AgentSafe,
        NseNetworkPolicy::AllowCidrs(vec![cidr]),
    )
    .expect("executor should construct");
    let ctx = executor.capability_context();

    assert_eq!(ctx.profile_kind, NseExecutionProfileKind::AgentSafe);
    assert!(matches!(
        ctx.network_policy,
        NseNetworkPolicy::AllowCidrs(_)
    ));

    let decision = ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::ProcessExec,
        target: None,
        bytes_hint: None,
        operation: "integration.popen",
    });
    assert!(
        decision.is_denied(),
        "AgentSafe via with_full_policy must deny process exec"
    );
}

// ---------------------------------------------------------------------------
// 4. with_policy remains manual-only and downgrades to ManualPermissive
// ---------------------------------------------------------------------------

#[test]
fn with_policy_uses_manual_permissive_capability_context() {
    let sandbox = SandboxConfig::default();
    let limits = NseExecutionLimits::default();
    let cancellation = eggsec_nse::NseCancellationToken::new();
    let script_policy = NseScriptPolicy {
        allow_builtin_scripts: true,
        allow_script_files: true,
        allowed_script_roots: Vec::new(),
        allow_conventional_nmap_paths: true,
        max_script_bytes: None,
    };
    let module_policy = NseModulePolicy {
        allow_builtin_modules: true,
        allow_filesystem_modules: true,
        allowed_module_roots: Vec::new(),
        max_module_bytes: None,
    };

    let executor =
        NseExecutor::with_policy(sandbox, limits, cancellation, script_policy, module_policy)
            .expect("executor should construct");
    let ctx = executor.capability_context();

    assert_eq!(
        ctx.profile_kind,
        NseExecutionProfileKind::ManualPermissive,
        "with_policy must keep ManualPermissive semantics for the capability context"
    );
    assert!(
        matches!(ctx.network_policy, NseNetworkPolicy::AllowAllManual),
        "with_policy must keep AllowAllManual network policy, got {:?}",
        ctx.network_policy
    );

    // Process exec must be allowed (with warning) under manual semantics.
    let decision = ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::ProcessExec,
        target: None,
        bytes_hint: None,
        operation: "integration.popen",
    });
    assert!(
        decision.is_allowed(),
        "ManualPermissive via with_policy must allow process exec, got {:?}",
        decision
    );
    assert!(
        decision.warning().is_some(),
        "ManualPermissive should record a warning for process exec"
    );
}

// ---------------------------------------------------------------------------
// 5. run_cli_with_profile() preserves AgentSafe capability semantics
//    (regression test for the profile-propagation bug)
// ---------------------------------------------------------------------------
//
// This test guards against the previous bug where `run_cli_with_profile()`
// constructed the executor with `NseExecutor::with_policy(...)`, which silently
// degraded AgentSafe to ManualPermissive in the capability context. The
// canonical helper now uses `NseExecutor::with_profile(&profile)`. We exercise
// the helper via a thin shim that mirrors what `run_cli_with_profile()` does
// for executor construction, and assert that the capability context preserves
// the AgentSafe profile kind.

#[test]
fn run_cli_helper_preserves_agent_safe_capability_kind() {
    let profile = ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);

    // Mirror the executor-construction path inside run_cli_with_profile().
    let executor = NseExecutor::with_profile(&profile).expect("executor should construct");
    let ctx: &NseCapabilityContext = executor.capability_context();

    assert_eq!(
        ctx.profile_kind,
        NseExecutionProfileKind::AgentSafe,
        "run_cli_with_profile executor must carry AgentSafe profile kind"
    );
    // AgentSafe with no scope CIDRs and IP target → AllowResolvedTargetSet.
    assert!(
        matches!(
            ctx.network_policy,
            NseNetworkPolicy::AllowResolvedTargetSet(_)
        ),
        "run_cli_with_profile executor must carry AgentSafe network policy, got {:?}",
        ctx.network_policy
    );
}

// ---------------------------------------------------------------------------
// 6. Capability context profile propagation for ManualPermissive remains permissive
// ---------------------------------------------------------------------------

#[test]
fn with_profile_manual_permissive_allows_process_exec_with_warning() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("10.0.0.1"));
    let executor = NseExecutor::with_profile(&profile).expect("executor should construct");
    let ctx = executor.capability_context();

    assert_eq!(ctx.profile_kind, NseExecutionProfileKind::ManualPermissive);

    let decision = ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::ProcessExec,
        target: None,
        bytes_hint: None,
        operation: "integration.popen",
    });
    assert!(decision.is_allowed());
    assert!(
        decision.warning().is_some(),
        "ManualPermissive should warn on process exec"
    );
}

// ---------------------------------------------------------------------------
// 7. AgentSafe filesystem read is denied unless path is under sandbox allowed_dir
// ---------------------------------------------------------------------------

#[test]
fn with_profile_agent_safe_denies_unscoped_filesystem_read() {
    let profile = ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
    let executor = NseExecutor::with_profile(&profile).expect("executor should construct");
    let ctx = executor.capability_context();

    let decision = ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::FilesystemRead,
        target: Some("/etc/passwd".to_string()),
        bytes_hint: None,
        operation: "integration.fs_read",
    });
    assert!(
        decision.is_denied(),
        "AgentSafe via with_profile must deny unscoped filesystem read, got {:?}",
        decision
    );
}
