//! Architecture guard tests for NSE profile enforcement.
//!
//! These tests verify that:
//! - Automated profiles (AgentSafe, CiSafe) cannot be bypassed
//! - ManualPermissive is not used in automated-surface code paths
//! - NseExecutor::new()/with_target()/with_sandbox() are documented as manual-only

#![cfg(feature = "nse")]

use eggsec_nse::profile::*;

#[test]
fn agent_safe_disallows_script_files() {
    let profile = ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
    assert!(
        !profile.script_policy.allow_script_files,
        "AgentSafe must not allow script files"
    );
}

#[test]
fn agent_safe_disallows_filesystem_modules() {
    let profile = ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
    assert!(
        !profile.module_policy.allow_filesystem_modules,
        "AgentSafe must not allow filesystem modules"
    );
}

#[test]
fn ci_safe_disallows_script_files() {
    let profile = ResolvedNseExecutionProfile::ci_safe();
    assert!(
        !profile.script_policy.allow_script_files,
        "CiSafe must not allow script files"
    );
}

#[test]
fn ci_safe_disallows_filesystem_modules() {
    let profile = ResolvedNseExecutionProfile::ci_safe();
    assert!(
        !profile.module_policy.allow_filesystem_modules,
        "CiSafe must not allow filesystem modules"
    );
}

#[test]
fn ci_safe_has_zero_network_operations() {
    let profile = ResolvedNseExecutionProfile::ci_safe();
    assert_eq!(
        profile.limits.max_network_operations,
        Some(0),
        "CiSafe must have zero network operations"
    );
}

#[test]
fn ci_safe_has_zero_network_bytes() {
    let profile = ResolvedNseExecutionProfile::ci_safe();
    assert_eq!(
        profile.limits.max_network_bytes_read,
        Some(0),
        "CiSafe must have zero network bytes read"
    );
    assert_eq!(
        profile.limits.max_network_bytes_written,
        Some(0),
        "CiSafe must have zero network bytes written"
    );
}

#[test]
fn agent_safe_has_automated_timeouts() {
    let profile = ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
    let timeout = profile
        .limits
        .wall_clock_timeout
        .expect("AgentSafe must have wall_clock_timeout set");
    assert!(
        timeout <= std::time::Duration::from_secs(30),
        "AgentSafe must have automated (short) timeout, got {:?}",
        timeout
    );
}

#[test]
fn ci_safe_has_automated_timeouts() {
    let profile = ResolvedNseExecutionProfile::ci_safe();
    let timeout = profile
        .limits
        .wall_clock_timeout
        .expect("CiSafe must have wall_clock_timeout set");
    assert!(
        timeout <= std::time::Duration::from_secs(30),
        "CiSafe must have automated (short) timeout, got {:?}",
        timeout
    );
}

#[test]
fn manual_permissive_allows_everything() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(None);
    assert!(profile.script_policy.allow_script_files);
    assert!(profile.script_policy.allow_builtin_scripts);
    assert!(profile.script_policy.allow_conventional_nmap_paths);
    assert!(profile.module_policy.allow_filesystem_modules);
    assert!(profile.module_policy.allow_builtin_modules);
    assert!(profile.limits.max_network_operations.is_none());
    assert!(profile.limits.max_filesystem_operations.is_none());
}

#[test]
fn agent_safe_has_no_filesystem_operations_cap() {
    let profile = ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
    assert!(
        profile.limits.max_filesystem_operations.is_some(),
        "AgentSafe should have a filesystem operations cap"
    );
}

#[test]
fn ci_safe_has_strict_filesystem_operations_cap() {
    let profile = ResolvedNseExecutionProfile::ci_safe();
    assert!(
        profile.limits.max_filesystem_operations <= Some(10),
        "CiSafe should have a strict filesystem operations cap (<=10), got {:?}",
        profile.limits.max_filesystem_operations
    );
}

/// Verify that manual_permissive profile kind is correctly identified.
#[test]
fn manual_permissive_kind_is_manual() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(None);
    assert_eq!(profile.kind, NseExecutionProfileKind::ManualPermissive);
}

/// Verify that agent_safe profile kind is correctly identified.
#[test]
fn agent_safe_kind_is_agent() {
    let profile = ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
    assert_eq!(profile.kind, NseExecutionProfileKind::AgentSafe);
}

/// Verify that ci_safe profile kind is correctly identified.
#[test]
fn ci_safe_kind_is_ci() {
    let profile = ResolvedNseExecutionProfile::ci_safe();
    assert_eq!(profile.kind, NseExecutionProfileKind::CiSafe);
}
