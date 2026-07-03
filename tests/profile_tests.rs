//! Tests for NSE execution profiles.
//!
//! Covers profile construction, policy enforcement, network policy resolution,
//! sandbox warnings, script path restrictions, and display formatting.

use eggsec_nse::profile::*;
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// 1. AgentSafe rejects arbitrary script files
// ---------------------------------------------------------------------------

#[test]
fn agent_safe_rejects_arbitrary_script_files() {
    let profile = ResolvedNseExecutionProfile::agent_safe("192.168.1.1", &[]);
    assert!(
        !profile.script_policy.allow_script_files,
        "AgentSafe must not allow arbitrary script files"
    );
    assert!(profile.script_policy.allowed_script_roots.is_empty());
}

// ---------------------------------------------------------------------------
// 2. AgentSafe rejects empty network allowlist (deny-all semantics)
// ---------------------------------------------------------------------------

#[test]
fn agent_safe_empty_scope_cidrs_results_in_deny_all() {
    let profile = ResolvedNseExecutionProfile::agent_safe("example.com", &[]);
    assert!(
        matches!(profile.network_policy, NseNetworkPolicy::DenyAll),
        "AgentSafe with no scope CIDRs and non-IP target must yield DenyAll, got {:?}",
        profile.network_policy
    );
}

// ---------------------------------------------------------------------------
// 3. AgentSafe allows an explicitly scoped target
// ---------------------------------------------------------------------------

#[test]
fn agent_safe_with_scope_cidrs_allows_matching_cidr() {
    let cidr = IpNetwork::from_str("10.0.0.0/8").unwrap();
    let profile = ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[cidr]);
    match &profile.network_policy {
        NseNetworkPolicy::AllowCidrs(cidrs) => {
            assert_eq!(cidrs.len(), 1);
            assert_eq!(cidrs[0], cidr);
        }
        other => panic!("Expected AllowCidrs, got {:?}", other),
    }
}

#[test]
fn agent_safe_with_ip_target_resolves_to_target_set() {
    let profile = ResolvedNseExecutionProfile::agent_safe("10.0.0.42", &[]);
    match &profile.network_policy {
        NseNetworkPolicy::AllowResolvedTargetSet(ips) => {
            assert_eq!(ips.len(), 1);
            assert_eq!(ips[0], IpAddr::from_str("10.0.0.42").unwrap());
        }
        other => panic!("Expected AllowResolvedTargetSet, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 4. ManualPermissive preserves existing manual compatibility behavior
// ---------------------------------------------------------------------------

#[test]
fn manual_permissive_allows_all_scripts_and_modules() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(None);
    assert!(profile.script_policy.allow_builtin_scripts);
    assert!(profile.script_policy.allow_script_files);
    assert!(profile.script_policy.allow_conventional_nmap_paths);
    assert!(profile.script_policy.allowed_script_roots.is_empty());
    assert!(profile.script_policy.max_script_bytes.is_none());

    assert!(profile.module_policy.allow_builtin_modules);
    assert!(profile.module_policy.allow_filesystem_modules);
    assert!(profile.module_policy.allowed_module_roots.is_empty());
    assert!(profile.module_policy.max_module_bytes.is_none());
}

#[test]
fn manual_permissive_no_target_yields_allow_all_manual() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(None);
    assert!(
        matches!(profile.network_policy, NseNetworkPolicy::AllowAllManual),
        "ManualPermissive with no target must yield AllowAllManual, got {:?}",
        profile.network_policy
    );
}

#[test]
fn manual_permissive_uses_manual_execution_limits() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(None);
    // manual_defaults: 120s timeout, 100M instructions, no network/filesystem caps
    assert_eq!(
        profile.limits.wall_clock_timeout,
        Some(std::time::Duration::from_secs(120))
    );
    assert_eq!(profile.limits.lua_instruction_budget, Some(100_000_000));
    assert!(profile.limits.max_network_operations.is_none());
    assert!(profile.limits.max_filesystem_operations.is_none());
}

// ---------------------------------------------------------------------------
// 5. ManualStrict rejects traversal/out-of-root script paths (policy, not runtime)
// ---------------------------------------------------------------------------

#[test]
fn manual_strict_restricts_script_roots() {
    let profile = ResolvedNseExecutionProfile::manual_strict(Some("10.0.0.1"), &[]);
    // Only /tmp/eggsec-nse is allowed
    assert_eq!(profile.script_policy.allowed_script_roots.len(), 1);
    assert_eq!(
        profile.script_policy.allowed_script_roots[0],
        PathBuf::from("/tmp/eggsec-nse")
    );
    // Conventional nmap paths are disallowed
    assert!(!profile.script_policy.allow_conventional_nmap_paths);
}

#[test]
fn manual_strict_has_script_size_cap() {
    let profile = ResolvedNseExecutionProfile::manual_strict(Some("10.0.0.1"), &[]);
    assert_eq!(
        profile.script_policy.max_script_bytes,
        Some(5 * 1024 * 1024)
    );
}

// ---------------------------------------------------------------------------
// 6. CLI handler selects a profile and does not bypass profile construction
// ---------------------------------------------------------------------------

#[test]
fn manual_permissive_returns_correct_kind() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(None);
    assert_eq!(profile.kind, NseExecutionProfileKind::ManualPermissive);
}

#[test]
fn each_constructor_returns_matching_kind() {
    let cidr = IpNetwork::from_str("192.168.0.0/16").unwrap();

    let p = ResolvedNseExecutionProfile::manual_permissive(Some("1.2.3.4"));
    assert_eq!(p.kind, NseExecutionProfileKind::ManualPermissive);

    let p = ResolvedNseExecutionProfile::manual_strict(Some("1.2.3.4"), &[cidr]);
    assert_eq!(p.kind, NseExecutionProfileKind::ManualStrict);

    let p = ResolvedNseExecutionProfile::agent_safe("1.2.3.4", &[cidr]);
    assert_eq!(p.kind, NseExecutionProfileKind::AgentSafe);

    let p = ResolvedNseExecutionProfile::ci_safe();
    assert_eq!(p.kind, NseExecutionProfileKind::CiSafe);

    let p = ResolvedNseExecutionProfile::compatibility_lab(Some("1.2.3.4"));
    assert_eq!(p.kind, NseExecutionProfileKind::CompatibilityLab);
}

// ---------------------------------------------------------------------------
// 7. Help text / operation descriptor agrees on target requirements
// ---------------------------------------------------------------------------

#[test]
fn manual_strict_requires_scope_for_network() {
    let profile = ResolvedNseExecutionProfile::manual_strict(None, &[]);
    // Without scope CIDRs and no IP target, network is denied
    assert!(
        matches!(profile.network_policy, NseNetworkPolicy::DenyAll),
        "ManualStrict without scope or IP target should deny network"
    );
}

#[test]
fn agent_safe_requires_explicit_target_or_scope() {
    // Non-IP target, no scope -> DenyAll
    let profile = ResolvedNseExecutionProfile::agent_safe("example.com", &[]);
    assert!(matches!(profile.network_policy, NseNetworkPolicy::DenyAll));

    // IP target, no scope -> AllowResolvedTargetSet
    let profile = ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
    assert!(matches!(
        profile.network_policy,
        NseNetworkPolicy::AllowResolvedTargetSet(_)
    ));
}

// ---------------------------------------------------------------------------
// 8. CiSafe has zero network operations allowed
// ---------------------------------------------------------------------------

#[test]
fn ci_safe_zero_network_operations() {
    let profile = ResolvedNseExecutionProfile::ci_safe();
    assert_eq!(profile.limits.max_network_operations, Some(0));
    assert_eq!(profile.limits.max_network_bytes_read, Some(0));
    assert_eq!(profile.limits.max_network_bytes_written, Some(0));
}

#[test]
fn ci_safe_network_policy_is_deny_all() {
    let profile = ResolvedNseExecutionProfile::ci_safe();
    assert!(
        matches!(profile.network_policy, NseNetworkPolicy::DenyAll),
        "CiSafe must always deny all network access"
    );
}

#[test]
fn ci_safe_rejects_script_files() {
    let profile = ResolvedNseExecutionProfile::ci_safe();
    assert!(!profile.script_policy.allow_script_files);
    assert!(!profile.script_policy.allow_conventional_nmap_paths);
    assert!(!profile.module_policy.allow_filesystem_modules);
}

#[test]
fn ci_safe_has_reduced_limits() {
    let profile = ResolvedNseExecutionProfile::ci_safe();
    assert_eq!(
        profile.limits.wall_clock_timeout,
        Some(std::time::Duration::from_secs(5))
    );
    assert_eq!(profile.limits.lua_instruction_budget, Some(1_000_000));
    assert_eq!(profile.limits.max_output_bytes, Some(512 * 1024));
    assert_eq!(profile.limits.max_script_bytes, Some(256 * 1024));
    assert_eq!(profile.limits.max_filesystem_operations, Some(10));
}

// ---------------------------------------------------------------------------
// 9. CompatibilityLab includes conventional Nmap paths
// ---------------------------------------------------------------------------

#[test]
fn compatibility_lab_includes_nmap_script_paths() {
    let profile = ResolvedNseExecutionProfile::compatibility_lab(None);
    let roots: Vec<_> = profile
        .script_policy
        .allowed_script_roots
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    assert!(
        roots.iter().any(|r| r.contains("/usr/share/nmap/scripts")),
        "CompatibilityLab must include /usr/share/nmap/scripts, got: {:?}",
        roots
    );
    assert!(
        roots
            .iter()
            .any(|r| r.contains("/usr/local/share/nmap/scripts")),
        "CompatibilityLab must include /usr/local/share/nmap/scripts, got: {:?}",
        roots
    );
}

#[test]
fn compatibility_lab_includes_nmap_module_paths() {
    let profile = ResolvedNseExecutionProfile::compatibility_lab(None);
    let roots: Vec<_> = profile
        .module_policy
        .allowed_module_roots
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    assert!(
        roots.iter().any(|r| r.contains("/usr/share/nmap/nselib")),
        "CompatibilityLab must include /usr/share/nmap/nselib, got: {:?}",
        roots
    );
    assert!(
        roots
            .iter()
            .any(|r| r.contains("/usr/local/share/nmap/nselib")),
        "CompatibilityLab must include /usr/local/share/nmap/nselib, got: {:?}",
        roots
    );
}

#[test]
fn compatibility_lab_allows_conventional_nmap_paths() {
    let profile = ResolvedNseExecutionProfile::compatibility_lab(None);
    assert!(profile.script_policy.allow_conventional_nmap_paths);
    assert!(profile.script_policy.allow_script_files);
    assert!(profile.module_policy.allow_filesystem_modules);
}

// ---------------------------------------------------------------------------
// 10. Profile kind Display produces expected strings
// ---------------------------------------------------------------------------

#[test]
fn profile_kind_display_strings() {
    assert_eq!(
        NseExecutionProfileKind::ManualPermissive.to_string(),
        "manual-permissive"
    );
    assert_eq!(
        NseExecutionProfileKind::ManualStrict.to_string(),
        "manual-strict"
    );
    assert_eq!(NseExecutionProfileKind::AgentSafe.to_string(), "agent-safe");
    assert_eq!(NseExecutionProfileKind::CiSafe.to_string(), "ci-safe");
    assert_eq!(
        NseExecutionProfileKind::CompatibilityLab.to_string(),
        "compatibility-lab"
    );
}

// ---------------------------------------------------------------------------
// 11. Sandbox warnings appear when sandbox feature is not compiled
// ---------------------------------------------------------------------------

#[test]
fn sandbox_warning_present_when_feature_disabled() {
    // Build without sandbox feature (default) -> warnings should appear
    let profile = ResolvedNseExecutionProfile::manual_permissive(None);
    let has_sandbox_warning = profile
        .warnings
        .iter()
        .any(|w| w.contains("sandbox feature not compiled"));
    // In default builds this should be true; if sandbox feature is enabled, it's false
    // Both are valid — just verify the warning logic is consistent
    if cfg!(feature = "sandbox") {
        assert!(
            !has_sandbox_warning,
            "Sandbox warning should NOT appear when sandbox feature is compiled"
        );
    } else {
        assert!(
            has_sandbox_warning,
            "Sandbox warning MUST appear when sandbox feature is not compiled"
        );
    }
}

#[test]
fn agent_safe_always_has_sandbox_warning_when_feature_disabled() {
    let profile = ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
    let has_sandbox_warning = profile
        .warnings
        .iter()
        .any(|w| w.contains("sandbox feature not compiled"));
    if cfg!(feature = "sandbox") {
        assert!(!has_sandbox_warning);
    } else {
        assert!(has_sandbox_warning);
    }
}

#[test]
fn ci_safe_always_has_sandbox_warning_when_feature_disabled() {
    let profile = ResolvedNseExecutionProfile::ci_safe();
    let has_sandbox_warning = profile
        .warnings
        .iter()
        .any(|w| w.contains("sandbox feature not compiled"));
    if cfg!(feature = "sandbox") {
        assert!(!has_sandbox_warning);
    } else {
        assert!(has_sandbox_warning);
    }
}

#[test]
fn compatibility_lab_has_not_agent_safe_warning() {
    let profile = ResolvedNseExecutionProfile::compatibility_lab(None);
    let has_not_agent_safe = profile
        .warnings
        .iter()
        .any(|w| w.contains("not agent-safe"));
    assert!(
        has_not_agent_safe,
        "CompatibilityLab must warn that it is not agent-safe"
    );
}

// ---------------------------------------------------------------------------
// 12. agent_safe with no scope and non-IP target results in DenyAll
// ---------------------------------------------------------------------------

#[test]
fn agent_safe_hostname_only_yields_deny_all() {
    let profile = ResolvedNseExecutionProfile::agent_safe("example.com", &[]);
    assert!(matches!(profile.network_policy, NseNetworkPolicy::DenyAll));
}

#[test]
fn agent_safe_empty_scope_cidrs_and_hostname_yields_deny_all() {
    let profile = ResolvedNseExecutionProfile::agent_safe("scanme.nmap.org", &[]);
    assert!(matches!(profile.network_policy, NseNetworkPolicy::DenyAll));
}

// ---------------------------------------------------------------------------
// 13. manual_permissive with IP target results in AllowResolvedTargetSet
// ---------------------------------------------------------------------------

#[test]
fn manual_permissive_ip_target_yields_allow_resolved_target_set() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("10.0.0.1"));
    match &profile.network_policy {
        NseNetworkPolicy::AllowResolvedTargetSet(ips) => {
            assert_eq!(ips.len(), 1);
            assert_eq!(ips[0], IpAddr::from_str("10.0.0.1").unwrap());
        }
        other => panic!("Expected AllowResolvedTargetSet, got {:?}", other),
    }
}

#[test]
fn manual_permissive_ipv6_target_yields_allow_resolved_target_set() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("::1"));
    match &profile.network_policy {
        NseNetworkPolicy::AllowResolvedTargetSet(ips) => {
            assert_eq!(ips.len(), 1);
            assert_eq!(ips[0], IpAddr::from_str("::1").unwrap());
        }
        other => panic!("Expected AllowResolvedTargetSet, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 14. manual_strict with scope CIDRs results in AllowCidrs
// ---------------------------------------------------------------------------

#[test]
fn manual_strict_single_cidr_yields_allow_cidrs() {
    let cidr = IpNetwork::from_str("10.0.0.0/8").unwrap();
    let profile = ResolvedNseExecutionProfile::manual_strict(Some("10.0.0.1"), &[cidr]);
    match &profile.network_policy {
        NseNetworkPolicy::AllowCidrs(cidrs) => {
            assert_eq!(cidrs.len(), 1);
            assert_eq!(cidrs[0], cidr);
        }
        other => panic!("Expected AllowCidrs, got {:?}", other),
    }
}

#[test]
fn manual_strict_multiple_cidrs_yields_allow_cidrs() {
    let cidr1 = IpNetwork::from_str("10.0.0.0/8").unwrap();
    let cidr2 = IpNetwork::from_str("192.168.0.0/16").unwrap();
    let profile = ResolvedNseExecutionProfile::manual_strict(Some("10.0.0.1"), &[cidr1, cidr2]);
    match &profile.network_policy {
        NseNetworkPolicy::AllowCidrs(cidrs) => {
            assert_eq!(cidrs.len(), 2);
            assert!(cidrs.contains(&cidr1));
            assert!(cidrs.contains(&cidr2));
        }
        other => panic!("Expected AllowCidrs, got {:?}", other),
    }
}

#[test]
fn manual_strict_scope_cidrs_propagated_to_sandbox() {
    let cidr = IpNetwork::from_str("10.0.0.0/8").unwrap();
    let profile = ResolvedNseExecutionProfile::manual_strict(Some("10.0.0.1"), &[cidr]);
    assert_eq!(profile.sandbox.allowed_networks, vec![cidr]);
}

// ---------------------------------------------------------------------------
// 15. All profiles have non-empty audit labels
// ---------------------------------------------------------------------------

#[test]
fn all_profiles_have_non_empty_audit_labels() {
    let cidr = IpNetwork::from_str("10.0.0.0/8").unwrap();

    let profiles = vec![
        ResolvedNseExecutionProfile::manual_permissive(None),
        ResolvedNseExecutionProfile::manual_strict(Some("10.0.0.1"), &[cidr]),
        ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[cidr]),
        ResolvedNseExecutionProfile::ci_safe(),
        ResolvedNseExecutionProfile::compatibility_lab(None),
    ];

    for profile in profiles {
        assert!(
            !profile.audit_label.is_empty(),
            "Profile {:?} must have a non-empty audit label",
            profile.kind
        );
        assert!(
            profile.audit_label.starts_with("nse:"),
            "Profile {:?} audit label must start with 'nse:', got '{}'",
            profile.kind,
            profile.audit_label
        );
    }
}

#[test]
fn audit_labels_match_expected_prefixes() {
    let profiles = vec![
        (
            ResolvedNseExecutionProfile::manual_permissive(None),
            "nse:manual-permissive",
        ),
        (
            ResolvedNseExecutionProfile::manual_strict(Some("10.0.0.1"), &[]),
            "nse:manual-strict",
        ),
        (
            ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]),
            "nse:agent-safe",
        ),
        (ResolvedNseExecutionProfile::ci_safe(), "nse:ci-safe"),
        (
            ResolvedNseExecutionProfile::compatibility_lab(None),
            "nse:compatibility-lab",
        ),
    ];

    for (profile, expected_label) in profiles {
        assert_eq!(
            profile.audit_label, expected_label,
            "Profile {:?} audit label mismatch",
            profile.kind
        );
    }
}

// ---------------------------------------------------------------------------
// Additional: Sandbox enabled flag consistency
// ---------------------------------------------------------------------------

#[test]
fn sandbox_enabled_depends_on_feature_flag() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(None);
    if cfg!(feature = "sandbox") {
        assert!(profile.sandbox.enabled);
    } else {
        assert!(!profile.sandbox.enabled);
    }
}

#[test]
fn all_profiles_use_consistent_sandbox_allowed_dir() {
    let cidr = IpNetwork::from_str("10.0.0.0/8").unwrap();

    let profiles = vec![
        ResolvedNseExecutionProfile::manual_permissive(None),
        ResolvedNseExecutionProfile::manual_strict(Some("10.0.0.1"), &[cidr]),
        ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[cidr]),
        ResolvedNseExecutionProfile::ci_safe(),
        ResolvedNseExecutionProfile::compatibility_lab(None),
    ];

    for profile in profiles {
        assert_eq!(
            profile.sandbox.allowed_dir,
            Some(PathBuf::from("/tmp/eggsec-nse")),
            "Profile {:?} must use /tmp/eggsec-nse as sandbox root",
            profile.kind
        );
    }
}

// ---------------------------------------------------------------------------
// Additional: Network policy precedence
// ---------------------------------------------------------------------------

#[test]
fn agent_safe_scope_cidrs_take_precedence_over_ip_target() {
    let cidr = IpNetwork::from_str("192.168.0.0/16").unwrap();
    // Even though target is an IP, scope CIDRs take precedence
    let profile = ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[cidr]);
    assert!(
        matches!(profile.network_policy, NseNetworkPolicy::AllowCidrs(_)),
        "Scope CIDRs should take precedence over IP target, got {:?}",
        profile.network_policy
    );
}

#[test]
fn manual_strict_scope_cidrs_take_precedence_over_ip_target() {
    let cidr = IpNetwork::from_str("172.16.0.0/12").unwrap();
    let profile = ResolvedNseExecutionProfile::manual_strict(Some("10.0.0.1"), &[cidr]);
    assert!(
        matches!(profile.network_policy, NseNetworkPolicy::AllowCidrs(_)),
        "Scope CIDRs should take precedence over IP target, got {:?}",
        profile.network_policy
    );
}

// ---------------------------------------------------------------------------
// Additional: Script policy consistency across profiles
// ---------------------------------------------------------------------------

#[test]
fn ci_safe_and_agent_safe_disallow_script_files() {
    let ci = ResolvedNseExecutionProfile::ci_safe();
    let agent = ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);

    assert!(!ci.script_policy.allow_script_files);
    assert!(!agent.script_policy.allow_script_files);
}

#[test]
fn manual_permissive_and_compatibility_lab_allow_script_files() {
    let manual = ResolvedNseExecutionProfile::manual_permissive(None);
    let compat = ResolvedNseExecutionProfile::compatibility_lab(None);

    assert!(manual.script_policy.allow_script_files);
    assert!(compat.script_policy.allow_script_files);
}

// ---------------------------------------------------------------------------
// Additional: Limits are strict for automated surfaces
// ---------------------------------------------------------------------------

#[test]
fn agent_safe_uses_automated_limits() {
    let profile = ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
    // automated_defaults: 15s timeout, 5M instructions, resource caps
    assert_eq!(
        profile.limits.wall_clock_timeout,
        Some(std::time::Duration::from_secs(15))
    );
    assert_eq!(profile.limits.lua_instruction_budget, Some(5_000_000));
    assert!(profile.limits.max_network_operations.is_some());
    assert!(profile.limits.max_filesystem_operations.is_some());
}

#[test]
fn compatibility_lab_uses_manual_limits() {
    let profile = ResolvedNseExecutionProfile::compatibility_lab(None);
    assert_eq!(
        profile.limits.wall_clock_timeout,
        Some(std::time::Duration::from_secs(120))
    );
    assert_eq!(profile.limits.lua_instruction_budget, Some(100_000_000));
}
