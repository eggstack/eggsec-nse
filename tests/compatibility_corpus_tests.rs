//! NSE compatibility corpus tests.
//!
//! Verifies that the report/resolver pipeline correctly classifies
//! supported, partial, approximate, unsupported, denied, and errored
//! behavior for representative NSE scripts and modules.
//!
//! Run with: `cargo test -p eggsec-nse --features nse compatibility_corpus`

use std::path::PathBuf;

use eggsec_nse::limits::NseExecutionLimits;
use eggsec_nse::profile::{NseModulePolicy, NseScriptPolicy, ResolvedNseExecutionProfile};
use eggsec_nse::report::*;
use eggsec_nse::resolver::{NseLoadDiagnostic, NseScriptSource, ScriptResolver};

// ---------------------------------------------------------------------------
// Corpus manifest
// ---------------------------------------------------------------------------

struct CorpusCase {
    name: &'static str,
    description: &'static str,
    script_file: &'static str,
    script_content: &'static str,
    profile_kind: ProfileKind,
    expected_status: NseRunCompatibilityStatus,
    expected_fidelity: NseRunFidelity,
    expected_resolved: bool,
    expected_block: bool,
}

enum ProfileKind {
    CompatibilityLab,
    ManualPermissive,
    AgentSafe,
}

fn test_limits() -> NseExecutionLimits {
    NseExecutionLimits {
        wall_clock_timeout: Some(std::time::Duration::from_secs(5)),
        lua_instruction_budget: Some(100_000),
        max_output_bytes: Some(1024),
        max_script_bytes: Some(65536),
        max_required_module_bytes: Some(32768),
        max_network_operations: Some(50),
        max_filesystem_operations: Some(25),
        max_lua_memory_bytes: Some(1024 * 1024),
        ..NseExecutionLimits::default()
    }
}

fn make_script_policy(roots: Vec<PathBuf>) -> NseScriptPolicy {
    NseScriptPolicy {
        allow_builtin_scripts: true,
        allow_script_files: true,
        allowed_script_roots: roots,
        allow_conventional_nmap_paths: false,
        max_script_bytes: Some(65536),
    }
}

fn make_module_policy(roots: Vec<PathBuf>) -> NseModulePolicy {
    NseModulePolicy {
        allow_builtin_modules: true,
        allow_filesystem_modules: true,
        allowed_module_roots: roots,
        max_module_bytes: Some(32768),
    }
}

fn make_profile(kind: ProfileKind, roots: Vec<PathBuf>) -> ResolvedNseExecutionProfile {
    let limits = test_limits();
    let script_policy = make_script_policy(roots.clone());
    let module_policy = make_module_policy(roots);
    match kind {
        ProfileKind::CompatibilityLab => ResolvedNseExecutionProfile {
            kind: eggsec_nse::NseExecutionProfileKind::CompatibilityLab,
            sandbox: eggsec_nse::SandboxConfig::default(),
            limits,
            script_policy,
            module_policy,
            network_policy: eggsec_nse::NseNetworkPolicy::AllowAllManual,
            audit_label: "nse:compatibility-corpus".to_string(),
            warnings: vec![],
        },
        ProfileKind::ManualPermissive => ResolvedNseExecutionProfile {
            kind: eggsec_nse::NseExecutionProfileKind::ManualPermissive,
            sandbox: eggsec_nse::SandboxConfig::default(),
            limits,
            script_policy,
            module_policy,
            network_policy: eggsec_nse::NseNetworkPolicy::AllowAllManual,
            audit_label: "nse:compatibility-corpus".to_string(),
            warnings: vec![],
        },
        ProfileKind::AgentSafe => {
            let mut p = ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
            p.script_policy.allow_script_files = false;
            p.script_policy.allowed_script_roots = vec![];
            p.script_policy.max_script_bytes = Some(65536);
            p.module_policy = make_module_policy(vec![]);
            p.limits = limits;
            p.audit_label = "nse:compatibility-corpus".to_string();
            p.warnings = vec![];
            p
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: write fixture file and return path
// ---------------------------------------------------------------------------

fn write_fixture(tmp_dir: &std::path::Path, name: &str, content: &str) -> PathBuf {
    let path = tmp_dir.join(name);
    std::fs::write(&path, content).expect("write fixture");
    path
}

// ---------------------------------------------------------------------------
// Test: Supported behavior — file script resolves and produces Compatible report
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_simple_portrule() {
    let tmp = std::env::temp_dir().join("eggsec-nse-corpus-simple-portrule");
    let _ = std::fs::create_dir_all(&tmp);
    let fixture = write_fixture(
        &tmp,
        "simple_portrule.nse",
        r#"local nmap = require "nmap"
description = [[Simple portrule test script.]]
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  return "portrule success"
end"#,
    );

    let profile = make_profile(ProfileKind::CompatibilityLab, vec![tmp.clone()]);
    let mut resolver =
        ScriptResolver::new(profile.script_policy.clone(), profile.module_policy.clone(), profile.limits.clone());

    let source = NseScriptSource::File {
        path: fixture.clone(),
    };
    let result = resolver.resolve_script(source.clone());
    assert!(result.is_ok(), "resolve failed: {:?}", result.err());
    let resolved = result.unwrap();
    assert!(resolved.size > 0);

    let diagnostics = resolver.take_diagnostics();
    assert!(
        diagnostics.iter().any(|d| matches!(d, NseLoadDiagnostic::Resolved { .. })),
        "expected Resolved diagnostic"
    );

    let report = NseRunReport::new("127.0.0.1", "simple_portrule")
        .with_profile(&profile)
        .with_script_source(&source)
        .with_resolver_diagnostics(&diagnostics)
        .with_output("portrule success")
        .compute_compatibility();

    assert_eq!(report.compatibility.status, NseRunCompatibilityStatus::Compatible);
    assert_eq!(report.compatibility.fidelity, NseRunFidelity::Full);
    assert!(report.compatibility.unsupported_features.is_empty());
    assert!(report.compatibility.approximations.is_empty());
    assert!(report.errors.is_empty());
    assert_eq!(report.resolver.resolved_count, 1);
    assert_eq!(report.resolver.blocked_count, 0);

    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// Test: Supported behavior — stdnse output script
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_stdnse_output() {
    let tmp = std::env::temp_dir().join("eggsec-nse-corpus-stdnse-output");
    let _ = std::fs::create_dir_all(&tmp);
    let fixture = write_fixture(
        &tmp,
        "stdnse_output.nse",
        r#"local stdnse = require "stdnse"
description = [[Test script using stdnse output functions.]]
portrule = function(host, port)
  return port.protocol == "tcp"
end
action = function(host, port)
  local result = stdnse.format_output("test-output", "value")
  return result
end"#,
    );

    let profile = make_profile(ProfileKind::CompatibilityLab, vec![tmp.clone()]);
    let mut resolver =
        ScriptResolver::new(profile.script_policy.clone(), profile.module_policy.clone(), profile.limits.clone());

    let source = NseScriptSource::File { path: fixture };
    let result = resolver.resolve_script(source.clone());
    assert!(result.is_ok());
    let diagnostics = resolver.take_diagnostics();

    let report = NseRunReport::new("127.0.0.1", "stdnse-output")
        .with_profile(&profile)
        .with_script_source(&source)
        .with_resolver_diagnostics(&diagnostics)
        .with_output("test-output: value")
        .compute_compatibility();

    assert_eq!(report.compatibility.status, NseRunCompatibilityStatus::Compatible);
    assert_eq!(report.compatibility.fidelity, NseRunFidelity::Full);
    assert_eq!(report.resolver.resolved_count, 1);

    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// Test: Supported behavior — builtin module require
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_builtin_module_require() {
    let tmp = std::env::temp_dir().join("eggsec-nse-corpus-builtin-module");
    let _ = std::fs::create_dir_all(&tmp);
    let fixture = write_fixture(
        &tmp,
        "builtin_module_require.nse",
        r#"description = [[Test script that requires a builtin module.]]
portrule = function(host, port)
  return port.protocol == "tcp"
end
action = function(host, port)
  local ok, err = pcall(require, "stdnse")
  if ok then
    return "builtin module loaded"
  else
    return "builtin module load failed: " .. tostring(err)
  end
end"#,
    );

    let profile = make_profile(ProfileKind::CompatibilityLab, vec![tmp.clone()]);
    let mut resolver =
        ScriptResolver::new(profile.script_policy.clone(), profile.module_policy.clone(), profile.limits.clone());

    let source = NseScriptSource::File { path: fixture };
    let result = resolver.resolve_script(source.clone());
    assert!(result.is_ok());
    let diagnostics = resolver.take_diagnostics();

    let report = NseRunReport::new("127.0.0.1", "builtin-module-require")
        .with_profile(&profile)
        .with_script_source(&source)
        .with_resolver_diagnostics(&diagnostics)
        .with_output("builtin module loaded")
        .compute_compatibility();

    assert_eq!(report.compatibility.status, NseRunCompatibilityStatus::Compatible);
    assert_eq!(report.compatibility.fidelity, NseRunFidelity::Full);
    assert_eq!(report.resolver.resolved_count, 1);

    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// Test: Supported behavior — hostrule script
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_simple_hostrule() {
    let tmp = std::env::temp_dir().join("eggsec-nse-corpus-hostrule");
    let _ = std::fs::create_dir_all(&tmp);
    let fixture = write_fixture(
        &tmp,
        "simple_hostrule.nse",
        r#"description = [[Simple hostrule test script.]]
hostrule = function(host)
  return host.host_state == "up"
end
action = function(host)
  return "hostrule success"
end"#,
    );

    let profile = make_profile(ProfileKind::CompatibilityLab, vec![tmp.clone()]);
    let mut resolver =
        ScriptResolver::new(profile.script_policy.clone(), profile.module_policy.clone(), profile.limits.clone());

    let source = NseScriptSource::File { path: fixture };
    let result = resolver.resolve_script(source.clone());
    assert!(result.is_ok());
    let diagnostics = resolver.take_diagnostics();

    let report = NseRunReport::new("127.0.0.1", "simple-hostrule")
        .with_profile(&profile)
        .with_script_source(&source)
        .with_resolver_diagnostics(&diagnostics)
        .with_output("hostrule success")
        .compute_compatibility();

    assert_eq!(report.compatibility.status, NseRunCompatibilityStatus::Compatible);
    assert_eq!(report.compatibility.fidelity, NseRunFidelity::Full);

    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// Test: Denied behavior — AgentSafe profile rejects file script
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_agent_denied() {
    let tmp = std::env::temp_dir().join("eggsec-nse-corpus-agent-denied");
    let _ = std::fs::create_dir_all(&tmp);
    let fixture = write_fixture(
        &tmp,
        "agent_denied_file.nse",
        r#"description = [[This script should be denied by AgentSafe policy.]]
portrule = function(host, port)
  return port.protocol == "tcp"
end
action = function(host, port)
  return "should not execute under agent-safe"
end"#,
    );

    let profile = make_profile(ProfileKind::AgentSafe, vec![]);
    let mut resolver =
        ScriptResolver::new(profile.script_policy.clone(), profile.module_policy.clone(), profile.limits.clone());

    let source = NseScriptSource::File { path: fixture };
    let result = resolver.resolve_script(source.clone());
    assert!(result.is_err(), "expected AgentSafe to reject file script");
    let err = result.unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("blocked by policy") || err_str.contains("not allowed"),
        "unexpected error: {}",
        err_str
    );

    let diagnostics = resolver.take_diagnostics();
    assert!(
        diagnostics.iter().any(|d| matches!(d, NseLoadDiagnostic::Blocked { .. })),
        "expected Blocked diagnostic"
    );

    let report = NseRunReport::new("10.0.0.1", "agent-denied-file")
        .with_profile(&profile)
        .with_script_source(&source)
        .with_resolver_diagnostics(&diagnostics)
        .with_error("script blocked by policy: file scripts not allowed")
        .compute_compatibility();

    assert_eq!(report.compatibility.status, NseRunCompatibilityStatus::Failed);
    assert_eq!(report.resolver.blocked_count, 1);

    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// Test: Error — file not found
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_file_not_found() {
    let profile = make_profile(ProfileKind::CompatibilityLab, vec![]);
    let mut resolver =
        ScriptResolver::new(profile.script_policy.clone(), profile.module_policy.clone(), profile.limits.clone());

    let source = NseScriptSource::File {
        path: PathBuf::from("/nonexistent/path/to/script.nse"),
    };
    let result = resolver.resolve_script(source.clone());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, eggsec_nse::NseLoadError::NotFound { .. }),
        "expected NotFound, got: {}",
        err
    );

    let diagnostics = resolver.take_diagnostics();

    let report = NseRunReport::new("127.0.0.1", "file-not-found")
        .with_profile(&profile)
        .with_script_source(&source)
        .with_resolver_diagnostics(&diagnostics)
        .with_error("script file not found")
        .compute_compatibility();

    assert_eq!(report.compatibility.status, NseRunCompatibilityStatus::Failed);
    assert_eq!(report.compatibility.fidelity, NseRunFidelity::Full);
    assert!(report.errors.iter().any(|e| e.contains("not found")));
}

// ---------------------------------------------------------------------------
// Test: Unsupported — invalid module name
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_invalid_module_name() {
    let profile = make_profile(ProfileKind::ManualPermissive, vec![]);
    let mut resolver =
        ScriptResolver::new(profile.script_policy.clone(), profile.module_policy.clone(), profile.limits.clone());

    let result = resolver.resolve_module("../../../etc/passwd");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, eggsec_nse::NseLoadError::InvalidModuleName { .. }),
        "expected InvalidModuleName, got: {}",
        err
    );

    let diagnostics = resolver.take_diagnostics();
    assert!(
        diagnostics
            .iter()
            .any(|d| matches!(d, NseLoadDiagnostic::ModuleNameRejected { .. })),
        "expected ModuleNameRejected diagnostic"
    );

    let report = NseRunReport::new("127.0.0.1", "invalid-module-name")
        .with_profile(&profile)
        .with_resolver_diagnostics(&diagnostics)
        .compute_compatibility();

    assert_eq!(report.compatibility.status, NseRunCompatibilityStatus::Partial);
    assert_eq!(report.compatibility.fidelity, NseRunFidelity::Minimal);
    assert!(
        !report.compatibility.unsupported_features.is_empty(),
        "unsupported_features should list the rejected module"
    );
    assert_eq!(report.resolver.rejected_count, 1);
}

// ---------------------------------------------------------------------------
// Test: Approximate — rule with approximate exactness
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_approximate_rule() {
    let profile = make_profile(ProfileKind::ManualPermissive, vec![]);
    let mut resolver =
        ScriptResolver::new(profile.script_policy.clone(), profile.module_policy.clone(), profile.limits.clone());

    let source = NseScriptSource::InlineManual {
        label: "approx-test".to_string(),
        content: "return 'hello'".to_string(),
    };
    let result = resolver.resolve_script(source.clone());
    assert!(result.is_ok());
    let diagnostics = resolver.take_diagnostics();

    let rules = vec![NseRuleEvaluationReport {
        kind: "portrule".to_string(),
        evaluated: true,
        matched: true,
        exactness: "approximate".to_string(),
        error: None,
        summary: "portrule matched with approximate port handling".to_string(),
    }];

    let report = NseRunReport::new("127.0.0.1", "approximate-rule")
        .with_profile(&profile)
        .with_script_source(&source)
        .with_resolver_diagnostics(&diagnostics)
        .with_rules(rules)
        .with_output("hello")
        .compute_compatibility();

    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::CompatibleWithWarnings
    );
    assert_eq!(report.compatibility.fidelity, NseRunFidelity::Approximate);
    assert!(
        !report.compatibility.approximations.is_empty(),
        "approximations should list the approximate rule"
    );
}

// ---------------------------------------------------------------------------
// Test: Module resolution — filesystem module found
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_module_resolution() {
    let tmp = std::env::temp_dir().join("eggsec-nse-corpus-module-res");
    let _ = std::fs::create_dir_all(&tmp);
    write_fixture(
        &tmp,
        "custom_module.lua",
        r#"local M = {}
function M.get_value()
  return "custom_module_value"
end
return M"#,
    );

    let profile = make_profile(ProfileKind::CompatibilityLab, vec![tmp.clone()]);
    let mut resolver =
        ScriptResolver::new(profile.script_policy.clone(), profile.module_policy.clone(), profile.limits.clone());

    let result = resolver.resolve_module("custom_module");
    assert!(result.is_ok(), "resolve_module failed: {:?}", result.err());
    let module = result.unwrap();
    assert!(module.is_some(), "expected module to be found");
    let module = module.unwrap();
    assert!(module.content.contains("custom_module_value"));
    assert_eq!(module.size, module.content.len());

    let diagnostics = resolver.take_diagnostics();
    assert!(
        diagnostics.iter().any(|d| matches!(d, NseLoadDiagnostic::Resolved { .. })),
        "expected Resolved diagnostic for module"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// Test: Library use report — metadata present
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_library_use_report() {
    let libraries = vec![NseLibraryUseReport {
        name: "stdnse".to_string(),
        category: "core".to_string(),
        registered: true,
        side_effects: vec![],
        fallback_behavior: "hard-fail".to_string(),
        notes: "Standard NSE utility library".to_string(),
        loaded: true,
        warnings: vec![],
    }];

    let profile = make_profile(ProfileKind::ManualPermissive, vec![]);
    let report = NseRunReport::new("127.0.0.1", "library-use-report")
        .with_profile(&profile)
        .with_libraries(libraries)
        .compute_compatibility();

    assert_eq!(report.libraries.len(), 1);
    assert_eq!(report.libraries[0].name, "stdnse");
    assert!(report.libraries[0].registered);
    assert!(report.libraries[0].loaded);
    assert_eq!(report.compatibility.status, NseRunCompatibilityStatus::Compatible);
}

// ---------------------------------------------------------------------------
// Test: Unsupported behavior — error in report
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_unsupported_behavior() {
    let profile = make_profile(ProfileKind::ManualPermissive, vec![]);
    let report = NseRunReport::new("127.0.0.1", "unsupported-behavior")
        .with_profile(&profile)
        .with_error("unsupported feature: script uses unimplemented API")
        .compute_compatibility();

    assert_eq!(report.compatibility.status, NseRunCompatibilityStatus::Failed);
    assert!(report.errors.iter().any(|e| e.contains("unsupported")));
}

// ---------------------------------------------------------------------------
// Test: Builtin script resolves
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_builtin_script() {
    let profile = make_profile(ProfileKind::ManualPermissive, vec![]);
    let mut resolver =
        ScriptResolver::new(profile.script_policy.clone(), profile.module_policy.clone(), profile.limits.clone());

    let source = NseScriptSource::Builtin {
        name: "ssl-cert".to_string(),
    };
    let result = resolver.resolve_script(source.clone());
    assert!(result.is_ok(), "builtin resolve failed: {:?}", result.err());
    let diagnostics = resolver.take_diagnostics();
    assert!(
        diagnostics.iter().any(|d| matches!(d, NseLoadDiagnostic::Resolved { .. })),
        "expected Resolved diagnostic for builtin"
    );

    let report = NseRunReport::new("127.0.0.1", "builtin-script")
        .with_profile(&profile)
        .with_script_source(&source)
        .with_resolver_diagnostics(&diagnostics)
        .compute_compatibility();

    assert_eq!(report.compatibility.status, NseRunCompatibilityStatus::Compatible);
    assert_eq!(report.script_source.kind, "builtin");
}

// ---------------------------------------------------------------------------
// Test: Inline script resolves
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_inline_script() {
    let profile = make_profile(ProfileKind::ManualPermissive, vec![]);
    let mut resolver =
        ScriptResolver::new(profile.script_policy.clone(), profile.module_policy.clone(), profile.limits.clone());

    let source = NseScriptSource::InlineManual {
        label: "inline-test".to_string(),
        content: "return 'inline-result'".to_string(),
    };
    let result = resolver.resolve_script(source.clone());
    assert!(result.is_ok());
    let resolved = result.unwrap();
    assert_eq!(resolved.content, "return 'inline-result'");

    let diagnostics = resolver.take_diagnostics();
    assert!(
        diagnostics.iter().any(|d| matches!(d, NseLoadDiagnostic::Resolved { .. })),
        "expected Resolved diagnostic for inline"
    );

    let report = NseRunReport::new("127.0.0.1", "inline-script")
        .with_profile(&profile)
        .with_script_source(&source)
        .with_resolver_diagnostics(&diagnostics)
        .compute_compatibility();

    assert_eq!(report.compatibility.status, NseRunCompatibilityStatus::Compatible);
    assert_eq!(report.script_source.kind, "inline");
}

// ---------------------------------------------------------------------------
// Test: Module not found in roots returns Ok(None)
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_module_not_found() {
    let tmp = std::env::temp_dir().join("eggsec-nse-corpus-module-nf");
    let _ = std::fs::create_dir_all(&tmp);

    let profile = make_profile(ProfileKind::CompatibilityLab, vec![tmp.clone()]);
    let mut resolver =
        ScriptResolver::new(profile.script_policy.clone(), profile.module_policy.clone(), profile.limits.clone());

    let result = resolver.resolve_module("nonexistent_module_xyz");
    assert!(result.is_ok(), "should return Ok(None) for missing module");
    let module = result.unwrap();
    assert!(module.is_none(), "expected None for missing module");

    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// Test: Multiple diagnostics — mixed resolved and blocked
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_mixed_diagnostics() {
    let diagnostics = vec![
        NseLoadDiagnostic::Resolved {
            source: NseScriptSource::Builtin {
                name: "ssl-cert".to_string(),
            },
            bytes: 100,
        },
        NseLoadDiagnostic::Blocked {
            source: NseScriptSource::File {
                path: PathBuf::from("/tmp/bad.nse"),
            },
            reason: "script files not allowed".to_string(),
        },
    ];

    let profile = make_profile(ProfileKind::ManualPermissive, vec![]);
    let report = NseRunReport::new("127.0.0.1", "mixed-diagnostics")
        .with_profile(&profile)
        .with_resolver_diagnostics(&diagnostics)
        .compute_compatibility();

    assert_eq!(report.resolver.resolved_count, 1);
    assert_eq!(report.resolver.blocked_count, 1);
    assert_eq!(report.resolver.total_diagnostics, 2);
    // No errors and no rejected → Compatible
    assert_eq!(report.compatibility.status, NseRunCompatibilityStatus::Compatible);
}

// ---------------------------------------------------------------------------
// Test: Serialization roundtrip
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_serialization_roundtrip() {
    let profile = make_profile(ProfileKind::ManualPermissive, vec![]);
    let source = NseScriptSource::Builtin {
        name: "ssl-cert".to_string(),
    };

    let report = NseRunReport::new("127.0.0.1", "roundtrip-test")
        .with_profile(&profile)
        .with_script_source(&source)
        .with_output("test output")
        .compute_compatibility();

    let json = serde_json::to_string(&report).expect("serialize");
    let deserialized: NseRunReport = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(deserialized.target, report.target);
    assert_eq!(deserialized.script_name, report.script_name);
    assert_eq!(deserialized.compatibility.status, report.compatibility.status);
    assert_eq!(deserialized.compatibility.fidelity, report.compatibility.fidelity);
}

// ---------------------------------------------------------------------------
// Test: Rule with exact match — no approximations
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_exact_rule() {
    let profile = make_profile(ProfileKind::ManualPermissive, vec![]);
    let rules = vec![NseRuleEvaluationReport {
        kind: "portrule".to_string(),
        evaluated: true,
        matched: true,
        exactness: "exact".to_string(),
        error: None,
        summary: "portrule matched exactly".to_string(),
    }];

    let report = NseRunReport::new("127.0.0.1", "exact-rule")
        .with_profile(&profile)
        .with_rules(rules)
        .compute_compatibility();

    assert_eq!(report.compatibility.status, NseRunCompatibilityStatus::Compatible);
    assert_eq!(report.compatibility.fidelity, NseRunFidelity::Full);
    assert!(report.compatibility.approximations.is_empty());
}

// ---------------------------------------------------------------------------
// Test: Rule with error — produces Failed
// ---------------------------------------------------------------------------

#[test]
fn compatibility_corpus_rule_error() {
    let profile = make_profile(ProfileKind::ManualPermissive, vec![]);
    let rules = vec![NseRuleEvaluationReport {
        kind: "portrule".to_string(),
        evaluated: true,
        matched: false,
        exactness: "exact".to_string(),
        error: Some("rule evaluation panicked".to_string()),
        summary: "portrule failed".to_string(),
    }];

    let report = NseRunReport::new("127.0.0.1", "rule-error")
        .with_profile(&profile)
        .with_rules(rules)
        .with_error("rule evaluation panicked")
        .compute_compatibility();

    assert_eq!(report.compatibility.status, NseRunCompatibilityStatus::Failed);
    assert!(report.errors.iter().any(|e| e.contains("panicked")));
}
