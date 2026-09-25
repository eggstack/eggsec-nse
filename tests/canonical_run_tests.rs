//! Milestone 001 Work Packages B/F — canonical execution/report convergence.
//!
//! Proves one runtime-owned pipeline (`execute_nse_run`) serves every
//! surface: resolver-first built-in/file/inline handling, centralized
//! rule/action execution, single library-use reconciliation, complete
//! report assembly (resolver diagnostics, rules, stats, libraries,
//! capability events, compatibility/fidelity, output, evidence), and
//! surface parity between manual and automated profiles.

#![cfg(feature = "nse")]

use eggsec_nse::limits::{NseCancellationToken, NseExecutionLimits};
use eggsec_nse::profile::ResolvedNseExecutionProfile;
use eggsec_nse::report::{NseRunCompatibilityStatus, NseRunReport};
use eggsec_nse::resolver::NseScriptSource;
use eggsec_nse::run::{
    execute_nse_run, extract_static_requires, script_name_for_source, NseRunErrorKind,
    NseRunRequest,
};
use eggsec_nse::{NseContextSource, NseHostContext, NsePortContext};

/// Deterministic local fixture: portrule matches the injected synthetic
/// port context; action returns a constant. No network, filesystem, or
/// process activity.
const PARITY_FIXTURE: &str = r#"
description = [[Canonical parity fixture.]]
local stdnse = require "stdnse"
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end
action = function(host, port)
  return "canonical-ok"
end
"#;

fn parity_request(profile: ResolvedNseExecutionProfile) -> NseRunRequest {
    NseRunRequest::new(
        "127.0.0.1",
        NseScriptSource::InlineManual {
            label: "parity-fixture".to_string(),
            content: PARITY_FIXTURE.to_string(),
        },
        profile,
    )
    .with_port_context(NsePortContext {
        port: 80,
        protocol: "tcp".to_string(),
        state: "open".to_string(),
        service: None,
        source: NseContextSource::Synthetic,
    })
}

#[test]
fn canonical_run_produces_complete_report() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"));
    let report = execute_nse_run(parity_request(profile)).expect("canonical run succeeds");

    assert_eq!(report.target, "127.0.0.1");
    assert_eq!(report.script_name, "parity-fixture");
    assert_eq!(report.script_source.kind, "inline");
    assert_eq!(report.profile.kind, "manual-permissive");
    // Resolver-first: diagnostics preserved.
    assert_eq!(report.resolver.total_diagnostics, 1);
    assert_eq!(report.resolver.resolved_count, 1);
    // Rule evaluation centralized: portrule matched.
    assert!(report.rules.iter().any(|r| r.matched));
    // Stats populated by the canonical path.
    assert!(report.stats.elapsed_secs.is_finite());
    // Library reconciliation: dynamic tracking or labeled static fallback.
    assert!(
        !report.libraries.is_empty(),
        "parity fixture requires stdnse-adjacent modules; libraries must be reported"
    );
    // Compatibility computed once; synthetic context yields approximate fidelity.
    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::CompatibleWithWarnings
    );
    // Output + evidence extracted once.
    assert!(report.output.has_output);
    assert!(
        !report.evidence.is_empty(),
        "non-empty output must produce ScriptOutput evidence"
    );
}

#[test]
fn canonical_run_builtin_source_reports_builtin_kind() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"));
    let request = NseRunRequest::new(
        "127.0.0.1",
        NseScriptSource::Builtin {
            name: "banner".to_string(),
        },
        profile,
    );
    let report = execute_nse_run(request).expect("builtin run succeeds");
    assert_eq!(report.script_name, "banner");
    assert_eq!(report.script_source.kind, "builtin");
    assert_eq!(report.resolver.resolved_count, 1);
}

#[test]
fn canonical_run_file_source_resolves_through_resolver() {
    let dir = std::env::temp_dir().join(format!("eggsec-canonical-file-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("parity.nse");
    std::fs::write(&path, "hostrule = function(host) return false end").unwrap();

    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"));
    let request = NseRunRequest::new(
        "127.0.0.1",
        NseScriptSource::File { path: path.clone() },
        profile,
    );
    let report = execute_nse_run(request).expect("file run succeeds");
    assert_eq!(report.script_source.kind, "file");
    assert_eq!(report.resolver.resolved_count, 1);
    assert_eq!(report.rules.len(), 1);
    assert!(!report.rules[0].matched);

    std::fs::remove_file(&path).ok();
    std::fs::remove_dir(&dir).ok();
}

#[test]
fn canonical_run_unmatched_rule_keeps_compatible_status() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"));
    let request = NseRunRequest::new(
        "127.0.0.1",
        NseScriptSource::InlineManual {
            label: "no-match".to_string(),
            content: "hostrule = function(host) return false end".to_string(),
        },
        profile,
    );
    let report = execute_nse_run(request).expect("run succeeds");
    assert!(report.rules.iter().all(|r| !r.matched));
    // Manual-permissive carries profile warnings, so CompatibleWithWarnings.
    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::CompatibleWithWarnings
    );
}

#[test]
fn manual_and_automated_profiles_agree_on_runtime_fields() {
    // Surface parity: the same fixture request reports the same runtime
    // fields under manual and automated profiles; only profile/limits
    // sections and timing may differ.
    let manual = execute_nse_run(parity_request(
        ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1")),
    ))
    .expect("manual run succeeds");
    let automated = execute_nse_run(parity_request(ResolvedNseExecutionProfile::agent_safe(
        "127.0.0.1",
        &[],
    )))
    .expect("automated run succeeds");

    assert_eq!(manual.profile.kind, "manual-permissive");
    assert_eq!(automated.profile.kind, "agent-safe");

    assert_eq!(manual.script_source.kind, automated.script_source.kind);
    assert_eq!(manual.rules.len(), automated.rules.len());
    for (a, b) in manual.rules.iter().zip(automated.rules.iter()) {
        assert_eq!(a.kind, b.kind);
        assert_eq!(a.matched, b.matched);
        assert_eq!(a.exactness, b.exactness);
    }
    assert_eq!(manual.output.content, automated.output.content);
    assert_eq!(manual.libraries.len(), automated.libraries.len());
    assert_eq!(
        manual.compatibility.status.to_string(),
        automated.compatibility.status.to_string()
    );
    assert_eq!(manual.evidence.len(), automated.evidence.len());
}

#[test]
fn limits_override_is_enforced_without_profile_rebuild() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"));
    let request = NseRunRequest::new(
        "127.0.0.1",
        NseScriptSource::InlineManual {
            label: "oversized".to_string(),
            content: "hostrule = function(host) return true end".to_string(),
        },
        profile,
    )
    .with_limits_override(NseExecutionLimits {
        max_script_bytes: Some(8),
        ..NseExecutionLimits::default()
    });
    let err = execute_nse_run(request).expect_err("8-byte script cap must reject fixture");
    assert_eq!(err.kind, NseRunErrorKind::Resolution);
    assert!(!err.diagnostics.is_empty());
}

#[test]
fn cancellation_before_execution_is_typed() {
    let token = NseCancellationToken::new();
    token.cancel();
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"));
    let request = parity_request(profile).with_cancellation(token);
    let err = execute_nse_run(request).expect_err("cancelled run must fail");
    assert_eq!(err.kind, NseRunErrorKind::Cancelled);
    // Cancellation never becomes a successful empty report.
    let failure = err.failure_report();
    assert_eq!(
        failure.compatibility.status,
        NseRunCompatibilityStatus::Failed
    );
}

#[test]
fn concurrent_runs_do_not_share_report_state() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"));
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let request = parity_request(profile.clone());
            std::thread::spawn(move || execute_nse_run(request).expect("concurrent run succeeds"))
        })
        .collect();

    let mut outputs = Vec::new();
    for handle in handles {
        let report = handle.join().expect("thread joins");
        assert!(report.rules.iter().any(|r| r.matched));
        outputs.push(report.output.content);
    }
    assert!(
        outputs.windows(2).all(|w| w[0] == w[1]),
        "independent runs must produce identical output"
    );
}

#[test]
fn automated_profile_denies_script_files_with_diagnostics() {
    let profile = ResolvedNseExecutionProfile::agent_safe("127.0.0.1", &[]);
    let request = NseRunRequest::new(
        "127.0.0.1",
        NseScriptSource::File {
            path: std::path::PathBuf::from("/tmp/eggsec-automated-denied.nse"),
        },
        profile,
    );
    let err = execute_nse_run(request).expect_err("agent-safe must deny script files");
    assert_eq!(err.kind, NseRunErrorKind::Resolution);
    assert!(!err.diagnostics.is_empty());
    // Automated surfaces never silently fall back to manual-permissive.
    assert_eq!(err.profile.kind.to_string(), "agent-safe");
    let failure = err.failure_report();
    assert_eq!(
        failure.compatibility.status,
        NseRunCompatibilityStatus::Failed
    );
    assert!(failure.errors.iter().any(|e| e.contains("agent-safe")));
}

#[test]
fn missing_and_misextended_files_are_resolution_failures() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"));
    for path in [
        "/tmp/eggsec-canonical-missing-does-not-exist.nse",
        "/tmp/eggsec-canonical-wrong-extension.txt",
    ] {
        let request = NseRunRequest::new(
            "127.0.0.1",
            NseScriptSource::File {
                path: std::path::PathBuf::from(path),
            },
            profile.clone(),
        );
        let err = execute_nse_run(request).expect_err("bad file source must fail");
        assert_eq!(err.kind, NseRunErrorKind::Resolution, "path: {}", path);
    }
}

#[test]
fn trusted_registry_source_is_resolution_failure() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"));
    let request = NseRunRequest::new(
        "127.0.0.1",
        NseScriptSource::TrustedRegistry {
            name: "future".to_string(),
        },
        profile,
    );
    let err = execute_nse_run(request).expect_err("registry lookup is unimplemented");
    assert_eq!(err.kind, NseRunErrorKind::Resolution);
}

#[test]
fn host_context_is_applied_to_executor() {
    // Executor rule tables stay synthetic (existing semantics), but the
    // supplied host context is injected into `nmap._hostinfo` where scripts
    // can observe it.
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"));
    let request = NseRunRequest::new(
        "127.0.0.1",
        NseScriptSource::InlineManual {
            label: "hostctx".to_string(),
            content: "hostrule = function(host) return true end\naction = function(host, port) return nmap._hostinfo.ip end".to_string(),
        },
        profile,
    )
    .with_host_context(NseHostContext {
        ip: "10.9.9.9".to_string(),
        hostname: None,
        target_label: "127.0.0.1".to_string(),
        source: NseContextSource::Fixture,
    });
    let report = execute_nse_run(request).expect("host context run succeeds");
    assert!(report.rules.iter().any(|r| r.matched));
    assert!(
        report.output.content.contains("10.9.9.9"),
        "injected host context must be visible to scripts; output={}",
        report.output.content
    );
}

#[test]
fn static_fallback_marks_unloaded_with_warning() {
    let reports = eggsec_nse::report::library_use_reports_from_static_requires(&[
        "stdnse".to_string(),
        "no-such-lib-xyz".to_string(),
    ]);
    assert_eq!(reports.len(), 2);
    for report in &reports {
        assert!(!report.loaded);
        assert!(report.warnings.iter().any(|w| w.contains("statically")));
    }
    assert!(reports[0].registered);
    assert!(!reports[1].registered);
}

#[test]
fn static_require_extraction_dedupes_and_trims() {
    let content =
        "local a = require \"stdnse\"\nlocal b = require('http')\nlocal c = require \"stdnse\"";
    assert_eq!(
        extract_static_requires(content),
        vec!["stdnse".to_string(), "http".to_string()]
    );
    assert!(extract_static_requires("").is_empty());
}

#[test]
fn script_name_derivation_matches_report_summary() {
    let builtin = NseScriptSource::Builtin {
        name: "banner".to_string(),
    };
    assert_eq!(script_name_for_source(&builtin), "banner");
    let inline = NseScriptSource::InlineManual {
        label: "custom".to_string(),
        content: String::new(),
    };
    assert_eq!(script_name_for_source(&inline), "custom");
}

#[test]
fn serialized_canonical_report_roundtrips_with_builtin_kind() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"));
    let request = NseRunRequest::new(
        "127.0.0.1",
        NseScriptSource::Builtin {
            name: "banner".to_string(),
        },
        profile,
    );
    let report: NseRunReport = execute_nse_run(request).expect("builtin run succeeds");
    let json = serde_json::to_string(&report).expect("report serializes");
    let value: serde_json::Value = serde_json::from_str(&json).expect("report deserializes");
    assert_eq!(value["script_source"]["kind"], "builtin");
    assert_eq!(value["profile"]["kind"], "manual-permissive");
    assert!(value.get("stats").is_some());
    assert!(value.get("evidence").is_some());
    let roundtrip: NseRunReport = serde_json::from_str(&json).expect("roundtrip");
    assert_eq!(roundtrip.target, report.target);
    assert_eq!(roundtrip.rules.len(), report.rules.len());
}
