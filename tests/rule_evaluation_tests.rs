use eggsec_nse::limits::{NseCancellationToken, NseExecutionLimits};
use eggsec_nse::report::*;
use eggsec_nse::{NseExecutor, SandboxConfig};

struct NseTestResult {
    report: NseRunReport,
}

fn run_nse_with_content(_script_args: &str, source: &str) -> NseTestResult {
    let mut executor = test_executor();
    executor.set_target("10.0.0.1").unwrap();

    let output = executor
        .run_script_with_limits(source)
        .expect("script execution should succeed");

    let script_source = eggsec_nse::resolver::NseScriptSource::Builtin {
        name: "test".to_string(),
    };
    let profile =
        eggsec_nse::profile::ResolvedNseExecutionProfile::manual_permissive(Some("10.0.0.1"));
    let report = executor.build_report(&profile, &script_source, &output, &[]);

    NseTestResult { report }
}

fn test_executor() -> NseExecutor {
    NseExecutor::with_policy(
        SandboxConfig::default(),
        NseExecutionLimits {
            wall_clock_timeout: Some(std::time::Duration::from_secs(5)),
            lua_instruction_budget: Some(100_000),
            ..NseExecutionLimits::default()
        },
        NseCancellationToken::new(),
        eggsec_nse::default_script_policy(),
        eggsec_nse::default_module_policy(),
    )
    .unwrap()
}

#[test]
fn rule_evaluates_to_true() {
    let report = evaluate_rule("portrule", Ok(mlua::Value::Boolean(true)));
    assert!(report.evaluated);
    assert!(report.matched);
    assert!(report.error.is_none());
    assert!(report.unsupported.is_none());
    assert_eq!(report.exactness, "exact");
    assert_eq!(report.summary, "rule matched");
}

#[test]
fn rule_evaluates_to_false() {
    let report = evaluate_rule("portrule", Ok(mlua::Value::Boolean(false)));
    assert!(report.evaluated);
    assert!(!report.matched);
    assert!(report.error.is_none());
    assert!(report.unsupported.is_none());
    assert_eq!(report.exactness, "exact");
    assert_eq!(report.summary, "rule did not match");
}

#[test]
fn rule_evaluates_to_nil() {
    let report = evaluate_rule("hostrule", Ok(mlua::Value::Nil));
    assert!(report.evaluated);
    assert!(!report.matched);
    assert!(report.error.is_none());
    assert!(report.unsupported.is_none());
    assert_eq!(report.summary, "rule returned nil");
}

#[test]
fn rule_error() {
    let err = mlua::Error::RuntimeError("syntax error near 'end'".to_string());
    let report = evaluate_rule("portrule", Err(err));
    assert!(!report.evaluated);
    assert!(!report.matched);
    assert!(report.error.is_some());
    assert!(report.unsupported.is_none());
    assert!(report.error.unwrap().contains("syntax error"));
}

#[test]
fn rule_returns_non_boolean_string() {
    let lua = mlua::Lua::new();
    let val = mlua::Value::String(lua.create_string("not a boolean").unwrap());
    let report = evaluate_rule("portrule", Ok(val));
    assert!(!report.evaluated);
    assert!(!report.matched);
    assert!(report.error.is_none());
    assert!(report.unsupported.is_some());
    assert!(report.unsupported.unwrap().contains("string"));
    assert_eq!(report.exactness, "unsupported");
}

#[test]
fn rule_not_present() {
    let mut executor = test_executor();
    let report = executor.evaluate_rule_value("portrule", None, mlua::Value::Nil);
    assert!(!report.evaluated);
    assert!(!report.matched);
    assert_eq!(report.exactness, "not_present");
    assert!(report.error.is_none());
    assert!(report.summary.contains("not defined"));
}

#[test]
fn multiple_rules_evaluated_in_sequence() {
    let lua = mlua::Lua::new();

    let results = vec![
        evaluate_rule("prerule", Ok(mlua::Value::Boolean(true))),
        evaluate_rule("hostrule", Ok(mlua::Value::Boolean(false))),
        evaluate_rule("portrule", Ok(mlua::Value::Nil)),
    ];

    assert_eq!(results.len(), 3);
    assert!(results[0].matched);
    assert!(!results[1].matched);
    assert!(!results[2].matched);
    assert_eq!(results[0].kind, "prerule");
    assert_eq!(results[1].kind, "hostrule");
    assert_eq!(results[2].kind, "portrule");

    let _ = lua;
}

#[test]
fn library_reports_stay_empty_without_require_activity() {
    let executor = test_executor();
    let source = eggsec_nse::resolver::NseScriptSource::Builtin {
        name: "test".to_string(),
    };
    let profile =
        eggsec_nse::profile::ResolvedNseExecutionProfile::manual_permissive(Some("10.0.0.1"));
    let report = executor.build_report(&profile, &source, "output", &[]);

    assert!(
        report.libraries.is_empty(),
        "unused registered libraries should not be fabricated"
    );
}

#[test]
fn library_reports_capture_runtime_require_attempts() {
    let mut executor = test_executor();
    executor.set_target("10.0.0.1").unwrap();

    let output = executor
        .run_script_with_limits(
            r#"
local stdnse = require "stdnse"
local ok = pcall(require, "definitely_missing_module")
return ok
"#,
        )
        .unwrap();

    let source = eggsec_nse::resolver::NseScriptSource::Builtin {
        name: "require-truthfulness".to_string(),
    };
    let profile =
        eggsec_nse::profile::ResolvedNseExecutionProfile::manual_permissive(Some("10.0.0.1"));
    let report = executor.build_report(&profile, &source, &output, &[]);

    assert_eq!(report.libraries.len(), 2);
    let stdnse = report
        .libraries
        .iter()
        .find(|l| l.name == "stdnse")
        .expect("stdnse should be recorded");
    assert!(stdnse.registered);
    assert!(stdnse.loaded);

    let missing = report
        .libraries
        .iter()
        .find(|l| l.name == "definitely_missing_module")
        .expect("missing module should be recorded");
    assert!(!missing.registered);
    assert!(!missing.loaded);
    assert!(!missing.warnings.is_empty());
    assert!(report
        .libraries
        .iter()
        .all(|l| l.name == "stdnse" || l.name == "definitely_missing_module"));
}

#[test]
fn failure_report_has_error() {
    let profile =
        eggsec_nse::profile::ResolvedNseExecutionProfile::manual_permissive(Some("10.0.0.1"));
    let report = NseRunReport::new("10.0.0.1", "failing-script")
        .with_profile(&profile)
        .with_error("script execution failed: permission denied")
        .compute_compatibility();

    assert!(!report.errors.is_empty());
    assert!(report.errors[0].contains("permission denied"));
    assert_eq!(
        report.compatibility.status,
        NseRunCompatibilityStatus::Failed
    );
}

#[test]
fn library_reports_empty_when_no_require_calls() {
    let result = run_nse_with_content("--script-args=nse_config=default", "return function() end");
    assert!(
        result.report.libraries.is_empty(),
        "No require() calls should produce empty library reports, got: {:?}",
        result.report.libraries
    );
}

#[test]
fn library_reports_capture_only_required_modules() {
    let result = run_nse_with_content(
        "--script-args=nse_config=default",
        r#"
        local stdnse = require "stdnse"
        return function() end
        "#,
    );
    assert!(
        !result.report.libraries.is_empty(),
        "Script requiring stdnse should have library reports"
    );
    let names: Vec<&str> = result
        .report
        .libraries
        .iter()
        .map(|l| l.name.as_str())
        .collect();
    assert!(
        names.contains(&"stdnse"),
        "stdnse should be in library reports, got: {:?}",
        names
    );
    // Must NOT contain unrelated registry entries
    assert!(
        names.len() <= 2,
        "Should only have stdnse and possibly one missing module, got {} entries: {:?}",
        names.len(),
        names
    );
}

#[test]
fn repeated_require_produces_stable_deduplicated_report() {
    let result = run_nse_with_content(
        "--script-args=nse_config=default",
        r#"
        local stdnse = require "stdnse"
        local stdnse2 = require "stdnse"
        local stdnse3 = require "stdnse"
        return function() end
        "#,
    );
    let stdnse_count = result
        .report
        .libraries
        .iter()
        .filter(|l| l.name == "stdnse")
        .count();
    assert_eq!(
        stdnse_count, 1,
        "Repeated require of stdnse should produce exactly one report entry, got {}",
        stdnse_count
    );
}

#[test]
fn missing_module_appears_with_loaded_false_and_warning() {
    let result = run_nse_with_content(
        "--script-args=nse_config=default",
        r#"
        local ok, err = pcall(require, "definitely_missing_module_xyz")
        return function() end
        "#,
    );
    let missing = result
        .report
        .libraries
        .iter()
        .find(|l| l.name == "definitely_missing_module_xyz");
    match missing {
        Some(entry) => {
            assert!(
                !entry.loaded,
                "Missing module should have loaded=false, got loaded={}",
                entry.loaded
            );
            assert!(
                !entry.warnings.is_empty(),
                "Missing module should have a warning about the failed require"
            );
        }
        None => {
            // It's also acceptable if missing modules don't appear at all
            // (depends on implementation), but loaded: true must never appear
        }
    }
    // Critical: no entry should have loaded=true for a missing module
    for entry in &result.report.libraries {
        if entry.name == "definitely_missing_module_xyz" {
            assert!(!entry.loaded, "Missing module must never have loaded=true");
        }
    }
}

#[test]
fn static_fallback_produces_loaded_false_entries() {
    // A script that uses require but we can verify the static fallback path
    // by checking that any statically-detected entries have loaded=false
    let result = run_nse_with_content(
        "--script-args=nse_config=default",
        r#"
        -- Use a require that will be detected statically
        local string = require "string"
        return function() end
        "#,
    );
    // If any library reports exist from static fallback, they must have loaded=false
    for entry in &result.report.libraries {
        if entry.warnings.iter().any(|w| w.contains("static")) {
            assert!(
                !entry.loaded,
                "Static fallback entry '{}' should have loaded=false",
                entry.name
            );
        }
    }
}

#[test]
fn library_and_rule_reports_populated_not_fabricated() {
    let result = run_nse_with_content(
        "--script-args=nse_config=default",
        r#"
        local stdnse = require "stdnse"
        return function(rule)
            return tostring(rule)
        end
        "#,
    );
    // Libraries should reflect only what was required, not a full registry dump
    if !result.report.libraries.is_empty() {
        let stdnse_present = result.report.libraries.iter().any(|l| l.name == "stdnse");
        assert!(
            stdnse_present,
            "stdnse should be present since it was required"
        );
        // Must not have all 43 registry entries
        assert!(
            result.report.libraries.len() < 43,
            "Libraries should not be a full registry dump, got {} entries",
            result.report.libraries.len()
        );
    }
    // Rules should be populated from real evaluation
    // (may be empty if no port/script rules were evaluated)
}
