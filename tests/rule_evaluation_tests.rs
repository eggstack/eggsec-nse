use eggsec_nse::limits::{NseCancellationToken, NseExecutionLimits};
use eggsec_nse::report::*;
use eggsec_nse::{NseExecutor, SandboxConfig};

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
fn library_reports_populated_from_registry() {
    let executor = test_executor();
    let source = eggsec_nse::resolver::NseScriptSource::Builtin {
        name: "test".to_string(),
    };
    let profile =
        eggsec_nse::profile::ResolvedNseExecutionProfile::manual_permissive(Some("10.0.0.1"));
    let report = executor.build_report(&profile, &source, "output", &[]);

    assert!(!report.libraries.is_empty());
    assert!(
        report.libraries.iter().any(|l| l.name == "stdnse"),
        "expected stdnse in library reports"
    );
    assert!(
        report.libraries.iter().all(|l| l.registered),
        "all libraries should be registered"
    );
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
