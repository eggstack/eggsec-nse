//! M005A provider/broker foundation integration tests.
//!
//! Proves injected clock/random/environment providers drive real NSE
//! execution through the canonical `execute_nse_run` pipeline while
//! capability/cancellation/accounting semantics stay centralized.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use eggsec_nse::resolver::NseScriptSource;
use eggsec_nse::{
    execute_nse_run, CountingEnvironmentProvider, CountingRandomProvider,
    DeterministicRandomProvider, FixedClockProvider, MapEnvironmentProvider, NseHostServices,
    NseRunRequest, ResolvedNseExecutionProfile,
};

fn manual_profile() -> ResolvedNseExecutionProfile {
    ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"))
}

fn inline_script(label: &str, body: &str) -> NseScriptSource {
    NseScriptSource::InlineManual {
        label: label.to_string(),
        content: body.to_string(),
    }
}

#[test]
fn fixed_clock_drives_datetime_now() {
    let fixed: i64 = 1_700_000_000;
    let services = NseHostServices::native().with_clock(Arc::new(FixedClockProvider::new(fixed)));
    let script = r#"
hostrule = function(host) return true end
action = function(host, port) return tostring(datetime.now()) end
"#;
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("fixed-clock", script),
        manual_profile(),
    )
    .with_host_services(services);
    let report = execute_nse_run(request).expect("fixed-clock run succeeds");
    assert!(
        report.output.content.contains(&fixed.to_string()),
        "injected clock must drive datetime.now, got: {}",
        report.output.content
    );
    assert!(
        report
            .capability_events
            .iter()
            .any(|e| e.kind == "time_clock" && e.allowed),
        "time-clock capability event must be recorded"
    );
}

#[test]
fn deterministic_random_drives_rand_bytes() {
    // Two runs with the same deterministic stream must observe the same bytes.
    let script = r#"
hostrule = function(host) return true end
action = function(host, port)
  local b = rand.bytes(8)
  local parts = {}
  for i = 1, #b do parts[#parts + 1] = tostring(b[i]) end
  return table.concat(parts, ",")
end
"#;
    let run_once = || {
        let services = NseHostServices::native()
            .with_random(Arc::new(DeterministicRandomProvider::new(vec![9u8])));
        let request = NseRunRequest::new(
            "127.0.0.1",
            inline_script("deterministic-rand", script),
            manual_profile(),
        )
        .with_host_services(services);
        execute_nse_run(request)
            .expect("deterministic run succeeds")
            .output
            .content
    };
    let first = run_once();
    let second = run_once();
    assert_eq!(first, second, "deterministic provider must replay");
    assert!(
        first.contains("9"),
        "deterministic pattern must be observable, got: {first}"
    );
}

#[test]
fn map_environment_drives_os_getenv() {
    let mut vars = HashMap::new();
    vars.insert(
        "EGGSEC_PROVIDER_TEST".to_string(),
        "injected-value".to_string(),
    );
    let services = NseHostServices::native().with_environment(Arc::new(
        MapEnvironmentProvider::new(vars, PathBuf::from("/tmp")),
    ));
    let script = r#"
hostrule = function(host) return true end
action = function(host, port) return os.getenv("EGGSEC_PROVIDER_TEST") end
"#;
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("map-env", script),
        manual_profile(),
    )
    .with_host_services(services);
    let report = execute_nse_run(request).expect("map-env run succeeds");
    assert!(
        report.output.content.contains("injected-value"),
        "injected env must drive os.getenv, got: {}",
        report.output.content
    );
}

#[test]
fn existing_callers_keep_native_behavior_without_injection() {
    // No with_host_services: must compile and run with native defaults.
    let script = r#"
hostrule = function(host) return true end
action = function(host, port)
  local t = datetime.now()
  return tostring(type(t))
end
"#;
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("native-default", script),
        manual_profile(),
    );
    let report = execute_nse_run(request).expect("native-default run succeeds");
    assert!(
        report.output.content.contains("number"),
        "native datetime.now must return a number type, got: {}",
        report.output.content
    );
}

#[test]
fn ci_safe_random_denied_without_touching_provider() {
    let counting = Arc::new(CountingRandomProvider::new(vec![1u8]));
    let services = NseHostServices::native()
        .with_random(counting.clone() as Arc<dyn eggsec_nse::NseRandomProvider>);
    let script = r#"
hostrule = function(host) return true end
action = function(host, port)
  local b = rand.bytes(4)
  return "should-not-reach"
end
"#;
    let profile = ResolvedNseExecutionProfile::ci_safe();
    let request = NseRunRequest::new("127.0.0.1", inline_script("ci-deny-rand", script), profile)
        .with_host_services(services);
    // Denial surfaces either as an execution error or as a completed run
    // carrying a denied capability event; either way the provider must not
    // have been invoked and the output must not contain the success marker.
    match execute_nse_run(request) {
        Err(e) => {
            assert!(
                e.to_string().contains("denied")
                    || e.to_string().contains("CI safe")
                    || e.to_string().contains("Randomness"),
                "unexpected CiSafe error: {e}"
            );
        }
        Ok(report) => {
            assert!(
                !report.output.content.contains("should-not-reach"),
                "denied randomness must not produce success output: {}",
                report.output.content
            );
            assert!(
                report
                    .capability_events
                    .iter()
                    .any(|ev| ev.kind == "randomness" && !ev.allowed),
                "denied randomness event must be recorded"
            );
        }
    }
    assert_eq!(
        counting.calls(),
        0,
        "denied operation must not invoke the provider"
    );
}

#[test]
fn ci_safe_environment_denied_without_touching_provider() {
    let counting = Arc::new(CountingEnvironmentProvider::new(
        HashMap::new(),
        PathBuf::from("/tmp"),
    ));
    let services = NseHostServices::native()
        .with_environment(counting.clone() as Arc<dyn eggsec_nse::NseEnvironmentProvider>);
    // Direct broker check proves denial precedes provider invocation even
    // when Lua maps denial to an empty string.
    let ctx_profile = ResolvedNseExecutionProfile::ci_safe();
    let ctx = eggsec_nse::NseCapabilityContext::new(
        ctx_profile.kind,
        ctx_profile.network_policy.clone(),
        ctx_profile.script_policy.clone(),
        ctx_profile.module_policy.clone(),
        ctx_profile.sandbox.clone(),
        ctx_profile.limits.clone(),
        eggsec_nse::NseCancellationToken::new(),
        Arc::new(eggsec_nse::NseResourceCounters::default()),
    );
    let err = eggsec_nse::broker_env_var(&ctx, &services, "HOME", "test.getenv").unwrap_err();
    assert!(err.contains("CI safe") || err.contains("denied"), "{err}");
    assert_eq!(counting.calls(), 0);
}

#[test]
fn concurrent_runs_isolate_provider_state() {
    let script = r#"
hostrule = function(host) return true end
action = function(host, port) return tostring(datetime.now()) end
"#;
    let run_with = |ts: i64| {
        let services = NseHostServices::native().with_clock(Arc::new(FixedClockProvider::new(ts)));
        let request = NseRunRequest::new(
            "127.0.0.1",
            inline_script("concurrent-clock", script),
            manual_profile(),
        )
        .with_host_services(services);
        execute_nse_run(request)
            .expect("concurrent run succeeds")
            .output
            .content
    };
    let first = std::thread::spawn(move || run_with(1_111_111_111));
    let second = std::thread::spawn(move || run_with(2_222_222_222));
    let a = first.join().expect("thread a");
    let b = second.join().expect("thread b");
    assert!(a.contains("1111111111"), "run A isolated, got: {a}");
    assert!(b.contains("2222222222"), "run B isolated, got: {b}");
}

#[test]
fn provider_bundle_clones_per_run() {
    let a = NseHostServices::native().with_clock(Arc::new(FixedClockProvider::new(1)));
    let b = NseHostServices::native().with_clock(Arc::new(FixedClockProvider::new(2)));
    assert_ne!(
        a.clock().unix_timestamp().unwrap(),
        b.clock().unix_timestamp().unwrap()
    );
}
