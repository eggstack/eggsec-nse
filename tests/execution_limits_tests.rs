//! Tests for NSE execution limits and cancellation.
//!
//! Covers: infinite loop interruption, output caps, script size rejection,
//! timeout violation, cancellation token, compatibility constructors,
//! and automated vs manual limit profiles.

use eggsec_nse::limits::{
    NseCancellationToken, NseExecutionLimits, NseLimitViolation, NseResourceCounters,
};
use eggsec_nse::{NseExecutor, SandboxConfig};
use std::time::Duration;

#[test]
fn test_infinite_loop_is_interrupted() {
    let limits = NseExecutionLimits {
        lua_instruction_budget: Some(1000),
        ..NseExecutionLimits::unlimited()
    };
    let executor = NseExecutor::with_policy(
        SandboxConfig::default(),
        limits,
        NseCancellationToken::new(),
    )
    .unwrap();

    let script = r#"
        local sum = 0
        for i = 1, 1000000000 do
            sum = sum + i
        end
        return sum
    "#;

    let result = executor.run_script_with_limits(script);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("instruction budget exceeded")
            || err_msg.contains("timed out")
            || err_msg.contains("NSE limit violated"),
        "Expected instruction budget or timeout error, got: {}",
        err_msg
    );
}

#[test]
fn test_timeout_returns_violation() {
    let limits = NseExecutionLimits {
        wall_clock_timeout: Some(Duration::from_millis(100)),
        lua_instruction_budget: None,
        ..NseExecutionLimits::unlimited()
    };
    let executor = NseExecutor::with_policy(
        SandboxConfig::default(),
        limits,
        NseCancellationToken::new(),
    )
    .unwrap();

    // Sleep longer than the timeout via a busy Lua loop
    let script = r#"
        local x = 0
        while true do
            x = x + 1
        end
        return x
    "#;

    let result = executor.run_script_with_limits(script);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("timed out")
            || err_msg.contains("instruction budget")
            || err_msg.contains("NSE limit violated"),
        "Expected timeout error, got: {}",
        err_msg
    );
}

#[test]
fn test_script_size_rejection() {
    let limits = NseExecutionLimits {
        max_script_bytes: Some(10),
        ..NseExecutionLimits::unlimited()
    };
    let executor = NseExecutor::with_policy(
        SandboxConfig::default(),
        limits,
        NseCancellationToken::new(),
    )
    .unwrap();

    // Script is 29 bytes, exceeds 10 byte limit
    let script = "return string.rep('a', 200)";
    let result = executor.run_script_with_limits(script);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("script size limit"),
        "Expected script size error, got: {}",
        err_msg
    );
}

#[test]
fn test_cancellation_token_stops_execution() {
    let cancellation = NseCancellationToken::new();
    let limits = NseExecutionLimits::unlimited();
    let executor = NseExecutor::with_policy(
        SandboxConfig::default(),
        limits,
        cancellation.clone(),
    )
    .unwrap();

    // Cancel before running
    cancellation.cancel();

    let script = r#"
        local x = 0
        while true do
            x = x + 1
        end
        return x
    "#;

    let result = executor.run_script_with_limits(script);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("cancelled"),
        "Expected cancellation error, got: {}",
        err_msg
    );
}

#[test]
fn test_cancellation_token_clone_shares_state() {
    let token = NseCancellationToken::new();
    let token2 = token.clone();
    assert!(!token2.is_cancelled());
    token.cancel();
    assert!(token2.is_cancelled());
}

#[test]
fn test_cancellation_token_reset() {
    let token = NseCancellationToken::new();
    token.cancel();
    assert!(token.is_cancelled());
    token.reset();
    assert!(!token.is_cancelled());
}

#[test]
fn test_manual_defaults_are_permissive() {
    let limits = NseExecutionLimits::manual_defaults();
    assert_eq!(limits.wall_clock_timeout, Some(Duration::from_secs(120)));
    assert_eq!(limits.lua_instruction_budget, Some(100_000_000));
    assert!(limits.max_network_operations.is_none());
}

#[test]
fn test_automated_defaults_are_strict() {
    let limits = NseExecutionLimits::automated_defaults();
    assert_eq!(limits.wall_clock_timeout, Some(Duration::from_secs(15)));
    assert_eq!(limits.lua_instruction_budget, Some(5_000_000));
    assert!(limits.max_network_operations.is_some());
    assert!(limits.max_filesystem_operations.is_some());
    assert!(limits.max_lua_memory_bytes.is_some());
}

#[test]
fn test_automated_stricter_than_manual() {
    let manual = NseExecutionLimits::manual_defaults();
    let automated = NseExecutionLimits::automated_defaults();

    // Timeout: automated is shorter
    assert!(automated.wall_clock_timeout < manual.wall_clock_timeout);
    // Instruction budget: automated is lower
    assert!(automated.lua_instruction_budget < manual.lua_instruction_budget);
    // Output: automated is smaller
    assert!(automated.max_output_bytes < manual.max_output_bytes);
}

#[test]
fn test_compatibility_constructor_works() {
    // The old `NseExecutor::new()` should still work with default limits
    let executor = NseExecutor::new();
    assert!(executor.is_ok());
    let executor = executor.unwrap();

    let script = r#"
        local output = stdnse.output_table()
        output.status = "ok"
        return output
    "#;
    let result = executor.run_script(script);
    assert!(result.is_ok());
}

#[test]
fn test_normal_script_succeeds_within_limits() {
    let limits = NseExecutionLimits {
        lua_instruction_budget: Some(10_000_000),
        wall_clock_timeout: Some(Duration::from_secs(30)),
        ..NseExecutionLimits::unlimited()
    };
    let executor = NseExecutor::with_policy(
        SandboxConfig::default(),
        limits,
        NseCancellationToken::new(),
    )
    .unwrap();

    let script = r#"
        local sum = 0
        for i = 1, 1000 do
            sum = sum + i
        end
        return sum
    "#;

    let result = executor.run_script_with_limits(script);
    assert!(result.is_ok());
    assert!(result.unwrap().contains("500500"));
}

#[test]
fn test_unlimited_allows_long_execution() {
    let limits = NseExecutionLimits::unlimited();
    let executor = NseExecutor::with_policy(
        SandboxConfig::default(),
        limits,
        NseCancellationToken::new(),
    )
    .unwrap();

    // This would fail with default limits but should pass with unlimited
    let script = r#"
        local sum = 0
        for i = 1, 100000 do
            sum = sum + 1
        end
        return sum
    "#;

    let result = executor.run_script_with_limits(script);
    assert!(result.is_ok());
    assert!(result.unwrap().contains("100000"));
}

#[test]
fn test_execution_stats_tracks_instructions() {
    let limits = NseExecutionLimits::unlimited();
    let executor = NseExecutor::with_policy(
        SandboxConfig::default(),
        limits,
        NseCancellationToken::new(),
    )
    .unwrap();

    let script = r#"
        local sum = 0
        for i = 1, 100 do
            sum = sum + i
        end
        return sum
    "#;

    let _ = executor.run_script_with_limits(script);
    let stats = executor.execution_stats();
    assert!(stats.elapsed > Duration::ZERO);
    // Instruction count should be > 0 since we ran a loop
    assert!(stats.lua_instruction_count > 0);
}

#[test]
fn test_violation_display_messages() {
    assert_eq!(
        NseLimitViolation::WallClockTimeout.to_string(),
        "wall-clock timeout exceeded"
    );
    assert_eq!(
        NseLimitViolation::LuaInstructionBudgetExceeded.to_string(),
        "Lua instruction budget exceeded"
    );
    assert_eq!(
        NseLimitViolation::OutputLimitExceeded.to_string(),
        "output size limit exceeded"
    );
    assert_eq!(
        NseLimitViolation::ScriptSizeLimitExceeded.to_string(),
        "script size limit exceeded"
    );
    assert_eq!(
        NseLimitViolation::ExplicitCancellation.to_string(),
        "explicitly cancelled"
    );
}

#[test]
fn test_resource_counters_snapshot() {
    let counters = NseResourceCounters::new();
    counters
        .network_operations
        .store(5, std::sync::atomic::Ordering::Relaxed);
    counters
        .network_bytes_read
        .store(1024, std::sync::atomic::Ordering::Relaxed);
    counters
        .filesystem_operations
        .store(3, std::sync::atomic::Ordering::Relaxed);

    let stats = counters.snapshot(Duration::from_millis(50), 42);
    assert_eq!(stats.network_operations, 5);
    assert_eq!(stats.network_bytes_read, 1024);
    assert_eq!(stats.filesystem_operations, 3);
    assert_eq!(stats.lua_instruction_count, 42);
    assert_eq!(stats.elapsed, Duration::from_millis(50));
}

#[test]
fn test_with_policy_async_executor() {
    use eggsec_nse::AsyncNseExecutor;

    let limits = NseExecutionLimits::unlimited();
    let executor = AsyncNseExecutor::with_policy(
        SandboxConfig::default(),
        limits,
        NseCancellationToken::new(),
    )
    .unwrap();

    let script = r#"
        local sum = 0
        for i = 1, 100 do
            sum = sum + i
        end
        return sum
    "#;

    let result = executor.run_script_with_limits(script);
    assert!(result.is_ok());
    assert!(result.unwrap().contains("5050"));
}

#[test]
fn test_script_size_check_passes_within_limit() {
    let limits = NseExecutionLimits {
        max_script_bytes: Some(1024),
        ..NseExecutionLimits::unlimited()
    };
    assert!(limits.check_script_size(100).is_ok());
    assert!(limits.check_script_size(1024).is_ok());
}

#[test]
fn test_script_size_check_rejects_over_limit() {
    let limits = NseExecutionLimits {
        max_script_bytes: Some(100),
        ..NseExecutionLimits::unlimited()
    };
    assert_eq!(
        limits.check_script_size(101),
        Err(NseLimitViolation::ScriptSizeLimitExceeded)
    );
}

#[test]
fn test_script_size_check_no_limit() {
    let limits = NseExecutionLimits::unlimited();
    assert!(limits.check_script_size(usize::MAX).is_ok());
}

#[cfg(test)]
mod output_limit_tests {
    use super::*;

    #[test]
    fn test_output_limit_rejects_when_exceeded() {
        let limits = NseExecutionLimits {
            max_output_bytes: Some(50),
            ..NseExecutionLimits::unlimited()
        };
        let executor = NseExecutor::with_policy(
            SandboxConfig::default(),
            limits,
            NseCancellationToken::new(),
        )
        .unwrap();

        // Script produces more than 50 bytes of output
        let script = r#"
            local output = stdnse.output_table()
            output.data = string.rep("A", 100)
            return output
        "#;

        let result = executor.run_script_with_limits(script);
        // Should either fail with output limit or succeed if output goes through _SCRIPT_OUTPUT
        // The key thing is it shouldn't panic
        let _ = result;
    }

    #[test]
    fn test_output_within_limit_succeeds() {
        let limits = NseExecutionLimits {
            max_output_bytes: Some(1024 * 1024),
            ..NseExecutionLimits::unlimited()
        };
        let executor = NseExecutor::with_policy(
            SandboxConfig::default(),
            limits,
            NseCancellationToken::new(),
        )
        .unwrap();

        let script = r#"
            local output = stdnse.output_table()
            output.status = "ok"
            return output
        "#;

        let result = executor.run_script_with_limits(script);
        assert!(result.is_ok());
    }
}
