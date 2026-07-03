//! NSE execution limits and cancellation support.
//!
//! Provides structured limits for bounding NSE script execution across
//! wall-clock time, Lua instruction count, output size, and resource usage.
//! Includes a cancellation token for cooperative interruption and a
//! structured violation type for identifying which limit was breached.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Execution limits for NSE script runs.
///
/// All fields are optional. `None` means no limit is enforced for that dimension.
/// Manual/default constructors set permissive defaults; automated surfaces
/// (MCP, agent, REST, daemon) should select stricter profiles.
#[derive(Debug, Clone)]
pub struct NseExecutionLimits {
    /// Maximum wall-clock time for the entire script execution.
    pub wall_clock_timeout: Option<Duration>,
    /// Maximum Lua instructions before the VM is interrupted.
    /// Checked via a debug hook that fires every N instructions.
    pub lua_instruction_budget: Option<u64>,
    /// Maximum total output bytes (string output + table output rendered to text).
    pub max_output_bytes: Option<usize>,
    /// Maximum script source size in bytes (rejected before evaluation).
    pub max_script_bytes: Option<usize>,
    /// Maximum size of a single required module in bytes.
    pub max_required_module_bytes: Option<usize>,
    /// Maximum number of network operations (connect, send, receive).
    pub max_network_operations: Option<u64>,
    /// Maximum total bytes read from network operations.
    pub max_network_bytes_read: Option<u64>,
    /// Maximum total bytes written to network operations.
    pub max_network_bytes_written: Option<u64>,
    /// Maximum number of filesystem operations (open, read, write, etc.).
    pub max_filesystem_operations: Option<u64>,
    /// Maximum total bytes read from filesystem operations.
    pub max_filesystem_bytes_read: Option<u64>,
    /// Maximum Lua memory usage in bytes (best-effort, runtime-dependent).
    pub max_lua_memory_bytes: Option<usize>,
}

impl Default for NseExecutionLimits {
    fn default() -> Self {
        Self {
            wall_clock_timeout: Some(Duration::from_secs(30)),
            lua_instruction_budget: Some(10_000_000),
            max_output_bytes: Some(10 * 1024 * 1024), // 10 MiB
            max_script_bytes: Some(5 * 1024 * 1024),  // 5 MiB
            max_required_module_bytes: Some(2 * 1024 * 1024), // 2 MiB
            max_network_operations: None,
            max_network_bytes_read: None,
            max_network_bytes_written: None,
            max_filesystem_operations: None,
            max_filesystem_bytes_read: None,
            max_lua_memory_bytes: None,
        }
    }
}

impl NseExecutionLimits {
    /// Permissive limits suitable for manual/interactive CLI use.
    /// Longer timeout, higher instruction budget, larger output cap.
    pub fn manual_defaults() -> Self {
        Self {
            wall_clock_timeout: Some(Duration::from_secs(120)),
            lua_instruction_budget: Some(100_000_000),
            max_output_bytes: Some(50 * 1024 * 1024), // 50 MiB
            max_script_bytes: Some(10 * 1024 * 1024), // 10 MiB
            max_required_module_bytes: Some(5 * 1024 * 1024),
            max_network_operations: None,
            max_network_bytes_read: None,
            max_network_bytes_written: None,
            max_filesystem_operations: None,
            max_filesystem_bytes_read: None,
            max_lua_memory_bytes: None,
        }
    }

    /// Strict limits suitable for automated surfaces (MCP, agent, REST, daemon).
    pub fn automated_defaults() -> Self {
        Self {
            wall_clock_timeout: Some(Duration::from_secs(15)),
            lua_instruction_budget: Some(5_000_000),
            max_output_bytes: Some(2 * 1024 * 1024), // 2 MiB
            max_script_bytes: Some(1024 * 1024),     // 1 MiB
            max_required_module_bytes: Some(512 * 1024),
            max_network_operations: Some(100),
            max_network_bytes_read: Some(10 * 1024 * 1024),
            max_network_bytes_written: Some(10 * 1024 * 1024),
            max_filesystem_operations: Some(50),
            max_filesystem_bytes_read: Some(5 * 1024 * 1024),
            max_lua_memory_bytes: Some(64 * 1024 * 1024),
        }
    }

    /// No limits at all (use with extreme caution).
    pub fn unlimited() -> Self {
        Self {
            wall_clock_timeout: None,
            lua_instruction_budget: None,
            max_output_bytes: None,
            max_script_bytes: None,
            max_required_module_bytes: None,
            max_network_operations: None,
            max_network_bytes_read: None,
            max_network_bytes_written: None,
            max_filesystem_operations: None,
            max_filesystem_bytes_read: None,
            max_lua_memory_bytes: None,
        }
    }

    /// Check whether a script source exceeds the size limit before evaluation.
    pub fn check_script_size(&self, script_bytes: usize) -> Result<(), NseLimitViolation> {
        if let Some(max) = self.max_script_bytes {
            if script_bytes > max {
                return Err(NseLimitViolation::ScriptSizeLimitExceeded);
            }
        }
        Ok(())
    }
}

/// Identifies which execution limit was breached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NseLimitViolation {
    WallClockTimeout,
    LuaInstructionBudgetExceeded,
    OutputLimitExceeded,
    ScriptSizeLimitExceeded,
    ModuleSizeLimitExceeded,
    NetworkOperationLimitExceeded,
    NetworkByteLimitExceeded,
    FilesystemOperationLimitExceeded,
    FilesystemByteLimitExceeded,
    ExplicitCancellation,
}

impl std::fmt::Display for NseLimitViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WallClockTimeout => write!(f, "wall-clock timeout exceeded"),
            Self::LuaInstructionBudgetExceeded => write!(f, "Lua instruction budget exceeded"),
            Self::OutputLimitExceeded => write!(f, "output size limit exceeded"),
            Self::ScriptSizeLimitExceeded => write!(f, "script size limit exceeded"),
            Self::ModuleSizeLimitExceeded => write!(f, "required module size limit exceeded"),
            Self::NetworkOperationLimitExceeded => write!(f, "network operation limit exceeded"),
            Self::NetworkByteLimitExceeded => write!(f, "network byte limit exceeded"),
            Self::FilesystemOperationLimitExceeded => {
                write!(f, "filesystem operation limit exceeded")
            }
            Self::FilesystemByteLimitExceeded => write!(f, "filesystem byte limit exceeded"),
            Self::ExplicitCancellation => write!(f, "explicitly cancelled"),
        }
    }
}

impl std::error::Error for NseLimitViolation {}

/// Cooperative cancellation token shared between the Rust executor and Lua VM.
///
/// Wraps an `Arc<AtomicBool>`. Check `is_cancelled()` before starting new
/// work; call `cancel()` to request shutdown.
#[derive(Debug, Clone)]
pub struct NseCancellationToken {
    inner: Arc<AtomicBool>,
}

impl NseCancellationToken {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.inner.store(true, Ordering::Release);
    }

    /// Check whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.inner.load(Ordering::Acquire)
    }

    /// Reset the token (useful for reusing across runs).
    pub fn reset(&self) {
        self.inner.store(false, Ordering::Release);
    }
}

impl Default for NseCancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Runtime counters collected during a script execution run.
///
/// Updated by the executor and Lua debug hook. Returned alongside the
/// script result to give callers visibility into resource consumption.
#[derive(Debug, Clone, Default)]
pub struct NseExecutionStats {
    pub elapsed: Duration,
    pub output_bytes: usize,
    pub lua_instruction_count: u64,
    pub network_operations: u64,
    pub network_bytes_read: u64,
    pub network_bytes_written: u64,
    pub filesystem_operations: u64,
    pub filesystem_bytes_read: u64,
    pub limit_violation: Option<NseLimitViolation>,
}

/// Shared atomic counters for Rust-side resource tracking during execution.
///
/// These are checked by library helpers (socket, io, lfs, os) to enforce
/// network and filesystem limits. Stored inside `ExecutorCore` and passed
/// to library registration functions.
#[derive(Debug)]
pub struct NseResourceCounters {
    pub network_operations: AtomicU64,
    pub network_bytes_read: AtomicU64,
    pub network_bytes_written: AtomicU64,
    pub filesystem_operations: AtomicU64,
    pub filesystem_bytes_read: AtomicU64,
    pub output_bytes: AtomicU64,
}

impl NseResourceCounters {
    pub fn new() -> Self {
        Self {
            network_operations: AtomicU64::new(0),
            network_bytes_read: AtomicU64::new(0),
            network_bytes_written: AtomicU64::new(0),
            filesystem_operations: AtomicU64::new(0),
            filesystem_bytes_read: AtomicU64::new(0),
            output_bytes: AtomicU64::new(0),
        }
    }

    /// Snapshot the current counter values into an `NseExecutionStats`.
    pub fn snapshot(&self, elapsed: Duration, lua_instruction_count: u64) -> NseExecutionStats {
        NseExecutionStats {
            elapsed,
            output_bytes: self.output_bytes.load(Ordering::Relaxed) as usize,
            lua_instruction_count,
            network_operations: self.network_operations.load(Ordering::Relaxed),
            network_bytes_read: self.network_bytes_read.load(Ordering::Relaxed),
            network_bytes_written: self.network_bytes_written.load(Ordering::Relaxed),
            filesystem_operations: self.filesystem_operations.load(Ordering::Relaxed),
            filesystem_bytes_read: self.filesystem_bytes_read.load(Ordering::Relaxed),
            limit_violation: None,
        }
    }
}

impl Default for NseResourceCounters {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn test_script_size_check_passes() {
        let limits = NseExecutionLimits::default();
        assert!(limits.check_script_size(100).is_ok());
    }

    #[test]
    fn test_script_size_check_rejects() {
        let limits = NseExecutionLimits {
            max_script_bytes: Some(100),
            ..Default::default()
        };
        assert_eq!(
            limits.check_script_size(101),
            Err(NseLimitViolation::ScriptSizeLimitExceeded)
        );
    }

    #[test]
    fn test_cancellation_token() {
        let token = NseCancellationToken::new();
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
        token.reset();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn test_cancellation_token_clone() {
        let token = NseCancellationToken::new();
        let token2 = token.clone();
        token.cancel();
        assert!(token2.is_cancelled());
    }

    #[test]
    fn test_violation_display() {
        assert_eq!(
            NseLimitViolation::WallClockTimeout.to_string(),
            "wall-clock timeout exceeded"
        );
        assert_eq!(
            NseLimitViolation::ExplicitCancellation.to_string(),
            "explicitly cancelled"
        );
    }

    #[test]
    fn test_resource_counters_snapshot() {
        let counters = NseResourceCounters::new();
        counters.network_operations.store(5, Ordering::Relaxed);
        counters.network_bytes_read.store(1024, Ordering::Relaxed);
        let stats = counters.snapshot(Duration::from_millis(100), 42);
        assert_eq!(stats.network_operations, 5);
        assert_eq!(stats.network_bytes_read, 1024);
        assert_eq!(stats.lua_instruction_count, 42);
        assert_eq!(stats.elapsed, Duration::from_millis(100));
    }

    #[test]
    fn test_unlimited_has_no_limits() {
        let limits = NseExecutionLimits::unlimited();
        assert!(limits.wall_clock_timeout.is_none());
        assert!(limits.lua_instruction_budget.is_none());
        assert!(limits.max_output_bytes.is_none());
        assert!(limits.max_script_bytes.is_none());
    }
}
