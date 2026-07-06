//! Async NSE Executor - Tokio-based async Lua VM wrapper
//!
//! Wraps ExecutorCore and adds tokio runtime ownership for async
//! NSE script execution contexts.

use mlua::{Lua, Result as LuaResult};
use std::path::PathBuf;
use tokio::runtime::Runtime;

use crate::executor_core::ExecutorCore;
use crate::limits::{NseCancellationToken, NseExecutionLimits, NseExecutionStats};
use crate::profile::{NseExecutionProfileKind, NseModulePolicy, NseNetworkPolicy, NseScriptPolicy};
use crate::SandboxMetrics;

/// Async NSE Executor with tokio runtime support.
///
/// Composes ExecutorCore for shared Lua VM state and adds optional
/// tokio runtime ownership for callers who need to spawn async tasks.
pub struct AsyncNseExecutor {
    core: ExecutorCore,
    runtime: Option<Runtime>,
    owns_runtime: bool,
}

impl AsyncNseExecutor {
    /// Create a new async executor with its own tokio runtime.
    pub fn new() -> LuaResult<Self> {
        let runtime = Runtime::new().map_err(|e| {
            mlua::Error::RuntimeError(format!("Failed to create tokio runtime: {}", e))
        })?;
        Ok(Self {
            core: ExecutorCore::new()?,
            runtime: Some(runtime),
            owns_runtime: true,
        })
    }

    /// Create a new async executor with sandbox restrictions.
    pub fn with_sandbox(sandbox: crate::SandboxConfig) -> LuaResult<Self> {
        let runtime = Runtime::new().map_err(|e| {
            mlua::Error::RuntimeError(format!("Failed to create tokio runtime: {}", e))
        })?;
        Ok(Self {
            core: ExecutorCore::with_sandbox(sandbox)?,
            runtime: Some(runtime),
            owns_runtime: true,
        })
    }

    /// Create async executor with a specific target.
    pub fn with_target(target: &str) -> LuaResult<Self> {
        let mut exec = Self::new()?;
        exec.core.set_target(target).ok();
        Ok(exec)
    }

    /// Create async executor using an externally-managed runtime.
    /// The runtime will NOT be shut down when this executor is dropped.
    pub fn with_runtime(runtime: Runtime) -> LuaResult<Self> {
        Ok(Self {
            core: ExecutorCore::new()?,
            runtime: Some(runtime),
            owns_runtime: false,
        })
    }

    /// Create an async executor with explicit execution limits and cancellation token.
    ///
    /// # Manual-only capability context
    ///
    /// This constructor hardcodes `ManualPermissive` profile kind and
    /// `AllowAllManual` network policy in the capability context. It is
    /// intended for manual CLI/TUI surfaces where the operator is trusted
    /// to scope behavior interactively.
    ///
    /// Automated surfaces (MCP, agent, REST, daemon, CI) MUST use
    /// [`AsyncNseExecutor::with_full_policy`] or
    /// [`AsyncNseExecutor::with_profile`] so the capability engine enforces
    /// the resolved profile's `profile_kind` and `network_policy`.
    pub fn with_policy(
        sandbox: crate::SandboxConfig,
        limits: NseExecutionLimits,
        cancellation: NseCancellationToken,
        script_policy: NseScriptPolicy,
        module_policy: NseModulePolicy,
    ) -> LuaResult<Self> {
        let runtime = Runtime::new().map_err(|e| {
            mlua::Error::RuntimeError(format!("Failed to create tokio runtime: {}", e))
        })?;
        Ok(Self {
            core: ExecutorCore::with_policy(
                sandbox,
                limits,
                cancellation,
                script_policy,
                module_policy,
            )?,
            runtime: Some(runtime),
            owns_runtime: true,
        })
    }

    /// Create an async executor with explicit profile kind and network policy.
    ///
    /// This is the canonical constructor for automated surfaces. It accepts
    /// the full capability policy set (`profile_kind`, `network_policy`,
    /// sandbox, limits, script/module policies) and threads them through to
    /// the `NseCapabilityContext` so capability decisions match the resolved
    /// profile.
    ///
    /// Automated surfaces should prefer [`AsyncNseExecutor::with_profile`]
    /// (which derives these fields from a `ResolvedNseExecutionProfile`).
    pub fn with_full_policy(
        sandbox: crate::SandboxConfig,
        limits: NseExecutionLimits,
        cancellation: NseCancellationToken,
        script_policy: NseScriptPolicy,
        module_policy: NseModulePolicy,
        profile_kind: NseExecutionProfileKind,
        network_policy: NseNetworkPolicy,
    ) -> LuaResult<Self> {
        let runtime = Runtime::new().map_err(|e| {
            mlua::Error::RuntimeError(format!("Failed to create tokio runtime: {}", e))
        })?;
        Ok(Self {
            core: ExecutorCore::with_full_policy(
                sandbox,
                limits,
                cancellation,
                script_policy,
                module_policy,
                profile_kind,
                network_policy,
            )?,
            runtime: Some(runtime),
            owns_runtime: true,
        })
    }

    /// Create an async executor from a resolved execution profile.
    ///
    /// This is the preferred constructor when a profile is available.
    /// It threads the profile's `kind` and `network_policy` into the
    /// capability context so capability decisions match the resolved profile.
    pub fn with_profile(profile: &crate::profile::ResolvedNseExecutionProfile) -> LuaResult<Self> {
        let runtime = Runtime::new().map_err(|e| {
            mlua::Error::RuntimeError(format!("Failed to create tokio runtime: {}", e))
        })?;
        Ok(Self {
            core: ExecutorCore::with_profile(profile)?,
            runtime: Some(runtime),
            owns_runtime: true,
        })
    }

    /// Create async executor with policy on an externally-managed runtime.
    ///
    /// # Manual-only capability context
    ///
    /// See [`AsyncNseExecutor::with_policy`] — this constructor shares the
    /// same manual-permissive capability semantics. Automated surfaces must
    /// use [`AsyncNseExecutor::with_profile`] or
    /// [`AsyncNseExecutor::with_full_policy`].
    pub fn with_policy_and_runtime(
        sandbox: crate::SandboxConfig,
        limits: NseExecutionLimits,
        cancellation: NseCancellationToken,
        script_policy: NseScriptPolicy,
        module_policy: NseModulePolicy,
        runtime: Runtime,
    ) -> LuaResult<Self> {
        Ok(Self {
            core: ExecutorCore::with_policy(
                sandbox,
                limits,
                cancellation,
                script_policy,
                module_policy,
            )?,
            runtime: Some(runtime),
            owns_runtime: false,
        })
    }

    /// Set the target host.
    pub fn set_target(&mut self, target: &str) {
        self.core.set_target(target).ok();
    }

    /// Get the target host.
    pub fn get_target(&self) -> &str {
        self.core.target()
    }

    /// Add a scripts search path.
    pub fn add_scripts_path(&self, path: PathBuf) {
        self.core.add_scripts_path(path);
    }

    /// Run an NSE script synchronously.
    pub fn run_script(&self, script: &str) -> LuaResult<String> {
        self.core.run_script(script)
    }

    /// Run a script with the configured execution limits.
    pub fn run_script_with_limits(&self, script: &str) -> LuaResult<String> {
        self.core.run_script(script)
    }

    /// Get the execution stats from the last run.
    pub fn execution_stats(&self) -> NseExecutionStats {
        self.core.execution_stats()
    }

    /// Get a reference to the cancellation token.
    pub fn cancellation_token(&self) -> &NseCancellationToken {
        self.core.cancellation_token()
    }

    /// Get a reference to the execution limits.
    pub fn limits(&self) -> &NseExecutionLimits {
        self.core.limits()
    }

    /// Get access to the underlying Lua VM.
    pub fn lua(&self) -> &Lua {
        self.core.lua()
    }

    pub fn get_sandbox_metrics(&self) -> SandboxMetrics {
        self.core.get_sandbox_metrics()
    }

    /// Get a reference to the executor's capability context.
    pub fn capability_context(&self) -> &crate::capabilities::NseCapabilityContext {
        self.core.capability_context()
    }

    /// Get all recorded capability events.
    pub fn capability_events(&self) -> Vec<crate::capabilities::NseCapabilityEvent> {
        self.core.capability_context().events()
    }

    /// Get access to the tokio runtime, if available.
    pub fn runtime(&self) -> Option<&Runtime> {
        self.runtime.as_ref()
    }
}

impl Drop for AsyncNseExecutor {
    fn drop(&mut self) {
        if self.owns_runtime {
            if let Some(runtime) = self.runtime.take() {
                runtime.shutdown_timeout(std::time::Duration::from_secs(5));
            }
        }
    }
}

impl Default for AsyncNseExecutor {
    fn default() -> Self {
        match Self::new() {
            Ok(executor) => executor,
            Err(e) => {
                tracing::error!("Lua VM initialization failed: {}", e);
                panic!("Lua VM initialization failed: {}", e);
            }
        }
    }
}
