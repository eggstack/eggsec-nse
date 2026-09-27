//! Per-run host providers for deterministic NSE execution.
//!
//! ADR-0003 boundary: narrow provider traits by host domain, a lightweight
//! per-run composition bundle (`NseHostServices`), native defaults, additive
//! injection through [`crate::run::NseRunRequest`], and capability-aware
//! broker functions that own policy/preflight/provider/accounting/event
//! sequencing.
//!
//! This slice covers clock, randomness, and environment reads only. Network,
//! DNS, HTTP, filesystem-handle, and process execution remain out of scope
//! (later M005 slices). Providers never authorize Eggsec operations and never
//! override [`crate::capabilities::NseCapabilityContext`] policy.
//!
//! Native providers may use `std`/`chrono`/`rand` internally. Migrated NSE
//! libraries must go through the broker functions below, never direct
//! `SystemTime`/`rand::random`/`std::env` calls.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::capabilities::{NseCapabilityContext, NseCapabilityKind, NseCapabilityRequest};

/// Runtime-owned provider failure.
///
/// Providers report transport-neutral failures; the broker maps them to the
/// same class of Lua/runtime error the native operation produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NseProviderError {
    /// Short machine-readable kind (e.g. `clock`, `random`, `environment`).
    pub kind: &'static str,
    /// Human-readable cause (no secrets).
    pub message: String,
}

impl NseProviderError {
    /// Build a provider error.
    pub fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for NseProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NSE {} provider failed: {}", self.kind, self.message)
    }
}

impl std::error::Error for NseProviderError {}

// ---------------------------------------------------------------------------
// Narrow provider traits (composition, not a monolithic host trait).
// ---------------------------------------------------------------------------

/// Clock/time reads.
///
/// Returns Unix timestamps. Native implementation reads system time;
/// deterministic tests inject a fixed value.
pub trait NseClockProvider: Send + Sync {
    /// Current Unix timestamp in seconds.
    fn unix_timestamp(&self) -> Result<i64, NseProviderError>;
}

/// Randomness.
///
/// Byte-oriented so deterministic tests can replay one stream. Provided
/// helpers derive scalar values without additional provider surface.
pub trait NseRandomProvider: Send + Sync {
    /// Fill `out` with random bytes.
    fn fill_bytes(&self, out: &mut [u8]) -> Result<(), NseProviderError>;

    /// One random `u32` derived from [`Self::fill_bytes`].
    fn random_u32(&self) -> Result<u32, NseProviderError> {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// One random `f64` in `[0, 1)` derived from [`Self::fill_bytes`].
    fn random_f64(&self) -> Result<f64, NseProviderError> {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf)?;
        let v = u64::from_le_bytes(buf) >> 11;
        Ok((v as f64) / ((1u64 << 53) as f64))
    }
}

/// Environment variable reads and env-derived path lookup.
///
/// Only reads needed by runtime setup are exposed (`var`, `temp_dir`).
/// Writes (`setenv`/`unsetenv`) remain NSE-library state, not provider state.
pub trait NseEnvironmentProvider: Send + Sync {
    /// Read one variable. `Ok(None)` means unset.
    fn var(&self, name: &str) -> Result<Option<String>, NseProviderError>;

    /// Env-derived temporary directory.
    fn temp_dir(&self) -> Result<PathBuf, NseProviderError>;
}

// ---------------------------------------------------------------------------
// Native implementations (default behavior, unchanged for existing callers).
// ---------------------------------------------------------------------------

/// Native clock backed by `chrono`/`SystemTime`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeClockProvider;

impl NseClockProvider for NativeClockProvider {
    fn unix_timestamp(&self) -> Result<i64, NseProviderError> {
        Ok(chrono::Utc::now().timestamp())
    }
}

/// Native randomness backed by `rand`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeRandomProvider;

impl NseRandomProvider for NativeRandomProvider {
    fn fill_bytes(&self, out: &mut [u8]) -> Result<(), NseProviderError> {
        for b in out.iter_mut() {
            *b = rand::random::<u8>();
        }
        Ok(())
    }
}

/// Native environment backed by `std::env`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeEnvironmentProvider;

impl NseEnvironmentProvider for NativeEnvironmentProvider {
    fn var(&self, name: &str) -> Result<Option<String>, NseProviderError> {
        Ok(std::env::var(name).ok())
    }

    fn temp_dir(&self) -> Result<PathBuf, NseProviderError> {
        Ok(std::env::temp_dir())
    }
}

// ---------------------------------------------------------------------------
// Per-run service bundle (composition object, Arc-backed, cloneable).
// ---------------------------------------------------------------------------

/// Lightweight per-run host-service bundle.
///
/// Carries only the M005A domains today; later M005 slices extend this struct
/// with additional provider fields. Cloning shares the underlying providers
/// (cheap `Arc` clones) so concurrent runs can hold different bundles without
/// process-global state.
#[derive(Clone)]
pub struct NseHostServices {
    clock: Arc<dyn NseClockProvider>,
    random: Arc<dyn NseRandomProvider>,
    environment: Arc<dyn NseEnvironmentProvider>,
}

impl std::fmt::Debug for NseHostServices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NseHostServices")
            .field("has_clock", &true)
            .field("has_random", &true)
            .field("has_environment", &true)
            .finish()
    }
}

impl Default for NseHostServices {
    fn default() -> Self {
        Self::native()
    }
}

impl NseHostServices {
    /// Native defaults (preserves pre-provider behavior).
    pub fn native() -> Self {
        Self {
            clock: Arc::new(NativeClockProvider),
            random: Arc::new(NativeRandomProvider),
            environment: Arc::new(NativeEnvironmentProvider),
        }
    }

    /// Build from explicit providers.
    pub fn new(
        clock: Arc<dyn NseClockProvider>,
        random: Arc<dyn NseRandomProvider>,
        environment: Arc<dyn NseEnvironmentProvider>,
    ) -> Self {
        Self {
            clock,
            random,
            environment,
        }
    }

    /// Replace the clock provider.
    pub fn with_clock(mut self, provider: Arc<dyn NseClockProvider>) -> Self {
        self.clock = provider;
        self
    }

    /// Replace the randomness provider.
    pub fn with_random(mut self, provider: Arc<dyn NseRandomProvider>) -> Self {
        self.random = provider;
        self
    }

    /// Replace the environment provider.
    pub fn with_environment(mut self, provider: Arc<dyn NseEnvironmentProvider>) -> Self {
        self.environment = provider;
        self
    }

    /// Borrow the clock provider.
    pub fn clock(&self) -> &Arc<dyn NseClockProvider> {
        &self.clock
    }

    /// Borrow the randomness provider.
    pub fn random(&self) -> &Arc<dyn NseRandomProvider> {
        &self.random
    }

    /// Borrow the environment provider.
    pub fn environment(&self) -> &Arc<dyn NseEnvironmentProvider> {
        &self.environment
    }
}

// ---------------------------------------------------------------------------
// Deterministic test providers (public so downstream harnesses can reuse).
// ---------------------------------------------------------------------------

/// Fixed clock returning one timestamp.
pub struct FixedClockProvider {
    timestamp: AtomicI64,
}

impl FixedClockProvider {
    /// Build a fixed clock.
    pub fn new(timestamp: i64) -> Self {
        Self {
            timestamp: AtomicI64::new(timestamp),
        }
    }
}

impl NseClockProvider for FixedClockProvider {
    fn unix_timestamp(&self) -> Result<i64, NseProviderError> {
        Ok(self.timestamp.load(Ordering::SeqCst))
    }
}

/// Deterministic byte-stream randomness.
///
/// Emits a repeating caller-supplied pattern (or an incrementing counter when
/// empty), so injected scripts observe stable values per run.
pub struct DeterministicRandomProvider {
    pattern: Vec<u8>,
    cursor: Mutex<usize>,
}

impl DeterministicRandomProvider {
    /// Build from a repeating pattern. Empty pattern uses a counter stream.
    pub fn new(pattern: Vec<u8>) -> Self {
        Self {
            pattern,
            cursor: Mutex::new(0),
        }
    }
}

impl NseRandomProvider for DeterministicRandomProvider {
    fn fill_bytes(&self, out: &mut [u8]) -> Result<(), NseProviderError> {
        let mut cursor = self.cursor.lock().map_err(|e| {
            NseProviderError::new("random", format!("deterministic RNG lock failed: {e}"))
        })?;
        for (i, slot) in out.iter_mut().enumerate() {
            if self.pattern.is_empty() {
                *slot = ((*cursor + i) % 256) as u8;
            } else {
                *slot = self.pattern[(*cursor + i) % self.pattern.len()];
            }
        }
        *cursor = cursor.wrapping_add(out.len());
        Ok(())
    }
}

/// Map-backed environment.
pub struct MapEnvironmentProvider {
    vars: HashMap<String, String>,
    temp_dir: PathBuf,
}

impl MapEnvironmentProvider {
    /// Build from a variable map and an explicit temp dir.
    pub fn new(vars: HashMap<String, String>, temp_dir: PathBuf) -> Self {
        Self { vars, temp_dir }
    }
}

impl NseEnvironmentProvider for MapEnvironmentProvider {
    fn var(&self, name: &str) -> Result<Option<String>, NseProviderError> {
        Ok(self.vars.get(name).cloned())
    }

    fn temp_dir(&self) -> Result<PathBuf, NseProviderError> {
        Ok(self.temp_dir.clone())
    }
}

/// Counting clock wrapper proving denial prevents provider invocation.
pub struct CountingClockProvider {
    inner: FixedClockProvider,
    calls: AtomicU64,
}

impl CountingClockProvider {
    /// Build a counting wrapper around a fixed timestamp.
    pub fn new(timestamp: i64) -> Self {
        Self {
            inner: FixedClockProvider::new(timestamp),
            calls: AtomicU64::new(0),
        }
    }

    /// Number of provider invocations observed.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl NseClockProvider for CountingClockProvider {
    fn unix_timestamp(&self) -> Result<i64, NseProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.unix_timestamp()
    }
}

/// Counting randomness wrapper.
pub struct CountingRandomProvider {
    inner: DeterministicRandomProvider,
    calls: AtomicU64,
}

impl CountingRandomProvider {
    /// Build a counting wrapper around a deterministic stream.
    pub fn new(pattern: Vec<u8>) -> Self {
        Self {
            inner: DeterministicRandomProvider::new(pattern),
            calls: AtomicU64::new(0),
        }
    }

    /// Number of provider invocations observed.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl NseRandomProvider for CountingRandomProvider {
    fn fill_bytes(&self, out: &mut [u8]) -> Result<(), NseProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.fill_bytes(out)
    }
}

/// Counting environment wrapper.
pub struct CountingEnvironmentProvider {
    inner: MapEnvironmentProvider,
    calls: AtomicU64,
}

impl CountingEnvironmentProvider {
    /// Build a counting wrapper around a variable map.
    pub fn new(vars: HashMap<String, String>, temp_dir: PathBuf) -> Self {
        Self {
            inner: MapEnvironmentProvider::new(vars, temp_dir),
            calls: AtomicU64::new(0),
        }
    }

    /// Number of provider invocations observed.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl NseEnvironmentProvider for CountingEnvironmentProvider {
    fn var(&self, name: &str) -> Result<Option<String>, NseProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.var(name)
    }

    fn temp_dir(&self) -> Result<PathBuf, NseProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.temp_dir()
    }
}

// ---------------------------------------------------------------------------
// Capability-aware broker functions.
//
// Sequence (ADR-0003):
//   capability decision -> cancellation/resource preflight -> provider
//   operation -> resource accounting -> event/report result.
//
// Denial or cancellation never reaches the provider.
// ---------------------------------------------------------------------------

fn broker_request(
    kind: NseCapabilityKind,
    target: Option<String>,
    bytes_hint: Option<u64>,
    operation: &'static str,
) -> NseCapabilityRequest {
    NseCapabilityRequest {
        kind,
        target,
        bytes_hint,
        operation,
    }
}

fn deny_message(decision: &crate::capabilities::NseCapabilityDecision, fallback: &str) -> String {
    decision.deny_reason().unwrap_or(fallback).to_string()
}

/// Brokered Unix timestamp.
///
/// Denied or cancelled callers receive an error and the provider is not
/// invoked. Success records the standard capability event/counters.
pub fn broker_unix_timestamp(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    operation: &'static str,
) -> Result<i64, String> {
    ctx.check_cancelled(operation)?;
    let request = broker_request(NseCapabilityKind::TimeClock, None, None, operation);
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "time clock access denied"));
    }
    ctx.before_blocking_operation(&request)?;
    let value = services
        .clock()
        .unix_timestamp()
        .map_err(|e| format!("clock provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(value)
}

/// Brokered random fill.
///
/// `out.len()` is used as the bytes hint for accounting parity with the
/// existing `wrapper.random_bytes` path.
pub fn broker_random_fill(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    out: &mut [u8],
    operation: &'static str,
) -> Result<(), String> {
    ctx.check_cancelled(operation)?;
    let request = broker_request(
        NseCapabilityKind::Randomness,
        None,
        Some(out.len() as u64),
        operation,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "randomness generation denied"));
    }
    ctx.before_blocking_operation(&request)?;
    services
        .random()
        .fill_bytes(out)
        .map_err(|e| format!("random provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, Some(out.len() as u64));
    Ok(())
}

/// Brokered random `f64` in `[0, 1)`.
pub fn broker_random_f64(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    operation: &'static str,
) -> Result<f64, String> {
    ctx.check_cancelled(operation)?;
    let request = broker_request(NseCapabilityKind::Randomness, None, None, operation);
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "randomness generation denied"));
    }
    ctx.before_blocking_operation(&request)?;
    let value = services
        .random()
        .random_f64()
        .map_err(|e| format!("random provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(value)
}

/// Brokered random `u32`.
pub fn broker_random_u32(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    operation: &'static str,
) -> Result<u32, String> {
    ctx.check_cancelled(operation)?;
    let request = broker_request(NseCapabilityKind::Randomness, None, None, operation);
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "randomness generation denied"));
    }
    ctx.before_blocking_operation(&request)?;
    let value = services
        .random()
        .random_u32()
        .map_err(|e| format!("random provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(value)
}

/// Brokered environment variable read.
///
/// Returns `Ok(None)` for unset variables (matching `std::env::var().ok()`
/// semantics used by the native path).
pub fn broker_env_var(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    name: &str,
    operation: &'static str,
) -> Result<Option<String>, String> {
    ctx.check_cancelled(operation)?;
    let request = broker_request(
        NseCapabilityKind::Environment,
        Some(name.to_string()),
        None,
        operation,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "environment access denied"));
    }
    ctx.before_blocking_operation(&request)?;
    let value = services
        .environment()
        .var(name)
        .map_err(|e| format!("environment provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(value)
}

/// Brokered temp-dir lookup.
pub fn broker_temp_dir(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    operation: &'static str,
) -> Result<PathBuf, String> {
    ctx.check_cancelled(operation)?;
    let request = broker_request(
        NseCapabilityKind::Environment,
        Some("TMPDIR".to_string()),
        None,
        operation,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "environment access denied"));
    }
    ctx.before_blocking_operation(&request)?;
    let value = services
        .environment()
        .temp_dir()
        .map_err(|e| format!("environment provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{NseCancellationToken, NseExecutionLimits, NseResourceCounters};
    use crate::profile::{
        NseExecutionProfileKind, NseModulePolicy, NseNetworkPolicy, NseScriptPolicy,
    };
    use crate::SandboxConfig;
    use std::sync::Arc;

    fn test_context(kind: NseExecutionProfileKind) -> NseCapabilityContext {
        NseCapabilityContext::new(
            kind,
            NseNetworkPolicy::AllowAllManual,
            NseScriptPolicy {
                allow_builtin_scripts: true,
                allow_script_files: false,
                allowed_script_roots: Vec::new(),
                allow_conventional_nmap_paths: false,
                max_script_bytes: None,
            },
            NseModulePolicy {
                allow_builtin_modules: true,
                allow_filesystem_modules: false,
                allowed_module_roots: Vec::new(),
                max_module_bytes: None,
            },
            SandboxConfig::default(),
            NseExecutionLimits::default(),
            NseCancellationToken::new(),
            Arc::new(NseResourceCounters::default()),
        )
    }

    #[test]
    fn native_services_preserve_behavior() {
        let services = NseHostServices::native();
        let before = chrono::Utc::now().timestamp();
        let now = services.clock().unix_timestamp().expect("native clock");
        let after = chrono::Utc::now().timestamp();
        assert!(
            (before..=after + 1).contains(&now),
            "native clock sane: {now}"
        );

        let mut buf = [0u8; 32];
        services
            .random()
            .fill_bytes(&mut buf)
            .expect("native random");
        // Random output is not asserted for value, only for successful fill.

        let native_var = std::env::var("PATH").ok();
        let provided = services.environment().var("PATH").expect("native env");
        assert_eq!(provided, native_var);
    }

    #[test]
    fn bundle_clones_share_providers() {
        let services = NseHostServices::native();
        let cloned = services.clone();
        assert!(Arc::ptr_eq(services.clock(), cloned.clock()));
        assert!(Arc::ptr_eq(services.random(), cloned.random()));
        assert!(Arc::ptr_eq(services.environment(), cloned.environment()));
    }

    #[test]
    fn deterministic_providers_are_stable() {
        let clock = FixedClockProvider::new(1_700_000_000);
        assert_eq!(clock.unix_timestamp().unwrap(), 1_700_000_000);

        let random = DeterministicRandomProvider::new(vec![7u8]);
        let mut a = [0u8; 4];
        let mut b = [0u8; 4];
        // Two providers with the same pattern produce the same stream.
        let other = DeterministicRandomProvider::new(vec![7u8]);
        random.fill_bytes(&mut a).unwrap();
        other.fill_bytes(&mut b).unwrap();
        assert_eq!(a, b);

        let mut vars = HashMap::new();
        vars.insert("EGGSEC_TEST".to_string(), "yes".to_string());
        let env = MapEnvironmentProvider::new(vars, PathBuf::from("/tmp/eggsec-test"));
        assert_eq!(env.var("EGGSEC_TEST").unwrap(), Some("yes".to_string()));
        assert_eq!(env.var("MISSING").unwrap(), None);
    }

    #[test]
    fn ci_safe_random_denied_before_provider_call() {
        let ctx = test_context(NseExecutionProfileKind::CiSafe);
        let counting = Arc::new(CountingRandomProvider::new(vec![1u8]));
        let services = NseHostServices::native().with_random(counting.clone());
        let mut out = [0u8; 8];
        let err = broker_random_fill(&ctx, &services, &mut out, "test.random").unwrap_err();
        assert!(err.contains("CI safe") || err.contains("denied"), "{err}");
        assert_eq!(
            counting.calls(),
            0,
            "denied operation must not touch provider"
        );
    }

    #[test]
    fn ci_safe_environment_denied_before_provider_call() {
        let ctx = test_context(NseExecutionProfileKind::CiSafe);
        let counting = Arc::new(CountingEnvironmentProvider::new(
            HashMap::new(),
            PathBuf::from("/tmp"),
        ));
        let services = NseHostServices::native().with_environment(counting.clone());
        let err = broker_env_var(&ctx, &services, "HOME", "test.getenv").unwrap_err();
        assert!(err.contains("CI safe") || err.contains("denied"), "{err}");
        assert_eq!(
            counting.calls(),
            0,
            "denied operation must not touch provider"
        );
    }

    #[test]
    fn agent_safe_environment_denied_before_provider_call() {
        let ctx = test_context(NseExecutionProfileKind::AgentSafe);
        let counting = Arc::new(CountingEnvironmentProvider::new(
            HashMap::new(),
            PathBuf::from("/tmp"),
        ));
        let services = NseHostServices::native().with_environment(counting.clone());
        let err = broker_env_var(&ctx, &services, "HOME", "test.getenv").unwrap_err();
        assert!(
            err.contains("agent safe") || err.contains("denied"),
            "{err}"
        );
        assert_eq!(counting.calls(), 0);
    }

    #[test]
    fn cancellation_prevents_provider_call() {
        let token = NseCancellationToken::new();
        token.cancel();
        let ctx = NseCapabilityContext::new(
            NseExecutionProfileKind::ManualPermissive,
            NseNetworkPolicy::AllowAllManual,
            NseScriptPolicy {
                allow_builtin_scripts: true,
                allow_script_files: false,
                allowed_script_roots: Vec::new(),
                allow_conventional_nmap_paths: false,
                max_script_bytes: None,
            },
            NseModulePolicy {
                allow_builtin_modules: true,
                allow_filesystem_modules: false,
                allowed_module_roots: Vec::new(),
                max_module_bytes: None,
            },
            SandboxConfig::default(),
            NseExecutionLimits::default(),
            token,
            Arc::new(NseResourceCounters::default()),
        );
        let counting = Arc::new(CountingClockProvider::new(42));
        let services = NseHostServices::native().with_clock(counting.clone());
        assert!(broker_unix_timestamp(&ctx, &services, "test.clock").is_err());
        assert_eq!(counting.calls(), 0);
    }
}
