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
/// Carries the M005A domains, the M005B network/DNS domains, the M005D
/// filesystem/process domains, and the M005C HTTP domain; later work
/// extends this struct with additional provider fields. Cloning shares the
/// underlying providers (cheap `Arc` clones) so concurrent runs can hold
/// different bundles without process-global state.
#[derive(Clone)]
pub struct NseHostServices {
    clock: Arc<dyn NseClockProvider>,
    random: Arc<dyn NseRandomProvider>,
    environment: Arc<dyn NseEnvironmentProvider>,
    dns: Arc<dyn NseDnsProvider>,
    tcp: Arc<dyn NseTcpSocketProvider>,
    udp: Arc<dyn NseUdpSocketProvider>,
    fs: Arc<dyn NseFilesystemProvider>,
    process: Arc<dyn NseProcessProvider>,
    http: Arc<dyn NseHttpProvider>,
}

impl std::fmt::Debug for NseHostServices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NseHostServices")
            .field("has_clock", &true)
            .field("has_random", &true)
            .field("has_environment", &true)
            .field("has_dns", &true)
            .field("has_tcp", &true)
            .field("has_udp", &true)
            .field("has_fs", &true)
            .field("has_process", &true)
            .field("has_http", &true)
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
            dns: Arc::new(NativeDnsProvider::new()),
            tcp: Arc::new(NativeTcpSocketProvider),
            udp: Arc::new(NativeUdpSocketProvider),
            fs: Arc::new(NativeFilesystemProvider::new()),
            process: Arc::new(NativeProcessProvider),
            http: Arc::new(NativeHttpProvider::new()),
        }
    }

    /// Build from explicit providers.
    ///
    /// The M005A three-domain form is preserved for compatibility; network,
    /// filesystem/process, and HTTP domains default to native. Use the
    /// `with_*` builders to override them.
    pub fn new(
        clock: Arc<dyn NseClockProvider>,
        random: Arc<dyn NseRandomProvider>,
        environment: Arc<dyn NseEnvironmentProvider>,
    ) -> Self {
        Self {
            clock,
            random,
            environment,
            dns: Arc::new(NativeDnsProvider::new()),
            tcp: Arc::new(NativeTcpSocketProvider),
            udp: Arc::new(NativeUdpSocketProvider),
            fs: Arc::new(NativeFilesystemProvider::new()),
            process: Arc::new(NativeProcessProvider),
            http: Arc::new(NativeHttpProvider::new()),
        }
    }

    /// Build from all six domain providers.
    pub fn new_full(
        clock: Arc<dyn NseClockProvider>,
        random: Arc<dyn NseRandomProvider>,
        environment: Arc<dyn NseEnvironmentProvider>,
        dns: Arc<dyn NseDnsProvider>,
        tcp: Arc<dyn NseTcpSocketProvider>,
        udp: Arc<dyn NseUdpSocketProvider>,
    ) -> Self {
        Self {
            clock,
            random,
            environment,
            dns,
            tcp,
            udp,
            fs: Arc::new(NativeFilesystemProvider::new()),
            process: Arc::new(NativeProcessProvider),
            http: Arc::new(NativeHttpProvider::new()),
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

    /// Replace the DNS provider.
    pub fn with_dns(mut self, provider: Arc<dyn NseDnsProvider>) -> Self {
        self.dns = provider;
        self
    }

    /// Replace the TCP socket provider.
    pub fn with_tcp(mut self, provider: Arc<dyn NseTcpSocketProvider>) -> Self {
        self.tcp = provider;
        self
    }

    /// Replace the UDP socket provider.
    pub fn with_udp(mut self, provider: Arc<dyn NseUdpSocketProvider>) -> Self {
        self.udp = provider;
        self
    }

    /// Replace the filesystem provider.
    pub fn with_fs(mut self, provider: Arc<dyn NseFilesystemProvider>) -> Self {
        self.fs = provider;
        self
    }

    /// Replace the process provider.
    pub fn with_process(mut self, provider: Arc<dyn NseProcessProvider>) -> Self {
        self.process = provider;
        self
    }

    /// Replace the HTTP provider.
    pub fn with_http(mut self, provider: Arc<dyn NseHttpProvider>) -> Self {
        self.http = provider;
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

    /// Borrow the DNS provider.
    pub fn dns(&self) -> &Arc<dyn NseDnsProvider> {
        &self.dns
    }

    /// Borrow the TCP socket provider.
    pub fn tcp(&self) -> &Arc<dyn NseTcpSocketProvider> {
        &self.tcp
    }

    /// Borrow the UDP socket provider.
    pub fn udp(&self) -> &Arc<dyn NseUdpSocketProvider> {
        &self.udp
    }

    /// Borrow the filesystem provider.
    pub fn fs(&self) -> &Arc<dyn NseFilesystemProvider> {
        &self.fs
    }

    /// Borrow the process provider.
    pub fn process(&self) -> &Arc<dyn NseProcessProvider> {
        &self.process
    }

    /// Borrow the HTTP provider.
    pub fn http(&self) -> &Arc<dyn NseHttpProvider> {
        &self.http
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
        assert!(Arc::ptr_eq(services.dns(), cloned.dns()));
        assert!(Arc::ptr_eq(services.tcp(), cloned.tcp()));
        assert!(Arc::ptr_eq(services.udp(), cloned.udp()));
        assert!(Arc::ptr_eq(services.fs(), cloned.fs()));
        assert!(Arc::ptr_eq(services.process(), cloned.process()));
        assert!(Arc::ptr_eq(services.http(), cloned.http()));
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

// ---------------------------------------------------------------------------
// M005B: DNS and socket providers (authority-preserving network/DNS).
//
// ADR-0003 boundary: narrow DNS/TCP/UDP traits join the per-run
// [`NseHostServices`] bundle; capability-aware brokers own the
// resolve -> select concrete candidate -> policy evaluation ->
// exact-endpoint connect sequence. A hostname decision is never reused for a
// later re-resolution: the provider connects only the selected endpoint.
//
// Native implementations live in this module (the single allow-listed native
// zone, mirroring M005A). Migrated libraries (`socket`, `comm`, `dns`,
// `nmap`, network wrappers) must go through the brokers below and must not
// perform direct `std::net`/Tokio/Hickory resolution or connects.
// ---------------------------------------------------------------------------

use std::collections::VecDeque;
use std::sync::OnceLock;

use hickory_resolver::proto::rr::{RData, RecordType};

/// Transport protocol carried by endpoint identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NseTransportProtocol {
    /// TCP stream transport.
    Tcp,
    /// UDP datagram transport.
    Udp,
}

impl NseTransportProtocol {
    /// Capability kind used for policy evaluation of this transport.
    fn capability_kind(self) -> NseCapabilityKind {
        match self {
            Self::Tcp => NseCapabilityKind::NetworkTcp,
            Self::Udp => NseCapabilityKind::NetworkUdp,
        }
    }

    /// Short protocol label (for endpoint identity display).
    pub fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Runtime-owned IP address.
///
/// Octet-based so provider contracts never expose `std::net` types. Native
/// code converts internally; libraries and tests use
/// [`NseIpAddress::parse`] plus the display/`is_loopback` helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NseIpAddress {
    /// IPv4 address octets.
    V4([u8; 4]),
    /// IPv6 address octets (network byte order).
    V6([u8; 16]),
}

impl NseIpAddress {
    /// Parse a literal IP address. Returns `None` for hostnames.
    pub fn parse(literal: &str) -> Option<Self> {
        match literal.parse::<std::net::IpAddr>().ok()? {
            std::net::IpAddr::V4(v4) => Some(Self::V4(v4.octets())),
            std::net::IpAddr::V6(v6) => Some(Self::V6(v6.octets())),
        }
    }

    /// True for loopback addresses (`127.0.0.0/8`, `::1`).
    pub fn is_loopback(&self) -> bool {
        match *self {
            Self::V4(o) => o[0] == 127,
            Self::V6(o) => o == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        }
    }

    /// True for IPv4 addresses.
    pub fn is_v4(&self) -> bool {
        matches!(self, Self::V4(_))
    }

    /// Reverse-DNS name (`in-addr.arpa` / `ip6.arpa`); pure computation.
    pub fn reverse_dns_name(&self) -> String {
        match *self {
            Self::V4(o) => format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]),
            Self::V6(o) => {
                let mut nibbles = Vec::with_capacity(32);
                for byte in o.iter().rev() {
                    nibbles.push(format!("{:x}", byte & 0x0f));
                    nibbles.push(format!("{:x}", byte >> 4));
                }
                format!("{}.ip6.arpa", nibbles.join("."))
            }
        }
    }

    /// Convert to the native address (crate-internal; never appears in
    /// public provider-trait signatures).
    pub(crate) fn to_std(&self) -> std::net::IpAddr {
        match *self {
            Self::V4(o) => std::net::IpAddr::V4(std::net::Ipv4Addr::from(o)),
            Self::V6(o) => std::net::IpAddr::V6(std::net::Ipv6Addr::from(o)),
        }
    }
}

impl std::fmt::Display for NseIpAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_std())
    }
}

/// Concrete, policy-selected network endpoint.
///
/// Carries the original hostname/label together with the exact approved IP
/// so providers connect without re-resolving and accounting records the
/// concrete identity that was authorized.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NseResolvedEndpoint {
    /// Original hostname or address label supplied by the script.
    pub hostname: String,
    /// Concrete approved IP address (never re-resolved after selection).
    pub address: NseIpAddress,
    /// Destination port.
    pub port: u16,
    /// Transport protocol.
    pub protocol: NseTransportProtocol,
}

impl NseResolvedEndpoint {
    /// Build an endpoint identity.
    pub fn new(
        hostname: impl Into<String>,
        address: NseIpAddress,
        port: u16,
        protocol: NseTransportProtocol,
    ) -> Self {
        Self {
            hostname: hostname.into(),
            address,
            port,
            protocol,
        }
    }

    /// Concrete `ip:port (proto)` identity string for diagnostics.
    pub fn describe(&self) -> String {
        format!("{}:{} ({})", self.address, self.port, self.protocol.name())
    }
}

/// DNS record type understood by the provider contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NseDnsRecordType {
    /// IPv4 address records.
    A,
    /// IPv6 address records.
    Aaaa,
    /// Mail exchange records.
    Mx,
    /// Text records.
    Txt,
    /// Name-server records.
    Ns,
    /// Start-of-authority records.
    Soa,
    /// Pointer records.
    Ptr,
    /// Canonical-name records.
    Cname,
    /// Any available records.
    Any,
}

impl NseDnsRecordType {
    /// Parse a Lua-level query-type label (case-insensitive; unknown labels
    /// fall back to `A`, matching the pre-provider resolver behavior).
    pub fn parse(label: &str) -> Self {
        match label.to_uppercase().as_str() {
            "AAAA" => Self::Aaaa,
            "MX" => Self::Mx,
            "TXT" => Self::Txt,
            "NS" => Self::Ns,
            "SOA" => Self::Soa,
            "PTR" => Self::Ptr,
            "CNAME" => Self::Cname,
            "ANY" => Self::Any,
            _ => Self::A,
        }
    }

    /// Canonical label.
    pub fn name(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Mx => "MX",
            Self::Txt => "TXT",
            Self::Ns => "NS",
            Self::Soa => "SOA",
            Self::Ptr => "PTR",
            Self::Cname => "CNAME",
            Self::Any => "ANY",
        }
    }

    /// True for candidate-producing address queries.
    pub fn is_address_query(&self) -> bool {
        matches!(self, Self::A | Self::Aaaa)
    }
}

/// One DNS answer record: a concrete address or display text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NseDnsRecord {
    /// Concrete address answer (A/AAAA).
    Address(NseIpAddress),
    /// Textual answer (MX/TXT/NS/SOA/PTR/CNAME/...).
    Text(String),
}

impl NseDnsRecord {
    /// Display form (matches the pre-provider `record.data.to_string()`
    /// Lua shapes).
    pub fn display(&self) -> String {
        match self {
            Self::Address(addr) => addr.to_string(),
            Self::Text(text) => text.clone(),
        }
    }

    /// Concrete address, if this record carries one.
    pub fn address(&self) -> Option<NseIpAddress> {
        match *self {
            Self::Address(addr) => Some(addr),
            Self::Text(_) => None,
        }
    }
}

/// DNS query DTO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NseDnsQuery {
    /// Name to resolve.
    pub name: String,
    /// Requested record type.
    pub record_type: NseDnsRecordType,
}

impl NseDnsQuery {
    /// Build a query.
    pub fn new(name: impl Into<String>, record_type: NseDnsRecordType) -> Self {
        Self {
            name: name.into(),
            record_type,
        }
    }
}

/// DNS answer DTO: provider-ordered records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NseDnsAnswer {
    /// Answer records in provider order.
    pub records: Vec<NseDnsRecord>,
}

impl NseDnsAnswer {
    /// Build an answer from records.
    pub fn new(records: Vec<NseDnsRecord>) -> Self {
        Self { records }
    }

    /// Concrete addresses in answer order.
    pub fn addresses(&self) -> Vec<NseIpAddress> {
        self.records
            .iter()
            .filter_map(NseDnsRecord::address)
            .collect()
    }

    /// Display forms in answer order.
    pub fn displays(&self) -> Vec<String> {
        self.records.iter().map(NseDnsRecord::display).collect()
    }
}

/// DNS resolution.
///
/// Returns provider-ordered answers; the broker (not the provider)
/// selects policy-approved concrete candidates.
pub trait NseDnsProvider: Send + Sync {
    /// Resolve `query`.
    fn lookup(&self, query: &NseDnsQuery) -> Result<NseDnsAnswer, NseProviderError>;
}

/// Opaque TCP connection handle.
///
/// Created by [`NseTcpSocketProvider::connect`] for an already-selected
/// endpoint; carries the approved endpoint identity so I/O brokers account
/// against the concrete address without re-resolution.
///
/// Handles are `Send + Sync` (the registry shares them across threads);
/// interior mutability, if any, is the implementation's responsibility.
pub trait NseTcpConnection: Send + Sync {
    /// Approved concrete endpoint backing this handle.
    fn endpoint(&self) -> &NseResolvedEndpoint;
    /// Send bytes; returns bytes written.
    fn send(&mut self, data: &[u8]) -> Result<usize, NseProviderError>;
    /// Receive up to `max_bytes`.
    fn receive(&mut self, max_bytes: usize) -> Result<Vec<u8>, NseProviderError>;
    /// Apply read/write timeouts.
    fn set_timeouts(&mut self, timeout: std::time::Duration) -> Result<(), NseProviderError>;
    /// Local port, if known.
    fn local_port(&self) -> Option<u16>;
    /// Non-destructive liveness probe.
    fn is_alive(&self) -> bool;
    /// Close the handle (idempotent).
    fn close(&mut self);
}

/// TCP connect for an already-selected concrete endpoint (no resolution).
pub trait NseTcpSocketProvider: Send + Sync {
    /// Connect exactly `endpoint`.
    fn connect(
        &self,
        endpoint: &NseResolvedEndpoint,
        timeout: std::time::Duration,
    ) -> Result<Box<dyn NseTcpConnection>, NseProviderError>;
}

/// Opaque UDP socket handle (connected semantics).
///
/// `Send + Sync`, like [`NseTcpConnection`].
pub trait NseUdpSocket: Send + Sync {
    /// Approved concrete endpoint backing this handle.
    fn endpoint(&self) -> &NseResolvedEndpoint;
    /// Send bytes to the connected endpoint; returns bytes written.
    fn send(&mut self, data: &[u8]) -> Result<usize, NseProviderError>;
    /// Receive up to `max_bytes`.
    fn receive(&mut self, max_bytes: usize) -> Result<Vec<u8>, NseProviderError>;
    /// Apply read/write timeouts.
    fn set_timeouts(&mut self, timeout: std::time::Duration) -> Result<(), NseProviderError>;
    /// Local port, if known.
    fn local_port(&self) -> Option<u16>;
    /// True while the handle is open.
    fn is_alive(&self) -> bool;
    /// Close the handle (idempotent).
    fn close(&mut self);
}

/// UDP "connect" for an already-selected concrete endpoint (no resolution).
pub trait NseUdpSocketProvider: Send + Sync {
    /// Bind an ephemeral socket and connect it exactly to `endpoint`.
    fn connect(
        &self,
        endpoint: &NseResolvedEndpoint,
        timeout: std::time::Duration,
    ) -> Result<Box<dyn NseUdpSocket>, NseProviderError>;
}

// ---------------------------------------------------------------------------
// Native implementations (default behavior, unchanged for existing callers).
// ---------------------------------------------------------------------------

fn hickory_record_type(record_type: &NseDnsRecordType) -> RecordType {
    match record_type {
        NseDnsRecordType::A => RecordType::A,
        NseDnsRecordType::Aaaa => RecordType::AAAA,
        NseDnsRecordType::Mx => RecordType::MX,
        NseDnsRecordType::Txt => RecordType::TXT,
        NseDnsRecordType::Ns => RecordType::NS,
        NseDnsRecordType::Soa => RecordType::SOA,
        NseDnsRecordType::Ptr => RecordType::PTR,
        NseDnsRecordType::Cname => RecordType::CNAME,
        NseDnsRecordType::Any => RecordType::ANY,
    }
}

/// Native DNS backed by Hickory.
///
/// One resolver per provider instance (no process-global state); concurrent
/// runs hold independent instances unless they explicitly share one.
pub struct NativeDnsProvider {
    resolver: OnceLock<hickory_resolver::TokioResolver>,
}

impl Default for NativeDnsProvider {
    fn default() -> Self {
        Self {
            resolver: OnceLock::new(),
        }
    }
}

impl NativeDnsProvider {
    /// Build a native DNS provider.
    pub fn new() -> Self {
        Self::default()
    }

    fn resolver(&self) -> Result<&hickory_resolver::TokioResolver, NseProviderError> {
        if let Some(resolver) = self.resolver.get() {
            return Ok(resolver);
        }
        let built = hickory_resolver::TokioResolver::builder_with_config(
            hickory_resolver::config::ResolverConfig::default(),
            hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
        )
        .with_options({
            let mut opts = hickory_resolver::config::ResolverOpts::default();
            opts.timeout = std::time::Duration::from_secs(5);
            opts.attempts = 2;
            opts
        })
        .build()
        .map_err(|e| {
            tracing::warn!("failed to initialize native DNS resolver: {e}");
            NseProviderError::new("dns", format!("DNS resolver unavailable: {e}"))
        })?;
        // Another thread may win the init race; first-wins keeps theirs.
        let _ = self.resolver.set(built);
        self.resolver
            .get()
            .ok_or_else(|| NseProviderError::new("dns", "DNS resolver unavailable after init"))
    }
}

impl NseDnsProvider for NativeDnsProvider {
    fn lookup(&self, query: &NseDnsQuery) -> Result<NseDnsAnswer, NseProviderError> {
        let resolver = self.resolver()?;
        let record_type = hickory_record_type(&query.record_type);
        let name = query.name.clone();
        let lookup = crate::libraries::runtime_bridge::try_block_on_async(
            resolver.lookup(name, record_type),
        )
        .map_err(|e| NseProviderError::new("dns", format!("DNS bridge failed: {e}")))?
        .map_err(|e| NseProviderError::new("dns", format!("DNS lookup failed: {e}")))?;
        let records = lookup
            .answers()
            .iter()
            .map(|record| match &record.data {
                RData::A(v4) => NseDnsRecord::Address(NseIpAddress::V4(v4.0.octets())),
                RData::AAAA(v6) => NseDnsRecord::Address(NseIpAddress::V6(v6.0.octets())),
                other => NseDnsRecord::Text(other.to_string()),
            })
            .collect();
        Ok(NseDnsAnswer::new(records))
    }
}

/// Native TCP backed by `std::net` (single allow-listed native zone).
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeTcpSocketProvider;

impl NativeTcpSocketProvider {
    /// Connect exactly `endpoint` and return the native stream.
    ///
    /// Native-only interop used by compatibility shims; the provider
    /// contract ([`NseTcpSocketProvider::connect`]) returns opaque handles.
    pub fn connect_std(
        &self,
        endpoint: &NseResolvedEndpoint,
        timeout: std::time::Duration,
    ) -> Result<std::net::TcpStream, NseProviderError> {
        let addr = std::net::SocketAddr::new(endpoint.address.to_std(), endpoint.port);
        let stream = std::net::TcpStream::connect_timeout(&addr, timeout).map_err(|e| {
            NseProviderError::new(
                "tcp",
                format!("TCP connect to {} failed: {e}", endpoint.describe()),
            )
        })?;
        stream
            .set_read_timeout(Some(timeout))
            .unwrap_or_else(|e| tracing::warn!("failed to set TCP read timeout: {e}"));
        stream
            .set_write_timeout(Some(timeout))
            .unwrap_or_else(|e| tracing::warn!("failed to set TCP write timeout: {e}"));
        Ok(stream)
    }
}

impl NseTcpSocketProvider for NativeTcpSocketProvider {
    fn connect(
        &self,
        endpoint: &NseResolvedEndpoint,
        timeout: std::time::Duration,
    ) -> Result<Box<dyn NseTcpConnection>, NseProviderError> {
        Ok(Box::new(NativeTcpConnection {
            stream: Some(self.connect_std(endpoint, timeout)?),
            endpoint: endpoint.clone(),
        }))
    }
}

/// Native TCP connection handle.
pub struct NativeTcpConnection {
    stream: Option<std::net::TcpStream>,
    endpoint: NseResolvedEndpoint,
}

impl NativeTcpConnection {
    /// Wrap an existing native stream (compatibility shims only).
    pub fn from_std(stream: std::net::TcpStream, endpoint: NseResolvedEndpoint) -> Self {
        Self {
            stream: Some(stream),
            endpoint,
        }
    }

    /// Unwrap back to the native stream (compatibility shims only).
    pub fn into_std(self) -> Option<std::net::TcpStream> {
        self.stream
    }
}

impl NseTcpConnection for NativeTcpConnection {
    fn endpoint(&self) -> &NseResolvedEndpoint {
        &self.endpoint
    }

    fn send(&mut self, data: &[u8]) -> Result<usize, NseProviderError> {
        use std::io::Write;
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| NseProviderError::new("tcp", "TCP handle is closed"))?;
        stream
            .write(data)
            .map_err(|e| NseProviderError::new("tcp", format!("TCP send failed: {e}")))
    }

    fn receive(&mut self, max_bytes: usize) -> Result<Vec<u8>, NseProviderError> {
        use std::io::Read;
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| NseProviderError::new("tcp", "TCP handle is closed"))?;
        let size = max_bytes.clamp(1, 65536);
        let mut buffer = vec![0u8; size];
        let n = stream
            .read(&mut buffer)
            .map_err(|e| NseProviderError::new("tcp", format!("TCP receive failed: {e}")))?;
        buffer.truncate(n);
        Ok(buffer)
    }

    fn set_timeouts(&mut self, timeout: std::time::Duration) -> Result<(), NseProviderError> {
        if let Some(stream) = self.stream.as_mut() {
            stream
                .set_read_timeout(Some(timeout))
                .unwrap_or_else(|e| tracing::warn!("failed to set TCP read timeout: {e}"));
            stream
                .set_write_timeout(Some(timeout))
                .unwrap_or_else(|e| tracing::warn!("failed to set TCP write timeout: {e}"));
        }
        Ok(())
    }

    fn local_port(&self) -> Option<u16> {
        self.stream
            .as_ref()
            .and_then(|s| s.local_addr().ok())
            .map(|a| a.port())
    }

    fn is_alive(&self) -> bool {
        match self.stream.as_ref() {
            None => false,
            Some(stream) => match stream.peek(&mut [0u8; 1]) {
                Ok(0) => false,
                Ok(_) => true,
                Err(e) => {
                    use std::io::ErrorKind;
                    e.kind() != ErrorKind::ConnectionReset
                        && e.kind() != ErrorKind::ConnectionAborted
                        && e.kind() != ErrorKind::BrokenPipe
                }
            },
        }
    }

    fn close(&mut self) {
        self.stream = None;
    }
}

/// Native UDP backed by `std::net` (single allow-listed native zone).
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeUdpSocketProvider;

impl NativeUdpSocketProvider {
    /// Bind an ephemeral socket and connect it exactly to `endpoint`.
    ///
    /// Native-only interop used by compatibility shims; the provider
    /// contract ([`NseUdpSocketProvider::connect`]) returns opaque handles.
    pub fn connect_std(
        &self,
        endpoint: &NseResolvedEndpoint,
        timeout: std::time::Duration,
    ) -> Result<std::net::UdpSocket, NseProviderError> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| NseProviderError::new("udp", format!("failed to bind UDP socket: {e}")))?;
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|e| NseProviderError::new("udp", format!("failed to set UDP timeout: {e}")))?;
        socket
            .set_write_timeout(Some(timeout))
            .map_err(|e| NseProviderError::new("udp", format!("failed to set UDP timeout: {e}")))?;
        let addr = std::net::SocketAddr::new(endpoint.address.to_std(), endpoint.port);
        socket.connect(addr).map_err(|e| {
            NseProviderError::new(
                "udp",
                format!("UDP connect to {} failed: {e}", endpoint.describe()),
            )
        })?;
        Ok(socket)
    }

    /// Single-shot receive on a fresh ephemeral socket (preserves the
    /// legacy `udp_receive` compatibility-shim semantics).
    ///
    /// The socket stays unconnected (receives from any sender), exactly like
    /// the legacy path. Authority was already evaluated by the caller's
    /// resolve-and-select step, so `_endpoint` is identity context only.
    ///
    /// Native-only interop; not part of the provider contract.
    pub fn recv_once_native(
        &self,
        _endpoint: &NseResolvedEndpoint,
        max_bytes: usize,
        timeout: std::time::Duration,
    ) -> Result<(Vec<u8>, std::net::SocketAddr), NseProviderError> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| NseProviderError::new("udp", format!("failed to bind UDP socket: {e}")))?;
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|e| NseProviderError::new("udp", format!("failed to set UDP timeout: {e}")))?;
        let mut buffer = vec![0u8; max_bytes.clamp(1, 65536)];
        socket
            .recv_from(&mut buffer)
            .map(|(n, from)| {
                buffer.truncate(n);
                (buffer, from)
            })
            .map_err(|e| NseProviderError::new("udp", format!("UDP receive failed: {e}")))
    }
}

impl NseUdpSocketProvider for NativeUdpSocketProvider {
    fn connect(
        &self,
        endpoint: &NseResolvedEndpoint,
        timeout: std::time::Duration,
    ) -> Result<Box<dyn NseUdpSocket>, NseProviderError> {
        Ok(Box::new(NativeUdpSocket {
            socket: Some(self.connect_std(endpoint, timeout)?),
            endpoint: endpoint.clone(),
        }))
    }
}

/// Native UDP socket handle.
pub struct NativeUdpSocket {
    socket: Option<std::net::UdpSocket>,
    endpoint: NseResolvedEndpoint,
}

impl NativeUdpSocket {
    /// Wrap an existing native socket (compatibility shims only).
    pub fn from_std(socket: std::net::UdpSocket, endpoint: NseResolvedEndpoint) -> Self {
        Self {
            socket: Some(socket),
            endpoint,
        }
    }

    /// Unwrap back to the native socket (compatibility shims only).
    pub fn into_std(self) -> Option<std::net::UdpSocket> {
        self.socket
    }
}

impl NseUdpSocket for NativeUdpSocket {
    fn endpoint(&self) -> &NseResolvedEndpoint {
        &self.endpoint
    }

    fn send(&mut self, data: &[u8]) -> Result<usize, NseProviderError> {
        let socket = self
            .socket
            .as_mut()
            .ok_or_else(|| NseProviderError::new("udp", "UDP handle is closed"))?;
        socket
            .send(data)
            .map_err(|e| NseProviderError::new("udp", format!("UDP send failed: {e}")))
    }

    fn receive(&mut self, max_bytes: usize) -> Result<Vec<u8>, NseProviderError> {
        let socket = self
            .socket
            .as_mut()
            .ok_or_else(|| NseProviderError::new("udp", "UDP handle is closed"))?;
        let size = max_bytes.clamp(1, 65536);
        let mut buffer = vec![0u8; size];
        match socket.recv(&mut buffer) {
            Ok(n) => {
                buffer.truncate(n);
                Ok(buffer)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(Vec::new()),
            Err(e) => Err(NseProviderError::new(
                "udp",
                format!("UDP receive failed: {e}"),
            )),
        }
    }

    fn set_timeouts(&mut self, timeout: std::time::Duration) -> Result<(), NseProviderError> {
        if let Some(socket) = self.socket.as_mut() {
            socket
                .set_read_timeout(Some(timeout))
                .unwrap_or_else(|e| tracing::warn!("failed to set UDP read timeout: {e}"));
            socket
                .set_write_timeout(Some(timeout))
                .unwrap_or_else(|e| tracing::warn!("failed to set UDP write timeout: {e}"));
        }
        Ok(())
    }

    fn local_port(&self) -> Option<u16> {
        self.socket
            .as_ref()
            .and_then(|s| s.local_addr().ok())
            .map(|a| a.port())
    }

    fn is_alive(&self) -> bool {
        self.socket.is_some()
    }

    fn close(&mut self) {
        self.socket = None;
    }
}

// ---------------------------------------------------------------------------
// Deterministic test providers (public so downstream harnesses can reuse).
// ---------------------------------------------------------------------------

/// Map-backed DNS: programmed answers per normalized `(name, record label)`.
///
/// Unknown names resolve to an empty answer (no addresses), which makes
/// restricted profiles fail closed without I/O.
pub struct MapDnsProvider {
    answers: HashMap<(String, String), NseDnsAnswer>,
    lookups: AtomicU64,
}

impl MapDnsProvider {
    /// Build from a normalized answer map.
    pub fn new(answers: HashMap<(String, String), NseDnsAnswer>) -> Self {
        Self {
            answers,
            lookups: AtomicU64::new(0),
        }
    }

    /// Convenience: one name with A-record addresses.
    pub fn with_addresses(name: &str, addresses: Vec<NseIpAddress>) -> Self {
        let mut answers = HashMap::new();
        answers.insert(
            (name.to_lowercase(), NseDnsRecordType::A.name().to_string()),
            NseDnsAnswer::new(addresses.into_iter().map(NseDnsRecord::Address).collect()),
        );
        Self::new(answers)
    }

    /// Number of provider invocations observed.
    pub fn lookups(&self) -> u64 {
        self.lookups.load(Ordering::SeqCst)
    }
}

impl NseDnsProvider for MapDnsProvider {
    fn lookup(&self, query: &NseDnsQuery) -> Result<NseDnsAnswer, NseProviderError> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .answers
            .get(&(
                query.name.to_lowercase(),
                query.record_type.name().to_string(),
            ))
            .cloned()
            .unwrap_or_default())
    }
}

/// Scripted DNS: pops one programmed answer per call.
///
/// Used for rebinding tests: the script proves how many resolutions the
/// broker performs and which answer generation backs the connect.
pub struct ScriptedDnsProvider {
    script: Mutex<VecDeque<NseDnsAnswer>>,
    lookups: AtomicU64,
}

impl ScriptedDnsProvider {
    /// Build from a per-call answer script.
    pub fn new(script: Vec<NseDnsAnswer>) -> Self {
        Self {
            script: Mutex::new(script.into()),
            lookups: AtomicU64::new(0),
        }
    }

    /// Number of provider invocations observed.
    pub fn lookups(&self) -> u64 {
        self.lookups.load(Ordering::SeqCst)
    }
}

impl NseDnsProvider for ScriptedDnsProvider {
    fn lookup(&self, _query: &NseDnsQuery) -> Result<NseDnsAnswer, NseProviderError> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        let mut script = self
            .script
            .lock()
            .map_err(|e| NseProviderError::new("dns", format!("scripted DNS lock failed: {e}")))?;
        Ok(script.pop_front().unwrap_or_default())
    }
}

/// In-memory TCP handle with a send log and canned receive bytes.
pub struct MemoryTcpConnection {
    endpoint: NseResolvedEndpoint,
    sent: Mutex<Vec<u8>>,
    recv_queue: Mutex<VecDeque<Vec<u8>>>,
    closed: AtomicU64,
    local: Option<u16>,
}

impl MemoryTcpConnection {
    /// Build a handle replaying `replay` chunks on receive.
    pub fn new(endpoint: NseResolvedEndpoint, replay: Vec<Vec<u8>>) -> Self {
        Self {
            endpoint,
            sent: Mutex::new(Vec::new()),
            recv_queue: Mutex::new(replay.into()),
            closed: AtomicU64::new(0),
            local: None,
        }
    }

    /// Bytes handed to [`NseTcpConnection::send`] so far.
    pub fn sent_bytes(&self) -> Vec<u8> {
        self.sent.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl NseTcpConnection for MemoryTcpConnection {
    fn endpoint(&self) -> &NseResolvedEndpoint {
        &self.endpoint
    }

    fn send(&mut self, data: &[u8]) -> Result<usize, NseProviderError> {
        if self.closed.load(Ordering::SeqCst) != 0 {
            return Err(NseProviderError::new("tcp", "TCP handle is closed"));
        }
        let mut sent = self
            .sent
            .lock()
            .map_err(|e| NseProviderError::new("tcp", format!("memory TCP lock failed: {e}")))?;
        sent.extend_from_slice(data);
        Ok(data.len())
    }

    fn receive(&mut self, _max_bytes: usize) -> Result<Vec<u8>, NseProviderError> {
        if self.closed.load(Ordering::SeqCst) != 0 {
            return Err(NseProviderError::new("tcp", "TCP handle is closed"));
        }
        let mut queue = self
            .recv_queue
            .lock()
            .map_err(|e| NseProviderError::new("tcp", format!("memory TCP lock failed: {e}")))?;
        Ok(queue.pop_front().unwrap_or_default())
    }

    fn set_timeouts(&mut self, _timeout: std::time::Duration) -> Result<(), NseProviderError> {
        Ok(())
    }

    fn local_port(&self) -> Option<u16> {
        self.local
    }

    fn is_alive(&self) -> bool {
        self.closed.load(Ordering::SeqCst) == 0
    }

    fn close(&mut self) {
        self.closed.store(1, Ordering::SeqCst);
    }
}

/// Scripted TCP provider recording every exact endpoint it connects.
///
/// Each connect drains the remaining replay queue into the new handle, so
/// tests observe both the endpoint identity and the I/O behavior.
pub struct MemoryTcpSocketProvider {
    connects: Mutex<Vec<NseResolvedEndpoint>>,
    replay: Mutex<VecDeque<Vec<u8>>>,
}

impl MemoryTcpSocketProvider {
    /// Build with canned receive chunks.
    pub fn new(replay: Vec<Vec<u8>>) -> Self {
        Self {
            connects: Mutex::new(Vec::new()),
            replay: Mutex::new(replay.into()),
        }
    }

    /// Exact endpoints the provider was asked to connect, in order.
    pub fn connects(&self) -> Vec<NseResolvedEndpoint> {
        self.connects.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl NseTcpSocketProvider for MemoryTcpSocketProvider {
    fn connect(
        &self,
        endpoint: &NseResolvedEndpoint,
        _timeout: std::time::Duration,
    ) -> Result<Box<dyn NseTcpConnection>, NseProviderError> {
        self.connects
            .lock()
            .map_err(|e| NseProviderError::new("tcp", format!("memory TCP lock failed: {e}")))?
            .push(endpoint.clone());
        let replay = self
            .replay
            .lock()
            .map(|g| g.clone().into())
            .unwrap_or_default();
        Ok(Box::new(MemoryTcpConnection::new(endpoint.clone(), replay)))
    }
}

/// In-memory UDP handle with a send log and canned receive bytes.
pub struct MemoryUdpSocket {
    endpoint: NseResolvedEndpoint,
    sent: Mutex<Vec<u8>>,
    recv_queue: Mutex<VecDeque<Vec<u8>>>,
    closed: AtomicU64,
}

impl MemoryUdpSocket {
    /// Build a handle replaying `replay` chunks on receive.
    pub fn new(endpoint: NseResolvedEndpoint, replay: Vec<Vec<u8>>) -> Self {
        Self {
            endpoint,
            sent: Mutex::new(Vec::new()),
            recv_queue: Mutex::new(replay.into()),
            closed: AtomicU64::new(0),
        }
    }

    /// Bytes handed to [`NseUdpSocket::send`] so far.
    pub fn sent_bytes(&self) -> Vec<u8> {
        self.sent.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl NseUdpSocket for MemoryUdpSocket {
    fn endpoint(&self) -> &NseResolvedEndpoint {
        &self.endpoint
    }

    fn send(&mut self, data: &[u8]) -> Result<usize, NseProviderError> {
        if self.closed.load(Ordering::SeqCst) != 0 {
            return Err(NseProviderError::new("udp", "UDP handle is closed"));
        }
        let mut sent = self
            .sent
            .lock()
            .map_err(|e| NseProviderError::new("udp", format!("memory UDP lock failed: {e}")))?;
        sent.extend_from_slice(data);
        Ok(data.len())
    }

    fn receive(&mut self, _max_bytes: usize) -> Result<Vec<u8>, NseProviderError> {
        if self.closed.load(Ordering::SeqCst) != 0 {
            return Err(NseProviderError::new("udp", "UDP handle is closed"));
        }
        let mut queue = self
            .recv_queue
            .lock()
            .map_err(|e| NseProviderError::new("udp", format!("memory UDP lock failed: {e}")))?;
        Ok(queue.pop_front().unwrap_or_default())
    }

    fn set_timeouts(&mut self, _timeout: std::time::Duration) -> Result<(), NseProviderError> {
        Ok(())
    }

    fn local_port(&self) -> Option<u16> {
        None
    }

    fn is_alive(&self) -> bool {
        self.closed.load(Ordering::SeqCst) == 0
    }

    fn close(&mut self) {
        self.closed.store(1, Ordering::SeqCst);
    }
}

/// Scripted UDP provider recording every exact endpoint it connects.
pub struct MemoryUdpSocketProvider {
    connects: Mutex<Vec<NseResolvedEndpoint>>,
    replay: Mutex<VecDeque<Vec<u8>>>,
}

impl MemoryUdpSocketProvider {
    /// Build with canned receive chunks.
    pub fn new(replay: Vec<Vec<u8>>) -> Self {
        Self {
            connects: Mutex::new(Vec::new()),
            replay: Mutex::new(replay.into()),
        }
    }

    /// Exact endpoints the provider was asked to connect, in order.
    pub fn connects(&self) -> Vec<NseResolvedEndpoint> {
        self.connects.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl NseUdpSocketProvider for MemoryUdpSocketProvider {
    fn connect(
        &self,
        endpoint: &NseResolvedEndpoint,
        _timeout: std::time::Duration,
    ) -> Result<Box<dyn NseUdpSocket>, NseProviderError> {
        self.connects
            .lock()
            .map_err(|e| NseProviderError::new("udp", format!("memory UDP lock failed: {e}")))?
            .push(endpoint.clone());
        let replay = self
            .replay
            .lock()
            .map(|g| g.clone().into())
            .unwrap_or_default();
        Ok(Box::new(MemoryUdpSocket::new(endpoint.clone(), replay)))
    }
}

/// Counting DNS wrapper proving denial prevents provider invocation.
pub struct CountingDnsProvider {
    inner: MapDnsProvider,
    calls: AtomicU64,
}

impl CountingDnsProvider {
    /// Build a counting wrapper around programmed answers.
    pub fn new(answers: HashMap<(String, String), NseDnsAnswer>) -> Self {
        Self {
            inner: MapDnsProvider::new(answers),
            calls: AtomicU64::new(0),
        }
    }

    /// Number of provider invocations observed.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl NseDnsProvider for CountingDnsProvider {
    fn lookup(&self, query: &NseDnsQuery) -> Result<NseDnsAnswer, NseProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.lookup(query)
    }
}

/// Counting TCP wrapper proving denial prevents provider invocation.
pub struct CountingTcpSocketProvider {
    inner: MemoryTcpSocketProvider,
    calls: AtomicU64,
}

impl CountingTcpSocketProvider {
    /// Build a counting wrapper around a memory provider.
    pub fn new(replay: Vec<Vec<u8>>) -> Self {
        Self {
            inner: MemoryTcpSocketProvider::new(replay),
            calls: AtomicU64::new(0),
        }
    }

    /// Number of provider invocations observed.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    /// Exact endpoints connected so far.
    pub fn connects(&self) -> Vec<NseResolvedEndpoint> {
        self.inner.connects()
    }
}

impl NseTcpSocketProvider for CountingTcpSocketProvider {
    fn connect(
        &self,
        endpoint: &NseResolvedEndpoint,
        timeout: std::time::Duration,
    ) -> Result<Box<dyn NseTcpConnection>, NseProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.connect(endpoint, timeout)
    }
}

/// Counting UDP wrapper proving denial prevents provider invocation.
pub struct CountingUdpSocketProvider {
    inner: MemoryUdpSocketProvider,
    calls: AtomicU64,
}

impl CountingUdpSocketProvider {
    /// Build a counting wrapper around a memory provider.
    pub fn new(replay: Vec<Vec<u8>>) -> Self {
        Self {
            inner: MemoryUdpSocketProvider::new(replay),
            calls: AtomicU64::new(0),
        }
    }

    /// Number of provider invocations observed.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    /// Exact endpoints connected so far.
    pub fn connects(&self) -> Vec<NseResolvedEndpoint> {
        self.inner.connects()
    }
}

impl NseUdpSocketProvider for CountingUdpSocketProvider {
    fn connect(
        &self,
        endpoint: &NseResolvedEndpoint,
        timeout: std::time::Duration,
    ) -> Result<Box<dyn NseUdpSocket>, NseProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.connect(endpoint, timeout)
    }
}

// ---------------------------------------------------------------------------
// Capability-aware broker functions (authority-preserving network/DNS).
//
// Sequence (ADR-0003, M005B):
//   capability decision -> cancellation/resource preflight -> provider
//   operation -> resource accounting -> event/report result.
//
// Resolution produces candidates; policy selects concrete allowable
// endpoints; the provider connects only the selected endpoint. Denial or
// cancellation never reaches the provider.
// ---------------------------------------------------------------------------

/// Brokered DNS lookup.
///
/// Denied or cancelled callers receive an error and the provider is not
/// invoked. Success records the standard capability event/counters.
pub fn broker_dns_lookup(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    name: &str,
    record_type: NseDnsRecordType,
    operation: &'static str,
) -> Result<NseDnsAnswer, String> {
    ctx.check_cancelled(operation)?;
    let request = broker_request(
        NseCapabilityKind::DnsResolution,
        Some(name.to_string()),
        None,
        operation,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "DNS resolution denied"));
    }
    ctx.before_blocking_operation(&request)?;
    let answer = services
        .dns()
        .lookup(&NseDnsQuery::new(name, record_type))
        .map_err(|e| format!("DNS provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(answer)
}

/// Resolve `host` and select the first concrete candidate approved by
/// network policy.
///
/// Literal IPs skip resolution. Hostnames resolve through the DNS provider
/// (A then AAAA); each candidate is evaluated individually against
/// `NseCapabilityContext` network policy and the first allowed concrete
/// endpoint wins. Fail-closed when no candidate is approved.
///
/// The returned endpoint must be connected exactly (see
/// [`broker_tcp_connect_endpoint`]); never re-resolve after selection.
pub fn broker_resolve_and_select(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    host: &str,
    port: u16,
    protocol: NseTransportProtocol,
    operation: &'static str,
) -> Result<NseResolvedEndpoint, String> {
    ctx.check_cancelled(operation)?;
    let kind = protocol.capability_kind();
    let mut candidates: Vec<NseIpAddress> = Vec::new();
    if let Some(literal) = NseIpAddress::parse(host) {
        candidates.push(literal);
    } else {
        // Resolution is a distinct step with its own capability gate so
        // DenyAll/CI-safe profiles fail before the resolver is touched.
        let dns_request = broker_request(
            NseCapabilityKind::DnsResolution,
            Some(host.to_string()),
            None,
            operation,
        );
        let dns_decision = ctx.check_capability(&dns_request);
        if !dns_decision.is_allowed() {
            return Err(deny_message(&dns_decision, "DNS resolution denied"));
        }
        ctx.before_blocking_operation(&dns_request)?;
        let mut answer = services
            .dns()
            .lookup(&NseDnsQuery::new(host, NseDnsRecordType::A))
            .map_err(|e| format!("DNS provider failed: {e}"))?;
        let aaaa = services
            .dns()
            .lookup(&NseDnsQuery::new(host, NseDnsRecordType::Aaaa))
            .map_err(|e| format!("DNS provider failed: {e}"))?;
        answer.records.extend(aaaa.records);
        ctx.after_blocking_operation(&dns_request, None);
        candidates = answer.addresses();
        if candidates.is_empty() {
            return Err(format!("DNS resolution for '{host}' returned no addresses"));
        }
    }
    for address in candidates {
        let endpoint = NseResolvedEndpoint::new(host, address, port, protocol);
        let decision = ctx.check_capability(&broker_request(
            kind,
            Some(address.to_string()),
            None,
            operation,
        ));
        if decision.is_allowed() {
            return Ok(endpoint);
        }
    }
    Err(format!(
        "network {} access denied: no approved concrete endpoint for '{host}:{port}'",
        protocol.name()
    ))
}

/// Connect exactly `endpoint` over TCP (no resolution inside).
pub fn broker_tcp_connect_endpoint(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    endpoint: &NseResolvedEndpoint,
    timeout: std::time::Duration,
    operation: &'static str,
) -> Result<Box<dyn NseTcpConnection>, String> {
    ctx.check_cancelled(operation)?;
    let request = broker_request(
        NseCapabilityKind::NetworkTcp,
        Some(endpoint.address.to_string()),
        None,
        operation,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "network TCP connect denied"));
    }
    ctx.before_blocking_operation(&request)?;
    let handle = services
        .tcp()
        .connect(endpoint, timeout)
        .map_err(|e| format!("TCP connect to {} failed: {e}", endpoint.describe()))?;
    ctx.after_blocking_operation(&request, None);
    Ok(handle)
}

/// Resolve, select the approved concrete endpoint, and connect over TCP.
///
/// Returns the opaque handle plus the exact endpoint connected.
pub fn broker_tcp_connect(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    host: &str,
    port: u16,
    timeout: std::time::Duration,
    operation: &'static str,
) -> Result<(Box<dyn NseTcpConnection>, NseResolvedEndpoint), String> {
    let endpoint = broker_resolve_and_select(
        ctx,
        services,
        host,
        port,
        NseTransportProtocol::Tcp,
        operation,
    )?;
    let handle = broker_tcp_connect_endpoint(ctx, services, &endpoint, timeout, operation)?;
    Ok((handle, endpoint))
}

/// Brokered TCP send on an established handle.
///
/// Policy is evaluated against the handle's concrete endpoint identity.
pub fn broker_tcp_send(
    ctx: &NseCapabilityContext,
    handle: &mut dyn NseTcpConnection,
    data: &[u8],
    operation: &'static str,
) -> Result<usize, String> {
    let target = handle.endpoint().address.to_string();
    ctx.check_cancelled(operation)?;
    let request = broker_request(
        NseCapabilityKind::NetworkTcp,
        Some(target),
        Some(data.len() as u64),
        operation,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "network TCP send denied"));
    }
    ctx.before_blocking_send(&request)?;
    let n = handle
        .send(data)
        .map_err(|e| format!("TCP send failed: {e}"))?;
    ctx.after_blocking_send(&request, Some(n as u64));
    Ok(n)
}

/// Brokered TCP receive on an established handle.
pub fn broker_tcp_receive(
    ctx: &NseCapabilityContext,
    handle: &mut dyn NseTcpConnection,
    max_bytes: usize,
    operation: &'static str,
) -> Result<Vec<u8>, String> {
    let target = handle.endpoint().address.to_string();
    ctx.check_cancelled(operation)?;
    let request = broker_request(
        NseCapabilityKind::NetworkTcp,
        Some(target),
        Some(max_bytes as u64),
        operation,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "network TCP receive denied"));
    }
    ctx.before_blocking_operation(&request)?;
    let data = handle
        .receive(max_bytes)
        .map_err(|e| format!("TCP receive failed: {e}"))?;
    let n = data.len();
    ctx.after_blocking_operation(&request, Some(n as u64));
    Ok(data)
}

/// Connect exactly `endpoint` over UDP (no resolution inside).
pub fn broker_udp_connect_endpoint(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    endpoint: &NseResolvedEndpoint,
    timeout: std::time::Duration,
    operation: &'static str,
) -> Result<Box<dyn NseUdpSocket>, String> {
    ctx.check_cancelled(operation)?;
    let request = broker_request(
        NseCapabilityKind::NetworkUdp,
        Some(endpoint.address.to_string()),
        None,
        operation,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "network UDP connect denied"));
    }
    ctx.before_blocking_operation(&request)?;
    let handle = services
        .udp()
        .connect(endpoint, timeout)
        .map_err(|e| format!("UDP connect to {} failed: {e}", endpoint.describe()))?;
    ctx.after_blocking_operation(&request, None);
    Ok(handle)
}

/// Resolve, select the approved concrete endpoint, and connect over UDP.
pub fn broker_udp_connect(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    host: &str,
    port: u16,
    timeout: std::time::Duration,
    operation: &'static str,
) -> Result<(Box<dyn NseUdpSocket>, NseResolvedEndpoint), String> {
    let endpoint = broker_resolve_and_select(
        ctx,
        services,
        host,
        port,
        NseTransportProtocol::Udp,
        operation,
    )?;
    let handle = broker_udp_connect_endpoint(ctx, services, &endpoint, timeout, operation)?;
    Ok((handle, endpoint))
}

/// Brokered UDP send on an established handle.
pub fn broker_udp_send(
    ctx: &NseCapabilityContext,
    handle: &mut dyn NseUdpSocket,
    data: &[u8],
    operation: &'static str,
) -> Result<usize, String> {
    let target = handle.endpoint().address.to_string();
    ctx.check_cancelled(operation)?;
    let request = broker_request(
        NseCapabilityKind::NetworkUdp,
        Some(target),
        Some(data.len() as u64),
        operation,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "network UDP send denied"));
    }
    ctx.before_blocking_send(&request)?;
    let n = handle
        .send(data)
        .map_err(|e| format!("UDP send failed: {e}"))?;
    ctx.after_blocking_send(&request, Some(n as u64));
    Ok(n)
}

/// Brokered UDP receive on an established handle.
pub fn broker_udp_receive(
    ctx: &NseCapabilityContext,
    handle: &mut dyn NseUdpSocket,
    max_bytes: usize,
    operation: &'static str,
) -> Result<Vec<u8>, String> {
    let target = handle.endpoint().address.to_string();
    ctx.check_cancelled(operation)?;
    let request = broker_request(
        NseCapabilityKind::NetworkUdp,
        Some(target),
        Some(max_bytes as u64),
        operation,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "network UDP receive denied"));
    }
    ctx.before_blocking_operation(&request)?;
    let data = handle
        .receive(max_bytes)
        .map_err(|e| format!("UDP receive failed: {e}"))?;
    let n = data.len();
    ctx.after_blocking_operation(&request, Some(n as u64));
    Ok(data)
}

/// Crate-internal sandbox helper: test a concrete endpoint against the
/// legacy `allowed_networks` list without re-resolving (the endpoint
/// already carries the approved IP).
pub(crate) fn endpoint_in_networks(
    endpoint: &NseResolvedEndpoint,
    nets: &[ipnetwork::IpNetwork],
) -> bool {
    if nets.is_empty() {
        return true;
    }
    let ip = endpoint.address.to_std();
    nets.iter().any(|net| net.contains(ip))
}

// ---------------------------------------------------------------------------
// M005D: filesystem and process providers (portability + per-run isolation).
//
// ADR-0003 boundary: narrow filesystem/process traits join the per-run
// [`NseHostServices`] bundle; capability-aware brokers own the
// capability/sandbox-path decision -> cancellation/resource preflight ->
// provider operation -> accounting/event sequence. Checks apply to the
// resolved provider path: relative paths resolve against the per-run
// virtual CWD, sandbox containment applies to the resolved path, and the
// provider operates on the approved path with no second transformation.
//
// Native implementations live in this module (the single allow-listed
// native zone, mirroring M005A/M005B). Migrated libraries (`io`, `lfs`,
// filesystem portions of `os`, `nmap` privilege/interface discovery, and
// the non-leaking filesystem wrappers) must go through the brokers below.
// Process-global `set_current_dir` is gone: the native filesystem provider
// keeps a per-instance virtual CWD override and never mutates the process.
// ---------------------------------------------------------------------------

use std::path::{Path, PathBuf as FsPathBuf};

/// Runtime-owned file metadata: only the fields NSE compatibility consumes.
///
/// No `std::fs::Metadata` crosses the provider contract; natives map via
/// [`NseFileMetadata::from_std`] (native interop, marked as such).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NseFileMetadata {
    /// File length in bytes.
    pub len: u64,
    /// True for directories.
    pub is_dir: bool,
    /// True for regular files.
    pub is_file: bool,
    /// True for symlinks (from `symlink_metadata`; always false for
    /// following `metadata` on most platforms).
    pub is_symlink: bool,
    /// True when read-only.
    pub readonly: bool,
    /// Modification time (seconds since the Unix epoch), if available.
    pub modified_secs: Option<u64>,
    /// Last access time (seconds since the Unix epoch), if available.
    pub accessed_secs: Option<u64>,
    /// Creation time (seconds since the Unix epoch), if available.
    pub created_secs: Option<u64>,
    /// Unix permission bits, if the platform reports them.
    pub unix_mode: Option<u32>,
}

impl NseFileMetadata {
    /// Map native metadata to the runtime-owned DTO (native interop).
    pub fn from_std(meta: &std::fs::Metadata) -> Self {
        fn secs(t: std::io::Result<std::time::SystemTime>) -> Option<u64> {
            t.ok()?
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs())
        }
        Self {
            len: meta.len(),
            is_dir: meta.is_dir(),
            is_file: meta.is_file(),
            is_symlink: meta.is_symlink(),
            readonly: meta.permissions().readonly(),
            modified_secs: secs(meta.modified()),
            accessed_secs: secs(meta.accessed()),
            created_secs: secs(meta.created()),
            unix_mode: unix_mode_of(meta),
        }
    }
}

#[cfg(unix)]
fn unix_mode_of(meta: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(meta.permissions().mode())
}

#[cfg(not(unix))]
fn unix_mode_of(_meta: &std::fs::Metadata) -> Option<u32> {
    None
}

/// File type carried by directory entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NseFileType {
    /// Regular file.
    File,
    /// Directory.
    Dir,
    /// Symlink or other special entry.
    Symlink,
    /// Unknown (entry type unavailable).
    Unknown,
}

/// Runtime-owned directory entry (name + type; no `DirEntry` leakage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NseDirEntry {
    /// File name within the listed directory.
    pub name: String,
    /// Entry type, if known.
    pub file_type: NseFileType,
}

impl NseDirEntry {
    /// Build an entry.
    pub fn new(name: impl Into<String>, file_type: NseFileType) -> Self {
        Self {
            name: name.into(),
            file_type,
        }
    }
}

/// Open mode for provider file handles (maps Lua `io.open` mode strings).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NseOpenMode {
    /// Read-only (`"r"`).
    Read,
    /// Write, truncate, create (`"w"`, `"w+"` without read).
    Write,
    /// Append, create (`"a"`).
    Append,
    /// Read/write without truncate (`"r+"`).
    ReadWrite,
    /// Read/write, truncate, create (`"w+"`).
    WriteRead,
    /// Read/append, create (`"a+"`).
    AppendRead,
}

impl NseOpenMode {
    /// Parse a Lua `io.open` mode string (unknown modes fall back to
    /// read-only, matching the pre-provider behavior).
    pub fn parse(mode: &str) -> Self {
        match mode {
            "w" => Self::Write,
            "a" => Self::Append,
            "r+" => Self::ReadWrite,
            "w+" => Self::WriteRead,
            "a+" => Self::AppendRead,
            _ => Self::Read,
        }
    }

    /// True for modes that create or modify content.
    pub fn is_write(&self) -> bool {
        !matches!(self, Self::Read)
    }
}

/// Opaque file handle (no `std::fs::File` in the contract).
pub trait NseFileHandle: Send + Sync {
    /// Read up to `max_bytes`.
    fn read(&mut self, max_bytes: usize) -> Result<Vec<u8>, NseProviderError>;
    /// Write bytes; returns bytes written.
    fn write(&mut self, data: &[u8]) -> Result<usize, NseProviderError>;
    /// Flush buffered writes.
    fn flush(&mut self) -> Result<(), NseProviderError>;
    /// Seek from the start; returns the new position.
    fn seek_from_start(&mut self, pos: u64) -> Result<u64, NseProviderError>;
    /// Close the handle (idempotent).
    fn close(&mut self);
    /// True while the handle is open.
    fn is_open(&self) -> bool;
}

/// Filesystem operations.
///
/// One domain trait (not a monolithic host trait): every method is a
/// path-scoped filesystem operation on runtime-owned path types. Path
/// arguments are already-resolved absolute paths approved by the broker;
/// relative-path joining against the virtual CWD happens in the broker via
/// [`broker_fs_resolve`], never by re-resolving after approval.
pub trait NseFilesystemProvider: Send + Sync {
    /// Read a whole file to a string.
    fn read_to_string(&self, path: &Path) -> Result<String, NseProviderError>;
    /// Read a whole file to bytes.
    fn read(&self, path: &Path) -> Result<Vec<u8>, NseProviderError>;
    /// Write bytes to a file (create or truncate).
    fn write(&self, path: &Path, bytes: &[u8]) -> Result<(), NseProviderError>;
    /// Following metadata.
    fn metadata(&self, path: &Path) -> Result<NseFileMetadata, NseProviderError>;
    /// Non-following (symlink) metadata.
    fn symlink_metadata(&self, path: &Path) -> Result<NseFileMetadata, NseProviderError>;
    /// List directory entries.
    fn read_dir(&self, path: &Path) -> Result<Vec<NseDirEntry>, NseProviderError>;
    /// Remove a file.
    fn remove_file(&self, path: &Path) -> Result<(), NseProviderError>;
    /// Rename/move a file or directory.
    fn rename(&self, from: &Path, to: &Path) -> Result<(), NseProviderError>;
    /// Create directories recursively.
    fn create_dir_all(&self, path: &Path) -> Result<(), NseProviderError>;
    /// Remove an empty directory.
    fn remove_dir(&self, path: &Path) -> Result<(), NseProviderError>;
    /// Create a hard link.
    fn hard_link(&self, src: &Path, dst: &Path) -> Result<(), NseProviderError>;
    /// Create a symbolic link (platform-localized; directory targets may
    /// be unsupported on some platforms).
    fn symlink(&self, src: &Path, dst: &Path) -> Result<(), NseProviderError>;
    /// Read a symlink target.
    fn read_link(&self, path: &Path) -> Result<FsPathBuf, NseProviderError>;
    /// Set Unix permission bits (unsupported on non-Unix platforms).
    fn set_unix_mode(&self, path: &Path, mode: u32) -> Result<(), NseProviderError>;
    /// Set the read-only flag (portable).
    fn set_readonly(&self, path: &Path, readonly: bool) -> Result<(), NseProviderError>;
    /// True when the path exists (any type).
    fn exists(&self, path: &Path) -> bool;
    /// Open a file handle.
    fn open(
        &self,
        path: &Path,
        mode: NseOpenMode,
    ) -> Result<Box<dyn NseFileHandle>, NseProviderError>;
    /// Per-run working directory: the virtual override when set through
    /// [`NseFilesystemProvider::set_current_dir`], else the process CWD.
    fn current_dir(&self) -> Result<FsPathBuf, NseProviderError>;
    /// Set the per-run virtual working directory. Records the override on
    /// this provider instance only; never mutates the embedding process.
    fn set_current_dir(&self, path: &Path) -> Result<(), NseProviderError>;
}

/// Process execution specification (no shell implied; callers select the
/// platform shell explicitly when shell semantics are required).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NseProcessSpec {
    /// Program to execute.
    pub program: String,
    /// Arguments (not shell-parsed).
    pub args: Vec<String>,
    /// Wall-clock bound for completion.
    pub timeout: std::time::Duration,
}

impl NseProcessSpec {
    /// Build a spec.
    pub fn new(
        program: impl Into<String>,
        args: Vec<String>,
        timeout: std::time::Duration,
    ) -> Self {
        Self {
            program: program.into(),
            args,
            timeout,
        }
    }
}

/// Process execution result (no `std::process::Output` in the contract).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NseProcessResult {
    /// Exit code, when the process exited normally.
    pub code: Option<i32>,
    /// True when the exit code is zero.
    pub success: bool,
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error.
    pub stderr: Vec<u8>,
}

/// Network interface record for privilege/interface discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NseNetworkInterface {
    /// Interface/device name.
    pub name: String,
    /// Associated addresses.
    pub addresses: Vec<NseIpAddress>,
}

impl NseNetworkInterface {
    /// Build an interface record.
    pub fn new(name: impl Into<String>, addresses: Vec<NseIpAddress>) -> Self {
        Self {
            name: name.into(),
            addresses,
        }
    }
}

/// Process execution and platform discovery.
///
/// Bounded execution only: implementations must enforce the spec timeout
/// (killing the child) and must not leave detached children.
pub trait NseProcessProvider: Send + Sync {
    /// Run to completion with captured output (bounded by spec timeout).
    fn run(&self, spec: &NseProcessSpec) -> Result<NseProcessResult, NseProviderError>;
    /// Spawn a child without waiting (for `io.popen` semantics); the
    /// caller owns the handle and must terminate it.
    fn spawn(&self, spec: &NseProcessSpec) -> Result<Box<dyn NseChildProcess>, NseProviderError>;
    /// Platform-localized privilege probe (`id -u == 0` on Unix, always
    /// false elsewhere).
    fn is_privileged(&self) -> Result<bool, NseProviderError>;
    /// Platform-localized interface enumeration with a loopback fallback.
    fn network_interfaces(&self) -> Result<Vec<NseNetworkInterface>, NseProviderError>;
}

/// Opaque running child process (for spawn-without-wait semantics).
pub trait NseChildProcess: Send {
    /// OS process id, if known.
    fn id(&self) -> Option<u32>;
    /// True while the child is still running.
    fn is_running(&mut self) -> bool;
    /// Terminate the child (best effort, idempotent).
    fn kill(&mut self);
}

// ---------------------------------------------------------------------------
// Native implementations (default behavior, unchanged for existing callers).
// ---------------------------------------------------------------------------

/// Native file handle backed by `std::fs` (single allow-listed native zone).
pub struct NativeFileHandle {
    file: Option<std::fs::File>,
}

impl NativeFileHandle {
    /// Wrap an open native file (native interop).
    pub fn from_std(file: std::fs::File) -> Self {
        Self { file: Some(file) }
    }
}

impl NseFileHandle for NativeFileHandle {
    fn read(&mut self, max_bytes: usize) -> Result<Vec<u8>, NseProviderError> {
        use std::io::Read;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| NseProviderError::new("fs", "file handle is closed"))?;
        let size = max_bytes.clamp(1, 16 * 1024 * 1024);
        let mut buffer = vec![0u8; size];
        let n = file
            .read(&mut buffer)
            .map_err(|e| NseProviderError::new("fs", format!("file read failed: {e}")))?;
        buffer.truncate(n);
        Ok(buffer)
    }

    fn write(&mut self, data: &[u8]) -> Result<usize, NseProviderError> {
        use std::io::Write;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| NseProviderError::new("fs", "file handle is closed"))?;
        file.write_all(data)
            .map_err(|e| NseProviderError::new("fs", format!("file write failed: {e}")))?;
        Ok(data.len())
    }

    fn flush(&mut self) -> Result<(), NseProviderError> {
        use std::io::Write;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| NseProviderError::new("fs", "file handle is closed"))?;
        file.flush()
            .map_err(|e| NseProviderError::new("fs", format!("file flush failed: {e}")))?;
        Ok(())
    }

    fn seek_from_start(&mut self, pos: u64) -> Result<u64, NseProviderError> {
        use std::io::Seek;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| NseProviderError::new("fs", "file handle is closed"))?;
        file.seek(std::io::SeekFrom::Start(pos))
            .map_err(|e| NseProviderError::new("fs", format!("file seek failed: {e}")))
    }

    fn close(&mut self) {
        if let Some(file) = self.file.take() {
            // Preserve the legacy sync-on-close behavior (warn, not fail).
            if let Err(e) = file.sync_all() {
                tracing::warn!("failed to sync file on close: {e}");
            }
        }
    }

    fn is_open(&self) -> bool {
        self.file.is_some()
    }
}

impl Drop for NativeFileHandle {
    fn drop(&mut self) {
        self.close();
    }
}

/// Native filesystem backed by `std::fs`/`std::env` (single allow-listed
/// native zone).
///
/// The virtual CWD override is per-instance state: concurrent runs hold
/// independent providers and never observe each other's `set_current_dir`.
/// The process working directory is never mutated.
pub struct NativeFilesystemProvider {
    cwd_override: Mutex<Option<FsPathBuf>>,
}

impl NativeFilesystemProvider {
    /// Build a native filesystem provider (no virtual CWD override).
    pub fn new() -> Self {
        Self {
            cwd_override: Mutex::new(None),
        }
    }
}

impl Default for NativeFilesystemProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl NseFilesystemProvider for NativeFilesystemProvider {
    fn read_to_string(&self, path: &Path) -> Result<String, NseProviderError> {
        std::fs::read_to_string(path)
            .map_err(|e| NseProviderError::new("fs", format!("read failed: {e}")))
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>, NseProviderError> {
        std::fs::read(path).map_err(|e| NseProviderError::new("fs", format!("read failed: {e}")))
    }

    fn write(&self, path: &Path, bytes: &[u8]) -> Result<(), NseProviderError> {
        std::fs::write(path, bytes)
            .map_err(|e| NseProviderError::new("fs", format!("write failed: {e}")))
    }

    fn metadata(&self, path: &Path) -> Result<NseFileMetadata, NseProviderError> {
        std::fs::metadata(path)
            .map(|m| NseFileMetadata::from_std(&m))
            .map_err(|e| NseProviderError::new("fs", format!("stat failed: {e}")))
    }

    fn symlink_metadata(&self, path: &Path) -> Result<NseFileMetadata, NseProviderError> {
        std::fs::symlink_metadata(path)
            .map(|m| NseFileMetadata::from_std(&m))
            .map_err(|e| NseProviderError::new("fs", format!("lstat failed: {e}")))
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<NseDirEntry>, NseProviderError> {
        let dir = std::fs::read_dir(path)
            .map_err(|e| NseProviderError::new("fs", format!("read_dir failed: {e}")))?;
        let mut entries = Vec::new();
        for entry in dir {
            let entry =
                entry.map_err(|e| NseProviderError::new("fs", format!("dir entry failed: {e}")))?;
            let file_type = entry
                .file_type()
                .map(|t| {
                    if t.is_dir() {
                        NseFileType::Dir
                    } else if t.is_file() {
                        NseFileType::File
                    } else if t.is_symlink() {
                        NseFileType::Symlink
                    } else {
                        NseFileType::Unknown
                    }
                })
                .unwrap_or(NseFileType::Unknown);
            entries.push(NseDirEntry::new(
                entry.file_name().to_string_lossy(),
                file_type,
            ));
        }
        Ok(entries)
    }

    fn remove_file(&self, path: &Path) -> Result<(), NseProviderError> {
        std::fs::remove_file(path)
            .map_err(|e| NseProviderError::new("fs", format!("remove failed: {e}")))
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<(), NseProviderError> {
        std::fs::rename(from, to)
            .map_err(|e| NseProviderError::new("fs", format!("rename failed: {e}")))
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), NseProviderError> {
        std::fs::create_dir_all(path)
            .map_err(|e| NseProviderError::new("fs", format!("mkdir failed: {e}")))
    }

    fn remove_dir(&self, path: &Path) -> Result<(), NseProviderError> {
        std::fs::remove_dir(path)
            .map_err(|e| NseProviderError::new("fs", format!("rmdir failed: {e}")))
    }

    fn hard_link(&self, src: &Path, dst: &Path) -> Result<(), NseProviderError> {
        std::fs::hard_link(src, dst)
            .map_err(|e| NseProviderError::new("fs", format!("hard link failed: {e}")))
    }

    fn symlink(&self, src: &Path, dst: &Path) -> Result<(), NseProviderError> {
        symlink_native(src, dst)
    }

    fn read_link(&self, path: &Path) -> Result<FsPathBuf, NseProviderError> {
        std::fs::read_link(path)
            .map_err(|e| NseProviderError::new("fs", format!("read_link failed: {e}")))
    }

    fn set_unix_mode(&self, path: &Path, mode: u32) -> Result<(), NseProviderError> {
        set_unix_mode_native(path, mode)
    }

    fn set_readonly(&self, path: &Path, readonly: bool) -> Result<(), NseProviderError> {
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| NseProviderError::new("fs", format!("stat failed: {e}")))?;
        let mut perms = meta.permissions();
        perms.set_readonly(readonly);
        std::fs::set_permissions(path, perms)
            .map_err(|e| NseProviderError::new("fs", format!("set permissions failed: {e}")))
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn open(
        &self,
        path: &Path,
        mode: NseOpenMode,
    ) -> Result<Box<dyn NseFileHandle>, NseProviderError> {
        use std::fs::OpenOptions;
        let file = match mode {
            NseOpenMode::Read => OpenOptions::new().read(true).open(path),
            NseOpenMode::Write => OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path),
            NseOpenMode::Append => OpenOptions::new().append(true).create(true).open(path),
            NseOpenMode::ReadWrite => OpenOptions::new().read(true).write(true).open(path),
            NseOpenMode::WriteRead => OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(path),
            NseOpenMode::AppendRead => OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open(path),
        }
        .map_err(|e| NseProviderError::new("fs", format!("open failed: {e}")))?;
        Ok(Box::new(NativeFileHandle::from_std(file)))
    }

    fn current_dir(&self) -> Result<FsPathBuf, NseProviderError> {
        if let Some(dir) = self
            .cwd_override
            .lock()
            .map_err(|e| NseProviderError::new("fs", format!("CWD lock failed: {e}")))?
            .clone()
        {
            return Ok(dir);
        }
        std::env::current_dir()
            .map_err(|e| NseProviderError::new("fs", format!("current_dir failed: {e}")))
    }

    fn set_current_dir(&self, path: &Path) -> Result<(), NseProviderError> {
        if !path.is_dir() {
            return Err(NseProviderError::new(
                "fs",
                "chdir target is not a directory",
            ));
        }
        *self
            .cwd_override
            .lock()
            .map_err(|e| NseProviderError::new("fs", format!("CWD lock failed: {e}")))? =
            Some(path.to_path_buf());
        Ok(())
    }
}

#[cfg(unix)]
fn symlink_native(src: &Path, dst: &Path) -> Result<(), NseProviderError> {
    std::os::unix::fs::symlink(src, dst)
        .map_err(|e| NseProviderError::new("fs", format!("symlink failed: {e}")))
}

#[cfg(windows)]
fn symlink_native(src: &Path, dst: &Path) -> Result<(), NseProviderError> {
    // Windows distinguishes file/dir symlinks and requires privileges;
    // file targets use symlink_file, directory targets are unsupported.
    if src.is_dir() {
        return Err(NseProviderError::new(
            "fs",
            "directory symlinks are unsupported on Windows",
        ));
    }
    std::os::windows::fs::symlink_file(src, dst)
        .map_err(|e| NseProviderError::new("fs", format!("symlink failed: {e}")))
}

#[cfg(not(unix))]
#[cfg(not(windows))]
fn symlink_native(_src: &Path, _dst: &Path) -> Result<(), NseProviderError> {
    Err(NseProviderError::new(
        "fs",
        "symlinks are unsupported on this platform",
    ))
}

#[cfg(unix)]
fn set_unix_mode_native(path: &Path, mode: u32) -> Result<(), NseProviderError> {
    use std::os::unix::fs::PermissionsExt;
    let permissions = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, permissions)
        .map_err(|e| NseProviderError::new("fs", format!("set mode failed: {e}")))
}

#[cfg(not(unix))]
fn set_unix_mode_native(_path: &Path, _mode: u32) -> Result<(), NseProviderError> {
    Err(NseProviderError::new(
        "fs",
        "Unix permission bits are unsupported on this platform (use set_readonly)",
    ))
}

/// Platform shell for `sh -c`/`cmd /C` semantics, localized in the native
/// layer so compatibility libraries never branch on the platform.
pub fn shell_command(cmd: &str) -> NseProcessSpec {
    #[cfg(unix)]
    {
        NseProcessSpec::new(
            "sh",
            vec!["-c".to_string(), cmd.to_string()],
            PROCESS_TIMEOUT,
        )
    }
    #[cfg(windows)]
    {
        NseProcessSpec::new(
            "cmd",
            vec!["/C".to_string(), cmd.to_string()],
            PROCESS_TIMEOUT,
        )
    }
    #[cfg(not(unix))]
    #[cfg(not(windows))]
    {
        let _ = cmd;
        NseProcessSpec::new("", Vec::new(), PROCESS_TIMEOUT)
    }
}

/// Default bound for shell-p spawned processes (matches the legacy
/// `io.popen` posture of spawning without a bound, now bounded).
const PROCESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Native running child backed by `std::process` (allow-listed native zone).
pub struct NativeChildProcess {
    child: Option<std::process::Child>,
}

impl NativeChildProcess {
    /// Wrap a spawned native child (native interop).
    pub fn from_std(child: std::process::Child) -> Self {
        Self { child: Some(child) }
    }
}

impl NseChildProcess for NativeChildProcess {
    fn id(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }

    fn is_running(&mut self) -> bool {
        match self.child.as_mut() {
            None => false,
            Some(child) => match child.try_wait() {
                Ok(None) => true,
                _ => false,
            },
        }
    }

    fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Best effort: kill, then reap without blocking indefinitely.
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for NativeChildProcess {
    fn drop(&mut self) {
        // Never leave detached children behind when the owning run ends.
        self.kill();
    }
}

/// Native process provider backed by `std::process` (allow-listed zone).
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeProcessProvider;

impl NativeProcessProvider {
    fn spawn_native(spec: &NseProcessSpec) -> Result<std::process::Child, NseProviderError> {
        if spec.program.is_empty() {
            return Err(NseProviderError::new(
                "process",
                "process execution is unsupported on this platform",
            ));
        }
        std::process::Command::new(&spec.program)
            .args(&spec.args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| NseProviderError::new("process", format!("spawn failed: {e}")))
    }
}

impl NseProcessProvider for NativeProcessProvider {
    fn run(&self, spec: &NseProcessSpec) -> Result<NseProcessResult, NseProviderError> {
        use std::io::Read;
        let mut child = Self::spawn_native(spec)?;
        let deadline = std::time::Instant::now() + spec.timeout;
        loop {
            match child
                .try_wait()
                .map_err(|e| NseProviderError::new("process", format!("wait failed: {e}")))?
            {
                Some(status) => {
                    let mut stdout = Vec::new();
                    let mut stderr = Vec::new();
                    if let Some(mut out) = child.stdout.take() {
                        let _ = out.read_to_end(&mut stdout);
                    }
                    if let Some(mut err) = child.stderr.take() {
                        let _ = err.read_to_end(&mut stderr);
                    }
                    return Ok(NseProcessResult {
                        code: status.code(),
                        success: status.success(),
                        stdout,
                        stderr,
                    });
                }
                None => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(NseProviderError::new(
                            "process",
                            "process execution timed out",
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            }
        }
    }

    fn spawn(&self, spec: &NseProcessSpec) -> Result<Box<dyn NseChildProcess>, NseProviderError> {
        Ok(Box::new(NativeChildProcess::from_std(Self::spawn_native(
            spec,
        )?)))
    }

    fn is_privileged(&self) -> Result<bool, NseProviderError> {
        is_privileged_native()
    }

    fn network_interfaces(&self) -> Result<Vec<NseNetworkInterface>, NseProviderError> {
        network_interfaces_native()
    }
}

#[cfg(unix)]
fn is_privileged_native() -> Result<bool, NseProviderError> {
    match std::process::Command::new("id").arg("-u").output() {
        Ok(output) => Ok(output.stdout == b"0\n"),
        Err(e) => Err(NseProviderError::new(
            "process",
            format!("privilege probe failed: {e}"),
        )),
    }
}

#[cfg(not(unix))]
fn is_privileged_native() -> Result<bool, NseProviderError> {
    Ok(false)
}

#[cfg(unix)]
fn network_interfaces_native() -> Result<Vec<NseNetworkInterface>, NseProviderError> {
    match std::process::Command::new("ip").arg("addr").output() {
        Ok(output) => Ok(parse_ip_addr_output(&String::from_utf8_lossy(
            &output.stdout,
        ))),
        Err(e) => Err(NseProviderError::new(
            "process",
            format!("interface enumeration failed: {e}"),
        )),
    }
}

#[cfg(windows)]
fn network_interfaces_native() -> Result<Vec<NseNetworkInterface>, NseProviderError> {
    match std::process::Command::new("ipconfig").output() {
        Ok(output) => Ok(parse_ipconfig_output(&String::from_utf8_lossy(
            &output.stdout,
        ))),
        Err(e) => Err(NseProviderError::new(
            "process",
            format!("interface enumeration failed: {e}"),
        )),
    }
}

#[cfg(not(unix))]
#[cfg(not(windows))]
fn network_interfaces_native() -> Result<Vec<NseNetworkInterface>, NseProviderError> {
    Ok(vec![NseNetworkInterface::new(
        "lo",
        vec![NseIpAddress::V4([127, 0, 0, 1])],
    )])
}

// ---------------------------------------------------------------------------
// Deterministic test providers (public so downstream harnesses can reuse).
// ---------------------------------------------------------------------------

/// Counting filesystem wrapper proving denial prevents provider invocation.
pub struct CountingFilesystemProvider {
    calls: AtomicU64,
}

impl CountingFilesystemProvider {
    /// Build a counting wrapper around native behavior.
    pub fn new() -> Self {
        Self {
            calls: AtomicU64::new(0),
        }
    }

    /// Number of provider invocations observed.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Default for CountingFilesystemProvider {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! counted_fs {
    ($self:ident, $native:expr) => {{
        $self.calls.fetch_add(1, Ordering::SeqCst);
        $native
    }};
}

impl NseFilesystemProvider for CountingFilesystemProvider {
    fn read_to_string(&self, path: &Path) -> Result<String, NseProviderError> {
        counted_fs!(self, NativeFilesystemProvider::new().read_to_string(path))
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>, NseProviderError> {
        counted_fs!(self, NativeFilesystemProvider::new().read(path))
    }

    fn write(&self, path: &Path, bytes: &[u8]) -> Result<(), NseProviderError> {
        counted_fs!(self, NativeFilesystemProvider::new().write(path, bytes))
    }

    fn metadata(&self, path: &Path) -> Result<NseFileMetadata, NseProviderError> {
        counted_fs!(self, NativeFilesystemProvider::new().metadata(path))
    }

    fn symlink_metadata(&self, path: &Path) -> Result<NseFileMetadata, NseProviderError> {
        counted_fs!(self, NativeFilesystemProvider::new().symlink_metadata(path))
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<NseDirEntry>, NseProviderError> {
        counted_fs!(self, NativeFilesystemProvider::new().read_dir(path))
    }

    fn remove_file(&self, path: &Path) -> Result<(), NseProviderError> {
        counted_fs!(self, NativeFilesystemProvider::new().remove_file(path))
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<(), NseProviderError> {
        counted_fs!(self, NativeFilesystemProvider::new().rename(from, to))
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), NseProviderError> {
        counted_fs!(self, NativeFilesystemProvider::new().create_dir_all(path))
    }

    fn remove_dir(&self, path: &Path) -> Result<(), NseProviderError> {
        counted_fs!(self, NativeFilesystemProvider::new().remove_dir(path))
    }

    fn hard_link(&self, src: &Path, dst: &Path) -> Result<(), NseProviderError> {
        counted_fs!(self, NativeFilesystemProvider::new().hard_link(src, dst))
    }

    fn symlink(&self, src: &Path, dst: &Path) -> Result<(), NseProviderError> {
        counted_fs!(self, NativeFilesystemProvider::new().symlink(src, dst))
    }

    fn read_link(&self, path: &Path) -> Result<FsPathBuf, NseProviderError> {
        counted_fs!(self, NativeFilesystemProvider::new().read_link(path))
    }

    fn set_unix_mode(&self, path: &Path, mode: u32) -> Result<(), NseProviderError> {
        counted_fs!(
            self,
            NativeFilesystemProvider::new().set_unix_mode(path, mode)
        )
    }

    fn set_readonly(&self, path: &Path, readonly: bool) -> Result<(), NseProviderError> {
        counted_fs!(
            self,
            NativeFilesystemProvider::new().set_readonly(path, readonly)
        )
    }

    fn exists(&self, path: &Path) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst);
        NativeFilesystemProvider::new().exists(path)
    }

    fn open(
        &self,
        path: &Path,
        mode: NseOpenMode,
    ) -> Result<Box<dyn NseFileHandle>, NseProviderError> {
        counted_fs!(self, NativeFilesystemProvider::new().open(path, mode))
    }

    fn current_dir(&self) -> Result<FsPathBuf, NseProviderError> {
        counted_fs!(self, NativeFilesystemProvider::new().current_dir())
    }

    fn set_current_dir(&self, path: &Path) -> Result<(), NseProviderError> {
        counted_fs!(self, NativeFilesystemProvider::new().set_current_dir(path))
    }
}

/// Denying filesystem provider: every fallible operation fails closed.
///
/// Used to prove brokers never reach the provider on denial (via the
/// counting wrapper) and to simulate unavailable filesystems.
pub struct DenyFilesystemProvider {
    message: String,
}

impl DenyFilesystemProvider {
    /// Build a denying provider with a fixed failure message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn deny(&self) -> NseProviderError {
        NseProviderError::new("fs", self.message.clone())
    }
}

impl NseFilesystemProvider for DenyFilesystemProvider {
    fn read_to_string(&self, _path: &Path) -> Result<String, NseProviderError> {
        Err(self.deny())
    }

    fn read(&self, _path: &Path) -> Result<Vec<u8>, NseProviderError> {
        Err(self.deny())
    }

    fn write(&self, _path: &Path, _bytes: &[u8]) -> Result<(), NseProviderError> {
        Err(self.deny())
    }

    fn metadata(&self, _path: &Path) -> Result<NseFileMetadata, NseProviderError> {
        Err(self.deny())
    }

    fn symlink_metadata(&self, _path: &Path) -> Result<NseFileMetadata, NseProviderError> {
        Err(self.deny())
    }

    fn read_dir(&self, _path: &Path) -> Result<Vec<NseDirEntry>, NseProviderError> {
        Err(self.deny())
    }

    fn remove_file(&self, _path: &Path) -> Result<(), NseProviderError> {
        Err(self.deny())
    }

    fn rename(&self, _from: &Path, _to: &Path) -> Result<(), NseProviderError> {
        Err(self.deny())
    }

    fn create_dir_all(&self, _path: &Path) -> Result<(), NseProviderError> {
        Err(self.deny())
    }

    fn remove_dir(&self, _path: &Path) -> Result<(), NseProviderError> {
        Err(self.deny())
    }

    fn hard_link(&self, _src: &Path, _dst: &Path) -> Result<(), NseProviderError> {
        Err(self.deny())
    }

    fn symlink(&self, _src: &Path, _dst: &Path) -> Result<(), NseProviderError> {
        Err(self.deny())
    }

    fn read_link(&self, _path: &Path) -> Result<FsPathBuf, NseProviderError> {
        Err(self.deny())
    }

    fn set_unix_mode(&self, _path: &Path, _mode: u32) -> Result<(), NseProviderError> {
        Err(self.deny())
    }

    fn set_readonly(&self, _path: &Path, _readonly: bool) -> Result<(), NseProviderError> {
        Err(self.deny())
    }

    fn exists(&self, _path: &Path) -> bool {
        false
    }

    fn open(
        &self,
        _path: &Path,
        _mode: NseOpenMode,
    ) -> Result<Box<dyn NseFileHandle>, NseProviderError> {
        Err(self.deny())
    }

    fn current_dir(&self) -> Result<FsPathBuf, NseProviderError> {
        Err(self.deny())
    }

    fn set_current_dir(&self, _path: &Path) -> Result<(), NseProviderError> {
        Err(self.deny())
    }
}

/// Counting process wrapper proving denial prevents provider invocation.
pub struct CountingProcessProvider {
    calls: AtomicU64,
}

impl CountingProcessProvider {
    /// Build a counting wrapper around native behavior.
    pub fn new() -> Self {
        Self {
            calls: AtomicU64::new(0),
        }
    }

    /// Number of provider invocations observed.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Default for CountingProcessProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl NseProcessProvider for CountingProcessProvider {
    fn run(&self, spec: &NseProcessSpec) -> Result<NseProcessResult, NseProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        NativeProcessProvider.run(spec)
    }

    fn spawn(&self, spec: &NseProcessSpec) -> Result<Box<dyn NseChildProcess>, NseProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        NativeProcessProvider.spawn(spec)
    }

    fn is_privileged(&self) -> Result<bool, NseProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        NativeProcessProvider.is_privileged()
    }

    fn network_interfaces(&self) -> Result<Vec<NseNetworkInterface>, NseProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        NativeProcessProvider.network_interfaces()
    }
}

/// Denying process provider: every operation fails closed.
pub struct DenyProcessProvider {
    message: String,
}

impl DenyProcessProvider {
    /// Build a denying provider with a fixed failure message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn deny(&self) -> NseProviderError {
        NseProviderError::new("process", self.message.clone())
    }
}

impl NseProcessProvider for DenyProcessProvider {
    fn run(&self, _spec: &NseProcessSpec) -> Result<NseProcessResult, NseProviderError> {
        Err(self.deny())
    }

    fn spawn(&self, _spec: &NseProcessSpec) -> Result<Box<dyn NseChildProcess>, NseProviderError> {
        Err(self.deny())
    }

    fn is_privileged(&self) -> Result<bool, NseProviderError> {
        Err(self.deny())
    }

    fn network_interfaces(&self) -> Result<Vec<NseNetworkInterface>, NseProviderError> {
        Err(self.deny())
    }
}

// ---------------------------------------------------------------------------
// Capability-aware broker functions (filesystem/process, M005D).
//
// Sequence (ADR-0003, plan §6):
//   capability/sandbox path decision -> cancellation/resource preflight ->
//   provider operation -> accounting/event result.
//
// Relative paths resolve against the per-run virtual CWD first; capability
// and sandbox checks apply to the resolved absolute path; the sandbox
// canonicalizes (when enabled) and the provider operates on that approved
// path with no second transformation. Denial or cancellation never reaches
// the provider.
// ---------------------------------------------------------------------------

/// Resolve `path` against the per-run virtual CWD (absolute paths pass
/// through). Pure joining only — no filesystem access, no canonicalization.
pub fn broker_fs_resolve(
    services: &NseHostServices,
    path: &str,
    operation: &'static str,
) -> Result<FsPathBuf, String> {
    let candidate = FsPathBuf::from(path);
    if candidate.is_absolute() {
        return Ok(candidate);
    }
    let cwd = services
        .fs()
        .current_dir()
        .map_err(|e| format!("{operation}: working directory unavailable: {e}"))?;
    Ok(cwd.join(candidate))
}

fn fs_approved_path(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    path: &str,
    kind: NseCapabilityKind,
    operation: &'static str,
) -> Result<(NseCapabilityRequest, FsPathBuf), String> {
    ctx.check_cancelled(operation)?;
    let resolved = broker_fs_resolve(services, path, operation)?;
    let request = broker_request(
        kind,
        Some(resolved.to_string_lossy().to_string()),
        None,
        operation,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "filesystem access denied"));
    }
    // Sandbox canonicalizes + enforces containment on the resolved path;
    // disabled sandbox passes the resolved path through unchanged.
    match ctx.sandbox.get_allowed_path(&resolved.to_string_lossy()) {
        Some(approved) => Ok((request, approved)),
        None => Err(format!(
            "{operation}: path '{}' blocked by sandbox",
            resolved.display()
        )),
    }
}

/// Brokered whole-file string read.
pub fn broker_fs_read_to_string(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    path: &str,
    operation: &'static str,
) -> Result<String, String> {
    let (request, approved) = fs_approved_path(
        ctx,
        services,
        path,
        NseCapabilityKind::FilesystemRead,
        operation,
    )?;
    ctx.before_blocking_operation(&request)?;
    let content = services
        .fs()
        .read_to_string(&approved)
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, Some(content.len() as u64));
    Ok(content)
}

/// Brokered whole-file byte read.
pub fn broker_fs_read(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    path: &str,
    operation: &'static str,
) -> Result<Vec<u8>, String> {
    let (request, approved) = fs_approved_path(
        ctx,
        services,
        path,
        NseCapabilityKind::FilesystemRead,
        operation,
    )?;
    ctx.before_blocking_operation(&request)?;
    let bytes = services
        .fs()
        .read(&approved)
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, Some(bytes.len() as u64));
    Ok(bytes)
}

/// Brokered file write.
pub fn broker_fs_write(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    path: &str,
    bytes: &[u8],
    operation: &'static str,
) -> Result<(), String> {
    ctx.check_cancelled(operation)?;
    let resolved = broker_fs_resolve(services, path, operation)?;
    let request = broker_request(
        NseCapabilityKind::FilesystemWrite,
        Some(resolved.to_string_lossy().to_string()),
        Some(bytes.len() as u64),
        operation,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "filesystem write denied"));
    }
    let approved = match ctx.sandbox.get_allowed_path(&resolved.to_string_lossy()) {
        Some(approved) => approved,
        None => {
            return Err(format!(
                "{operation}: path '{}' blocked by sandbox",
                resolved.display()
            ))
        }
    };
    ctx.before_blocking_operation(&request)?;
    services
        .fs()
        .write(&approved, bytes)
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, Some(bytes.len() as u64));
    Ok(())
}

/// Brokered following metadata stat.
pub fn broker_fs_metadata(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    path: &str,
    operation: &'static str,
) -> Result<NseFileMetadata, String> {
    let (request, approved) = fs_approved_path(
        ctx,
        services,
        path,
        NseCapabilityKind::FilesystemRead,
        operation,
    )?;
    ctx.before_blocking_operation(&request)?;
    let meta = services
        .fs()
        .metadata(&approved)
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(meta)
}

/// Brokered symlink (non-following) metadata stat.
pub fn broker_fs_symlink_metadata(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    path: &str,
    operation: &'static str,
) -> Result<NseFileMetadata, String> {
    let (request, approved) = fs_approved_path(
        ctx,
        services,
        path,
        NseCapabilityKind::FilesystemRead,
        operation,
    )?;
    ctx.before_blocking_operation(&request)?;
    let meta = services
        .fs()
        .symlink_metadata(&approved)
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(meta)
}

/// Brokered directory listing.
pub fn broker_fs_read_dir(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    path: &str,
    operation: &'static str,
) -> Result<Vec<NseDirEntry>, String> {
    let (request, approved) = fs_approved_path(
        ctx,
        services,
        path,
        NseCapabilityKind::FilesystemRead,
        operation,
    )?;
    ctx.before_blocking_operation(&request)?;
    let entries = services
        .fs()
        .read_dir(&approved)
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(entries)
}

/// Brokered file removal.
pub fn broker_fs_remove_file(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    path: &str,
    operation: &'static str,
) -> Result<(), String> {
    let (request, approved) = fs_approved_path(
        ctx,
        services,
        path,
        NseCapabilityKind::FilesystemWrite,
        operation,
    )?;
    ctx.before_blocking_operation(&request)?;
    services
        .fs()
        .remove_file(&approved)
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(())
}

/// Brokered rename/move (both ends resolved, checked, and sandbox-approved).
pub fn broker_fs_rename(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    from: &str,
    to: &str,
    operation: &'static str,
) -> Result<(), String> {
    let (request, approved_from) = fs_approved_path(
        ctx,
        services,
        from,
        NseCapabilityKind::FilesystemWrite,
        operation,
    )?;
    let resolved_to = broker_fs_resolve(services, to, operation)?;
    let request_to = broker_request(
        NseCapabilityKind::FilesystemWrite,
        Some(resolved_to.to_string_lossy().to_string()),
        None,
        operation,
    );
    let decision = ctx.check_capability(&request_to);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "filesystem write denied"));
    }
    let approved_to = match ctx.sandbox.get_allowed_path(&resolved_to.to_string_lossy()) {
        Some(approved) => approved,
        None => {
            return Err(format!(
                "{operation}: path '{}' blocked by sandbox",
                resolved_to.display()
            ))
        }
    };
    ctx.before_blocking_operation(&request)?;
    services
        .fs()
        .rename(&approved_from, &approved_to)
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(())
}

/// Brokered recursive directory creation.
pub fn broker_fs_create_dir_all(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    path: &str,
    operation: &'static str,
) -> Result<(), String> {
    let (request, approved) = fs_approved_path(
        ctx,
        services,
        path,
        NseCapabilityKind::FilesystemWrite,
        operation,
    )?;
    ctx.before_blocking_operation(&request)?;
    services
        .fs()
        .create_dir_all(&approved)
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(())
}

/// Brokered empty-directory removal.
pub fn broker_fs_remove_dir(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    path: &str,
    operation: &'static str,
) -> Result<(), String> {
    let (request, approved) = fs_approved_path(
        ctx,
        services,
        path,
        NseCapabilityKind::FilesystemWrite,
        operation,
    )?;
    ctx.before_blocking_operation(&request)?;
    services
        .fs()
        .remove_dir(&approved)
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(())
}

/// Brokered hard-link creation (both ends approved).
pub fn broker_fs_hard_link(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    src: &str,
    dst: &str,
    operation: &'static str,
) -> Result<(), String> {
    let (request, approved_src) = fs_approved_path(
        ctx,
        services,
        src,
        NseCapabilityKind::FilesystemWrite,
        operation,
    )?;
    let resolved_dst = broker_fs_resolve(services, dst, operation)?;
    let decision = ctx.check_capability(&broker_request(
        NseCapabilityKind::FilesystemWrite,
        Some(resolved_dst.to_string_lossy().to_string()),
        None,
        operation,
    ));
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "filesystem write denied"));
    }
    let approved_dst = match ctx
        .sandbox
        .get_allowed_path(&resolved_dst.to_string_lossy())
    {
        Some(approved) => approved,
        None => {
            return Err(format!(
                "{operation}: path '{}' blocked by sandbox",
                resolved_dst.display()
            ))
        }
    };
    ctx.before_blocking_operation(&request)?;
    services
        .fs()
        .hard_link(&approved_src, &approved_dst)
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(())
}

/// Brokered symlink creation (both ends approved; platform-localized).
pub fn broker_fs_symlink(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    src: &str,
    dst: &str,
    operation: &'static str,
) -> Result<(), String> {
    let (request, approved_src) = fs_approved_path(
        ctx,
        services,
        src,
        NseCapabilityKind::FilesystemWrite,
        operation,
    )?;
    let resolved_dst = broker_fs_resolve(services, dst, operation)?;
    let decision = ctx.check_capability(&broker_request(
        NseCapabilityKind::FilesystemWrite,
        Some(resolved_dst.to_string_lossy().to_string()),
        None,
        operation,
    ));
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "filesystem write denied"));
    }
    let approved_dst = match ctx
        .sandbox
        .get_allowed_path(&resolved_dst.to_string_lossy())
    {
        Some(approved) => approved,
        None => {
            return Err(format!(
                "{operation}: path '{}' blocked by sandbox",
                resolved_dst.display()
            ))
        }
    };
    ctx.before_blocking_operation(&request)?;
    services
        .fs()
        .symlink(&approved_src, &approved_dst)
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(())
}

/// Brokered symlink-target read.
pub fn broker_fs_read_link(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    path: &str,
    operation: &'static str,
) -> Result<FsPathBuf, String> {
    let (request, approved) = fs_approved_path(
        ctx,
        services,
        path,
        NseCapabilityKind::FilesystemRead,
        operation,
    )?;
    ctx.before_blocking_operation(&request)?;
    let target = services
        .fs()
        .read_link(&approved)
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(target)
}

/// Brokered Unix permission-bit change (unsupported on non-Unix providers).
pub fn broker_fs_set_unix_mode(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    path: &str,
    mode: u32,
    operation: &'static str,
) -> Result<(), String> {
    let (request, approved) = fs_approved_path(
        ctx,
        services,
        path,
        NseCapabilityKind::FilesystemWrite,
        operation,
    )?;
    ctx.before_blocking_operation(&request)?;
    services
        .fs()
        .set_unix_mode(&approved, mode)
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(())
}

/// Brokered read-only flag change (portable).
pub fn broker_fs_set_readonly(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    path: &str,
    readonly: bool,
    operation: &'static str,
) -> Result<(), String> {
    let (request, approved) = fs_approved_path(
        ctx,
        services,
        path,
        NseCapabilityKind::FilesystemWrite,
        operation,
    )?;
    ctx.before_blocking_operation(&request)?;
    services
        .fs()
        .set_readonly(&approved, readonly)
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(())
}

/// Brokered existence probe.
pub fn broker_fs_exists(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    path: &str,
    operation: &'static str,
) -> bool {
    // Existence is a read-class question; denial or cancellation answers
    // "no" without touching the provider.
    if ctx.check_cancelled(operation).is_err() {
        return false;
    }
    let Ok(resolved) = broker_fs_resolve(services, path, operation) else {
        return false;
    };
    let decision = ctx.check_capability(&broker_request(
        NseCapabilityKind::FilesystemRead,
        Some(resolved.to_string_lossy().to_string()),
        None,
        operation,
    ));
    if !decision.is_allowed() {
        return false;
    }
    if ctx
        .sandbox
        .get_allowed_path(&resolved.to_string_lossy())
        .is_none()
    {
        return false;
    }
    services.fs().exists(&resolved)
}

/// Brokered file-handle open (returns the opaque handle; callers own it).
pub fn broker_fs_open(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    path: &str,
    mode: NseOpenMode,
    operation: &'static str,
) -> Result<Box<dyn NseFileHandle>, String> {
    let kind = if mode.is_write() {
        NseCapabilityKind::FilesystemWrite
    } else {
        NseCapabilityKind::FilesystemRead
    };
    let (request, approved) = fs_approved_path(ctx, services, path, kind, operation)?;
    ctx.before_blocking_operation(&request)?;
    let handle = services
        .fs()
        .open(&approved, mode)
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(handle)
}

/// Brokered per-run working-directory read.
pub fn broker_fs_current_dir(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    operation: &'static str,
) -> Result<FsPathBuf, String> {
    ctx.check_cancelled(operation)?;
    let request = broker_request(NseCapabilityKind::FilesystemRead, None, None, operation);
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "filesystem access denied"));
    }
    ctx.before_blocking_operation(&request)?;
    let dir = services
        .fs()
        .current_dir()
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(dir)
}

/// Brokered per-run working-directory change.
///
/// Records the virtual CWD override on the provider; never mutates the
/// embedding process.
pub fn broker_fs_set_current_dir(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    path: &str,
    operation: &'static str,
) -> Result<(), String> {
    let (request, approved) = fs_approved_path(
        ctx,
        services,
        path,
        NseCapabilityKind::FilesystemRead,
        operation,
    )?;
    ctx.before_blocking_operation(&request)?;
    services
        .fs()
        .set_current_dir(&approved)
        .map_err(|e| format!("filesystem provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(())
}

/// Brokered bounded process execution.
///
/// Denied in AgentSafe/CiSafe before the provider is invoked.
pub fn broker_process_run(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    spec: &NseProcessSpec,
    operation: &'static str,
) -> Result<NseProcessResult, String> {
    ctx.check_cancelled(operation)?;
    let request = broker_request(
        NseCapabilityKind::ProcessExec,
        Some(spec.program.clone()),
        None,
        operation,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "process execution denied"));
    }
    ctx.before_blocking_operation(&request)?;
    let result = services
        .process()
        .run(spec)
        .map_err(|e| format!("process provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(result)
}

/// Brokered process spawn (for `io.popen` semantics; caller must terminate).
pub fn broker_process_spawn(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    spec: &NseProcessSpec,
    operation: &'static str,
) -> Result<Box<dyn NseChildProcess>, String> {
    ctx.check_cancelled(operation)?;
    let request = broker_request(
        NseCapabilityKind::ProcessExec,
        Some(spec.program.clone()),
        None,
        operation,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "process execution denied"));
    }
    ctx.before_blocking_operation(&request)?;
    let child = services
        .process()
        .spawn(spec)
        .map_err(|e| format!("process provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(child)
}

/// Brokered privilege probe.
pub fn broker_is_privileged(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    program_label: &str,
    operation: &'static str,
) -> Result<bool, String> {
    ctx.check_cancelled(operation)?;
    let request = broker_request(
        NseCapabilityKind::ProcessExec,
        Some(program_label.to_string()),
        None,
        operation,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "process execution denied"));
    }
    ctx.before_blocking_operation(&request)?;
    let privileged = services
        .process()
        .is_privileged()
        .map_err(|e| format!("process provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(privileged)
}

/// Brokered interface enumeration.
pub fn broker_network_interfaces(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    program_label: &str,
    operation: &'static str,
) -> Result<Vec<NseNetworkInterface>, String> {
    ctx.check_cancelled(operation)?;
    let request = broker_request(
        NseCapabilityKind::ProcessExec,
        Some(program_label.to_string()),
        None,
        operation,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(deny_message(&decision, "process execution denied"));
    }
    ctx.before_blocking_operation(&request)?;
    let interfaces = services
        .process()
        .network_interfaces()
        .map_err(|e| format!("process provider failed: {e}"))?;
    ctx.after_blocking_operation(&request, None);
    Ok(interfaces)
}

/// Parse `ip addr` output into interface records (moved verbatim from the
/// compatibility layer so behavior is preserved).
fn parse_ip_addr_output(output: &str) -> Vec<NseNetworkInterface> {
    let mut interfaces: Vec<NseNetworkInterface> = Vec::new();
    let mut current: Option<NseNetworkInterface> = None;
    for line in output.lines() {
        if line
            .split(':')
            .nth(1)
            .map(|name| !name.trim().is_empty())
            .unwrap_or(false)
            && line.starts_with(|c: char| c.is_ascii_digit())
        {
            if let Some(iface) = current.take() {
                interfaces.push(iface);
            }
            let name = line
                .split(':')
                .nth(1)
                .unwrap_or("unknown")
                .trim()
                .split('@')
                .next()
                .unwrap_or("unknown")
                .to_string();
            current = Some(NseNetworkInterface::new(name, Vec::new()));
        } else if line.trim().starts_with("inet ") {
            if let Some(ref mut iface) = current {
                if let Some(addr) = line.trim().split_whitespace().nth(1) {
                    let ip = addr.split('/').next().unwrap_or(addr);
                    if let Some(parsed) = NseIpAddress::parse(ip) {
                        iface.addresses.push(parsed);
                    }
                }
            }
        }
    }
    if let Some(iface) = current.take() {
        interfaces.push(iface);
    }
    if interfaces.is_empty() {
        interfaces.push(NseNetworkInterface::new(
            "lo",
            vec![NseIpAddress::V4([127, 0, 0, 1])],
        ));
    }
    interfaces
}

/// Parse `ipconfig` output into interface records (moved verbatim from the
/// compatibility layer so behavior is preserved).
#[cfg(windows)]
fn parse_ipconfig_output(output: &str) -> Vec<NseNetworkInterface> {
    let mut interfaces: Vec<NseNetworkInterface> = Vec::new();
    let mut current: Option<NseNetworkInterface> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with(':') && !trimmed.contains("adapter") && !trimmed.is_empty() {
            if let Some(iface) = current.take() {
                if !iface.addresses.is_empty() || !iface.name.is_empty() {
                    interfaces.push(iface);
                }
            }
            current = Some(NseNetworkInterface::new(
                trimmed.trim_end_matches(':').trim(),
                Vec::new(),
            ));
        } else if trimmed.to_lowercase().starts_with("ipv4") {
            if let Some(ref mut iface) = current {
                if let Some(addr) = trimmed.split(':').nth(1) {
                    if let Some(parsed) = NseIpAddress::parse(addr.trim()) {
                        iface.addresses.push(parsed);
                    }
                }
            }
        }
    }
    if let Some(iface) = current.take() {
        if !iface.addresses.is_empty() || !iface.name.is_empty() {
            interfaces.push(iface);
        }
    }
    if interfaces.is_empty() {
        interfaces.push(NseNetworkInterface::new(
            "lo",
            vec![NseIpAddress::V4([127, 0, 0, 1])],
        ));
    }
    interfaces
}

// ---------------------------------------------------------------------------
// M005C: HTTP provider (runtime-neutral contract + native reqwest backend).
//
// ADR-0003 boundary: a narrow HTTP trait joins the per-run
// [`NseHostServices`] bundle; the capability-aware broker owns the runtime
// capability check -> cancellation/budget preflight -> provider request ->
// accounting/event sequence. DTOs are runtime-owned (no reqwest/Eggsec
// types in the contract); the native provider uses reqwest internally in
// this allow-listed module. TLS intent (`insecure_tls`) is set by the
// calling library from the capability profile — scripts cannot escalate it.
// ---------------------------------------------------------------------------

/// HTTP method covered by the NSE parity matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NseHttpMethod {
    /// GET.
    Get,
    /// POST.
    Post,
    /// PUT.
    Put,
    /// DELETE.
    Delete,
    /// PATCH.
    Patch,
    /// HEAD.
    Head,
    /// OPTIONS.
    Options,
    /// TRACE.
    Trace,
}

impl NseHttpMethod {
    /// Parse a method name (case-insensitive). Unknown names fail closed:
    /// callers needing legacy leniency map to `Get` before the broker.
    pub fn parse(name: &str) -> Result<Self, NseProviderError> {
        match name.trim().to_ascii_uppercase().as_str() {
            "GET" => Ok(Self::Get),
            "POST" => Ok(Self::Post),
            "PUT" => Ok(Self::Put),
            "DELETE" => Ok(Self::Delete),
            "PATCH" => Ok(Self::Patch),
            "HEAD" => Ok(Self::Head),
            "OPTIONS" => Ok(Self::Options),
            "TRACE" => Ok(Self::Trace),
            other => Err(NseProviderError::new(
                "http",
                format!("unsupported NSE HTTP method '{other}'"),
            )),
        }
    }

    /// Canonical method token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
        }
    }
}

/// Runtime-owned HTTP request DTO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NseHttpRequest {
    /// Request method.
    pub method: NseHttpMethod,
    /// Canonical URL (built by the calling library).
    pub url: String,
    /// Host identity for capability evaluation (set by the library that
    /// built the URL, so the broker never parses authority from strings).
    pub host: String,
    /// Request headers (overwrite semantics).
    pub headers: Vec<(String, String)>,
    /// Replayable body bytes (empty = no body).
    pub body: Vec<u8>,
    /// Per-request timeout.
    pub timeout: std::time::Duration,
    /// Connect timeout.
    pub connect_timeout: std::time::Duration,
    /// TLS verification bypass intent. Set by the calling library from the
    /// capability profile (`allows_insecure_tls`); scripts cannot escalate.
    pub insecure_tls: bool,
}

impl NseHttpRequest {
    /// Build a GET request with default timeouts (30s/10s, verified TLS).
    pub fn get(url: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            method: NseHttpMethod::Get,
            url: url.into(),
            host: host.into(),
            headers: Vec::new(),
            body: Vec::new(),
            timeout: std::time::Duration::from_secs(30),
            connect_timeout: std::time::Duration::from_secs(10),
            insecure_tls: false,
        }
    }
}

/// Runtime-owned HTTP response DTO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NseHttpResponse {
    /// HTTP status code (`0` is never produced by providers; transport
    /// failures surface as [`NseHttpError`]).
    pub status: u16,
    /// Response headers in received order.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
    /// Final URL after redirects.
    pub final_url: String,
    /// Protocol version label (e.g. `"HTTP/1.1"`).
    pub version: String,
}

impl NseHttpResponse {
    /// First header value for `name` (case-insensitive), if present.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Body as lossy text.
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

/// Typed HTTP provider failure (preserves the legacy timeout/connection/
/// request classification for Lua `reason` mapping).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NseHttpError {
    /// Capability/sandbox denial (provider not called).
    Denied(String),
    /// Cancellation (provider not called, or await abandoned).
    Cancelled(String),
    /// Bounded timeout exceeded.
    Timeout,
    /// Connection-level failure.
    Connection(String),
    /// Any other request failure.
    Request(String),
}

impl NseHttpError {
    /// Short machine-readable reason (matches the legacy Lua `reason`
    /// values: `denied`, `cancelled`, `timeout`, `connection`, `request`).
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Denied(_) => "denied",
            Self::Cancelled(_) => "cancelled",
            Self::Timeout => "timeout",
            Self::Connection(_) => "connection",
            Self::Request(_) => "request",
        }
    }

    /// Human-readable detail (no secrets).
    pub fn detail(&self) -> String {
        match self {
            Self::Denied(m) | Self::Cancelled(m) | Self::Connection(m) | Self::Request(m) => {
                m.clone()
            }
            Self::Timeout => "HTTP request timed out".to_string(),
        }
    }
}

impl std::fmt::Display for NseHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.detail())
    }
}

impl std::error::Error for NseHttpError {}

/// HTTP request execution.
///
/// Synchronous (blocking) contract usable from sync Lua closures; async
/// library variants call the broker inline with bounded timeouts (no
/// detached tasks).
pub trait NseHttpProvider: Send + Sync {
    /// Execute one request.
    fn request(&self, req: &NseHttpRequest) -> Result<NseHttpResponse, NseHttpError>;
}

// ---------------------------------------------------------------------------
// Native implementations (default behavior for existing callers).
// ---------------------------------------------------------------------------

/// Native HTTP backed by reqwest (single allow-listed native zone).
///
/// Clients are cached per instance keyed by (insecure-TLS, timeout,
/// connect-timeout), so one bundle reuses pooled connections without any
/// process-global client or TLS-flag state.
pub struct NativeHttpProvider {
    clients: Mutex<HashMap<(bool, u64, u64), reqwest::blocking::Client>>,
}

impl NativeHttpProvider {
    /// Build a native HTTP provider.
    pub fn new() -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
        }
    }

    fn client_for(&self, req: &NseHttpRequest) -> Result<reqwest::blocking::Client, NseHttpError> {
        let key = (
            req.insecure_tls,
            req.timeout.as_secs(),
            req.connect_timeout.as_secs(),
        );
        let mut clients = self
            .clients
            .lock()
            .map_err(|e| NseHttpError::Request(format!("HTTP client cache lock failed: {e}")))?;
        if let Some(client) = clients.get(&key) {
            return Ok(client.clone());
        }
        crate::install_tls_provider();
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(req.timeout.max(std::time::Duration::from_secs(1)))
            .connect_timeout(req.connect_timeout)
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(std::time::Duration::from_secs(30));
        if req.insecure_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder
            .build()
            .map_err(|e| NseHttpError::Request(format!("HTTP client build failed: {e}")))?;
        clients.insert(key, client.clone());
        Ok(client)
    }
}

impl Default for NativeHttpProvider {
    fn default() -> Self {
        Self::new()
    }
}

fn native_http_method(method: NseHttpMethod) -> reqwest::Method {
    match method {
        NseHttpMethod::Get => reqwest::Method::GET,
        NseHttpMethod::Post => reqwest::Method::POST,
        NseHttpMethod::Put => reqwest::Method::PUT,
        NseHttpMethod::Delete => reqwest::Method::DELETE,
        NseHttpMethod::Patch => reqwest::Method::PATCH,
        NseHttpMethod::Head => reqwest::Method::HEAD,
        NseHttpMethod::Options => reqwest::Method::OPTIONS,
        NseHttpMethod::Trace => reqwest::Method::TRACE,
    }
}

fn native_http_error(e: reqwest::Error) -> NseHttpError {
    if e.is_timeout() {
        NseHttpError::Timeout
    } else if e.is_connect() {
        NseHttpError::Connection(e.to_string())
    } else {
        NseHttpError::Request(e.to_string())
    }
}

impl NseHttpProvider for NativeHttpProvider {
    fn request(&self, req: &NseHttpRequest) -> Result<NseHttpResponse, NseHttpError> {
        let client = self.client_for(req)?;
        let mut builder = client.request(native_http_method(req.method), &req.url);
        for (name, value) in &req.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        if !req.body.is_empty() {
            builder = builder.body(req.body.clone());
        }
        let resp = builder.send().map_err(native_http_error)?;
        let status = resp.status().as_u16();
        let version = format!("{:?}", resp.version());
        let final_url = resp.url().to_string();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = resp.bytes().map(|b| b.to_vec()).unwrap_or_default();
        Ok(NseHttpResponse {
            status,
            headers,
            body,
            final_url,
            version,
        })
    }
}

// ---------------------------------------------------------------------------
// Deterministic test providers (public so downstream harnesses can reuse).
// ---------------------------------------------------------------------------

/// Scripted HTTP provider: pops one programmed outcome per call and logs
/// every request identity it receives.
pub struct MockHttpProvider {
    script: Mutex<VecDeque<Result<NseHttpResponse, NseHttpError>>>,
    requests: Mutex<Vec<NseHttpRequest>>,
}

impl MockHttpProvider {
    /// Build from a per-call outcome script.
    pub fn new(script: Vec<Result<NseHttpResponse, NseHttpError>>) -> Self {
        Self {
            script: Mutex::new(script.into()),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Request identities received, in order.
    pub fn requests(&self) -> Vec<NseHttpRequest> {
        self.requests.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl NseHttpProvider for MockHttpProvider {
    fn request(&self, req: &NseHttpRequest) -> Result<NseHttpResponse, NseHttpError> {
        self.requests
            .lock()
            .map(|mut g| g.push(req.clone()))
            .unwrap_or(());
        self.script
            .lock()
            .map_err(|e| NseHttpError::Request(format!("mock HTTP lock failed: {e}")))
            .and_then(|mut script| {
                script.pop_front().unwrap_or(Err(NseHttpError::Request(
                    "mock HTTP script exhausted".to_string(),
                )))
            })
    }
}

/// Counting HTTP wrapper proving denial prevents provider invocation.
pub struct CountingHttpProvider {
    inner: MockHttpProvider,
    calls: AtomicU64,
}

impl CountingHttpProvider {
    /// Build a counting wrapper around a scripted outcome list.
    pub fn new(script: Vec<Result<NseHttpResponse, NseHttpError>>) -> Self {
        Self {
            inner: MockHttpProvider::new(script),
            calls: AtomicU64::new(0),
        }
    }

    /// Number of provider invocations observed.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    /// Request identities received, in order.
    pub fn requests(&self) -> Vec<NseHttpRequest> {
        self.inner.requests()
    }
}

impl NseHttpProvider for CountingHttpProvider {
    fn request(&self, req: &NseHttpRequest) -> Result<NseHttpResponse, NseHttpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.request(req)
    }
}

// ---------------------------------------------------------------------------
// Capability-aware broker function (HTTP, M005C).
//
// Sequence (ADR-0003): runtime capability check on the library-supplied
// host identity -> cancellation/budget preflight -> provider request ->
// accounting/event result. Denial or cancellation never reaches the
// provider. TLS intent travels inside the request DTO (set by the library
// from the profile, never by scripts).
// ---------------------------------------------------------------------------

/// Brokered HTTP request.
pub fn broker_http_request(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    request: &NseHttpRequest,
    operation: &'static str,
) -> Result<NseHttpResponse, NseHttpError> {
    if let Err(e) = ctx.check_cancelled(operation) {
        return Err(NseHttpError::Cancelled(e));
    }
    // Response size is unknowable before the call, so no byte hint is
    // preflighted here; request/response bodies are bucketed post-call.
    let broker_request = broker_request(
        NseCapabilityKind::NetworkTcp,
        Some(request.host.clone()),
        None,
        operation,
    );
    let decision = ctx.check_capability(&broker_request);
    if !decision.is_allowed() {
        return Err(NseHttpError::Denied(deny_message(
            &decision,
            "network HTTP request denied",
        )));
    }
    if let Err(e) = ctx.before_blocking_operation(&broker_request) {
        if e.contains("cancelled") {
            return Err(NseHttpError::Cancelled(e));
        }
        return Err(NseHttpError::Request(e));
    }
    let response = services.http().request(request)?;
    // Direction-correct accounting: response bytes are read, request body
    // bytes are written (never lumped into the read bucket).
    ctx.after_blocking_operation(&broker_request, Some(response.body.len() as u64));
    ctx.counters.network_bytes_written.fetch_add(
        request.body.len() as u64,
        std::sync::atomic::Ordering::AcqRel,
    );
    Ok(response)
}
