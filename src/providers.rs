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
/// Carries the M005A domains plus the M005B network/DNS domains; later M005
/// slices extend this struct with additional provider fields. Cloning shares
/// the underlying providers (cheap `Arc` clones) so concurrent runs can hold
/// different bundles without process-global state.
#[derive(Clone)]
pub struct NseHostServices {
    clock: Arc<dyn NseClockProvider>,
    random: Arc<dyn NseRandomProvider>,
    environment: Arc<dyn NseEnvironmentProvider>,
    dns: Arc<dyn NseDnsProvider>,
    tcp: Arc<dyn NseTcpSocketProvider>,
    udp: Arc<dyn NseUdpSocketProvider>,
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
        }
    }

    /// Build from explicit providers.
    ///
    /// The M005A three-domain form is preserved for compatibility; network
    /// domains default to native. Use the `with_dns`/`with_tcp`/`with_udp`
    /// builders to override them.
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
    ctx.before_blocking_operation(&request)?;
    let n = handle
        .send(data)
        .map_err(|e| format!("TCP send failed: {e}"))?;
    ctx.after_blocking_operation(&request, Some(n as u64));
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
    ctx.before_blocking_operation(&request)?;
    let n = handle
        .send(data)
        .map_err(|e| format!("UDP send failed: {e}"))?;
    ctx.after_blocking_operation(&request, Some(n as u64));
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
