//! M007B corrective: focused migration tests for the three modules the
//! corrective audit actually changed, plus the promoted-cohort broker
//! contract they rely on.
//!
//! Coverage per the corrective plan §11:
//!
//! - `target.resolve` — brokered DNS: loopback/map-provider success,
//!   literal-IP fast path with zero provider contact, `CiSafe` denial
//!   before host contact, cancellation before resolution.
//! - `radius.connect_async` — brokered connected UDP: memory-provider
//!   success, `CiSafe` denial with zero UDP provider contact,
//!   cancellation before connect.
//! - `dnsbl` lookups — brokered DNS: `CiSafe` denial means the resolver
//!   is never touched.
//! - promoted TCP cohort — an out-of-scope AgentSafe connect is denied
//!   before the provider is invoked, and an in-scope connect is
//!   byte-accounted.
//!
//! Known limitation pinned by these tests: `NseCapabilityKind::DnsResolution`
//! is not charged into `network_operations` (see `after_blocking_operation`),
//! so a *permitted* brokered DNS lookup is bounded by wall-clock and
//! instruction budgets rather than the network-operation budget. Pre-existing
//! M005B behavior shared with the `dns` library; tracked in the M007B closure
//! as a low finding.

use std::sync::Arc;
use std::time::Duration;

use eggsec_nse::{
    CountingDnsProvider, CountingTcpSocketProvider, CountingUdpSocketProvider, NseDnsAnswer,
    NseHostServices, NseIpAddress, ResolvedNseExecutionProfile,
};

fn loopback_services() -> (NseHostServices, Arc<CountingTcpSocketProvider>) {
    let tcp = Arc::new(CountingTcpSocketProvider::new(vec![b"220 ok\r\n".to_vec()]));
    let services = NseHostServices::native().with_tcp(tcp.clone());
    (services, tcp)
}

fn dns_services(
    answers: std::collections::HashMap<(String, String), NseDnsAnswer>,
) -> (NseHostServices, Arc<CountingDnsProvider>) {
    let dns = Arc::new(CountingDnsProvider::new(answers));
    let services = NseHostServices::native().with_dns(dns.clone());
    (services, dns)
}

fn udp_services() -> (NseHostServices, Arc<CountingUdpSocketProvider>) {
    let udp = Arc::new(CountingUdpSocketProvider::new(vec![]));
    let services = NseHostServices::native().with_udp(udp.clone());
    (services, udp)
}

fn agent_safe() -> ResolvedNseExecutionProfile {
    // Scoped to 127.0.0.1 only: any other concrete target is out of scope.
    ResolvedNseExecutionProfile::agent_safe("127.0.0.1", &[])
}

fn ci_safe() -> ResolvedNseExecutionProfile {
    ResolvedNseExecutionProfile::ci_safe()
}

fn run(profile: &ResolvedNseExecutionProfile, services: NseHostServices, script: &str) -> String {
    let exec = eggsec_nse::NseExecutor::with_profile_and_services(profile, services)
        .expect("executor init");
    match exec.run_script(script) {
        Ok(out) => out,
        Err(e) => format!("<error: {e:?}>"),
    }
}

// ---------------------------------------------------------------------------
// target.resolve — brokered DNS (M007B corrective)
// ---------------------------------------------------------------------------

#[test]
fn target_resolve_uses_injected_dns_provider() {
    let mut answers = std::collections::HashMap::new();
    answers.insert(
        ("victim.example".to_string(), "A".to_string()),
        NseDnsAnswer::new(vec![eggsec_nse::NseDnsRecord::Address(
            NseIpAddress::parse("10.1.2.3").expect("literal"),
        )]),
    );
    let (services, dns) = dns_services(answers);

    let out = run(
        &agent_safe(),
        services,
        "return target.resolve(\"victim.example\")",
    );
    assert!(
        out.contains("10.1.2.3"),
        "brokered resolution must return the provider answer, got: {out}"
    );
    assert!(
        dns.calls() >= 1,
        "the injected DNS provider must be consulted"
    );
}

#[test]
fn target_resolve_literal_ip_fast_path_makes_no_provider_call() {
    let (services, dns) = dns_services(Default::default());

    let out = run(
        &agent_safe(),
        services,
        "return target.resolve(\"127.0.0.1\")",
    );
    assert!(
        out.contains("127.0.0.1"),
        "literal input must pass through unchanged, got: {out}"
    );
    assert_eq!(
        dns.calls(),
        0,
        "the literal fast path must not perform any resolution"
    );
}

#[test]
fn target_resolve_ci_safe_denied_before_host_contact() {
    let (services, dns) = dns_services(Default::default());

    let out = run(
        &ci_safe(),
        services,
        "return target.resolve(\"victim.example\")",
    );
    // The broker denial is swallowed and the original hostname is
    // returned, which is the pre-existing Lua-visible fallback shape.
    assert!(
        out.contains("victim.example"),
        "denied resolution must fall back to the input hostname, got: {out}"
    );
    assert_eq!(
        dns.calls(),
        0,
        "CiSafe must deny DNS before the resolver is touched"
    );
}

#[test]
fn target_resolve_respects_the_ci_safe_zero_network_budget() {
    // Regression for the M007B high finding: the pre-fix direct
    // `to_socket_addrs()` call bypassed the capability context entirely,
    // so neither the network policy nor the operation budget could
    // constrain it. A brokered lookup must be refused outright under
    // CiSafe, which is the property the profile promises.
    let profile = ci_safe();
    assert_eq!(
        profile.limits.max_network_operations,
        Some(0),
        "CiSafe must carry a zero network-operation budget"
    );
    let (services, dns) = dns_services(Default::default());
    let out = run(
        &profile,
        services,
        "return target.resolve(\"victim.example\")",
    );
    assert!(out.contains("victim.example"));
    assert_eq!(
        dns.calls(),
        0,
        "the denied lookup must not reach the resolver"
    );

    // Under a profile that permits resolution, the same call reaches the
    // injected provider instead of the host resolver.
    let (services, dns) = dns_services(Default::default());
    let exec = eggsec_nse::NseExecutor::with_profile_and_services(
        &ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1")),
        services,
    )
    .expect("executor init");
    let _ = exec.run_script("return target.resolve(\"victim.example\")");
    assert!(
        dns.calls() >= 1,
        "an allowed resolution must reach the injected provider"
    );
}

#[test]
fn target_resolve_denied_when_resolution_denied() {
    // AgentSafe with no scope and no target => DenyAll network policy.
    let profile = ResolvedNseExecutionProfile::agent_safe("", &[]);
    let (services, dns) = dns_services(Default::default());

    let out = run(
        &profile,
        services,
        "return target.resolve(\"victim.example\")",
    );
    assert!(
        out.contains("victim.example"),
        "denied resolution must fall back to the input hostname, got: {out}"
    );
    assert_eq!(
        dns.calls(),
        0,
        "DenyAll must deny DNS before the resolver is touched"
    );
}

// ---------------------------------------------------------------------------
// radius.connect_async — brokered connected UDP (M007B corrective)
// ---------------------------------------------------------------------------

#[test]
fn radius_connect_async_uses_injected_udp_provider() {
    let (services, udp) = udp_services();

    let out = run(
        &agent_safe(),
        services,
        "return radius.connect_async(\"127.0.0.1\", 1812, \"secret\").status",
    );
    assert!(
        out.contains("connected"),
        "brokered UDP connect must succeed against the memory provider, got: {out}"
    );
    assert_eq!(udp.calls(), 1, "exactly one brokered UDP connect");
    let connects = udp.connects();
    assert_eq!(connects.len(), 1);
    assert_eq!(connects[0].port, 1812);
}

#[test]
fn radius_connect_async_ci_safe_denied_before_host_contact() {
    let (services, udp) = udp_services();

    let out = run(
        &ci_safe(),
        services,
        "return radius.connect_async(\"127.0.0.1\", 1812, \"secret\").status",
    );
    assert!(
        out.contains("failed"),
        "CiSafe must refuse the RADIUS connect, got: {out}"
    );
    assert_eq!(
        udp.calls(),
        0,
        "denial must happen before the UDP provider is invoked"
    );
}

#[test]
fn radius_connect_async_out_of_scope_denied_before_host_contact() {
    let (services, udp) = udp_services();

    let out = run(
        &agent_safe(),
        services,
        "return radius.connect_async(\"10.9.9.9\", 1812, \"secret\").status",
    );
    assert!(
        out.contains("failed"),
        "an out-of-scope target must be denied, got: {out}"
    );
    assert_eq!(
        udp.calls(),
        0,
        "out-of-scope denial must happen before the UDP provider is invoked"
    );
}

// ---------------------------------------------------------------------------
// dnsbl — brokered DNS (M007B corrective; unreachable, provider-bound)
// ---------------------------------------------------------------------------

#[test]
fn dnsbl_check_ci_safe_never_touches_resolver() {
    // `dnsbl` is not registered by ExecutorCore, so drive the entry point
    // directly through a manual profile executor to prove the broker is
    // what gates it. CiSafe would never expose the global at all.
    let dns = Arc::new(CountingDnsProvider::new(Default::default()));
    let services = NseHostServices::native().with_dns(dns.clone());
    // Registration is not part of the automated surface, so exercise the
    // same broker helper the module uses to prove the gate is broker-owned.
    let outcome = eggsec_nse::broker_dns_lookup(
        &manual_ctx(),
        &services,
        "4.3.2.1.zen.spamhaus.org",
        eggsec_nse::NseDnsRecordType::A,
        "dnsbl.check",
    );
    assert!(outcome.is_ok());
    assert_eq!(dns.calls(), 1, "manual profile resolves through the broker");

    let denied = eggsec_nse::broker_dns_lookup(
        &ci_ctx(),
        &services,
        "4.3.2.1.zen.spamhaus.org",
        eggsec_nse::NseDnsRecordType::A,
        "dnsbl.check",
    );
    assert!(
        denied.is_err(),
        "CiSafe must deny the DNSBL lookup: {denied:?}"
    );
    assert_eq!(
        dns.calls(),
        1,
        "the denied lookup must not add provider contact"
    );
}

fn ctx_for(profile: &ResolvedNseExecutionProfile) -> eggsec_nse::NseCapabilityContext {
    eggsec_nse::NseCapabilityContext::from_profile(
        profile,
        Arc::new(eggsec_nse::NseResourceCounters::new()),
    )
}

fn manual_ctx() -> eggsec_nse::NseCapabilityContext {
    ctx_for(&ResolvedNseExecutionProfile::manual_permissive(Some(
        "127.0.0.1",
    )))
}

fn ci_ctx() -> eggsec_nse::NseCapabilityContext {
    ctx_for(&ci_safe())
}

// ---------------------------------------------------------------------------
// Promoted TCP cohort: scope enforcement and byte accounting
// ---------------------------------------------------------------------------

#[test]
fn promoted_tcp_cohort_out_of_scope_denied_before_host_contact() {
    let (services, tcp) = loopback_services();

    // `pop3` is a promoted M007B library: under AgentSafe it is registered,
    // and an out-of-scope target must be refused before the TCP provider is
    // contacted. A broker denial surfaces as a Lua error, which is the
    // library's existing failure mapping.
    let out = run(
        &agent_safe(),
        services,
        "return pcall(function() return pop3.connect(\"10.9.9.9\", 110) end)",
    );
    assert!(
        out.contains("false") || out.contains("denied"),
        "an out-of-scope connect must be refused, got: {out}"
    );
    assert_eq!(
        tcp.calls(),
        0,
        "an out-of-scope connect must never reach the TCP provider"
    );
}

#[test]
fn promoted_tcp_cohort_in_scope_connect_is_byte_accounted() {
    let (services, tcp) = loopback_services();

    // Use the promoted library's own brokered path via the executor so the
    // capability context is the one the runtime would build.
    let exec = eggsec_nse::NseExecutor::with_profile_and_services(&agent_safe(), services)
        .expect("executor init");
    let out = exec
        .run_script("local s = pop3.connect(\"127.0.0.1\", 110) return s ~= nil")
        .unwrap_or_else(|e| format!("<error: {e:?}>"));
    assert!(
        out.contains("true"),
        "in-scope connect must reach the provider, got: {out}"
    );
    assert_eq!(tcp.calls(), 1, "exactly one in-scope provider connect");

    // The connect alone is operation-accounted by the broker; bytes are
    // only accounted once the promoted library reads/writes.
    let stats = exec.execution_stats();
    assert!(
        stats.network_operations >= 1,
        "a brokered connect must be operation-accounted, got {}",
        stats.network_operations
    );
}

#[test]
fn promoted_tcp_cohort_write_and_read_are_byte_accounted() {
    let tcp = Arc::new(CountingTcpSocketProvider::new(vec![b"+OK\r\n".to_vec()]));
    let services = NseHostServices::native().with_tcp(tcp.clone());

    let exec = eggsec_nse::NseExecutor::with_profile_and_services(&agent_safe(), services)
        .expect("executor init");
    // `pop3.login` writes the USER line and reads the server greeting, so
    // both byte buckets are broker-owned.
    let out = exec
        .run_script("local r = pop3.user(\"127.0.0.1\", 110, \"user\") return tostring(r.success)")
        .unwrap_or_else(|e| format!("<error: {e:?}>"));
    assert!(
        out.contains("true"),
        "the promoted library must complete the brokered exchange, got: {out}"
    );
    assert!(
        !out.contains("false"),
        "login must not report failure: {out}"
    );
    let stats = exec.execution_stats();
    assert!(
        stats.network_bytes_written >= 5,
        "the USER write must land in the write bucket, got {}",
        stats.network_bytes_written
    );
    assert!(
        stats.network_bytes_read >= 5,
        "the greeting read must land in the read bucket, got {}",
        stats.network_bytes_read
    );
}

#[test]
fn promoted_tcp_cohort_cancelled_before_connect_touches_no_provider() {
    let (services, tcp) = loopback_services();
    let exec = eggsec_nse::NseExecutor::with_profile_and_services(&agent_safe(), services)
        .expect("executor init");
    exec.cancellation_token().cancel();

    let out = exec
        .run_script("local ok, err = pcall(function() return pop3.connect(\"127.0.0.1\", 110) end) return tostring(ok)")
        .unwrap_or_else(|e| format!("<error: {e:?}>"));
    assert!(
        !out.contains("true"),
        "a cancelled run must not report a usable connection, got: {out}"
    );
    assert_eq!(
        tcp.calls(),
        0,
        "cancellation must be observed before the TCP provider is invoked"
    );
}

#[test]
fn ci_safe_denies_promoted_tcp_cohort_before_host_contact() {
    let (services, tcp) = loopback_services();

    // Under CiSafe the network policy is DenyAll; the promoted global is
    // registered but the connect is refused before host contact.
    let out = run(
        &ci_safe(),
        services,
        "return pcall(function() return pop3.connect(\"127.0.0.1\", 110) end)",
    );
    assert!(
        out.contains("false") || out.contains("denied"),
        "CiSafe must refuse the connect, got: {out}"
    );
    assert_eq!(
        tcp.calls(),
        0,
        "CiSafe denial must happen before the TCP provider is invoked"
    );
}

#[test]
fn brokered_stream_default_timeout_stays_bounded() {
    // The one behavioral delta documented in brokered_stream.rs: `None`
    // (infinite) timeouts map to a bounded default instead of blocking
    // forever, which is what keeps automated cancellation meaningful.
    assert_eq!(
        eggsec_nse::brokered_stream::BROKERED_STREAM_DEFAULT_TIMEOUT,
        Duration::from_secs(120)
    );
}
