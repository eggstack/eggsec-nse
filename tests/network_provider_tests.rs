//! M005B authority-preserving network/DNS integration tests.
//!
//! Proves the provider broker resolves, policy-selects a concrete endpoint,
//! and connects exactly it: no hostname re-resolution, fail-closed
//! restricted profiles, denial/cancellation never touching providers, and
//! accounting/cancellation surrounding real provider operations.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eggsec_nse::limits::{NseCancellationToken, NseExecutionLimits, NseResourceCounters};
use eggsec_nse::profile::{
    NseExecutionProfileKind, NseModulePolicy, NseNetworkPolicy, NseScriptPolicy,
};
use eggsec_nse::resolver::NseScriptSource;
use eggsec_nse::{
    broker_dns_lookup, broker_resolve_and_select, broker_tcp_connect, broker_tcp_receive,
    broker_tcp_send, broker_udp_connect, broker_udp_receive, broker_udp_send, execute_nse_run,
    CountingDnsProvider, CountingTcpSocketProvider, CountingUdpSocketProvider, MapDnsProvider,
    MemoryTcpSocketProvider, MemoryUdpSocketProvider, NseCapabilityContext, NseDnsAnswer,
    NseDnsRecord, NseDnsRecordType, NseHostServices, NseIpAddress, NseRunRequest,
    NseTransportProtocol, ResolvedNseExecutionProfile, SandboxConfig, ScriptedDnsProvider,
};

fn policies() -> (NseScriptPolicy, NseModulePolicy) {
    (
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
    )
}

fn test_context(
    kind: NseExecutionProfileKind,
    network: NseNetworkPolicy,
) -> (NseCapabilityContext, Arc<NseResourceCounters>) {
    let (scripts, modules) = policies();
    let counters = Arc::new(NseResourceCounters::default());
    let ctx = NseCapabilityContext::new(
        kind,
        network,
        scripts,
        modules,
        SandboxConfig::default(),
        NseExecutionLimits::default(),
        NseCancellationToken::new(),
        counters.clone(),
    );
    (ctx, counters)
}

fn manual_ctx() -> (NseCapabilityContext, Arc<NseResourceCounters>) {
    test_context(
        NseExecutionProfileKind::ManualPermissive,
        NseNetworkPolicy::AllowAllManual,
    )
}

fn loopback_cidr_ctx() -> (NseCapabilityContext, Arc<NseResourceCounters>) {
    test_context(
        NseExecutionProfileKind::AgentSafe,
        NseNetworkPolicy::AllowCidrs(vec!["127.0.0.0/8".parse().unwrap()]),
    )
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> NseIpAddress {
    NseIpAddress::V4([a, b, c, d])
}

fn addr_answer(ips: Vec<NseIpAddress>) -> NseDnsAnswer {
    NseDnsAnswer::new(ips.into_iter().map(NseDnsRecord::Address).collect())
}

// ---------------------------------------------------------------------------
// DTO unit tests
// ---------------------------------------------------------------------------

#[test]
fn ip_address_parse_display_loopback() {
    let v4 = NseIpAddress::parse("127.0.0.1").expect("v4 parses");
    assert_eq!(v4, NseIpAddress::V4([127, 0, 0, 1]));
    assert_eq!(v4.to_string(), "127.0.0.1");
    assert!(v4.is_loopback());
    assert!(v4.is_v4());
    assert_eq!(v4.reverse_dns_name(), "1.0.0.127.in-addr.arpa");

    let v6 = NseIpAddress::parse("::1").expect("v6 parses");
    assert!(!v6.is_v4());
    assert!(v6.is_loopback());
    assert!(v6.reverse_dns_name().ends_with(".ip6.arpa"));

    assert!(NseIpAddress::parse("not-a-host.example").is_none());
    assert!(NseIpAddress::parse("").is_none());
    assert!(!NseIpAddress::parse("8.8.8.8").unwrap().is_loopback());
}

#[test]
fn dns_record_type_parse_matches_legacy_fallback() {
    assert_eq!(NseDnsRecordType::parse("a"), NseDnsRecordType::A);
    assert_eq!(NseDnsRecordType::parse("AAAA"), NseDnsRecordType::Aaaa);
    assert_eq!(NseDnsRecordType::parse("ptr"), NseDnsRecordType::Ptr);
    assert_eq!(NseDnsRecordType::parse("mystery"), NseDnsRecordType::A);
    assert!(NseDnsRecordType::A.is_address_query());
    assert!(!NseDnsRecordType::Mx.is_address_query());
    assert_eq!(
        addr_answer(vec![v4(1, 2, 3, 4)]).addresses(),
        vec![v4(1, 2, 3, 4)]
    );
}

// ---------------------------------------------------------------------------
// Authority: literal IPs skip the resolver
// ---------------------------------------------------------------------------

#[test]
fn literal_ip_skips_dns_resolver() {
    let (ctx, _) = manual_ctx();
    let dns = Arc::new(CountingDnsProvider::new(HashMap::new()));
    let tcp = Arc::new(MemoryTcpSocketProvider::new(vec![]));
    let services = NseHostServices::native()
        .with_dns(dns.clone())
        .with_tcp(tcp.clone());

    let (handle, endpoint) = broker_tcp_connect(
        &ctx,
        &services,
        "127.0.0.1",
        80,
        Duration::from_secs(1),
        "test.literal",
    )
    .expect("literal connect selects without DNS");

    assert_eq!(dns.calls(), 0, "literal IP must not touch the resolver");
    assert_eq!(endpoint.address, v4(127, 0, 0, 1));
    assert_eq!(endpoint.port, 80);
    assert_eq!(endpoint.protocol, NseTransportProtocol::Tcp);
    assert_eq!(endpoint.hostname, "127.0.0.1");
    assert_eq!(tcp.connects(), vec![endpoint.clone()]);
    assert_eq!(handle.endpoint(), &endpoint);
}

// ---------------------------------------------------------------------------
// Authority: mixed candidates connect only the approved endpoint
// ---------------------------------------------------------------------------

#[test]
fn mixed_candidates_connect_only_approved_endpoint() {
    let (ctx, counters) = loopback_cidr_ctx();
    let mut answers = HashMap::new();
    answers.insert(
        ("mixed.test".to_string(), "A".to_string()),
        addr_answer(vec![v4(192, 0, 2, 1), v4(127, 0, 0, 1)]),
    );
    let dns = Arc::new(MapDnsProvider::new(answers));
    let tcp = Arc::new(MemoryTcpSocketProvider::new(vec![b"banner".to_vec()]));
    let services = NseHostServices::native()
        .with_dns(dns.clone())
        .with_tcp(tcp.clone());

    let ops_before = counters.network_operations.load(Ordering::Relaxed);
    let (mut handle, endpoint) = broker_tcp_connect(
        &ctx,
        &services,
        "mixed.test",
        1234,
        Duration::from_secs(1),
        "test.mixed",
    )
    .expect("an approved candidate exists");

    assert_eq!(endpoint.address, v4(127, 0, 0, 1));
    assert_eq!(tcp.connects().len(), 1);
    assert_eq!(tcp.connects()[0].address, v4(127, 0, 0, 1));

    let sent = broker_tcp_send(&ctx, handle.as_mut(), b"ping", "test.mixed")
        .expect("send on approved handle");
    assert_eq!(sent, 4);
    let received = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "test.mixed")
        .expect("receive on approved handle");
    assert_eq!(received, b"banner");
    assert!(counters.network_operations.load(Ordering::Relaxed) > ops_before);
}

#[test]
fn cidr_deny_fails_closed_without_connect() {
    let (ctx, _) = loopback_cidr_ctx();
    let dns = Arc::new(MapDnsProvider::with_addresses(
        "outside.test",
        vec![v4(192, 0, 2, 1)],
    ));
    let tcp = Arc::new(MemoryTcpSocketProvider::new(vec![]));
    let services = NseHostServices::native()
        .with_dns(dns.clone())
        .with_tcp(tcp.clone());

    let err = match broker_tcp_connect(
        &ctx,
        &services,
        "outside.test",
        80,
        Duration::from_secs(1),
        "test.cidr-deny",
    ) {
        Ok(_) => panic!("no candidate is approved, connect must fail"),
        Err(e) => e,
    };
    assert!(err.contains("no approved concrete endpoint"), "{err}");
    assert!(tcp.connects().is_empty(), "denied host must not connect");
}

#[test]
fn resolved_target_set_selects_member() {
    let (scripts, modules) = policies();
    let counters = Arc::new(NseResourceCounters::default());
    let ctx = NseCapabilityContext::new(
        NseExecutionProfileKind::AgentSafe,
        NseNetworkPolicy::AllowResolvedTargetSet(vec!["127.0.0.1".parse().unwrap()]),
        scripts,
        modules,
        SandboxConfig::default(),
        NseExecutionLimits::default(),
        NseCancellationToken::new(),
        counters,
    );
    let mut answers = HashMap::new();
    answers.insert(
        ("scoped.test".to_string(), "A".to_string()),
        addr_answer(vec![v4(192, 0, 2, 1), v4(127, 0, 0, 1)]),
    );
    let services = NseHostServices::native()
        .with_dns(Arc::new(MapDnsProvider::new(answers)))
        .with_tcp(Arc::new(MemoryTcpSocketProvider::new(vec![])));

    let (_handle, endpoint) = broker_tcp_connect(
        &ctx,
        &services,
        "scoped.test",
        80,
        Duration::from_secs(1),
        "test.target-set",
    )
    .expect("target-set member approved");
    assert_eq!(endpoint.address, v4(127, 0, 0, 1));
}

// ---------------------------------------------------------------------------
// Authority: no second resolution (rebinding)
// ---------------------------------------------------------------------------

#[test]
fn no_second_resolution_for_connect() {
    let (ctx, _) = manual_ctx();
    // Round one answers 10.0.0.9; a hypothetical second round would answer
    // 10.0.0.10. The broker must perform exactly one A+AAAA round.
    let scripted = Arc::new(ScriptedDnsProvider::new(vec![
        addr_answer(vec![v4(10, 0, 0, 9)]),
        NseDnsAnswer::default(),
        addr_answer(vec![v4(10, 0, 0, 10)]),
        NseDnsAnswer::default(),
    ]));
    let tcp = Arc::new(MemoryTcpSocketProvider::new(vec![]));
    let services = NseHostServices::native()
        .with_dns(scripted.clone())
        .with_tcp(tcp.clone());

    let (_handle, endpoint) = broker_tcp_connect(
        &ctx,
        &services,
        "flap.test",
        80,
        Duration::from_secs(1),
        "test.rebinding",
    )
    .expect("first-round candidate connects");

    assert_eq!(endpoint.address, v4(10, 0, 0, 9));
    assert_eq!(
        scripted.lookups(),
        2,
        "exactly one A+AAAA resolution round, no re-resolution for connect"
    );
    assert_eq!(tcp.connects().len(), 1);
    assert_eq!(tcp.connects()[0].address, v4(10, 0, 0, 9));
}

// ---------------------------------------------------------------------------
// Denial and cancellation never touch providers
// ---------------------------------------------------------------------------

#[test]
fn deny_all_touches_no_provider() {
    let (ctx, _) = test_context(NseExecutionProfileKind::CiSafe, NseNetworkPolicy::DenyAll);
    let dns = Arc::new(CountingDnsProvider::new(HashMap::new()));
    let tcp = Arc::new(CountingTcpSocketProvider::new(vec![]));
    let udp = Arc::new(CountingUdpSocketProvider::new(vec![]));
    let services = NseHostServices::native()
        .with_dns(dns.clone())
        .with_tcp(tcp.clone())
        .with_udp(udp.clone());

    assert!(broker_tcp_connect(
        &ctx,
        &services,
        "example.com",
        80,
        Duration::from_secs(1),
        "test.deny"
    )
    .is_err());
    assert!(broker_udp_connect(
        &ctx,
        &services,
        "example.com",
        53,
        Duration::from_secs(1),
        "test.deny"
    )
    .is_err());
    assert!(broker_dns_lookup(
        &ctx,
        &services,
        "example.com",
        NseDnsRecordType::A,
        "test.deny"
    )
    .is_err());
    assert_eq!(dns.calls(), 0);
    assert_eq!(tcp.calls(), 0);
    assert_eq!(udp.calls(), 0);
}

#[test]
fn cancellation_prevents_provider_calls() {
    let (scripts, modules) = policies();
    let token = NseCancellationToken::new();
    token.cancel();
    let ctx = NseCapabilityContext::new(
        NseExecutionProfileKind::ManualPermissive,
        NseNetworkPolicy::AllowAllManual,
        scripts,
        modules,
        SandboxConfig::default(),
        NseExecutionLimits::default(),
        token,
        Arc::new(NseResourceCounters::default()),
    );
    let dns = Arc::new(CountingDnsProvider::new(HashMap::new()));
    let tcp = Arc::new(CountingTcpSocketProvider::new(vec![]));
    let services = NseHostServices::native()
        .with_dns(dns.clone())
        .with_tcp(tcp.clone());

    assert!(broker_tcp_connect(
        &ctx,
        &services,
        "127.0.0.1",
        80,
        Duration::from_secs(1),
        "test.cancel"
    )
    .is_err());
    assert_eq!(dns.calls(), 0);
    assert_eq!(tcp.calls(), 0);
}

#[test]
fn cancellation_during_established_session_fails_io() {
    let (scripts, modules) = policies();
    let token = NseCancellationToken::new();
    let ctx = NseCapabilityContext::new(
        NseExecutionProfileKind::ManualPermissive,
        NseNetworkPolicy::AllowAllManual,
        scripts,
        modules,
        SandboxConfig::default(),
        NseExecutionLimits::default(),
        token.clone(),
        Arc::new(NseResourceCounters::default()),
    );
    let services =
        NseHostServices::native().with_tcp(Arc::new(MemoryTcpSocketProvider::new(vec![
            b"data".to_vec()
        ])));

    let (mut handle, _endpoint) = broker_tcp_connect(
        &ctx,
        &services,
        "127.0.0.1",
        80,
        Duration::from_secs(1),
        "test.cancel-session",
    )
    .expect("connect before cancellation");
    token.cancel();
    let err = broker_tcp_send(&ctx, handle.as_mut(), b"ping", "test.cancel-session")
        .expect_err("send after cancel must fail");
    assert!(err.contains("cancelled"), "{err}");
    let err = broker_tcp_receive(&ctx, handle.as_mut(), 16, "test.cancel-session")
        .expect_err("receive after cancel must fail");
    assert!(err.contains("cancelled"), "{err}");
}

// ---------------------------------------------------------------------------
// UDP authority flow + accounting semantics
// ---------------------------------------------------------------------------

#[test]
fn udp_authority_flow_with_accounting() {
    let (ctx, counters) = manual_ctx();
    let dns = Arc::new(MapDnsProvider::with_addresses(
        "udp.test",
        vec![v4(127, 0, 0, 1)],
    ));
    let udp = Arc::new(MemoryUdpSocketProvider::new(vec![b"pong".to_vec()]));
    let services = NseHostServices::native()
        .with_dns(dns)
        .with_udp(udp.clone());

    let ops_before = counters.network_operations.load(Ordering::Relaxed);
    let read_before = counters.network_bytes_read.load(Ordering::Relaxed);
    let written_before = counters.network_bytes_written.load(Ordering::Relaxed);

    let (mut handle, endpoint) = broker_udp_connect(
        &ctx,
        &services,
        "udp.test",
        5353,
        Duration::from_secs(1),
        "test.udp",
    )
    .expect("udp connect");
    assert_eq!(endpoint.address, v4(127, 0, 0, 1));
    assert_eq!(endpoint.protocol, NseTransportProtocol::Udp);
    assert_eq!(udp.connects(), vec![endpoint.clone()]);

    let sent = broker_udp_send(&ctx, handle.as_mut(), b"ping", "test.udp").expect("udp send");
    assert_eq!(sent, 4);
    let received = broker_udp_receive(&ctx, handle.as_mut(), 1024, "test.udp").expect("udp recv");
    assert_eq!(received, b"pong");

    // connect + send + receive each record one network operation; sent
    // bytes land in the written bucket and received bytes in the read
    // bucket (M005E direction-correct accounting).
    assert_eq!(
        counters.network_operations.load(Ordering::Relaxed) - ops_before,
        3
    );
    assert_eq!(
        counters.network_bytes_read.load(Ordering::Relaxed) - read_before,
        4,
        "received pong bytes are read"
    );
    assert_eq!(
        counters.network_bytes_written.load(Ordering::Relaxed) - written_before,
        4,
        "sent ping bytes are written"
    );
}

// ---------------------------------------------------------------------------
// Contention: concurrent runs hold independent provider state
// ---------------------------------------------------------------------------

#[test]
fn concurrent_runs_use_independent_providers() {
    let mut threads = Vec::new();
    for i in 0..8u8 {
        threads.push(std::thread::spawn(move || {
            let (ctx, _) = manual_ctx();
            let dns = Arc::new(MapDnsProvider::with_addresses(
                "concurrent.test",
                vec![v4(127, 0, 0, i)],
            ));
            let tcp = Arc::new(MemoryTcpSocketProvider::new(vec![]));
            let services = NseHostServices::native()
                .with_dns(dns)
                .with_tcp(tcp.clone());
            let (_handle, endpoint) = broker_tcp_connect(
                &ctx,
                &services,
                "concurrent.test",
                8000 + u16::from(i),
                Duration::from_secs(1),
                "test.concurrent",
            )
            .expect("concurrent connect");
            assert_eq!(endpoint.address, v4(127, 0, 0, i));
            assert_eq!(tcp.connects().len(), 1);
        }));
    }
    for t in threads {
        t.join().expect("thread joins");
    }
}

// ---------------------------------------------------------------------------
// Native I/O: local echo fixtures through the broker
// ---------------------------------------------------------------------------

fn tcp_echo_once() -> (u16, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let port = listener.local_addr().expect("port").port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("timeout");
        // Retry transient reads until the deadline; the client may still
        // be completing its connect when accept returns.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(n) => {
                    stream.write_all(&buf[..n]).expect("echo");
                    return;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::Interrupted =>
                {
                    if Instant::now() >= deadline {
                        panic!("echo server timed out waiting for bytes");
                    }
                }
                Err(e) => panic!("echo server read failed: {e}"),
            }
        }
    });
    (port, handle)
}

#[test]
fn native_tcp_echo_roundtrip_through_broker() {
    let (port, server) = tcp_echo_once();
    let (ctx, counters) = manual_ctx();
    let services = NseHostServices::native();

    let (mut handle, endpoint) = broker_tcp_connect(
        &ctx,
        &services,
        "127.0.0.1",
        port,
        Duration::from_secs(5),
        "test.echo",
    )
    .expect("echo connect");
    assert_eq!(endpoint.address, v4(127, 0, 0, 1));
    assert!(handle.local_port().is_some());

    let sent = broker_tcp_send(&ctx, handle.as_mut(), b"hello", "test.echo").expect("send");
    assert_eq!(sent, 5);
    let echoed = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "test.echo").expect("receive");
    assert_eq!(echoed, b"hello");
    assert!(
        counters.network_bytes_read.load(Ordering::Relaxed) >= 5,
        "echoed bytes are read"
    );
    assert!(
        counters.network_bytes_written.load(Ordering::Relaxed) >= 5,
        "sent bytes are written (M005E direction-correct accounting)"
    );

    handle.close();
    assert!(!handle.is_alive(), "closed handle must report not alive");
    server.join().expect("echo server joins");
}

fn udp_echo_once() -> (u16, std::thread::JoinHandle<()>) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp echo");
    let port = socket.local_addr().expect("port").port();
    let handle = std::thread::spawn(move || {
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let mut buf = [0u8; 1024];
        let (n, from) = socket.recv_from(&mut buf).expect("recv");
        socket.send_to(&buf[..n], from).expect("echo");
    });
    (port, handle)
}

#[test]
fn native_udp_echo_roundtrip_through_broker() {
    let (port, server) = udp_echo_once();
    let (ctx, _) = manual_ctx();
    let services = NseHostServices::native();

    let (mut handle, endpoint) = broker_udp_connect(
        &ctx,
        &services,
        "127.0.0.1",
        port,
        Duration::from_secs(5),
        "test.udp-echo",
    )
    .expect("udp echo connect");
    assert_eq!(endpoint.address, v4(127, 0, 0, 1));

    broker_udp_send(&ctx, handle.as_mut(), b"datagram", "test.udp-echo").expect("send");
    let echoed = broker_udp_receive(&ctx, handle.as_mut(), 1024, "test.udp-echo").expect("receive");
    assert_eq!(echoed, b"datagram");
    server.join().expect("udp echo server joins");
}

#[test]
fn connect_timeout_bounds_failure() {
    let (ctx, _) = manual_ctx();
    let services = NseHostServices::native();
    let start = Instant::now();
    let err = match broker_tcp_connect(
        &ctx,
        &services,
        "192.0.2.1",
        1,
        Duration::from_millis(300),
        "test.timeout",
    ) {
        Ok(_) => panic!("TEST-NET-1 must not connect"),
        Err(e) => e,
    };
    assert!(err.contains("failed"), "{err}");
    assert!(
        start.elapsed() < Duration::from_secs(15),
        "connect must stay bounded, took {:?}",
        start.elapsed()
    );
}

// ---------------------------------------------------------------------------
// End to end: deterministic DNS and socket I/O through real NSE execution
// ---------------------------------------------------------------------------

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
fn deterministic_dns_drives_dns_library() {
    let mut answers = HashMap::new();
    answers.insert(
        ("webscan.test".to_string(), "A".to_string()),
        addr_answer(vec![v4(93, 184, 216, 34)]),
    );
    let services = NseHostServices::native().with_dns(Arc::new(MapDnsProvider::new(answers)));
    let script = r#"
hostrule = function(host) return true end
action = function(host, port)
  local r = dns.resolve("webscan.test", "A")
  return (r.address or "missing") .. "|" .. (r.answers[1] or "missing")
end
"#;
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("deterministic-dns", script),
        manual_profile(),
    )
    .with_host_services(services);
    let report = execute_nse_run(request).expect("dns run succeeds");
    assert!(
        report
            .output
            .content
            .contains("93.184.216.34|93.184.216.34"),
        "injected DNS must drive dns.resolve without external I/O, got: {}",
        report.output.content
    );
    assert!(
        report
            .capability_events
            .iter()
            .any(|e| e.kind == "dns_resolution" && e.allowed),
        "dns-resolution capability event must be recorded"
    );
}

#[test]
fn memory_socket_drives_socket_library() {
    let dns = Arc::new(MapDnsProvider::with_addresses(
        "svc.test",
        vec![v4(127, 0, 0, 1)],
    ));
    let tcp = Arc::new(MemoryTcpSocketProvider::new(vec![b"OK".to_vec()]));
    let services = NseHostServices::native()
        .with_dns(dns)
        .with_tcp(tcp.clone());
    let script = r#"
hostrule = function(host) return true end
action = function(host, port)
  local sock = socket.tcp()
  local c = sock:connect("svc.test", 80)
  assert(c.status == "connected", "connect failed")
  local s = sock:send("hello")
  assert(s.status == "sent", "send failed")
  local r = sock:receive(16)
  return "got:" .. r.data
end
"#;
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("memory-socket", script),
        manual_profile(),
    )
    .with_host_services(services);
    let report = execute_nse_run(request).expect("socket run succeeds");
    assert!(
        report.output.content.contains("got:OK"),
        "memory socket must drive socket.tcp Lua I/O, got: {}",
        report.output.content
    );
    assert_eq!(tcp.connects().len(), 1);
    assert_eq!(tcp.connects()[0].address, v4(127, 0, 0, 1));
    assert!(
        report
            .capability_events
            .iter()
            .any(|e| e.kind == "network_tcp" && e.allowed),
        "network-tcp capability events must be recorded"
    );
}

#[test]
fn comm_exchange_echoes_through_broker() {
    let (port, server) = tcp_echo_once();
    let services = NseHostServices::native();
    let script = format!(
        r#"
hostrule = function(host) return true end
action = function(host, port)
  local r = comm.exchange("127.0.0.1", {}, "ping")
  return "echo:" .. r.data
end
"#,
        port
    );
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("comm-exchange", &script),
        manual_profile(),
    )
    .with_host_services(services);
    let report = execute_nse_run(request).expect("comm run succeeds");
    assert!(
        report.output.content.contains("echo:ping"),
        "comm.exchange must round-trip through the broker, got: {}",
        report.output.content
    );
    server.join().expect("echo server joins");
}

#[test]
fn resolve_and_select_agrees_with_broker_connect() {
    // The select step and the full connect must agree on identity.
    let (ctx, _) = manual_ctx();
    let dns = Arc::new(MapDnsProvider::with_addresses(
        "agree.test",
        vec![v4(127, 0, 0, 1)],
    ));
    let tcp = Arc::new(MemoryTcpSocketProvider::new(vec![]));
    let services = NseHostServices::native().with_dns(dns).with_tcp(tcp);
    let selected = broker_resolve_and_select(
        &ctx,
        &services,
        "agree.test",
        8080,
        NseTransportProtocol::Tcp,
        "test.agree",
    )
    .expect("select");
    let (_handle, connected) = broker_tcp_connect(
        &ctx,
        &services,
        "agree.test",
        8080,
        Duration::from_secs(1),
        "test.agree",
    )
    .expect("connect");
    assert_eq!(selected, connected);
}
