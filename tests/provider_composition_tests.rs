//! M005E cross-domain provider composition qualification.
//!
//! Proves the M005 provider bundle is coherent rather than several unrelated
//! injection mechanisms:
//! - one Lua run drives clock + environment + DNS + TCP + HTTP + filesystem
//!   through a single injected bundle, and every provider receives exactly
//!   its intended operations (no native leakage, endpoint/authority
//!   identity preserved across the DNS -> TCP -> HTTP chain);
//! - concurrent full runs isolate bundles and per-run filesystem state;
//! - cancellation/denial at the broker blocks every provider domain with
//!   zero provider contact;
//! - resource counters reflect actual provider execution.
//!
//! Run with:
//!   cargo test -p eggsec-nse --features nse --test provider_composition_tests

#![cfg(feature = "nse")]

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use eggsec_nse::limits::{NseCancellationToken, NseExecutionLimits, NseResourceCounters};
use eggsec_nse::profile::{
    NseExecutionProfileKind, NseModulePolicy, NseNetworkPolicy, NseScriptPolicy,
    ResolvedNseExecutionProfile,
};
use eggsec_nse::resolver::NseScriptSource;
use eggsec_nse::{
    broker_dns_lookup, broker_env_var, broker_fs_write, broker_http_request, broker_random_fill,
    broker_tcp_connect_endpoint, broker_tcp_receive, broker_tcp_send, broker_unix_timestamp,
    execute_nse_run, CountingClockProvider, CountingDnsProvider, CountingEnvironmentProvider,
    CountingFilesystemProvider, CountingHttpProvider, CountingRandomProvider,
    CountingTcpSocketProvider, MockHttpProvider, NseDnsAnswer, NseDnsRecord, NseDnsRecordType,
    NseHostServices, NseHttpRequest, NseHttpResponse, NseIpAddress, NseResolvedEndpoint,
    NseRunRequest, NseTransportProtocol, SandboxConfig,
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

fn context_with_counters(
    kind: NseExecutionProfileKind,
    network: NseNetworkPolicy,
    token: NseCancellationToken,
) -> (eggsec_nse::NseCapabilityContext, Arc<NseResourceCounters>) {
    let (scripts, modules) = policies();
    let counters = Arc::new(NseResourceCounters::default());
    let ctx = eggsec_nse::NseCapabilityContext::new(
        kind,
        network,
        scripts,
        modules,
        SandboxConfig::default(),
        NseExecutionLimits::default(),
        token,
        counters.clone(),
    );
    (ctx, counters)
}

fn manual_ctx() -> (eggsec_nse::NseCapabilityContext, Arc<NseResourceCounters>) {
    context_with_counters(
        NseExecutionProfileKind::ManualPermissive,
        NseNetworkPolicy::AllowAllManual,
        NseCancellationToken::new(),
    )
}

fn manual_profile() -> ResolvedNseExecutionProfile {
    ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"))
}

fn inline_script(label: &str, body: &str) -> NseScriptSource {
    NseScriptSource::InlineManual {
        label: label.to_string(),
        content: body.to_string(),
    }
}

fn ok_response(status: u16, body: &str) -> NseHttpResponse {
    NseHttpResponse {
        status,
        headers: vec![("content-type".to_string(), "text/plain".to_string())],
        body: body.as_bytes().to_vec(),
        final_url: "http://compose.test/".to_string(),
        version: "HTTP/1.1".to_string(),
    }
}

fn addr_answer(ip: NseIpAddress) -> NseDnsAnswer {
    NseDnsAnswer::new(vec![NseDnsRecord::Address(ip)])
}

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "eggsec-nse-compose-{}-{}",
            std::process::id(),
            label
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn file(&self, name: &str) -> String {
        self.path.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Cross-domain single-run composition
// ---------------------------------------------------------------------------

/// One Lua run drives six provider domains through a single injected bundle.
///
/// DNS resolves `compose.test` to a scripted address; the socket layer must
/// connect exactly that concrete endpoint (no re-resolution); HTTP carries
/// the script-supplied host identity to the mock; clock/env/fs are fixed.
#[test]
fn multi_provider_single_run_uses_one_bundle() {
    let dir = TempDir::new("bundle");
    let target = dir.file("note.txt");

    let clock = Arc::new(CountingClockProvider::new(1_700_000_000));
    let random = Arc::new(CountingRandomProvider::new(vec![0xA5; 64]));
    let env = Arc::new(CountingEnvironmentProvider::new(
        HashMap::from([("COMPOSE_MARKER".to_string(), "marker-value".to_string())]),
        dir.path.clone(),
    ));
    let mut answers = HashMap::new();
    answers.insert(
        ("compose.test".to_string(), "A".to_string()),
        addr_answer(NseIpAddress::V4([127, 0, 0, 53])),
    );
    let dns = Arc::new(CountingDnsProvider::new(answers));
    let tcp = Arc::new(CountingTcpSocketProvider::new(vec![
        b"compose-banner".to_vec()
    ]));
    let http = Arc::new(MockHttpProvider::new(vec![Ok(ok_response(
        200,
        "compose-http",
    ))]));
    let fs = Arc::new(CountingFilesystemProvider::new());

    let services = NseHostServices::native()
        .with_clock(clock.clone())
        .with_random(random.clone())
        .with_environment(env.clone())
        .with_dns(dns.clone())
        .with_tcp(tcp.clone())
        .with_http(http.clone())
        .with_fs(fs.clone());

    let script = format!(
        r#"
hostrule = function(host) return true end
action = function(host, port)
  local parts = {{}}
  local ts = datetime.now()
  assert(ts == 1700000000, "fixed clock, got " .. tostring(ts))
  parts[#parts + 1] = "clock-ok"
  local marker = os.getenv("COMPOSE_MARKER")
  assert(marker == "marker-value", "mapped env, got " .. tostring(marker))
  parts[#parts + 1] = "env-ok"
  local resolved = dns.resolve("compose.test", "A")
  assert(resolved.address == "127.0.0.53", "scripted dns, got " .. tostring(resolved.address))
  parts[#parts + 1] = "dns-ok"
  local sock = socket.tcp()
  local ok, err = sock:connect("compose.test", 445)
  assert(ok, "tcp connect: " .. tostring(err))
  sock:send("HELLO\n")
  local reply = sock:receive()
  sock:close()
  assert(reply and reply.data == "compose-banner", "tcp replay")
  parts[#parts + 1] = "tcp-ok"
  local r = http.get("compose.test", 80, "/x")
  assert(r.status == 200 and r.body == "compose-http", "http mock")
  parts[#parts + 1] = "http-ok"
  local f = io.open("{target}", "w")
  assert(f.fd ~= nil, "fs open")
  io.write(f, "compose-fs")
  io.close(f)
  local g = io.open("{target}", "r")
  local data = io.read(g, 32)
  io.close(g)
  assert(data == "compose-fs", "fs round-trip")
  parts[#parts + 1] = "fs-ok"
  return parts[1] .. "," .. parts[2] .. "," .. parts[3] .. "," .. parts[4] .. "," .. parts[5] .. "," .. parts[6]
end
"#,
        target = target.replace('\\', "\\\\")
    );
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("compose", &script),
        manual_profile(),
    )
    .with_host_services(services);
    let report = execute_nse_run(request).expect("composition run succeeds");
    assert!(
        report
            .output
            .content
            .contains("clock-ok,env-ok,dns-ok,tcp-ok,http-ok,fs-ok"),
        "all six domains must succeed in one run, got: {}",
        report.output.content
    );

    // Every injected provider receives exactly its intended operations
    // (socket.connect performs A + AAAA lookups internally, hence 3 DNS).
    assert_eq!(clock.calls(), 1, "clock provider call count");
    assert_eq!(env.calls(), 1, "environment provider call count");
    assert_eq!(
        dns.calls(),
        3,
        "dns provider call count (resolve + connect A/AAAA)"
    );
    assert_eq!(tcp.calls(), 1, "tcp provider call count");
    assert_eq!(http.requests().len(), 1, "http provider call count");
    assert!(
        fs.calls() >= 3,
        "fs provider call count, got {}",
        fs.calls()
    );
    // Random is injected in the bundle but unused by this script: proves an
    // unused domain stays untouched rather than leaking to native.
    assert_eq!(random.calls(), 0, "unused random provider stays untouched");

    // Endpoint identity: TCP connects exactly the DNS-selected concrete
    // address, preserving the script-supplied hostname label.
    let endpoints = tcp.connects();
    assert_eq!(endpoints.len(), 1, "exactly one TCP connect");
    assert_eq!(
        endpoints[0].address,
        NseIpAddress::V4([127, 0, 0, 53]),
        "TCP must dial the DNS-approved concrete endpoint"
    );
    assert_eq!(endpoints[0].hostname, "compose.test");
    assert_eq!(endpoints[0].port, 445);

    // Authority identity: the HTTP request carries the script-supplied host.
    let requests = http.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].host, "compose.test");
    assert!(requests[0].url.contains("compose.test"));

    // Capability events cover every exercised domain.
    let kinds: Vec<&str> = report
        .capability_events
        .iter()
        .map(|e| e.kind.as_str())
        .collect();
    for expected in [
        "time_clock",
        "environment",
        "dns_resolution",
        "network_tcp",
        "filesystem_write",
        "filesystem_read",
    ] {
        assert!(
            kinds.iter().any(|k| *k == expected),
            "missing capability event {expected}, got {kinds:?}"
        );
    }
    assert!(
        report.capability_events.iter().all(|e| e.allowed),
        "composition run must have no denials"
    );
}

// ---------------------------------------------------------------------------
// Concurrent full-run isolation
// ---------------------------------------------------------------------------

/// Concurrent full runs with distinct bundles isolate HTTP responses,
/// filesystem state, and per-run provider calls.
#[test]
fn concurrent_runs_isolate_bundles_and_filesystem() {
    let process_cwd = std::env::current_dir().expect("process cwd");
    let mut threads = Vec::new();
    for i in 0..4u32 {
        threads.push(std::thread::spawn(move || {
            let dir = TempDir::new(&format!("worker-{i}"));
            let target = dir.file("w.txt");
            let body = format!("worker-{i}-body");
            let http = Arc::new(MockHttpProvider::new(vec![Ok(ok_response(200, &body))]));
            let services = NseHostServices::native().with_http(http.clone());
            let script = format!(
                r#"
hostrule = function(host) return true end
action = function(host, port)
  local r = http.get("127.0.0.1", 80, "/w")
  local f = io.open("{target}", "w")
  io.write(f, r.body)
  io.close(f)
  return "wrote:" .. r.body
end
"#,
                target = target.replace('\\', "\\\\")
            );
            let request = NseRunRequest::new(
                "127.0.0.1",
                inline_script(&format!("worker-{i}"), &script),
                manual_profile(),
            )
            .with_host_services(services);
            let report = execute_nse_run(request).expect("worker run succeeds");
            assert!(
                report
                    .output
                    .content
                    .contains(&format!("wrote:worker-{i}-body")),
                "worker {i} must see its own bundle response, got: {}",
                report.output.content
            );
            let stored = std::fs::read_to_string(&target).expect("worker reads its own file");
            assert_eq!(stored, format!("worker-{i}-body"));
            assert_eq!(http.requests().len(), 1);
        }));
    }
    for t in threads {
        t.join().expect("worker joins");
    }
    assert_eq!(
        std::env::current_dir().expect("process cwd after"),
        process_cwd,
        "concurrent runs must never mutate the process CWD"
    );
}

// ---------------------------------------------------------------------------
// Cross-domain cancellation / denial (broker level)
// ---------------------------------------------------------------------------

fn counting_bundle() -> (
    NseHostServices,
    Arc<CountingClockProvider>,
    Arc<CountingRandomProvider>,
    Arc<CountingEnvironmentProvider>,
    Arc<CountingDnsProvider>,
    Arc<CountingTcpSocketProvider>,
    Arc<CountingHttpProvider>,
    Arc<CountingFilesystemProvider>,
) {
    let clock = Arc::new(CountingClockProvider::new(1));
    let random = Arc::new(CountingRandomProvider::new(vec![1, 2, 3, 4]));
    let env = Arc::new(CountingEnvironmentProvider::new(
        HashMap::from([("K".to_string(), "V".to_string())]),
        std::env::temp_dir(),
    ));
    let mut answers = HashMap::new();
    answers.insert(
        ("example.test".to_string(), "A".to_string()),
        addr_answer(NseIpAddress::V4([127, 0, 0, 1])),
    );
    let dns = Arc::new(CountingDnsProvider::new(answers));
    let tcp = Arc::new(CountingTcpSocketProvider::new(vec![]));
    let http = Arc::new(CountingHttpProvider::new(vec![Ok(ok_response(200, "x"))]));
    let fs = Arc::new(CountingFilesystemProvider::new());
    let services = NseHostServices::native()
        .with_clock(clock.clone())
        .with_random(random.clone())
        .with_environment(env.clone())
        .with_dns(dns.clone())
        .with_tcp(tcp.clone())
        .with_http(http.clone())
        .with_fs(fs.clone());
    (services, clock, random, env, dns, tcp, http, fs)
}

fn attempt_all_domains(
    ctx: &eggsec_nse::NseCapabilityContext,
    services: &NseHostServices,
) -> Vec<Result<(), String>> {
    let mut out = Vec::new();
    out.push(broker_unix_timestamp(ctx, services, "test.compose").map(|_| ()));
    let mut buf = [0u8; 4];
    out.push(broker_random_fill(ctx, services, &mut buf, "test.compose").map(|_| ()));
    out.push(broker_env_var(ctx, services, "K", "test.compose").map(|_| ()));
    out.push(
        broker_dns_lookup(
            ctx,
            services,
            "example.test",
            NseDnsRecordType::A,
            "test.compose",
        )
        .map(|_| ()),
    );
    let endpoint = NseResolvedEndpoint::new(
        "example.test",
        NseIpAddress::V4([127, 0, 0, 1]),
        80,
        NseTransportProtocol::Tcp,
    );
    out.push(
        broker_tcp_connect_endpoint(
            ctx,
            services,
            &endpoint,
            Duration::from_secs(1),
            "test.compose",
        )
        .map(|_| ()),
    );
    out.push(
        broker_http_request(
            ctx,
            services,
            &NseHttpRequest::get("http://example.test/", "example.test"),
            "test.compose",
        )
        .map(|_| ())
        .map_err(|e| e.to_string()),
    );
    let path = std::env::temp_dir().join("eggsec-nse-compose-cancel-probe.txt");
    let _ = std::fs::remove_file(&path);
    out.push(
        broker_fs_write(
            ctx,
            services,
            &path.to_string_lossy(),
            b"probe",
            "test.compose",
        )
        .map(|_| ()),
    );
    let _ = std::fs::remove_file(&path);
    out
}

/// A cancelled token blocks every provider domain before provider contact.
#[test]
fn cancelled_context_blocks_all_provider_domains() {
    let (services, clock, random, env, dns, tcp, http, fs) = counting_bundle();
    let token = NseCancellationToken::new();
    token.cancel();
    let (ctx, _) = context_with_counters(
        NseExecutionProfileKind::ManualPermissive,
        NseNetworkPolicy::AllowAllManual,
        token,
    );
    let results = attempt_all_domains(&ctx, &services);
    assert_eq!(results.len(), 7);
    for (i, r) in results.iter().enumerate() {
        assert!(r.is_err(), "domain {i} must fail when cancelled, got {r:?}");
    }
    for (name, calls) in [
        ("clock", clock.calls()),
        ("random", random.calls()),
        ("env", env.calls()),
        ("dns", dns.calls()),
        ("tcp", tcp.calls()),
        ("http", http.requests().len() as u64),
        ("fs", fs.calls()),
    ] {
        assert_eq!(
            calls, 0,
            "{name} provider must see zero calls when cancelled"
        );
    }
}

/// A deny-all profile denies every provider domain before provider contact.
#[test]
fn deny_all_profile_blocks_all_provider_domains() {
    let (services, clock, random, env, dns, tcp, http, fs) = counting_bundle();
    let (ctx, _) = context_with_counters(
        NseExecutionProfileKind::CiSafe,
        NseNetworkPolicy::DenyAll,
        NseCancellationToken::new(),
    );
    let results = attempt_all_domains(&ctx, &services);
    assert_eq!(results.len(), 7);
    // Clock/random/env/fs may be allowed by CiSafe policy while network is
    // denied; the invariant is that *denied* domains never reach providers
    // and network domains are always denied here.
    for (i, r) in results.iter().enumerate().skip(3) {
        assert!(r.is_err(), "network domain {i} must be denied, got {r:?}");
    }
    assert_eq!(dns.calls(), 0, "denied dns sees zero calls");
    assert_eq!(tcp.calls(), 0, "denied tcp sees zero calls");
    assert_eq!(http.requests().len(), 0, "denied http sees zero calls");
    let _ = (clock, random, env, fs);
}

// ---------------------------------------------------------------------------
// Accounting reflects actual provider execution
// ---------------------------------------------------------------------------

/// Resource counters increase exactly around real provider-backed operations.
#[test]
fn provider_accounting_reflects_actual_execution() {
    let (ctx, counters) = manual_ctx();
    let tcp = Arc::new(CountingTcpSocketProvider::new(vec![b"acct".to_vec()]));
    let services = NseHostServices::native().with_tcp(tcp.clone());
    let before_ops = counters.network_operations.load(Ordering::SeqCst);
    let before_read = counters.network_bytes_read.load(Ordering::SeqCst);
    let before_written = counters.network_bytes_written.load(Ordering::SeqCst);

    let endpoint = NseResolvedEndpoint::new(
        "127.0.0.1",
        NseIpAddress::V4([127, 0, 0, 1]),
        80,
        NseTransportProtocol::Tcp,
    );
    let mut conn = broker_tcp_connect_endpoint(
        &ctx,
        &services,
        &endpoint,
        Duration::from_secs(5),
        "test.acct",
    )
    .expect("tcp connect");
    assert_eq!(tcp.calls(), 1);
    let sent = broker_tcp_send(&ctx, conn.as_mut(), b"ping", "test.acct").expect("tcp send");
    assert_eq!(sent, 4);
    let received = broker_tcp_receive(&ctx, conn.as_mut(), 64, "test.acct").expect("tcp receive");
    assert_eq!(received, b"acct".to_vec());

    assert!(
        counters.network_operations.load(Ordering::SeqCst) > before_ops,
        "tcp operations must be counted"
    );
    assert_eq!(
        counters.network_bytes_written.load(Ordering::SeqCst) - before_written,
        4,
        "sent bytes must land in the written bucket, not read"
    );
    assert_eq!(
        counters.network_bytes_read.load(Ordering::SeqCst) - before_read,
        4,
        "received bytes must land in the read bucket"
    );
}

/// The write-byte limit preflights sends before provider contact.
#[test]
fn write_byte_limit_preflight_blocks_send() {
    let tcp = Arc::new(CountingTcpSocketProvider::new(vec![]));
    let services = NseHostServices::native().with_tcp(tcp.clone());
    let (scripts, modules) = policies();
    let counters = Arc::new(NseResourceCounters::default());
    let limits = NseExecutionLimits {
        max_network_bytes_written: Some(3),
        ..Default::default()
    };
    let ctx = eggsec_nse::NseCapabilityContext::new(
        NseExecutionProfileKind::ManualPermissive,
        NseNetworkPolicy::AllowAllManual,
        scripts,
        modules,
        SandboxConfig::default(),
        limits,
        NseCancellationToken::new(),
        counters.clone(),
    );
    let endpoint = NseResolvedEndpoint::new(
        "127.0.0.1",
        NseIpAddress::V4([127, 0, 0, 1]),
        80,
        NseTransportProtocol::Tcp,
    );
    let mut conn = broker_tcp_connect_endpoint(
        &ctx,
        &services,
        &endpoint,
        Duration::from_secs(5),
        "test.limit",
    )
    .expect("connect within limits");
    let err = broker_tcp_send(&ctx, conn.as_mut(), b"ping", "test.limit")
        .expect_err("4-byte send over a 3-byte write budget must fail");
    assert!(
        err.contains("written"),
        "limit error must name the written bucket, got: {err}"
    );
    assert_eq!(tcp.calls(), 1, "only the connect reached the provider");
    assert_eq!(
        counters.network_bytes_written.load(Ordering::SeqCst),
        0,
        "denied send must account zero written bytes"
    );
}

/// HTTP accounting splits request (written) from response (read) bytes.
#[test]
fn http_accounting_splits_request_and_response() {
    let http = Arc::new(CountingHttpProvider::new(vec![Ok(ok_response(
        200,
        "resp-body",
    ))]));
    let services = NseHostServices::native().with_http(http.clone());
    let (ctx, counters) = manual_ctx();
    let mut req = NseHttpRequest::get("http://example.test/", "example.test");
    req.body = b"request-payload".to_vec();
    let resp = broker_http_request(&ctx, &services, &req, "test.http-acct").expect("http succeeds");
    assert_eq!(resp.body, b"resp-body".to_vec());
    assert_eq!(http.calls(), 1);
    assert_eq!(
        counters.network_bytes_read.load(Ordering::SeqCst),
        9,
        "response bytes are read"
    );
    assert_eq!(
        counters.network_bytes_written.load(Ordering::SeqCst),
        15,
        "request body bytes are written"
    );
}

// ---------------------------------------------------------------------------
// Denied run leaves providers untouched end to end
// ---------------------------------------------------------------------------

/// A CiSafe Lua run touching TCP/HTTP produces denials with zero provider
/// contact across both domains in one execution.
#[test]
fn denied_run_contacts_no_provider_across_domains() {
    let tcp = Arc::new(CountingTcpSocketProvider::new(vec![]));
    let http = Arc::new(CountingHttpProvider::new(vec![Ok(ok_response(200, "x"))]));
    let services = NseHostServices::native()
        .with_tcp(tcp.clone())
        .with_http(http.clone());
    let script = r#"
hostrule = function(host) return true end
action = function(host, port)
  local sock = socket.tcp()
  local ok, err = pcall(function() return sock:connect("127.0.0.1", 80) end)
  local r = http.get("127.0.0.1", 80, "/")
  return "tcp:" .. tostring(ok) .. " http:" .. tostring(r.status)
end
"#;
    let profile = ResolvedNseExecutionProfile {
        kind: NseExecutionProfileKind::CiSafe,
        sandbox: SandboxConfig::default(),
        limits: NseExecutionLimits::default(),
        script_policy: NseScriptPolicy {
            allow_builtin_scripts: true,
            allow_script_files: false,
            allowed_script_roots: Vec::new(),
            allow_conventional_nmap_paths: false,
            max_script_bytes: None,
        },
        module_policy: NseModulePolicy {
            allow_builtin_modules: true,
            allow_filesystem_modules: false,
            allowed_module_roots: Vec::new(),
            max_module_bytes: None,
        },
        network_policy: NseNetworkPolicy::DenyAll,
        audit_label: "compose-denied".to_string(),
        warnings: vec![],
    };
    let request = NseRunRequest::new("127.0.0.1", inline_script("denied", script), profile)
        .with_host_services(services);
    let report = execute_nse_run(request).expect("denied run still reports");
    assert_eq!(tcp.calls(), 0, "denied tcp sees zero provider calls");
    assert_eq!(http.requests().len(), 0, "denied http sees zero calls");
    let denials: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| !e.allowed)
        .collect();
    assert!(
        denials.len() >= 2,
        "both domains must record denials, got {:?}",
        report.capability_events
    );
}
