//! M005C HTTP provider integration tests.
//!
//! Proves brokered HTTP execution: DTO conversion, TLS-intent gating,
//! denial/cancellation before provider invocation, scripted Lua end to end
//! for every migrated library, and native parity against a loopback HTTP
//! fixture.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use eggsec_nse::limits::{NseCancellationToken, NseExecutionLimits, NseResourceCounters};
use eggsec_nse::profile::{
    NseExecutionProfileKind, NseModulePolicy, NseNetworkPolicy, NseScriptPolicy,
};
use eggsec_nse::resolver::NseScriptSource;
use eggsec_nse::{
    broker_http_request, execute_nse_run, CountingHttpProvider, MockHttpProvider,
    NseCapabilityContext, NseHostServices, NseHttpError, NseHttpMethod, NseHttpRequest,
    NseHttpResponse, NseRunRequest, ResolvedNseExecutionProfile, SandboxConfig,
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

fn ok_response(status: u16, body: &str) -> NseHttpResponse {
    NseHttpResponse {
        status,
        headers: vec![("content-type".to_string(), "text/plain".to_string())],
        body: body.as_bytes().to_vec(),
        final_url: "http://127.0.0.1/".to_string(),
        version: "HTTP/1.1".to_string(),
    }
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

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[test]
fn http_method_parse_covers_parity_matrix() {
    for (label, method) in [
        ("GET", NseHttpMethod::Get),
        ("post", NseHttpMethod::Post),
        ("Put", NseHttpMethod::Put),
        ("DELETE", NseHttpMethod::Delete),
        ("patch", NseHttpMethod::Patch),
        ("HEAD", NseHttpMethod::Head),
        ("options", NseHttpMethod::Options),
        ("TRACE", NseHttpMethod::Trace),
    ] {
        assert_eq!(NseHttpMethod::parse(label).expect("parity method"), method);
    }
    assert!(NseHttpMethod::parse("BREW").is_err());
    assert!(NseHttpMethod::parse("").is_err());
    assert_eq!(NseHttpMethod::Get.as_str(), "GET");
}

#[test]
fn http_error_reasons_match_legacy_lua_values() {
    assert_eq!(NseHttpError::Denied("x".into()).reason(), "denied");
    assert_eq!(NseHttpError::Cancelled("x".into()).reason(), "cancelled");
    assert_eq!(NseHttpError::Timeout.reason(), "timeout");
    assert_eq!(NseHttpError::Connection("x".into()).reason(), "connection");
    assert_eq!(NseHttpError::Request("x".into()).reason(), "request");
    assert!(NseHttpError::Timeout.detail().contains("timed out"));
}

#[test]
fn http_response_helpers() {
    let resp = ok_response(200, "hello");
    assert_eq!(resp.header("Content-Type"), Some("text/plain"));
    assert_eq!(resp.header("missing"), None);
    assert_eq!(resp.body_text(), "hello");
}

// ---------------------------------------------------------------------------
// Broker: denial/cancellation precede provider invocation
// ---------------------------------------------------------------------------

#[test]
fn ci_safe_denied_before_provider_call() {
    let (ctx, _) = test_context(NseExecutionProfileKind::CiSafe, NseNetworkPolicy::DenyAll);
    let counting = Arc::new(CountingHttpProvider::new(vec![Ok(ok_response(200, "x"))]));
    let services = NseHostServices::native().with_http(counting.clone());
    let req = NseHttpRequest::get("http://example.com/", "example.com");

    let err = broker_http_request(&ctx, &services, &req, "test.deny")
        .expect_err("CiSafe HTTP must be denied");
    assert!(matches!(err, NseHttpError::Denied(_)), "{err:?}");
    assert_eq!(err.reason(), "denied");
    assert_eq!(counting.calls(), 0);
}

#[test]
fn cancellation_precedes_provider_call() {
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
    let counting = Arc::new(CountingHttpProvider::new(vec![Ok(ok_response(200, "x"))]));
    let services = NseHostServices::native().with_http(counting.clone());
    let req = NseHttpRequest::get("http://example.com/", "example.com");

    let err = broker_http_request(&ctx, &services, &req, "test.cancel")
        .expect_err("cancelled HTTP must fail");
    assert!(matches!(err, NseHttpError::Cancelled(_)), "{err:?}");
    assert_eq!(counting.calls(), 0);
}

#[test]
fn broker_forwards_request_identity_and_accounts() {
    let (ctx, counters) = manual_ctx();
    let mock = Arc::new(MockHttpProvider::new(vec![Ok(ok_response(201, "created"))]));
    let services = NseHostServices::native().with_http(mock.clone());
    let req = NseHttpRequest {
        method: NseHttpMethod::Post,
        url: "http://127.0.0.1:8080/submit".to_string(),
        host: "127.0.0.1".to_string(),
        headers: vec![("X-Test".to_string(), "1".to_string())],
        body: b"a=1".to_vec(),
        timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(2),
        insecure_tls: true,
    };

    let ops_before = counters
        .network_operations
        .load(std::sync::atomic::Ordering::Relaxed);
    let resp = broker_http_request(&ctx, &services, &req, "test.forward").expect("mock serves");
    assert_eq!(resp.status, 201);
    assert_eq!(resp.body_text(), "created");

    let seen = mock.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].url, "http://127.0.0.1:8080/submit");
    assert_eq!(seen[0].host, "127.0.0.1");
    assert_eq!(seen[0].method, NseHttpMethod::Post);
    assert_eq!(
        seen[0].headers,
        vec![("X-Test".to_string(), "1".to_string())]
    );
    assert_eq!(seen[0].body, b"a=1");
    assert!(seen[0].insecure_tls, "TLS intent must pass through");
    assert_eq!(
        counters
            .network_operations
            .load(std::sync::atomic::Ordering::Relaxed)
            - ops_before,
        1
    );
}

#[test]
fn provider_timeout_maps_to_typed_error() {
    let (ctx, _) = manual_ctx();
    let mock = Arc::new(MockHttpProvider::new(vec![Err(NseHttpError::Timeout)]));
    let services = NseHostServices::native().with_http(mock);
    let req = NseHttpRequest::get("http://127.0.0.1/", "127.0.0.1");

    let err = broker_http_request(&ctx, &services, &req, "test.timeout-map")
        .expect_err("timeout must surface");
    assert!(matches!(err, NseHttpError::Timeout));
    assert_eq!(err.reason(), "timeout");
}

// ---------------------------------------------------------------------------
// Lua end to end through the mock provider
// ---------------------------------------------------------------------------

fn mock_services(
    script: Vec<Result<NseHttpResponse, NseHttpError>>,
) -> (NseHostServices, Arc<MockHttpProvider>) {
    let mock = Arc::new(MockHttpProvider::new(script));
    let services = NseHostServices::native().with_http(mock.clone());
    (services, mock)
}

#[test]
fn http_get_post_shapes_through_lua() {
    let (services, mock) = mock_services(vec![
        Ok(ok_response(200, "get-body")),
        Ok(ok_response(201, "post-body")),
    ]);
    let script = r#"
hostrule = function(host) return true end
action = function(host, port)
  local g = http.get("127.0.0.1", 80, "/a")
  assert(g.status == 200, "get status")
  assert(g.body == "get-body", "get body")
  assert(g.header["content-type"] == "text/plain", "get header map")
  assert(g.headers[1] == "content-type: text/plain", "get header line")
  local p = http.post("127.0.0.1", 80, "/b", "x=1")
  assert(p.status == 201, "post status")
  return "http-ok:" .. g.body .. "+" .. p.body
end
"#;
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("http-shapes", script),
        manual_profile(),
    )
    .with_host_services(services);
    let report = execute_nse_run(request).expect("http run succeeds");
    assert!(
        report.output.content.contains("http-ok:get-body+post-body"),
        "mock must drive http.get/post, got: {}",
        report.output.content
    );
    let seen = mock.requests();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].url, "http://127.0.0.1:80/a");
    assert_eq!(seen[1].method, NseHttpMethod::Post);
    assert_eq!(seen[1].body, b"x=1");
    // Manual profile arms insecure TLS intent (profile-gated, documented).
    assert!(seen[0].insecure_tls);
    assert!(
        report
            .capability_events
            .iter()
            .any(|e| e.kind == "network_tcp" && e.allowed),
        "HTTP must record network capability events"
    );
}

#[test]
fn http_generic_request_options_through_lua() {
    let (services, mock) = mock_services(vec![Ok(ok_response(200, "req-body"))]);
    let script = r#"
hostrule = function(host) return true end
action = function(host, port)
  local r = http.request("PUT", "127.0.0.1", 8080, "/item", {
    body = "v=2",
    headers = { ["X-A"] = "a" },
    authorization = "Bearer t",
    useragent = "probe/1.0",
  })
  assert(r.status == 200, "request status")
  return "req:" .. r.body
end
"#;
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("http-req", script),
        manual_profile(),
    )
    .with_host_services(services);
    let report = execute_nse_run(request).expect("request run succeeds");
    assert!(
        report.output.content.contains("req:req-body"),
        "{}",
        report.output.content
    );
    let seen = mock.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, NseHttpMethod::Put);
    assert!(seen[0]
        .headers
        .contains(&("Authorization".to_string(), "Bearer t".to_string())));
    assert!(seen[0]
        .headers
        .contains(&("User-Agent".to_string(), "probe/1.0".to_string())));
    assert_eq!(seen[0].body, b"v=2");
}

#[test]
fn http_error_reason_mapping_through_lua() {
    let (services, _) = mock_services(vec![Err(NseHttpError::Timeout)]);
    let script = r#"
hostrule = function(host) return true end
action = function(host, port)
  local r = http.get("127.0.0.1", 80, "/slow")
  assert(r.status == 0, "error status")
  assert(r.reason == "timeout", "reason, got: " .. (r.reason or "?"))
  return "reason-ok"
end
"#;
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("http-reason", script),
        manual_profile(),
    )
    .with_host_services(services);
    let report = execute_nse_run(request).expect("reason run succeeds");
    assert!(
        report.output.content.contains("reason-ok"),
        "{}",
        report.output.content
    );
}

#[test]
fn http_denied_returns_denied_table() {
    let (services, mock) = mock_services(vec![Ok(ok_response(200, "nope"))]);
    let script = r#"
hostrule = function(host) return true end
action = function(host, port)
  local r = http.get("203.0.113.9", 80, "/x")
  assert(r.status == 0, "denied status")
  assert(r.reason == "denied", "reason")
  return "denied-ok"
end
"#;
    // TEST-NET-3 is outside the loopback-only scope: fail closed.
    let profile =
        ResolvedNseExecutionProfile::agent_safe("203.0.113.9", &["127.0.0.0/8".parse().unwrap()]);
    let request = NseRunRequest::new("203.0.113.9", inline_script("http-deny", script), profile)
        .with_host_services(services);
    let report = execute_nse_run(request).expect("deny run succeeds");
    assert!(
        report.output.content.contains("denied-ok"),
        "{}",
        report.output.content
    );
    assert!(
        mock.requests().is_empty(),
        "denied request must not reach the provider"
    );
}

#[test]
fn pipeline_brute_upnp_shapes_through_lua() {
    let (services, _) = mock_services(vec![
        Ok(ok_response(200, "one")),
        Ok(ok_response(200, "two")),
        Ok(ok_response(200, "auth-body")),
        Ok(NseHttpResponse {
            status: 200,
            headers: Vec::new(),
            body: b"LINE device thing\nLINE other\n".to_vec(),
            final_url: "http://127.0.0.1/desc".to_string(),
            version: "HTTP/1.1".to_string(),
        }),
    ]);
    let script = r#"
hostrule = function(host) return true end
action = function(host, port)
  local pipe = httppipeline.new("127.0.0.1", 80, {})
  httppipeline.add(pipe, "GET", "/one", {})
  httppipeline.add(pipe, "GET", "/two", {})
  local rs = httppipeline.go(pipe)
  assert(rs[1].body == "one" and rs[2].body == "two", "pipeline")
  local q = httppipeline.queue("127.0.0.1", 80, {})
  local b = brute.http_auth("127.0.0.1", 80, "/login", "u", "p")
  assert(b.success == true and b.code == 200, "brute auth")
  local u = upnp.get_devices("http://127.0.0.1/desc")
  assert(u.success == true, "upnp")
  return "family-ok"
end
"#;
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("http-family", script),
        manual_profile(),
    )
    .with_host_services(services);
    let report = execute_nse_run(request).expect("family run succeeds");
    assert!(
        report.output.content.contains("family-ok"),
        "{}",
        report.output.content
    );
}

#[test]
fn vulns_nvd_lookup_through_mock() {
    let body = br#"{
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-0001",
                    "descriptions": [{"lang": "en", "value": "Mocked vuln"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    }
                }
            }
        ]
    }"#;
    let (services, mock) = mock_services(vec![Ok(NseHttpResponse {
        status: 200,
        headers: Vec::new(),
        body: body.to_vec(),
        final_url: "https://services.nvd.nist.gov/".to_string(),
        version: "HTTP/1.1".to_string(),
    })]);
    let script = r#"
hostrule = function(host) return true end
action = function(host, port)
  local v = vulns.lookup_cve("CVE-2099-0001")
  assert(v.id == "CVE-2099-0001", "cve id")
  assert(v.cvss_score == 9.8, "score")
  return "vulns-ok"
end
"#;
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("vulns-mock", script),
        manual_profile(),
    )
    .with_host_services(services);
    let report = execute_nse_run(request).expect("vulns run succeeds");
    assert!(
        report.output.content.contains("vulns-ok"),
        "{}",
        report.output.content
    );
    assert_eq!(mock.requests().len(), 1);
    assert_eq!(mock.requests()[0].host, "services.nvd.nist.gov");
}

#[test]
fn tryssl_through_mock() {
    let (services, _) = mock_services(vec![Ok(ok_response(200, "tls-body"))]);
    let script = r#"
hostrule = function(host) return true end
action = function(host, port)
  local r = comm.tryssl("127.0.0.1", 443, "", nil)
  assert(r.status == 200, "tryssl status")
  return "tryssl:" .. r.data
end
"#;
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("tryssl", script),
        manual_profile(),
    )
    .with_host_services(services);
    let report = execute_nse_run(request).expect("tryssl run succeeds");
    assert!(
        report.output.content.contains("tryssl:tls-body"),
        "{}",
        report.output.content
    );
}

// ---------------------------------------------------------------------------
// Native parity against a loopback HTTP fixture (no mocks)
// ---------------------------------------------------------------------------

/// Minimal HTTP/1.1 fixture: serves scripted (status, body) pairs in accept
/// order, then closes. Returns the port and server handle.
fn http_fixture(responses: Vec<(u16, &'static str)>) -> (u16, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fixture");
    let port = listener.local_addr().expect("port").port();
    let handle = std::thread::spawn(move || {
        for (status, body) in responses {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            // Drain the request head.
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while !buf.ends_with(b"\r\n\r\n") && buf.len() < 65536 {
                match stream.read(&mut byte) {
                    Ok(0) => break,
                    Ok(_) => buf.push(byte[0]),
                    Err(_) => break,
                }
            }
            let reason = if status == 200 { "OK" } else { "Error" };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nX-Fixture: 1\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).expect("respond");
        }
    });
    (port, handle)
}

#[test]
fn native_get_post_roundtrip() {
    let (port, server) = http_fixture(vec![(200, "hello-get"), (201, "hello-post")]);
    let (ctx, _) = manual_ctx();
    let services = NseHostServices::native();
    let base = format!("http://127.0.0.1:{port}");

    let get = NseHttpRequest {
        method: NseHttpMethod::Get,
        url: format!("{base}/a"),
        host: "127.0.0.1".to_string(),
        headers: Vec::new(),
        body: Vec::new(),
        timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        insecure_tls: false,
    };
    let resp = broker_http_request(&ctx, &services, &get, "test.native-get").expect("GET");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body_text(), "hello-get");
    assert_eq!(resp.header("X-Fixture"), Some("1"));
    assert_eq!(resp.version, "HTTP/1.1");

    let post = NseHttpRequest {
        method: NseHttpMethod::Post,
        url: format!("{base}/b"),
        host: "127.0.0.1".to_string(),
        headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
        body: b"payload".to_vec(),
        timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(5),
        insecure_tls: false,
    };
    let resp = broker_http_request(&ctx, &services, &post, "test.native-post").expect("POST");
    assert_eq!(resp.status, 201);
    assert_eq!(resp.body_text(), "hello-post");
    server.join().expect("fixture joins");
}

#[test]
fn native_error_classification() {
    let (ctx, _) = manual_ctx();
    let services = NseHostServices::native();
    // TEST-NET-1 with a short timeout: connection failure, bounded.
    let req = NseHttpRequest {
        method: NseHttpMethod::Get,
        url: "http://192.0.2.1/".to_string(),
        host: "192.0.2.1".to_string(),
        headers: Vec::new(),
        body: Vec::new(),
        timeout: Duration::from_millis(300),
        connect_timeout: Duration::from_millis(300),
        insecure_tls: false,
    };
    let start = std::time::Instant::now();
    let err = broker_http_request(&ctx, &services, &req, "test.native-err")
        .expect_err("unroutable must fail");
    assert!(
        matches!(err, NseHttpError::Timeout | NseHttpError::Connection(_)),
        "classified failure, got: {err:?}"
    );
    assert!(start.elapsed() < Duration::from_secs(15), "bounded");
}

#[test]
fn concurrent_runs_use_independent_http_providers() {
    let mut threads = Vec::new();
    for i in 0..8u32 {
        threads.push(std::thread::spawn(move || {
            let (ctx, _) = manual_ctx();
            let body = format!("worker-{i}");
            let mock = Arc::new(MockHttpProvider::new(vec![Ok(ok_response(200, &body))]));
            let services = NseHostServices::native().with_http(mock.clone());
            let req = NseHttpRequest::get("http://127.0.0.1/", "127.0.0.1");
            let resp = broker_http_request(&ctx, &services, &req, "test.concurrent").expect("ok");
            assert_eq!(resp.body_text(), body);
            assert_eq!(mock.requests().len(), 1);
        }));
    }
    for t in threads {
        t.join().expect("thread joins");
    }
}

#[test]
fn async_variants_use_mock_provider() {
    let (services, _) = mock_services(vec![Ok(ok_response(200, "async-body"))]);
    let script = r#"
hostrule = function(host) return true end
action = function(host, port)
  local r = http.async_get("127.0.0.1", 80, "/x")
  assert(r.status == 200 and r.body == "async-body", "async_get")
  return "async-ok"
end
"#;
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("http-async", script),
        manual_profile(),
    )
    .with_host_services(services);
    let report = execute_nse_run(request).expect("async run succeeds");
    assert!(
        report.output.content.contains("async-ok"),
        "{}",
        report.output.content
    );
}
