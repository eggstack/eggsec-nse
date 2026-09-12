//! Narrow NSE HTTP script capability backed by the scoped transport contract.
//!
//! Phase D workstream 3 separates language/runtime compatibility from
//! ordinary HTTP implementation. Lua scripts never receive a raw
//! unrestricted `reqwest`/`eggfetch` client. Instead, script-facing HTTP
//! helpers build this capability's [`ScopedHttpRequest`] DTO (pure, no I/O),
//! preflight through [`NseCapabilityContext::check_capability`] (`NetworkTcp`
//! via `wrappers::check_network_tcp`, preserving the existing guard-enforced
//! gates), and dispatch only through an injected
//! [`HttpTransport`] with the operation's [`NetworkAuthority`].
//!
//! Status in this increment:
//! - Pure DTO construction + TLS-policy mapping + method coverage are
//!   implemented here with unit tests (no network, no Lua).
//! - The existing Lua `http`/`httppipeline`/`brute`/`vulns`/`comm`/`upnp`
//!   libraries still dispatch on the pre-migration `reqwest`
//!   (`blocking` inside sync Lua closures per guard 52/67 + async via
//!   `runtime_bridge::block_on_async`). Full backend cutover is deferred
//!   pending the async-Lua story and engine-side `ScopeAuthority` binding;
//!   those sites are documented `remain specialized (blocking)` in the
//!   Phase D disposition, not silently widened.
//! - Insecure TLS stays gated on
//!   [`NseCapabilityContext::allows_insecure_tls`] (ManualPermissive /
//!   CompatibilityLab only). AgentSafe/CiSafe/ManualStrict always build
//!   verified requests; a script cannot escalate by passing insecure flags.
//!
//! No `reqwest`/`eggfetch`/`rustls`/`tokio-rustls`/`hickory` types appear in
//! this module. DNS stays with the existing `dns`/`dnsbl` libs + `socket.rs`
//! (`RAWNET`, remain specialized). OpenSSL/`native-tls` stay feature-gated
//! for NSE protocol compatibility (`sslcert`/`openssl` libs + `nse` feature),
//! never for ordinary HTTP aesthetics.

use std::collections::HashMap;

use eggsec_transport::{
    HttpTransport, NetworkAuthority, RedirectPolicy, RequestBody, ScopedHttpRequest, TimeoutPolicy,
    TlsPolicy,
};

use crate::capabilities::NseCapabilityContext;

/// Re-exported for script-capability dispatch sites (keeps call sites on
/// transport-neutral types without a direct `http`/`url` dependency).
pub use eggsec_transport::{Method, StatusCode};

/// Maximum redirect hops for script HTTP (same-host only).
pub const NSE_MAX_REDIRECTS: u8 = 5;
/// Default per-request timeout for script HTTP (parity with `http.rs` 30s).
pub const NSE_DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Connect timeout for script HTTP (parity with `http.rs` 10s helpers).
pub const NSE_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Map a script-supplied method name to a transport-neutral [`Method`].
///
/// Covers all 8 methods in the Phase A parity matrix
/// (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS/TRACE). Unknown names fail closed
/// (extension methods such as BREW are rejected: scripts speak the 8
/// parity-covered verbs only).
pub fn nse_method(name: &str) -> Result<Method, String> {
    match name.trim().to_ascii_uppercase().as_str() {
        "GET" => Ok(Method::GET),
        "POST" => Ok(Method::POST),
        "PUT" => Ok(Method::PUT),
        "DELETE" => Ok(Method::DELETE),
        "PATCH" => Ok(Method::PATCH),
        "HEAD" => Ok(Method::HEAD),
        "OPTIONS" => Ok(Method::OPTIONS),
        "TRACE" => Ok(Method::TRACE),
        _ => Err(format!("unsupported NSE HTTP method '{name}'")),
    }
}

/// TLS policy for the operation's capability context.
///
/// Insecure mode (cert + hostname verification off) is armed only when the
/// resolved profile explicitly permits it (`allows_insecure_tls`). All other
/// profiles build verified requests. There is no per-request insecure
/// override: scripts cannot escalate beyond their operation's profile.
pub fn tls_policy_for_context(ctx: &NseCapabilityContext) -> TlsPolicy {
    if ctx.allows_insecure_tls() {
        tracing::warn!(
            "NSE script HTTP armed insecure TLS under profile '{}'; \
             verification off for compatibility/lab traffic only",
            ctx.profile_kind
        );
        TlsPolicy::insecure()
    } else {
        TlsPolicy::verified()
    }
}

/// Pure script-request builder (no I/O, no authorization).
///
/// - `method`: one of the 8 parity-matrix methods (case-insensitive).
/// - `url`: canonical URL (userinfo rejected fail-closed, host required).
/// - `headers`: applied overwrite (same semantics as
///   `apply_auth_context_to_transport`).
/// - `body`: replayable bytes only (`None` = empty); streaming bodies are
///   not representable (contract requires replayability for redirects).
/// - `timeout_secs`: per-request timeout (`max(1)`), plus the 10s NSE
///   connect timeout for parity.
/// - Redirects: `SameHostOnly{5}` (cross-host 3xx surfaces, never follows
///   out-of-scope hosts). Proxy: `Direct` (script proxy routing deferred;
///   proxied execution fails closed at dispatch).
/// - TLS: from [`tls_policy_for_context`] (profile-gated, no script override).
///
/// The caller must still preflight via `wrappers::check_network_tcp`
/// (capability gate + sandbox + cancellation + budget) before dispatch and
/// must execute via [`HttpTransport::execute`] with the operation's
/// [`NetworkAuthority`]. Building a request never authorizes one.
#[allow(clippy::too_many_arguments)]
pub fn build_scoped_request(
    ctx: &NseCapabilityContext,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<Vec<u8>>,
    timeout_secs: u64,
) -> Result<ScopedHttpRequest, String> {
    let http_method = nse_method(method)?;
    let mut request = ScopedHttpRequest::new_with_url(http_method, url)
        .map_err(|e| format!("invalid NSE HTTP URL '{url}': {e}"))?;
    if !headers.is_empty() {
        let map = eggsec_transport::header_map_from_pairs(headers)
            .map_err(|e| format!("invalid NSE HTTP headers: {e}"))?;
        for (name, value) in map {
            if let Some(name) = name {
                request.headers.insert(name, value);
            }
        }
    }
    request.body = match body {
        Some(bytes) if !bytes.is_empty() => RequestBody::from_bytes(bytes),
        _ => RequestBody::Empty,
    };
    request.timeout = TimeoutPolicy::with_request_timeout(timeout_secs.max(1))
        .with_connect_timeout(NSE_CONNECT_TIMEOUT_SECS);
    request.redirect = RedirectPolicy::SameHostOnly {
        max_redirects: NSE_MAX_REDIRECTS,
    };
    request.tls = tls_policy_for_context(ctx);
    Ok(request)
}

/// Dispatch a pre-built script request (thin checkpoint-preserving wrapper).
///
/// Exists so future Lua `http` wiring has one call site owning the
/// authority-threading shape; today it only forwards to
/// [`HttpTransport::execute`] (no retry, no jar, no decompression — all
/// deferred per the transport contract). Cancellation flows from the
/// capability context's token via the caller's future (drop cancels, no
/// detached tasks).
pub async fn dispatch_scoped_request<T: HttpTransport>(
    transport: &T,
    authority: &dyn NetworkAuthority,
    request: ScopedHttpRequest,
) -> Result<eggsec_transport::ScopedHttpResponse, eggsec_transport::TransportError> {
    transport.execute(authority, request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::NseCapabilityContext;
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
    fn all_parity_methods_map() {
        for method in [
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE",
        ] {
            assert!(nse_method(method).is_ok(), "{method}");
            assert!(nse_method(&method.to_ascii_lowercase()).is_ok(), "{method}");
        }
        assert!(nse_method("BREW").is_err());
        assert!(nse_method("").is_err());
    }

    #[test]
    fn userinfo_url_rejected() {
        let ctx = test_context(NseExecutionProfileKind::AgentSafe);
        let err = build_scoped_request(
            &ctx,
            "GET",
            "http://user:pass@example.com/",
            &HashMap::new(),
            None,
            30,
        )
        .unwrap_err();
        assert!(err.contains("invalid NSE HTTP URL"), "{err}");
    }

    #[test]
    fn invalid_headers_rejected() {
        let ctx = test_context(NseExecutionProfileKind::AgentSafe);
        let mut headers = HashMap::new();
        headers.insert("Bad Header Name!!".to_string(), "v".to_string());
        let err = build_scoped_request(&ctx, "GET", "http://example.com/", &headers, None, 30)
            .unwrap_err();
        assert!(err.contains("invalid NSE HTTP headers"), "{err}");
    }

    #[test]
    fn insecure_gated_on_profile() {
        let manual = test_context(NseExecutionProfileKind::ManualPermissive);
        let compat = test_context(NseExecutionProfileKind::CompatibilityLab);
        assert!(!tls_policy_for_context(&manual).is_verified());
        assert!(!tls_policy_for_context(&compat).is_verified());
        for kind in [
            NseExecutionProfileKind::AgentSafe,
            NseExecutionProfileKind::CiSafe,
            NseExecutionProfileKind::ManualStrict,
        ] {
            let ctx = test_context(kind);
            assert!(tls_policy_for_context(&ctx).is_verified(), "{kind:?}");
            let req = build_scoped_request(
                &ctx,
                "GET",
                "http://example.com/",
                &HashMap::new(),
                None,
                30,
            )
            .expect("builds");
            assert!(req.tls.is_verified());
        }
        let req = build_scoped_request(
            &manual,
            "POST",
            "http://example.com/submit",
            &HashMap::new(),
            Some(b"a=1".to_vec()),
            30,
        )
        .expect("builds");
        assert!(!req.tls.is_verified());
    }

    #[test]
    fn policies_match_parity() {
        let ctx = test_context(NseExecutionProfileKind::AgentSafe);
        let mut headers = HashMap::new();
        headers.insert("X-Custom".to_string(), "1".to_string());
        let req = build_scoped_request(
            &ctx,
            "POST",
            "http://example.com:8080/a",
            &headers,
            Some(b"hi".to_vec()),
            30,
        )
        .expect("builds");
        assert_eq!(req.method, Method::POST);
        assert_eq!(
            req.timeout.request_timeout,
            std::time::Duration::from_secs(30)
        );
        assert_eq!(
            req.timeout.connect_timeout,
            Some(std::time::Duration::from_secs(NSE_CONNECT_TIMEOUT_SECS))
        );
        assert_eq!(
            req.redirect,
            RedirectPolicy::SameHostOnly {
                max_redirects: NSE_MAX_REDIRECTS
            }
        );
        assert!(!req.proxy.uses_proxy());
        assert!(req.body.is_replayable());
        assert_eq!(req.body.len(), 2);
        // Timeout floor: 0 clamps to 1s (fail-closed, never zero).
        let floored =
            build_scoped_request(&ctx, "GET", "http://example.com/", &HashMap::new(), None, 0)
                .expect("builds");
        assert_eq!(
            floored.timeout.request_timeout,
            std::time::Duration::from_secs(1)
        );
    }

    #[test]
    fn no_concrete_client_types_in_module() {
        // Compile-time boundary: this module's public surface names only
        // transport-neutral types. If a future edit adds concrete-client
        // imports here, this test's source scan fails loudly.
        // (Banned literals are concat-built so this test does not match
        // itself in the include_str! scan.)
        let src = include_str!("http_capability.rs");
        let banned: Vec<String> = vec![
            ["reqwest", "::"].concat(),
            "eggfetch".to_string(),
            ["rustls", "::"].concat(),
            ["tokio_rustls", "::"].concat(),
            ["hickory_resolver", "::"].concat(),
            "RequestBuilder".to_string(),
            "Client::builder".to_string(),
        ];
        for b in &banned {
            // Allow the two doc-comment mentions that state the boundary
            // ("never receive a raw unrestricted X client", "No X types
            // appear in this module") plus this test's own concat
            // construction: count occurrences outside comments/test.
            let code_lines: Vec<&str> = src
                .lines()
                .filter(|l| {
                    let t = l.trim_start();
                    !(t.starts_with("//!")
                        || t.starts_with("//")
                        || t.contains(".concat()")
                        || t.contains(".to_string()"))
                })
                .collect();
            let joined = code_lines.join("\n");
            assert!(
                !joined.contains(b.as_str()),
                "http_capability.rs code must not mention '{b}'"
            );
        }
    }
}
