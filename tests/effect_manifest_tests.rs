//! M007A: Automated Library Effect Gate and HTTP Authority Assurance tests.
//!
//! Covers:
//! - Eligibility API surface and invariants
//! - Manifest classification coverage (every registered library has a class)
//! - Profile-gated safety predicate
//! - Unknown library fail-closed under automated profiles
//! - HTTP broker authority-bound assertion under automated profiles
//! - Registration gate behavior (Lua-side globals absent for unsafe libraries)
//! - Dynamic require gate behavior (BlockedByPolicy reports)

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use eggsec_nse::{
    automated_library_eligibility, broker_http_request, classify, eligible_for_profile,
    is_automated_library_safe, is_automated_profile, NseAutomatedLibraryEligibility,
    NseHostServices, NseHttpError, NseHttpMethod, NseHttpProvider, NseHttpRequest, NseHttpResponse,
    ResolvedNseExecutionProfile,
};

fn profile_agent_safe() -> ResolvedNseExecutionProfile {
    ResolvedNseExecutionProfile::agent_safe("127.0.0.1", &[])
}

fn profile_ci_safe() -> ResolvedNseExecutionProfile {
    ResolvedNseExecutionProfile::ci_safe()
}

fn profile_manual_permissive() -> ResolvedNseExecutionProfile {
    ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"))
}

fn make_capability_context(
    profile: &ResolvedNseExecutionProfile,
) -> eggsec_nse::NseCapabilityContext {
    // Build a real capability context via NseExecutor's profile
    // constructor so we have a NseCapabilityContext that is wired to
    // the same profile_kind/network_policy that the broker expects.
    let exec = eggsec_nse::NseExecutor::with_profile(profile).expect("executor init");
    // The CapabilityContext is owned by ExecutorCore; we need it as a
    // cloneable reference. Since NseExecutor owns it, we work around
    // the borrow by re-creating one for the test using a helper
    // constructor on NseCapabilityContext.
    drop(exec);
    eggsec_nse::NseCapabilityContext::new(
        profile.kind,
        profile.network_policy.clone(),
        profile.script_policy.clone(),
        profile.module_policy.clone(),
        profile.sandbox.clone(),
        profile.limits.clone(),
        eggsec_nse::NseCancellationToken::new(),
        std::sync::Arc::new(eggsec_nse::NseResourceCounters::new()),
    )
}

#[test]
fn eligibility_classification_is_deterministic() {
    let names = ["http", "stdnse", "smb", "pop3", "ssh", "ssl", "dns", "io"];
    for name in names {
        let a = automated_library_eligibility(name);
        let b = automated_library_eligibility(name);
        assert_eq!(a, b, "classification must be deterministic for '{}'", name);
    }
}

#[test]
fn known_libraries_have_classification() {
    // M005E direct-I/O residual
    assert_eq!(
        automated_library_eligibility("pop3"),
        NseAutomatedLibraryEligibility::ManualOnlyDirectIo
    );
    // M005E advisory-gated
    assert_eq!(
        automated_library_eligibility("smb"),
        NseAutomatedLibraryEligibility::ManualOnlyAdvisory
    );
    // Provider-backed
    assert_eq!(
        automated_library_eligibility("http"),
        NseAutomatedLibraryEligibility::ProviderBacked
    );
    // Pure
    assert_eq!(
        automated_library_eligibility("stdnse"),
        NseAutomatedLibraryEligibility::ProviderBacked
    );
    assert_eq!(
        automated_library_eligibility("base64"),
        NseAutomatedLibraryEligibility::Pure
    );
}

#[test]
fn unknown_library_resolves_to_manual_only() {
    let elig = automated_library_eligibility("never_registered");
    assert_eq!(
        elig,
        NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        "unknown names must default to ManualOnlyDirectIo per ADR-0004 §3"
    );
}

#[test]
fn manual_profiles_permit_all_known_libraries() {
    let profile = profile_manual_permissive();
    for name in ["http", "stdnse", "smb", "pop3", "ssh", "ssl"] {
        assert!(
            is_automated_library_safe(name, profile.kind),
            "manual profile must permit '{}'",
            name
        );
    }
}

#[test]
fn automated_profiles_block_unsafe_libraries() {
    for profile in [profile_agent_safe(), profile_ci_safe()] {
        // Safe
        assert!(is_automated_library_safe("http", profile.kind));
        assert!(is_automated_library_safe("stdnse", profile.kind));
        // Unsafe
        assert!(!is_automated_library_safe("smb", profile.kind));
        assert!(!is_automated_library_safe("pop3", profile.kind));
        assert!(!is_automated_library_safe("ssh", profile.kind));
    }
}

#[test]
fn automated_profile_predicate_matches_kind() {
    assert!(is_automated_profile(
        eggsec_nse::NseExecutionProfileKind::AgentSafe
    ));
    assert!(is_automated_profile(
        eggsec_nse::NseExecutionProfileKind::CiSafe
    ));
    assert!(!is_automated_profile(
        eggsec_nse::NseExecutionProfileKind::ManualPermissive
    ));
}

#[test]
fn eligible_for_profile_is_alias_for_safe() {
    let profile = profile_agent_safe().kind;
    for name in ["http", "smb", "pop3"] {
        assert_eq!(
            is_automated_library_safe(name, profile),
            eligible_for_profile(name, profile)
        );
    }
}

#[test]
fn classify_returns_manifest_entry() {
    let entry = classify("http").expect("http must have a manifest entry");
    assert_eq!(entry.name, "http");
    assert_eq!(
        entry.eligibility,
        NseAutomatedLibraryEligibility::ProviderBacked
    );
    assert!(entry.register_fn.starts_with("register_"));
    assert!(entry.rationale.len() > 10);
}

#[test]
fn classify_returns_none_for_unknown() {
    assert!(classify("definitely_not_a_real_library").is_none());
}

#[test]
fn manifest_covers_at_least_140_libraries() {
    // As of M007A, the manifest covers every `register_*_library` call
    // (147 functions in `ExecutorCore::register_libraries()`). The count
    // can grow over time as new libraries are added; the guard is a
    // floor that would only fail if someone shrank the manifest.
    let count = eggsec_nse::eligibility_counts();
    assert!(
        count.total() >= 140,
        "expected at least 140 manifest entries, got {}",
        count.total()
    );
}

#[test]
fn manifest_automated_safe_count_is_substantial() {
    let counts = eggsec_nse::eligibility_counts();
    assert!(
        counts.automated_safe() >= 40,
        "expected at least 40 automated-safe entries (Pure + ProviderBacked), got {}",
        counts.automated_safe()
    );
}

#[test]
fn manifest_manual_only_count_matches_m005e_residual() {
    // 72 ungated + 25 advisory = 97 entries with manual-only profile.
    // Pure/ProviderBacked libraries are also eligible under manual
    // profiles; we only assert the manual-only subset meets the M005E
    // floor.
    let counts = eggsec_nse::eligibility_counts();
    assert!(
        counts.manual_only() >= 70,
        "expected at least 70 manual-only entries (M005E residual floor), got {}",
        counts.manual_only()
    );
}

#[test]
fn classify_table_format_is_stable() {
    // Sanity: all entries display via Debug.
    for entry in eggsec_nse::classified_libraries() {
        let _ = format!("{:?}", entry);
    }
}

// HTTP authority assurance tests
// -----------------------------------------------------------------------

struct CountingHttp {
    calls: AtomicUsize,
    response: NseHttpResponse,
}

impl NseHttpProvider for CountingHttp {
    fn request(&self, _req: &NseHttpRequest) -> Result<NseHttpResponse, NseHttpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.response.clone())
    }
}

fn make_request() -> NseHttpRequest {
    NseHttpRequest::get("http://127.0.0.1/get", "127.0.0.1")
}

#[test]
fn automated_profile_native_http_denied_before_provider_call() {
    let counter = Arc::new(CountingHttp {
        calls: AtomicUsize::new(0),
        response: NseHttpResponse {
            status: 200,
            headers: Default::default(),
            body: Vec::new(),
            final_url: "http://127.0.0.1/get".to_string(),
            version: "HTTP/1.1".to_string(),
        },
    });

    // Build services with native HTTP but WITHOUT authority assurance.
    let services = NseHostServices::native().with_http(counter.clone() as Arc<dyn NseHttpProvider>);

    let profile = profile_agent_safe();
    let cap_ctx = make_capability_context(&profile);
    let req = make_request();

    let err = broker_http_request(&cap_ctx, &services, &req, "test")
        .expect_err("automated + non-authority HTTP must deny");
    assert!(
        matches!(err, NseHttpError::Denied(_)),
        "expected Denied, got {:?}",
        err
    );
    assert_eq!(
        counter.calls.load(Ordering::SeqCst),
        0,
        "provider must not be called when denial occurs"
    );
}

#[test]
fn automated_profile_authority_bound_http_can_be_invoked() {
    struct OkHttp;
    impl NseHttpProvider for OkHttp {
        fn request(&self, _req: &NseHttpRequest) -> Result<NseHttpResponse, NseHttpError> {
            Ok(NseHttpResponse {
                status: 200,
                headers: Default::default(),
                body: Vec::new(),
                final_url: "http://127.0.0.1/get".to_string(),
                version: "HTTP/1.1".to_string(),
            })
        }
    }

    let services = NseHostServices::native()
        .with_http(Arc::new(OkHttp) as Arc<dyn NseHttpProvider>)
        .with_authority_bound_http();

    let profile = profile_agent_safe();
    let cap_ctx = make_capability_context(&profile);
    let req = make_request();

    let resp = broker_http_request(&cap_ctx, &services, &req, "test")
        .expect("authority-bound + AgentSafe must succeed");
    assert_eq!(resp.status, 200);
}

#[test]
fn ci_safe_native_http_denied_before_provider_call() {
    let counter = Arc::new(CountingHttp {
        calls: AtomicUsize::new(0),
        response: NseHttpResponse {
            status: 200,
            headers: Default::default(),
            body: Vec::new(),
            final_url: "http://127.0.0.1/get".to_string(),
            version: "HTTP/1.1".to_string(),
        },
    });
    let services = NseHostServices::native().with_http(counter.clone() as Arc<dyn NseHttpProvider>);

    let profile = profile_ci_safe();
    let cap_ctx = make_capability_context(&profile);
    let req = make_request();

    let err = broker_http_request(&cap_ctx, &services, &req, "test")
        .expect_err("CiSafe + non-authority HTTP must deny");
    assert!(matches!(err, NseHttpError::Denied(_)));
    assert_eq!(
        counter.calls.load(Ordering::SeqCst),
        0,
        "provider must not be called when CiSafe denies"
    );
}

#[test]
fn manual_profile_native_http_still_works() {
    struct OkHttp;
    impl NseHttpProvider for OkHttp {
        fn request(&self, _req: &NseHttpRequest) -> Result<NseHttpResponse, NseHttpError> {
            Ok(NseHttpResponse {
                status: 200,
                headers: Default::default(),
                body: Vec::new(),
                final_url: "http://127.0.0.1/get".to_string(),
                version: "HTTP/1.1".to_string(),
            })
        }
    }
    let services =
        NseHostServices::native().with_http(Arc::new(OkHttp) as Arc<dyn NseHttpProvider>);

    let profile = profile_manual_permissive();
    let cap_ctx = make_capability_context(&profile);
    let req = make_request();

    let resp = broker_http_request(&cap_ctx, &services, &req, "test")
        .expect("manual profile + native HTTP must succeed for compatibility");
    assert_eq!(resp.status, 200);
}

#[test]
fn authority_bound_flag_is_propagated() {
    let s1 = NseHostServices::native();
    assert!(!s1.is_http_authority_bound());

    let s2 = s1.clone().with_authority_bound_http();
    assert!(s2.is_http_authority_bound());

    let s3 = s2.clone().with_authority_bound_http();
    assert!(s3.is_http_authority_bound());
}

// Registration-gate direct-global regression tests (M007A §5C)
// -----------------------------------------------------------------------
// Representative unsafe libraries — including ones that bypass
// `gate_then_register()` at their call site and rely on the
// post-registration scrub (`pop3`, `sip`, `tftp`, `smbauth`) plus gated
// ones (`ftp`, `smb`, `ssh`, `sslcert`) — must be `nil` under automated
// profiles and present under manual profiles.

const REPRESENTATIVE_UNSAFE_GLOBALS: &[&str] = &[
    "pop3",
    "sip",
    "tftp",
    "smbauth",
    "memcached",
    "netbios",
    "ftp",
    "smb",
    "ssh",
    "sslcert",
];

const REPRESENTATIVE_SAFE_GLOBALS: &[&str] = &["http", "stdnse", "base64", "json"];

#[test]
fn automated_direct_globals_absent_for_unsafe_libraries() {
    for profile in [profile_agent_safe(), profile_ci_safe()] {
        let exec = eggsec_nse::NseExecutor::with_profile(&profile).expect("executor init");
        for lib in REPRESENTATIVE_UNSAFE_GLOBALS {
            let probe = format!("return {lib} == nil");
            let out = exec
                .run_script(&probe)
                .unwrap_or_else(|e| panic!("probe for '{lib}' failed: {e:?}"));
            assert!(
                out.contains("true"),
                "automated profile {:?} must not expose global '{}': got '{}'",
                profile.kind,
                lib,
                out
            );
        }
        for lib in REPRESENTATIVE_SAFE_GLOBALS {
            let probe = format!("return {lib} == nil");
            let out = exec
                .run_script(&probe)
                .unwrap_or_else(|e| panic!("probe for '{lib}' failed: {e:?}"));
            assert!(
                out.contains("false"),
                "automated profile {:?} must retain safe global '{}': got '{}'",
                profile.kind,
                lib,
                out
            );
        }
    }
}

#[test]
fn manual_direct_globals_present_for_same_libraries() {
    let profile = profile_manual_permissive();
    let exec = eggsec_nse::NseExecutor::with_profile(&profile).expect("executor init");
    for lib in REPRESENTATIVE_UNSAFE_GLOBALS
        .iter()
        .chain(REPRESENTATIVE_SAFE_GLOBALS.iter())
    {
        let probe = format!("return {lib} == nil");
        let out = exec
            .run_script(&probe)
            .unwrap_or_else(|e| panic!("probe for '{lib}' failed: {e:?}"));
        assert!(
            out.contains("false"),
            "manual profile must retain global '{}': got '{}'",
            lib,
            out
        );
    }
}

#[test]
fn automated_dynamic_require_blocked_for_representative_unsafe() {
    for profile in [profile_agent_safe(), profile_ci_safe()] {
        for lib in ["pop3", "sip", "smb", "ftp", "unknown_lib_xyz"] {
            let exec = eggsec_nse::NseExecutor::with_profile(&profile).expect("executor init");
            let probe = format!("local m = require(\"{lib}\"); return m ~= nil");
            let _ = exec.run_script(&probe);
            let reports = exec.required_modules();
            let blocked = reports.iter().any(|r| {
                r.name == lib
                    && !r.loaded
                    && matches!(
                        r.source,
                        eggsec_nse::NseRequiredModuleSource::BlockedByPolicy
                    )
            });
            assert!(
                blocked,
                "automated profile {:?} must record BlockedByPolicy for require('{}'): {:?}",
                profile.kind,
                lib,
                reports
                    .iter()
                    .map(|r| (&r.name, r.loaded, &r.source))
                    .collect::<Vec<_>>(),
            );
        }
    }
}

#[test]
fn automated_dynamic_require_succeeds_for_safe_module() {
    let profile = profile_agent_safe();
    let exec = eggsec_nse::NseExecutor::with_profile(&profile).expect("executor init");
    let _ = exec.run_script("local m = require(\"json\"); return m ~= nil");
    let reports = exec.required_modules();
    assert!(
        reports.iter().any(|r| r.name == "json" && r.loaded),
        "safe module 'json' must load under AgentSafe: {:?}",
        reports
            .iter()
            .map(|r| (&r.name, r.loaded, &r.source))
            .collect::<Vec<_>>(),
    );
}
