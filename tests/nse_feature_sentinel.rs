//! Sentinel test that detects when NSE feature-gated tests are being silently
//! skipped because `--features nse` was not passed.
//!
//! Without the `nse` feature: this test fails with a clear message.
//! With the `nse` feature: this test passes trivially.

#[cfg(not(feature = "nse"))]
#[test]
fn nse_feature_not_enabled_tests_skipped() {
    panic!(
        "NSE feature-gated tests (local_protocol_tests, runtime_corpus_tests) \
         are being skipped. Re-run with: cargo test -p eggsec-nse --features nse"
    );
}

#[cfg(feature = "nse")]
#[test]
fn nse_feature_enabled() {
    // Sentinel passes when feature is active.
}
