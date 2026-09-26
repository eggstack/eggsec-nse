# Contributing

## Requirements

- Rust 1.89 (MSRV) or newer.
- `clang` and the platform build tools needed by `mlua`/OpenSSL when enabling `nse`.
- `ripgrep` for repository boundary checks.

## Verification

Run the checks relevant to your change before opening a pull request:

```bash
cargo fmt --all --check
cargo metadata --no-deps
cargo check --no-default-features
cargo check --features nse
cargo test --features nse
cargo check --features nse-ssh2
cargo check --features nse,sandbox
cargo clippy --all-targets --features nse -- -D warnings
cargo package --list
cargo package
./scripts/check-boundaries.sh
```

The SSH runtime qualification uses `tests/ssh_runtime_tests.rs`. CI provisions an isolated loopback `sshd`, creates a throwaway account and password, and runs the test with `NSE_SSH_TEST_PORT`. Never use public targets or persistent credentials for runtime tests.

## Architecture

`NseRunRequest` → `execute_nse_run` → `NseRunReport` is the canonical production pipeline. Resolver, profile, executor, limits, cancellation, capability events, compatibility, and report construction belong to the runtime. Embedding applications own authorization and target-scope enforcement. Keep this crate independent of Eggsec crates and DTOs.

## Compatibility corpus

Only independently authored, clean-room fixtures belong in `tests/fixtures/nse_corpus/`. Record the fixture's authorship/source, expected compatibility tier, and rationale in `manifest.toml`; retain the provenance notes in `docs/PROVENANCE.md`. Do not copy, vendor, or derive fixtures from upstream Nmap scripts or nselib content.
