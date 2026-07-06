# NSE Compatibility Corpus

Local-only regression test fixtures for NSE compatibility verification.

## Categories

- **discovery**: Safe host/service discovery patterns (portrule, hostrule, prerule, postrule)
- **version**: Service/version detection patterns
- **default**: Scripts representative of Nmap default category behavior
- **protocol**: Protocol libraries with local fixtures (HTTP, DNS)
- **auth**: Credential-shape tests (no real brute force)
- **partial**: Supported with approximations or warnings
- **unsupported**: Expected denials, capability blocks, missing modules
- **regression**: Loader/report/capability regressions from prior milestones

## Usage

The corpus is loaded by `compatibility_corpus_tests.rs` via `manifest.toml`.
Each fixture declares its expected status, fidelity, libraries, rules, and capability events.

Adding a new fixture:
1. Create the .nse/.lua file in the appropriate `scripts/` subdirectory
2. Add a `[[fixture]]` entry to `manifest.toml`
3. Run `cargo test -p eggsec-nse --features nse compatibility_corpus`
