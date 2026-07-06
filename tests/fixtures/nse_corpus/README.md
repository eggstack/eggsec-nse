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
- **upstream**: Upstream-style fixtures testing Nmap API patterns (shortport, sslcert, vulns, etc.) — all clean-room, no upstream source copied

## Provenance

Every fixture declares `provenance` (`clean-room` or `upstream-derived`), `upstream_reference` (pattern description), and `license_note`. All current fixtures are clean-room with "No upstream source copied".

## Gap Classification

Every fixture declares `gap_classification`:
- `supported` — fully supported behavior
- `approximate` — supported with approximations
- `capability_denied` — blocked by capability context (e.g. AgentSafe)
- `missing_library` — library not implemented in Eggsec
- `context_gap` — behavior depends on runtime context not available in harness
- `unsupported_runtime` — Lua runtime limitation or Nmap-specific API

## Usage

The corpus is loaded by `compatibility_corpus_tests.rs` via `manifest.toml`.
Each fixture declares its expected status, fidelity, libraries, rules, capability events, provenance, and gap classification.

Adding a new fixture:
1. Create the .nse/.lua file in the appropriate `scripts/` subdirectory
2. Add a `[[fixture]]` entry to `manifest.toml` with provenance and gap classification
3. Run `cargo test -p eggsec-nse --features nse --test compatibility_corpus_tests -- corpus_harness`
