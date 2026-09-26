# Changelog

All notable changes to `eggsec-nse` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — first public release

Initial standalone release of the scanner-independent NSE compatibility
runtime, extracted with history from the Eggsec workspace
(`eggstack/eggsec`, path `crates/eggsec-nse`).

### Added

- Canonical runtime pipeline `NseRunRequest` → `execute_nse_run` →
  `NseRunReport`: resolver-first script handling, profile-aware execution,
  rule evaluation, limits/cancellation, capability decisions, and one
  complete report assembly path (rules, stats, resolver diagnostics,
  library usage, capability events, compatibility/fidelity, output, and
  extracted evidence).
- Optional Cargo features: `nse` (Lua runtime + supported NSE libraries),
  `nse-ssh2` (SSH2-backed authentication/command operations; implies
  `nse`), `sandbox` (sandbox defaults/enforcement), `stress-testing`
  (stress-testing library functionality). No features are enabled by
  default.
- Execution profiles `ManualPermissive`, `ManualStrict`, `AgentSafe`,
  `CiSafe`, and `CompatibilityLab`. Profiles and capability checks
  constrain runtime operations; they are not authorization or scope
  enforcement for the embedding application.
- Resolver source policy: canonical-path containment, symlink-escape
  rejection, extension/size limits, and validated module names.
- Clean-room compatibility corpus under `tests/fixtures/nse_corpus/`
  with provenance tracked in `docs/PROVENANCE.md` and `manifest.toml`.
  No upstream Nmap scripts or nselib files are bundled.
- Compatibility tiers and known gaps in `docs/COMPATIBILITY.md`;
  release/ownership guidance in `docs/RELEASING.md`.

### Compatibility notes

- MSRV is Rust 1.89; edition is 2021; license is MIT.
- This release targets practical compatibility for supported script
  categories. It does not claim full Nmap NSE or nselib parity.
- The runtime has zero `eggsec-*` dependencies. Embedding applications
  must authorize each requested operation and enforce their own target
  scope before calling this crate.

[0.1.0]: https://github.com/eggstack/eggsec-nse/releases/tag/v0.1.0
