# Changelog

All notable changes to `eggsec-nse` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — provider inversion and portability hardening

Minor release (0.x rules): public provider surface, one breaking public
signature, and corrected network-byte accounting. See `docs/PROVIDERS.md`
for the provider contract and the pinned residual inventory.

### Added

- `NseHostServices` per-run provider bundle (additive injection over
  native defaults) with one capability-aware broker sequence:
  capability decision → cancellation/resource preflight → narrow provider
  operation → resource accounting → capability/report event.
- Clock, random, and environment providers with deterministic test
  doubles (`FixedClockProvider`, scripted/counting providers).
- DNS/TCP/UDP provider contracts with exact-endpoint selection and the
  resolve-authorize-connect identity (TCP connects the DNS-approved
  concrete address, not a re-resolved name).
- Filesystem/process providers with runtime-owned metadata/process DTOs,
  opaque file handles, and per-run virtual CWD (no process-global CWD
  mutation).
- HTTP provider contract (`NseHttpProvider` DTO surface) with a native
  reqwest backend; HTTP-family libraries execute through the broker
  where parity permits.
- Public broker/provider DTO types required by embedders
  (`NseHostServices`, provider traits, `broker_*` functions).
- Windows compile/check qualification (full tests/clippy/package stay
  Linux-gated on Unix-only fixtures); MSRV remains 1.89.

### Changed

- **Breaking:** `register_vulns_library(lua)` now requires
  `register_vulns_library(lua, capability_ctx:
  &NseCapabilityContext)` (provider-backed NVD lookup helpers execute
  through the HTTP provider broker under capability gating).
- Network send bytes now count as written rather than read
  (`network_bytes_written`); configurations setting
  `max_network_bytes_written` are now actually enforced on sends
  (previously dead). Snapshots of `network_bytes_read` around sends
  will read lower — the old totals were wrong.
- HTTP accounting splits request body bytes written from response
  bytes read.
- Provider-backed libraries now execute through capability-aware
  brokers (cancel/deny block all brokered domains with zero provider
  contact).

### Security/compatibility notes

- Runtime provider mechanics are not embedding-application
  authorization. Embedders must authorize each requested operation and
  enforce their own target scope before calling this crate.
- The known 72-file specialized direct-I/O residual remains outside
  provider/capability coverage and is pinned against expansion
  (`scripts/nse-specialized-ungated.txt` + boundary guard). Automated
  embedding applications must not treat 0.2.0 as complete
  protocol-wide scope enforcement.
- No upstream Nmap script/nselib corpus is bundled; the clean-room
  compatibility corpus is unchanged in provenance policy.

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

[0.2.0]: https://github.com/eggstack/eggsec-nse/releases/tag/v0.2.0
[0.1.0]: https://github.com/eggstack/eggsec-nse/releases/tag/v0.1.0
