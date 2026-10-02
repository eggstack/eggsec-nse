# Changelog

All notable changes to `eggsec-nse` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — breaking security release: automated library effect gate

Deliberate major release. The M007 runtime hardening removed **74 public
functions** relative to 0.2.0, so no 0.2.x can carry it. Two of those 74 were
a capability bypass on the public API and are withdrawn without replacement;
the other 72 are entry points whose signature now takes the runtime's
capability context and host services. See `docs/PROVIDERS.md` for the
provider contract, the residual inventory, and the guards.

`cargo semver-checks check-release --baseline-version 0.2.0 --features nse`
reports exactly one failed lint, `function_missing`, with exactly these 74
items. No other breaking lint fires.

### Security — public direct-connect helpers withdrawn (breaking, no replacement)

`helpers::tls_connect` and `helpers::tcp_connect_with_timeout` were `pub` on
0.1.0 and 0.2.0. Both opened a raw socket through
`std::net::TcpStream::connect_timeout` without receiving an
`NseCapabilityContext` and without executing through `NseHostServices` or the
provider broker, so a consumer calling them bypassed the runtime's capability
decision, cancellation, accounting, and provider-selection boundary for that
connection (ADR-0004 §8). They are removed. **Do not recreate them, and do not
add a deprecated alias** — a deprecated alias would still be a reachable
bypass.

```text
- helpers::tls_connect
- helpers::tcp_connect_with_timeout
- helpers::make_addr                 (pure: format!("{}:{}", host, port))
- helpers::parse_socket_addr         (pure: SocketAddr parse)
```

Migration:

- Connection work moves to the broker: `broker_tcp_connect`,
  `broker_dns_lookup`. Those go through the capability gate, cancellation, and
  accounting, which is the entire point of the change.
- `make_addr` / `parse_socket_addr` are pure and trivially inlined; no
  crate-internal caller remains.

Both names are enforced absent by the compiler, not only by a text scan:
`src/libraries/helpers.rs` carries `compile_fail` doctests for all four, and
`scripts/check-boundaries.sh` re-runs the specialized direct-I/O scan on the
**untruncated** file so a primitive hidden after a `mod tests` marker fails
closed. See the guard note below.

### Breaking — 70 library registration entry points now require services

`register_<mod>_library(lua: &Lua)` has no way to obtain an
`NseCapabilityContext` or `NseHostServices`, so it could only ever construct
native defaults — the fallback path ADR-0004 forbids for automated authority
claims. The replacement is mechanical:

```rust
// 0.2.0
nbd::register_nbd_library(lua)?;
// 0.3.0
nbd::register_nbd_library_with_services(lua, &capability_ctx, &services)?;
```

The two new arguments are mandatory and deliberately have no defaults:
defaulting them would recreate the native-fallback path. A consumer with no
profile context must construct one explicitly. `NseHostServices::native()` is
the escape hatch for manual, operator-driven use; it is **not** valid for
automated authority claims (see `http_authority_bound` in `docs/PROVIDERS.md`).

All 70 affected modules:

```text
afp ajp amqp anyconnect bitcoin bittorrent cassandra citrixxml cvs dicom drda finger ftp
http2 iec61850mms imap informix ipp irc iscsi isns jdwp kafka ldap libssh2_utility membase
memcached mongodb mqtt msrpc msrpcperformance mssql mysql nbd ncp ndmp netbios nrpc omp2
oops openssl oracle pgsql pop3 postgres proxy rdp redis rmi rpcap rsync rtsp sftp sip smb
smb2 smtp socks ssh1 sslcert sslv2 tls tn3270 tns versant vnc websocket whois winrm xmpp
```

Two notes so the count is not misread later:

- `register_telnet_library` is also `_with_services`-only, but it was never
  published as a plain function, so it is additive rather than a break. The
  published break set is 70 modules, not 71.
- 18 modules still expose both forms. Those retained plain entry points are a
  deliberate, separately reviewed compatibility surface pinned in
  `scripts/nse-registration-compat-entries.txt`; they are not part of this
  break.

There is no 0.2.1. The two withdrawn helpers make a patch release
unachievable by construction, not merely unverified.

### Security — automated library effect gate

- A standalone effect manifest (`src/effect_manifest.rs`, 159 entries)
  classifies every `register_*_library` call in
  `ExecutorCore::register_libraries()`: `Pure` 34, `ProviderBacked` 84,
  `ManualOnlyDirectIo` 34, `ManualOnlyAdvisory` 7. An unknown name resolves
  to `ManualOnlyDirectIo`, so the manifest is deny-by-default.
- 65 libraries move from manual-only to `ProviderBacked`, and `target` moves
  from `Pure` to `ProviderBacked`. Manual-only registrations fall 106 → 41.
- `AgentSafe` and `CiSafe` gain a registration and `require()` gate: 27
  high-risk libraries route through `gate_then_register()`, and
  `scrub_ineligible_globals()` runs after every registration and before any
  script executes, setting each ineligible global to `nil` under automated
  profiles. Manual profiles are untouched. `report.libraries` surfaces a
  `require()` denial as a `blocked-by-policy` warning.
- `NseHostServices` carries an additive `http_authority_bound` flag, default
  `false`; only `with_authority_bound_http()` sets it `true`.
  `broker_http_request()` denies AgentSafe hostname requests before provider
  contact unless the bundle explicitly carries authority-bound assurance.
  CiSafe remains network-denied.

Automated exposure is still governed by the runtime network policy:
`AgentSafe` builds `NseNetworkPolicy::AllowCidrs(scope)` or
`AllowResolvedTargetSet([approved target])`, `CiSafe` builds `DenyAll`, and
the broker evaluates the capability against the **concrete resolved endpoint**.
Promotion widens availability; it does not weaken authority.

### Security — `target.resolve` DNS is now brokered

The M007B corrective audit found `target.resolve` performing
`std::net::ToSocketAddrs::to_socket_addrs` directly while the library was
classified `Pure`. A direct resolution consults no capability context, so
`CiSafe`'s `DenyAll` could not stop it, and the resolved name was never bound
to scope. The call now goes through `broker_dns_lookup` and the library is
`ProviderBacked`. Three further findings from the same audit were fixed in
this release: `radius.connect_async` was claimed migrated but still used a raw
UDP bind/connect; `dnsbl` had two direct DNS effects plus a process-global
hickory resolver; and 66 manifest `register_fn` values plus 12 unregistered
manifest entries were stale.

### Honest residual — what is still not provider-backed

The specialized direct-I/O residual is **97 → 22 files** (15 ungated + 7
advisory). The remaining long-tail direct-I/O protocols are **not**
provider-backed: unconnected/broadcast/multicast UDP (`bjnp`, `coap`, `dhcp`,
`dhcp6`, `eigrp`, `iax2`, `ike`, `ipmi`, `knx`, `natpmp`, `ntp`, `snmp`,
`srvloc`, `stun`, `tftp`, `wsdd`, `xdmcp`), raw packet/interface (`packet`),
native socket handoff to `ssh2::Session` (`libssh2`, `ssh`, `ssh2`), and the
public sync compatibility surface (`public_api/api.rs`). These are shapes the
current provider contract cannot represent; they are manual-only, and the set
is pinned against expansion. **Automated embedding applications must not
treat 0.3.0 as complete protocol-wide scope enforcement.**

`scripts/nse-m005e-direct-io-baseline.txt` freezes the original 97 paths as
history and `scripts/nse-migration-classes.txt` keeps exactly one final class
per baseline entry, so a migration can never erase the history it is measured
against.

### Known limitations (unchanged or inherited, not fixed here)

- `broker_dns_lookup` gates `DnsResolution` on `DenyAll` only and does not
  evaluate per-target membership for the resolved name. A promoted
  `ProviderBacked` library can therefore resolve a name outside the approved
  target set under `AgentSafe`. No connection is possible, so this is an
  egress/timing surface rather than a scope bypass of the connection path. The
  runtime DNS policy is bound to approved scope in the consuming application,
  not here.
- `DnsResolution` is not charged to `network_operations`, so a permitted
  brokered lookup is bounded only by the wall-clock and instruction budgets.
  Pre-existing behavior, shared with the `dns` library; `DenyAll` already
  refuses it under `CiSafe`.
- `upnp.discover` performs a brokered TCP connect to the SSDP multicast group
  `239.255.255.250:1900` instead of real UDP multicast discovery, so SSDP
  discovery does not work. Out of scope until an unconnected/multicast
  provider exists.

### Guard changes in this release

- The two withdrawn direct-connect helpers are enforced absent by
  `compile_fail` doctests in `src/libraries/helpers.rs`, so the check is made
  by the compiler over the whole crate.
- `scripts/check-boundaries.sh` re-runs the specialized direct-I/O scan on the
  **untruncated** file and requires the result to stay inside the pinned
  residual inventory. The residual scan reads production code only and
  truncates each file at its first `mod tests` marker, so a primitive placed
  after a test module was previously invisible; it now fails closed. The pins
  are unchanged — the untruncated sweep resolves to the same 22 files.

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

[0.3.0]: https://github.com/eggstack/eggsec-nse/releases/tag/v0.3.0
[0.2.0]: https://github.com/eggstack/eggsec-nse/releases/tag/v0.2.0
[0.1.0]: https://github.com/eggstack/eggsec-nse/releases/tag/v0.1.0
