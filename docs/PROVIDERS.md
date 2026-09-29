# NSE Host Providers (M005A broker foundation + M005B network/DNS + M005D filesystem/process + M005C HTTP)

Status: M005A implementation (clock, randomness, environment reads), M005B
implementation (authority-preserving DNS/TCP/UDP), M005D implementation
(filesystem/process providers, per-run virtual CWD, platform localization),
and M005C implementation (runtime-neutral HTTP contract + native backend +
Eggsec scoped-transport adapter).

ADR-0003 boundary: narrow per-domain provider traits, a per-run `NseHostServices`
composition bundle, native defaults, additive `NseRunRequest::with_host_services`
injection, and capability-aware broker sequencing:

```text
capability decision
-> cancellation/resource preflight
-> narrow provider operation
-> resource accounting
-> capability/report event
```

Providers never authorize Eggsec operations. `NseCapabilityContext` remains the
runtime policy owner; provider availability never overrides profile policy.

## Domains in this slice

| Domain | Trait | Native | Broker | Migrated libraries |
|---|---|---|---|---|
| Clock | `NseClockProvider::unix_timestamp` | `NativeClockProvider` (chrono) | `broker_unix_timestamp` | `datetime`, `os` (clock/date/time), `stdnse` (clock/get_time/clock_ms/clock_us/time), `nmap` (current_time/clock/clock_ms) |
| Randomness | `NseRandomProvider::fill_bytes` (+ `random_u32`/`random_f64` helpers) | `NativeRandomProvider` (rand) | `broker_random_fill`, `broker_random_f64`, `broker_random_u32` | `rand`, `stdnse` (random_string/urandom), `nmap` (get_random_bytes/get_random) |
| Environment | `NseEnvironmentProvider::var`, `temp_dir` | `NativeEnvironmentProvider` (std::env) | `broker_env_var`, `broker_temp_dir` | `os.getenv` (capability-gated, denial returns `""`), `os.tmpdir` (provider-backed), `ExecutorCore::add_default_scripts_path_with_services` (HOME/ProgramFiles via provider) |

## Injection

```rust,no_run
use eggsec_nse::{execute_nse_run, FixedClockProvider, NseHostServices, NseRunRequest};
use std::sync::Arc;

let services = NseHostServices::native()
    .with_clock(Arc::new(FixedClockProvider::new(1_700_000_000)));
let request = NseRunRequest::new("127.0.0.1", source, profile)
    .with_host_services(services);
let report = execute_nse_run(request)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Existing `NseRunRequest::new(...)` callers without injection receive native
behavior unchanged. `NseHostServices` is `Clone` (Arc-backed); concurrent runs
hold independent bundles with no process-global provider state. `sleep`/`usleep`
remain native chunked sleeps (cancellation-preserving); a dedicated sleeper
provider is deferred.

## Deterministic test providers

Public helpers (usable by downstream harnesses): `FixedClockProvider`,
`DeterministicRandomProvider` (repeating pattern or counter stream),
`MapEnvironmentProvider`, plus `CountingClockProvider`,
`CountingRandomProvider`, `CountingEnvironmentProvider` proving denied
operations never touch the provider.

## M005B — authority-preserving network/DNS

Broker sequence for every connect (ADR-0003):

```text
capability decision (DNS gate for hostnames; literals skip resolution)
-> cancellation/resource preflight
-> resolve via DNS provider (A then AAAA; one round)
-> per-candidate NseCapabilityContext evaluation (concrete IP target)
-> first allowed candidate wins; none approved -> fail closed
-> cancellation re-check + connect-time preflight
-> provider connects exactly the selected endpoint (no re-resolution)
-> I/O via opaque handle (policy re-evaluated on concrete identity)
-> post-operation counters/events
```

A hostname decision is never reused for a later connection: providers only
ever see the selected `NseResolvedEndpoint` (hostname label + concrete IP +
port + protocol). Restricted CIDR/resolved-target profiles fail closed when
no candidate is approved, and `DenyAll`/CI-safe profiles never touch the
resolver or socket providers (proven by counting-provider tests).

### Domains in this slice

| Domain | Trait | Native | Broker | Migrated paths |
|---|---|---|---|---|
| DNS | `NseDnsProvider::lookup` | `NativeDnsProvider` (per-instance Hickory, 5s/2 attempts) | `broker_dns_lookup` | `dns` library (`resolve`/`query`/`forward`/`ptr`; Lua shapes unchanged; literal-IP fast paths stay local) |
| TCP | `NseTcpSocketProvider::connect` + `NseTcpConnection` (send/receive/timeouts/local-port/alive/close/endpoint) | `NativeTcpSocketProvider`/`NativeTcpConnection` (`std::net`) | `broker_resolve_and_select`, `broker_tcp_connect`, `broker_tcp_connect_endpoint`, `broker_tcp_send`, `broker_tcp_receive` | `socket` library (opaque handles + endpoint identity), `comm` get_banner/exchange (+ async-named variants), `nmap` socket_connect/send/receive (+ async variants, opaque registry), network wrappers (authority-preserving shims, signatures unchanged) |
| UDP | `NseUdpSocketProvider::connect` + `NseUdpSocket` | `NativeUdpSocketProvider`/`NativeUdpSocket` | `broker_udp_connect`, `broker_udp_connect_endpoint`, `broker_udp_send`, `broker_udp_receive` | `socket` UDP paths (`connect_udp`/`sendto`/`receive_from`), UDP wrapper shims |

### Deterministic test providers (network)

`MapDnsProvider` (programmed answers, empty-answer default fails closed),
`ScriptedDnsProvider` (per-call answer script for rebinding tests),
`MemoryTcpSocketProvider`/`MemoryTcpConnection` and
`MemoryUdpSocketProvider`/`MemoryUdpSocket` (exact-endpoint connect log +
canned I/O), `CountingDnsProvider`, `CountingTcpSocketProvider`,
`CountingUdpSocketProvider`. Handles are `Send + Sync`; concurrent runs
hold independent provider state (covered by a contention test).

### Authority-preservation rationale

The pre-provider code checked a hostname string, then resolved and
connected separately (`to_socket_addrs().next()`, Tokio `connect(host:port)`
re-resolving inside). Under `AllowCidrs`/`AllowResolvedTargetSet` the policy
saw a hostname (unparseable as `SocketAddr`, so CIDR checks were skipped for
names) while the socket used whatever the resolver returned later. The
broker closes this split: policy is evaluated against every concrete
candidate IP, exactly one approved endpoint is connected, and provider
call-counts prove no second lookup occurs.

Fail-closed denial messages keep the `"denied"` convention
(`network tcp access denied: no approved concrete endpoint ...`) so Lua
callers matching on denial strings behave as before.

### Semantic notes (behavior deltas, all intentional)

- `nmap.socket_connect` previously accepted only literal `SocketAddr`
  strings (`"Address parse error"` otherwise); it now resolves hostnames
  through the broker. Literal-IP callers are unaffected.
- The legacy sandbox gate required *all* resolved addresses to sit inside
  `allowed_networks`; the broker selects via capability policy first and the
  sandbox then gates the selected concrete endpoint (fail closed either way).
- `socket.send` previously skipped the preflight check (only
  post-accounting); the broker adds capability + limit preflight on the
  concrete endpoint.
- Failed connects no longer increment `network_operations` (previously the
  increment was conditional on where the OS call failed); success-only
  accounting is now exact and locked by tests.
- Async-named closures (`*_async`, `comm.*_async`, `nmap.async_*`) execute
  the synchronous provider flow inline: bounded by the operation timeout,
  no detached tasks, no Tokio connect helpers.
- Native UDP binds `0.0.0.0:0` (legacy parity); IPv6 UDP endpoints fail at
  bind — same limitation as before, now documented.
- `NseIpAddress` is octet-based; provider contracts never expose
  `std::net`/Tokio/Hickory types. Native-only interop (`connect_std`,
  `from_std`, `into_std`, `recv_once_native`) is marked as such and used
  only by compatibility shims.

### Remaining direct-network inventory (explicit, not hidden)

Guard-enforced migrated set (CI fails on new bypasses):
`socket.rs`, `dns.rs` (zero direct network calls), `comm.rs` (only
`reqwest` in `tryssl`), `nmap.rs` (only shim signatures), `wrappers.rs`
(no connection creation/resolution), natives isolated in `providers.rs`.

Deferred, still capability-checked per hostname but *not*
authority-preserving (hostname check + native resolve split retained);
rewriting them is explicitly out of scope for 005B:

- Protocol-specific libraries with direct `connect_timeout`/
  `TcpStream::connect`/`UdpSocket`/`tokio::net` calls. The 005B text
  claimed these "fail closed on DenyAll/CI-safe (capability check
  first)"; the M005E source audit falsified that blanket claim.
  **M007B migrated the broker-compatible cohort**, so the residual is
  now 22 files (15 ungated + 7 advisory), pinned in
  `scripts/nse-specialized-{advisory,ungated}.txt` and
  guard-enforced. The 97-file M005E baseline is preserved as history in
  `scripts/nse-migration-classes.txt` (one final class per original
  entry). The current split:
  - **advisory-gated (7 files)**: capability consultation is present
    but the direct effect still bypasses provider
    injection/cancellation/accounting — `dhcp`, `dhcp6`, `libssh2`,
    `ntp`, `snmp`, `ssh`, `xdmcp`.
  - **ungated residual (15 files)**: direct socket I/O with no
    capability consultation at all — `bjnp`, `coap`, `eigrp`, `iax2`,
    `ike`, `ipmi`, `knx`, `natpmp`, `packet`, `srvloc`, `ssh2`, `stun`,
    `tftp`, `wsdd`, plus `public_api/api.rs`.

  Every remaining residual is a shape the current provider contract
  cannot represent: unconnected/broadcast/multicast UDP, raw packet or
  interface access, native socket handoff to `ssh2::Session`, or the
  public sync compatibility surface. They are deliberately manual-only;
  see the "M007B" section for the promotion rules and the guard that
  fails if a `BrokerCompatible*` class is ever left on a file that still
  holds a direct effect.
- `comm.tryssl` (HTTPS via `reqwest`): deferred to the 005C HTTP provider.
- `SandboxConfig::resolve_host`/`is_host_allowed` (`lib.rs`): legacy
  resolving sandbox helpers with documented rebinding risk; no production
  callers remain in migrated paths (capability policy + broker selection
  supersede them). Retained for API compatibility.
- `nmap.add_connection`/`get_connection`: compatibility shims wrapping
  caller-supplied native streams as opaque handles (endpoint recovered from
  peer address; no new connection). `get_connection` keeps its
  always-`None` (parity) ownership semantics.
- `nmap` registry metadata timestamps (`created_at`/`connected_at`):
  native `SystemTime`, not Lua-visible; retained intentionally.
- Wrapper I/O shims (`nse_network_tcp_send`/`receive`) operate on
  caller-supplied connected handles with concrete-peer policy targets;
  no resolution/connection is created there.

Regeneration: `rg -c -e 'TcpStream::connect' -e 'connect_timeout'
-e 'UdpSocket::bind' -e 'to_socket_addrs' -e 'lookup_host' -e 'tokio::net::'
-e 'reqwest::' src/libraries/*.rs src/*.rs` (counts archived in the 005B
closure).

## Residual direct host calls (explicit inventory, not hidden)

- `nmap.rs` internal connection-registry timestamps (`created_at`,
  `connected_at`): native `SystemTime` metadata, not Lua-visible clock reads.
  Retained intentionally in 005B (registry metadata, not endpoint identity).
- `stdnse.rs`/`nmap.rs`/`datetime.rs`/`os.rs` broker fallbacks
  (`unwrap_or_else(|_| chrono::Utc::now()...)`): reached only when the broker
  itself is denied/failed; TimeClock is allowed in all profiles so these are
  defensive, not primary paths.
- `os.rs` `get_current_timestamp` helper: retained for the above fallbacks.
- `os.rs` `getcwd`/`chdir` (`env::current_dir`/`set_current_dir`): process-global
  CWD semantics deferred to 005D per-run virtual CWD work.
- `os.rs` `NSE_ENV` thread-local setenv state: library-level override preserved;
  real environment reads are provider-backed.
- `nmap.rs` privilege/interface discovery (`id`, `ip`, `ipconfig` via
  `std::process::Command`): deferred to 005D process/platform providers.
- All HTTP/filesystem-handle/process domains: out of scope for 005A/005B,
  covered by 005C/005D plans. Core network/DNS is 005B (see above);
  protocol-specific libraries remain deferred (see 005B inventory).

## Guards

`scripts/check-boundaries.sh` (M005A section) enforces: no monolithic host
trait; `datetime`/`rand` zero direct host calls; no `std::env::var` in
`os.rs`/`executor_core.rs`; no `rand::random`/`thread_rng` in
`stdnse.rs`/`nmap.rs`; clock reads only in broker fallbacks (plus nmap
connection-metadata residual); every migrated module references `broker_`.

The M005B section additionally enforces: zero direct network calls in
`socket.rs`/`dns.rs`; no direct socket calls in `comm.rs` (`reqwest` only in
`tryssl`); no connection creation/resolution in `nmap.rs` (`TcpStream` only
in shim signatures/comments); no creation/resolution in `wrappers.rs`;
`broker_` presence in every migrated network module.

The M005D section additionally enforces: no process-global
`set_current_dir` in `src/`; zero direct fs/process calls in `io.rs`/`lfs.rs`
(`std::process::id` + the env `temp_dir` fallback in `io.tmpfile` are
inventoried); no direct fs/CWD calls in `os.rs` (env `temp_dir` fallback +
`hostname` lookup inventoried); no child-process spawns in `nmap.rs`;
delegated wrapper fns call no `std::fs` directly (metadata/read-dir/
symlink-metadata/process-exec shims keep native bodies for their leaking
signatures); `broker_` presence in `io`/`lfs`/`os`/`nmap`.

The M005C section additionally enforces: no `reqwest` in the migrated
HTTP-family libraries (`http`, `httppipeline`, `comm`, `brute`, `vulns`,
`upnp`); natives isolated in `providers.rs`; `broker_` presence in every
migrated HTTP module.

The M005E section additionally enforces: the direct-socket file set
(production code) exactly matches the pinned advisory + ungated
inventories (`scripts/nse-specialized-{advisory,ungated}.txt`); every
advisory file keeps consulting capability; `reqwest` is allow-listed to
the pinned set (`scripts/nse-reqwest-inventory.txt`); no platform host
modules (`os::unix`/`os::windows`/`nix`/`libc`) outside `providers.rs`.
The M007B section (below) replaces the M005E socket scan with a
corrected, provider-aware one and adds the migration-class,
registration-compat, and direct-HTTP cross-checks.
The 005B/005C "capability-checked" blanket claims for deferred protocol
libraries are corrected by the M005E audit (advisory vs ungated split).

## M005D — filesystem/process providers and per-run isolation

Broker sequence for every filesystem/process operation (plan §6):

```text
capability/sandbox path decision (on the resolved absolute path)
-> cancellation/resource preflight
-> provider operation on the sandbox-approved path (no second transformation)
-> accounting/event result
```

Relative paths resolve against the per-run virtual CWD first; the sandbox
canonicalizes (when enabled) and enforces containment; the provider
operates on the approved path. Denial or cancellation never reaches the
provider.

### Domains in this slice

| Domain | Trait | Native | Broker | Migrated paths |
|---|---|---|---|---|
| Filesystem | `NseFilesystemProvider` (17 path-scoped ops) + `NseFileHandle` (read/write/flush/seek/close) | `NativeFilesystemProvider`/`NativeFileHandle` (`std::fs`/`std::env`); per-instance virtual-CWD override, never process-global | `broker_fs_*` (read/write/stat/dir/remove/rename/mkdir/links/permissions/exists/open/CWD) + `broker_fs_resolve` (pure CWD join) | `io` (open/read/write/flush/seek/lines/tmpfile; per-registration handle registry), `lfs` (all fns; `chdir`/`currentdir` virtual), `os` remove/rename/getcwd/chdir, non-leaking filesystem wrappers |
| Process | `NseProcessProvider` (run/spawn/is_privileged/network_interfaces) + `NseChildProcess` | `NativeProcessProvider`/`NativeChildProcess` (`std::process`; bounded run with kill-on-timeout; kill-on-drop) | `broker_process_run`, `broker_process_spawn`, `broker_is_privileged`, `broker_network_interfaces` | `io.popen` (platform shell localized in `shell_command`), `nmap` is_admin/is_privileged/list_interfaces/get_interface |

DTOs: `NseFileMetadata` (len/type/readonly/timestamps/unix-mode), `NseDirEntry`,
`NseOpenMode`, `NseProcessSpec`/`NseProcessResult`, `NseNetworkInterface`
(reuses `NseIpAddress`). No `std::fs`/`std::process` types cross provider
contracts; native-only interop (`from_std`, `from_std` handles) is marked as
such. Deterministic story: `CountingFilesystemProvider`,
`DenyFilesystemProvider`, `CountingProcessProvider`, `DenyProcessProvider`
(zero-call denial proofs); I/O parity via isolated tempdir fixtures.

### Virtual CWD semantics

- `set_current_dir` records an override on the provider instance (validated
  `is_dir`); `current_dir` returns the override or the live process CWD.
- Concurrent runs hold independent providers: different virtual CWDs,
  same fd numbers, no interference (contention test).
- Fresh bundles have no override (run-local state resets with the run).
- Intentional isolation fix: `lfs.chdir`/`os.chdir` no longer mutate the
  process. Non-migrated protocol libraries still see the process CWD for
  relative paths (documented boundary; they are deferred).
- `os.chdir` newly carries a read-kind capability gate (matching
  `lfs.chdir`); `os.getcwd`/`lfs.currentdir` stay check-free (legacy-exact).

### Platform support matrix

| Area | Unix | Windows | Other |
|---|---|---|---|
| Core fs ops | native | native | native |
| Symlinks | `symlink` | `symlink_file` (files; dir targets unsupported, explicit error) | explicit unsupported error |
| Permission bits | `set_unix_mode` | unsupported (use `set_readonly`; wrapper maps write-bits) | unsupported |
| Privilege probe | `id -u == 0` | always false | always false |
| Interface enumeration | `ip addr` parse | `ipconfig` parse | loopback fallback |
| Process run/spawn | `Command` + timeout kill | `Command` + timeout kill | spawn unsupported error |
| `io.popen` shell | `sh -c` | `cmd /C` | unsupported error |
| CI | full | `check` (no-default, nse, nse+sandbox) | — |

Unix/Windows differences live in `providers.rs` native fns (`symlink_native`,
`set_unix_mode_native`, `is_privileged_native`,
`network_interfaces_native`, `shell_command`); compatibility libraries
contain no `cfg(unix)`/`cfg(windows)` branches for fs/process anymore.

### Semantic notes (behavior deltas, all intentional)

- `io` handles are per-registration: fd numbers restart at 100 per run;
  `reset_for_run` is a documented no-op for handles (kept for API compat);
  live-handle metrics continue via a counter (no global handle storage).
- `io.open` parent auto-creation is now capability-gated (was unchecked).
- `io` handle read/write carry cancellation/limit preflight + byte
  accounting (open-time policy only, handles are capabilities).
- `io.tmpfile` names gain a randomness suffix (`eggsec_tmp_{pid}_{rand}`).
- `io.popen` children are tracked per-registration and terminated at run
  end (previously leaked); spawn itself is unbounded, the run is the bound.
- `nmap.list_interfaces` emits one entry per interface with filled
  addresses (legacy emitted one entry per matching output line).
- Failed filesystem ops do not bump counters (success-only accounting,
  matching the 005B network semantics).
- Loader reads (script/module search + `datafiles`) stay direct: policy is
  enforced at resolution with canonical containment, and broker events
  there would double-count into reports. Inventoried, not hidden.

### Remaining direct host-operation inventory (explicit, not hidden)

- Loader/lookup reads: `executor_core.rs` script search reads,
  `datafiles.rs` authorized reads (policy enforced pre-read on the same
  path).
- Wrapper shims with leaking signatures: `nse_fs_metadata`,
  `nse_fs_read_dir`, `nse_fs_symlink_metadata` (`std::fs` types),
  `nse_process_exec` (`std::process::Output`) — capability-gated native
  bodies, documented for 005E disposition.
- `os.hostname` (`hostname` crate) and `os.tmpdir`/`io.tmpfile` env
  `temp_dir` fallbacks: ungated host reads preserved from legacy.
- `SandboxConfig::resolve_host`/`is_host_allowed`: no production callers
  in migrated paths (superseded by broker resolution + selection).
- `nmap` registry metadata + `add/get_connection` shims: unchanged from
  005B inventory.
- Protocol-specific file/process helpers (not shared/core): deferred per
  plan scope; covered by 005E source audit.
- `std::process::id` (pid labels) and `NSE_ENV` thread-local setenv state:
  not host mutations/reads of concern; retained.

Regeneration: `rg -n -e 'std::fs::' -e 'std::process::' -e 'std::env::' -e
'std::os::' src/libraries/io.rs src/libraries/lfs.rs src/libraries/os.rs
src/libraries/nmap.rs src/wrappers.rs` (only allow-listed residuals may
remain; guards enforce the rest).

## M005C — HTTP provider and Eggsec scoped-transport adapter

Broker sequence for every HTTP request (plan §6):

```text
runtime capability check (on the library-supplied host identity)
-> cancellation/budget preflight
-> provider request
-> accounting/event result
```

The Eggsec adapter maps the runtime DTO to `ScopedHttpRequest` and
dispatches through `HttpTransport::execute` with the injected authority
(same-host redirects only, direct proxy posture, profile TLS).

### Domains in this slice

| Domain | Trait | Native | Broker | Migrated paths |
|---|---|---|---|---|
| HTTP | `NseHttpProvider::request` | `NativeHttpProvider` (reqwest blocking; per-instance pooled clients keyed by TLS/timeouts) | `broker_http_request` (typed `NseHttpError`: denied/cancelled/timeout/connection/request) | `http` (all methods + async variants, shapes preserved), `httppipeline` (go/queue), `comm.tryssl`, `brute.http_auth`, `vulns` NVD lookups, `upnp.get_devices` |

DTOs: `NseHttpMethod` (8 parity verbs, fail-closed parse), `NseHttpRequest`
(method/url/host/headers/body/timeouts/TLS intent), `NseHttpResponse`
(status/headers/body/final URL/version). No reqwest/Eggsec types cross the
contract. Deterministic story: `MockHttpProvider` (scripted outcomes +
request log), `CountingHttpProvider` (zero-call denial proofs).

### TLS intent alignment (intended behavior change)

Legacy standalone requests were effectively always verified (global accept
flags defaulted false with no callers). Migrated libraries now set
`insecure_tls` from `ctx.allows_insecure_tls()`, matching the documented
Eggsec profile posture (Manual/CompatibilityLab bypass; all other profiles
verified; scripts cannot escalate — the flag is library-set, and the
Eggsec adapter structurally ignores the DTO flag in favor of its
construction-time decision). Locked by tests on both sides.

### Semantic notes (behavior deltas, all intentional)

- Process-global reqwest clients and TLS flags are gone; pooling lives in
  the per-bundle native provider (keyed by TLS/timeout triple).
- `set_accept_invalid_certs/hostnames` are deprecated no-op shims (no
  callers existed).
- `http.get/post/put` keep legacy option handling (timeout only; headers
  ignored); `delete/head/options` ignore options; `request`/`post_host`/
  `put_data` pass body/headers/authorization/useragent as before.
- Async-named HTTP fns call the synchronous broker inline (bounded);
  concurrency characteristics differ from the old true-async client,
  completion/error shapes do not.
- `httppipeline` keeps per-request timeout/header/body support (a superset
  of legacy, which ignored them); `queue`'s 30s bound preserved.
- `upnp.get_devices` gains the 30s default bound (legacy `blocking::get`
  was unbounded).
- `vulns` NVD lookups are now capability-gated (were unchecked external
  access); verified TLS preserved.
- `brute.http_auth` builds the Basic header in-library (same credentials).
- `nmap.list_interfaces` shape normalization is a 005D change, reused here.
- HTTP gains byte/operation accounting (previously uncounted).
- `nmap`/`brute`-TCP/SSDP-socket code is untouched (deferred protocol
  surface, inventoried for 005E).

### Eggsec adapter (engine-owned)

`crates/eggsec/src/nse_http_provider.rs`: `NseHttpTransportProvider`
implements the runtime trait over `HttpTransport` + injected
`NetworkAuthority`, reusing `nse_http_capability` mapping (refactored to
an explicit-TLS core; no policy duplication). Out-of-scope/cross-host
fail closed in transport with no native fallback; `reqwest` never appears
(adapter source-scan test). Production dispatch is NOT rewired: current
NSE dispatch holds no `Scope`/`ApprovedExecution`, so manual dispatch
keeps the native provider until the NSE enforcement prerequisite exists
(see closure disposition). The adapter is staged on a feature branch and
activates with the runtime release/adoption step.

### Remaining direct HTTP inventory (explicit, not hidden)

- Migrated set (guard-enforced reqwest-free): `http`, `httppipeline`,
  `comm` (tryssl now brokered; no reqwest remains), `brute` (HTTP-auth
  only; TCP helpers deferred), `vulns` (NVD only; local DB unaffected),
  `upnp` (description fetch only; SSDP sockets specialized).
- Deferred protocol HTTP (not shared/core, per plan scope): anything
  outside the migrated set keeps native paths; the 005B-era
  "capability-checked" blanket claim is corrected by the M005E audit
  (advisory-gated vs ungated-residual split above applies to HTTP
  clients like `elasticsearch`, `httpspider`, `mobileme` as well).
- Regeneration: `rg -n -e 'reqwest' src/libraries/http.rs
  src/libraries/httppipeline.rs src/libraries/comm.rs
  src/libraries/brute.rs src/libraries/vulns.rs src/libraries/upnp.rs`
  (must be empty; guards enforce).

## M005E — provider coverage qualification

Qualification/integration pass, not a migration: one coherent bundle
across domains, source-derived inventory, corrected coverage claims,
and a release disposition. Corrective production change in this slice
is limited to the send-accounting defect below.

### Source inventory classification (post-005A-D)

| Class | Members | Enforcement |
|---|---|---|
| provider-backed (broker sequence) | `socket`, `dns`, `comm` (incl. tryssl), `http`, `httppipeline`, `io`, `lfs`, `os` (getenv/remove/tmpdir/hostname-intent), `datetime`, `rand`, `stdnse`, `nmap` Lua-visible clock/random, `vulns` NVD, `brute.http_auth`, `upnp` description fetch | capability + cancel + provider + accounting; guards |
| native implementations | `providers.rs` only | single allow-listed zone; guards |
| compatibility shims (capability-gated native bodies) | `wrappers.rs` leaking-signature shims (`fs_metadata`, `read_dir`, `symlink_metadata`, `process_exec`, `time_now`, `random_bytes`, `env_var`, TCP/UDP send/receive on caller handles); `nmap.add/get_connection` | gate + accounting; no injection (signatures leak std types); public but only tests call the `nse_*` time/random/env/process fns |
| advisory-gated specialized (7 files, post-M007B) | `scripts/nse-specialized-advisory.txt` | entry denial; no injection/cancel/accounting; gate-presence guarded |
| ungated specialized residual (15 files, post-M007B) | `scripts/nse-specialized-ungated.txt` | none; set pinned against expansion; the 97-file M005E baseline is preserved in `scripts/nse-migration-classes.txt` |
| specialized HTTP/TLS/SSH clients | `public_api/api.rs` (public sync API, native), `cve/{nvd,osv,cisa_kev}.rs` (reqwest clients), `helpers.rs` (shared TLS/HTTP builders used by gated callers), `elasticsearch.rs`, `httpspider.rs`, `mobileme.rs`, `tls.rs` (gated `connect_tcp`), `sslcert.rs`/`openssl.rs` (mixed), `ssh.rs`/`libssh2.rs` (gated entries) | allow-listed reqwest set (`scripts/nse-reqwest-inventory.txt`) |
| loader/lookup reads | `executor_core.rs` script search, `resolver` script/module loads, `datafiles.rs` policy-checked reads, `bjnp.rs`/`ls.rs`/`pppoe.rs` data reads | ScriptResolver/module policy gates the loader paths |
| diagnostic timestamps | `output.rs` (report timing), `nmap` registry metadata | not Lua-visible; retained |
| pure parse, no I/O | `capabilities.rs`/`match_lib.rs` IP/SocketAddr parsing, `datetime` chrono conversions | none needed |
| stubs (no host effect) | `os.execute` (returns status 1, never spawns) | none needed |
| runtime plumbing | `lib.rs` `spawn_blocking`, `async_executor` Runtime import, `run.rs` regex statics, `smb` session static / `nmap` connection registry / `openssl` TLS-connector static (specialized state, ungated — same residual class as their libraries) | documented; the `dnsbl` process-global resolver was removed in M007B |
| process/env residuals | `io.rs` `process::id` + `temp_dir` fallback, `os.rs` `temp_dir` fallback + `hostname` lookup + `SystemTime`, `wrappers` env/time shims | inventoried 005D residuals |

Regeneration: the `scripts/nse-*.txt` pins plus
`tests/provider_composition_tests.rs` (bundle coherence) are the
machine-readable inventory; `scripts/check-boundaries.sh` (M005E and
M007B sections) diffs source against the pins.

### Send-accounting correction (closure-blocker fix)

`broker_tcp_send`/`broker_udp_send` counted sent bytes in the
**read** bucket, leaving `network_bytes_written` permanently zero and
the `max_network_bytes_written` limit dead; HTTP lumped
request+response bodies into read. Fixed with direction-aware
accounting (`before_blocking_send`/`after_blocking_send` in
`capabilities.rs`; written bucket + written-limit preflight for
TCP/UDP sends; HTTP splits request-written/response-read). Wrapper
send shims already posted to the written bucket and now preflight it
too. Proven by `provider_accounting_reflects_actual_execution`,
`write_byte_limit_preflight_blocks_send`,
`http_accounting_splits_request_and_response`, and the corrected
legacy asserts in `network_provider_tests.rs`.

### Composition evidence (M005E)

`tests/provider_composition_tests.rs` (8 tests): one Lua run drives
clock+env+DNS+TCP+HTTP+fs through a single injected bundle with exact
per-provider call counts, DNS-selected endpoint identity on the TCP
connect, and script-supplied host identity on the HTTP request;
concurrent full runs isolate bundles/filesystem/CWD; cancelled and
deny-all contexts block all seven brokered domains with zero provider
contact; denied Lua runs record denials with zero provider contact.

## M007A — automated library effect gate and HTTP authority assurance

Fail-closed automated-profile boundary over every Lua library/global,
plus an explicit authority contract for automated HTTP.

### Effect manifest

`src/effect_manifest.rs` (`LIBRARY_EFFECT_MANIFEST`, 159 entries) classifies
every `register_*_library` call in `ExecutorCore::register_libraries()`:

| Class | Meaning | Automated profiles |
|---|---|---|
| `Pure` (34) | no host side effects | allowed |
| `ProviderBacked` (84) | effects route through the capability-aware broker | allowed |
| `ManualOnlyDirectIo` (34) | direct host I/O remains, no provider injection | denied |
| `ManualOnlyAdvisory` (7) | capability gate exists but effects stay outside provider accounting/authority | denied |

M007B moved the broker-compatible cohort from manual-only to
`ProviderBacked` (M007A baseline: 35 / 18 / 80 / 26). `target` moved from
`Pure` to `ProviderBacked` because the corrective audit found a direct
`ToSocketAddrs` call in `target.resolve`.

Unknown/unclassified names resolve to `ManualOnlyDirectIo` (deny by
default, ADR-0004 §3). The manifest is additive: the public
`NseLibraryDescriptor` struct layout is untouched.

The 22-file post-M007B residual (15 ungated + 7 advisory) maps to the
two manual-only classes; those 22 files are the only registered manual-only
direct-I/O modules, and 13 further manual-only entries are conservative
classifications of modules with no direct network effect (stubs such as
`eap`, `gps`, `sasl`, `multicast`, `pppoe`, `rpc`, `ospf`, `giop`,
`vuzedht`, `mobileme`, `httpspider`, `smbauth`; fail-closed, not a safety
defect). Representative pins: `pop3`/`smb` → `ProviderBacked` (M007B
promotion), `tftp` → `ManualOnlyDirectIo`, `snmp` →
`ManualOnlyAdvisory`, `http`/`stdnse` → `ProviderBacked`, `base64`
→ `Pure`.

### Registration gate

- 27 high-risk libraries route through `gate_then_register()` at their
  call site (representative residual + advisory modules).
- All remaining manual-only libraries are removed by
  `scrub_ineligible_globals()`, which runs after every registration
  (before any script executes) and sets each ineligible global to `nil`
  under AgentSafe/CiSafe. Manual profiles are untouched.
- Dynamic `require()` consults the same manifest and records
  `NseRequiredModuleSource::BlockedByPolicy` for unsafe/unknown names
  under automated profiles; `report.libraries` surfaces the denial as a
  `blocked-by-policy` warning.

Proven by `tests/effect_manifest_tests.rs` (direct-global absence for
`tftp`/`snmp`/`ssh`/`packet`/`stun`/`smbauth` under AgentSafe+CiSafe,
presence of the promoted cohort, presence under manual, safe globals
retained, require blocked for unsafe/unknown, require succeeds for
`json`) and the migrated `tests/local_protocol_tests.rs` denial tests.
Post-M007B, promoted libraries are *registered* under automated
profiles, so their automated denial comes from the broker's capability
gate instead: `assert_promoted_library_denied_at_capability_gate`
asserts the global is present **and** a denied `network*` capability
event was recorded, paired with the existing zero-server-hits
assertions. That is a stronger contract than the old
"library absent" proof, because it pins the actual authority decision.

### Registration ↔ manifest consistency (M007B)

M007A checked registration → manifest only, and 12 manifest entries
described modules that are never registered. M007B closes both
directions:

- `register_fn` on every manifest entry is the exact function called
  from `ExecutorCore::register_libraries()` (the M005E-M007B baseline
  recorded base names, which had gone stale for 66 entries after the
  services-aware refactor);
- `scripts/nse-registration-compat-entries.txt` pins the 16 modules
  that define a `pub fn register_*` but are never registered, each with
  a reviewed rationale (12 of them still have a manifest entry so a
  future registration cannot bypass the gate; 4 are unreachable and
  therefore outside the automated-eligibility surface).

Enforced by `effect_manifest::tests::registration_and_manifest_agree`
(via `include_str!`, so it holds in every feature combination) and by
`scripts/check-boundaries.sh`, which also fails if a listed module has
since been wired up.

### HTTP authority assurance

`NseHostServices` carries an additive `http_authority_bound` flag
(default `false`; only `with_authority_bound_http()` sets it `true`).
`broker_http_request()` denies AgentSafe hostname requests before
provider contact unless the bundle explicitly carries authority-bound
assurance; CiSafe remains network-denied; manual profiles keep native
behavior. No provider is treated as authority-bound merely because a
capability pre-check occurred — the Eggsec adapter becomes the first
authority-bound provider in M007D.

Regeneration: `scripts/check-boundaries.sh` (M007A section) asserts
manifest coverage of every `register_*_library` call, scrub presence,
representative residual pins, and the `false`-by-default HTTP flag.

## M007B — broker-compatible protocol migration and residual reconciliation

`BrokeredTcpStream` (`src/brokered_stream.rs`) is the compatibility
adapter that let the blocking-TCP protocol cohort move to
`broker_tcp_connect` / `broker_send_all` / `broker_read_into` without
rewriting each protocol state machine. It exposes a `TcpStream`-shaped
surface plus `Read`/`Write`, so `native_tls` handshakes and internal
`TcpStream` plumbing work unchanged. The native socket is never exposed:
there is no `into_inner`, `as_raw_fd`, `try_clone`, `set_nonblocking`,
or `shutdown`. Call sites needing those stay manual-only
(`NativeHandleEscape`).

One documented behavior delta: `set_read_timeout(None)` /
`set_write_timeout(None)` (infinite blocking) map to
`BROKERED_STREAM_DEFAULT_TIMEOUT` (120s) because the provider contract
requires a concrete duration. Keeping the run bounded is what makes
cancellation meaningful under automated profiles.

### What the corrective audit found

The M005E scan (`TcpStream::connect | UdpSocket::bind |
AsyncTcpStream::connect`, unanchored) could not distinguish a brokered
call from a native one, because `TcpStream::connect` is a substring of
`BrokeredTcpStream::connect`. Sixteen fully-migrated libraries therefore
still matched. The corrected scan anchors every pattern behind a
non-identifier boundary, drops comment-only lines, covers direct DNS
resolution, and excludes provider/broker infrastructure. That surfaced
four real findings beyond the migration bookkeeping:

| Finding | Detail | Resolution |
|---|---|---|
| `target.resolve` was a direct DNS effect while classified `Pure` | `std::net::ToSocketAddrs::to_socket_addrs` with no capability check, no cancellation, no accounting, reachable from `AgentSafe`/`CiSafe` | migrated to `broker_dns_lookup`; reclassified `ProviderBacked` |
| `radius.connect_async` was claimed migrated but was not | raw `tokio::net::UdpSocket::bind` + `connect` to the caller's host | migrated to `broker_udp_connect`; promoted to `ProviderBacked` |
| `dnsbl` had two direct DNS effects and a process-global hickory resolver | `ToSocketAddrs` in `check`/`check_multi` plus a `OnceLock<TokioResolver>` in `check_async` | migrated to `broker_dns_lookup`; `check_async` now shares the brokered path |
| 66 manifest `register_fn` values were stale, and 12 entries described unregistered modules | base-name prefix instead of the `_with_services` function actually called | corrected; reverse direction pinned in `scripts/nse-registration-compat-entries.txt` |

### Residual after M007B

97 M005E entries → **22** (15 ungated + 7 advisory). Every one is a
shape the current provider contract cannot represent:

- unconnected / broadcast / multicast UDP: `bjnp`, `coap`, `dhcp`,
  `dhcp6`, `eigrp`, `iax2`, `ike`, `ipmi`, `knx`, `natpmp`, `ntp`,
  `snmp`, `srvloc`, `stun`, `tftp`, `wsdd`, `xdmcp`;
- raw packet / interface: `packet`;
- native socket handoff to `ssh2::Session`: `libssh2`, `ssh`, `ssh2`;
- public sync compatibility surface: `public_api/api.rs`.

`scripts/nse-migration-classes.txt` keeps one final class per original
M005E entry (plus the two DNS entries the corrected scan discovered), and
`scripts/check-boundaries.sh` fails if a `BrokerCompatible*` /
`ProviderBackedDns` class is ever left on a file that still holds a
direct effect, if a residual file has no class, or if
provider/broker infrastructure re-enters the pins.

### Promotion rule

A registered module became `ProviderBacked` only when every
automated-relevant network effect is broker/provider-backed, the module
has no unconnected/native-handle/raw effect reachable from its Lua
surface, and its registration receives the runtime's
`NseCapabilityContext` and `NseHostServices`. 65 modules qualified
(the broker-compatible cohort plus `target` and `radius`).
Line-count reduction alone was never a criterion.

Automated exposure of these libraries is still governed by the
runtime's network policy: `AgentSafe` builds
`NseNetworkPolicy::AllowCidrs(scope)` or
`AllowResolvedTargetSet([approved target])`, `CiSafe` builds
`DenyAll`, and the broker evaluates the capability against the *concrete
resolved endpoint*. An out-of-scope connect or a DNS query is refused
before the provider is invoked, so promotion widens availability
without weakening authority. Eggsec-side automated NSE stays
quarantined until M007E.

### Guards added in the M007B section

`scripts/check-boundaries.sh` now asserts, in addition to the M005E
checks:

1. the specialized residual equals the pins, under the corrected
   provider-aware scan;
2. every current residual has a migration class, and no
   `BrokerCompatible*` / `ProviderBackedDns` class sits on a file with
   a direct effect;
3. every classified path is a real source file, appears exactly once,
   and carries a recognized class plus rationale;
4. `src/providers.rs` / `src/brokered_stream.rs` never enter the
   residual pins;
5. representative residuals (`tftp`, `ssh`, `snmp`, `eigrp`, `packet`)
   stay `ManualOnly*`;
6. every `src/libraries/*.rs` defining `pub fn register_*` is either
   registered or allow-listed, and the allow-list does not rot;
7. every `reqwest`-touching library module that appears in the manifest
   stays `ManualOnly*`, so a native-HTTP site can never be promoted.

Tests: `src/effect_manifest.rs` (`registration_and_manifest_agree`,
`migrated_cohort_is_promoted_to_provider_backed`,
`unresolved_residual_stays_manual_only`),
`tests/effect_manifest_tests.rs`, `tests/m007b_migration_tests.rs`
(focused loopback success, in-scope/out-of-scope, CiSafe denial,
cancellation, and byte-accounting evidence for `target`, `radius`, and
the promoted TCP cohort), and `tests/brokered_stream_tests.rs`.
