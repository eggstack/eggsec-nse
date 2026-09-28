# NSE Host Providers (M005A broker foundation + M005B network/DNS)

Status: M005A implementation (clock, randomness, environment reads) plus
M005B implementation (authority-preserving DNS/TCP/UDP).

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

- ~100 protocol-specific libraries (`ftp`, `mongodb`, `ssh`, `http`,
  `smb`, `irc`, `sip`, `dhcp`, `helpers`, ...) with direct
  `connect_timeout`/`TcpStream::connect`/`UdpSocket`/`tokio::net` calls
  (full per-file count table in the 005B closure record). They fail closed
  on `DenyAll`/CI-safe (capability check first) but keep the legacy
  check-then-resolve shape under hostname/CIDR policies.
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
