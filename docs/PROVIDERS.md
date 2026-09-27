# NSE Host Providers (M005A — broker foundation)

Status: M005A implementation (clock, randomness, environment reads).

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

## Residual direct host calls (explicit inventory, not hidden)

- `nmap.rs` internal connection-registry timestamps (`created_at`,
  `connected_at`): native `SystemTime` metadata, not Lua-visible clock reads.
  Deferred to network-provider slice (005B) if endpoint identity requires it.
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
- All other network/DNS/HTTP/filesystem-handle/process domains: out of scope
  for 005A, covered by 005B/005C/005D plans.

## Guards

`scripts/check-boundaries.sh` (M005A section) enforces: no monolithic host
trait; `datetime`/`rand` zero direct host calls; no `std::env::var` in
`os.rs`/`executor_core.rs`; no `rand::random`/`thread_rng` in
`stdnse.rs`/`nmap.rs`; clock reads only in broker fallbacks (plus nmap
connection-metadata residual); every migrated module references `broker_`.
