# eggsec-nse

Standalone Lua-based Nmap Scripting Engine runtime maintained by Eggstack. The crate provides a profile-aware request, execution, and report pipeline for running NSE-style scripts with a curated library surface.

This project targets practical compatibility for supported script categories. It does not claim full Nmap NSE or nselib parity, and it does not bundle upstream Nmap scripts or libraries.

## Use

```toml
[dependencies]
eggsec-nse = { version = "0.1", features = ["nse"] }
```

```rust,no_run
use eggsec_nse::{execute_nse_run, NseExecutionProfileKind, NseRunRequest,
    ResolvedNseExecutionProfile};

let profile = ResolvedNseExecutionProfile::ci_safe();
let request = NseRunRequest::new(
    "127.0.0.1",
    eggsec_nse::NseScriptSource::InlineManual {
        label: "example".into(),
        content: "action = function() return 'hello' end".into(),
    },
    profile,
);
let report = execute_nse_run(request)?;
println!("{}", serde_json::to_string_pretty(&report)?);
# Ok::<(), Box<dyn std::error::Error>>(())
```

The canonical high-level entry point is `execute_nse_run(NseRunRequest)`. It owns source resolution, executor setup, rule/action evaluation, and `NseRunReport` assembly. Integrators should render the returned report and should not reproduce the execution pipeline.

## Features

- `nse`: Lua runtime and the supported NSE libraries; opt-in.
- `nse-ssh2`: SSH2-backed SSH authentication and command operations; implies `nse`.
- `sandbox`: enable sandbox defaults and enforcement.
- `stress-testing`: stress-testing library functionality.

The crate defaults to no features. Execution profiles include `ManualPermissive`, `ManualStrict`, `AgentSafe`, `CiSafe`, and `CompatibilityLab`. Choose a profile appropriate to the embedding application and pass a cancellation token/limits where needed.

## Safety and embedding

Profiles and capability checks constrain NSE runtime operations; they are **not authorization or scope enforcement for the embedding application**. Applications must independently authorize each requested operation and enforce their own target scope before calling this crate. In particular, `ManualPermissive` is intended for an explicitly controlled manual surface, not unattended execution.

The resolver applies source policy, canonical path containment, symlink-escape rejection, extension and size limits, and validated module names. Network, filesystem, and process helpers use runtime capability checks. Those controls do not replace operating-system isolation when executing untrusted scripts.

## Host providers and deterministic testing

Clock, randomness, and environment reads execute through narrow per-run
providers (`NseHostServices`, native by default) behind capability-aware broker
functions. Inject deterministic doubles without changing caller construction:

```rust,no_run
use eggsec_nse::{FixedClockProvider, NseHostServices};
use std::sync::Arc;

let services = NseHostServices::native()
    .with_clock(Arc::new(FixedClockProvider::new(1_700_000_000)));
let request = request.with_host_services(services);
```

Provider mechanics never authorize operations; capability policy stays in
`NseCapabilityContext`. See [`docs/PROVIDERS.md`](docs/PROVIDERS.md) for the
contract, residual inventory, and guards.

## Compatibility fixtures and provenance

The local-only compatibility corpus is clean-room, representative test material under `tests/fixtures/nse_corpus/`. Its inventory and source notes are tracked in `docs/PROVENANCE.md` and `manifest.toml`. Do not copy upstream Nmap scripts or nselib files into this repository. Additions must be independently authored and include a manifest provenance entry.

Compatibility tiers and known gaps are described in [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md). Fixtures use loopback or synthetic targets; test runs do not require public targets.

## Build and verify

Requires Rust 1.89 or newer.

```bash
cargo fmt --all --check
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

The SSH runtime test is exercised in CI against a loopback OpenSSH daemon with disposable credentials. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the complete local workflow.

## License

MIT. See [`LICENSE`](LICENSE).
