# Releasing `eggsec-nse`

This document defines the only supported release procedure for the
standalone `eggsec-nse` crate. The first published version is immutable;
follow the bootstrap path exactly once, then use the steady-state path.

## Version / tag / source invariants

- Package name is `eggsec-nse`. Never rename the package to work around a
  registry conflict; stop and reconcile instead.
- Versions follow semver. The first public version is `0.1.0`.
- Release tags are `v<version>` (for example `v0.1.0`) and must point at
  the exact source commit that produced the published artifact. Never move
  or recreate a release tag after publication.
- The published archive must correspond to the qualified release-candidate
  commit. Never publish from a dirty tree, and never use `--allow-dirty`
  or `--no-verify` to force publication.

## First-release bootstrap (used once for `0.1.0`)

crates.io Trusted Publishing cannot create a crate that does not exist
yet, so the first release must use ordinary authenticated Cargo
publication from a maintainer workstation:

1. Confirm registry state: `eggsec-nse` is unclaimed and `0.1.0` is
   absent. Query the crates.io API and the sparse index; do not rely on
   web search. If the name is owned by another party, stop.
2. Freeze the release-candidate commit: `CHANGELOG.md` entry,
   `docs/RELEASING.md`, README, and package metadata (`0.1.0`, edition
   2021, MSRV 1.89, MIT, explicit repository/homepage/documentation/
   readme) reconciled, with a clean working tree.
3. Fully qualify the candidate (see "Release verification" below),
   including Linux/macOS CI, MSRV 1.89, `cargo package` inspection,
   the clean-room corpus, and the loopback SSH2 runtime test.
4. Run `cargo publish --dry-run` from a clean checkout.
5. Run `cargo publish` from the exact clean candidate. Do not pass the
   token on a command line that will be captured in logs; rely on the
   Cargo credential store and never commit or print credential material.
6. Wait for registry/index availability, then verify:
   `cargo search`/registry metadata resolves `eggsec-nse 0.1.0`, and a
   clean scratch crate resolves and builds the published package with
   the required feature combinations (no Git/path dependency).
7. Create the `v0.1.0` tag pointing exactly at the published source
   commit, and create the GitHub Release with concise notes that do not
   overclaim Nmap parity.
8. Update the README installation example from the Git/revision form to
   the crates.io form on `main` (post-release commit, not the tag).

## Steady-state releases (after `0.1.0` exists)

- Preferred: crates.io Trusted Publishing from the `eggstack/eggsec-nse`
  repository via a minimal release workflow (explicit tag/version
  consistency checks, explicit release environment, minimum
  `id-token: write` / `contents: read` permissions, never triggered by
  ordinary pushes or pull requests).
- Manual token publication remains the documented recovery path when
  Trusted Publishing is unavailable; it requires human version/tag
  verification before `cargo publish`.
- Do not publish another version merely to exercise automation.

### Release history

- `0.1.0` (`v0.1.0`): first public release via the bootstrap path above.
- `0.2.0` (`v0.2.0`): provider-inversion release (M005 provider
  surface, breaking `register_vulns_library` signature, corrected
  send/write accounting); published via the manual-token recovery path
  with exact-candidate qualification, crates.io/docs.rs verification,
  and an immutable tag on the published source commit. The release
  workflow's ripgrep prerequisite was fixed in the same release.
- `0.3.0` (`v0.3.0`): breaking security release carrying the M007A/M007B
  boundary work (automated library effect gate, broker-compatible protocol
  migration, residual reconciliation); published via the manual-token
  recovery path. Removed 74 public functions relative to 0.2.0 — 70
  `register_<mod>_library(&Lua)` entry points plus 4 `helpers::*` — of
  which two were a capability bypass on the public API and are withdrawn
  without replacement.

### Security-disclosure note

`0.3.0` is the first release without the capability-bypassing public TCP
helpers `helpers::tls_connect` and `helpers::tcp_connect_with_timeout`, both
of which returned a raw `std::net::TcpStream` from an unmediated
`connect_timeout`. Both were present in **every** published version
(`0.1.0` and `0.2.0`): `src/libraries/helpers.rs` is byte-for-byte identical
between the two tags, and both reach `TcpStream::connect_timeout` twice.

Advisory `GHSA-w2g3-v83j-frp2` (`eggsec-nse`, Rust/crates.io) was published
*after* `0.3.0` was verified on the registry, with affected range
`>= 0.1.0, < 0.3.0`, patched `0.3.0`, and severity `medium` — derived from the
threat model (the consumer must call the public helper, so this is a
library-boundary bypass, not a remote-execution vulnerability), not from the
word "bypass".

### Predecessor-version disposition (recorded)

- `0.1.0`: **yanked.** No identified consumer requires a fresh `0.1`
  resolution, and `0.3.0` is available as the safe upgrade target. A lockfile
  pinned to `0.1.0` still resolves and builds; a fresh `^0.1` resolution is
  refused; an unconstrained `>=0.1.0` consumer now resolves to `0.3.0`.
- `0.2.0`: **not yanked, deliberately.** The principal consumer requires
  `^0.2.0`, and `0.2.0` is the only `0.2.x` that exists, so yanking it would
  leave that requirement with no resolvable candidate — the case the release
  procedure exists to prevent. The version **remains affected**; not being
  yanked does not make it safe. Revisit once the principal consumer adopts
  `0.3.0`.

Two communication rules for any release that touches this area:

1. Publish the advisory **after** the fixed artifact is verified, never
   before, unless an active-exploitation reason is recorded separately.
2. Never collapse four distinct facts into one: the withdrawn public helper
   bypass; the broader M007 automated-library effect gating; the 22-file
   specialized direct-I/O residual (not provider-backed); and the still-deferred
   DNS scope binding in the consuming application. 0.3.0 does not deliver
   universal NSE protocol scope enforcement.

### Trusted Publishing status

- Repository side: `.github/workflows/release.yml` is Trusted
  Publishing-ready (tag-only trigger `vX.Y.Z`, `release` environment,
  official `rust-lang/crates-io-auth-action`, tag==`Cargo.toml` version
  gate, clean-tree gate, full qualification before `cargo publish`).
- Registry side: **pending**. The Trusted Publisher entry must be added
  in the crate's settings on the crates.io website by a crate owner;
  there is no API-only path available during this milestone. Until that
  website-side step completes, the workflow fails closed at
  authentication and releases use the manual-token recovery path above.
  This is a low/operational residual, not a release blocker.

## Release verification

Run against the exact release-candidate commit:

```bash
cargo fmt --all --check
./scripts/check-boundaries.sh
cargo metadata --no-deps
cargo tree --workspace
cargo check --no-default-features
cargo check --features nse
cargo test --features nse
cargo check --features nse-ssh2
cargo check --features nse,sandbox
cargo clippy --all-targets --features nse
cargo +1.89.0 check --locked --no-default-features
cargo +1.89.0 check --locked --features nse
cargo publish --dry-run
cargo package --list
cargo package
```

Lint-gate note: the historical gate spelled `cargo clippy ...
-- -D warnings`, but the repository carries accepted warning debt
(deprecated `openssl::asn1::Asn1StringRef::as_utf8` call sites and
related lints), so `-D warnings` does not pass. Release
qualification uses plain `cargo clippy --all-targets --features nse`
(zero errors) plus the hosted CI matrix. Do not re-add `-D warnings`
to release docs or scripts without first clearing the underlying
debt under a separate plan.

CI must also exercise the real loopback SSH2 runtime test
(`tests/ssh_runtime_tests.rs` with a disposable local `sshd`).

Post-publish, resolve `eggsec-nse = "<version>"` from crates.io in a
clean temporary Cargo consumer and build the needed feature
combinations. Compare published crate source/metadata against the
release candidate where practical.

## Rollback / yank guidance

- Published versions are immutable. Never attempt to overwrite a release.
- If a post-publish source/tag problem is discovered, do not move the
  release tag to a different commit while claiming it is the published
  source.
- If the artifact is critically defective, evaluate crates.io yank
  semantics and publish a corrected version under a new semver version
  through a separate corrective plan. Yanking hides the version from new
  resolution but does not delete it; downstream lockfiles pinned to the
  yanked version keep resolving.
- Until the principal consumer (Eggsec) has adopted the registry
  artifact, the previously qualified Git revision remains the rollback
  point.
