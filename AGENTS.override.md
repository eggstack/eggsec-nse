# NSE Module AGENTS Override

## Module Overview

The NSE (Nmap Scripting Engine) module (`crates/eggsec-nse/`) provides Lua VM integration, NSE libraries, sandbox enforcement, and CVE integration.

> **Milestone 1 (loader/profile) is closed.** Canonical implementation, tests, policy contract, and deferred work are listed in the [Milestone 1 Closure Index](../../architecture/nse_integration.md#milestone-1-closure-index). Future work should treat that index as the authoritative pointer; do not duplicate its content.

> **Milestone 2 (registry/report/corpus) is closed.** Library registry metadata (`NseLibraryDescriptor` / `LIBRARY_REGISTRY`) is the source of truth for library compatibility. `NseRunReport.libraries` records per-run observed or attempted `require()` activity, not a capability snapshot. Each entry has a `loaded` field: `true` means the runtime observed a successful module load; `false` means a `require()` was attempted but the module failed, was blocked, was missing, had an invalid name, or was statically detected without runtime confirmation. Static `require()` detection is approximate and labeled with a warning. The later truthfulness follow-up refined that reporting without reopening Milestone 2. Rule behavior is defined by `NseRuleEvaluationReport`. Run output truthfulness is defined by `NseRunReport`. The compatibility corpus is representative and local-only. See the [Milestone 2 Closure Note](../../architecture/nse_integration.md#milestone-2-closure-note).

> **Milestone 3 (capability wrappers) Phase 01 complete.** A complete capability inventory and risk classification exists at `architecture/nse_capability_inventory.md`. The inventory classifies all side-effecting NSE helper operations by capability class, blocking risk, profile policy, accounting needs, cancellation requirements, and report events. Key findings: 4 libraries sandboxed (socket, io, os, lfs), all protocol libraries (~100+) bypass sandbox, `nmap.socket_*()` bypasses socket sandbox, `stdnse.sleep()` blocks without cancellation checks. Migration priority: process execution → filesystem write → filesystem read → network TCP/UDP → DNS → compression → crypto/TLS → time/randomness → pure CPU.

> **Milestone 3 Phase 02 complete.** `NseCapabilityContext` and decision engine (`capabilities.rs`) provide centralized policy enforcement. `NseCapabilityKind` covers 11 operation classes. Profile-specific checks: ManualPermissive allows all with warnings, ManualStrict enforces path/network policy, AgentSafe denies process exec + FS write, CiSafe denies all side effects. `NseCapabilityEvent` integration into `NseRunReport.capability_events`. Pilot wrappers in `wrappers.rs`. `ExecutorCore` stores capability context. Architecture guards detect direct high-risk ops in NSE libraries (informational).

> **Milestone 3 Phase 03 complete.** Filesystem and process wrappers fully migrated. Libraries `io.rs`, `lfs.rs`, `os.rs`, `nmap.rs` route all side-effecting operations through capability checks. Executing wrappers (`nse_fs_read_to_string`, `nse_fs_write`, `nse_fs_remove_file`, `nse_fs_create_dir`, `nse_fs_rename`, `nse_process_exec`, etc.) combine capability checking with the actual operation. Library registration functions accept `&NseCapabilityContext`.

> **Milestone 3 Phase 04 complete.** Network TCP/UDP and DNS wrappers migrated. Executing wrappers: `nse_network_tcp_connect`, `nse_network_tcp_send`, `nse_network_tcp_receive`, `nse_network_udp_send`, `nse_network_udp_receive`, `nse_dns_lookup`, plus check-only `check_network_udp`. Libraries `socket.rs`, `comm.rs`, `dns.rs` accept `&NseCapabilityContext`.

> **Milestone 3 Phase 05 complete.** Time, randomness, environment, crypto, and compression helpers routed through `NseCapabilityContext`. Executing wrappers: `nse_time_now`, `nse_random_bytes`, `nse_env_var`, `nse_compress`, `nse_decompress`. Check-only wrappers: `check_randomness`, `check_environment`, `check_crypto`, `check_compression`. Libraries migrated: `datetime.rs`, `rand.rs`, `openssl.rs`, `tls.rs`, `sslcert.rs`, `zlib.rs`. Compression enforces 64 MiB input and 256 MiB output limits.

> **Milestone 3 Closure (Phase 06).** All helper-side enforcement is complete for: filesystem (io/lfs/os), process execution (os/nmap), network TCP/UDP (socket/comm), DNS (dns), time (datetime), randomness (rand), environment (os), compression (zlib), and crypto/TLS (openssl/tls/sslcert). Deferred: unpwdb, brute, datafiles, protocol-specific internal helpers beyond network I/O. Capability events are wired into `NseRunReport.capability_events` via `with_capability_events()`. Architecture guard checks 33/33b/33c prevent new direct side-effect bypasses. Check 33 (process exec) is a hard FAIL; 33b (filesystem) and 33c (network) are INFO for unmigrated protocol libraries. New side-effect helpers must route through `NseCapabilityContext` wrappers. See `architecture/nse_capability_inventory.md` for the capability class catalog.

> **Milestone 4 complete (2026-07-06).** Evidence model (`NseEvidenceKind`, `NseEvidenceItem`), extraction (`extract_evidence()`), bridge (`to_report_envelope()`), CLI UX (`print_human_report()`), 40 corpus fixtures, 43 library registry. See [architecture/nse_integration.md](../architecture/nse_integration.md).

> **Milestone 4 closure (2026-07-06, runtime harness).** The compatibility corpus is now verified by two structurally separated harnesses:
> - `compatibility_corpus_tests.rs` (`mod corpus_manifest`, formerly `corpus_harness`) is the **static** harness: resolver-only, no script execution. Verifies script/module resolution, file policies, blocked-at-resolver diagnostics.
> - `runtime_corpus_tests.rs` is the **runtime** harness: drives every fixture through `NseExecutor::with_profile(&ResolvedNseExecutionProfile)` with synthetic host/port context. Asserts manifest expectations (`expected_status`, `expected_fidelity`, `expected_libraries`, `expected_rules`, `expected_capability_events`) against observed behavior.
> - `runtime_smoke_tests.rs` exercises the full pipeline (profile → context → execution → report → `ReportEnvelope` bridge) for representative scenarios.
>
> Architecture guards 42/43/44 enforce the separation: the runtime test binary must exist, must use `NseExecutor::with_profile`, and the static harness must not call `run_script_with_rules`. See the [Milestone 4 Closure Verification](../../architecture/nse_integration.md#milestone-4-closure-verification) for the full verification table.

> **Milestone 5 Phase 03 (2026-07-06, local protocol fixtures).** Local TCP/HTTP/UDP fixture harness (`local_fixtures.rs`), 5 new `.nse` scripts (`tcp_connect_echo`, `tcp_connect_denied`, `http_get_local`, `http_post_local`, `udp_echo`), 16 runtime tests (`local_protocol_tests.rs`). Manifest `local_service` metadata + runtime harness skip for all 7 iteration sites. Architecture guard Check 47. 452 NSE tests pass (1 ignored), 47 architecture guards pass.
> **Milestone 5 Phase 04 (2026-07-06, deferred library migration).** `unpwdb.rs` migrated from Deferred to Wrapped (FS reads through `nse_fs_read_to_string`). `http.rs` migrated to Wrapped (all network operations gated via `check_network_tcp()`; denied requests never reach reqwest). `ssl` registry entry corrected to Wrapped (stale since Milestone 3 Phase 05). Registry tests updated. 182 lib tests, 43 corpus tests, 47 architecture guards pass.
> **Milestone 6 Phase 01 (2026-07-06, HTTP capability bypass and runtime strictness).** HTTP library `http.rs` promoted from `PartiallyWrapped` to `Wrapped` — all network operations gated via `check_network_tcp()`; denied requests never reach reqwest. Local HTTP fixtures gained atomic hit counters proving denied requests don't reach server. AgentSafe HTTP tests upgraded from permissive to strict denial assertions. CiSafe HTTP test added. Runtime library assertions tightened from lenient to hard failures. Architecture guards 48-50 added. 494 NSE tests pass, 50 architecture guards pass.

> **Milestone 6 Phase 02 (2026-07-07, HTTP method coverage and guard hardening).** All HTTP methods (GET/POST/PUT/DELETE/HEAD/OPTIONS/request) now have ManualPermissive success tests and AgentSafe/CiSafe zero-hit denial tests. `maybe_denied_response()` helper centralizes HTTP policy checks. HttpServer tracks method/path. Architecture guards 48b-48d added. All tests pass, architecture guards pass.

## Recent Bug Fixes (2026-05-28)

| Component | Issue | Fix |
|-----------|-------|-----|
| `eggsec-nse/src/libraries/smbauth.rs` | 8 functions defined twice (shadowing issue) | Removed duplicate definitions, keep first occurrence |
| `eggsec-nse/src/libraries/smbauth.rs` | `signing_hmac_md5` defined 3 times | Kept first (lines 121-131), removed others |
| `eggsec-nse/src/libraries/datafiles.rs` | `ssh`, `ntp`, `mongodb` entries duplicated | Removed duplicate entries |
| `eggsec-nse/src/libraries/io.rs:140,163,181,194,211` | `file.get("fd").unwrap_or(-1)` masks missing fd | Return explicit error when fd missing |
| `src/libraries/http.rs:143-144` | Performance | Replaced `HashMap` with `FxHashMap` in `parse_options` |
| `src/libraries/datafiles.rs:31-33` | Performance | Replaced `HashMap` with `FxHashMap` in `get_services()` |
| `src/libraries/creds.rs:102,123` | Performance | Replaced `HashSet` with `FxHashSet` for local `seen` variables |
| `src/public_api/api.rs:107-108,381,413,463,486,532` | Performance | Replaced all `HashMap` with `FxHashMap` for CVE database, HTTP headers |

## Recent Bug Fixes (2026-06-03)

| Component | Issue | Fix |
|-----------|-------|-----|
| `src/libraries/nmap.rs` | 7 `SystemTime::now().duration_since(UNIX_EPOCH).unwrap()` calls | Changed to `.unwrap_or_default()` for clock edge case safety |
| `src/libraries/nmap.rs` | `lua.create_table().unwrap()` in standalone calls | Changed to `lua.create_table()?` where closure returns Result |
| `src/libraries/nmap.rs` | 25 `lua.create_table().unwrap()` in `unwrap_or_else` fallbacks | Kept as-is (safe fallback; Table doesn't impl Default) |
| `src/libraries/brute.rs:282` | `reqwest::blocking::Client::builder()...build().unwrap()` | Changed to match with error response on failure |
| `src/libraries/smb.rs:56` | `addr.parse::<SocketAddr>().unwrap()` | Changed to `.map_err()` returning io::Error |
| `src/libraries/io.rs:68,77` | `let _ = std::fs::create_dir_all(parent)` silent failure | Added `tracing::warn!` logging on directory creation failure |
| `src/libraries/stdnse.rs:822` | `SystemTime::now()...unwrap()` | Changed to `.unwrap_or_default()` |
| `tests/sandbox_tests.rs` | No sandbox integration tests | Added 17 integration tests for SandboxConfig (paths, commands, networks, host resolution) |
| `src/libraries/lfs.rs` | TOCTOU documentation gap | Added module-level doc explaining TOCTOU limitation and mitigation approach |
| `src/libraries/peg_parser.rs:224` | `current_char().unwrap()` could panic on empty input | Changed to `.ok_or(PegError::UnexpectedEnd)?` with new test case |
| `src/libraries/vnc.rs:101,107,311,317` | `try_into().unwrap()` on challenge slices | Changed to `.map_err()` returning io::Error with descriptive message |

## NSE Libraries HashMap Usage

All NSE library files now use `rustc_hash::FxHashMap`/`FxHashSet` for consistency and performance.

## Key Patterns

- **NSE duplicate functions**: Check for duplicate function definitions (especially in `smbauth.rs`)
- **Sandbox enforcement**: UDP sendto is sandboxed via `connect_udp()` host check
- **Mutex poisoning**: Use `.unwrap_or_else(|e| e.into_inner())` for graceful handling
- **Async on sync RwLock**: parking_lot RwLock is synchronous - don't use `.await`
- **Execution limits**: `NseExecutionLimits` in `limits.rs` bounds wall-clock time, instruction count, output size, script size, and resource usage. Luau `set_interrupt` hook enforces limits cooperatively during execution.
- **Cancellation**: `NseCancellationToken` wraps `Arc<AtomicBool>` for cooperative cancellation. Check `is_cancelled()` in hooks and before starting work.
- **Resource counters**: `NseResourceCounters` tracks network/filesystem operations and bytes. Updated by library wrappers; snapshot via `execution_stats()`.
- **Hook API**: mlua 0.11.6 uses Luau — `set_interrupt()` for interrupt hooks, NOT `set_hook()`. `remove_hook()` is `#[cfg(not(feature = "luau"))]` — unavailable for Luau.
- **parking_lot::Mutex**: Returns `MutexGuard` directly from `lock()`, no `Result` wrapping.
- **Execution Profiles**: `profile.rs` provides `NseExecutionProfileKind` (5 variants), `ResolvedNseExecutionProfile`, `ScopeInput`, and policy types. Profiles resolve into `SandboxConfig`, `NseExecutionLimits`, script/module/network policy, and audit metadata. Constructors: `manual_permissive`, `manual_strict`, `agent_safe`, `ci_safe`, `compatibility_lab`. CLI handler uses `ManualPermissive` by default.
- **Profile-Aware Execution**: `run_cli_with_profile(config, Option<ResolvedNseExecutionProfile>)` in `lib.rs` is the profile-aware entry point. Falls back to `manual_permissive` when `None`. Validates script file policy, creates executor via `NseExecutor::with_profile(&resolved_profile)`, includes profile metadata in JSON output. `NseExecutor::with_profile()` constructs the capability context from the resolved profile (not manual-permissive defaults). `with_policy(...)` is manual-only; automated surfaces (CLI via `run_cli_with_profile`, agent, MCP, REST) must use `with_profile(...)` or `with_full_policy(...)`. AgentSafe filesystem reads are scoped-only (path must be under sandbox `allowed_dir` or explicit root).
- **Script/Module Resolver**: `resolver.rs` provides `ScriptResolver` which enforces profile-derived script/module policies, strict module-name grammar, canonical path validation, symlink-aware containment, file extension allowlists, size limits, and structured diagnostics. All script and module loading flows through the resolver. Types: `NseScriptSource`, `NseModuleName`, `ResolvedNseScript`, `ResolvedNseModule`, `NseLoadError`, `NseLoadDiagnostic`. Validation function: `validate_nse_module_name()`.
- **Read-path vs Write-path Helpers**: `resolver.rs` exposes two distinct root-containment helpers. `validate_existing_path_under_roots()` is read-only — requires the canonical file path to resolve, returns `IoError` for non-existent files. `validate_parent_under_roots()` is reserved for future create/write semantics (currently `#[allow(dead_code)]`). Read paths must never authorize non-existent script/module files via parent fallback.
- **Empty-roots semantics**: `allowed_script_roots.is_empty()` means *unrestricted manual file selection* under `ManualPermissive` (intentional), but *misconfiguration* under `ManualStrict` / `CompatibilityLab` (rejected by canonical root check). Under `AgentSafe` / `CiSafe`, scripts/filesystem modules are denied before any root check. See the empty-roots semantic table in `architecture/nse_integration.md` and `profile.rs` doc comments on `NseScriptPolicy` / `NseModulePolicy`.

## Rust-Side Side-Effect Inventory (Milestone 1 Closure)

All Rust-side side-effecting helpers have been classified. Cancellation is enforced at the Lua interrupt hook level (`set_interrupt`) which fires between Lua instructions — not during blocking I/O syscalls. Individual cancellation checks are present in core infrastructure paths (`load_script`, `setup_require`). Library-level helpers are classified for Milestone 3 capability-wrapper migration.

### Core Infrastructure (cancellation-aware)

| Location | Category | Cancellation | Notes |
|----------|----------|-------------|-------|
| `executor_core.rs:load_script()` | fs | ✅ Pre-check | Checks `cancellation.is_cancelled()` before file reads |
| `executor_core.rs:setup_require()` | fs | ✅ Pre-check | Checks `is_cancelled()` before resolver delegation |
| `resolver.rs:resolve_module_content()` | fs | ⚠️ Bounded | File reads bounded by `max_required_module_bytes` |
| `resolver.rs:resolve_script_content()` | fs | ⚠️ Bounded | File reads bounded by `max_script_bytes` |

### Lua Library Helpers (Milestone 3 follow-up)

| Category | Count | Key Files | Current Bounding |
|----------|-------|-----------|-----------------|
| TCP connect | ~85 | `nmap.rs`, `smb.rs`, `vnc.rs`, `brute.rs`, `comm.rs`, `sslcert.rs`, ... | Lua interrupt hook; `connect_timeout` on some |
| UDP bind/send | ~31 | `socket.rs`, `snmp.rs`, `dhcp.rs`, `packet.rs`, ... | Lua interrupt hook only |
| reqwest::blocking | ~12 | `http.rs`, `upnp.rs`, `vulns.rs`, `httpspider.rs`, ... | HTTP client timeout on some |
| native_tls | ~16 | `tls.rs`, `openssl.rs`, `sslcert.rs` | TLS handshake timeout |
| std::process::Command | 6 | `nmap.rs`, `io.rs` | Sandbox-gated; no timeout |
| std::fs (library) | ~20 | `io.rs`, `unpwdb.rs`, `os.rs`, `brute.rs`, `datafiles.rs` | Resource counters; no cancellation |

### Public API Helpers (manual-only, not Lua-bound)

| Category | Count | Files | Notes |
|----------|-------|-------|-------|
| TcpStream::connect | 5 | `public_api/api.rs` | Hardcoded timeouts; manual-only Rust API |
| reqwest::blocking | 3 | `public_api/api.rs` | HTTP client timeout; manual-only |
| UdpSocket | 1 | `public_api/api.rs` | Manual-only |

### Architecture Guard

Do NOT add new direct `std::fs::read_to_string`, `TcpStream::connect`, or `reqwest::blocking` calls outside:
- `resolver.rs` (script/module loading)
- `executor_core.rs` (load_script, setup_require)
- `public_api/api.rs` (manual-only Rust APIs)
- `libraries/` (Lua-bound helpers — require sandbox enforcement + resource counters)

New side-effecting code in `eggsec-nse` must go through `ScriptResolver` for file reads, or be classified in this inventory.

## Known Issues (Pending Fix)

1. ~~**Missing Sandbox Integration Tests**~~ FIXED - 17 integration tests added in `tests/sandbox_tests.rs` covering path restrictions, command allowlists, network filtering, and host resolution.

2. **TOCTOU Vulnerability in lfs Path Traversal**: DOCUMENTED - Module-level doc in `lfs.rs` explains the race window and mitigation (canonicalization). Remaining gap requires local filesystem write access to exploit.

3. **DNS Rebinding Attack Vector**: `is_host_allowed()` DNS resolution could be vulnerable to DNS rebinding if `allowed_networks` changes between check and connect.

4. **LazyLock Initialization Contention**: `WAF_SIGNATURES` LazyLock in the main eggsec crate may have thread contention during first access in multi-threaded context.

5. **Dead Code Files**: `peg_parser.rs` and `pest_bridge.rs` exist in `src/libraries/` but are not declared in `mod.rs` and never compiled. They may be leftover from development or intended for future use.
6. ~~**Direct filesystem reads in NSE execution paths**~~ FIXED - Phase 03: All script/module loading now flows through `ScriptResolver` which enforces policy, path containment, size limits, and module name grammar. Direct `std::fs::read_to_string` in execution paths has been eliminated.
7. ~~**NSE Milestone 1 loader policy**~~ CLOSED - Final corrective pass: `ManualPermissive` script-file loading with empty roots is now an intentional, documented semantic. Read-path authorization (`validate_existing_path_under_roots`) cannot authorize non-existent files. 14 new integration tests in `tests/script_file_policy_tests.rs` cover manual, strict, and automated profile flows. Empty-roots semantic table documented in `architecture/nse_integration.md` and `profile.rs`. Remaining NSE work is Rust-side blocking helper cancellation (Milestone 3).
8. ~~**NSE Milestone 3 profile propagation**~~ CLOSED - Corrective pass fix: `run_cli_with_profile()` uses `NseExecutor::with_profile()` (not `with_policy()`). 7 propagation tests + 5 end-to-end profile/report tests verify profile→context→event→report pipeline. Architecture guards Check 35/36 enforce the fix. 369 tests pass. See `architecture/nse_integration.md#milestone-3-final-verification`.

9. **NSE Milestone 5 is closed** (2026-07-06). 16-command verification matrix passes. 493 eggsec-nse tests, 174 eggsec nse_tests, 352 feature/enforcement matrix tests, 47 architecture guards. Bug fixes: `test_nse_prerule_postrule` (boolean return + `stdnse.register_prerule`), `local_http_get_agent_safe_documentation` (assertion update). Remaining deferred: protocol library wrappers, `stdnse.sleep()` cancellation, reqwest capability bypass. See `architecture/nse_integration.md#milestone-5-final-verification`.

## Dependencies

- `mlua` for Lua VM
- `rb-sys` / `magnus` for Ruby (feature-gated)
- `pyo3` for Python (feature-gated)