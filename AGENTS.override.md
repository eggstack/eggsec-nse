# NSE Module AGENTS Override

## Module Overview

The NSE (Nmap Scripting Engine) module (`crates/eggsec-nse/`) provides Lua VM integration, NSE libraries, sandbox enforcement, and CVE integration.

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
- **Profile-Aware Execution**: `run_cli_with_profile(config, Option<ResolvedNseExecutionProfile>)` in `lib.rs` is the profile-aware entry point. Falls back to `manual_permissive` when `None`. Validates script file policy, creates executor via `NseExecutor::with_policy()`, includes profile metadata in JSON output.

## Known Issues (Pending Fix)

1. ~~**Missing Sandbox Integration Tests**~~ FIXED - 17 integration tests added in `tests/sandbox_tests.rs` covering path restrictions, command allowlists, network filtering, and host resolution.

2. **TOCTOU Vulnerability in lfs Path Traversal**: DOCUMENTED - Module-level doc in `lfs.rs` explains the race window and mitigation (canonicalization). Remaining gap requires local filesystem write access to exploit.

3. **DNS Rebinding Attack Vector**: `is_host_allowed()` DNS resolution could be vulnerable to DNS rebinding if `allowed_networks` changes between check and connect.

4. **LazyLock Initialization Contention**: `WAF_SIGNATURES` LazyLock in the main eggsec crate may have thread contention during first access in multi-threaded context.

5. **Dead Code Files**: `peg_parser.rs` and `pest_bridge.rs` exist in `src/libraries/` but are not declared in `mod.rs` and never compiled. They may be leftover from development or intended for future use.

## Dependencies

- `mlua` for Lua VM
- `rb-sys` / `magnus` for Ruby (feature-gated)
- `pyo3` for Python (feature-gated)