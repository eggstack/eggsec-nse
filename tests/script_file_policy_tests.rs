//! Integration tests for script-file and module-file policy enforcement
//! across `ResolvedNseExecutionProfile` and `ScriptResolver`.
//!
//! These tests exercise the resolver path used by `run_cli_with_profile()`
//! for `--script-file` and `require()` semantics. They complement the
//! profile-pure tests in `profile_tests.rs` and `profile_guard_tests.rs`
//! by exercising real files on disk under each profile.
//!
//! # Milestone 1 final corrective pass
//!
//! Empty `allowed_script_roots` for `ManualPermissive` is intentionally
//! permitted (unrestricted manual file selection). Restricted profiles
//! (`ManualStrict`, `CompatibilityLab`) and automated profiles
//! (`AgentSafe`, `CiSafe`) must enforce the documented table in
//! `NseScriptPolicy` / `NseModulePolicy`.
//!
//! # File-system notes
//!
//! All filesystem cases use temporary directories under
//! `std::env::temp_dir()` with deterministic cleanup. We do not use the
//! `tempfile` crate because it is not declared as a dev-dependency.

#![cfg(feature = "nse")]

use std::fs;
use std::path::{Path, PathBuf};

use eggsec_nse::{NseLoadError, NseScriptSource, ResolvedNseExecutionProfile, ScriptResolver};

/// Create a temp directory under `std::env::temp_dir()` for filesystem tests.
/// Returns `(dir, cleanup_path)` so the test can `let _ = cleanup`.
fn make_tmp(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("eggsec-nse-sfp-{}", label));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Drop helper: best-effort `remove_dir_all` ignoring errors.
fn cleanup(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

/// Write `content` to `<dir>/<filename>` and return the path.
fn write_script(dir: &Path, filename: &str, content: &str) -> PathBuf {
    let path = dir.join(filename);
    fs::write(&path, content).expect("write script");
    path
}

/// Build a `ScriptResolver` from a profile.
fn resolver_for(profile: ResolvedNseExecutionProfile) -> ScriptResolver {
    ScriptResolver::new(profile.script_policy, profile.module_policy, profile.limits)
}

// ---------------------------------------------------------------------------
// ManualPermissive: script files with empty roots are accepted
// ---------------------------------------------------------------------------

#[test]
fn manual_permissive_accepts_real_script_file_with_empty_roots() {
    let dir = make_tmp("manual-accept");
    let path = write_script(&dir, "demo.nse", "-- a demo script\nreturn 1\n");

    let profile = ResolvedNseExecutionProfile::manual_permissive(None);
    assert!(
        profile.script_policy.allow_script_files,
        "ManualPermissive must permit script files"
    );
    assert!(
        profile.script_policy.allowed_script_roots.is_empty(),
        "ManualPermissive intentionally has empty roots (unrestricted manual)"
    );

    let mut resolver = resolver_for(profile);
    let result = resolver.resolve_script(NseScriptSource::File { path: path.clone() });
    assert!(
        result.is_ok(),
        "ManualPermissive must accept a real script file: {:?}",
        result.err()
    );
    let resolved = result.unwrap();
    let on_disk = fs::metadata(&path).unwrap().len() as usize;
    assert_eq!(resolved.size, on_disk);

    cleanup(&dir);
}

#[test]
fn manual_permissive_accepts_lua_extension() {
    let dir = make_tmp("manual-lua");
    let path = write_script(&dir, "demo.lua", "return 42\n");

    let profile = ResolvedNseExecutionProfile::manual_permissive(None);
    let mut resolver = resolver_for(profile);
    let result = resolver.resolve_script(NseScriptSource::File { path });
    assert!(result.is_ok(), "lua extension must be accepted");
    cleanup(&dir);
}

#[test]
fn manual_permissive_rejects_invalid_extension_even_with_empty_roots() {
    let dir = make_tmp("manual-bad-ext");
    let path = write_script(&dir, "demo.txt", "return 1\n");

    let profile = ResolvedNseExecutionProfile::manual_permissive(None);
    let mut resolver = resolver_for(profile);
    let result = resolver.resolve_script(NseScriptSource::File { path: path.clone() });

    assert!(matches!(result, Err(NseLoadError::InvalidExtension { .. })));
    cleanup(&dir);
}

#[test]
fn manual_permissive_enforces_max_script_bytes_when_configured() {
    let dir = make_tmp("manual-size-cap");
    // Build a profile with a small script-size cap.
    let mut profile = ResolvedNseExecutionProfile::manual_permissive(None);
    profile.script_policy.max_script_bytes = Some(8);
    let mut resolver = resolver_for(profile);

    let path = write_script(&dir, "too-big.nse", "this content is too long\n");
    let result = resolver.resolve_script(NseScriptSource::File { path });

    assert!(
        matches!(result, Err(NseLoadError::Oversized { .. })),
        "ManualPermissive with max_script_bytes must reject oversized files"
    );
    cleanup(&dir);
}

#[test]
fn manual_permissive_rejects_nonexistent_file() {
    let profile = ResolvedNseExecutionProfile::manual_permissive(None);
    let mut resolver = resolver_for(profile);

    let path = std::env::temp_dir().join("eggsec-nse-does-not-exist-12345.nse");
    let _ = fs::remove_file(&path);

    let result = resolver.resolve_script(NseScriptSource::File { path });
    assert!(
        matches!(result, Err(NseLoadError::NotFound { .. })),
        "ManualPermissive must reject non-existent files"
    );
}

// ---------------------------------------------------------------------------
// ManualStrict: roots enforced
// ---------------------------------------------------------------------------

#[test]
fn manual_strict_accepts_script_file_under_approved_root() {
    let root = make_tmp("manual-strict-ok");
    let path = write_script(&root, "ok.nse", "return 1\n");

    let mut profile = ResolvedNseExecutionProfile::manual_strict(None, &[]);
    profile.script_policy.allowed_script_roots = vec![root.clone()];
    let mut resolver = resolver_for(profile);

    let result = resolver.resolve_script(NseScriptSource::File { path });
    assert!(
        result.is_ok(),
        "ManualStrict must accept files inside an approved root: {:?}",
        result.err()
    );
    cleanup(&root);
}

#[test]
fn manual_strict_rejects_script_file_outside_approved_root() {
    let root = make_tmp("manual-strict-root");
    let outside = make_tmp("manual-strict-outside");
    let path = write_script(&outside, "evil.nse", "return 1\n");

    let mut profile = ResolvedNseExecutionProfile::manual_strict(None, &[]);
    profile.script_policy.allowed_script_roots = vec![root.clone()];
    let mut resolver = resolver_for(profile);

    let result = resolver.resolve_script(NseScriptSource::File { path });
    assert!(
        matches!(result, Err(NseLoadError::OutsideRoot { .. })),
        "ManualStrict must reject files outside approved root: {:?}",
        result
    );
    cleanup(&root);
    cleanup(&outside);
}

#[test]
fn manual_strict_rejects_symlink_escape_via_file_source() {
    // Build a directory tree: approved root contains a symlink that points
    // to a file outside the root. ManualStrict must reject it via
    // validate_symlink_containment.
    let root = make_tmp("manual-strict-symlink-root");
    let outside = make_tmp("manual-strict-symlink-outside");
    let real = write_script(&outside, "secret.nse", "return 1\n");

    let link = root.join("escape.nse");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real, &link).expect("create symlink");
    #[cfg(not(unix))]
    {
        // Non-unix: skip the symlink portion of this assertion.
        cleanup(&root);
        cleanup(&outside);
        return;
    }

    let mut profile = ResolvedNseExecutionProfile::manual_strict(None, &[]);
    profile.script_policy.allowed_script_roots = vec![root.clone()];
    let mut resolver = resolver_for(profile);

    let result = resolver.resolve_script(NseScriptSource::File { path: link });
    // The resolver rejects the symlink either via canonical root
    // containment (OutsideRoot — canonical path is outside roots) or
    // via validate_symlink_containment (SymlinkEscape). Both are valid
    // rejections; the contract is "ManualStrict must not load it".
    match result {
        Err(NseLoadError::SymlinkEscape { .. }) | Err(NseLoadError::OutsideRoot { .. }) => {}
        other => panic!(
            "ManualStrict must reject symlinks escaping the root, got: {:?}",
            other
        ),
    }
    cleanup(&root);
    cleanup(&outside);
}

// ---------------------------------------------------------------------------
// AgentSafe / CiSafe: script files denied before any filesystem path check
// ---------------------------------------------------------------------------

#[test]
fn agent_safe_rejects_file_source_before_path_authorization() {
    let dir = make_tmp("agent-deny");
    let path = write_script(&dir, "evil.nse", "return 1\n");

    let profile = ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
    assert!(
        !profile.script_policy.allow_script_files,
        "AgentSafe must not permit script files"
    );

    let mut resolver = resolver_for(profile);
    let result = resolver.resolve_script(NseScriptSource::File { path });
    assert!(
        matches!(result, Err(NseLoadError::BlockedByPolicy { .. })),
        "AgentSafe must reject File source: {:?}",
        result
    );
    cleanup(&dir);
}

#[test]
fn ci_safe_rejects_file_source_before_path_authorization() {
    let dir = make_tmp("ci-deny");
    let path = write_script(&dir, "evil.nse", "return 1\n");

    let profile = ResolvedNseExecutionProfile::ci_safe();
    assert!(
        !profile.script_policy.allow_script_files,
        "CiSafe must not permit script files"
    );

    let mut resolver = resolver_for(profile);
    let result = resolver.resolve_script(NseScriptSource::File { path });
    assert!(
        matches!(result, Err(NseLoadError::BlockedByPolicy { .. })),
        "CiSafe must reject File source: {:?}",
        result
    );
    cleanup(&dir);
}

// ---------------------------------------------------------------------------
// Module filesystem semantics under each profile
// ---------------------------------------------------------------------------

#[test]
fn manual_permissive_filesystem_modules_with_empty_roots_return_none() {
    // ManualPermissive permits `allow_filesystem_modules` but does not
    // configure roots by default. resolve_module must return Ok(None)
    // for any name — filesystem modules require explicit roots.
    let profile = ResolvedNseExecutionProfile::manual_permissive(None);
    let mut resolver = resolver_for(profile);

    let result = resolver.resolve_module("stdnse").unwrap();
    assert!(
        result.is_none(),
        "ManualPermissive with empty roots must not load filesystem modules"
    );
}

#[test]
fn manual_strict_filesystem_modules_require_root_match() {
    let root = make_tmp("module-strict-root");
    fs::write(root.join("stdnse.lua"), "-- builtin\nreturn {}").unwrap();

    let mut profile = ResolvedNseExecutionProfile::manual_strict(None, &[]);
    profile.module_policy.allowed_module_roots = vec![root.clone()];
    let mut resolver = resolver_for(profile);

    let result = resolver.resolve_module("stdnse").unwrap();
    assert!(
        result.is_some(),
        "ManualStrict must resolve filesystem modules under an approved root"
    );

    cleanup(&root);
}

#[test]
fn agent_safe_filesystem_modules_disallowed_even_with_roots() {
    let root = make_tmp("module-agent-root");
    fs::write(root.join("stdnse.lua"), "-- builtin\nreturn {}").unwrap();

    let mut profile = ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
    // Force-allow roots to prove that the deny is at allow_filesystem_modules.
    profile.module_policy.allowed_module_roots = vec![root.clone()];
    let mut resolver = resolver_for(profile);

    let result = resolver.resolve_module("stdnse").unwrap();
    assert!(
        result.is_none(),
        "AgentSafe must not load filesystem modules even when roots are configured"
    );
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// CLI/resolver integration: empty-roots manual flow must not be a regression
// ---------------------------------------------------------------------------

/// Smoke test for the same resolver path used by `run_cli_with_profile()`
/// when the user invokes `--script-file` from the CLI. This mirrors what
/// `lib.rs:run_cli_with_profile()` does after step 3 (script file validation).
#[test]
fn run_cli_resolver_path_manual_script_file_succeeds() {
    let dir = make_tmp("cli-manual");
    let path = write_script(&dir, "user-script.nse", "-- user script\nreturn 'ok'\n");

    let profile = ResolvedNseExecutionProfile::manual_permissive(None);
    let mut resolver = resolver_for(profile);

    let source = NseScriptSource::File { path };
    let resolved = resolver.resolve_script(source).expect("resolve");
    assert!(resolved.content.contains("user script"));
    assert!(resolved.size > 0);
    cleanup(&dir);
}
