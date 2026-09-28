//! Boundary-check tooling contract tests.
//!
//! Validates that `scripts/check-boundaries.sh`:
//!
//! - fails fast with one actionable diagnostic when `rg` is missing instead of
//!   emitting dozens of `rg: command not found` lines and silently passing;
//! - continues to run the full guard suite when `rg` is available.
//!
//! This regression test guards against the M005 landing/CI corrective defect:
//! prior to the fix, every `rg` call was inside an `if` condition so a
//! missing-binary failure returned 0, which masked the missing prerequisite
//! from CI. The standalone CI workflow now installs ripgrep on Linux/macOS
//! jobs and the script enforces its own prerequisite before any guard runs.
//!
//! The missing-tool simulation is hermetic: it uses an empty temporary
//! directory as the child `PATH` rather than a fixed system directory such as
//! `/usr/bin:/bin`. Fixed directories cannot prove tool absence because the
//! package manager may install `rg` into them (apt places `rg` in
//! `/usr/bin` on Ubuntu CI runners). The test proves `rg` is unresolvable in
//! the child environment before asserting the script's fail-fast behavior.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const SCRIPT_PATH: &str = "scripts/check-boundaries.sh";

/// Candidates for a Bash binary that can be executed without consulting the
/// child `PATH`. The child environment intentionally has an empty tool PATH,
/// so the test must not rely on `PATH` lookup to find the shell itself.
const BASH_CANDIDATES: &[&str] = &["/usr/bin/bash", "/bin/bash"];

static HERMETIC_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn bash_binary() -> PathBuf {
    for candidate in BASH_CANDIDATES {
        let path = Path::new(candidate);
        if path.is_file() {
            return path.to_path_buf();
        }
    }
    panic!(
        "no usable absolute bash binary found; tried: {:?}",
        BASH_CANDIDATES
    );
}

fn script_absolute_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(SCRIPT_PATH)
}

/// Create an empty directory known to contain no `rg` binary. The directory
/// name is unique per call so parallel tests cannot share state.
fn empty_path_dir() -> PathBuf {
    let id = HERMETIC_DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("eggsec-nse-no-rg-{}-{}", std::process::id(), id));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).expect("remove stale hermetic PATH dir");
    }
    std::fs::create_dir_all(&dir).expect("create hermetic PATH dir");
    dir
}

/// Return true if any `PATH` entry contains a file named `rg`.
fn path_contains_rg(path_value: &str) -> bool {
    std::env::split_paths(path_value).any(|dir| dir.join("rg").is_file())
}

/// Prove via the child shell itself that `rg` is unresolvable under the
/// controlled `PATH`. This guards against hidden `rg` binaries the directory
/// scan could miss (e.g. shell hashes or aliases cannot leak in because the
/// child is a fresh non-interactive shell with the controlled environment).
fn assert_child_shell_cannot_resolve_rg(bash: &Path, path_value: &str) {
    let probe = Command::new(bash)
        .arg("-c")
        .arg("command -v rg")
        .env("PATH", path_value)
        .stdin(Stdio::null())
        .output()
        .expect("spawn rg-absence probe");
    assert!(
        !probe.status.success(),
        "hermetic PATH unexpectedly resolves rg; PATH={:?}\nstdout:\n{}\nstderr:\n{}",
        path_value,
        String::from_utf8_lossy(&probe.stdout),
        String::from_utf8_lossy(&probe.stderr),
    );
}

fn run_script_with_path(bash: &Path, script: &Path, path_value: &str) -> std::process::Output {
    Command::new(bash)
        .arg(script)
        .env("PATH", path_value)
        .stdin(Stdio::null())
        .output()
        .expect("spawn check-boundaries.sh")
}

#[test]
fn script_fails_fast_when_ripgrep_missing() {
    let bash = bash_binary();
    let script = script_absolute_path();
    let dir = empty_path_dir();
    let path_value = dir
        .to_str()
        .expect("hermetic PATH dir must be valid Unicode")
        .to_owned();

    // Prove the child environment genuinely has no `rg` before asserting the
    // script's failure behavior. This is the invariant the old
    // `/usr/bin:/bin` fixture failed to establish on runners where apt
    // installs ripgrep into `/usr/bin`.
    assert!(
        !path_contains_rg(&path_value),
        "hermetic PATH dir unexpectedly contains rg: {:?}",
        dir,
    );
    assert_child_shell_cannot_resolve_rg(&bash, &path_value);

    let output = run_script_with_path(&bash, &script, &path_value);
    // Best-effort cleanup; test assertions below take precedence over a
    // leftover empty temp dir.
    let _ = std::fs::remove_dir_all(&dir);

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();

    // The script must exit with a distinct status before any guard runs;
    // 127 is the conventional "command not found" exit code so CI surfaces
    // the prerequisite problem at a glance.
    assert_eq!(
        output.status.code(),
        Some(127),
        "expected exit 127 when rg is missing; got {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout,
        stderr,
    );

    // Diagnostic must identify ripgrep by name and appear exactly once,
    // proving the fail-fast path fired before any guard iterated.
    let diagnostic_marker = "required tool 'rg' (ripgrep) is not installed";
    assert!(
        stderr.contains(diagnostic_marker),
        "stderr missing fail-fast diagnostic for ripgrep:\n{}",
        stderr,
    );
    assert_eq!(
        stderr.matches(diagnostic_marker).count(),
        1,
        "fail-fast diagnostic should fire exactly once, not per-guard:\n{}",
        stderr,
    );

    // The script must not silently report success when the prerequisite is
    // missing; ensure the success marker is absent.
    assert!(
        !stdout.contains("standalone boundary and provenance checks passed"),
        "stdout must not contain the success marker when rg is missing:\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr,
    );
}

#[test]
fn script_passes_when_ripgrep_available() {
    // Inherits the parent PATH; the test environment must have `rg` installed
    // for the rest of the M005 boundary guard contract to hold. CI installs
    // it explicitly; this test simply verifies the script still passes when
    // it does.
    let output = Command::new("bash")
        .arg(SCRIPT_PATH)
        .stdin(Stdio::null())
        .output()
        .expect("spawn check-boundaries.sh");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();

    assert!(
        output.status.success(),
        "expected check-boundaries.sh to succeed with rg on PATH; got {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        stdout,
        stderr,
    );
    assert!(
        stdout.contains("standalone boundary and provenance checks passed"),
        "expected success marker in stdout:\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr,
    );
}
