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

use std::path::Path;
use std::process::{Command, Stdio};

const SCRIPT_PATH: &str = "scripts/check-boundaries.sh";
const MINIMAL_PATH: &str = "/usr/bin:/bin";

fn run_script_with_path<P: AsRef<Path>>(path: P) -> std::process::Output {
    Command::new("bash")
        .arg(SCRIPT_PATH)
        .env("PATH", path.as_ref())
        .stdin(Stdio::null())
        .output()
        .expect("spawn check-boundaries.sh")
}

#[test]
fn script_fails_fast_when_ripgrep_missing() {
    let output = run_script_with_path(MINIMAL_PATH);
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
