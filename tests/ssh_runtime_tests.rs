//! Executes the ssh2-backed Lua runtime path against a disposable loopback server.

use eggsec_nse::{NseExecutionProfileKind, NseExecutor, ResolvedNseExecutionProfile};
use std::time::Duration;

#[test]
fn authenticates_against_local_disposable_ssh_server() {
    let Ok(port) = std::env::var("NSE_SSH_TEST_PORT") else {
        eprintln!("skipping: NSE_SSH_TEST_PORT is not set (CI provisions loopback sshd)");
        return;
    };
    let port: u16 = port.parse().expect("valid SSH test port");
    let profile = ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"));
    assert_eq!(profile.kind, NseExecutionProfileKind::ManualPermissive);
    let executor = NseExecutor::with_profile(&profile).expect("construct executor");
    let script = format!(
        r#"
local result = ssh.login("127.0.0.1", {port}, "nse-ci", "nse-ci-temporary-password")
assert(result.success == true, "SSH2 runtime authentication failed: " .. tostring(result.error))
return "authenticated:" .. result.user
"#
    );

    let started = std::time::Instant::now();
    let output = executor
        .run_script(&script)
        .expect("execute SSH login script");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "SSH test exceeded bound"
    );
    assert!(
        output.contains("authenticated:nse-ci"),
        "unexpected Lua output: {output}"
    );
}
