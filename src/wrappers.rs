//! NSE helper wrappers routed through capability context.
//!
//! Each wrapper checks the capability context before performing the operation,
//! records the event, and returns the result or an error.
//!
//! This module provides both check-only functions (for advisory checks) and
//! executing wrappers (check + perform) for filesystem, process, and other
//! side-effecting operations.

use crate::capabilities::{
    NseCapabilityContext, NseCapabilityDecision, NseCapabilityKind, NseCapabilityRequest,
};

/// Check a time/clock capability and return the decision.
///
/// Callers should check `decision.is_allowed()` before proceeding.
/// If denied, return the denial reason to Lua as an error.
pub fn check_time_clock(
    ctx: &NseCapabilityContext,
    operation: &'static str,
) -> NseCapabilityDecision {
    ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::TimeClock,
        target: None,
        bytes_hint: None,
        operation,
    })
}

/// Check a filesystem read capability and return the decision.
pub fn check_fs_read(
    ctx: &NseCapabilityContext,
    path: &str,
    operation: &'static str,
) -> NseCapabilityDecision {
    ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::FilesystemRead,
        target: Some(path.to_string()),
        bytes_hint: None,
        operation,
    })
}

/// Check a filesystem write capability and return the decision.
pub fn check_fs_write(
    ctx: &NseCapabilityContext,
    path: &str,
    operation: &'static str,
) -> NseCapabilityDecision {
    ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::FilesystemWrite,
        target: Some(path.to_string()),
        bytes_hint: None,
        operation,
    })
}

/// Check a network TCP capability and return the decision.
pub fn check_network_tcp(
    ctx: &NseCapabilityContext,
    host: &str,
    operation: &'static str,
) -> NseCapabilityDecision {
    ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::NetworkTcp,
        target: Some(host.to_string()),
        bytes_hint: None,
        operation,
    })
}

/// Check a process execution capability and return the decision.
pub fn check_process_exec(
    ctx: &NseCapabilityContext,
    command: &str,
    operation: &'static str,
) -> NseCapabilityDecision {
    ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::ProcessExec,
        target: Some(command.to_string()),
        bytes_hint: None,
        operation,
    })
}

/// Check a DNS resolution capability and return the decision.
pub fn check_dns(
    ctx: &NseCapabilityContext,
    hostname: &str,
    operation: &'static str,
) -> NseCapabilityDecision {
    ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::DnsResolution,
        target: Some(hostname.to_string()),
        bytes_hint: None,
        operation,
    })
}

// ---------------------------------------------------------------------------
// Executing wrappers: check capability, perform operation, record event.
// ---------------------------------------------------------------------------

fn build_request(
    kind: NseCapabilityKind,
    target: Option<String>,
    bytes_hint: Option<u64>,
    operation: &'static str,
) -> NseCapabilityRequest {
    NseCapabilityRequest {
        kind,
        target,
        bytes_hint,
        operation,
    }
}

/// Read a file to string after checking filesystem-read capability.
pub fn nse_fs_read_to_string(
    ctx: &NseCapabilityContext,
    path: &str,
) -> Result<std::string::String, String> {
    let op = "wrapper.fs_read_to_string";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::FilesystemRead,
        Some(path.to_string()),
        None,
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("filesystem read denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    match std::fs::read_to_string(path) {
        Ok(content) => {
            ctx.after_blocking_operation(&request, Some(content.len() as u64));
            Ok(content)
        }
        Err(e) => Err(format!("Failed to read '{}': {}", path, e)),
    }
}

/// Read a file to bytes after checking filesystem-read capability.
pub fn nse_fs_read(
    ctx: &NseCapabilityContext,
    path: &str,
) -> Result<Vec<u8>, String> {
    let op = "wrapper.fs_read";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::FilesystemRead,
        Some(path.to_string()),
        None,
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("filesystem read denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    match std::fs::read(path) {
        Ok(bytes) => {
            ctx.after_blocking_operation(&request, Some(bytes.len() as u64));
            Ok(bytes)
        }
        Err(e) => Err(format!("Failed to read '{}': {}", path, e)),
    }
}

/// Write bytes to a file after checking filesystem-write capability.
pub fn nse_fs_write(
    ctx: &NseCapabilityContext,
    path: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let op = "wrapper.fs_write";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::FilesystemWrite,
        Some(path.to_string()),
        Some(bytes.len() as u64),
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("filesystem write denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    match std::fs::write(path, bytes) {
        Ok(()) => {
            ctx.after_blocking_operation(&request, Some(bytes.len() as u64));
            Ok(())
        }
        Err(e) => Err(format!("Failed to write '{}': {}", path, e)),
    }
}

/// Get file metadata after checking filesystem-read capability.
pub fn nse_fs_metadata(
    ctx: &NseCapabilityContext,
    path: &str,
) -> Result<std::fs::Metadata, String> {
    let op = "wrapper.fs_metadata";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::FilesystemRead,
        Some(path.to_string()),
        None,
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("filesystem read denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    match std::fs::metadata(path) {
        Ok(meta) => {
            ctx.after_blocking_operation(&request, None);
            Ok(meta)
        }
        Err(e) => Err(format!("Failed to stat '{}': {}", path, e)),
    }
}

/// Read directory entries after checking filesystem-read capability.
pub fn nse_fs_read_dir(
    ctx: &NseCapabilityContext,
    path: &str,
) -> Result<Vec<std::fs::DirEntry>, String> {
    let op = "wrapper.fs_read_dir";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::FilesystemRead,
        Some(path.to_string()),
        None,
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("filesystem read denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    match std::fs::read_dir(path) {
        Ok(entries) => {
            let collected: Vec<std::fs::DirEntry> = entries.filter_map(|e| e.ok()).collect();
            ctx.after_blocking_operation(&request, None);
            Ok(collected)
        }
        Err(e) => Err(format!("Failed to read dir '{}': {}", path, e)),
    }
}

/// Remove a file after checking filesystem-write capability.
pub fn nse_fs_remove_file(
    ctx: &NseCapabilityContext,
    path: &str,
) -> Result<(), String> {
    let op = "wrapper.fs_remove_file";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::FilesystemWrite,
        Some(path.to_string()),
        None,
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("filesystem write denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    match std::fs::remove_file(path) {
        Ok(()) => {
            ctx.after_blocking_operation(&request, None);
            Ok(())
        }
        Err(e) => Err(format!("Failed to remove '{}': {}", path, e)),
    }
}

/// Rename a file/directory after checking filesystem-write capability.
pub fn nse_fs_rename(
    ctx: &NseCapabilityContext,
    from: &str,
    to: &str,
) -> Result<(), String> {
    let op = "wrapper.fs_rename";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::FilesystemWrite,
        Some(from.to_string()),
        None,
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("filesystem write denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    match std::fs::rename(from, to) {
        Ok(()) => {
            ctx.after_blocking_operation(&request, None);
            Ok(())
        }
        Err(e) => Err(format!("Failed to rename '{}' -> '{}': {}", from, to, e)),
    }
}

/// Create directories recursively after checking filesystem-write capability.
pub fn nse_fs_create_dir_all(
    ctx: &NseCapabilityContext,
    path: &str,
) -> Result<(), String> {
    let op = "wrapper.fs_create_dir_all";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::FilesystemWrite,
        Some(path.to_string()),
        None,
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("filesystem write denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    match std::fs::create_dir_all(path) {
        Ok(()) => {
            ctx.after_blocking_operation(&request, None);
            Ok(())
        }
        Err(e) => Err(format!("Failed to create dir '{}': {}", path, e)),
    }
}

/// Remove a directory after checking filesystem-write capability.
pub fn nse_fs_remove_dir(
    ctx: &NseCapabilityContext,
    path: &str,
) -> Result<(), String> {
    let op = "wrapper.fs_remove_dir";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::FilesystemWrite,
        Some(path.to_string()),
        None,
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("filesystem write denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    match std::fs::remove_dir(path) {
        Ok(()) => {
            ctx.after_blocking_operation(&request, None);
            Ok(())
        }
        Err(e) => Err(format!("Failed to remove dir '{}': {}", path, e)),
    }
}

/// Create a hard link after checking filesystem-write capability.
pub fn nse_fs_hard_link(
    ctx: &NseCapabilityContext,
    src: &str,
    dst: &str,
) -> Result<(), String> {
    let op = "wrapper.fs_hard_link";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::FilesystemWrite,
        Some(src.to_string()),
        None,
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("filesystem write denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    match std::fs::hard_link(src, dst) {
        Ok(()) => {
            ctx.after_blocking_operation(&request, None);
            Ok(())
        }
        Err(e) => Err(format!("Failed to hard link '{}' -> '{}': {}", src, dst, e)),
    }
}

/// Create a symbolic link after checking filesystem-write capability.
pub fn nse_fs_symlink(
    ctx: &NseCapabilityContext,
    src: &str,
    dst: &str,
) -> Result<(), String> {
    let op = "wrapper.fs_symlink";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::FilesystemWrite,
        Some(src.to_string()),
        None,
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("filesystem write denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    #[cfg(unix)]
    {
        match std::os::unix::fs::symlink(src, dst) {
            Ok(()) => {
                ctx.after_blocking_operation(&request, None);
                Ok(())
            }
            Err(e) => Err(format!("Failed to symlink '{}' -> '{}': {}", src, dst, e)),
        }
    }
    #[cfg(not(unix))]
    {
        match std::os::windows::fs::symlink_file(src, dst) {
            Ok(()) => {
                ctx.after_blocking_operation(&request, None);
                Ok(())
            }
            Err(e) => Err(format!("Failed to symlink '{}' -> '{}': {}", src, dst, e)),
        }
    }
}

/// Read a symlink target after checking filesystem-read capability.
pub fn nse_fs_read_link(
    ctx: &NseCapabilityContext,
    path: &str,
) -> Result<std::path::PathBuf, String> {
    let op = "wrapper.fs_read_link";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::FilesystemRead,
        Some(path.to_string()),
        None,
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("filesystem read denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    match std::fs::read_link(path) {
        Ok(target) => {
            ctx.after_blocking_operation(&request, None);
            Ok(target)
        }
        Err(e) => Err(format!("Failed to read link '{}': {}", path, e)),
    }
}

/// Set file permissions after checking filesystem-write capability.
pub fn nse_fs_set_permissions(
    ctx: &NseCapabilityContext,
    path: &str,
    mode: u32,
) -> Result<(), String> {
    let op = "wrapper.fs_set_permissions";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::FilesystemWrite,
        Some(path.to_string()),
        None,
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("filesystem write denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    use std::os::unix::fs::PermissionsExt;
    let permissions = std::fs::Permissions::from_mode(mode);
    match std::fs::set_permissions(path, permissions) {
        Ok(()) => {
            ctx.after_blocking_operation(&request, None);
            Ok(())
        }
        Err(e) => Err(format!("Failed to set permissions on '{}': {}", path, e)),
    }
}

/// Get symlink metadata (does not follow symlinks) after checking filesystem-read capability.
pub fn nse_fs_symlink_metadata(
    ctx: &NseCapabilityContext,
    path: &str,
) -> Result<std::fs::Metadata, String> {
    let op = "wrapper.fs_symlink_metadata";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::FilesystemRead,
        Some(path.to_string()),
        None,
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("filesystem read denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            ctx.after_blocking_operation(&request, None);
            Ok(meta)
        }
        Err(e) => Err(format!("Failed to get symlink metadata for '{}': {}", path, e)),
    }
}

/// Execute a process after checking process-exec capability.
pub fn nse_process_exec(
    ctx: &NseCapabilityContext,
    command: &str,
    args: &[String],
) -> Result<std::process::Output, String> {
    let op = "wrapper.process_exec";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::ProcessExec,
        Some(command.to_string()),
        None,
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("process execution denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    match std::process::Command::new(command).args(args).output() {
        Ok(output) => {
            let bytes = (output.stdout.len() + output.stderr.len()) as u64;
            ctx.after_blocking_operation(&request, Some(bytes));
            Ok(output)
        }
        Err(e) => Err(format!("Failed to execute '{}': {}", command, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{NseCancellationToken, NseResourceCounters};
    use crate::profile::{
        NseExecutionProfileKind, NseModulePolicy, NseNetworkPolicy, NseScriptPolicy,
    };
    use crate::SandboxConfig;
    use std::sync::Arc;

    fn make_ctx(profile: NseExecutionProfileKind) -> NseCapabilityContext {
        let counters = Arc::new(NseResourceCounters::new());
        NseCapabilityContext::new(
            profile,
            NseNetworkPolicy::AllowAllManual,
            NseScriptPolicy {
                allow_builtin_scripts: true,
                allow_script_files: true,
                allowed_script_roots: Vec::new(),
                allow_conventional_nmap_paths: true,
                max_script_bytes: None,
            },
            NseModulePolicy {
                allow_builtin_modules: true,
                allow_filesystem_modules: true,
                allowed_module_roots: Vec::new(),
                max_module_bytes: None,
            },
            SandboxConfig::default(),
            crate::limits::NseExecutionLimits::default(),
            NseCancellationToken::new(),
            counters,
        )
    }

    #[test]
    fn test_time_clock_allowed_in_all_profiles() {
        for profile in [
            NseExecutionProfileKind::ManualPermissive,
            NseExecutionProfileKind::ManualStrict,
            NseExecutionProfileKind::AgentSafe,
            NseExecutionProfileKind::CiSafe,
            NseExecutionProfileKind::CompatibilityLab,
        ] {
            let ctx = make_ctx(profile);
            let decision = check_time_clock(&ctx, "os.clock");
            assert!(
                decision.is_allowed(),
                "time clock should be allowed in {:?}",
                profile
            );
        }
    }

    #[test]
    fn test_process_exec_denied_in_agent_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::AgentSafe);
        let decision = check_process_exec(&ctx, "id -u", "nmap.is_admin");
        assert!(decision.is_denied());
    }

    #[test]
    fn test_process_exec_denied_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let decision = check_process_exec(&ctx, "id -u", "nmap.is_admin");
        assert!(decision.is_denied());
    }

    #[test]
    fn test_process_exec_allowed_with_warning_in_manual() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let decision = check_process_exec(&ctx, "id -u", "nmap.is_admin");
        assert!(decision.is_allowed());
        assert!(decision.warning().is_some());
    }

    #[test]
    fn test_network_tcp_denied_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let decision = check_network_tcp(&ctx, "192.168.1.1", "socket.connect");
        assert!(decision.is_denied());
    }

    #[test]
    fn test_fs_read_allowed_in_manual() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let decision = check_fs_read(&ctx, "/tmp/test.txt", "io.read");
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_fs_write_denied_in_agent_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::AgentSafe);
        let decision = check_fs_write(&ctx, "/tmp/test.txt", "io.write");
        assert!(decision.is_denied());
    }

    #[test]
    fn test_dns_denied_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let decision = check_dns(&ctx, "example.com", "dns.resolve");
        assert!(decision.is_denied());
    }

    // -----------------------------------------------------------------------
    // Helper for unique temp paths
    // -----------------------------------------------------------------------

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "eggsec_nse_test_{}_{}",
            std::process::id(),
            name
        ))
    }

    fn temp_dir_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "eggsec_nse_test_dir_{}_{}",
            std::process::id(),
            name
        ))
    }

    // -----------------------------------------------------------------------
    // #1: Filesystem read allowed in manual permissive
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_read_to_string_allowed_in_manual_permissive() {
        let path = temp_path("read_to_string_ok");
        std::fs::write(&path, b"hello eggsec").unwrap();

        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let result = nse_fs_read_to_string(&ctx, path.to_str().unwrap());

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello eggsec");

        std::fs::remove_file(&path).ok();
    }

    // -----------------------------------------------------------------------
    // #2: Filesystem read allowed in agent safe (reads are permitted)
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_read_to_string_allowed_in_agent_safe() {
        let path = temp_path("read_agent_safe");
        std::fs::write(&path, b"agent safe read").unwrap();

        let ctx = make_ctx(NseExecutionProfileKind::AgentSafe);
        let result = nse_fs_read_to_string(&ctx, path.to_str().unwrap());

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "agent safe read");

        std::fs::remove_file(&path).ok();
    }

    // -----------------------------------------------------------------------
    // #3: Filesystem write allowed in manual permissive
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_write_allowed_in_manual_permissive() {
        let path = temp_path("write_ok");

        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let result = nse_fs_write(&ctx, path.to_str().unwrap(), b"written by test");

        assert!(result.is_ok());
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "written by test");

        std::fs::remove_file(&path).ok();
    }

    // -----------------------------------------------------------------------
    // #4: Filesystem write denied in agent safe
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_write_wrapper_denied_in_agent_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::AgentSafe);
        let result = nse_fs_write(&ctx, "/tmp/eggsec_nse_write_denied.txt", b"nope");

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("not allowed") || err.contains("denied"),
            "expected denial message, got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // #5: Filesystem write denied in CI safe
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_write_denied_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let result = nse_fs_write(&ctx, "/tmp/eggsec_nse_write_ci_denied.txt", b"nope");

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("not allowed") || err.contains("denied"),
            "expected denial message, got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // #6: Filesystem metadata on an existing file
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_metadata_on_existing_file() {
        let path = temp_path("metadata_ok");
        std::fs::write(&path, b"meta content").unwrap();

        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let result = nse_fs_metadata(&ctx, path.to_str().unwrap());

        assert!(result.is_ok());
        let meta = result.unwrap();
        assert!(meta.is_file());
        assert!(!meta.is_dir());

        std::fs::remove_file(&path).ok();
    }

    // -----------------------------------------------------------------------
    // #7: Filesystem read_dir on a temp directory
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_read_dir_on_temp_dir() {
        let dir = temp_dir_path("readdir");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"a").unwrap();
        std::fs::write(dir.join("b.txt"), b"b").unwrap();

        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let result = nse_fs_read_dir(&ctx, dir.to_str().unwrap());

        assert!(result.is_ok());
        let entries = result.unwrap();
        assert_eq!(entries.len(), 2);

        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // #8: Filesystem remove_file in manual permissive
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_remove_file_in_manual_permissive() {
        let path = temp_path("remove_ok");
        std::fs::write(&path, b"delete me").unwrap();
        assert!(path.exists());

        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let result = nse_fs_remove_file(&ctx, path.to_str().unwrap());

        assert!(result.is_ok());
        assert!(!path.exists());
    }

    // -----------------------------------------------------------------------
    // #9: Filesystem remove_file denied in agent safe
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_remove_file_denied_in_agent_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::AgentSafe);
        let result = nse_fs_remove_file(&ctx, "/tmp/eggsec_nse_remove_denied.txt");

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("not allowed") || err.contains("denied"),
            "expected denial message, got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // #10: Filesystem rename in manual permissive
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_rename_in_manual_permissive() {
        let from = temp_path("rename_src");
        let to = temp_path("rename_dst");
        std::fs::write(&from, b"rename me").unwrap();

        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let result = nse_fs_rename(
            &ctx,
            from.to_str().unwrap(),
            to.to_str().unwrap(),
        );

        assert!(result.is_ok());
        assert!(!from.exists());
        assert!(to.exists());
        assert_eq!(std::fs::read_to_string(&to).unwrap(), "rename me");

        std::fs::remove_file(&to).ok();
    }

    // -----------------------------------------------------------------------
    // #11: Filesystem create_dir_all in manual permissive
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_create_dir_all_in_manual_permissive() {
        let dir = temp_dir_path("create_dir/nested/deep");

        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let result = nse_fs_create_dir_all(&ctx, dir.to_str().unwrap());

        assert!(result.is_ok());
        assert!(dir.exists());
        assert!(dir.is_dir());

        std::fs::remove_dir_all(temp_dir_path("create_dir")).ok();
    }

    // -----------------------------------------------------------------------
    // #12: Process exec allowed with warning in manual
    // -----------------------------------------------------------------------

    #[test]
    fn test_process_exec_allowed_with_warning_in_manual_permissive() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let result = nse_process_exec(&ctx, "echo", &[String::from("hello")]);

        assert!(result.is_ok());
        let output = result.unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("hello"));
    }

    // -----------------------------------------------------------------------
    // #13: Process exec denied in agent safe
    // -----------------------------------------------------------------------

    #[test]
    fn test_process_exec_denied_in_agent_safe_wrapper() {
        let ctx = make_ctx(NseExecutionProfileKind::AgentSafe);
        let result = nse_process_exec(&ctx, "echo", &[String::from("nope")]);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("not allowed") || err.contains("denied"),
            "expected denial message, got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // #14: Process exec denied in CI safe
    // -----------------------------------------------------------------------

    #[test]
    fn test_process_exec_denied_in_ci_safe_wrapper() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let result = nse_process_exec(&ctx, "echo", &[String::from("nope")]);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("not allowed") || err.contains("denied"),
            "expected denial message, got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // #15: Cancellation prevents fs operations
    // -----------------------------------------------------------------------

    #[test]
    fn test_cancellation_prevents_fs_read() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        ctx.cancellation.cancel();

        let result = nse_fs_read_to_string(&ctx, "/tmp/anything.txt");

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("cancelled") || err.contains("cancelled"),
            "expected cancellation message, got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // #16: Cancellation prevents process exec
    // -----------------------------------------------------------------------

    #[test]
    fn test_cancellation_prevents_process_exec() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        ctx.cancellation.cancel();

        let result = nse_process_exec(&ctx, "echo", &[String::from("nope")]);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("cancelled") || err.contains("cancelled"),
            "expected cancellation message, got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // #17: Filesystem bytes counter updates after reads
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_counters_update_after_read() {
        use std::sync::atomic::Ordering;

        let path = temp_path("counters_read");
        let payload = b"counter test payload";
        std::fs::write(&path, payload).unwrap();

        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);

        let ops_before = ctx.counters.filesystem_operations.load(Ordering::Relaxed);
        let bytes_before = ctx.counters.filesystem_bytes_read.load(Ordering::Relaxed);

        let result = nse_fs_read_to_string(&ctx, path.to_str().unwrap());
        assert!(result.is_ok());

        let ops_after = ctx.counters.filesystem_operations.load(Ordering::Relaxed);
        let bytes_after = ctx.counters.filesystem_bytes_read.load(Ordering::Relaxed);

        assert_eq!(ops_after, ops_before + 1);
        assert_eq!(bytes_after, bytes_before + payload.len() as u64);

        std::fs::remove_file(&path).ok();
    }
}
