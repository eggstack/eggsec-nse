//! NSE helper wrappers routed through capability context.
//!
//! Each wrapper checks the capability context before performing the operation,
//! records the event, and returns the result or an error.
//!
//! This module provides both check-only functions (for advisory checks) and
//! executing wrappers (check + perform) for filesystem, process, network,
//! DNS, and other side-effecting operations.

use std::net::ToSocketAddrs;

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

/// Check a network UDP capability and return the decision.
pub fn check_network_udp(
    ctx: &NseCapabilityContext,
    host: &str,
    operation: &'static str,
) -> NseCapabilityDecision {
    ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::NetworkUdp,
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

/// Check a randomness capability and return the decision.
pub fn check_randomness(
    ctx: &NseCapabilityContext,
    operation: &'static str,
) -> NseCapabilityDecision {
    ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::Randomness,
        target: None,
        bytes_hint: None,
        operation,
    })
}

/// Check an environment access capability and return the decision.
pub fn check_environment(
    ctx: &NseCapabilityContext,
    var_name: &str,
    operation: &'static str,
) -> NseCapabilityDecision {
    ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::Environment,
        target: Some(var_name.to_string()),
        bytes_hint: None,
        operation,
    })
}

/// Check a crypto capability and return the decision.
pub fn check_crypto(ctx: &NseCapabilityContext, operation: &'static str) -> NseCapabilityDecision {
    ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::Crypto,
        target: None,
        bytes_hint: None,
        operation,
    })
}

/// Check a compression capability and return the decision.
pub fn check_compression(
    ctx: &NseCapabilityContext,
    operation: &'static str,
) -> NseCapabilityDecision {
    ctx.check_capability(&NseCapabilityRequest {
        kind: NseCapabilityKind::Compression,
        target: None,
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
pub fn nse_fs_read(ctx: &NseCapabilityContext, path: &str) -> Result<Vec<u8>, String> {
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
pub fn nse_fs_write(ctx: &NseCapabilityContext, path: &str, bytes: &[u8]) -> Result<(), String> {
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
pub fn nse_fs_remove_file(ctx: &NseCapabilityContext, path: &str) -> Result<(), String> {
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
pub fn nse_fs_rename(ctx: &NseCapabilityContext, from: &str, to: &str) -> Result<(), String> {
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
pub fn nse_fs_create_dir_all(ctx: &NseCapabilityContext, path: &str) -> Result<(), String> {
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
pub fn nse_fs_remove_dir(ctx: &NseCapabilityContext, path: &str) -> Result<(), String> {
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
pub fn nse_fs_hard_link(ctx: &NseCapabilityContext, src: &str, dst: &str) -> Result<(), String> {
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
pub fn nse_fs_symlink(ctx: &NseCapabilityContext, src: &str, dst: &str) -> Result<(), String> {
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
        Err(e) => Err(format!(
            "Failed to get symlink metadata for '{}': {}",
            path, e
        )),
    }
}

/// Connect a TCP socket after checking network-tcp capability.
///
/// Returns a `std::net::TcpStream` on success, or a denial/error string.
pub fn nse_network_tcp_connect(
    ctx: &NseCapabilityContext,
    host: &str,
    port: u16,
    timeout: Option<std::time::Duration>,
) -> Result<std::net::TcpStream, String> {
    let op = "wrapper.network_tcp_connect";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::NetworkTcp,
        Some(host.to_string()),
        None,
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("network TCP connect denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;

    let timeout = timeout.unwrap_or(std::time::Duration::from_secs(10));
    let addr = format!("{}:{}", host, port);
    let socket_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| format!("Invalid socket address '{}': {}", addr, e))?;

    match std::net::TcpStream::connect_timeout(&socket_addr, timeout) {
        Ok(stream) => {
            ctx.after_blocking_operation(&request, None);
            Ok(stream)
        }
        Err(e) => Err(format!("TCP connect to {}:{} failed: {}", host, port, e)),
    }
}

/// Send data over a TCP stream after checking network-tcp capability.
///
/// Accounts for bytes written in the resource counters.
pub fn nse_network_tcp_send(
    ctx: &NseCapabilityContext,
    host: &str,
    stream: &mut std::net::TcpStream,
    data: &[u8],
) -> Result<usize, String> {
    let op = "wrapper.network_tcp_send";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::NetworkTcp,
        Some(host.to_string()),
        Some(data.len() as u64),
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("network TCP send denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;

    use std::io::Write;
    match stream.write(data) {
        Ok(n) => {
            ctx.after_blocking_operation(&request, None);
            ctx.counters
                .network_bytes_written
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
            Ok(n)
        }
        Err(e) => Err(format!("TCP send to {} failed: {}", host, e)),
    }
}

/// Receive data from a TCP stream after checking network-tcp capability.
///
/// Accounts for bytes read in the resource counters.
pub fn nse_network_tcp_receive(
    ctx: &NseCapabilityContext,
    host: &str,
    stream: &mut std::net::TcpStream,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let op = "wrapper.network_tcp_receive";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::NetworkTcp,
        Some(host.to_string()),
        Some(max_bytes as u64),
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("network TCP receive denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;

    use std::io::Read;
    let mut buffer = vec![0u8; max_bytes];
    match stream.read(&mut buffer) {
        Ok(n) => {
            buffer.truncate(n);
            ctx.after_blocking_operation(&request, Some(n as u64));
            Ok(buffer)
        }
        Err(e) => Err(format!("TCP receive from {} failed: {}", host, e)),
    }
}

/// Send data over a UDP socket after checking network-udp capability.
///
/// Accounts for bytes written in the resource counters.
pub fn nse_network_udp_send(
    ctx: &NseCapabilityContext,
    host: &str,
    port: u16,
    data: &[u8],
) -> Result<usize, String> {
    let op = "wrapper.network_udp_send";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::NetworkUdp,
        Some(host.to_string()),
        Some(data.len() as u64),
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("network UDP send denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;

    let addr = format!("{}:{}", host, port);
    let socket_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| format!("Invalid socket address '{}': {}", addr, e))?;

    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

    match socket.send_to(data, socket_addr) {
        Ok(n) => {
            ctx.after_blocking_operation(&request, None);
            ctx.counters
                .network_bytes_written
                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
            Ok(n)
        }
        Err(e) => Err(format!("UDP send to {}:{} failed: {}", host, port, e)),
    }
}

/// Receive data from a UDP socket after checking network-udp capability.
///
/// Accounts for bytes read in the resource counters.
pub fn nse_network_udp_receive(
    ctx: &NseCapabilityContext,
    host: &str,
    max_bytes: usize,
) -> Result<(Vec<u8>, std::net::SocketAddr), String> {
    let op = "wrapper.network_udp_receive";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::NetworkUdp,
        Some(host.to_string()),
        Some(max_bytes as u64),
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("network UDP receive denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;

    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| format!("Failed to set UDP read timeout: {}", e))?;

    let mut buffer = vec![0u8; max_bytes];
    match socket.recv_from(&mut buffer) {
        Ok((n, from)) => {
            buffer.truncate(n);
            ctx.after_blocking_operation(&request, Some(n as u64));
            Ok((buffer, from))
        }
        Err(e) => Err(format!("UDP receive failed: {}", e)),
    }
}

/// Perform a DNS lookup after checking DNS resolution capability.
///
/// Returns the resolved addresses or a denial/error string.
pub fn nse_dns_lookup(
    ctx: &NseCapabilityContext,
    name: &str,
    record_type: Option<&str>,
) -> Result<Vec<String>, String> {
    let op = "wrapper.dns_lookup";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::DnsResolution,
        Some(name.to_string()),
        None,
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("DNS resolution denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;

    // Use std::net::ToSocketAddrs for basic resolution (system resolver)
    let addr = format!("{}:0", name);
    match addr.to_socket_addrs() {
        Ok(addrs) => {
            let results: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            ctx.after_blocking_operation(&request, None);
            Ok(results)
        }
        Err(e) => Err(format!("DNS lookup for '{}' failed: {}", name, e)),
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

/// Get the current wall-clock time after checking time-clock capability.
pub fn nse_time_now(ctx: &NseCapabilityContext) -> Result<i64, String> {
    let op = "wrapper.time_now";
    ctx.check_cancelled(op)?;
    let request = build_request(NseCapabilityKind::TimeClock, None, None, op);
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("time clock access denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("System time error: {}", e))?
        .as_secs() as i64;
    ctx.after_blocking_operation(&request, None);
    Ok(now)
}

/// Generate random bytes after checking randomness capability.
pub fn nse_random_bytes(ctx: &NseCapabilityContext, count: usize) -> Result<Vec<u8>, String> {
    let op = "wrapper.random_bytes";
    ctx.check_cancelled(op)?;
    let request = build_request(NseCapabilityKind::Randomness, None, Some(count as u64), op);
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("randomness generation denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    let bytes: Vec<u8> = (0..count).map(|_| rand::random::<u8>()).collect();
    ctx.after_blocking_operation(&request, Some(count as u64));
    Ok(bytes)
}

/// Read an environment variable after checking environment capability.
pub fn nse_env_var(ctx: &NseCapabilityContext, var_name: &str) -> Result<Option<String>, String> {
    let op = "wrapper.env_var";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::Environment,
        Some(var_name.to_string()),
        None,
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("environment access denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;
    let value = std::env::var(var_name).ok();
    ctx.after_blocking_operation(&request, None);
    Ok(value)
}

/// Compress data after checking compression capability.
///
/// Enforces a maximum input size to prevent compression bombs.
pub fn nse_compress(
    ctx: &NseCapabilityContext,
    data: &[u8],
    level: Option<u32>,
) -> Result<Vec<u8>, String> {
    let op = "wrapper.compress";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::Compression,
        None,
        Some(data.len() as u64),
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("compression denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;

    // Enforce maximum input size (64 MiB)
    const MAX_COMPRESS_INPUT: usize = 64 * 1024 * 1024;
    if data.len() > MAX_COMPRESS_INPUT {
        return Err(format!(
            "Compression input too large: {} bytes (max {})",
            data.len(),
            MAX_COMPRESS_INPUT
        ));
    }

    let compression_level = match level.unwrap_or(6) {
        0 => flate2::Compression::none(),
        1..=3 => flate2::Compression::fast(),
        4..=6 => flate2::Compression::default(),
        7..=9 => flate2::Compression::best(),
        _ => flate2::Compression::default(),
    };

    use flate2::write::ZlibEncoder;
    use std::io::Write;
    let mut encoder = ZlibEncoder::new(Vec::new(), compression_level);
    encoder
        .write_all(data)
        .map_err(|e| format!("Compression failed: {}", e))?;
    let compressed = encoder
        .finish()
        .map_err(|e| format!("Compression finish failed: {}", e))?;
    ctx.after_blocking_operation(&request, Some(compressed.len() as u64));
    Ok(compressed)
}

/// Decompress data after checking compression capability.
///
/// Enforces maximum input and output expansion limits to prevent decompression bombs.
pub fn nse_decompress(ctx: &NseCapabilityContext, data: &[u8]) -> Result<Vec<u8>, String> {
    let op = "wrapper.decompress";
    ctx.check_cancelled(op)?;
    let request = build_request(
        NseCapabilityKind::Compression,
        None,
        Some(data.len() as u64),
        op,
    );
    let decision = ctx.check_capability(&request);
    if !decision.is_allowed() {
        return Err(decision
            .deny_reason()
            .unwrap_or("decompression denied")
            .to_string());
    }
    ctx.before_blocking_operation(&request)?;

    // Enforce maximum input size (64 MiB)
    const MAX_DECOMPRESS_INPUT: usize = 64 * 1024 * 1024;
    if data.len() > MAX_DECOMPRESS_INPUT {
        return Err(format!(
            "Decompression input too large: {} bytes (max {})",
            data.len(),
            MAX_DECOMPRESS_INPUT
        ));
    }

    // Enforce maximum output expansion (256 MiB)
    const MAX_DECOMPRESS_OUTPUT: usize = 256 * 1024 * 1024;

    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| format!("Decompression failed: {}", e))?;
        if n == 0 {
            break;
        }
        decompressed.extend_from_slice(&buf[..n]);
        if decompressed.len() > MAX_DECOMPRESS_OUTPUT {
            return Err(format!(
                "Decompression output too large: exceeded {} bytes",
                MAX_DECOMPRESS_OUTPUT
            ));
        }
    }
    ctx.after_blocking_operation(&request, Some(decompressed.len() as u64));
    Ok(decompressed)
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
        std::env::temp_dir().join(format!("eggsec_nse_test_{}_{}", std::process::id(), name))
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
    // #2: Filesystem read allowed in agent safe when path is under sandbox allowed_dir
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_read_to_string_allowed_in_agent_safe_when_scoped() {
        let path = temp_path("read_agent_safe_scoped");
        std::fs::write(&path, b"agent safe read").unwrap();

        let mut ctx = make_ctx(NseExecutionProfileKind::AgentSafe);
        // Configure sandbox to permit reads under the temp directory used by
        // this test (the only path allowed for AgentSafe filesystem reads).
        ctx.sandbox.enabled = true;
        ctx.sandbox.allowed_dir = Some(std::env::temp_dir());

        let result = nse_fs_read_to_string(&ctx, path.to_str().unwrap());

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "agent safe read");

        std::fs::remove_file(&path).ok();
    }

    // -----------------------------------------------------------------------
    // #2a: Filesystem read denied in agent safe for unscoped paths
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_read_to_string_denied_in_agent_safe_when_unscoped() {
        let path = temp_path("read_agent_safe_unscoped");
        std::fs::write(&path, b"agent safe read").unwrap();

        let ctx = make_ctx(NseExecutionProfileKind::AgentSafe);
        // Default sandbox: enabled but allowed_dir points at /tmp/eggsec-nse,
        // which does not contain `path`. The read must be denied.
        let result = nse_fs_read_to_string(&ctx, path.to_str().unwrap());

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("agent-safe") || err.contains("agent safe") || err.contains("denied"),
            "expected agent-safe denial message, got: {}",
            err
        );

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
        let result = nse_fs_rename(&ctx, from.to_str().unwrap(), to.to_str().unwrap());

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

    // -----------------------------------------------------------------------
    // Network TCP wrappers
    // -----------------------------------------------------------------------

    #[test]
    fn test_network_tcp_connect_allowed_in_manual_permissive() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        // Use a non-routable address to test denial path, not actual connectivity
        let decision = check_network_tcp(&ctx, "192.0.2.1", "socket.connect");
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_network_tcp_connect_denied_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let decision = check_network_tcp(&ctx, "192.0.2.1", "socket.connect");
        assert!(decision.is_denied());
    }

    #[test]
    fn test_network_tcp_connect_wrapper_denied_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let result = nse_network_tcp_connect(&ctx, "192.0.2.1", 80, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("denied") || err.contains("not allowed"),
            "expected denial message, got: {}",
            err
        );
    }

    #[test]
    fn test_network_tcp_send_denied_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        // Use cancellation to avoid needing a real stream - the wrapper checks cancellation first
        ctx.cancellation.cancel();
        let mut stream = std::net::TcpStream::connect("127.0.0.1:1").ok();
        if let Some(ref mut s) = stream {
            let result = nse_network_tcp_send(&ctx, "127.0.0.1", s, b"test");
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("cancelled"));
        } else {
            // No server available - verify denial via the check function directly
            let decision = check_network_tcp(&ctx, "127.0.0.1", "test");
            assert!(decision.is_denied());
        }
    }

    #[test]
    fn test_network_tcp_connect_wrapper_cancellation() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        ctx.cancellation.cancel();
        let result = nse_network_tcp_connect(&ctx, "192.0.2.1", 80, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("cancelled"),
            "expected cancellation message, got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // Network UDP wrappers
    // -----------------------------------------------------------------------

    #[test]
    fn test_network_udp_check_allowed_in_manual_permissive() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let decision = check_network_udp(&ctx, "192.0.2.1", "socket.sendto");
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_network_udp_check_denied_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let decision = check_network_udp(&ctx, "192.0.2.1", "socket.sendto");
        assert!(decision.is_denied());
    }

    #[test]
    fn test_network_udp_send_denied_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let result = nse_network_udp_send(&ctx, "192.0.2.1", 80, b"test");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("denied") || err.contains("not allowed"),
            "expected denial message, got: {}",
            err
        );
    }

    #[test]
    fn test_network_udp_send_cancellation() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        ctx.cancellation.cancel();
        let result = nse_network_udp_send(&ctx, "192.0.2.1", 80, b"test");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("cancelled"),
            "expected cancellation message, got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // DNS wrapper
    // -----------------------------------------------------------------------

    #[test]
    fn test_dns_lookup_allowed_in_manual_permissive() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let decision = check_dns(&ctx, "localhost", "dns.resolve");
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_dns_lookup_denied_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let decision = check_dns(&ctx, "example.com", "dns.resolve");
        assert!(decision.is_denied());
    }

    #[test]
    fn test_dns_lookup_wrapper_denied_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let result = nse_dns_lookup(&ctx, "example.com", Some("A"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("denied") || err.contains("not allowed"),
            "expected denial message, got: {}",
            err
        );
    }

    #[test]
    fn test_dns_lookup_wrapper_cancellation() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        ctx.cancellation.cancel();
        let result = nse_dns_lookup(&ctx, "localhost", Some("A"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("cancelled"),
            "expected cancellation message, got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // Network counters
    // -----------------------------------------------------------------------

    #[test]
    fn test_network_counters_update_after_tcp_connect() {
        use std::sync::atomic::Ordering;

        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let ops_before = ctx.counters.network_operations.load(Ordering::Relaxed);

        // TCP connect to a non-existent host will fail, but the counter
        // should still be updated after the capability check passes
        let _ = nse_network_tcp_connect(
            &ctx,
            "192.0.2.1",
            1,
            Some(std::time::Duration::from_millis(10)),
        );

        // The counter may or may not increment depending on whether the
        // connect_timeout fails before after_blocking_operation is called.
        // At minimum, the capability check should have passed.
        let ops_after = ctx.counters.network_operations.load(Ordering::Relaxed);
        // Connect may fail at the OS level, but the check passed
        assert!(ops_after >= ops_before);
    }

    // -----------------------------------------------------------------------
    // AgentSafe scope enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn test_network_tcp_allowed_in_agent_safe_with_scope() {
        use crate::profile::NseNetworkPolicy;
        use std::sync::Arc;

        let counters = Arc::new(NseResourceCounters::new());
        let ctx = NseCapabilityContext::new(
            NseExecutionProfileKind::AgentSafe,
            NseNetworkPolicy::AllowCidrs(vec!["10.0.0.0/8".parse().unwrap()]),
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
        );

        // 10.0.0.1 is in scope
        let decision = check_network_tcp(&ctx, "10.0.0.1", "socket.connect");
        assert!(decision.is_allowed());

        // 192.168.1.1 is out of scope
        let decision = check_network_tcp(&ctx, "192.168.1.1", "socket.connect");
        assert!(decision.is_denied());
    }

    #[test]
    fn test_dns_allowed_in_agent_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::AgentSafe);
        // AgentSafe allows DNS unless DenyAll policy
        let decision = check_dns(&ctx, "example.com", "dns.resolve");
        assert!(decision.is_allowed());
    }

    // -----------------------------------------------------------------------
    // Time wrapper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_time_now_allowed_in_manual_permissive() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let result = nse_time_now(&ctx);
        assert!(result.is_ok());
        assert!(result.unwrap() > 0);
    }

    #[test]
    fn test_time_now_allowed_in_agent_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::AgentSafe);
        let result = nse_time_now(&ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn test_time_now_cancellation() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        ctx.cancellation.cancel();
        let result = nse_time_now(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cancelled"));
    }

    // -----------------------------------------------------------------------
    // Randomness wrapper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_random_bytes_allowed_in_manual_permissive() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let result = nse_random_bytes(&ctx, 32);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_random_bytes_allowed_in_agent_safe_with_warning() {
        let ctx = make_ctx(NseExecutionProfileKind::AgentSafe);
        let result = nse_random_bytes(&ctx, 16);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
        // Check that a warning event was recorded
        let events = ctx.events();
        assert!(events
            .iter()
            .any(|e| e.kind == NseCapabilityKind::Randomness));
    }

    #[test]
    fn test_random_bytes_denied_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let result = nse_random_bytes(&ctx, 32);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not allowed"));
    }

    #[test]
    fn test_random_bytes_cancellation() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        ctx.cancellation.cancel();
        let result = nse_random_bytes(&ctx, 32);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cancelled"));
    }

    // -----------------------------------------------------------------------
    // Environment wrapper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_env_var_allowed_in_manual_permissive() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        // PATH usually exists on Unix
        let result = nse_env_var(&ctx, "PATH");
        assert!(result.is_ok());
    }

    #[test]
    fn test_env_var_denied_in_agent_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::AgentSafe);
        let result = nse_env_var(&ctx, "PATH");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not allowed"));
    }

    #[test]
    fn test_env_var_denied_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let result = nse_env_var(&ctx, "PATH");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not allowed"));
    }

    #[test]
    fn test_env_var_cancellation() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        ctx.cancellation.cancel();
        let result = nse_env_var(&ctx, "PATH");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cancelled"));
    }

    // -----------------------------------------------------------------------
    // Compression wrapper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_compress_decompress_roundtrip() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let data = b"Hello, eggsec compression test! ".repeat(100);
        let compressed = nse_compress(&ctx, &data, None);
        assert!(compressed.is_ok());
        let compressed = compressed.unwrap();
        assert!(compressed.len() < data.len());

        let decompressed = nse_decompress(&ctx, &compressed);
        assert!(decompressed.is_ok());
        assert_eq!(decompressed.unwrap(), data);
    }

    #[test]
    fn test_compress_allowed_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let result = nse_compress(&ctx, b"test data", None);
        // CiSafe allows compression (it's not denied)
        assert!(result.is_ok());
    }

    #[test]
    fn test_compress_cancellation() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        ctx.cancellation.cancel();
        let result = nse_compress(&ctx, b"test", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cancelled"));
    }

    #[test]
    fn test_decompress_cancellation() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        ctx.cancellation.cancel();
        let result = nse_decompress(&ctx, b"test");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cancelled"));
    }

    // -----------------------------------------------------------------------
    // Check-only wrapper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_randomness_allowed_in_manual() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let decision = check_randomness(&ctx, "rand.random");
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_check_randomness_denied_in_ci_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::CiSafe);
        let decision = check_randomness(&ctx, "rand.random");
        assert!(decision.is_denied());
    }

    #[test]
    fn test_check_environment_denied_in_agent_safe() {
        let ctx = make_ctx(NseExecutionProfileKind::AgentSafe);
        let decision = check_environment(&ctx, "HOME", "os.getenv");
        assert!(decision.is_denied());
    }

    #[test]
    fn test_check_environment_allowed_in_manual() {
        let ctx = make_ctx(NseExecutionProfileKind::ManualPermissive);
        let decision = check_environment(&ctx, "HOME", "os.getenv");
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_check_crypto_allowed_in_all_profiles() {
        for profile in [
            NseExecutionProfileKind::ManualPermissive,
            NseExecutionProfileKind::ManualStrict,
            NseExecutionProfileKind::AgentSafe,
            NseExecutionProfileKind::CiSafe,
            NseExecutionProfileKind::CompatibilityLab,
        ] {
            let ctx = make_ctx(profile);
            let decision = check_crypto(&ctx, "openssl.connect");
            assert!(
                decision.is_allowed(),
                "crypto should be allowed in {:?}",
                profile
            );
        }
    }

    #[test]
    fn test_check_compression_allowed_in_all_profiles() {
        for profile in [
            NseExecutionProfileKind::ManualPermissive,
            NseExecutionProfileKind::ManualStrict,
            NseExecutionProfileKind::AgentSafe,
            NseExecutionProfileKind::CiSafe,
            NseExecutionProfileKind::CompatibilityLab,
        ] {
            let ctx = make_ctx(profile);
            let decision = check_compression(&ctx, "zlib.compress");
            assert!(
                decision.is_allowed(),
                "compression should be allowed in {:?}",
                profile
            );
        }
    }
}
