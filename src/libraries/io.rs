//! NSE io library wrapper
//!
//! Provides file I/O operations compatible with NSE.
//!
//! M005D: file operations go through the injected [`NseFilesystemProvider`]
//! via capability-aware brokers; `io.popen` spawns through the injected
//! [`NseProcessProvider`]. Open handles live in a per-registration
//! [`IoHandleRegistry`] (per run) instead of the former process-global map,
//! and relative paths resolve against the per-run virtual CWD. Lua shapes
//! are unchanged.

use mlua::{Lua, Result as LuaResult, Table};
use rustc_hash::FxHashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::capabilities::NseCapabilityContext;
use crate::providers::{
    broker_fs_create_dir_all, broker_fs_open, broker_fs_read_to_string, broker_fs_resolve,
    broker_process_spawn, broker_random_u32, shell_command, NseFileHandle, NseHostServices,
    NseOpenMode,
};
use crate::SandboxConfig;

/// Live open-handle count across registrations (metrics only; handle state
/// itself is per-registry and never shared between runs).
static LIVE_IO_HANDLES: AtomicUsize = AtomicUsize::new(0);

/// Per-run open-file registry.
///
/// Created once per library registration (one Lua state per run), so file
/// descriptors never leak across runs and concurrent runs hold independent
/// handle tables. Spawned `popen` children are tracked here and terminated
/// when the registry drops, so no detached child outlives its run.
pub struct IoHandleRegistry {
    next_fd: Mutex<i32>,
    handles: Mutex<FxHashMap<i32, Box<dyn NseFileHandle>>>,
    children: Mutex<Vec<Box<dyn crate::providers::NseChildProcess>>>,
}

impl IoHandleRegistry {
    /// Build an empty registry (first fd is 100, preserving legacy numbering).
    pub fn new() -> Self {
        Self {
            next_fd: Mutex::new(100),
            handles: Mutex::new(FxHashMap::default()),
            children: Mutex::new(Vec::new()),
        }
    }

    /// Number of currently open handles.
    pub fn len(&self) -> usize {
        self.handles.lock().map(|h| h.len()).unwrap_or(0)
    }

    fn alloc(&self, handle: Box<dyn NseFileHandle>) -> Result<i32, String> {
        let mut next = self
            .next_fd
            .lock()
            .map_err(|_| "handle registry lock failed".to_string())?;
        let fd = *next;
        *next += 1;
        self.handles
            .lock()
            .map_err(|_| "handle registry lock failed".to_string())?
            .insert(fd, handle);
        LIVE_IO_HANDLES.fetch_add(1, Ordering::SeqCst);
        Ok(fd)
    }

    fn with<R>(&self, fd: i32, f: impl FnOnce(&mut Box<dyn NseFileHandle>) -> R) -> Option<R> {
        self.handles
            .lock()
            .ok()
            .and_then(|mut handles| handles.get_mut(&fd).map(f))
    }

    /// Close and forget one handle; returns true when it existed.
    pub fn remove(&self, fd: i32) -> bool {
        let removed = self
            .handles
            .lock()
            .map(|mut handles| handles.remove(&fd))
            .ok()
            .flatten();
        if let Some(mut handle) = removed {
            handle.close();
            LIVE_IO_HANDLES.fetch_sub(1, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    /// Track a spawned child for run-end termination.
    pub fn track_child(&self, child: Box<dyn crate::providers::NseChildProcess>) {
        if let Ok(mut children) = self.children.lock() {
            children.push(child);
        }
    }
}

impl Default for IoHandleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for IoHandleRegistry {
    fn drop(&mut self) {
        // Close open files (sync-on-close preserved in the native handle)
        // and terminate tracked children so nothing outlives the run.
        if let Ok(mut handles) = self.handles.lock() {
            let n = handles.len();
            for (_, mut handle) in handles.drain() {
                handle.close();
            }
            LIVE_IO_HANDLES.fetch_sub(n, Ordering::SeqCst);
        }
    }
}

/// Clear per-run library globals so back-to-back scans do not
/// leak state between runs.
///
/// M005D: open-handle state is per-registration (see [`IoHandleRegistry`])
/// and needs no clearing; this function is retained for API compatibility.
pub fn reset_for_run() {
    // No process-global handle state remains to clear.
}

pub static IO_SANDBOX_VIOLATIONS: AtomicUsize = AtomicUsize::new(0);

pub fn get_io_sandbox_metrics() -> (usize, usize) {
    let handles = LIVE_IO_HANDLES.load(Ordering::SeqCst);
    let violations = IO_SANDBOX_VIOLATIONS.load(Ordering::SeqCst);
    (handles, violations)
}

/// True for broker errors that reflect policy/sandbox denial (as opposed
/// to provider I/O failures); used to preserve violation observability.
fn is_policy_error(message: &str) -> bool {
    message.contains("denied")
        || message.contains("not allowed")
        || message.contains("blocked")
        || message.contains("sandbox")
        || message.contains("cancelled")
}

pub fn register_io_library(
    lua: &Lua,
    sandbox: &SandboxConfig,
    capability_ctx: &NseCapabilityContext,
) -> LuaResult<()> {
    register_io_library_with_services(lua, sandbox, capability_ctx, &NseHostServices::native())
}

/// Provider-backed io registration.
///
/// `services` backs every file/process path; handles live in a
/// per-registration [`IoHandleRegistry`].
pub fn register_io_library_with_services(
    lua: &Lua,
    sandbox: &SandboxConfig,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let io = lua.create_table()?;
    let registry = Arc::new(IoHandleRegistry::new());

    let sandbox_enabled = sandbox.enabled;
    let sandbox_for_open = sandbox.clone();
    let cap_ctx_for_open = capability_ctx.clone();
    let svc_for_open = services.clone();
    let reg_for_open = registry.clone();

    io.set(
        "open",
        lua.create_function(move |lua, (filename, mode): (String, Option<String>)| {
            let mode_str = mode.unwrap_or_else(|| "r".to_string());
            let open_mode = NseOpenMode::parse(&mode_str);

            // For write modes, create missing parents first (legacy
            // behavior), now capability-gated like any other write.
            if matches!(open_mode, NseOpenMode::Write | NseOpenMode::WriteRead) {
                if let Ok(resolved) = broker_fs_resolve(&svc_for_open, &filename, "io.open") {
                    if let Some(parent) = resolved.parent() {
                        if !parent.as_os_str().is_empty() {
                            let parent_str = parent.to_string_lossy().to_string();
                            if let Err(e) = broker_fs_create_dir_all(
                                &cap_ctx_for_open,
                                &svc_for_open,
                                &parent_str,
                                "io.open",
                            ) {
                                // Missing parents are best-effort (legacy
                                // warned and continued); hard failures
                                // surface from the open itself.
                                tracing::warn!(
                                    "Failed to create parent directory {}: {}",
                                    parent_str,
                                    e
                                );
                            }
                        }
                    }
                }
            }

            match broker_fs_open(
                &cap_ctx_for_open,
                &svc_for_open,
                &filename,
                open_mode,
                "io.open",
            ) {
                Ok(handle) => match reg_for_open.alloc(handle) {
                    Ok(fd) => {
                        let result = lua.create_table()?;
                        result.set("fd", fd)?;
                        result.set("filename", filename)?;
                        result.set("mode", mode_str)?;
                        Ok(result)
                    }
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("error", e)?;
                        Ok(result)
                    }
                },
                Err(e) => {
                    if is_policy_error(&e) {
                        IO_SANDBOX_VIOLATIONS.fetch_add(1, Ordering::SeqCst);
                    }
                    // Preserve the legacy sandbox error wording for blocked
                    // paths so script-visible behavior is unchanged.
                    if sandbox_enabled && sandbox_for_open.get_allowed_path(&filename).is_none() {
                        let result = lua.create_table()?;
                        result.set("error", format!("Path '{}' blocked by sandbox", filename))?;
                        return Ok(result);
                    }
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    Ok(result)
                }
            }
        })?,
    )?;

    let reg_for_close = registry.clone();
    io.set(
        "close",
        lua.create_function(move |_lua, file: Table| {
            if let Ok(fd) = file.get::<i32>("fd") {
                reg_for_close.remove(fd);
            }
            Ok(())
        })?,
    )?;

    let cap_ctx_for_io = capability_ctx.clone();
    let reg_for_rw = registry.clone();
    io.set(
        "read",
        lua.create_function(move |_lua, (file, size): (Table, Option<usize>)| {
            let fd: i32 = file.get("fd").unwrap_or_else(|_e| {
                tracing::debug!("File descriptor missing from handle");
                -1
            });
            let size = size.unwrap_or(4096);

            match reg_for_rw.with(fd, |handle| {
                if cap_ctx_for_io.check_cancelled("io.read").is_err() {
                    return Err("cancelled".to_string());
                }
                let request = crate::capabilities::NseCapabilityRequest {
                    kind: crate::capabilities::NseCapabilityKind::FilesystemRead,
                    target: None,
                    bytes_hint: Some(size as u64),
                    operation: "io.read",
                };
                if let Err(e) = cap_ctx_for_io.before_blocking_operation(&request) {
                    return Err(e);
                }
                let data = handle.read(size).map_err(|e| format!("Error: {e}"))?;
                let n = data.len();
                cap_ctx_for_io.after_blocking_operation(&request, Some(n as u64));
                Ok(String::from_utf8_lossy(&data).to_string())
            }) {
                Some(Ok(content)) => Ok(content),
                Some(Err(e)) => Ok(e),
                None => Ok(String::new()),
            }
        })?,
    )?;

    let cap_ctx_for_write = capability_ctx.clone();
    let reg_for_write = registry.clone();
    io.set(
        "write",
        lua.create_function(move |_lua, (file, content): (Table, String)| {
            let fd: i32 = file.get("fd").unwrap_or_else(|_e| {
                tracing::debug!("File descriptor missing from handle");
                -1
            });

            match reg_for_write.with(fd, |handle| {
                if cap_ctx_for_write.check_cancelled("io.write").is_err() {
                    return 0;
                }
                let request = crate::capabilities::NseCapabilityRequest {
                    kind: crate::capabilities::NseCapabilityKind::FilesystemWrite,
                    target: None,
                    bytes_hint: Some(content.len() as u64),
                    operation: "io.write",
                };
                if cap_ctx_for_write
                    .before_blocking_operation(&request)
                    .is_err()
                {
                    return 0;
                }
                let n = handle.write(content.as_bytes()).unwrap_or(0);
                cap_ctx_for_write.after_blocking_operation(&request, Some(n as u64));
                n
            }) {
                Some(n) => Ok(n),
                None => Ok(0),
            }
        })?,
    )?;

    let reg_for_flush = registry.clone();
    io.set(
        "flush",
        lua.create_function(move |_lua, file: Table| {
            let fd: i32 = file.get("fd").unwrap_or_else(|_e| {
                tracing::debug!("File descriptor missing from handle");
                -1
            });

            if let Some(()) = reg_for_flush.with(fd, |handle| {
                if handle.flush().is_err() {
                    tracing::warn!("Failed to flush file handle {}", fd);
                }
            }) {
                // Handle existed (flush attempted).
            }
            Ok(true)
        })?,
    )?;

    let reg_for_seek = registry.clone();
    io.set(
        "seek",
        lua.create_function(move |_lua, (file, offset): (Table, i64)| {
            let fd: i32 = file.get("fd").unwrap_or_else(|_e| {
                tracing::debug!("File descriptor missing from handle");
                -1
            });

            match reg_for_seek.with(fd, |handle| {
                handle.seek_from_start(offset.max(0) as u64).unwrap_or(0) as i64
            }) {
                Some(pos) => Ok(pos),
                None => Ok(0i64),
            }
        })?,
    )?;

    let reg_for_type = registry.clone();
    io.set(
        "type",
        lua.create_function(move |_lua, file: Table| {
            let fd: i32 = file.get("fd").unwrap_or_else(|_e| {
                tracing::debug!("File descriptor missing from handle");
                -1
            });
            match reg_for_type.with(fd, |handle| handle.is_open()) {
                Some(true) => Ok("file".to_string()),
                _ => Ok("nil".to_string()),
            }
        })?,
    )?;

    let sandbox_for_lines = sandbox.clone();
    let cap_ctx_for_lines = capability_ctx.clone();
    let svc_for_lines = services.clone();
    io.set(
        "lines",
        lua.create_function(move |lua, filename: String| {
            match broker_fs_read_to_string(
                &cap_ctx_for_lines,
                &svc_for_lines,
                &filename,
                "io.lines",
            ) {
                Ok(content) => {
                    let lines = lua.create_table()?;
                    for (i, line) in content.lines().enumerate() {
                        lines.set(i + 1, line.to_string())?;
                    }
                    Ok(lines)
                }
                Err(e) => {
                    if is_policy_error(&e) {
                        IO_SANDBOX_VIOLATIONS.fetch_add(1, Ordering::SeqCst);
                    }
                    if sandbox_enabled && sandbox_for_lines.get_allowed_path(&filename).is_none() {
                        let result = lua.create_table()?;
                        result.set("error", format!("Path '{}' blocked by sandbox", filename))?;
                        return Ok(result);
                    }
                    // Legacy swallowed I/O failures into an empty table.
                    Ok(lua.create_table()?)
                }
            }
        })?,
    )?;

    let sandbox_for_popen = sandbox.clone();
    let cap_ctx_for_popen = capability_ctx.clone();
    let svc_for_popen = services.clone();
    let reg_for_popen = registry.clone();
    io.set(
        "popen",
        lua.create_function(move |lua, (cmd, mode): (String, Option<String>)| {
            // Sandbox command check first (legacy order preserved).
            if sandbox_for_popen.enabled && !sandbox_for_popen.is_command_allowed(&cmd) {
                if sandbox_for_popen.log_violations {
                    tracing::warn!(
                        command = %cmd,
                        "Sandbox: blocked io.popen call"
                    );
                }
                let result = lua.create_table()?;
                result.set("error", "io.popen blocked by sandbox")?;
                return Ok(result);
            }

            // Platform shell selection lives in the native provider layer.
            let mode_str = mode.unwrap_or_else(|| "r".to_string());
            let spec = shell_command(&cmd);

            match broker_process_spawn(&cap_ctx_for_popen, &svc_for_popen, &spec, "io.popen") {
                Ok(child) => {
                    let pid = child.id().unwrap_or(0);
                    reg_for_popen.track_child(child);
                    let result = lua.create_table()?;
                    result.set("pid", pid)?;
                    result.set("command", cmd)?;
                    result.set("mode", mode_str)?;
                    result.set("running", true)?;
                    result.set("type", "process")?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", format!("Failed to execute command: {e}"))?;
                    Ok(result)
                }
            }
        })?,
    )?;

    let sandbox_for_tmpfile = sandbox.clone();
    let cap_ctx_for_tmpfile = capability_ctx.clone();
    let svc_for_tmpfile = services.clone();
    io.set(
        "tmpfile",
        lua.create_function(move |lua, _: ()| {
            // Temp dir selection preserves the legacy ungated behavior
            // (sandbox allowed_dir wins when enabled, else the environment
            // provider); only the file creation itself is capability-gated.
            let temp_dir = if sandbox_for_tmpfile.enabled {
                sandbox_for_tmpfile.allowed_dir.clone().unwrap_or_else(|| {
                    svc_for_tmpfile
                        .environment()
                        .temp_dir()
                        .unwrap_or_else(|_| std::env::temp_dir())
                })
            } else {
                svc_for_tmpfile
                    .environment()
                    .temp_dir()
                    .unwrap_or_else(|_| std::env::temp_dir())
            };

            // Unique name: process id plus a provider random suffix (legacy
            // used the pid alone, which collided across runs).
            let nonce = broker_random_u32(&cap_ctx_for_tmpfile, &svc_for_tmpfile, "io.tmpfile")
                .unwrap_or(0);
            let filename = format!("eggsec_tmp_{}_{}.tmp", std::process::id(), nonce);
            let path = temp_dir.join(&filename);
            let path_str = path.to_string_lossy().to_string();

            if sandbox_for_tmpfile.enabled {
                if let Some(ref allowed) = sandbox_for_tmpfile.allowed_dir {
                    if !path.starts_with(allowed) {
                        let result = lua.create_table()?;
                        result.set("error", "Temp file path blocked by sandbox")?;
                        return Ok(result);
                    }
                }
            }

            // Check write capability for temp file creation.
            let write_decision =
                crate::wrappers::check_fs_write(&cap_ctx_for_tmpfile, &path_str, "io.tmpfile");
            if write_decision.is_denied() {
                let result = lua.create_table()?;
                result.set(
                    "error",
                    write_decision.deny_reason().unwrap_or("write denied"),
                )?;
                return Ok(result);
            }

            match svc_for_tmpfile
                .fs()
                .open(&path, crate::providers::NseOpenMode::Write)
            {
                Ok(mut handle) => {
                    handle.close();
                    let result = lua.create_table()?;
                    result.set("filename", path.to_string_lossy().to_string())?;
                    result.set("type", "file")?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", format!("Failed to create temp file: {e}"))?;
                    Ok(result)
                }
            }
        })?,
    )?;

    globals.set("io", io)?;
    Ok(())
}
