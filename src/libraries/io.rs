//! NSE io library wrapper
//!
//! Provides file I/O operations compatible with NSE.

use mlua::{Lua, Result as LuaResult, Table};
use rustc_hash::FxHashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::SandboxConfig;

struct FileHandle {
    file: File,
    fd: i32,
}

impl Drop for FileHandle {
    fn drop(&mut self) {
        if let Err(e) = self.file.sync_all() {
            tracing::warn!("Failed to sync file on close: {}", e);
        }
    }
}

static FILE_HANDLES: std::sync::LazyLock<Mutex<FxHashMap<i32, FileHandle>>> =
    std::sync::LazyLock::new(|| Mutex::new(FxHashMap::default()));

static NEXT_FD: std::sync::LazyLock<Mutex<i32>> = std::sync::LazyLock::new(|| Mutex::new(100));

pub static IO_SANDBOX_VIOLATIONS: AtomicUsize = AtomicUsize::new(0);

pub fn get_io_sandbox_metrics() -> (usize, usize) {
    let handles = FILE_HANDLES.lock().map(|h| h.len()).unwrap_or(0);
    let violations = IO_SANDBOX_VIOLATIONS.load(Ordering::SeqCst);
    (handles, violations)
}

pub fn register_io_library(lua: &Lua, sandbox: &SandboxConfig) -> LuaResult<()> {
    let globals = lua.globals();
    let io = lua.create_table()?;

    let sandbox_enabled = sandbox.enabled;
    let sandbox_for_open = sandbox.clone();

    io.set(
        "open",
        lua.create_function(move |lua, (filename, mode): (String, Option<String>)| {
            if sandbox_enabled && sandbox_for_open.get_allowed_path(&filename).is_none() {
                IO_SANDBOX_VIOLATIONS.fetch_add(1, Ordering::SeqCst);
                let result = lua.create_table()?;
                result.set("error", format!("Path '{}' blocked by sandbox", filename))?;
                return Ok(result);
            }

            let mode_str = mode.unwrap_or_else(|| "r".to_string());

            let file = match mode_str.as_str() {
                "r" => File::open(&filename),
                "w" => {
                    let path = PathBuf::from(&filename);
                    if let Some(parent) = path.parent() {
                        if let Err(e) = std::fs::create_dir_all(parent) {
                            tracing::warn!("Failed to create parent directory {:?}: {}", parent, e);
                        }
                    }
                    File::create(&filename)
                }
                "a" => OpenOptions::new().append(true).open(&filename),
                "r+" => OpenOptions::new().read(true).write(true).open(&filename),
                "w+" => {
                    let path = PathBuf::from(&filename);
                    if let Some(parent) = path.parent() {
                        if let Err(e) = std::fs::create_dir_all(parent) {
                            tracing::warn!("Failed to create parent directory {:?}: {}", parent, e);
                        }
                    }
                    OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&filename)
                }
                "a+" => OpenOptions::new()
                    .read(true)
                    .append(true)
                    .create(true)
                    .open(&filename),
                _ => File::open(&filename),
            };

            match file {
                Ok(f) => {
                    let fd = {
                        let mut next = NEXT_FD
                            .lock()
                            .map_err(|_| std::io::Error::other("lock error"))?;
                        let fd = *next;
                        *next += 1;
                        fd
                    };

                    let mut handles = FILE_HANDLES
                        .lock()
                        .map_err(|_| std::io::Error::other("lock error"))?;
                    handles.insert(fd, FileHandle { file: f, fd });

                    let result = lua.create_table()?;
                    result.set("fd", fd)?;
                    result.set("filename", filename)?;
                    result.set("mode", mode_str)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        })?,
    )?;

    io.set(
        "close",
        lua.create_function(|_lua, file: Table| {
            if let Ok(fd) = file.get::<i32>("fd") {
                if let Ok(mut handles) = FILE_HANDLES.lock() {
                    handles.remove(&fd);
                }
            }
            Ok(())
        })?,
    )?;

    io.set(
        "read",
        lua.create_function(|_lua, (file, size): (Table, Option<usize>)| {
            let fd: i32 = file.get("fd").unwrap_or_else(|_e| {
                tracing::debug!("File descriptor missing from handle");
                -1
            });
            let size = size.unwrap_or(4096);

            if let Ok(mut handles) = FILE_HANDLES.lock() {
                if let Some(handle) = handles.get_mut(&fd) {
                    let mut buffer = vec![0u8; size];
                    match handle.file.read(&mut buffer) {
                        Ok(n) => {
                            buffer.truncate(n);
                            let content = String::from_utf8_lossy(&buffer).to_string();
                            return Ok(content);
                        }
                        Err(e) => return Ok(format!("Error: {}", e)),
                    }
                }
            }
            Ok(String::new())
        })?,
    )?;

    io.set(
        "write",
        lua.create_function(|_lua, (file, content): (Table, String)| {
            let fd: i32 = file.get("fd").unwrap_or_else(|_e| {
                tracing::debug!("File descriptor missing from handle");
                -1
            });

            if let Ok(mut handles) = FILE_HANDLES.lock() {
                if let Some(handle) = handles.get_mut(&fd) {
                    match handle.file.write_all(content.as_bytes()) {
                        Ok(()) => return Ok(content.len()),
                        Err(_) => return Ok(0),
                    }
                }
            }
            Ok(0)
        })?,
    )?;

    io.set(
        "flush",
        lua.create_function(|_lua, file: Table| {
            let fd: i32 = file.get("fd").unwrap_or_else(|_e| {
                tracing::debug!("File descriptor missing from handle");
                -1
            });

            if let Ok(mut handles) = FILE_HANDLES.lock() {
                if let Some(handle) = handles.get_mut(&fd) {
                    let _ = handle.file.flush();
                }
            }
            Ok(true)
        })?,
    )?;

    io.set(
        "seek",
        lua.create_function(|_lua, (file, offset): (Table, i64)| {
            let fd: i32 = file.get("fd").unwrap_or_else(|_e| {
                tracing::debug!("File descriptor missing from handle");
                -1
            });

            if let Ok(mut handles) = FILE_HANDLES.lock() {
                if let Some(handle) = handles.get_mut(&fd) {
                    use std::io::Seek;
                    if let Ok(pos) = handle.file.seek(std::io::SeekFrom::Start(offset as u64)) {
                        return Ok(pos as i64);
                    }
                }
            }
            Ok(0i64)
        })?,
    )?;

    io.set(
        "type",
        lua.create_function(|_lua, file: Table| {
            let fd: i32 = file.get("fd").unwrap_or_else(|_e| {
                tracing::debug!("File descriptor missing from handle");
                -1
            });
            if let Ok(handles) = FILE_HANDLES.lock() {
                if handles.contains_key(&fd) {
                    return Ok("file".to_string());
                }
            }
            Ok("nil".to_string())
        })?,
    )?;

    let sandbox_for_lines = sandbox.clone();
    io.set(
        "lines",
        lua.create_function(move |lua, filename: String| {
            if sandbox_enabled && sandbox_for_lines.get_allowed_path(&filename).is_none() {
                IO_SANDBOX_VIOLATIONS.fetch_add(1, Ordering::SeqCst);
                let result = lua.create_table()?;
                result.set("error", format!("Path '{}' blocked by sandbox", filename))?;
                return Ok(result);
            }

            let lines = lua.create_table()?;

            if let Ok(content) = std::fs::read_to_string(&filename) {
                for (i, line) in content.lines().enumerate() {
                    lines.set(i + 1, line.to_string())?;
                }
            }

            Ok(lines)
        })?,
    )?;

    let sandbox_for_popen = sandbox.clone();
    io.set(
        "popen",
        lua.create_function(move |lua, (cmd, mode): (String, Option<String>)| {
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

            let mode_str = mode.unwrap_or_else(|| "r".to_string());

            #[cfg(unix)]
            {
                use std::process::{Command, Stdio};

                let read_stdout = mode_str.contains('r');
                let write_stdin = mode_str.contains('w');

                let mut command = Command::new("sh");
                command.arg("-c");
                command.arg(&cmd);

                if read_stdout {
                    command.stdout(Stdio::piped());
                    command.stderr(Stdio::piped());
                } else if write_stdin {
                    command.stdin(Stdio::piped());
                }

                match command.spawn() {
                    Ok(child) => {
                        let result = lua.create_table()?;
                        result.set("pid", child.id())?;
                        result.set("command", cmd)?;
                        result.set("mode", mode_str)?;
                        result.set("running", true)?;
                        result.set("type", "process")?;
                        Ok(result)
                    }
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("error", format!("Failed to execute command: {}", e))?;
                        Ok(result)
                    }
                }
            }

            #[cfg(windows)]
            {
                use std::process::{Command, Stdio};

                let read_stdout = mode_str.contains('r');

                let mut command = Command::new("cmd");
                command.arg("/C");
                command.arg(&cmd);

                if read_stdout {
                    command.stdout(Stdio::piped());
                    command.stderr(Stdio::piped());
                } else {
                    command.stdin(Stdio::piped());
                }

                match command.spawn() {
                    Ok(child) => {
                        let result = lua.create_table()?;
                        result.set("pid", child.id())?;
                        result.set("command", cmd)?;
                        result.set("mode", mode_str)?;
                        result.set("running", true)?;
                        result.set("type", "process")?;
                        Ok(result)
                    }
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("error", format!("Failed to execute command: {}", e))?;
                        Ok(result)
                    }
                }
            }

            #[cfg(not(unix))]
            #[cfg(not(windows))]
            {
                let result = lua.create_table()?;
                result.set("error", "popen not supported on this platform")?;
                Ok(result)
            }
        })?,
    )?;

    let sandbox_for_tmpfile = sandbox.clone();
    io.set(
        "tmpfile",
        lua.create_function(move |lua, _: ()| {
            use std::fs;
            let temp_dir = if sandbox_for_tmpfile.enabled {
                sandbox_for_tmpfile
                    .allowed_dir
                    .clone()
                    .unwrap_or_else(std::env::temp_dir)
            } else {
                std::env::temp_dir()
            };

            let filename = format!("eggsec_tmp_{}.tmp", std::process::id());
            let path = temp_dir.join(&filename);

            if sandbox_for_tmpfile.enabled {
                if let Some(ref allowed) = sandbox_for_tmpfile.allowed_dir {
                    if !path.starts_with(allowed) {
                        let result = lua.create_table()?;
                        result.set("error", "Temp file path blocked by sandbox")?;
                        return Ok(result);
                    }
                }
            }

            match fs::File::create(&path) {
                Ok(_file) => {
                    let result = lua.create_table()?;
                    result.set("filename", path.to_string_lossy().to_string())?;
                    result.set("type", "file")?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", format!("Failed to create temp file: {}", e))?;
                    Ok(result)
                }
            }
        })?,
    )?;

    globals.set("io", io)?;
    Ok(())
}
