//! NSE lfs (LuaFileSystem) library wrapper
//!
//! File system operations for NSE scripts.
//! Based on Nmap's lfs library concepts.
//!
//! M005D: every operation goes through the injected [`NseFilesystemProvider`]
//! via capability-aware brokers. Sandbox allow-list/canonicalization and
//! capability checks apply to the resolved provider path inside the broker;
//! `chdir`/`currentdir` use the per-run virtual CWD (no process-global
//! mutation). Lua shapes are unchanged.
//!
//! # Security Note - TOCTOU Limitation
//! File operations validate the resolved path against the sandbox's
//! `allowed_dir` using canonicalization before the provider operates on the
//! approved path (no second transformation after approval). The residual
//! race documented pre-M005D (symlink swap between canonicalization and the
//! filesystem call inside one brokered step) still requires local write
//! access plus precise timing; `O_NOFOLLOW`-class hardening remains future
//! work and is out of scope for 005D.

use mlua::{Lua, Result as LuaResult};

use crate::capabilities::NseCapabilityContext;
use crate::providers::{
    broker_fs_create_dir_all, broker_fs_exists, broker_fs_hard_link, broker_fs_metadata,
    broker_fs_read_dir, broker_fs_read_link, broker_fs_remove_dir, broker_fs_remove_file,
    broker_fs_rename, broker_fs_set_current_dir, broker_fs_set_unix_mode, broker_fs_symlink,
    broker_fs_symlink_metadata, broker_fs_write, NseHostServices,
};
use crate::SandboxConfig;

use std::sync::atomic::{AtomicUsize, Ordering};

pub static LFS_SANDBOX_VIOLATIONS: AtomicUsize = AtomicUsize::new(0);

pub fn get_lfs_sandbox_metrics() -> usize {
    LFS_SANDBOX_VIOLATIONS.load(Ordering::SeqCst)
}

/// Map a broker error to the legacy Lua error shape, preserving the
/// sandbox-blocked wording and violation observability.
fn lfs_error(path: &str, message: String) -> mlua::Error {
    if message.contains("blocked by sandbox") {
        LFS_SANDBOX_VIOLATIONS.fetch_add(1, Ordering::SeqCst);
        return mlua::Error::RuntimeError(format!("Path '{}' blocked by sandbox", path));
    }
    mlua::Error::RuntimeError(message)
}

pub fn register_lfs_library(
    lua: &Lua,
    _sandbox: &SandboxConfig,
    capability_ctx: &NseCapabilityContext,
) -> LuaResult<()> {
    register_lfs_library_with_services(lua, _sandbox, capability_ctx, &NseHostServices::native())
}

/// Provider-backed lfs registration.
///
/// `services` backs every filesystem path; sandbox policy comes from the
/// capability context's sandbox config.
pub fn register_lfs_library_with_services(
    lua: &Lua,
    _sandbox: &SandboxConfig,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let lfs = lua.create_table()?;

    // lfs.attributes(path) - Get file attributes
    let cap_ctx_for_attributes = capability_ctx.clone();
    let svc_for_attributes = services.clone();
    let attributes_fn = lua.create_function(move |lua, path: String| {
        match broker_fs_metadata(
            &cap_ctx_for_attributes,
            &svc_for_attributes,
            &path,
            "lfs.attributes",
        ) {
            Ok(meta) => {
                let attrs = lua.create_table()?;

                attrs.set("modification", meta.modified_secs.unwrap_or(0) as f64)?;
                attrs.set("access", meta.accessed_secs.unwrap_or(0) as f64)?;
                attrs.set("creation", meta.created_secs.unwrap_or(0) as f64)?;

                attrs.set("size", meta.len)?;
                attrs.set(
                    "permissions",
                    if meta.readonly {
                        "r--r--r--"
                    } else {
                        "rw-rw-rw-"
                    },
                )?;
                attrs.set("readonly", meta.readonly)?;
                attrs.set("is_dir", meta.is_dir)?;
                attrs.set("is_file", meta.is_file)?;
                attrs.set("is_link", meta.is_symlink)?;

                Ok(attrs)
            }
            Err(e) => Err(lfs_error(&path, e)),
        }
    })?;
    lfs.set("attributes", attributes_fn)?;

    // lfs.dir(path) - Iterate over directory entries
    let cap_ctx_for_dir = capability_ctx.clone();
    let svc_for_dir = services.clone();
    let dir_fn = lua.create_function(move |lua, path: String| {
        match broker_fs_read_dir(&cap_ctx_for_dir, &svc_for_dir, &path, "lfs.dir") {
            Ok(entries) => {
                let result = lua.create_table()?;
                for (idx, entry) in entries.iter().enumerate() {
                    result.set(idx + 1, entry.name.clone())?;
                }
                Ok(result)
            }
            Err(e) => Err(lfs_error(&path, e)),
        }
    })?;
    lfs.set("dir", dir_fn)?;

    // lfs.mkdir(path) - Create directory
    let cap_ctx_for_mkdir = capability_ctx.clone();
    let svc_for_mkdir = services.clone();
    let mkdir_fn =
        lua.create_function(move |_lua, path: String| {
            match broker_fs_create_dir_all(&cap_ctx_for_mkdir, &svc_for_mkdir, &path, "lfs.mkdir") {
                Ok(()) => Ok(true),
                Err(e) => Err(lfs_error(&path, e)),
            }
        })?;
    lfs.set("mkdir", mkdir_fn)?;

    // lfs.rmdir(path) - Remove directory
    let cap_ctx_for_rmdir = capability_ctx.clone();
    let svc_for_rmdir = services.clone();
    let rmdir_fn = lua.create_function(move |_lua, path: String| {
        match broker_fs_remove_dir(&cap_ctx_for_rmdir, &svc_for_rmdir, &path, "lfs.rmdir") {
            Ok(()) => Ok(true),
            Err(e) => Err(lfs_error(&path, e)),
        }
    })?;
    lfs.set("rmdir", rmdir_fn)?;

    // lfs.remove(path) - Remove file
    let cap_ctx_for_remove = capability_ctx.clone();
    let svc_for_remove = services.clone();
    let remove_fn = lua.create_function(move |_lua, path: String| {
        match broker_fs_remove_file(&cap_ctx_for_remove, &svc_for_remove, &path, "lfs.remove") {
            Ok(()) => Ok(true),
            Err(e) => Err(lfs_error(&path, e)),
        }
    })?;
    lfs.set("remove", remove_fn)?;

    // lfs.rename(old, new) - Rename file/directory
    let cap_ctx_for_rename = capability_ctx.clone();
    let svc_for_rename = services.clone();
    let rename_fn = lua.create_function(move |_lua, (old_path, new_path): (String, String)| {
        match broker_fs_rename(
            &cap_ctx_for_rename,
            &svc_for_rename,
            &old_path,
            &new_path,
            "lfs.rename",
        ) {
            Ok(()) => Ok(true),
            Err(e) => {
                if e.contains("blocked by sandbox") {
                    LFS_SANDBOX_VIOLATIONS.fetch_add(1, Ordering::SeqCst);
                    return Err(mlua::Error::RuntimeError(
                        "Rename blocked by sandbox".to_string(),
                    ));
                }
                Err(mlua::Error::RuntimeError(e))
            }
        }
    })?;
    lfs.set("rename", rename_fn)?;

    // lfs.link(source, link, symbolic) - Create link
    let cap_ctx_for_link = capability_ctx.clone();
    let svc_for_link = services.clone();
    let link_fn = lua.create_function(
        move |_lua, (source, link, symbolic): (String, String, bool)| {
            let result = if symbolic {
                broker_fs_symlink(&cap_ctx_for_link, &svc_for_link, &source, &link, "lfs.link")
            } else {
                broker_fs_hard_link(&cap_ctx_for_link, &svc_for_link, &source, &link, "lfs.link")
            };
            match result {
                Ok(()) => Ok(true),
                Err(e) => {
                    if e.contains("blocked by sandbox") {
                        LFS_SANDBOX_VIOLATIONS.fetch_add(1, Ordering::SeqCst);
                        return Err(mlua::Error::RuntimeError(
                            "Link creation blocked by sandbox".to_string(),
                        ));
                    }
                    Err(mlua::Error::RuntimeError(e))
                }
            }
        },
    )?;
    lfs.set("link", link_fn)?;

    // lfs.currentdir() - Get the per-run working directory.
    //
    // Direct provider read (no capability gate), preserving the legacy
    // check-free behavior exactly.
    let svc_for_currentdir = services.clone();
    let currentdir_fn =
        lua.create_function(
            move |_lua, _: ()| match svc_for_currentdir.fs().current_dir() {
                Ok(p) => Ok(p.to_string_lossy().to_string()),
                Err(e) => Err(mlua::Error::RuntimeError(format!(
                    "Failed to get current directory: {}",
                    e
                ))),
            },
        )?;
    lfs.set("currentdir", currentdir_fn)?;

    // lfs.chdir(path) - Change the per-run working directory (never the
    // process-global CWD).
    let cap_ctx_for_chdir = capability_ctx.clone();
    let svc_for_chdir = services.clone();
    let chdir_fn =
        lua.create_function(move |_lua, path: String| {
            match broker_fs_set_current_dir(&cap_ctx_for_chdir, &svc_for_chdir, &path, "lfs.chdir")
            {
                Ok(()) => Ok(true),
                Err(e) => Err(lfs_error(&path, e)),
            }
        })?;
    lfs.set("chdir", chdir_fn)?;

    // lfs.touch(path) - Touch file
    let cap_ctx_for_touch = capability_ctx.clone();
    let svc_for_touch = services.clone();
    let touch_fn = lua.create_function(
        move |_lua, (path, _access_time, _modification_time): (String, Option<u64>, Option<u64>)| {
            if broker_fs_exists(&cap_ctx_for_touch, &svc_for_touch, &path, "lfs.touch") {
                return Ok(true);
            }
            match broker_fs_write(&cap_ctx_for_touch, &svc_for_touch, &path, b"", "lfs.touch") {
                Ok(()) => Ok(true),
                Err(e) => Err(lfs_error(&path, e)),
            }
        },
    )?;
    lfs.set("touch", touch_fn)?;

    // lfs.lock(filehandle, mode) - Lock file
    let lock_fn = lua.create_function(|_lua, (_path, _mode): (String, String)| {
        // Simplified lock implementation
        Ok(true)
    })?;
    lfs.set("lock", lock_fn)?;

    // lfs.unlock(filehandle) - Unlock file
    let unlock_fn = lua.create_function(|_lua, _path: String| Ok(true))?;
    lfs.set("unlock", unlock_fn)?;

    // lfs.set_mode(path, mode) - Set file permissions.
    //
    // Unix permission bits are provider-backed on Unix; on other platforms
    // the operation is explicitly unsupported (previously it did not
    // compile there at all).
    let cap_ctx_for_set_mode = capability_ctx.clone();
    let svc_for_set_mode = services.clone();
    let set_mode_fn = lua.create_function(move |_lua, (path, mode): (String, String)| {
        let Ok(perms) = u32::from_str_radix(&mode, 8) else {
            return Err(mlua::Error::RuntimeError("Invalid mode".to_string()));
        };
        match broker_fs_set_unix_mode(
            &cap_ctx_for_set_mode,
            &svc_for_set_mode,
            &path,
            perms,
            "lfs.set_mode",
        ) {
            Ok(()) => Ok(true),
            Err(e) => Err(lfs_error(&path, e)),
        }
    })?;
    lfs.set("set_mode", set_mode_fn)?;

    // lfs.symlinkattributes(path) - Get symlink attributes
    let cap_ctx_for_symlink = capability_ctx.clone();
    let svc_for_symlink = services.clone();
    let symlinkattributes_fn = lua.create_function(move |lua, path: String| {
        let meta = match broker_fs_symlink_metadata(
            &cap_ctx_for_symlink,
            &svc_for_symlink,
            &path,
            "lfs.symlinkattributes",
        ) {
            Ok(meta) => meta,
            Err(e) => return Err(lfs_error(&path, e)),
        };
        let attrs = lua.create_table()?;

        attrs.set("size", meta.len)?;
        attrs.set("readonly", meta.readonly)?;
        attrs.set("is_dir", meta.is_dir)?;
        attrs.set("is_file", meta.is_file)?;
        attrs.set("is_link", meta.is_symlink)?;

        if meta.is_symlink {
            // The target read is brokered separately so it carries its own
            // capability/sandbox approval (same path, same decision).
            match broker_fs_read_link(
                &cap_ctx_for_symlink,
                &svc_for_symlink,
                &path,
                "lfs.symlinkattributes",
            ) {
                Ok(target) => {
                    attrs.set("target", target.to_string_lossy().to_string())?;
                }
                Err(e) => {
                    return Err(mlua::Error::RuntimeError(format!(
                        "Failed to read link target: {}",
                        e
                    )));
                }
            }
        }

        Ok(attrs)
    })?;
    lfs.set("symlinkattributes", symlinkattributes_fn)?;

    // lfs.version() - Get version
    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    lfs.set("version", version_fn)?;

    globals.set("lfs", lfs)?;
    Ok(())
}
