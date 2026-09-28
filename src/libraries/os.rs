//! NSE os library wrapper
//!
//! Provides OS operations compatible with NSE.

use mlua::{Lua, Result as LuaResult, Table};
use rustc_hash::FxHashMap;
use std::cell::RefCell;
use std::env;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::capabilities::NseCapabilityContext;
use crate::SandboxConfig;

thread_local! {
    static NSE_ENV: RefCell<FxHashMap<String, String>> = RefCell::new(FxHashMap::default());
}

static EXIT_CODE: AtomicI32 = AtomicI32::new(0);

pub static OS_SANDBOX_VIOLATIONS: AtomicUsize = AtomicUsize::new(0);

pub fn get_os_sandbox_metrics() -> usize {
    OS_SANDBOX_VIOLATIONS.load(Ordering::SeqCst)
}

pub fn get_exit_code() -> i32 {
    EXIT_CODE.load(Ordering::SeqCst)
}

pub fn reset_exit_code() {
    EXIT_CODE.store(0, Ordering::SeqCst);
}

fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn timestamp_to_tm(timestamp: i64) -> (i32, i32, i32, i32, i32, i32, i32) {
    let mut secs = timestamp;
    let mut days = secs / 86400;
    secs %= 86400;

    let hour = secs / 3600;
    secs %= 3600;
    let min = secs / 60;
    secs %= 60;

    let mut year = 1970;
    loop {
        let days_in_year: i64 = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let mut month = 1;
    loop {
        let days_in_month: i64 = days_in_month_of(year, month);
        if days < days_in_month {
            break;
        }
        days -= days_in_month;
        month += 1;
    }

    let day = (days + 1) as i32;

    let wday = ((timestamp / 86400 + 4) % 7) as i32;

    (year, month, day, hour as i32, min as i32, secs as i32, wday)
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month_of(year: i32, month: i32) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}

pub fn register_os_library(
    lua: &Lua,
    sandbox: &SandboxConfig,
    capability_ctx: &NseCapabilityContext,
) -> LuaResult<()> {
    register_os_library_with_services(
        lua,
        sandbox,
        capability_ctx,
        &crate::providers::NseHostServices::native(),
    )
}

/// Provider-backed OS registration.
///
/// `getenv` real-environment reads go through
/// [`crate::providers::broker_env_var`] (capability-gated, denial returns
/// `""` fail-closed without touching the provider). `NSE_ENV` setenv state
/// is preserved as an override. Clock/date/time reads go through the broker
/// clock; `tmpdir` uses the environment provider directly to preserve the
/// infallible string contract.
pub fn register_os_library_with_services(
    lua: &Lua,
    sandbox: &SandboxConfig,
    capability_ctx: &NseCapabilityContext,
    services: &crate::providers::NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let nse_os = lua.create_table()?;

    let sandbox_enabled = sandbox.enabled;

    let cap_ctx = capability_ctx.clone();
    let svc = services.clone();
    let getenv_fn = lua.create_function(move |_lua, name: String| {
        // NSE_ENV override first (setenv state, never a host read).
        if let Some(local) = NSE_ENV.with(|e| e.borrow().get(&name).cloned()) {
            return Ok(local);
        }
        if sandbox_enabled {
            return Ok(String::new());
        }
        match crate::providers::broker_env_var(&cap_ctx, &svc, &name, "os.getenv") {
            Ok(value) => Ok(value.unwrap_or_default()),
            Err(_) => Ok(String::new()),
        }
    })?;
    nse_os.set("getenv", getenv_fn)?;

    let sandbox_for_setenv = sandbox.clone();
    let setenv_fn = lua.create_function(move |_lua, (name, value): (String, String)| {
        if sandbox_for_setenv.enabled {
            OS_SANDBOX_VIOLATIONS.fetch_add(1, Ordering::SeqCst);
            if sandbox_for_setenv.log_violations {
                tracing::warn!(var = %name, "Sandbox: blocked os.setenv call");
            }
            return Ok(false);
        }
        NSE_ENV.with(|e| {
            e.borrow_mut().insert(name, value);
        });
        Ok(true)
    })?;
    nse_os.set("setenv", setenv_fn)?;

    let sandbox_for_unsetenv = sandbox.clone();
    let unsetenv_fn = lua.create_function(move |_lua, name: String| {
        if sandbox_for_unsetenv.enabled {
            OS_SANDBOX_VIOLATIONS.fetch_add(1, Ordering::SeqCst);
            if sandbox_for_unsetenv.log_violations {
                tracing::warn!(var = %name, "Sandbox: blocked os.unsetenv call");
            }
            return Ok(false);
        }
        NSE_ENV.with(|e| {
            e.borrow_mut().remove(&name);
        });
        Ok(true)
    })?;
    nse_os.set("unsetenv", unsetenv_fn)?;

    let execute_fn = lua.create_function(|lua, cmd: Option<String>| {
        let result = lua.create_table()?;
        if cmd.is_some() {
            result.set("status", 1)?;
            result.set("code", 1)?;
            result.set("signal", 0)?;
        } else {
            result.set("status", true)?;
        }
        Ok(result)
    })?;
    nse_os.set("execute", execute_fn)?;

    let sandbox_for_remove = sandbox.clone();
    let cap_ctx_for_remove = capability_ctx.clone();
    let svc_for_remove = services.clone();
    let remove_fn = lua.create_function(move |_lua, filename: String| {
        // Capability + sandbox enforcement lives in the broker; the legacy
        // sandbox violation wording is preserved for blocked paths.
        match crate::providers::broker_fs_remove_file(
            &cap_ctx_for_remove,
            &svc_for_remove,
            &filename,
            "os.remove",
        ) {
            Ok(()) => Ok(true),
            Err(e) => {
                if e.contains("denied")
                    || e.contains("not allowed")
                    || e.contains("blocked")
                    || e.contains("sandbox")
                {
                    OS_SANDBOX_VIOLATIONS.fetch_add(1, Ordering::SeqCst);
                    if sandbox_for_remove.log_violations {
                        tracing::warn!(path = %filename, "Capability: blocked os.remove call: {}", e);
                    }
                }
                Ok(false)
            }
        }
    })?;
    nse_os.set("remove", remove_fn)?;

    let sandbox_for_rename = sandbox.clone();
    let cap_ctx_for_rename = capability_ctx.clone();
    let svc_for_rename = services.clone();
    let rename_fn = lua.create_function(move |_lua, (oldname, newname): (String, String)| {
        match crate::providers::broker_fs_rename(
            &cap_ctx_for_rename,
            &svc_for_rename,
            &oldname,
            &newname,
            "os.rename",
        ) {
            Ok(()) => Ok(true),
            Err(e) => {
                if e.contains("denied")
                    || e.contains("not allowed")
                    || e.contains("blocked")
                    || e.contains("sandbox")
                {
                    OS_SANDBOX_VIOLATIONS.fetch_add(1, Ordering::SeqCst);
                    if sandbox_for_rename.log_violations {
                        tracing::warn!(old = %oldname, new = %newname, "Capability: blocked os.rename call: {}", e);
                    }
                }
                Ok(false)
            }
        }
    })?;
    nse_os.set("rename", rename_fn)?;

    // Per-run working directory read (direct provider read, preserving the
    // legacy check-free behavior exactly).
    let svc_for_getcwd = services.clone();
    let getcwd_fn =
        lua.create_function(move |_lua, _: ()| match svc_for_getcwd.fs().current_dir() {
            Ok(p) => Ok(p.to_string_lossy().to_string()),
            Err(_) => Ok("/".to_string()),
        })?;
    nse_os.set("getcwd", getcwd_fn)?;

    let sandbox_for_chdir = sandbox.clone();
    let cap_ctx_for_chdir = capability_ctx.clone();
    let svc_for_chdir = services.clone();
    let chdir_fn = lua.create_function(move |_lua, path: String| {
        // Brokered virtual-CWD change (read-kind gate, matching lfs.chdir;
        // never mutates the process). Legacy os.chdir had no capability
        // check; the broker adds one — documented hardening, Manual
        // profiles unaffected.
        match crate::providers::broker_fs_set_current_dir(
            &cap_ctx_for_chdir,
            &svc_for_chdir,
            &path,
            "os.chdir",
        ) {
            Ok(()) => Ok(0),
            Err(e) => {
                if e.contains("blocked by sandbox") {
                    OS_SANDBOX_VIOLATIONS.fetch_add(1, Ordering::SeqCst);
                    if sandbox_for_chdir.log_violations {
                        tracing::warn!(path = %path, "Sandbox: blocked os.chdir call");
                    }
                }
                Ok(-1)
            }
        }
    })?;
    nse_os.set("chdir", chdir_fn)?;

    let cap_ctx = capability_ctx.clone();
    let svc = services.clone();
    let clock_fn = lua.create_function(move |_lua, _: ()| {
        let now = crate::providers::broker_unix_timestamp(&cap_ctx, &svc, "os.clock")
            .unwrap_or_else(|_| get_current_timestamp() as i64);
        Ok(now as f64)
    })?;
    nse_os.set("clock", clock_fn)?;

    let cap_ctx = capability_ctx.clone();
    let svc = services.clone();
    let date_fn = lua.create_function(move |lua, format: Option<String>| {
        let ts = crate::providers::broker_unix_timestamp(&cap_ctx, &svc, "os.date")
            .unwrap_or_else(|_| get_current_timestamp() as i64);
        let (year, month, day, hour, min, sec, wday) = timestamp_to_tm(ts);

        if format.as_deref() == Some("*t") {
            let result = lua.create_table()?;
            result.set("year", year)?;
            result.set("month", month)?;
            result.set("day", day)?;
            result.set("hour", hour)?;
            result.set("min", min)?;
            result.set("sec", sec)?;
            result.set("wday", wday + 1)?;
            return Ok(result);
        }

        let weekday_name = match wday {
            0 => "Sunday",
            1 => "Monday",
            2 => "Tuesday",
            3 => "Wednesday",
            4 => "Thursday",
            5 => "Friday",
            6 => "Saturday",
            _ => "Unknown",
        };

        let month_name = match month {
            1 => "January",
            2 => "February",
            3 => "March",
            4 => "April",
            5 => "May",
            6 => "June",
            7 => "July",
            8 => "August",
            9 => "September",
            10 => "October",
            11 => "November",
            12 => "December",
            _ => "Unknown",
        };

        let formatted = format!(
            "{} {} {:2} {:2}:{:2}:{:2} {}",
            weekday_name, month_name, day, hour, min, sec, year
        );

        let result = lua.create_table()?;
        result.set("formatted", formatted)?;
        Ok(result)
    })?;
    nse_os.set("date", date_fn)?;

    let cap_ctx = capability_ctx.clone();
    let svc = services.clone();
    let time_fn = lua.create_function(move |_lua, _table: Option<Table>| {
        let now = crate::providers::broker_unix_timestamp(&cap_ctx, &svc, "os.time")
            .unwrap_or_else(|_| get_current_timestamp() as i64);
        Ok(now)
    })?;
    nse_os.set("time", time_fn)?;

    let difftime_fn = lua.create_function(|_lua, (t1, t2): (i64, i64)| Ok((t1 - t2) as f64))?;
    nse_os.set("difftime", difftime_fn)?;

    let exit_fn = lua.create_function(|_lua, code: Option<i32>| {
        let code = code.unwrap_or(0);
        EXIT_CODE.store(code, Ordering::SeqCst);
        Ok(code)
    })?;
    nse_os.set("exit", exit_fn)?;

    let svc = services.clone();
    let tmpdir_fn = lua.create_function(move |_lua, _: ()| {
        // Env-derived lookup via provider; preserves the infallible string
        // contract by falling back to std on provider failure.
        let dir = svc
            .environment()
            .temp_dir()
            .unwrap_or_else(|_| env::temp_dir());
        Ok(dir.to_string_lossy().to_string())
    })?;
    nse_os.set("tmpdir", tmpdir_fn)?;

    let hostname_fn = lua.create_function(|_lua, _: ()| {
        Ok(hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "localhost".to_string()))
    })?;
    nse_os.set("hostname", hostname_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    nse_os.set("version", version_fn)?;

    globals.set("os", nse_os)?;
    Ok(())
}
