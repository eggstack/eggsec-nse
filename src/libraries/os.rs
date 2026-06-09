//! NSE os library wrapper
//!
//! Provides OS operations compatible with NSE.

use mlua::{Lua, Result as LuaResult, Table};
use std::env;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::SandboxConfig;

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

pub fn register_os_library(lua: &Lua, sandbox: &SandboxConfig) -> LuaResult<()> {
    let globals = lua.globals();
    let nse_os = lua.create_table()?;

    let sandbox_enabled = sandbox.enabled;

    let getenv_fn = lua.create_function(move |_lua, name: String| {
        if sandbox_enabled {
            Ok(String::new())
        } else {
            Ok(env::var(&name).unwrap_or_default())
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
        // SAFETY: This NSE executor runs inside a single-threaded Lua VM within
        // spawn_blocking(). Concurrent NSE executors each have their own isolated
        // Lua state, but env::set_var modifies process-global state. This is a known
        // TOCTOU hazard. NSE scripts should not rely on environment mutation across
        // threads. Consider replacing with a per-executor env store in the future.
        unsafe { env::set_var(&name, &value) };
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
        // SAFETY: Same concern as setenv_fn — process-global env mutation.
        unsafe { env::remove_var(&name) };
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
    let remove_fn = lua.create_function(move |_lua, filename: String| {
        let file_path = if sandbox_for_remove.enabled {
            match sandbox_for_remove.get_allowed_path(&filename) {
                Some(canonical) => canonical,
                None => {
                    OS_SANDBOX_VIOLATIONS.fetch_add(1, Ordering::SeqCst);
                    if sandbox_for_remove.log_violations {
                        tracing::warn!(path = %filename, "Sandbox: blocked os.remove call");
                    }
                    return Ok(false);
                }
            }
        } else {
            std::path::PathBuf::from(&filename)
        };
        match std::fs::remove_file(&file_path) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    })?;
    nse_os.set("remove", remove_fn)?;

    let sandbox_for_rename = sandbox.clone();
    let rename_fn = lua.create_function(move |_lua, (oldname, newname): (String, String)| {
        let (old_path, new_path) = if sandbox_for_rename.enabled {
            let Some(canonical_old) = sandbox_for_rename.get_allowed_path(&oldname) else {
                OS_SANDBOX_VIOLATIONS.fetch_add(1, Ordering::SeqCst);
                if sandbox_for_rename.log_violations {
                    tracing::warn!(old = %oldname, new = %newname, "Sandbox: blocked os.rename call");
                }
                return Ok(false);
            };
            let Some(canonical_new) = sandbox_for_rename.get_allowed_path(&newname) else {
                OS_SANDBOX_VIOLATIONS.fetch_add(1, Ordering::SeqCst);
                if sandbox_for_rename.log_violations {
                    tracing::warn!(old = %oldname, new = %newname, "Sandbox: blocked os.rename call");
                }
                return Ok(false);
            };
            (canonical_old, canonical_new)
        } else {
            (std::path::PathBuf::from(&oldname), std::path::PathBuf::from(&newname))
        };
        match std::fs::rename(&old_path, &new_path) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    })?;
    nse_os.set("rename", rename_fn)?;

    let getcwd_fn = lua.create_function(|_lua, _: ()| match env::current_dir() {
        Ok(p) => Ok(p.to_string_lossy().to_string()),
        Err(_) => Ok("/".to_string()),
    })?;
    nse_os.set("getcwd", getcwd_fn)?;

    let sandbox_for_chdir = sandbox.clone();
    let chdir_fn = lua.create_function(move |_lua, path: String| {
        let dir_path = if sandbox_for_chdir.enabled {
            match sandbox_for_chdir.get_allowed_path(&path) {
                Some(canonical) => canonical,
                None => {
                    OS_SANDBOX_VIOLATIONS.fetch_add(1, Ordering::SeqCst);
                    if sandbox_for_chdir.log_violations {
                        tracing::warn!(path = %path, "Sandbox: blocked os.chdir call");
                    }
                    return Ok(-1);
                }
            }
        } else {
            std::path::PathBuf::from(&path)
        };
        match env::set_current_dir(&dir_path) {
            Ok(()) => Ok(0),
            Err(_) => Ok(-1),
        }
    })?;
    nse_os.set("chdir", chdir_fn)?;

    let clock_fn = lua.create_function(|_lua, _: ()| {
        let now = get_current_timestamp() as f64;
        Ok(now)
    })?;
    nse_os.set("clock", clock_fn)?;

    let date_fn = lua.create_function(|lua, format: Option<String>| {
        let ts = get_current_timestamp() as i64;
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

    let time_fn = lua.create_function(|_lua, _table: Option<Table>| {
        let now = get_current_timestamp() as i64;
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

    let tmpdir_fn =
        lua.create_function(|_lua, _: ()| Ok(env::temp_dir().to_string_lossy().to_string()))?;
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
