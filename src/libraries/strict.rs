//! NSE strict library wrapper
//!
//! Checks for undeclared global variables during runtime.

use mlua::{Lua, Result as LuaResult, Table};

pub fn register_strict_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let strict = lua.create_table()?;

    strict.set(
        "on",
        lua.create_function(|_lua, env: Option<Table>| {
            if let Some(e) = env {
                if let Err(err) = e.set("_STRICT", true) {
                    tracing::warn!("Failed to set _STRICT mode: {}", err);
                }
            }
            Ok(true)
        })?,
    )?;

    strict.set(
        "off",
        lua.create_function(|_lua, env: Option<Table>| {
            if let Some(e) = env {
                if let Err(err) = e.set("_STRICT", false) {
                    tracing::warn!("Failed to unset _STRICT mode: {}", err);
                }
            }
            Ok(true)
        })?,
    )?;

    strict.set(
        "check",
        lua.create_function(|_lua, (env, name): (Table, String)| {
            let known_globals = [
                "stdnse",
                "nmap",
                "http",
                "socket",
                "ssl",
                "tls",
                "shortport",
                "comm",
                "sslcert",
                "mysql",
                "postgres",
                "mssql",
                "redis",
                "mongodb",
                "ldap",
                "smb",
                "snmp",
                "ftp",
                "smtp",
                "dns",
                "ssh",
                "ssh2",
                "datafiles",
                "url",
                "json",
                "base64",
                "datetime",
                "rand",
                "bit",
                "io",
                "os",
                "strbuf",
                "tab",
                "stringaux",
                "print",
                "pairs",
                "ipairs",
                "table",
                "string",
                "math",
                "os",
                "coroutine",
                "debug",
            ];

            if known_globals.iter().any(|&g| g == name) {
                return Ok(false);
            }

            if let Ok(strict) = env.get::<bool>("_STRICT") {
                if strict {
                    eprintln!("[NSE STRICT] Undeclared global: {}", name);
                }
            }

            Ok(false)
        })?,
    )?;

    globals.set("strict", strict)?;
    Ok(())
}
