//! NSE rsync library wrapper
//!
//! Rsync protocol support for NSE scripts.
//! Based on Nmap's rsync library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_rsync_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let rsync = lua.create_table()?;

    rsync.set(
        "connect",
        lua.create_function(|lua, (host, port): (String, u16)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);
            let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                Ok(a) => a,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                    return Ok(result);
                }
            };
            let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))
            {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            // Rsync protocol greeting
            let greeting = b"@RSYNCD: 31.0\n";
            stream.write_all(greeting).unwrap_or_else(|e| tracing::warn!("Failed to send rsync greeting: {}", e));

            let mut response = [0u8; 1024];
            let n = stream.read(&mut response).unwrap_or(0);
            let response_str = String::from_utf8_lossy(&response[..n]);

            if response_str.starts_with("@RSYNCD:") {
                result.set("status", "ok")?;
                result.set("connected", true)?;
                result.set("version", response_str.trim())?;
            } else {
                result.set("status", "error")?;
            }

            Ok(result)
        })?,
    )?;

    rsync.set(
        "list_modules",
        lua.create_function(|lua, (host, port): (String, u16)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);
            let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                Ok(a) => a,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                    return Ok(result);
                }
            };
            let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))
            {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            stream.write_all(b"@RSYNCD: 31.0\n").unwrap_or_else(|e| tracing::warn!("Failed to send rsync greeting: {}", e));
            stream.write_all(b"\n").unwrap_or_else(|e| tracing::warn!("Failed to send rsync newline: {}", e));

            let mut response = [0u8; 4096];
            let n = stream.read(&mut response).unwrap_or(0);

            let modules = lua.create_table()?;
            let response_str = String::from_utf8_lossy(&response[..n]);

            let mut i = 1;
            for line in response_str.lines() {
                if !line.starts_with('@') && !line.is_empty() {
                    if let Some(name) = line.split_whitespace().next() {
                        modules.set(i, name)?;
                        i += 1;
                    }
                }
            }

            result.set("status", "ok")?;
            result.set("modules", modules)?;

            Ok(result)
        })?,
    )?;

    rsync.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("rsync", rsync)?;
    Ok(())
}
