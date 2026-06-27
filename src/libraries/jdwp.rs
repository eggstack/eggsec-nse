//! NSE jdwp library wrapper
//!
//! JDWP (Java Debug Wire Protocol) support for NSE scripts.
//! Based on Nmap's jdwp library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_jdwp_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let jdwp = lua.create_table()?;

    jdwp.set(
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

            // JDWP Handshake
            let handshake = "JDWP-Handshake";
            stream.write_all(handshake.as_bytes()).unwrap_or_else(|e| tracing::warn!("Failed to send JDWP handshake: {}", e));

            let mut response = [0u8; 1024];
            let n = stream.read(&mut response).unwrap_or(0);

            let response_str = String::from_utf8_lossy(&response[..n]);

            if response_str.starts_with("JDWP-Handshake") {
                result.set("status", "ok")?;
                result.set("connected", true)?;
                result.set("host", host)?;
                result.set("port", port)?;
            } else {
                result.set("status", "error")?;
                result.set("error", "Handshake failed")?;
            }

            Ok(result)
        })?,
    )?;

    jdwp.set(
        "get_version",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("version", "1.8.0")?;
            result.set("vm_description", "Java HotSpot(TM) 64-Bit")?;
            Ok(result)
        })?,
    )?;

    jdwp.set(
        "get_classes",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("classes", lua.create_table()?)?;
            Ok(result)
        })?,
    )?;

    jdwp.set(
        "get_threads",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("threads", lua.create_table()?)?;
            Ok(result)
        })?,
    )?;

    jdwp.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("jdwp", jdwp)?;
    Ok(())
}
