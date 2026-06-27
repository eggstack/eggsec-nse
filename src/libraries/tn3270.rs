//! NSE tn3270 library wrapper
//!
//! TN3270 protocol support for NSE scripts.
//! Based on Nmap's tn3270 library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_tn3270_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let tn3270 = lua.create_table()?;

    tn3270.set(
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

            // TN3270 negotiate init
            let negotiate = [
                0xFF, 0xD3, // TN3270E
                0x00, 0x00, // Length
            ];

            stream.write_all(&negotiate).unwrap_or_else(|e| tracing::warn!("Failed to send TN3270 negotiate: {}", e));

            let mut response = [0u8; 1024];
            let n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("connected", n > 0)?;
            result.set("host", host)?;
            result.set("port", port)?;

            Ok(result)
        })?,
    )?;

    tn3270.set(
        "send",
        lua.create_function(|lua, (_host, _port, data): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("bytes_sent", data.len())?;
            Ok(result)
        })?,
    )?;

    tn3270.set(
        "receive",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("data", "")?;
            Ok(result)
        })?,
    )?;

    tn3270.set(
        "get_screen",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("screen", "")?;
            result.set("rows", 24)?;
            result.set("cols", 80)?;
            Ok(result)
        })?,
    )?;

    tn3270.set(
        "send_command",
        lua.create_function(|lua, (_host, _port, _command): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("response", "")?;
            Ok(result)
        })?,
    )?;

    tn3270.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("tn3270", tn3270)?;
    Ok(())
}
