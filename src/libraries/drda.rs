//! NSE drda library wrapper
//!
//! DRDA (Distributed Relational Database Architecture) protocol support.
//! Based on Nmap's drda library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_drda_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let drda = lua.create_table()?;

    drda.set(
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

            // DRDA exchange attributes
            let excat = [
                0xD0, 0x17, // Format
                0x00, 0x00, 0x00, 0x2D, // Length
                0x41, 0x41, 0x41,
                0x41, // Correlation token
                      // DRDA parameters follow
            ];

            stream.write_all(&excat).ok();

            let mut response = [0u8; 1024];
            let n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("connected", n > 0)?;
            result.set("host", host)?;
            result.set("port", port)?;

            Ok(result)
        })?,
    )?;

    drda.set(
        "parse_header",
        lua.create_function(|lua, data: String| {
            let result = lua.create_table()?;

            if data.len() >= 10 {
                let bytes = data.as_bytes();
                result.set("format", bytes[0])?;
                result.set("length", u16::from_be_bytes([bytes[2], bytes[3]]))?;
                result.set("codepoint", u16::from_be_bytes([bytes[8], bytes[9]]))?;
            }

            result.set("status", "ok")?;
            Ok(result)
        })?,
    )?;

    drda.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("drda", drda)?;
    Ok(())
}
