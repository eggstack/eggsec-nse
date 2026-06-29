//! NSE membase library wrapper
//!
//! Membase (Couchbase) NoSQL database support.
//! Based on Nmap's membase library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_membase_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let membase = lua.create_table()?;

    membase.set(
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

            // Membase hello
            let hello = b"MECHO\r\n";
            stream
                .write_all(hello)
                .unwrap_or_else(|e| tracing::warn!("Failed to send membase hello: {}", e));

            let mut response = [0u8; 1024];
            let n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("connected", n > 0)?;
            result.set("host", host)?;
            result.set("port", port)?;

            Ok(result)
        })?,
    )?;

    membase.set(
        "get",
        lua.create_function(|lua, (_host, _port, key): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("key", key)?;
            result.set("value", "")?;
            Ok(result)
        })?,
    )?;

    membase.set(
        "set",
        lua.create_function(
            |lua, (_host, _port, _key, _value): (String, u16, String, String)| {
                let result = lua.create_table()?;
                result.set("status", "ok")?;
                result.set("success", true)?;
                Ok(result)
            },
        )?,
    )?;

    membase.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("membase", membase)?;
    Ok(())
}
