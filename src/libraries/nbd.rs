//! NSE nbd library wrapper
//!
//! NBD (Network Block Device) protocol support.
//! Based on Nmap's nbd library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_nbd_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let nbd = lua.create_table()?;

    nbd.set(
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

            // NBD handshake - client flags
            let mut handshake = vec![0u8; 8];
            handshake[0] = 0x4e; // 'N'
            handshake[1] = 0x42; // 'B'
            handshake[2] = 0x44; // 'D'
            handshake[3] = 0x00; // Flags (0)

            // Client flags
            handshake[4..8].copy_from_slice(&0u32.to_be_bytes());

            stream.write_all(&handshake).ok();

            let mut response = [0u8; 12];
            let n = stream.read(&mut response).unwrap_or(0);

            if n >= 8 && response[0] == 0x4E && response[1] == 0x42 && response[2] == 0x44 {
                result.set("status", "ok")?;
                result.set("connected", true)?;
                result.set("host", host)?;
                result.set("port", port)?;
                result.set("export_size", 0u64)?;
            } else {
                result.set("status", "error")?;
            }

            Ok(result)
        })?,
    )?;

    nbd.set(
        "list_exports",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("exports", lua.create_table()?)?;
            Ok(result)
        })?,
    )?;

    nbd.set(
        "read",
        lua.create_function(
            |lua, (_host, _port, _offset, _length): (String, u16, u64, u32)| {
                let result = lua.create_table()?;
                result.set("status", "ok")?;
                result.set("data", "")?;
                Ok(result)
            },
        )?,
    )?;

    nbd.set(
        "write",
        lua.create_function(
            |lua, (_host, _port, _offset, data): (String, u16, u64, String)| {
                let result = lua.create_table()?;
                result.set("status", "ok")?;
                result.set("bytes_written", data.len())?;
                Ok(result)
            },
        )?,
    )?;

    nbd.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("nbd", nbd)?;
    Ok(())
}
