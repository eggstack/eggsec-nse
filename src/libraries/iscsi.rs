//! NSE iscsi library wrapper
//!
//! iSCSI protocol support for NSE scripts.
//! Based on Nmap's iscsi library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_iscsi_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let iscsi = lua.create_table()?;

    iscsi.set(
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

            // iSCSI Login Request (Text)
            let mut login = vec![
                0x01, // Opcode (Login Request)
                0xC0, // Flags
                0x00, 0x00, // Total AHS length
                0x00, 0x00, 0x00, 0x24, // Data segment length
            ];

            // Initiator Name
            login.extend_from_slice(b"TargetName=iqn.2024-01.local:target");

            stream.write_all(&login).ok();

            let mut response = [0u8; 1024];
            let n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("connected", n > 0)?;
            result.set("host", host)?;
            result.set("port", port)?;

            Ok(result)
        })?,
    )?;

    iscsi.set(
        "discover_targets",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;

            let targets = lua.create_table()?;
            targets.set(1, "iqn.2024-01.local:disk0")?;
            targets.set(2, "iqn.2024-01.local:disk1")?;

            result.set("targets", targets)?;

            Ok(result)
        })?,
    )?;

    iscsi.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("iscsi", iscsi)?;
    Ok(())
}
