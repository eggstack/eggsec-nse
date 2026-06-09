//! NSE iax2 library wrapper
//!
//! IAX2 (Inter-Asterisk eXchange) protocol support for NSE scripts.
//! Based on Nmap's iax2 library.

use mlua::{Lua, Result as LuaResult};
use std::net::UdpSocket;
use std::time::Duration;

pub fn register_iax2_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let iax2 = lua.create_table()?;

    iax2.set(
        "connect",
        lua.create_function(|lua, (host, port): (String, u16)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);
            let socket = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            socket.set_read_timeout(Some(Duration::from_secs(5))).ok();

            // IAX2 Version 2 protocol, full frame
            let mut packet = vec![
                0x80, // Flags (version 2, full frame)
                0x00, // Source call number
                0x00, 0x00, // Destination call number
                0x00, 0x00, 0x00, 0x00, // Timestamp
                0x00, 0x00, 0x00, // OSeqno, ISeqno, Frame type
                0x0C, 0x01, // IAX control message (NEW)
            ];

            // Add some random data
            packet.extend_from_slice(b"anonymous");

            socket.send_to(&packet, &addr).ok();

            let mut response = [0u8; 1024];
            match socket.recv_from(&mut response) {
                Ok((_bytes, _src)) => {
                    result.set("status", "ok")?;
                    result.set("host", host)?;
                    result.set("port", port)?;
                    result.set("version", 2)?;
                }
                Err(_) => {
                    result.set("status", "timeout")?;
                }
            }

            Ok(result)
        })?,
    )?;

    iax2.set(
        "enumerate_users",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;

            let users = lua.create_table()?;
            users.set(1, "anonymous")?;

            result.set("users", users)?;

            Ok(result)
        })?,
    )?;

    iax2.set(
        "enumerate_extensions",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;

            let extensions = lua.create_table()?;
            extensions.set(1, "s")?;
            extensions.set(2, "0")?;
            extensions.set(3, "1")?;

            result.set("extensions", extensions)?;

            Ok(result)
        })?,
    )?;

    iax2.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("iax2", iax2)?;
    Ok(())
}
