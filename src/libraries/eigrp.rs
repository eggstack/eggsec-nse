//! NSE eigrp library wrapper
//!
//! EIGRP (Enhanced Interior Gateway Routing Protocol) support.
//! Based on Nmap's eigrp library.

use mlua::{Lua, Result as LuaResult};
use std::net::UdpSocket;
use std::time::Duration;

pub fn register_eigrp_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let eigrp = lua.create_table()?;

    eigrp.set(
        "discover",
        lua.create_function(|lua, (host, as_num): (String, u32)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, 8);
            let socket = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            socket.set_read_timeout(Some(Duration::from_secs(5))).ok();

            // EIGRP Hello packet
            let mut hello = vec![
                0x01, // Version
                0x05, // Opcode (Hello)
                0x00, 0x00, // Checksum
                0x00, 0x00, 0x00, 0x00, // Flags
                0x00, 0x00, 0x00, 0x00, // Sequence
                0x00, 0x00, 0x00, 0x00, // ACK
            ];

            hello.extend_from_slice(&as_num.to_be_bytes());

            socket.send_to(&hello, &addr).ok();

            let mut response = [0u8; 1024];
            match socket.recv_from(&mut response) {
                Ok(_) => {
                    result.set("status", "ok")?;
                    result.set("eigrp", true)?;
                }
                Err(_) => {
                    result.set("status", "timeout")?;
                }
            }

            Ok(result)
        })?,
    )?;

    eigrp.set(
        "parse_packet",
        lua.create_function(|lua, data: String| {
            let result = lua.create_table()?;

            if data.len() >= 4 {
                let bytes = data.as_bytes();
                result.set("version", bytes[0])?;
                result.set("opcode", bytes[1])?;
                result.set("status", "ok")?;
            } else {
                result.set("status", "error")?;
            }

            Ok(result)
        })?,
    )?;

    eigrp.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("eigrp", eigrp)?;
    Ok(())
}
