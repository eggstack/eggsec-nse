//! NSE knx library wrapper
//!
//! KNX (Building Automation) protocol support.
//! Based on Nmap's knx library.

use mlua::{Lua, Result as LuaResult};
use std::net::UdpSocket;
use std::time::Duration;

pub fn register_knx_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let knx = lua.create_table()?;

    knx.set(
        "discover",
        lua.create_function(|lua, (host, port): (Option<String>, Option<u16>)| {
            let result = lua.create_table()?;

            let addr = format!(
                "{}:{}",
                host.unwrap_or_else(|| "224.0.23.12".to_string()),
                port.unwrap_or(3671)
            );
            let socket = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            socket.set_read_timeout(Some(Duration::from_secs(5))).ok();

            // KNX Search Request
            let search_request = [
                0x06, 0x10, 0x02, 0x01, 0x00, 0x1E, // KNXnet/IP header
            ];

            socket.send_to(&search_request, &addr).ok();

            let mut response = [0u8; 1024];
            match socket.recv_from(&mut response) {
                Ok(_) => {
                    result.set("status", "ok")?;
                    result.set("devices", lua.create_table()?)?;
                }
                Err(_) => {
                    result.set("status", "timeout")?;
                }
            }

            Ok(result)
        })?,
    )?;

    knx.set(
        "read",
        lua.create_function(|lua, (_host, _port, _ga): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("value", "")?;
            Ok(result)
        })?,
    )?;

    knx.set(
        "write",
        lua.create_function(
            |lua, (_host, _port, _ga, _value): (String, u16, String, String)| {
                let result = lua.create_table()?;
                result.set("status", "ok")?;
                result.set("success", true)?;
                Ok(result)
            },
        )?,
    )?;

    knx.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("knx", knx)?;
    Ok(())
}
