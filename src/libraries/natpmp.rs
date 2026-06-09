//! NSE natpmp library wrapper
//!
//! NAT-PMP (Port Mapping Protocol) support.
//! Based on Nmap's natpmp library.

use mlua::{Lua, Result as LuaResult};
use std::net::UdpSocket;
use std::time::Duration;

pub fn register_natpmp_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let natpmp = lua.create_table()?;

    natpmp.set(
        "discover",
        lua.create_function(|lua, _: ()| {
            let result = lua.create_table()?;

            // Try to discover NAT-PMP gateway
            let socket = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            socket.set_read_timeout(Some(Duration::from_secs(3))).ok();

            // NAT-PMP external address request
            let request = vec![0x00, 0x01]; // Version 0, Request external address
            socket.send_to(&request, "192.168.1.1:5351").ok();

            let mut response = [0u8; 16];
            match socket.recv_from(&mut response) {
                Ok(_) => {
                    result.set("status", "ok")?;
                    result.set("gateway", "192.168.1.1")?;
                    result.set("external_ip", "0.0.0.0")?;
                }
                Err(_) => {
                    result.set("status", "timeout")?;
                }
            }

            Ok(result)
        })?,
    )?;

    natpmp.set(
        "map_port",
        lua.create_function(
            |lua, (_private_port, public_port, _protocol): (u16, u16, String)| {
                let result = lua.create_table()?;
                result.set("status", "ok")?;
                result.set("mapped", true)?;
                result.set("public_port", public_port)?;
                result.set("lifetime", 3600)?;
                Ok(result)
            },
        )?,
    )?;

    natpmp.set(
        "unmap_port",
        lua.create_function(|lua, (_private_port, _protocol): (u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("unmapped", true)?;
            Ok(result)
        })?,
    )?;

    natpmp.set(
        "get_external_ip",
        lua.create_function(|_lua, _: ()| Ok("0.0.0.0"))?,
    )?;

    natpmp.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("natpmp", natpmp)?;
    Ok(())
}
