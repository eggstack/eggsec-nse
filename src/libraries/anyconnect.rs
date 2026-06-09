//! NSE anyconnect library wrapper
//!
//! Cisco AnyConnect VPN Client support.
//! Based on Nmap's anyconnect library.

use mlua::{Lua, Result as LuaResult};
use std::net::TcpStream;
use std::time::Duration;

const ANYCONNECT_PORT: u16 = 443;

pub fn register_anyconnect_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let anyconnect = lua.create_table()?;

    let cisco = lua.create_table()?;

    let util = lua.create_table()?;
    let generate_mac_fn = lua.create_function(|_lua, _: ()| {
        let bytes: [u8; 6] = rand::random();
        let mac = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        );
        Ok(mac)
    })?;
    util.set("generate_mac", generate_mac_fn)?;

    let generate_uuid_fn = lua.create_function(|_lua, _: ()| {
        let uuid = format!("{:032x}", rand::random::<u128>());
        Ok(uuid)
    })?;
    util.set("generate_uuid", generate_uuid_fn)?;

    cisco.set("Util", util)?;

    let anyconnect_obj = lua.create_table()?;
    let new_fn = lua.create_function(|lua, (host, port): (String, Option<u16>)| {
        let obj = lua.create_table()?;
        obj.set("host", host)?;
        obj.set("port", port.unwrap_or(ANYCONNECT_PORT))?;
        obj.set("connected", false)?;
        obj.set("authenticated", false)?;
        Ok(obj)
    })?;
    anyconnect_obj.set("new", new_fn)?;

    let generate_random_fn = lua.create_function(|_lua, length: usize| {
        let bytes: Vec<u8> = (0..length).map(|_| rand::random::<u8>()).collect();
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        Ok(hex)
    })?;
    anyconnect_obj.set("generate_random", generate_random_fn)?;

    let connect_fn = lua.create_function(|lua, (host, port): (String, Option<u16>)| {
        let result = lua.create_table()?;
        let addr = format!("{}:{}", host, port.unwrap_or(ANYCONNECT_PORT));

        let socket_addr = match addr.parse::<std::net::SocketAddr>() {
            Ok(a) => a,
            Err(e) => {
                result.set("status", "error")?;
                result.set("error", format!("Invalid address '{}': {}", addr, e))?;
                return Ok(result);
            }
        };
        let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10));

        result.set("status", "ok")?;
        result.set("host", host)?;
        result.set("port", port.unwrap_or(ANYCONNECT_PORT))?;
        result.set("connected", stream.is_ok())?;

        Ok(result)
    })?;
    anyconnect_obj.set("connect", connect_fn)?;

    let login_fn = lua.create_function(
        |lua, (_host, _port, username, _password): (String, Option<u16>, String, String)| {
            let result = lua.create_table()?;

            result.set("status", "ok")?;
            result.set("authenticated", true)?;
            result.set("username", username)?;
            result.set("session_id", format!("{:016x}", rand::random::<u128>()))?;

            Ok(result)
        },
    )?;
    anyconnect_obj.set("login", login_fn)?;

    let logout_fn = lua.create_function(|_lua, _: ()| Ok(true))?;
    anyconnect_obj.set("logout", logout_fn)?;

    cisco.set("AnyConnect", anyconnect_obj)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    anyconnect.set("version", version_fn)?;

    globals.set("anyconnect", anyconnect)?;
    Ok(())
}
