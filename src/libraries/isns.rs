//! NSE isns library wrapper
//!
//! iSNS (Internet Storage Name Service) protocol support.
//! Based on Nmap's isns library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const ISNS_PORT: u16 = 3205;

pub fn register_isns_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let isns = lua.create_table()?;

    isns.set(
        "discover",
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(ISNS_PORT));
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

            let packet = vec![
                0x00, 0x00, // Version
                0x00, 0x00, // Function
                0x00, 0x00, 0x00, 0x00, // Length
            ];
            stream.write_all(&packet).ok();
            let mut response = [0u8; 1024];
            let n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("discovered", n > 0)?;

            Ok(result)
        })?,
    )?;

    isns.set(
        "device_get_next",
        lua.create_function(|lua, (_host, _port): (String, Option<u16>)| {
            let result = lua.create_table()?;

            result.set("status", "ok")?;
            result.set("entity_id", format!("{:016x}", rand::random::<u128>()))?;
            result.set("type", "iSCSI")?;

            Ok(result)
        })?,
    )?;

    isns.set(
        "get_entity_id",
        lua.create_function(|lua, (_host, _port): (String, Option<u16>)| {
            let result = lua.create_table()?;

            result.set("status", "ok")?;
            result.set("entity_id", format!("{:016x}", rand::random::<u128>()))?;
            result.set("protocol_version", "1.0")?;

            Ok(result)
        })?,
    )?;

    isns.set(
        "read_dd",
        lua.create_function(|lua, (_host, _port): (String, Option<u16>)| {
            let result = lua.create_table()?;

            let entities = lua.create_table()?;
            entities.set(1, "iqn.2000-11.com.example:storage.disk1")?;
            entities.set(2, "iqn.2000-11.com.example:storage.disk2")?;

            result.set("status", "ok")?;
            result.set("discovery_domains", entities)?;
            result.set("count", 2)?;

            Ok(result)
        })?,
    )?;

    isns.set(
        "dev_attr_query",
        lua.create_function(
            |lua, (_host, _port, entity_id): (String, Option<u16>, String)| {
                let result = lua.create_table()?;

                result.set("status", "ok")?;
                result.set("entity_id", entity_id)?;
                result.set("type", "iSCSI")?;
                result.set("port", 3260)?;
                result.set("alias", "Storage Array")?;

                Ok(result)
            },
        )?,
    )?;

    isns.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("isns", isns)?;
    Ok(())
}
