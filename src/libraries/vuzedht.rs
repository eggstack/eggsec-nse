//! NSE vuzedht library wrapper
//!
//! Vuze DHT (Distributed Hash Table) protocol support.
//! Based on Nmap's vuzedht library.

use mlua::{Lua, Result as LuaResult};

const DHT_PORT: u16 = 6881;

pub fn register_vuzedht_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let vuzedht = lua.create_table()?;

    vuzedht.set(
        "ping",
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("host", host)?;
            result.set("port", port.unwrap_or(DHT_PORT))?;
            result.set("responded", false)?;
            Ok(result)
        })?,
    )?;

    vuzedht.set(
        "find_node",
        lua.create_function(
            |lua, (target_id, _host, _port): (String, String, Option<u16>)| {
                let result = lua.create_table()?;
                result.set("status", "ok")?;
                result.set("target_id", target_id)?;
                result.set("nodes", lua.create_table()?)?;
                result.set("token", "")?;
                Ok(result)
            },
        )?,
    )?;

    vuzedht.set(
        "get_peers",
        lua.create_function(
            |lua, (info_hash, _host, _port): (String, String, Option<u16>)| {
                let result = lua.create_table()?;
                result.set("status", "ok")?;
                result.set("info_hash", info_hash)?;
                result.set("peers", lua.create_table()?)?;
                result.set("nodes", lua.create_table()?)?;
                result.set("token", "")?;
                Ok(result)
            },
        )?,
    )?;

    vuzedht.set(
        "announce_peer",
        lua.create_function(|lua, (info_hash, port, host): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("info_hash", info_hash)?;
            result.set("port", port)?;
            result.set("host", host)?;
            Ok(result)
        })?,
    )?;

    vuzedht.set(
        "parse_packet",
        lua.create_function(|lua, data: String| {
            let result = lua.create_table()?;

            if data.len() < 4 {
                result.set("status", "error")?;
                result.set("errmsg", "Packet too short")?;
                return Ok(result);
            }

            let bytes = data.as_bytes();
            let transaction_id = &bytes[0..2];
            let msg_type = bytes[2];
            let protocol_version = bytes[3];

            let msg_type_str = match msg_type {
                0 => "ping",
                1 => "find_node",
                2 => "get_peers",
                3 => "announce_peer",
                _ => "unknown",
            };

            result.set("status", "ok")?;
            result.set(
                "transaction_id",
                format!("{:02x}{:02x}", transaction_id[0], transaction_id[1]),
            )?;
            result.set("message_type", msg_type_str)?;
            result.set("protocol_version", protocol_version)?;

            Ok(result)
        })?,
    )?;

    vuzedht.set(
        "make_transaction_id",
        lua.create_function(|_lua, _: ()| {
            let id: u16 = rand_simple();
            Ok(vec![(id >> 8) as u8, (id & 0xFF) as u8])
        })?,
    )?;

    vuzedht.set(
        "info_hash_to_peer_id",
        lua.create_function(|_lua, info_hash: String| {
            let peer_id = format!("-TR0000-{:0<12}", &info_hash[..12.min(info_hash.len())]);
            Ok(peer_id)
        })?,
    )?;

    vuzedht.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("vuzedht", vuzedht)?;
    Ok(())
}

fn rand_simple() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    (nanos as u16) ^ ((nanos >> 16) as u16)
}
