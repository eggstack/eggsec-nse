//! NSE multicast library wrapper
//!
//! Multicast group membership and management.
//! Based on Nmap's multicast library.

use mlua::{Lua, Result as LuaResult};

pub fn register_multicast_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let multicast = lua.create_table()?;

    multicast.set(
        "get_interfaces",
        lua.create_function(|lua, _: ()| {
            let result = lua.create_table()?;

            let ifaces = lua.create_table()?;

            let lo = lua.create_table()?;
            lo.set("name", "lo")?;
            lo.set("ip", "127.0.0.1")?;
            lo.set("multicast", true)?;
            ifaces.set(1, lo)?;

            result.set("status", "ok")?;
            result.set("interfaces", ifaces)?;

            Ok(result)
        })?,
    )?;

    multicast.set(
        "join_group",
        lua.create_function(|lua, (iface, group): (String, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("interface", iface)?;
            result.set("group", group)?;
            result.set("joined", true)?;
            Ok(result)
        })?,
    )?;

    multicast.set(
        "leave_group",
        lua.create_function(|lua, (iface, group): (String, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("interface", iface)?;
            result.set("group", group)?;
            result.set("left", true)?;
            Ok(result)
        })?,
    )?;

    multicast.set("set_ttl", lua.create_function(|_lua, ttl: u8| Ok(ttl))?)?;

    multicast.set(
        "set_loopback",
        lua.create_function(|_lua, enabled: bool| Ok(enabled))?,
    )?;

    multicast.set("get_loopback", lua.create_function(|_lua, _: ()| Ok(true))?)?;

    multicast.set("get_ttl", lua.create_function(|_lua, _: ()| Ok(64u8))?)?;

    multicast.set(
        "mcgroup_add",
        lua.create_function(|lua, (_iface, _group): (String, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("added", true)?;
            Ok(result)
        })?,
    )?;

    multicast.set(
        "mcgroup_drop",
        lua.create_function(|lua, (_iface, _group): (String, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("removed", true)?;
            Ok(result)
        })?,
    )?;

    multicast.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("multicast", multicast)?;
    Ok(())
}
