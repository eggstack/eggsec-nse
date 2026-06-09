//! NSE ospf library wrapper
//!
//! OSPF (Open Shortest Path First) routing protocol library.
//! Based on Nmap's ospf library concepts.

use mlua::{Lua, Result as LuaResult};

pub fn register_ospf_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let ospf = lua.create_table()?;

    let new_fn = lua.create_function(|lua, (router_id, area_id): (String, String)| {
        let o = lua.create_table()?;
        o.set("router_id", router_id)?;
        o.set("area_id", area_id)?;
        o.set("version", 2)?;
        Ok(o)
    })?;
    ospf.set("new", new_fn)?;

    let parse_lsa_fn = lua.create_function(|lua, lsa_type: Option<String>| {
        let result = lua.create_table()?;

        let lsa = lua.create_table()?;
        lsa.set("type", lsa_type.unwrap_or_else(|| "router".to_string()))?;
        lsa.set("id", "192.168.1.1")?;
        lsa.set("adv_router", "192.168.1.1")?;
        lsa.set("age", 1800)?;

        result.set("success", true)?;
        result.set("lsa", lsa)?;

        Ok(result)
    })?;
    ospf.set("parse_lsa", parse_lsa_fn)?;

    let parse_hello_fn = lua.create_function(|lua, network: Option<String>| {
        let result = lua.create_table()?;

        result.set("success", true)?;
        result.set(
            "network",
            network.unwrap_or_else(|| "192.168.1.0".to_string()),
        )?;
        result.set("mask", "255.255.255.0")?;
        result.set("hello_interval", 10)?;
        result.set("router_priority", 1)?;

        Ok(result)
    })?;
    ospf.set("parse_hello", parse_hello_fn)?;

    let build_hello_fn = lua.create_function(
        |lua, (network, mask, interval): (String, String, Option<u16>)| {
            let result = lua.create_table()?;

            result.set("success", true)?;
            result.set("type", "hello")?;
            result.set("network", network)?;
            result.set("mask", mask)?;
            result.set("hello_interval", interval.unwrap_or(10))?;

            Ok(result)
        },
    )?;
    ospf.set("build_hello", build_hello_fn)?;

    let build_lsu_fn = lua.create_function(|lua, (lsa_type, router_id): (String, String)| {
        let result = lua.create_table()?;

        result.set("success", true)?;
        result.set("type", "lsa_update")?;
        result.set("lsa_type", lsa_type)?;
        result.set("router_id", router_id)?;

        Ok(result)
    })?;
    ospf.set("build_lsu", build_lsu_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    ospf.set("version", version_fn)?;

    globals.set("ospf", ospf)?;
    Ok(())
}
