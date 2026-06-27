//! NSE msrpcperformance library wrapper
//!
//! MSRPC Performance monitoring.
//! Based on Nmap's msrpcperformance library.

use mlua::{Lua, Result as LuaResult, Table};
use std::net::TcpStream;
use std::time::Duration;

const DCERPC_PORT: u16 = 135;

pub fn register_msrpcperformance_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let msrpcperformance = lua.create_table()?;

    let get_counter_fn = lua.create_function(|lua, name: String| {
        let counter = lua.create_table()?;
        counter.set("name", name)?;
        counter.set("value", 0u64)?;
        counter.set(
            "timestamp",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )?;
        Ok(counter)
    })?;
    msrpcperformance.set("get_counter", get_counter_fn)?;

    let increment_fn = lua.create_function(|_lua, (counter, amount): (Table, u64)| {
        let current: u64 = counter.get("value").unwrap_or(0);
        counter.set("value", current + amount)?;
        Ok(counter)
    })?;
    msrpcperformance.set("increment", increment_fn)?;

    let decrement_fn = lua.create_function(|_lua, (counter, amount): (Table, u64)| {
        let current: u64 = counter.get("value").unwrap_or(0);
        counter.set("value", current.saturating_sub(amount))?;
        Ok(counter)
    })?;
    msrpcperformance.set("decrement", decrement_fn)?;

    let reset_fn = lua.create_function(|_lua, counter: Table| {
        counter.set("value", 0u64)?;
        Ok(counter)
    })?;
    msrpcperformance.set("reset", reset_fn)?;

    let get_value_fn = lua.create_function(|_lua, counter: Table| counter.get::<u64>("value"))?;
    msrpcperformance.set("get_value", get_value_fn)?;

    let set_value_fn = lua.create_function(|_lua, (counter, value): (Table, u64)| {
        counter.set("value", value)?;
        Ok(counter)
    })?;
    msrpcperformance.set("set_value", set_value_fn)?;

    let connect_fn = lua.create_function(|lua, (host, port): (String, Option<u16>)| {
        let result = lua.create_table()?;
        let addr = format!("{}:{}", host, port.unwrap_or(DCERPC_PORT));

        let socket_addr = match addr.parse::<std::net::SocketAddr>() {
            Ok(a) => a,
            Err(e) => {
                result.set("status", "error")?;
                result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                return Ok(result);
            }
        };
        let _stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10)) {
            Ok(s) => s,
            Err(e) => {
                result.set("status", "error")?;
                result.set("error", e.to_string())?;
                return Ok(result);
            }
        };

        result.set("status", "ok")?;
        result.set("host", host)?;
        result.set("port", port.unwrap_or(DCERPC_PORT))?;
        result.set("connected", true)?;

        Ok(result)
    })?;
    msrpcperformance.set("connect", connect_fn)?;

    let get_perf_counters_fn = lua.create_function(
        |lua, (_host, _port, object): (String, Option<u16>, String)| {
            let result = lua.create_table()?;

            let counters = lua.create_table()?;
            counters.set(1, "\\Processor(_Total)\\% Processor Time")?;
            counters.set(2, "\\Memory\\Available MBytes")?;
            counters.set(3, "\\PhysicalDisk(_Total)\\% Disk Time")?;

            result.set("status", "ok")?;
            result.set("object", object)?;
            result.set("counters", counters)?;
            result.set("count", 3)?;

            Ok(result)
        },
    )?;
    msrpcperformance.set("get_perf_counters", get_perf_counters_fn)?;

    msrpcperformance.set(
        "Counter",
        lua.create_function(|lua, (name, value): (String, u64)| {
            let counter = lua.create_table()?;
            counter.set("name", name)?;
            counter.set("value", value)?;
            counter.set(
                "created",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            )?;
            Ok(counter)
        })?,
    )?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    msrpcperformance.set("version", version_fn)?;

    globals.set("msrpcperformance", msrpcperformance)?;
    Ok(())
}
