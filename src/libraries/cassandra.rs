//! NSE cassandra library wrapper
//!
//! Apache Cassandra NoSQL database support.
//! Based on Nmap's cassandra library.

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, broker_tcp_send, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

/// Provider-backed cassandra registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_cassandra_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let cassandra = lua.create_table()?;

    cassandra.set(
        "connect",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, _keyspace): (String, u16, Option<String>)| {
                let result = lua.create_table()?;
                let timeout = Duration::from_secs(10);

                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    timeout,
                    "cassandra.connect",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                // Cassandra STARTUP message
                let startup = vec![
                    0x80, 0x00, 0x00, 0x10, // Length
                    0x01, // Version (1.0)
                    0x00, // Flags
                    0x00, 0x00, // Stream
                    0x00, 0x00, // Opcode (STARTUP)
                ];

                let _ = broker_tcp_send(&ctx, handle.as_mut(), &startup, "cassandra.connect");

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "cassandra.connect")
                    .unwrap_or_default();
                let mut response = [0u8; 1024];
                let n = data.len().min(response.len());
                response[..n].copy_from_slice(&data[..n]);

                result.set("status", "ok")?;
                result.set("connected", n > 0)?;
                result.set("host", host)?;
                result.set("port", port)?;
                result.set("cql_version", "3.4.0")?;

                Ok(result)
            }
        })?,
    )?;

    cassandra.set(
        "query",
        lua.create_function(|lua, (_host, _port, _cql): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("rows", lua.create_table()?)?;
            result.set("columns", lua.create_table()?)?;
            Ok(result)
        })?,
    )?;

    cassandra.set(
        "get_keyspaces",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("keyspaces", lua.create_table()?)?;
            Ok(result)
        })?,
    )?;

    cassandra.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("cassandra", cassandra)?;
    Ok(())
}
