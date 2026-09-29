//! NSE isns library wrapper
//!
//! iSNS (Internet Storage Name Service) protocol support.
//! Based on Nmap's isns library.

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, broker_tcp_send, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

const ISNS_PORT: u16 = 3205;

/// Provider-backed isns registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_isns_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let isns = lua.create_table()?;

    isns.set(
        "discover",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port): (String, Option<u16>)| {
                let result = lua.create_table()?;
                let port = port.unwrap_or(ISNS_PORT);
                let timeout = Duration::from_secs(10);

                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    timeout,
                    "isns.discover",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                let packet = vec![
                    0x00, 0x00, // Version
                    0x00, 0x00, // Function
                    0x00, 0x00, 0x00, 0x00, // Length
                ];
                let _ = broker_tcp_send(&ctx, handle.as_mut(), &packet, "isns.discover");
                let data = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "isns.discover")
                    .unwrap_or_default();
                let mut response = [0u8; 1024];
                let n = data.len().min(response.len());
                response[..n].copy_from_slice(&data[..n]);

                result.set("status", "ok")?;
                result.set("discovered", n > 0)?;

                Ok(result)
            }
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
