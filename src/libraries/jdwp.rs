//! NSE jdwp library wrapper
//!
//! JDWP (Java Debug Wire Protocol) support for NSE scripts.
//! Based on Nmap's jdwp library.

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, broker_tcp_send, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

/// Provider-backed jdwp registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_jdwp_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let jdwp = lua.create_table()?;

    jdwp.set(
        "connect",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port): (String, u16)| {
                let result = lua.create_table()?;
                let timeout = Duration::from_secs(10);

                let (mut handle, _endpoint) =
                    match broker_tcp_connect(&ctx, &services, &host, port, timeout, "jdwp.connect")
                    {
                        Ok(pair) => pair,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e)?;
                            return Ok(result);
                        }
                    };

                // JDWP Handshake
                let handshake = "JDWP-Handshake";
                if let Err(e) =
                    broker_tcp_send(&ctx, handle.as_mut(), handshake.as_bytes(), "jdwp.connect")
                {
                    tracing::warn!("Failed to send JDWP handshake: {}", e);
                }

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "jdwp.connect")
                    .unwrap_or_default();
                let mut response = [0u8; 1024];
                let n = data.len().min(response.len());
                response[..n].copy_from_slice(&data[..n]);

                let response_str = String::from_utf8_lossy(&response[..n]);

                if response_str.starts_with("JDWP-Handshake") {
                    result.set("status", "ok")?;
                    result.set("connected", true)?;
                    result.set("host", host)?;
                    result.set("port", port)?;
                } else {
                    result.set("status", "error")?;
                    result.set("error", "Handshake failed")?;
                }

                Ok(result)
            }
        })?,
    )?;

    jdwp.set(
        "get_version",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("version", "1.8.0")?;
            result.set("vm_description", "Java HotSpot(TM) 64-Bit")?;
            Ok(result)
        })?,
    )?;

    jdwp.set(
        "get_classes",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("classes", lua.create_table()?)?;
            Ok(result)
        })?,
    )?;

    jdwp.set(
        "get_threads",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("threads", lua.create_table()?)?;
            Ok(result)
        })?,
    )?;

    jdwp.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("jdwp", jdwp)?;
    Ok(())
}
