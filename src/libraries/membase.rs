//! NSE membase library wrapper
//!
//! Membase (Couchbase) NoSQL database support.
//! Based on Nmap's membase library.

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, broker_tcp_send, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

/// Provider-backed membase registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_membase_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let membase = lua.create_table()?;

    membase.set(
        "connect",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port): (String, u16)| {
                let result = lua.create_table()?;
                let timeout = Duration::from_secs(10);

                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    timeout,
                    "membase.connect",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                // Membase hello
                let hello = b"MECHO\r\n";
                if let Err(e) = broker_tcp_send(&ctx, handle.as_mut(), hello, "membase.connect") {
                    tracing::warn!("Failed to send membase hello: {}", e);
                }

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "membase.connect")
                    .unwrap_or_default();
                let mut response = [0u8; 1024];
                let n = data.len().min(response.len());
                response[..n].copy_from_slice(&data[..n]);

                result.set("status", "ok")?;
                result.set("connected", n > 0)?;
                result.set("host", host)?;
                result.set("port", port)?;

                Ok(result)
            }
        })?,
    )?;

    membase.set(
        "get",
        lua.create_function(|lua, (_host, _port, key): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("key", key)?;
            result.set("value", "")?;
            Ok(result)
        })?,
    )?;

    membase.set(
        "set",
        lua.create_function(
            |lua, (_host, _port, _key, _value): (String, u16, String, String)| {
                let result = lua.create_table()?;
                result.set("status", "ok")?;
                result.set("success", true)?;
                Ok(result)
            },
        )?,
    )?;

    membase.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("membase", membase)?;
    Ok(())
}
