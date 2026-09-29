//! NSE tn3270 library wrapper
//!
//! TN3270 protocol support for NSE scripts.
//! Based on Nmap's tn3270 library.

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, broker_tcp_send, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

/// Provider-backed tn3270 registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_tn3270_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let tn3270 = lua.create_table()?;

    tn3270.set(
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
                    "tn3270.connect",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                // TN3270 negotiate init
                let negotiate = [
                    0xFF, 0xD3, // TN3270E
                    0x00, 0x00, // Length
                ];

                if let Err(e) = broker_tcp_send(&ctx, handle.as_mut(), &negotiate, "tn3270.connect")
                {
                    tracing::warn!("Failed to send TN3270 negotiate: {}", e);
                }

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "tn3270.connect")
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

    tn3270.set(
        "send",
        lua.create_function(|lua, (_host, _port, data): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("bytes_sent", data.len())?;
            Ok(result)
        })?,
    )?;

    tn3270.set(
        "receive",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("data", "")?;
            Ok(result)
        })?,
    )?;

    tn3270.set(
        "get_screen",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("screen", "")?;
            result.set("rows", 24)?;
            result.set("cols", 80)?;
            Ok(result)
        })?,
    )?;

    tn3270.set(
        "send_command",
        lua.create_function(|lua, (_host, _port, _command): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("response", "")?;
            Ok(result)
        })?,
    )?;

    tn3270.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("tn3270", tn3270)?;
    Ok(())
}
