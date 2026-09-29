//! NSE drda library wrapper
//!
//! DRDA (Distributed Relational Database Architecture) protocol support.
//! Based on Nmap's drda library.

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, broker_tcp_send, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

/// Provider-backed drda registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_drda_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let drda = lua.create_table()?;

    drda.set(
        "connect",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port): (String, u16)| {
                let result = lua.create_table()?;
                let timeout = Duration::from_secs(10);

                let (mut handle, _endpoint) =
                    match broker_tcp_connect(&ctx, &services, &host, port, timeout, "drda.connect")
                    {
                        Ok(pair) => pair,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e)?;
                            return Ok(result);
                        }
                    };

                // DRDA exchange attributes
                let excat = [
                    0xD0, 0x17, // Format
                    0x00, 0x00, 0x00, 0x2D, // Length
                    0x41, 0x41, 0x41,
                    0x41, // Correlation token
                          // DRDA parameters follow
                ];

                let _ = broker_tcp_send(&ctx, handle.as_mut(), &excat, "drda.connect");

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "drda.connect")
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

    drda.set(
        "parse_header",
        lua.create_function(|lua, data: String| {
            let result = lua.create_table()?;

            if data.len() >= 10 {
                let bytes = data.as_bytes();
                result.set("format", bytes[0])?;
                result.set("length", u16::from_be_bytes([bytes[2], bytes[3]]))?;
                result.set("codepoint", u16::from_be_bytes([bytes[8], bytes[9]]))?;
            }

            result.set("status", "ok")?;
            Ok(result)
        })?,
    )?;

    drda.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("drda", drda)?;
    Ok(())
}
