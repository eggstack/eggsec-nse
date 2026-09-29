//! NSE rsync library wrapper
//!
//! Rsync protocol support for NSE scripts.
//! Based on Nmap's rsync library.

use crate::brokered_stream::broker_send_all;
use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

/// Provider-backed rsync registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_rsync_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let rsync = lua.create_table()?;

    rsync.set(
        "connect",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port): (String, u16)| {
                let result = lua.create_table()?;

                // The broker resolves `host` (authority-preserving); unresolvable
                // or refused hosts keep the original `status = "error"` shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "rsync.connect",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                // Rsync protocol greeting
                let greeting = b"@RSYNCD: 31.0\n";
                if broker_send_all(&ctx, handle.as_mut(), greeting, "rsync.connect").is_err() {
                    tracing::warn!("Failed to send rsync greeting");
                }

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "rsync.connect")
                    .unwrap_or_default();
                let response_str = String::from_utf8_lossy(&data);

                if response_str.starts_with("@RSYNCD:") {
                    result.set("status", "ok")?;
                    result.set("connected", true)?;
                    result.set("version", response_str.trim())?;
                } else {
                    result.set("status", "error")?;
                }

                Ok(result)
            }
        })?,
    )?;

    rsync.set(
        "list_modules",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port): (String, u16)| {
                let result = lua.create_table()?;

                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "rsync.list_modules",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                if broker_send_all(
                    &ctx,
                    handle.as_mut(),
                    b"@RSYNCD: 31.0\n",
                    "rsync.list_modules",
                )
                .is_err()
                {
                    tracing::warn!("Failed to send rsync greeting");
                }
                if broker_send_all(&ctx, handle.as_mut(), b"\n", "rsync.list_modules").is_err() {
                    tracing::warn!("Failed to send rsync newline");
                }

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 4096, "rsync.list_modules")
                    .unwrap_or_default();

                let modules = lua.create_table()?;
                let response_str = String::from_utf8_lossy(&data);

                let mut i = 1;
                for line in response_str.lines() {
                    if !line.starts_with('@') && !line.is_empty() {
                        if let Some(name) = line.split_whitespace().next() {
                            modules.set(i, name)?;
                            i += 1;
                        }
                    }
                }

                result.set("status", "ok")?;
                result.set("modules", modules)?;

                Ok(result)
            }
        })?,
    )?;

    rsync.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("rsync", rsync)?;
    Ok(())
}
