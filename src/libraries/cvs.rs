//! NSE cvs library wrapper
//!
//! CVS (Concurrent Versions System) server support.
//! Based on Nmap's cvs library.

use crate::brokered_stream::broker_send_all;
use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

/// Provider-backed cvs registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_cvs_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let cvs = lua.create_table()?;

    cvs.set(
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
                    "cvs.connect",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };
                let _ = broker_send_all(
                    &ctx,
                    handle.as_mut(),
                    b"BEGIN AUTH REQUEST\n/root\nEND AUTH REQUEST\n",
                    "cvs.connect",
                );
                let data = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "cvs.connect")
                    .unwrap_or_default();
                let n = data.len();
                result.set("status", "ok")?;
                result.set("connected", n > 0)?;
                Ok(result)
            }
        })?,
    )?;

    cvs.set(
        "authenticate",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, username, password): (String, u16, String, String)| {
                let result = lua.create_table()?;
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "cvs.authenticate",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                let request = format!(
                    "BEGIN AUTH REQUEST\n{}\n{}\nEND AUTH REQUEST\n",
                    username, password
                );
                let _ = broker_send_all(
                    &ctx,
                    handle.as_mut(),
                    request.as_bytes(),
                    "cvs.authenticate",
                );

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "cvs.authenticate")
                    .unwrap_or_default();
                let response_str = String::from_utf8_lossy(&data);

                if response_str.contains("I LOVE YOU") {
                    result.set("status", "ok")?;
                    result.set("authenticated", true)?;
                } else {
                    result.set("status", "ok")?;
                    result.set("authenticated", false)?;
                    result.set("error", "Authentication failed")?;
                }

                Ok(result)
            }
        })?,
    )?;

    cvs.set(
        "send_request",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, request): (String, u16, String)| {
                let result = lua.create_table()?;
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "cvs.send_request",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                let _ = broker_send_all(
                    &ctx,
                    handle.as_mut(),
                    request.as_bytes(),
                    "cvs.send_request",
                );

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 4096, "cvs.send_request")
                    .unwrap_or_default();

                result.set("status", "ok")?;
                result.set("response", String::from_utf8_lossy(&data).to_string())?;

                Ok(result)
            }
        })?,
    )?;

    cvs.set(
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
                    "cvs.list_modules",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                let _ = broker_send_all(&ctx, handle.as_mut(), b"VALIDATE\n", "cvs.list_modules");
                let _ = broker_send_all(&ctx, handle.as_mut(), b"REPOSITORY\n", "cvs.list_modules");
                let _ = broker_send_all(&ctx, handle.as_mut(), b"END\n", "cvs.list_modules");

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 4096, "cvs.list_modules")
                    .unwrap_or_default();

                let modules = lua.create_table()?;
                let response_str = String::from_utf8_lossy(&data);

                for (i, line) in response_str.lines().enumerate() {
                    if !line.is_empty() && !line.starts_with('E') && !line.starts_with('o') {
                        modules.set(i + 1, line.to_string())?;
                    }
                }

                result.set("status", "ok")?;
                result.set("modules", modules)?;

                Ok(result)
            }
        })?,
    )?;

    cvs.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("cvs", cvs)?;
    Ok(())
}
