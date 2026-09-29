//! NSE socks library wrapper
//!
//! SOCKS proxy protocol support for NSE scripts.
//! Based on Nmap's socks library.

use crate::brokered_stream::broker_send_all;
use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

/// Provider-backed socks registration.
///
/// `services` backs every TCP connect/send/receive path. Note the proxied
/// second hop (`target_host`/`target_port`) travels as bytes inside the
/// brokered proxy connection — no additional direct network effect.
pub fn register_socks_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let socks = lua.create_table()?;

    socks.set(
        "connect",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, target_host, target_port): (String, u16, String, u16)| {
                let result = lua.create_table()?;

                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused proxies keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "socks.connect",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                // SOCKS5 greeting
                let greeting = vec![
                    0x05, // Version
                    0x01, // Number of methods
                    0x00, // No authentication
                ];

                broker_send_all(&ctx, handle.as_mut(), &greeting, "socks.connect").map_err(
                    |e| mlua::Error::RuntimeError(format!("SOCKS5 greeting write failed: {}", e)),
                )?;

                let mut response = [0u8; 2];
                if broker_tcp_receive(&ctx, handle.as_mut(), response.len(), "socks.connect")
                    .map(|data| {
                        let n = data.len().min(response.len());
                        response[..n].copy_from_slice(&data[..n]);
                    })
                    .is_err()
                {
                    result.set("status", "error")?;
                    result.set("error", "Failed to read SOCKS5 greeting response")?;
                    return Ok(result);
                }

                if response[1] == 0x00 {
                    // SOCKS5 connect request
                    let mut request = vec![
                        0x05, // Version
                        0x01, // Connect command
                        0x00, // Reserved
                    ];

                    // Add domain
                    request.push(0x03); // Domain
                    request.push(target_host.len() as u8);
                    request.extend_from_slice(target_host.as_bytes());
                    request.extend_from_slice(&target_port.to_be_bytes());

                    broker_send_all(&ctx, handle.as_mut(), &request, "socks.connect").map_err(
                        |e| {
                            mlua::Error::RuntimeError(format!("SOCKS5 request write failed: {}", e))
                        },
                    )?;

                    let mut reply = [0u8; 10];
                    if broker_tcp_receive(&ctx, handle.as_mut(), reply.len(), "socks.connect")
                        .map(|data| {
                            let n = data.len().min(reply.len());
                            reply[..n].copy_from_slice(&data[..n]);
                        })
                        .is_err()
                    {
                        result.set("status", "error")?;
                        result.set("error", "Failed to read SOCKS5 connect reply")?;
                        return Ok(result);
                    }

                    if reply[0] == 0x05 && reply[1] == 0x00 {
                        result.set("status", "ok")?;
                        result.set("connected", true)?;
                    } else {
                        result.set("status", "error")?;
                    }
                } else {
                    result.set("status", "error")?;
                    result.set("error", "Authentication failed")?;
                }

                Ok(result)
            }
        })?,
    )?;

    socks.set(
        "auth_methods",
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
                    "socks.auth_methods",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                // SOCKS5 greeting
                broker_send_all(
                    &ctx,
                    handle.as_mut(),
                    &[0x05, 0x02, 0x00, 0x02],
                    "socks.auth_methods",
                )
                .map_err(|e| {
                    mlua::Error::RuntimeError(format!("SOCKS5 greeting write failed: {}", e))
                })?;

                let mut response = [0u8; 2];
                if broker_tcp_receive(&ctx, handle.as_mut(), response.len(), "socks.auth_methods")
                    .map(|data| {
                        let n = data.len().min(response.len());
                        response[..n].copy_from_slice(&data[..n]);
                    })
                    .is_err()
                {
                    result.set("status", "error")?;
                    result.set("error", "Failed to read SOCKS5 auth response")?;
                    return Ok(result);
                }

                let methods = lua.create_table()?;
                if response[1] == 0x00 {
                    methods.set(1, "no_auth")?;
                }
                if response[1] == 0x02 {
                    methods.set(2, "gssapi")?;
                }

                result.set("status", "ok")?;
                result.set("methods", methods)?;

                Ok(result)
            }
        })?,
    )?;

    socks.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("socks", socks)?;
    Ok(())
}
