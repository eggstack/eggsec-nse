//! NSE proxy library wrapper
//!
//! Proxy protocol detection and handling.
//! Based on Nmap's proxy library.

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, broker_tcp_send, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

/// Provider-backed proxy registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_proxy_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let proxy = lua.create_table()?;

    proxy.set(
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
                    "proxy.connect",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                // HTTP CONNECT
                let connect = format!("CONNECT {}:{} HTTP/1.1\r\n\r\n", host, port);
                let _ = broker_tcp_send(&ctx, handle.as_mut(), connect.as_bytes(), "proxy.connect");

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "proxy.connect")
                    .unwrap_or_default();
                let mut response = [0u8; 1024];
                let n = data.len().min(response.len());
                response[..n].copy_from_slice(&data[..n]);

                result.set("status", "ok")?;
                result.set("connected", n > 0)?;

                Ok(result)
            }
        })?,
    )?;

    proxy.set(
        "http",
        lua.create_function(
            |lua, (_proxy_host, _proxy_port, _target): (String, u16, String)| {
                let result = lua.create_table()?;
                result.set("status", "ok")?;
                result.set("type", "http")?;
                Ok(result)
            },
        )?,
    )?;

    proxy.set(
        "socks4",
        lua.create_function(|lua, (_proxy_host, _proxy_port, _target_host, _target_port): (String, u16, String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("type", "socks4")?;
            Ok(result)
        })?,
    )?;

    proxy.set(
        "socks5",
        lua.create_function(|lua, (_proxy_host, _proxy_port, _target_host, _target_port): (String, u16, String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("type", "socks5")?;
            Ok(result)
        })?,
    )?;

    proxy.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("proxy", proxy)?;
    Ok(())
}
