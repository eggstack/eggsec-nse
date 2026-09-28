//! NSE comm library wrapper
//!
//! Provides low-level socket communication for banner grabbing and data exchange.
//!
//! M005B: `get_banner`/`exchange` (and their async-named variants) go through
//! the authority-preserving provider broker. `tryssl` performs HTTPS via
//! `reqwest` and is explicitly deferred to the 005C HTTP provider.

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, broker_tcp_send, NseHostServices};
use crate::wrappers;
use mlua::{Lua, Result as LuaResult, Table};
use std::time::Duration;

pub fn register_comm_library(lua: &Lua, capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    register_comm_library_with_services(lua, capability_ctx, &NseHostServices::native())
}

/// Provider-backed comm registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_comm_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();

    let capability_ctx = capability_ctx.clone();
    let services = services.clone();

    let comm = lua.create_table()?;

    comm.set(
        "get_banner",
        lua.create_function({
            let capability_ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, _options): (String, u16, Option<Table>)| {
                let result = lua.create_table()?;
                let timeout = Duration::from_secs(5);

                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &capability_ctx,
                    &services,
                    &host,
                    port,
                    timeout,
                    "comm.get_banner",
                ) {
                    Ok(pair) => pair,
                    Err(_) => {
                        result.set("data", "")?;
                        return Ok(result);
                    }
                };

                std::thread::sleep(Duration::from_millis(500));

                match broker_tcp_receive(&capability_ctx, handle.as_mut(), 4096, "comm.get_banner")
                {
                    Ok(data) => {
                        result.set("data", String::from_utf8_lossy(&data).to_string())?;
                    }
                    Err(_) => {
                        result.set("data", "")?;
                    }
                }
                Ok(result)
            }
        })?,
    )?;

    comm.set(
        "exchange",
        lua.create_function({
            let capability_ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, data, _options): (String, u16, String, Option<Table>)| {
                let result = lua.create_table()?;
                let timeout = Duration::from_secs(5);

                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &capability_ctx,
                    &services,
                    &host,
                    port,
                    timeout,
                    "comm.exchange",
                ) {
                    Ok(pair) => pair,
                    Err(_) => {
                        result.set("data", "")?;
                        return Ok(result);
                    }
                };

                if broker_tcp_send(
                    &capability_ctx,
                    handle.as_mut(),
                    data.as_bytes(),
                    "comm.exchange",
                )
                .is_err()
                {
                    result.set("data", "")?;
                    return Ok(result);
                }

                std::thread::sleep(Duration::from_millis(500));

                match broker_tcp_receive(&capability_ctx, handle.as_mut(), 4096, "comm.exchange") {
                    Ok(response) => {
                        result.set("data", String::from_utf8_lossy(&response).to_string())?;
                    }
                    Err(_) => {
                        result.set("data", "")?;
                    }
                }
                Ok(result)
            }
        })?,
    )?;

    comm.set(
        "tryssl",
        lua.create_function({
            let capability_ctx = capability_ctx.clone();
            move |lua, (host, port, _data, _options): (String, u16, String, Option<Table>)| {
                let decision = wrappers::check_dns(&capability_ctx, &host, "comm.tryssl");
                if decision.is_denied() {
                    let result = lua.create_table()?;
                    result.set("status", 0i32)?;
                    result.set("data", "DNS resolution denied by capability policy")?;
                    return Ok(result);
                }

                let url = format!("https://{}:{}", host, port);
                let insecure_tls = capability_ctx.allows_insecure_tls();

                // M005B residual: HTTPS probing stays on reqwest until the
                // 005C HTTP provider lands (see docs/PROVIDERS.md inventory).
                let client = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .danger_accept_invalid_certs(insecure_tls)
                    .build();

                match client {
                    Ok(c) => match c.get(&url).send() {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let result = lua.create_table()?;
                            result.set("status", status as i32)?;
                            match resp.text() {
                                Ok(body) => {
                                    result.set("data", body)?;
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "comm.tryssl body read failed for {}: {}",
                                        url,
                                        e
                                    );
                                    result.set("data", "")?;
                                    result.set("error", format!("body read failed: {}", e))?;
                                }
                            }
                            Ok(result)
                        }
                        Err(e) => {
                            let result = lua.create_table()?;
                            result.set("status", 0i32)?;
                            result.set("data", e.to_string())?;
                            Ok(result)
                        }
                    },
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("status", 0i32)?;
                        result.set("data", e.to_string())?;
                        Ok(result)
                    }
                }
            }
        })?,
    )?;

    comm.set("close", lua.create_function(|_, _socket: Table| Ok(()))?)?;

    comm.set(
        "get_banner_async",
        lua.create_function({
            let capability_ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, _options): (String, u16, Option<Table>)| {
                let result = lua.create_table()?;
                let timeout = Duration::from_secs(5);

                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &capability_ctx,
                    &services,
                    &host,
                    port,
                    timeout,
                    "comm.get_banner_async",
                ) {
                    Ok(pair) => pair,
                    Err(_) => {
                        result.set("data", "")?;
                        return Ok(result);
                    }
                };

                std::thread::sleep(Duration::from_millis(500));

                match broker_tcp_receive(
                    &capability_ctx,
                    handle.as_mut(),
                    4096,
                    "comm.get_banner_async",
                ) {
                    Ok(data) => {
                        result.set("data", String::from_utf8_lossy(&data).to_string())?;
                    }
                    Err(_) => {
                        result.set("data", "")?;
                    }
                }
                Ok(result)
            }
        })?,
    )?;

    comm.set(
        "exchange_async",
        lua.create_function({
            let capability_ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, data, _options): (String, u16, String, Option<Table>)| {
                let result = lua.create_table()?;
                let timeout = Duration::from_secs(5);

                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &capability_ctx,
                    &services,
                    &host,
                    port,
                    timeout,
                    "comm.exchange_async",
                ) {
                    Ok(pair) => pair,
                    Err(_) => {
                        result.set("data", "")?;
                        return Ok(result);
                    }
                };

                if broker_tcp_send(
                    &capability_ctx,
                    handle.as_mut(),
                    data.as_bytes(),
                    "comm.exchange_async",
                )
                .is_err()
                {
                    result.set("data", "")?;
                    return Ok(result);
                }

                std::thread::sleep(Duration::from_millis(500));

                match broker_tcp_receive(
                    &capability_ctx,
                    handle.as_mut(),
                    4096,
                    "comm.exchange_async",
                ) {
                    Ok(response) => {
                        result.set("data", String::from_utf8_lossy(&response).to_string())?;
                    }
                    Err(_) => {
                        result.set("data", "")?;
                    }
                }
                Ok(result)
            }
        })?,
    )?;

    globals.set("comm", comm)?;
    Ok(())
}
