//! NSE oops library wrapper
//!
//! Out-Of-Band (OOB) data processing support.
//! Based on Nmap's oops library.

use crate::brokered_stream::broker_send_all;
use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, NseHostServices};
use mlua::{Lua, Result as LuaResult, Table};
use std::time::Duration;

/// Provider-backed oops registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_oops_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let oops = lua.create_table()?;

    oops.set(
        "send",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, data): (String, u16, String)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving); unresolvable
                // or refused hosts keep the original `status = "error"` shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(5),
                    "oops.send",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                match broker_send_all(&ctx, handle.as_mut(), data.as_bytes(), "oops.send") {
                    Ok(_) => {
                        result.set("status", "ok")?;
                        result.set("bytes_sent", data.len())?;
                    }
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                    }
                }

                Ok(result)
            }
        })?,
    )?;

    oops.set(
        "receive",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, timeout): (String, u16, Option<u32>)| {
                let result = lua.create_table()?;

                let timeout_dur = Duration::from_millis(timeout.unwrap_or(5000) as u64);

                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(5),
                    "oops.receive",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                if handle.set_timeouts(timeout_dur).is_err() {
                    tracing::warn!("Failed to set OOPS read timeout");
                }

                match broker_tcp_receive(&ctx, handle.as_mut(), 65536, "oops.receive") {
                    Ok(data) => {
                        result.set("status", "ok")?;
                        result.set("data", String::from_utf8_lossy(&data).to_string())?;
                        result.set("bytes_received", data.len())?;
                    }
                    Err(e) => {
                        // The broker surfaces timeouts as error strings (the
                        // `ErrorKind::TimedOut` distinction does not cross the
                        // provider boundary); match the timeout text to preserve
                        // the original `status = "timeout"` shape.
                        if e.contains("timed out") || e.contains("timeout") {
                            result.set("status", "timeout")?;
                            result.set("data", "")?;
                        } else {
                            result.set("status", "error")?;
                            result.set("error", e)?;
                        }
                    }
                }

                Ok(result)
            }
        })?,
    )?;

    oops.set(
        "send_and_receive",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, data, timeout): (String, u16, String, Option<u32>)| {
                let result = lua.create_table()?;

                let timeout_dur = Duration::from_millis(timeout.unwrap_or(5000) as u64);

                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(5),
                    "oops.send_and_receive",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                // The provider exposes a single read/write timeout.
                if handle.set_timeouts(timeout_dur).is_err() {
                    tracing::warn!("Failed to set OOPS timeout");
                }

                if let Err(e) = broker_send_all(
                    &ctx,
                    handle.as_mut(),
                    data.as_bytes(),
                    "oops.send_and_receive",
                ) {
                    result.set("status", "error")?;
                    result.set("error", e)?;
                    return Ok(result);
                }

                match broker_tcp_receive(&ctx, handle.as_mut(), 65536, "oops.send_and_receive") {
                    Ok(data) => {
                        result.set("status", "ok")?;
                        result.set("data", String::from_utf8_lossy(&data).to_string())?;
                        result.set("bytes_received", data.len())?;
                    }
                    Err(e) => {
                        if e.contains("timed out") || e.contains("timeout") {
                            result.set("status", "timeout")?;
                            result.set("data", "")?;
                        } else {
                            result.set("status", "error")?;
                            result.set("error", e)?;
                        }
                    }
                }

                Ok(result)
            }
        })?,
    )?;

    oops.set(
        "new",
        lua.create_function(|lua, (oob_type, data): (String, Option<String>)| {
            let pkt = lua.create_table()?;
            pkt.set("type", oob_type)?;
            pkt.set("data", data.unwrap_or_default())?;
            pkt.set(
                "timestamp",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            )?;
            Ok(pkt)
        })?,
    )?;

    oops.set(
        "set_data",
        lua.create_function(|_lua, (pkt, data): (Table, String)| {
            pkt.set("data", data)?;
            Ok(pkt)
        })?,
    )?;

    oops.set(
        "get_data",
        lua.create_function(|_lua, pkt: Table| pkt.get::<String>("data"))?,
    )?;

    oops.set(
        "set_type",
        lua.create_function(|_lua, (pkt, oob_type): (Table, String)| {
            pkt.set("type", oob_type)?;
            Ok(pkt)
        })?,
    )?;

    oops.set(
        "get_type",
        lua.create_function(|_lua, pkt: Table| pkt.get::<String>("type"))?,
    )?;

    oops.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("oops", oops)?;
    Ok(())
}
