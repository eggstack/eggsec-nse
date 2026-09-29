//! NSE whois library wrapper
//!
//! WHOIS protocol support for NSE scripts.
//! Includes both blocking and async implementations.

use crate::brokered_stream::{broker_read_into, broker_write_all};
use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

/// Provider-backed whois registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_whois_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let whois = lua.create_table()?;

    let whois_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, query): (String, String)| {
            // The broker resolves `host` (authority-preserving) on the fixed
            // whois port; failures keep the original error-table shape.
            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                43,
                Duration::from_secs(10),
                "whois.whois",
            ) {
                Ok(pair) => pair,
                Err(_) => {
                    let result = lua.create_table()?;
                    result.set("error", "Connection failed")?;
                    return Ok(result);
                }
            };

            let _ = handle.set_timeouts(Duration::from_secs(10));

            let _ = broker_write_all(
                &ctx,
                handle.as_mut(),
                format!("{}\r\n", query).as_bytes(),
                "whois.whois",
            );

            let mut response = vec![0u8; 16384];
            let n =
                broker_read_into(&ctx, handle.as_mut(), &mut response, "whois.whois").unwrap_or(0);

            let result = lua.create_table()?;
            if n > 0 {
                result.set(
                    "response",
                    String::from_utf8_lossy(&response[..n]).to_string(),
                )?;
            } else {
                result.set("response", "")?;
            }

            Ok(result)
        }
    })?;
    whois.set("whois", whois_fn)?;

    let parse_whois_fn = lua.create_function(|lua, response: String| {
        let result = lua.create_table()?;

        let fields = lua.create_table()?;

        for line in response.lines() {
            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                if !key.is_empty() && !value.is_empty() {
                    fields.set(key, value)?;
                }
            }
        }

        result.set("fields", fields)?;

        Ok(result)
    })?;
    whois.set("parse_whois", parse_whois_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    whois.set("version", version_fn)?;

    // Async lookup: previously bridged `AsyncTcpStream` through a throwaway
    // runtime. Rewired to the brokered sync path (entry name kept).
    let async_whois_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, query): (String, String)| {
            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                43,
                Duration::from_secs(10),
                "whois.whois_async",
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    let r = lua.create_table()?;
                    r.set("error", e)?;
                    return Ok(r);
                }
            };

            let query_with_newline = format!("{}\r\n", query);
            let _ = broker_write_all(
                &ctx,
                handle.as_mut(),
                query_with_newline.as_bytes(),
                "whois.whois_async",
            );

            let mut buffer = vec![0u8; 8192];
            let n = broker_read_into(&ctx, handle.as_mut(), &mut buffer, "whois.whois_async")
                .unwrap_or(0);

            let response = String::from_utf8_lossy(&buffer[..n]).to_string();

            let result = lua.create_table()?;
            result.set("response", response)?;
            result.set("host", host)?;
            Ok(result)
        }
    })?;
    whois.set("whois_async", async_whois_fn)?;

    globals.set("whois", whois)?;
    Ok(())
}
