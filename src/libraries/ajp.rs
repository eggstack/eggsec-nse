//! NSE ajp library wrapper
//!
//! AJP (Apache JServ Protocol) library for Apache mod_proxy_ajp.
//! Based on Nmap's ajp library concepts.

use crate::brokered_stream::{broker_read_into, broker_write_all};
use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, NseHostServices};
use mlua::{Lua, Result as LuaResult, Table};
use std::time::Duration;

const AJP_PORT: u16 = 8009;

fn build_ajp_request(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut packet = Vec::new();

    packet.push(0x12);
    packet.push(0x34);

    let mut data = Vec::new();

    data.push(0x02);
    data.push(method.len() as u8);
    data.extend_from_slice(method.as_bytes());

    data.push(0x02);
    data.extend_from_slice(path.as_bytes());
    data.push(0x00);

    for (key, value) in headers {
        data.push(0x0A);
        data.extend_from_slice(key.as_bytes());
        data.push(0x00);
        data.extend_from_slice(value.as_bytes());
        data.push(0x00);
    }

    data.push(0xFF);

    if !body.is_empty() {
        data.extend_from_slice(body.as_bytes());
    }

    let len = data.len() as u16;
    packet.extend_from_slice(&len.to_be_bytes());
    packet.extend_from_slice(&data);

    packet
}

/// Provider-backed ajp registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_ajp_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let ajp = lua.create_table()?;

    let new_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let a = lua.create_table()?;
        a.set("host", host)?;
        a.set("port", port)?;
        a.set("timeout", 5i64)?;
        Ok(a)
    })?;
    ajp.set("new", new_fn)?;

    let connect_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port): (String, u16)| {
            let result = lua.create_table()?;

            // Reachability + banner probe through the broker
            // (authority-preserving resolve replaces the
            // literal-parse-plus-loopback-fallback).
            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port,
                Duration::from_secs(5),
                "ajp.connect",
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                    return Ok(result);
                }
            };
            let _ = handle.set_timeouts(Duration::from_secs(5));

            let request = build_ajp_request("GET", "/", &[], "");

            if let Err(e) = broker_write_all(&ctx, handle.as_mut(), &request, "ajp.connect") {
                result.set("success", false)?;
                result.set("error", format!("Send failed: {}", e))?;
                return Ok(result);
            }

            let mut response = [0u8; 4096];
            match broker_read_into(&ctx, handle.as_mut(), &mut response, "ajp.connect") {
                Ok(n) => {
                    if n > 0 {
                        result.set("success", true)?;
                        result.set("status", "connected")?;
                    } else {
                        result.set("success", true)?;
                        result.set("status", "connected")?;
                    }
                }
                Err(_) => {
                    result.set("success", true)?;
                    result.set("status", "connected")?;
                }
            }

            Ok(result)
        }
    })?;
    ajp.set("connect", connect_fn)?;

    let request_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua,
              (host, port, method, path, headers, body): (
            String,
            u16,
            String,
            String,
            Option<Table>,
            Option<String>,
        )| {
            let result = lua.create_table()?;

            let header_vec: Vec<(String, String)> = if let Some(h) = headers {
                let mut v = Vec::new();
                for (k, val) in h.pairs::<String, String>().flatten() {
                    v.push((k.clone(), val.clone()));
                }
                v
            } else {
                vec![(host.clone(), host.clone())]
            };

            let body_str = body.unwrap_or_default();

            let header_refs: Vec<(&str, &str)> = header_vec
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();

            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port,
                Duration::from_secs(5),
                "ajp.request",
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                    return Ok(result);
                }
            };
            let _ = handle.set_timeouts(Duration::from_secs(10));

            let request = build_ajp_request(&method, &path, &header_refs, &body_str);

            if let Err(e) = broker_write_all(&ctx, handle.as_mut(), &request, "ajp.request") {
                result.set("success", false)?;
                result.set("error", format!("Send failed: {}", e))?;
                return Ok(result);
            }

            let mut response = [0u8; 8192];
            match broker_read_into(&ctx, handle.as_mut(), &mut response, "ajp.request") {
                Ok(n) => {
                    result.set("success", true)?;
                    result.set("method", method)?;
                    result.set("path", path)?;
                    result.set("bytes", n)?;
                }
                Err(e) => {
                    result.set("success", true)?;
                    result.set("note", format!("Request sent, read failed: {}", e))?;
                }
            }

            Ok(result)
        }
    })?;
    ajp.set("request", request_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    ajp.set("version", version_fn)?;

    // Async connect probe: previously bridged `AsyncTcpStream` through the
    // ambient runtime. Rewired to the brokered sync probe (entry name kept).
    let async_connect_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port): (String, u16)| {
            let result = lua.create_table()?;
            let port = if port == 0 { AJP_PORT } else { port };

            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port,
                Duration::from_secs(5),
                "ajp.connect_async",
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                    return Ok(result);
                }
            };

            let request = build_ajp_request("GET", "/", &[], "");

            if let Err(e) = broker_write_all(&ctx, handle.as_mut(), &request, "ajp.connect_async") {
                result.set("success", false)?;
                result.set("error", format!("Send failed: {}", e))?;
                return Ok(result);
            }

            let mut response = [0u8; 4096];
            match broker_read_into(&ctx, handle.as_mut(), &mut response, "ajp.connect_async") {
                Ok(n) => {
                    if n > 0 {
                        result.set("success", true)?;
                        result.set("status", "connected")?;
                    } else {
                        result.set("success", true)?;
                        result.set("status", "connected")?;
                    }
                }
                Err(_) => {
                    result.set("success", true)?;
                    result.set("status", "connected")?;
                }
            }

            Ok(result)
        }
    })?;
    ajp.set("connect_async", async_connect_fn)?;

    // Async request: previously bridged `AsyncTcpStream` through the ambient
    // runtime. Rewired to the brokered sync path (entry name kept).
    let async_request_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua,
              (host, port, method, path, headers, body): (
            String,
            u16,
            String,
            String,
            Option<Table>,
            Option<String>,
        )| {
            let result = lua.create_table()?;
            let port = if port == 0 { AJP_PORT } else { port };

            let header_vec: Vec<(String, String)> = if let Some(h) = headers {
                let mut v = Vec::new();
                for (k, val) in h.pairs::<String, String>().flatten() {
                    v.push((k.clone(), val.clone()));
                }
                v
            } else {
                vec![(host.clone(), host.clone())]
            };

            let body_str = body.unwrap_or_default();

            let header_refs: Vec<(&str, &str)> = header_vec
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();

            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port,
                Duration::from_secs(5),
                "ajp.request_async",
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                    return Ok(result);
                }
            };

            let request = build_ajp_request(&method, &path, &header_refs, &body_str);

            if let Err(e) = broker_write_all(&ctx, handle.as_mut(), &request, "ajp.request_async") {
                result.set("success", false)?;
                result.set("error", format!("Send failed: {}", e))?;
                return Ok(result);
            }

            let mut response = [0u8; 8192];
            match broker_read_into(&ctx, handle.as_mut(), &mut response, "ajp.request_async") {
                Ok(n) => {
                    result.set("success", true)?;
                    result.set("method", method)?;
                    result.set("path", path)?;
                    result.set("bytes", n)?;
                }
                Err(e) => {
                    result.set("success", true)?;
                    result.set("note", format!("Request sent, read failed: {}", e))?;
                }
            }

            Ok(result)
        }
    })?;
    ajp.set("request_async", async_request_fn)?;

    globals.set("ajp", ajp)?;
    Ok(())
}
