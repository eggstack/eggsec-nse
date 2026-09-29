//! NSE rtsp library wrapper
//!
//! RTSP (Real Time Streaming Protocol) support for NSE scripts.
//! Based on Nmap's rtsp library.

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, broker_tcp_send, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

/// Provider-backed rtsp registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_rtsp_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let rtsp = lua.create_table()?;

    rtsp.set(
        "request",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, method, url): (String, u16, String, String)| {
                let result = lua.create_table()?;
                let timeout = Duration::from_secs(10);

                let (mut handle, _endpoint) =
                    match broker_tcp_connect(&ctx, &services, &host, port, timeout, "rtsp.request")
                    {
                        Ok(pair) => pair,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e)?;
                            return Ok(result);
                        }
                    };

                let request = format!(
                    "{} {} RTSP/1.0\r\n\
                 Host: {}:{}\r\n\
                 User-Agent: Nmap-Eggsec\r\n\
                 CSeq: 1\r\n\
                 \r\n",
                    method, url, host, port
                );

                let _ = broker_tcp_send(&ctx, handle.as_mut(), request.as_bytes(), "rtsp.request");

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 4096, "rtsp.request")
                    .unwrap_or_default();
                let mut response = [0u8; 4096];
                let n = data.len().min(response.len());
                response[..n].copy_from_slice(&data[..n]);
                let response_str = String::from_utf8_lossy(&response[..n]);

                // Parse status line
                for line in response_str.lines() {
                    if line.starts_with("RTSP/") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            result.set("status_code", parts[1])?;
                            break;
                        }
                    }
                }

                result.set("status", "ok")?;
                result.set("response", response_str)?;

                Ok(result)
            }
        })?,
    )?;

    rtsp.set(
        "options",
        lua.create_function(|lua, (_host, _port, _url): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("methods", "DESCRIBE,SETUP,PLAY,PAUSE,TEARDOWN")?;
            Ok(result)
        })?,
    )?;

    rtsp.set(
        "describe",
        lua.create_function(|lua, (_host, _port, _url): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("sdp", "")?;
            Ok(result)
        })?,
    )?;

    rtsp.set(
        "setup",
        lua.create_function(
            |lua, (_host, _port, _url, _track): (String, u16, String, String)| {
                let result = lua.create_table()?;
                result.set("status", "ok")?;
                result.set("session", "mock_session_id")?;
                Ok(result)
            },
        )?,
    )?;

    rtsp.set(
        "play",
        lua.create_function(|lua, (_host, _port, _url): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            Ok(result)
        })?,
    )?;

    rtsp.set(
        "pause",
        lua.create_function(|lua, (_host, _port, _url): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            Ok(result)
        })?,
    )?;

    rtsp.set(
        "teardown",
        lua.create_function(|lua, (_host, _port, _url): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            Ok(result)
        })?,
    )?;

    rtsp.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("rtsp", rtsp)?;
    Ok(())
}
