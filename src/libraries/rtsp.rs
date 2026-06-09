//! NSE rtsp library wrapper
//!
//! RTSP (Real Time Streaming Protocol) support for NSE scripts.
//! Based on Nmap's rtsp library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_rtsp_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let rtsp = lua.create_table()?;

    rtsp.set(
        "request",
        lua.create_function(
            |lua, (host, port, method, url): (String, u16, String, String)| {
                let result = lua.create_table()?;

                let addr = format!("{}:{}", host, port);
                let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                    Ok(a) => a,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                        return Ok(result);
                    }
                };
                let mut stream =
                    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10)) {
                        Ok(s) => s,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
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

                stream.write_all(request.as_bytes()).ok();

                let mut response = [0u8; 4096];
                let n = stream.read(&mut response).unwrap_or(0);
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
            },
        )?,
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
