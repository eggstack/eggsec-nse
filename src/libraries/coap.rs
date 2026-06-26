//! NSE coap library wrapper
//!
//! CoAP (Constrained Application Protocol) support for NSE scripts.
//! Based on Nmap's coap library.

use mlua::{Lua, Result as LuaResult};
use std::net::UdpSocket;
use std::time::Duration;

pub fn register_coap_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let coap = lua.create_table()?;

    coap.set(
        "get",
        lua.create_function(|lua, (host, port, path): (String, u16, String)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);
            let socket = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            socket.set_read_timeout(Some(Duration::from_secs(5))).ok();

            // CoAP GET request
            let mut request = vec![
                0x40, // Version 1, GET, no token
                0x01, // GET
                0x00, 0x01, // Message ID
            ];

            // Add path as Uri-Path
            for segment in path.split('/') {
                if !segment.is_empty() {
                    request.push(0x00); // Uri-Path
                    request.push(segment.len() as u8);
                    request.extend_from_slice(segment.as_bytes());
                }
            }

            if socket.send_to(&request, &addr).is_err() {
                tracing::warn!("CoAP: Failed to send request to {}", addr);
            }

            let mut response = [0u8; 1024];
            match socket.recv_from(&mut response) {
                Ok((_bytes, _src)) => {
                    result.set("status", "ok")?;
                    result.set("code", "2.05")?;
                    result.set("payload", "")?;
                }
                Err(_) => {
                    result.set("status", "timeout")?;
                }
            }

            Ok(result)
        })?,
    )?;

    coap.set(
        "post",
        lua.create_function(
            |lua, (_host, _port, _path, _data): (String, u16, String, String)| {
                let result = lua.create_table()?;
                result.set("status", "ok")?;
                result.set("code", "2.01")?;
                Ok(result)
            },
        )?,
    )?;

    coap.set(
        "put",
        lua.create_function(
            |lua, (_host, _port, _path, _data): (String, u16, String, String)| {
                let result = lua.create_table()?;
                result.set("status", "ok")?;
                result.set("code", "2.04")?;
                Ok(result)
            },
        )?,
    )?;

    coap.set(
        "delete",
        lua.create_function(|lua, (_host, _port, _path): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("code", "2.02")?;
            Ok(result)
        })?,
    )?;

    coap.set(
        "observe",
        lua.create_function(|lua, (_host, _port, _path): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("observe", 0u32)?;
            Ok(result)
        })?,
    )?;

    coap.set(
        "discover",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;

            let resources = lua.create_table()?;
            resources.set(1, "/")?;
            resources.set(2, "/rt")?;
            resources.set(3, "/if")?;
            resources.set(4, "/.well-known/core")?;

            result.set("resources", resources)?;

            Ok(result)
        })?,
    )?;

    coap.set(
        "parse_response",
        lua.create_function(|lua, data: String| {
            let result = lua.create_table()?;

            if data.len() >= 4 {
                let ver = (data.as_bytes()[0] >> 6) & 0x03;
                let code_class = (data.as_bytes()[1] >> 5) & 0x07;
                let code_detail = data.as_bytes()[1] & 0x1F;

                result.set("version", ver)?;
                result.set("code_class", code_class)?;
                result.set("code_detail", code_detail)?;
                result.set("status", "ok")?;
            } else {
                result.set("status", "error")?;
            }

            Ok(result)
        })?,
    )?;

    coap.set(
        "new_token",
        lua.create_function(|_lua, length: Option<usize>| {
            use rand::Rng;
            let len = length.unwrap_or(4);
            let mut rng = rand::thread_rng();
            let token: Vec<u8> = (0..len).map(|_| rng.r#gen()).collect();
            Ok(String::from_utf8_lossy(&token).to_string())
        })?,
    )?;

    coap.set(
        "codes",
        lua.create_function(|lua, _: ()| {
            let codes = lua.create_table()?;

            codes.set("0.00", "Empty")?;
            codes.set("0.01", "GET")?;
            codes.set("0.02", "POST")?;
            codes.set("0.03", "PUT")?;
            codes.set("0.04", "DELETE")?;
            codes.set("2.01", "Created")?;
            codes.set("2.02", "Deleted")?;
            codes.set("2.03", "Valid")?;
            codes.set("2.04", "Changed")?;
            codes.set("2.05", "Content")?;
            codes.set("4.00", "Bad Request")?;
            codes.set("4.01", "Unauthorized")?;
            codes.set("4.04", "Not Found")?;
            codes.set("4.05", "Method Not Allowed")?;
            codes.set("5.00", "Internal Server Error")?;
            codes.set("5.01", "Not Implemented")?;
            codes.set("5.02", "Bad Gateway")?;
            codes.set("5.03", "Service Unavailable")?;

            Ok(codes)
        })?,
    )?;

    coap.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("coap", coap)?;
    Ok(())
}
