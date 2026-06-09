//! NSE cvs library wrapper
//!
//! CVS (Concurrent Versions System) server support.
//! Based on Nmap's cvs library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_cvs_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let cvs = lua.create_table()?;

    cvs.set(
        "connect",
        lua.create_function(|lua, (host, port): (String, u16)| {
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
            let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))
            {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };
            stream
                .write_all(b"BEGIN AUTH REQUEST\n/root\nEND AUTH REQUEST\n")
                .ok();
            let mut response = [0u8; 1024];
            let n = stream.read(&mut response).unwrap_or(0);
            result.set("status", "ok")?;
            result.set("connected", n > 0)?;
            Ok(result)
        })?,
    )?;

    cvs.set(
        "authenticate",
        lua.create_function(
            |lua, (host, port, username, password): (String, u16, String, String)| {
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
                    "BEGIN AUTH REQUEST\n{}\n{}\nEND AUTH REQUEST\n",
                    username, password
                );
                stream.write_all(request.as_bytes()).ok();

                let mut response = [0u8; 1024];
                let n = stream.read(&mut response).unwrap_or(0);
                let response_str = String::from_utf8_lossy(&response[..n]);

                if response_str.contains("I LOVE YOU") {
                    result.set("status", "ok")?;
                    result.set("authenticated", true)?;
                } else {
                    result.set("status", "ok")?;
                    result.set("authenticated", false)?;
                    result.set("error", "Authentication failed")?;
                }

                Ok(result)
            },
        )?,
    )?;

    cvs.set(
        "send_request",
        lua.create_function(|lua, (host, port, request): (String, u16, String)| {
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
            let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))
            {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            stream.write_all(request.as_bytes()).ok();

            let mut response = [0u8; 4096];
            let n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set(
                "response",
                String::from_utf8_lossy(&response[..n]).to_string(),
            )?;

            Ok(result)
        })?,
    )?;

    cvs.set(
        "list_modules",
        lua.create_function(|lua, (host, port): (String, u16)| {
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
            let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))
            {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            stream.write_all(b"VALIDATE\n").ok();
            stream.write_all(b"REPOSITORY\n").ok();
            stream.write_all(b"END\n").ok();

            let mut response = [0u8; 4096];
            let n = stream.read(&mut response).unwrap_or(0);

            let modules = lua.create_table()?;
            let response_str = String::from_utf8_lossy(&response[..n]);

            for (i, line) in response_str.lines().enumerate() {
                if !line.is_empty() && !line.starts_with('E') && !line.starts_with('o') {
                    modules.set(i + 1, line.to_string())?;
                }
            }

            result.set("status", "ok")?;
            result.set("modules", modules)?;

            Ok(result)
        })?,
    )?;

    cvs.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("cvs", cvs)?;
    Ok(())
}
