//! NSE socks library wrapper
//!
//! SOCKS proxy protocol support for NSE scripts.
//! Based on Nmap's socks library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_socks_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let socks = lua.create_table()?;

    socks.set(
        "connect",
        lua.create_function(
            |lua, (host, port, target_host, target_port): (String, u16, String, u16)| {
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

                // SOCKS5 greeting
                let greeting = vec![
                    0x05, // Version
                    0x01, // Number of methods
                    0x00, // No authentication
                ];

                stream.write_all(&greeting).ok();

                let mut response = [0u8; 2];
                let _ = stream.read(&mut response);

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

                    stream.write_all(&request).ok();

                    let mut reply = [0u8; 10];
                    let _ = stream.read(&mut reply);

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
            },
        )?,
    )?;

    socks.set(
        "auth_methods",
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

            // SOCKS5 greeting
            stream.write_all(&[0x05, 0x02, 0x00, 0x02]).ok();

            let mut response = [0u8; 2];
            let _ = stream.read(&mut response);

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
        })?,
    )?;

    socks.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("socks", socks)?;
    Ok(())
}
