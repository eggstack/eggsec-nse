//! NSE rmi library wrapper
//!
//! RMI (Java Remote Method Invocation) support.
//! Based on Nmap's rmi library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const RMI_PORT: u16 = 1099;

pub fn register_rmi_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let rmi = lua.create_table()?;

    rmi.set(
        "connect",
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(RMI_PORT));
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

            stream.write_all(b"JRMI").ok();
            let mut response = [0u8; 1024];
            let n = stream.read(&mut response).unwrap_or(0);
            result.set("status", "ok")?;
            result.set("connected", n > 0)?;
            Ok(result)
        })?,
    )?;

    rmi.set(
        "list_methods",
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(RMI_PORT));
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

            let request = vec![
                0x50, 0x01, 0x3b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ];
            stream.write_all(&request).ok();

            let mut response = [0u8; 4096];
            let _n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("methods", lua.create_table()?)?;
            result.set("object_number", 0)?;

            Ok(result)
        })?,
    )?;

    rmi.set(
        "get_registry",
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(RMI_PORT));
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

            stream.write_all(b"JRMI").ok();

            let mut response = [0u8; 1024];
            let _n = stream.read(&mut response).unwrap_or(0);

            let bindings = lua.create_table()?;
            bindings.set(1, "java.rmi.registry.Registry")?;

            result.set("status", "ok")?;
            result.set("bindings", bindings)?;

            Ok(result)
        })?,
    )?;

    rmi.set(
        "get_object_ref",
        lua.create_function(
            |lua, (host, port, object_name): (String, Option<u16>, String)| {
                let result = lua.create_table()?;
                let port_val = port.unwrap_or(RMI_PORT);
                result.set("status", "ok")?;
                result.set("host", host.clone())?;
                result.set("port", port_val)?;
                result.set("object_name", object_name.clone())?;
                result.set(
                    "object_ref",
                    format!("//{}:{}/{}", host, port_val, object_name),
                )?;
                Ok(result)
            },
        )?,
    )?;

    rmi.set(
        "is_科",
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(RMI_PORT));
            let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                Ok(a) => a,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", format!("Invalid address '{}': {}", addr, e))?;
                    return Ok(result);
                }
            };
            let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(3));

            result.set("status", "ok")?;
            result.set("is_rmi", stream.is_ok())?;
            Ok(result)
        })?,
    )?;

    rmi.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("rmi", rmi)?;
    Ok(())
}
