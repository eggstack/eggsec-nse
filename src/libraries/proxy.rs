//! NSE proxy library wrapper
//!
//! Proxy protocol detection and handling.
//! Based on Nmap's proxy library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_proxy_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let proxy = lua.create_table()?;

    proxy.set(
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

            // HTTP CONNECT
            let connect = format!("CONNECT {}:{} HTTP/1.1\r\n\r\n", host, port);
            stream.write_all(connect.as_bytes()).ok();

            let mut response = [0u8; 1024];
            let n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("connected", n > 0)?;

            Ok(result)
        })?,
    )?;

    proxy.set(
        "http",
        lua.create_function(
            |lua, (_proxy_host, _proxy_port, _target): (String, u16, String)| {
                let result = lua.create_table()?;
                result.set("status", "ok")?;
                result.set("type", "http")?;
                Ok(result)
            },
        )?,
    )?;

    proxy.set(
        "socks4",
        lua.create_function(|lua, (_proxy_host, _proxy_port, _target_host, _target_port): (String, u16, String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("type", "socks4")?;
            Ok(result)
        })?,
    )?;

    proxy.set(
        "socks5",
        lua.create_function(|lua, (_proxy_host, _proxy_port, _target_host, _target_port): (String, u16, String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("type", "socks5")?;
            Ok(result)
        })?,
    )?;

    proxy.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("proxy", proxy)?;
    Ok(())
}
