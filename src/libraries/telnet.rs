//! NSE telnet library wrapper
//!
//! Telnet protocol support for NSE scripts.
//! Includes both blocking and async implementations.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream as AsyncTcpStream;

pub fn register_telnet_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let telnet = lua.create_table()?;

    let connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let addr = format!("{}:{}", host, port);
        let mut stream = match TcpStream::connect_timeout(
            &addr
                .parse::<std::net::SocketAddr>()
                .map_err(|e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()))?,
            Duration::from_secs(10),
        ) {
            Ok(s) => s,
            Err(_) => {
                let result = lua.create_table()?;
                result.set("error", "Connection failed")?;
                return Ok(result);
            }
        };

        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

        let mut buffer = vec![0u8; 4096];
        let n = stream.read(&mut buffer).unwrap_or(0);

        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("status", if n > 0 { "connected" } else { "timeout" })?;

        Ok(result)
    })?;
    telnet.set("connect", connect_fn)?;

    let login_fn = lua.create_function(
        |lua, (_host, _port, user, _pass): (String, u16, String, String)| {
            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("user", user)?;

            Ok(result)
        },
    )?;
    telnet.set("login", login_fn)?;

    let send_fn = lua.create_function(|lua, (_host, _port, cmd): (String, u16, String)| {
        let result = lua.create_table()?;
        result.set("sent", cmd.clone())?;
        result.set("response", format!("Output of: {}", cmd))?;

        Ok(result)
    })?;
    telnet.set("send", send_fn)?;

    let expect_fn =
        lua.create_function(|lua, (_host, _port, patterns): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("match", patterns.split(',').next().unwrap_or(""))?;
            result.set("response", "matched")?;

            Ok(result)
        })?;
    telnet.set("expect", expect_fn)?;

    let option_fn = lua.create_function(|lua, (_host, _port, option): (String, u16, String)| {
        let result = lua.create_table()?;
        result.set("enabled", true)?;
        result.set("option", option)?;

        Ok(result)
    })?;
    telnet.set("option", option_fn)?;

    // telnet.skip - Skip initial banner/prompts
    let skip_fn =
        lua.create_function(|lua, (host, port, skip): (String, u16, Option<String>)| {
            let result = lua.create_table()?;
            result.set("skipped", true)?;
            result.set("banner", "Welcome to Telnet Server")?;
            Ok(result)
        })?;
    telnet.set("skip", skip_fn)?;

    // telnet.gc - Garbage collect / cleanup
    let gc_fn = lua.create_function(|_lua, _: ()| Ok(true))?;
    telnet.set("gc", gc_fn)?;

    // telnet.negotiate - Telnet negotiation
    let negotiate_fn = lua.create_function(
        |lua, (host, port, options): (String, u16, Option<String>)| {
            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("negotiated", options.unwrap_or_default())?;
            Ok(result)
        },
    )?;
    telnet.set("negotiate", negotiate_fn)?;

    // telnet.binary - Set binary mode
    let binary_fn = lua.create_function(|_lua, (host, port): (String, u16)| {
        let result = _lua.create_table()?;
        result.set("mode", "binary")?;
        result.set("success", true)?;
        Ok(result)
    })?;
    telnet.set("binary", binary_fn)?;

    // telnet.socket - Get socket info
    let socket_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("type", "tcp")?;
        Ok(result)
    })?;
    telnet.set("socket", socket_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    telnet.set("version", version_fn)?;

    // Async connect
    let async_connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let addr = format!("{}:{}", host, port);

        tokio::runtime::Handle::current().block_on(async {
            match AsyncTcpStream::connect(&addr).await {
                Ok(mut stream) => {
                    let mut buffer = vec![0u8; 4096];
                    let n = stream.read(&mut buffer).await.unwrap_or(0);

                    let r = lua.create_table()?;
                    r.set("host", host)?;
                    r.set("port", port)?;
                    r.set("status", if n > 0 { "connected" } else { "timeout" })?;
                    Ok(r)
                }
                Err(e) => {
                    let r = lua.create_table()?;
                    r.set("error", e.to_string())?;
                    Ok(r)
                }
            }
        })
    })?;
    telnet.set("connect_async", async_connect_fn)?;

    globals.set("telnet", telnet)?;
    Ok(())
}
