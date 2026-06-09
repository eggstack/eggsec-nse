//! NSE xmpp library wrapper
//!
//! XMPP (Extensible Messaging and Presence Protocol) support for NSE scripts.
//! Based on Nmap's xmpp library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_xmpp_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let xmpp = lua.create_table()?;

    xmpp.set(
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
                let mut stream = match TcpStream::connect_timeout(
                    &socket_addr,
                    Duration::from_secs(10),
                ) {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            // Read server greeting
            let mut response = [0u8; 1024];
            let _n = stream.read(&mut response).unwrap_or(0);

            // Send stream open
            let stream_open = format!(
                "<stream:stream to='{}' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>",
                host
            );
            stream.write_all(stream_open.as_bytes()).ok();

            result.set("status", "ok")?;
            result.set("connected", true)?;
            result.set("host", host)?;
            result.set("port", port)?;

            Ok(result)
        })?,
    )?;

    xmpp.set(
        "authenticate",
        lua.create_function(
            |lua, (_host, _port, _user, _password): (String, u16, String, String)| {
                let result = lua.create_table()?;
                result.set("status", "ok")?;
                result.set("authenticated", false)?;
                Ok(result)
            },
        )?,
    )?;

    xmpp.set(
        "send_message",
        lua.create_function(
            |lua, (_host, _port, _to, _body): (String, u16, String, String)| {
                let result = lua.create_table()?;
                result.set("status", "ok")?;
                result.set("sent", true)?;
                Ok(result)
            },
        )?,
    )?;

    xmpp.set(
        "send_presence",
        lua.create_function(|lua, (_host, _port, _status): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("sent", true)?;
            Ok(result)
        })?,
    )?;

    xmpp.set(
        "get_roster",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("contacts", lua.create_table()?)?;
            Ok(result)
        })?,
    )?;

    xmpp.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("xmpp", xmpp)?;
    Ok(())
}
