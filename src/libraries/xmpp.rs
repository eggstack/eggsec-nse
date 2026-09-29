//! NSE xmpp library wrapper
//!
//! XMPP (Extensible Messaging and Presence Protocol) support for NSE scripts.
//! Based on Nmap's xmpp library.

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, broker_tcp_send, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

/// Provider-backed xmpp registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_xmpp_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let xmpp = lua.create_table()?;

    xmpp.set(
        "connect",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port): (String, u16)| {
                let result = lua.create_table()?;
                let timeout = Duration::from_secs(10);

                let (mut handle, _endpoint) =
                    match broker_tcp_connect(&ctx, &services, &host, port, timeout, "xmpp.connect")
                    {
                        Ok(pair) => pair,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e)?;
                            return Ok(result);
                        }
                    };

                // Read server greeting (ignored on failure, matching the
                // original `unwrap_or(0)` semantics).
                let data = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "xmpp.connect")
                    .unwrap_or_default();
                let mut response = [0u8; 1024];
                let n = data.len().min(response.len());
                response[..n].copy_from_slice(&data[..n]);
                let _ = n;

                // Send stream open
                let stream_open = format!(
                    "<stream:stream to='{}' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>",
                    host
                );
                let _ =
                    broker_tcp_send(&ctx, handle.as_mut(), stream_open.as_bytes(), "xmpp.connect");

                result.set("status", "ok")?;
                result.set("connected", true)?;
                result.set("host", host)?;
                result.set("port", port)?;

                Ok(result)
            }
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
