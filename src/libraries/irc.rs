//! NSE irc library wrapper
//!
//! IRC (Internet Relay Chat) protocol support.
//! Based on Nmap's irc library.

use crate::brokered_stream::{broker_read_into, broker_write_all};
use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

/// Provider-backed irc registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_irc_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let irc = lua.create_table()?;

    // irc.connect() - Connect to IRC server
    irc.set(
        "connect",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, nick): (String, u16, String)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused hosts keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "irc.connect",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                handle.set_timeouts(Duration::from_secs(10)).ok();
                handle.set_timeouts(Duration::from_secs(10)).ok();

                // IRC NICK and USER
                broker_write_all(
                    &ctx,
                    handle.as_mut(),
                    format!("NICK {}\r\n", nick).as_bytes(),
                    "irc.connect",
                )
                .ok();
                broker_write_all(
                    &ctx,
                    handle.as_mut(),
                    format!("USER {} 0 * :Eggsec\r\n", nick).as_bytes(),
                    "irc.connect",
                )
                .ok();

                // Read welcome message
                let mut response = vec![0u8; 1024];
                let n = broker_read_into(&ctx, handle.as_mut(), &mut response, "irc.connect")
                    .unwrap_or(0);

                result.set("status", "ok")?;
                result.set("connected", n > 0)?;
                result.set("nick", nick)?;

                Ok(result)
            }
        })?,
    )?;

    // irc.join() - Join a channel
    irc.set(
        "join",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, nick, channel): (String, u16, String, String)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused hosts keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "irc.join",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                handle.set_timeouts(Duration::from_secs(10)).ok();
                handle.set_timeouts(Duration::from_secs(10)).ok();

                // Send NICK and USER
                broker_write_all(
                    &ctx,
                    handle.as_mut(),
                    format!("NICK {}\r\n", nick).as_bytes(),
                    "irc.join",
                )
                .ok();
                broker_write_all(
                    &ctx,
                    handle.as_mut(),
                    format!("USER {} 0 * :Eggsec\r\n", nick).as_bytes(),
                    "irc.join",
                )
                .ok();

                // Wait a bit for registration
                std::thread::sleep(std::time::Duration::from_millis(500));

                // Join channel
                broker_write_all(
                    &ctx,
                    handle.as_mut(),
                    format!("JOIN {}\r\n", channel).as_bytes(),
                    "irc.join",
                )
                .ok();

                let mut response = vec![0u8; 1024];
                let n =
                    broker_read_into(&ctx, handle.as_mut(), &mut response, "irc.join").unwrap_or(0);

                let response_str = String::from_utf8_lossy(&response[..n]).to_string();

                if response_str.contains("JOIN") || response_str.contains("353") {
                    result.set("success", true)?;
                    result.set("channel", channel)?;
                } else {
                    result.set("success", false)?;
                }

                Ok(result)
            }
        })?,
    )?;

    // irc.privmsg() - Send a private message
    irc.set(
        "privmsg",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, nick, target, message): (String, u16, String, String, String)| {
                let result = lua.create_table()?;
            // The broker resolves `host` (authority-preserving);
            // unresolvable or refused hosts keep the error-table shape.
            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port,
                Duration::from_secs(10),
                "irc.privmsg",
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };

                handle.set_timeouts(Duration::from_secs(10)).ok();
                handle.set_timeouts(Duration::from_secs(10)).ok();

                // Send NICK and USER
                broker_write_all(&ctx, handle.as_mut(), format!("NICK {}\r\n", nick).as_bytes(), "irc.privmsg")
                    .ok();
                broker_write_all(&ctx, handle.as_mut(), format!("USER {} 0 * :Eggsec\r\n", nick).as_bytes(), "irc.privmsg")
                    .ok();

                // Wait a bit for registration
                std::thread::sleep(std::time::Duration::from_millis(500));

                // Send PRIVMSG
                broker_write_all(&ctx, handle.as_mut(), format!("PRIVMSG {} :{}\r\n", target, message).as_bytes(), "irc.privmsg")
                    .ok();

                result.set("success", true)?;
                result.set("target", target)?;
                result.set("message", message)?;

                Ok(result)
            }
})?,
    )?;

    // irc.part() - Leave a channel
    irc.set(
        "part",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, nick, channel): (String, u16, String, String)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused hosts keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "irc.part",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                handle.set_timeouts(Duration::from_secs(10)).ok();
                handle.set_timeouts(Duration::from_secs(10)).ok();

                // Send NICK and USER
                broker_write_all(
                    &ctx,
                    handle.as_mut(),
                    format!("NICK {}\r\n", nick).as_bytes(),
                    "irc.part",
                )
                .ok();
                broker_write_all(
                    &ctx,
                    handle.as_mut(),
                    format!("USER {} 0 * :Eggsec\r\n", nick).as_bytes(),
                    "irc.part",
                )
                .ok();

                // Wait a bit for registration
                std::thread::sleep(std::time::Duration::from_millis(500));

                // Part channel
                broker_write_all(
                    &ctx,
                    handle.as_mut(),
                    format!("PART {}\r\n", channel).as_bytes(),
                    "irc.part",
                )
                .ok();

                result.set("success", true)?;
                result.set("channel", channel)?;

                Ok(result)
            }
        })?,
    )?;

    // irc.nick() - Change nickname
    irc.set(
        "nick",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, new_nick): (String, u16, String)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused hosts keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "irc.nick",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                handle.set_timeouts(Duration::from_secs(10)).ok();
                handle.set_timeouts(Duration::from_secs(10)).ok();

                // Send NICK
                broker_write_all(
                    &ctx,
                    handle.as_mut(),
                    format!("NICK {}\r\n", new_nick).as_bytes(),
                    "irc.nick",
                )
                .ok();

                let mut response = vec![0u8; 512];
                let n =
                    broker_read_into(&ctx, handle.as_mut(), &mut response, "irc.nick").unwrap_or(0);

                let response_str = String::from_utf8_lossy(&response[..n]).to_string();

                if response_str.contains("NICK") || n > 0 {
                    result.set("success", true)?;
                    result.set("nick", new_nick)?;
                } else {
                    result.set("success", false)?;
                }

                Ok(result)
            }
        })?,
    )?;

    // irc.quit() - Quit IRC
    irc.set(
        "quit",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, nick, message): (String, u16, String, Option<String>)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused hosts keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "irc.quit",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                handle.set_timeouts(Duration::from_secs(10)).ok();
                handle.set_timeouts(Duration::from_secs(10)).ok();

                // Send NICK and USER
                broker_write_all(
                    &ctx,
                    handle.as_mut(),
                    format!("NICK {}\r\n", nick).as_bytes(),
                    "irc.quit",
                )
                .ok();
                broker_write_all(
                    &ctx,
                    handle.as_mut(),
                    format!("USER {} 0 * :Eggsec\r\n", nick).as_bytes(),
                    "irc.quit",
                )
                .ok();

                // Wait a bit for registration
                std::thread::sleep(std::time::Duration::from_millis(500));

                // Quit
                if let Some(msg) = message {
                    broker_write_all(
                        &ctx,
                        handle.as_mut(),
                        format!("QUIT :{}\r\n", msg).as_bytes(),
                        "irc.quit",
                    )
                    .ok();
                } else {
                    broker_write_all(&ctx, handle.as_mut(), b"QUIT\r\n", "irc.quit").ok();
                }

                result.set("success", true)?;

                Ok(result)
            }
        })?,
    )?;

    // irc.list() - List channels
    irc.set(
        "list",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, channel): (String, u16, Option<String>)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused hosts keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "irc.list",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                handle.set_timeouts(Duration::from_secs(10)).ok();
                handle.set_timeouts(Duration::from_secs(10)).ok();

                // Send NICK and USER
                broker_write_all(&ctx, handle.as_mut(), b"NICK eggsec\r\n", "irc.list").ok();
                broker_write_all(
                    &ctx,
                    handle.as_mut(),
                    b"USER eggsec 0 * :Eggsec\r\n",
                    "irc.list",
                )
                .ok();

                // Wait a bit for registration
                std::thread::sleep(std::time::Duration::from_millis(500));

                // List channels
                if let Some(ch) = channel {
                    broker_write_all(
                        &ctx,
                        handle.as_mut(),
                        format!("LIST {}\r\n", ch).as_bytes(),
                        "irc.list",
                    )
                    .ok();
                } else {
                    broker_write_all(&ctx, handle.as_mut(), b"LIST\r\n", "irc.list").ok();
                }

                let mut response = vec![0u8; 4096];
                let n =
                    broker_read_into(&ctx, handle.as_mut(), &mut response, "irc.list").unwrap_or(0);

                let channels = lua.create_table()?;
                let response_str = String::from_utf8_lossy(&response[..n]).to_string();

                for line in response_str.lines() {
                    if line.contains("323") || line.contains("322") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 4 {
                            let ch_name = parts.get(3).unwrap_or(&"").trim_start_matches(':');
                            if !ch_name.is_empty() {
                                let count = channels.len().unwrap_or(0) + 1;
                                channels.set(count, ch_name)?;
                            }
                        }
                    }
                }

                result.set("channels", channels)?;

                Ok(result)
            }
        })?,
    )?;

    // irc.whois() - Get user info
    irc.set(
        "whois",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, target): (String, u16, String)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused hosts keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "irc.whois",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                handle.set_timeouts(Duration::from_secs(10)).ok();
                handle.set_timeouts(Duration::from_secs(10)).ok();

                // Send NICK and USER
                broker_write_all(&ctx, handle.as_mut(), b"NICK eggsec\r\n", "irc.whois").ok();
                broker_write_all(
                    &ctx,
                    handle.as_mut(),
                    b"USER eggsec 0 * :Eggsec\r\n",
                    "irc.whois",
                )
                .ok();

                // Wait a bit for registration
                std::thread::sleep(std::time::Duration::from_millis(500));

                // WHOIS
                broker_write_all(
                    &ctx,
                    handle.as_mut(),
                    format!("WHOIS {}\r\n", target).as_bytes(),
                    "irc.whois",
                )
                .ok();

                let mut response = vec![0u8; 2048];
                let n = broker_read_into(&ctx, handle.as_mut(), &mut response, "irc.whois")
                    .unwrap_or(0);

                let response_str = String::from_utf8_lossy(&response[..n]).to_string();

                result.set("target", target)?;
                result.set("response", response_str.trim())?;

                Ok(result)
            }
        })?,
    )?;

    irc.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("irc", irc)?;
    Ok(())
}
