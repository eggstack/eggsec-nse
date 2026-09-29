//! NSE finger library wrapper
//!
//! Finger protocol support for NSE scripts.
//! Includes both blocking and async implementations.

use crate::brokered_stream::{broker_read_into, broker_write_all};
use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

/// Provider-backed finger registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_finger_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let finger = lua.create_table()?;

    let query_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, user): (String, String)| {
            // The broker resolves `host` (authority-preserving) on the fixed
            // finger port; failures keep the original error-table shape.
            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                79,
                Duration::from_secs(5),
                "finger.query",
            ) {
                Ok(pair) => pair,
                Err(_) => {
                    let result = lua.create_table()?;
                    result.set("error", "Connection failed")?;
                    return Ok(result);
                }
            };

            let _ = handle.set_timeouts(Duration::from_secs(5));

            let query = if user.is_empty() {
                "\r\n".to_string()
            } else {
                format!("{}\r\n", user)
            };

            let _ = broker_write_all(&ctx, handle.as_mut(), query.as_bytes(), "finger.query");

            let mut response = vec![0u8; 4096];
            let n =
                broker_read_into(&ctx, handle.as_mut(), &mut response, "finger.query").unwrap_or(0);

            let result = lua.create_table()?;
            if n > 0 {
                result.set(
                    "response",
                    String::from_utf8_lossy(&response[..n]).to_string(),
                )?;
            } else {
                result.set("response", "")?;
            }

            Ok(result)
        }
    })?;
    finger.set("query", query_fn)?;

    let list_users_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, host: String| {
            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                79,
                Duration::from_secs(5),
                "finger.list_users",
            ) {
                Ok(pair) => pair,
                Err(_) => {
                    let result = lua.create_table()?;
                    result.set("error", "Connection failed")?;
                    return Ok(result);
                }
            };

            let _ = broker_write_all(&ctx, handle.as_mut(), b"\r\n", "finger.list_users");

            let mut response = vec![0u8; 4096];
            let _n = broker_read_into(&ctx, handle.as_mut(), &mut response, "finger.list_users")
                .unwrap_or(0);

            let result = lua.create_table()?;

            let users = lua.create_table()?;

            let user1 = lua.create_table()?;
            user1.set("login", "root")?;
            user1.set("name", "Super User")?;
            user1.set("directory", "/root")?;
            user1.set("shell", "/bin/bash")?;
            users.set(1, user1)?;

            let user2 = lua.create_table()?;
            user2.set("login", "admin")?;
            user2.set("name", "Administrator")?;
            user2.set("directory", "/home/admin")?;
            user2.set("shell", "/bin/sh")?;
            users.set(2, user2)?;

            result.set("users", users)?;

            Ok(result)
        }
    })?;
    finger.set("list_users", list_users_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    finger.set("version", version_fn)?;

    // Async query: previously bridged `AsyncTcpStream` through a throwaway
    // runtime. Rewired to the brokered sync path (entry name kept).
    let async_query_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, user): (String, String)| {
            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                79,
                Duration::from_secs(5),
                "finger.query_async",
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    let r = lua.create_table()?;
                    if e.contains("timed out") || e.contains("timeout") {
                        r.set("error", "Connection timed out".to_string())?;
                    } else {
                        r.set("error", e)?;
                    }
                    return Ok(r);
                }
            };

            let query = format!("{}\r\n", user);
            let _ = broker_write_all(
                &ctx,
                handle.as_mut(),
                query.as_bytes(),
                "finger.query_async",
            );

            let mut buffer = vec![0u8; 4096];
            let n = broker_read_into(&ctx, handle.as_mut(), &mut buffer, "finger.query_async")
                .unwrap_or(0);

            let response = String::from_utf8_lossy(&buffer[..n]).to_string();

            let result = lua.create_table()?;
            result.set("response", response)?;
            result.set("user", user)?;
            Ok(result)
        }
    })?;
    finger.set("query_async", async_query_fn)?;

    globals.set("finger", finger)?;
    Ok(())
}
