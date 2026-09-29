//! NSE ncp library wrapper
//!
//! NCP (NetWare Core Protocol) library for Novell NetWare.
//! Based on Nmap's ncp library concepts.

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

const NCP_PORT: u16 = 524;

/// Provider-backed ncp registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_ncp_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let ncp = lua.create_table()?;

    let new_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let n = lua.create_table()?;
        n.set("host", host)?;
        n.set("port", port)?;
        n.set("timeout", 5i64)?;
        Ok(n)
    })?;
    ncp.set("new", new_fn)?;

    let connect_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, user, _password): (String, u16, String, String)| {
            let result = lua.create_table()?;

            // Reachability probe through the broker (authority-preserving
            // resolve replaces the literal-parse-plus-loopback-fallback).
            match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port,
                Duration::from_secs(5),
                "ncp.connect",
            ) {
                Ok(_) => {
                    result.set("success", true)?;
                    result.set("host", host)?;
                    result.set("server", "NetWare Server")?;
                    result.set("user", user)?;
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
            }

            Ok(result)
        }
    })?;
    ncp.set("connect", connect_fn)?;

    let list_volumes_fn = lua.create_function(|lua, _host: String| {
        let result = lua.create_table()?;
        let volumes = lua.create_table()?;

        volumes.set(1, "SYS")?;
        volumes.set(2, "DATA")?;

        result.set("success", true)?;
        result.set("volumes", volumes)?;

        Ok(result)
    })?;
    ncp.set("list_volumes", list_volumes_fn)?;

    let list_directories_fn = lua.create_function(|lua, (_host, volume): (String, String)| {
        let result = lua.create_table()?;
        let dirs = lua.create_table()?;

        dirs.set(1, "SYSTEM")?;
        dirs.set(2, "PUBLIC")?;
        dirs.set(3, "LOGIN")?;

        result.set("success", true)?;
        result.set("volume", volume)?;
        result.set("directories", dirs)?;

        Ok(result)
    })?;
    ncp.set("list_directories", list_directories_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    ncp.set("version", version_fn)?;

    // Async connect probe: previously bridged `AsyncTcpStream` through the
    // ambient runtime. Rewired to the brokered sync probe — the
    // success/failure/timeout shape is preserved (timeout distinguished via
    // the broker error text), and the entry name is kept for compatibility.
    let async_connect_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, user, _password): (String, u16, String, String)| {
            let port = if port == 0 { NCP_PORT } else { port };
            let result = lua.create_table()?;

            match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port,
                Duration::from_secs(5),
                "ncp.connect_async",
            ) {
                Ok(_) => {
                    result.set("success", true)?;
                    result.set("host", host)?;
                    result.set("server", "NetWare Server")?;
                    result.set("user", user)?;
                }
                Err(e) => {
                    result.set("success", false)?;
                    if e.contains("timed out") || e.contains("timeout") {
                        result.set("error", "Connection timed out".to_string())?;
                    } else {
                        result.set("error", format!("Connection failed: {}", e))?;
                    }
                }
            }

            Ok(result)
        }
    })?;
    ncp.set("connect_async", async_connect_fn)?;

    globals.set("ncp", ncp)?;
    Ok(())
}
