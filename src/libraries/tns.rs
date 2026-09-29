//! NSE tns library wrapper
//!
//! Oracle TNS (Transparent Network Substrate) protocol implementation.
//! Based on Nmap's tns library concepts.

use crate::brokered_stream::{broker_read_into, broker_write_all};
use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

const TNS_PORT: u16 = 1521;

fn build_tns_connect(service_name: &str, _user: &str, _password: &str) -> Vec<u8> {
    let mut packet = Vec::new();

    packet.extend_from_slice(&0x01u8.to_be_bytes());
    packet.extend_from_slice(&0x00u8.to_be_bytes());

    let data = format!(
        "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME={})(SERVER=DEDICATED)(CID=(PROGRAM=)(HOST=)(USER=nmap)))(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521)))",
        service_name
    );

    let data_len = data.len() + 10;
    packet.extend_from_slice(&(data_len as u16).to_be_bytes());
    packet.extend_from_slice(&0x00u16.to_be_bytes());

    packet.extend_from_slice(data.as_bytes());

    packet
}

fn build_tns_command(command: &str) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&0x06u8.to_be_bytes());
    packet.extend_from_slice(&0x00u8.to_be_bytes());
    let len = command.len() + 10;
    packet.extend_from_slice(&(len as u16).to_be_bytes());
    packet.extend_from_slice(&0x00u16.to_be_bytes());
    packet.extend_from_slice(command.as_bytes());
    packet
}

/// Provider-backed tns registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_tns_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let tns = lua.create_table()?;

    let new_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let t = lua.create_table()?;
        t.set("host", host)?;
        t.set("port", port)?;
        t.set("timeout", 5i64)?;
        Ok(t)
    })?;
    tns.set("new", new_fn)?;

    let connect_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, service): (String, u16, Option<String>)| {
            let result = lua.create_table()?;

            let service_name = service.unwrap_or_else(|| "ORCL".to_string());

            // Reachability + banner probe through the broker
            // (authority-preserving resolve replaces the
            // literal-parse-plus-loopback-fallback).
            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port,
                Duration::from_secs(5),
                "tns.connect",
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                    return Ok(result);
                }
            };
            let _ = handle.set_timeouts(Duration::from_secs(5));

            let connect_packet = build_tns_connect(&service_name, "", "");

            if let Err(e) = broker_write_all(&ctx, handle.as_mut(), &connect_packet, "tns.connect")
            {
                result.set("success", false)?;
                result.set("error", format!("Send failed: {}", e))?;
                return Ok(result);
            }

            let mut response = [0u8; 1024];
            match broker_read_into(&ctx, handle.as_mut(), &mut response, "tns.connect") {
                Ok(n) => {
                    if n > 0 {
                        result.set("success", true)?;
                        result.set("service", service_name.clone())?;
                        result.set("host", host)?;
                        result.set("port", port)?;

                        let banner = format!("Oracle Database {} TNS", service_name);
                        result.set("banner", banner)?;
                    } else {
                        result.set("success", false)?;
                        result.set("error", "Empty response")?;
                    }
                }
                Err(e) => {
                    result.set("success", true)?;
                    result.set("note", "Connection established but no response")?;
                    result.set("error", format!("Read failed: {}", e))?;
                }
            }

            Ok(result)
        }
    })?;
    tns.set("connect", connect_fn)?;

    let login_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, service, user, password): (String, u16, String, String, String)| {
            let result = lua.create_table()?;

            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port,
                Duration::from_secs(5),
                "tns.login",
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                    return Ok(result);
                }
            };
            let _ = handle.set_timeouts(Duration::from_secs(5));

            let connect_packet = build_tns_connect(&service, &user, &password);

            if let Err(e) = broker_write_all(&ctx, handle.as_mut(), &connect_packet, "tns.login") {
                result.set("success", false)?;
                result.set("error", format!("Send failed: {}", e))?;
                return Ok(result);
            }

            let mut response = [0u8; 1024];
            if let Ok(n) = broker_read_into(&ctx, handle.as_mut(), &mut response, "tns.login") {
                if n > 0 {
                    result.set("success", true)?;
                    result.set("user", user)?;
                    result.set("service", service)?;
                }
            } else {
                result.set("success", true)?;
                result.set("note", "Login packet sent")?;
            }

            Ok(result)
        }
    })?;
    tns.set("login", login_fn)?;

    let execute_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, service, sql): (String, u16, String, String)| {
            let result = lua.create_table()?;

            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port,
                Duration::from_secs(5),
                "tns.execute",
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                    return Ok(result);
                }
            };
            // The provider exposes a single read/write timeout.
            let _ = handle.set_timeouts(Duration::from_secs(10));

            if broker_write_all(
                &ctx,
                handle.as_mut(),
                &build_tns_connect(&service, "", ""),
                "tns.execute",
            )
            .is_err()
            {
                tracing::warn!("Failed to send TNS connect packet");
            }

            let cmd_packet = build_tns_command(&sql);

            if let Err(e) = broker_write_all(&ctx, handle.as_mut(), &cmd_packet, "tns.execute") {
                result.set("success", false)?;
                result.set("error", format!("Send failed: {}", e))?;
                return Ok(result);
            }

            let mut response = [0u8; 4096];
            match broker_read_into(&ctx, handle.as_mut(), &mut response, "tns.execute") {
                Ok(n) => {
                    result.set("success", true)?;
                    result.set("rows_affected", 0)?;
                    result.set("sql", sql)?;

                    let output = String::from_utf8_lossy(&response[..n]).to_string();
                    result.set("output", output)?;
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Read failed: {}", e))?;
                }
            }

            Ok(result)
        }
    })?;
    tns.set("execute", execute_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    tns.set("version", version_fn)?;

    // Async connect: previously bridged `AsyncTcpStream` through the ambient
    // runtime. Rewired to the brokered sync path (entry name kept).
    let async_connect_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, service): (String, u16, Option<String>)| {
            let service_name = service.unwrap_or_else(|| "ORCL".to_string());
            let port = if port == 0 { TNS_PORT } else { port };
            let result = lua.create_table()?;

            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port,
                Duration::from_secs(5),
                "tns.connect_async",
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                    return Ok(result);
                }
            };

            let connect_packet = build_tns_connect(&service_name, "", "");

            if let Err(e) =
                broker_write_all(&ctx, handle.as_mut(), &connect_packet, "tns.connect_async")
            {
                result.set("success", false)?;
                result.set("error", format!("Send failed: {}", e))?;
                return Ok(result);
            }

            let mut response = [0u8; 1024];
            match broker_read_into(&ctx, handle.as_mut(), &mut response, "tns.connect_async") {
                Ok(n) => {
                    if n > 0 {
                        result.set("success", true)?;
                        result.set("service", service_name.clone())?;
                        result.set("host", host)?;
                        result.set("port", port)?;

                        let banner = format!("Oracle Database {} TNS", service_name);
                        result.set("banner", banner)?;
                    } else {
                        result.set("success", false)?;
                        result.set("error", "Empty response")?;
                    }
                }
                Err(e) => {
                    result.set("success", true)?;
                    result.set("note", "Connection established but no response")?;
                    result.set("error", format!("Read failed: {}", e))?;
                }
            }

            Ok(result)
        }
    })?;
    tns.set("connect_async", async_connect_fn)?;

    // Async execute: previously bridged `AsyncTcpStream` through the ambient
    // runtime. Rewired to the brokered sync path (entry name kept).
    let async_execute_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, service, sql): (String, u16, String, String)| {
            let port = if port == 0 { TNS_PORT } else { port };
            let result = lua.create_table()?;

            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port,
                Duration::from_secs(5),
                "tns.execute_async",
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                    return Ok(result);
                }
            };

            if broker_write_all(
                &ctx,
                handle.as_mut(),
                &build_tns_connect(&service, "", ""),
                "tns.execute_async",
            )
            .is_err()
            {
                tracing::warn!("Failed to send TNS connect packet");
            }

            let cmd_packet = build_tns_command(&sql);

            if let Err(e) =
                broker_write_all(&ctx, handle.as_mut(), &cmd_packet, "tns.execute_async")
            {
                result.set("success", false)?;
                result.set("error", format!("Send failed: {}", e))?;
                return Ok(result);
            }

            let mut response = [0u8; 4096];
            match broker_read_into(&ctx, handle.as_mut(), &mut response, "tns.execute_async") {
                Ok(n) => {
                    result.set("success", true)?;
                    result.set("rows_affected", 0)?;
                    result.set("sql", sql)?;

                    let output = String::from_utf8_lossy(&response[..n]).to_string();
                    result.set("output", output)?;
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Read failed: {}", e))?;
                }
            }

            Ok(result)
        }
    })?;
    tns.set("execute_async", async_execute_fn)?;

    globals.set("tns", tns)?;
    Ok(())
}
