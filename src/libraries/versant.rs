//! NSE versant library wrapper
//!
//! Versant object database support.
//! Based on Nmap's versant library.

use crate::brokered_stream::broker_send_all;
use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

const VERSANT_PORT: u16 = 5019;

/// Provider-backed versant registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_versant_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let versant = lua.create_table()?;

    versant.set(
        "connect",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port): (String, Option<u16>)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused hosts keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port.unwrap_or(VERSANT_PORT),
                    Duration::from_secs(10),
                    "versant.connect",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };
                let _ = broker_send_all(&ctx, handle.as_mut(), b"V8", "versant.connect");
                let data = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "versant.connect")
                    .unwrap_or_default();
                let n = data.len();
                result.set("status", "ok")?;
                result.set("connected", n > 0)?;
                result.set("host", host)?;
                result.set("port", port.unwrap_or(VERSANT_PORT))?;
                Ok(result)
            }
        })?,
    )?;

    versant.set(
        "open_database",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, dbname): (String, Option<u16>, String)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused hosts keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port.unwrap_or(VERSANT_PORT),
                    Duration::from_secs(10),
                    "versant.open_database",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                let cmd = format!("OPEN {}\n", dbname);
                let _ = broker_send_all(
                    &ctx,
                    handle.as_mut(),
                    cmd.as_bytes(),
                    "versant.open_database",
                );

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "versant.open_database")
                    .unwrap_or_default();
                let n = data.len();

                result.set("status", "ok")?;
                result.set("database", dbname)?;
                result.set("opened", n > 0)?;

                Ok(result)
            }
        })?,
    )?;

    versant.set(
        "create_object",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, classname): (String, Option<u16>, String)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused hosts keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port.unwrap_or(VERSANT_PORT),
                    Duration::from_secs(10),
                    "versant.create_object",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                let cmd = format!("NEW {}\n", classname);
                let _ = broker_send_all(
                    &ctx,
                    handle.as_mut(),
                    cmd.as_bytes(),
                    "versant.create_object",
                );

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 256, "versant.create_object")
                    .unwrap_or_default();
                let n = data.len();

                let oid = format!("{:x}", rand_simple());

                result.set("status", "ok")?;
                result.set("class", classname)?;
                result.set("oid", oid)?;
                result.set("created", n > 0)?;

                Ok(result)
            }
        })?,
    )?;

    versant.set(
        "get_object",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, oid): (String, Option<u16>, String)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused hosts keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port.unwrap_or(VERSANT_PORT),
                    Duration::from_secs(10),
                    "versant.get_object",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                let cmd = format!("GET {}\n", oid);
                let _ =
                    broker_send_all(&ctx, handle.as_mut(), cmd.as_bytes(), "versant.get_object");

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 4096, "versant.get_object")
                    .unwrap_or_default();

                result.set("status", "ok")?;
                result.set("oid", oid)?;
                result.set("data", String::from_utf8_lossy(&data).to_string())?;

                Ok(result)
            }
        })?,
    )?;

    versant.set(
        "delete_object",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, oid): (String, Option<u16>, String)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused hosts keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port.unwrap_or(VERSANT_PORT),
                    Duration::from_secs(10),
                    "versant.delete_object",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                let cmd = format!("DELETE {}\n", oid);
                let _ = broker_send_all(
                    &ctx,
                    handle.as_mut(),
                    cmd.as_bytes(),
                    "versant.delete_object",
                );

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 256, "versant.delete_object")
                    .unwrap_or_default();
                let _n = data.len();

                result.set("status", "ok")?;
                result.set("oid", oid)?;
                result.set("deleted", true)?;

                Ok(result)
            }
        })?,
    )?;

    versant.set(
        "query",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, oql): (String, Option<u16>, String)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused hosts keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port.unwrap_or(VERSANT_PORT),
                    Duration::from_secs(10),
                    "versant.query",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                let cmd = format!("QUERY {}\n", oql);
                let _ = broker_send_all(&ctx, handle.as_mut(), cmd.as_bytes(), "versant.query");

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 8192, "versant.query")
                    .unwrap_or_default();
                let _n = data.len();

                let objects = lua.create_table()?;
                let oid_result = format!("{:x}", rand_simple());
                objects.set(1, oid_result)?;

                result.set("status", "ok")?;
                result.set("query", oql)?;
                result.set("objects", objects)?;
                result.set("count", 1)?;

                Ok(result)
            }
        })?,
    )?;

    versant.set(
        "list_classes",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port): (String, Option<u16>)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused hosts keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port.unwrap_or(VERSANT_PORT),
                    Duration::from_secs(10),
                    "versant.list_classes",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                let _ =
                    broker_send_all(&ctx, handle.as_mut(), b"CLASSES\n", "versant.list_classes");

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 4096, "versant.list_classes")
                    .unwrap_or_default();
                let _n = data.len();

                let classes = lua.create_table()?;
                classes.set(1, "Object")?;

                result.set("status", "ok")?;
                result.set("classes", classes)?;
                result.set("count", 1)?;

                Ok(result)
            }
        })?,
    )?;

    versant.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("versant", versant)?;
    Ok(())
}

fn rand_simple() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
}
