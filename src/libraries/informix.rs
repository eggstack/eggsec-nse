//! NSE informix library wrapper
//!
//! Informix database support.
//! Based on Nmap's informix library.

use crate::brokered_stream::broker_send_all;
use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, NseHostServices, NseTcpConnection};
use mlua::{Lua, Result as LuaResult, Table};
use std::time::Duration;

const INFORMIX_PORT: u16 = 9088;

/// Brokered connect helper: resolve + capability-check + connect.
///
/// Returns the opaque handle; all send/receive sites use the broker fns so
/// every byte is accounted and every operation is cancellable.
fn informix_connect(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    host: &str,
    port: u16,
    operation: &'static str,
) -> Result<Box<dyn NseTcpConnection>, String> {
    let (handle, _endpoint) = broker_tcp_connect(
        ctx,
        services,
        host,
        port,
        Duration::from_secs(10),
        operation,
    )?;
    Ok(handle)
}

/// Provider-backed informix registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_informix_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let informix = lua.create_table()?;

    let packet = lua.create_table()?;

    let new_fn = lua.create_function(|lua, typ: String| {
        let obj = lua.create_table()?;
        obj.set("type", typ)?;
        obj.set("data", "")?;
        obj.set("length", 0)?;
        Ok(obj)
    })?;
    packet.set("new", new_fn)?;

    let set_data_fn = lua.create_function(|_lua, (pkt, data): (Table, String)| {
        let len = data.len();
        pkt.set("data", data)?;
        pkt.set("length", len)?;
        Ok(pkt)
    })?;
    packet.set("setData", set_data_fn)?;

    let get_data_fn = lua.create_function(|_lua, pkt: Table| pkt.get::<String>("data"))?;
    packet.set("getData", get_data_fn)?;

    let get_length_fn = lua.create_function(|_lua, pkt: Table| pkt.get::<u32>("length"))?;
    packet.set("getLength", get_length_fn)?;

    informix.set("Packet", packet)?;

    informix.set(
        "connect",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port): (String, Option<u16>)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving); unresolvable
                // or refused hosts keep the original `status = "error"` shape.
                let port = port.unwrap_or(INFORMIX_PORT);
                let mut handle =
                    match informix_connect(&ctx, &services, &host, port, "informix.connect") {
                        Ok(h) => h,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e)?;
                            return Ok(result);
                        }
                    };

                let connect_str = format!("{}:INFORMIXSERVER\t\n", host);
                let _ = broker_send_all(
                    &ctx,
                    handle.as_mut(),
                    connect_str.as_bytes(),
                    "informix.connect",
                );

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 256, "informix.connect")
                    .unwrap_or_default();
                let n = data.len();

                result.set("status", "ok")?;
                result.set("host", host)?;
                result.set("port", port)?;
                result.set("connected", n > 0)?;

                Ok(result)
            }
        })?,
    )?;

    informix.set(
        "execute",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, sql): (String, Option<u16>, String)| {
                let result = lua.create_table()?;
                let port = port.unwrap_or(INFORMIX_PORT);
                let mut handle =
                    match informix_connect(&ctx, &services, &host, port, "informix.execute") {
                        Ok(h) => h,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e)?;
                            return Ok(result);
                        }
                    };

                let exec_cmd = format!("execute\t{}\n", sql);
                let _ = broker_send_all(
                    &ctx,
                    handle.as_mut(),
                    exec_cmd.as_bytes(),
                    "informix.execute",
                );

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 4096, "informix.execute")
                    .unwrap_or_default();

                result.set("status", "ok")?;
                result.set("rows_affected", 0)?;
                result.set("response", String::from_utf8_lossy(&data).to_string())?;

                Ok(result)
            }
        })?,
    )?;

    informix.set(
        "query",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, sql): (String, Option<u16>, String)| {
                let result = lua.create_table()?;
                let port = port.unwrap_or(INFORMIX_PORT);
                let mut handle =
                    match informix_connect(&ctx, &services, &host, port, "informix.query") {
                        Ok(h) => h,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e)?;
                            return Ok(result);
                        }
                    };

                let query_cmd = format!("sqlexec\t{}\n", sql);
                let _ = broker_send_all(
                    &ctx,
                    handle.as_mut(),
                    query_cmd.as_bytes(),
                    "informix.query",
                );

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 8192, "informix.query")
                    .unwrap_or_default();

                let columns = lua.create_table()?;
                let rows = lua.create_table()?;

                result.set("status", "ok")?;
                result.set("columns", columns)?;
                result.set("rows", rows)?;
                result.set("count", 0)?;
                result.set("response", String::from_utf8_lossy(&data).to_string())?;

                Ok(result)
            }
        })?,
    )?;

    informix.set(
        "list_databases",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port): (String, Option<u16>)| {
                let result = lua.create_table()?;
                let port = port.unwrap_or(INFORMIX_PORT);
                let mut handle =
                    match informix_connect(&ctx, &services, &host, port, "informix.list_databases")
                    {
                        Ok(h) => h,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e)?;
                            return Ok(result);
                        }
                    };

                let _ = broker_send_all(
                    &ctx,
                    handle.as_mut(),
                    b"databases\t\n",
                    "informix.list_databases",
                );

                let data =
                    broker_tcp_receive(&ctx, handle.as_mut(), 2048, "informix.list_databases")
                        .unwrap_or_default();

                let databases = lua.create_table()?;
                let response_str = String::from_utf8_lossy(&data);

                for (i, line) in response_str.lines().enumerate() {
                    if !line.is_empty() {
                        databases.set(i + 1, line.trim().to_string())?;
                    }
                }

                let count = databases.len().unwrap_or(0) as i32;
                result.set("status", "ok")?;
                result.set("databases", databases)?;
                result.set("count", count)?;

                Ok(result)
            }
        })?,
    )?;

    informix.set(
        "list_tables",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, _database): (String, Option<u16>, String)| {
                let result = lua.create_table()?;
                let port = port.unwrap_or(INFORMIX_PORT);
                let mut handle =
                    match informix_connect(&ctx, &services, &host, port, "informix.list_tables") {
                        Ok(h) => h,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e)?;
                            return Ok(result);
                        }
                    };

                let _ =
                    broker_send_all(&ctx, handle.as_mut(), b"tables\t\n", "informix.list_tables");

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 4096, "informix.list_tables")
                    .unwrap_or_default();

                let tables = lua.create_table()?;
                let response_str = String::from_utf8_lossy(&data);

                for (i, line) in response_str.lines().enumerate() {
                    if !line.is_empty() {
                        tables.set(i + 1, line.trim().to_string())?;
                    }
                }

                let count = tables.len().unwrap_or(0) as i32;
                result.set("status", "ok")?;
                result.set("tables", tables)?;
                result.set("count", count)?;

                Ok(result)
            }
        })?,
    )?;

    informix.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("informix", informix)?;
    Ok(())
}
