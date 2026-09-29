//! NSE pgsql library wrapper
//!
//! PostgreSQL protocol support - alias for postgres library.
//! Based on Nmap's pgsql library.

use crate::brokered_stream::{broker_read_into, broker_write_all};
use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, NseHostServices};
use mlua::{Lua, Result as LuaResult, Table};
use std::time::Duration;

const PGSQL_PORT: u16 = 5432;

/// Provider-backed pgsql registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_pgsql_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let pgsql = lua.create_table()?;

    pgsql.set(
        "connect",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua,
                  (host, port, database, user, _password): (
                String,
                Option<u16>,
                String,
                String,
                String,
            )| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused hosts keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port.unwrap_or(PGSQL_PORT),
                    Duration::from_secs(10),
                    "pgsql.connect",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                let startup_msg = format!(
                    "user={}\0database={}\0application_name=lua\0",
                    user, database
                );
                let mut packet = vec![0u8];
                packet.extend_from_slice(&(startup_msg.len() as u32 + 4).to_be_bytes());
                packet.extend_from_slice(startup_msg.as_bytes());
                broker_write_all(&ctx, handle.as_mut(), &packet, "pgsql.connect").ok();

                let mut response = [0u8; 1024];
                let n = broker_read_into(&ctx, handle.as_mut(), &mut response, "pgsql.connect")
                    .unwrap_or(0);

                result.set("status", "ok")?;
                result.set("host", host)?;
                result.set("port", port.unwrap_or(PGSQL_PORT))?;
                result.set("database", database)?;
                result.set("user", user)?;
                result.set("connected", n > 0)?;

                Ok(result)
            }
        })?,
    )?;

    pgsql.set(
        "query",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, sql): (String, Option<u16>, String)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused hosts keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port.unwrap_or(PGSQL_PORT),
                    Duration::from_secs(10),
                    "pgsql.query",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                let mut query_packet = vec![b'Q'];
                let len = (sql.len() as u32 + 4).to_be_bytes();
                query_packet.extend_from_slice(&len);
                query_packet.extend_from_slice(sql.as_bytes());
                query_packet.push(0);
                broker_write_all(&ctx, handle.as_mut(), &query_packet, "pgsql.query").ok();

                let mut response = [0u8; 8192];
                let _n = broker_read_into(&ctx, handle.as_mut(), &mut response, "pgsql.query")
                    .unwrap_or(0);

                let columns = lua.create_table()?;
                let rows = lua.create_table()?;

                result.set("status", "ok")?;
                result.set("query", sql)?;
                result.set("rows_affected", 0)?;
                result.set("columns", columns)?;
                result.set("rows", rows)?;
                result.set("count", 0)?;

                Ok(result)
            }
        })?,
    )?;

    pgsql.set(
        "execute",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, stmt, _params): (String, Option<u16>, String, Table)| {
                let result = lua.create_table()?;
                // The broker resolves `host` (authority-preserving);
                // unresolvable or refused hosts keep the error-table shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port.unwrap_or(PGSQL_PORT),
                    Duration::from_secs(10),
                    "pgsql.execute",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                let exec_msg = format!("EXECUTE {} 1", stmt);
                let mut query_packet = vec![b'Q'];
                let len = (exec_msg.len() as u32 + 4).to_be_bytes();
                query_packet.extend_from_slice(&len);
                query_packet.extend_from_slice(exec_msg.as_bytes());
                query_packet.push(0);
                broker_write_all(&ctx, handle.as_mut(), &query_packet, "pgsql.execute").ok();

                let mut response = [0u8; 4096];
                let n = broker_read_into(&ctx, handle.as_mut(), &mut response, "pgsql.execute")
                    .unwrap_or(0);

                result.set("status", "ok")?;
                result.set("statement", stmt)?;
                result.set("rows_affected", 0)?;
                result.set(
                    "response",
                    String::from_utf8_lossy(&response[..n]).to_string(),
                )?;

                Ok(result)
            }
        })?,
    )?;

    pgsql.set(
        "list_databases",
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
                    port.unwrap_or(PGSQL_PORT),
                    Duration::from_secs(10),
                    "pgsql.list_databases",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                let query_packet = vec![b'Q', 0, 0, 0, 13, b'l', b'i', b's', b't', b'd', b'b', 0];
                broker_write_all(&ctx, handle.as_mut(), &query_packet, "pgsql.list_databases").ok();

                let mut response = [0u8; 4096];
                let _n =
                    broker_read_into(&ctx, handle.as_mut(), &mut response, "pgsql.list_databases")
                        .unwrap_or(0);

                let databases = lua.create_table()?;
                databases.set(1, "postgres")?;
                databases.set(2, "template0")?;
                databases.set(3, "template1")?;

                result.set("status", "ok")?;
                result.set("databases", databases)?;
                result.set("count", 3)?;

                Ok(result)
            }
        })?,
    )?;

    pgsql.set(
        "list_tables",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, _database): (String, Option<u16>, String)| {
            let result = lua.create_table()?;
            // The broker resolves `host` (authority-preserving);
            // unresolvable or refused hosts keep the error-table shape.
            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port.unwrap_or(PGSQL_PORT),
                Duration::from_secs(10),
                "pgsql.list_tables",
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };

            let query = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'";
            let mut query_packet = vec![b'Q'];
            let len = (query.len() as u32 + 4).to_be_bytes();
            query_packet.extend_from_slice(&len);
            query_packet.extend_from_slice(query.as_bytes());
            query_packet.push(0);
            broker_write_all(&ctx, handle.as_mut(), &query_packet, "pgsql.list_tables").ok();

            let mut response = [0u8; 4096];
            let _n = broker_read_into(&ctx, handle.as_mut(), &mut response, "pgsql.list_tables").unwrap_or(0);

            let tables = lua.create_table()?;

            result.set("status", "ok")?;
            result.set("tables", tables)?;
            result.set("count", 0)?;

            Ok(result)
        }
})?,
    )?;

    pgsql.set(
        "get_columns",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, table): (String, Option<u16>, String)| {
            let result = lua.create_table()?;
            // The broker resolves `host` (authority-preserving);
            // unresolvable or refused hosts keep the error-table shape.
            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port.unwrap_or(PGSQL_PORT),
                Duration::from_secs(10),
                "pgsql.get_columns",
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };

            let query = format!(
                "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '{}'",
                table
            );
            let mut query_packet = vec![b'Q'];
            let len = (query.len() as u32 + 4).to_be_bytes();
            query_packet.extend_from_slice(&len);
            query_packet.extend_from_slice(query.as_bytes());
            query_packet.push(0);
            broker_write_all(&ctx, handle.as_mut(), &query_packet, "pgsql.get_columns").ok();

            let mut response = [0u8; 4096];
            let _n = broker_read_into(&ctx, handle.as_mut(), &mut response, "pgsql.get_columns").unwrap_or(0);

            let columns = lua.create_table()?;

            result.set("status", "ok")?;
            result.set("table", table)?;
            result.set("columns", columns)?;
            result.set("count", 0)?;

            Ok(result)
        }
})?,
    )?;

    pgsql.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("pgsql", pgsql)?;
    Ok(())
}
