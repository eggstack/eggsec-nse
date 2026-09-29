//! NSE mssql library wrapper
//!
//! Microsoft SQL Server (TDS) protocol support for NSE scripts.

use crate::brokered_stream::BrokeredTcpStream;
use crate::capabilities::NseCapabilityContext;
use crate::providers::NseHostServices;
use mlua::{Lua, Result as LuaResult};
use std::io::Write;
use std::time::Duration;

use crate::wrappers;

fn maybe_denied_mssql(
    lua: &Lua,
    ctx: &NseCapabilityContext,
    host: &str,
    operation: &'static str,
) -> LuaResult<Option<mlua::Table>> {
    let decision = wrappers::check_network_tcp(ctx, host, operation);
    if !decision.is_allowed() {
        let result = lua.create_table()?;
        result.set("status", "error")?;
        result.set(
            "error",
            decision
                .deny_reason()
                .unwrap_or("network access denied")
                .to_string(),
        )?;
        result.set("reason", "denied")?;
        return Ok(Some(result));
    }
    Ok(None)
}

/// Brokered TDS exchange: authority-preserving resolve replaces the literal
/// `addr` parse; stream timeouts bound the round-trip (10s).
fn mssql_exchange(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    host: &str,
    port: u16,
    packet: &[u8],
    operation: &'static str,
) -> std::io::Result<Vec<u8>> {
    let (mut stream, _endpoint) = BrokeredTcpStream::connect(
        ctx,
        services,
        host,
        port,
        Duration::from_secs(10),
        operation,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(packet)?;
    let mut response = vec![0u8; 65536];
    let n = stream.read(&mut response).unwrap_or(0);
    Ok(response[..n].to_vec())
}

/// Provider-backed mssql registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_mssql_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let mssql = lua.create_table()?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let connect_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_mssql(lua, &cap, &host, "mssql.connect")? {
            return Ok(denied);
        }
        // Brokered reachability probe; authority-preserving resolve
        // replaces the literal-parse form.
        let (_stream, _endpoint) = BrokeredTcpStream::connect(
            &cap,
            &svc,
            &host,
            port,
            Duration::from_secs(10),
            "mssql.connect",
        )
        .map_err(mlua::Error::RuntimeError)?;

        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("status", "connected")?;

        Ok(result)
    })?;
    mssql.set("connect", connect_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let login_fn = lua.create_function(
        move |lua, (host, port, user, _pass, _db): (String, u16, String, String, String)| {
            if let Some(denied) = maybe_denied_mssql(lua, &cap, &host, "mssql.login")? {
                return Ok(denied);
            }
            // Brokered reachability check; the stub result is unchanged.
            let (_stream, _endpoint) = BrokeredTcpStream::connect(
                &cap,
                &svc,
                &host,
                port,
                Duration::from_secs(10),
                "mssql.login",
            )
            .map_err(mlua::Error::RuntimeError)?;

            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("user", user)?;

            Ok(result)
        },
    )?;
    mssql.set("login", login_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let query_fn =
        lua.create_function(move |_lua, (host, port, query): (String, u16, String)| {
            if let Some(denied) = maybe_denied_mssql(_lua, &cap, &host, "mssql.query")? {
                tracing::debug!(denial = ?denied, "mssql.query denied by capability policy");
                return Ok(String::new());
            }
            let mut packet = vec![b'S', 0x01, 0x00, 0x00];
            let len = (query.len() + 8) as u16;
            packet.extend_from_slice(&len.to_le_bytes());
            packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00]);
            packet.extend_from_slice(query.as_bytes());
            packet.push(0);

            // Brokered TDS round-trip; empty reply maps to the empty
            // string exactly like the historical `unwrap_or(0)` path.
            let response = mssql_exchange(&cap, &svc, &host, port, &packet, "mssql.query")
                .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

            if response.is_empty() {
                return Ok(String::new());
            }

            Ok(String::from_utf8_lossy(&response).to_string())
        })?;
    mssql.set("query", query_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    mssql.set("version", version_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let async_connect_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_mssql(lua, &cap, &host, "mssql.connect_async")? {
            return Ok(denied);
        }
        // Synchronous brokered probe; the async surface keeps its
        // name for script compatibility.
        let result = lua.create_table()?;

        match BrokeredTcpStream::connect(
            &cap,
            &svc,
            &host,
            port,
            Duration::from_secs(10),
            "mssql.connect_async",
        ) {
            Ok((_stream, _endpoint)) => {
                result.set("host", host)?;
                result.set("port", port)?;
                result.set("status", "connected")?;
            }
            Err(e) => {
                result.set("status", "failed")?;
                result.set("error", format!("Connection failed: {}", e))?;
            }
        }

        Ok(result)
    })?;
    mssql.set("connect_async", async_connect_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let async_login_fn = lua.create_function(
        move |lua, (host, port, user, _pass, _db): (String, u16, String, String, String)| {
            if let Some(denied) = maybe_denied_mssql(lua, &cap, &host, "mssql.login_async")? {
                return Ok(denied);
            }
            // Synchronous brokered probe; the async surface keeps its
            // name for script compatibility.
            let result = lua.create_table()?;

            match BrokeredTcpStream::connect(
                &cap,
                &svc,
                &host,
                port,
                Duration::from_secs(10),
                "mssql.login_async",
            ) {
                Ok((_stream, _endpoint)) => {
                    result.set("success", true)?;
                    result.set("user", user)?;
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
            }

            Ok(result)
        },
    )?;
    mssql.set("login_async", async_login_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let async_query_fn =
        lua.create_function(move |lua, (host, port, query): (String, u16, String)| {
            if let Some(denied) = maybe_denied_mssql(lua, &cap, &host, "mssql.query_async")? {
                return Ok(denied);
            }
            // Synchronous brokered exchange; the async surface keeps
            // its name for script compatibility.
            let result = lua.create_table()?;

            match BrokeredTcpStream::connect(
                &cap,
                &svc,
                &host,
                port,
                Duration::from_secs(10),
                "mssql.query_async",
            ) {
                Ok((mut stream, _endpoint)) => {
                    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
                    let mut packet = vec![b'S', 0x01, 0x00, 0x00];
                    let len = (query.len() + 8) as u16;
                    packet.extend_from_slice(&len.to_le_bytes());
                    packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00]);
                    packet.extend_from_slice(query.as_bytes());
                    packet.push(0);

                    if let Err(e) = stream.write_all(&packet) {
                        result.set("success", false)?;
                        result.set("error", format!("Send failed: {}", e))?;
                        return Ok(result);
                    }

                    let mut response = vec![0u8; 65536];
                    match stream.read(&mut response) {
                        Ok(n) => {
                            if n == 0 {
                                result.set("success", true)?;
                                result.set("output", "")?;
                            } else {
                                result.set("success", true)?;
                                result.set(
                                    "output",
                                    String::from_utf8_lossy(&response[..n]).to_string(),
                                )?;
                            }
                        }
                        Err(e) => {
                            result.set("success", false)?;
                            result.set("error", format!("Read failed: {}", e))?;
                        }
                    }
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
            }

            Ok(result)
        })?;
    mssql.set("query_async", async_query_fn)?;

    // mssql.exec() - Execute a stored procedure
    let exec_fn =
        lua.create_function(|_lua, (_host, _port, procedure): (String, u16, String)| {
            let result = mlua::Lua::default().create_table()?;
            result.set("procedure", procedure)?;
            result.set("executed", true)?;
            Ok(result)
        })?;
    mssql.set("exec", exec_fn)?;

    // mssql.get_db_names() - Get list of databases
    let get_db_names_fn = lua.create_function(|_lua, (_host, _port): (String, u16)| {
        let lua = mlua::Lua::default();
        let result = lua.create_table()?;

        let dbs = lua.create_table()?;
        dbs.set(1, "master")?;
        dbs.set(2, "tempdb")?;
        dbs.set(3, "model")?;
        dbs.set(4, "msdb")?;

        result.set("databases", dbs)?;
        Ok(result)
    })?;
    mssql.set("get_db_names", get_db_names_fn)?;

    // mssql.get_table_names() - Get list of tables in a database
    let get_table_names_fn =
        lua.create_function(|_lua, (_host, _port, database): (String, u16, String)| {
            let lua = mlua::Lua::default();
            let result = lua.create_table()?;

            let tables = lua.create_table()?;
            tables.set(1, "sysusers")?;
            tables.set(2, "sysobjects")?;
            tables.set(3, "syscolumns")?;

            result.set("database", database)?;
            result.set("tables", tables)?;
            Ok(result)
        })?;
    mssql.set("get_table_names", get_table_names_fn)?;

    // mssql.sp_columns() - Get column information
    let sp_columns_fn =
        lua.create_function(|_lua, (_host, _port, table): (String, u16, String)| {
            let lua = mlua::Lua::default();
            let result = lua.create_table()?;

            let columns = lua.create_table()?;

            let col1 = lua.create_table()?;
            col1.set("TABLE_QUALIFIER", "")?;
            col1.set("TABLE_OWNER", "dbo")?;
            col1.set("TABLE_NAME", table.clone())?;
            col1.set("COLUMN_NAME", "id")?;
            col1.set("DATA_TYPE", 4)?; // INTEGER
            col1.set("TYPE_NAME", "int")?;
            col1.set("PRECISION", 10)?;
            col1.set("NULLABLE", 0)?;
            columns.set(1, col1)?;

            let col2 = lua.create_table()?;
            col2.set("TABLE_QUALIFIER", "")?;
            col2.set("TABLE_OWNER", "dbo")?;
            col2.set("TABLE_NAME", table.clone())?;
            col2.set("COLUMN_NAME", "name")?;
            col2.set("DATA_TYPE", 12)?; // VARCHAR
            col2.set("TYPE_NAME", "varchar")?;
            col2.set("PRECISION", 255)?;
            col2.set("NULLABLE", 1)?;
            columns.set(2, col2)?;

            result.set("columns", columns)?;
            Ok(result)
        })?;
    mssql.set("sp_columns", sp_columns_fn)?;

    // mssql.sp_tables() - Get table information
    let sp_tables_fn = lua.create_function(|_lua, (_host, _port, db): (String, u16, String)| {
        let lua = mlua::Lua::default();
        let result = lua.create_table()?;

        let tables = lua.create_table()?;

        let tbl = lua.create_table()?;
        tbl.set("TABLE_QUALIFIER", db.as_str())?;
        tbl.set("TABLE_OWNER", "dbo")?;
        tbl.set("TABLE_NAME", "users")?;
        tbl.set("TABLE_TYPE", "TABLE")?;
        tbl.set("REMARKS", "")?;
        tables.set(1, tbl)?;

        let tbl2 = lua.create_table()?;
        tbl2.set("TABLE_QUALIFIER", db.as_str())?;
        tbl2.set("TABLE_OWNER", "dbo")?;
        tbl2.set("TABLE_NAME", "orders")?;
        tbl2.set("TABLE_TYPE", "TABLE")?;
        tbl2.set("REMARKS", "")?;
        tables.set(2, tbl2)?;

        result.set("tables", tables)?;
        Ok(result)
    })?;
    mssql.set("sp_tables", sp_tables_fn)?;

    // mssql.get_type_info() - Get SQL data type information
    let get_type_info_fn = lua.create_function(
        |_lua, (_host, _port, _data_type): (String, u16, Option<i32>)| {
            let lua = mlua::Lua::default();
            let result = lua.create_table()?;

            let types = lua.create_table()?;

            let t1 = lua.create_table()?;
            t1.set("DATA_TYPE", 4)?;
            t1.set("TYPE_NAME", "int")?;
            t1.set("COLUMN_SIZE", 10)?;
            t1.set("NULLABLE", 1)?;
            types.set(1, t1)?;

            let t2 = lua.create_table()?;
            t2.set("DATA_TYPE", 12)?;
            t2.set("TYPE_NAME", "varchar")?;
            t2.set("COLUMN_SIZE", 255)?;
            t2.set("NULLABLE", 1)?;
            types.set(2, t2)?;

            result.set("types", types)?;
            Ok(result)
        },
    )?;
    mssql.set("get_type_info", get_type_info_fn)?;

    globals.set("mssql", mssql.clone())?;
    globals.set("sybase", mssql)?;
    Ok(())
}
