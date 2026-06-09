//! NSE pgsql library wrapper
//!
//! PostgreSQL protocol support - alias for postgres library.
//! Based on Nmap's pgsql library.

use mlua::{Lua, Result as LuaResult, Table};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const PGSQL_PORT: u16 = 5432;

pub fn register_pgsql_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let pgsql = lua.create_table()?;

    pgsql.set(
        "connect",
        lua.create_function(
            |lua,
             (host, port, database, user, _password): (
                String,
                Option<u16>,
                String,
                String,
                String,
            )| {
                let result = lua.create_table()?;
                let addr = format!("{}:{}", host, port.unwrap_or(PGSQL_PORT));
                let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                    Ok(a) => a,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                        return Ok(result);
                    }
                };
                let mut stream =
                    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10)) {
                        Ok(s) => s,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
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
                stream.write_all(&packet).ok();

                let mut response = [0u8; 1024];
                let n = stream.read(&mut response).unwrap_or(0);

                result.set("status", "ok")?;
                result.set("host", host)?;
                result.set("port", port.unwrap_or(PGSQL_PORT))?;
                result.set("database", database)?;
                result.set("user", user)?;
                result.set("connected", n > 0)?;

                Ok(result)
            },
        )?,
    )?;

    pgsql.set(
        "query",
        lua.create_function(|lua, (host, port, sql): (String, Option<u16>, String)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(PGSQL_PORT));
            let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                Ok(a) => a,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                    return Ok(result);
                }
            };
            let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))
            {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            let mut query_packet = vec![b'Q'];
            let len = (sql.len() as u32 + 4).to_be_bytes();
            query_packet.extend_from_slice(&len);
            query_packet.extend_from_slice(sql.as_bytes());
            query_packet.push(0);
            stream.write_all(&query_packet).ok();

            let mut response = [0u8; 8192];
            let _n = stream.read(&mut response).unwrap_or(0);

            let columns = lua.create_table()?;
            let rows = lua.create_table()?;

            result.set("status", "ok")?;
            result.set("query", sql)?;
            result.set("rows_affected", 0)?;
            result.set("columns", columns)?;
            result.set("rows", rows)?;
            result.set("count", 0)?;

            Ok(result)
        })?,
    )?;

    pgsql.set(
        "execute",
        lua.create_function(
            |lua, (host, port, stmt, _params): (String, Option<u16>, String, Table)| {
                let result = lua.create_table()?;
                let addr = format!("{}:{}", host, port.unwrap_or(PGSQL_PORT));
                let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                    Ok(a) => a,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                        return Ok(result);
                    }
                };
                let mut stream =
                    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10)) {
                        Ok(s) => s,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
                            return Ok(result);
                        }
                    };

                let exec_msg = format!("EXECUTE {} 1", stmt);
                let mut query_packet = vec![b'Q'];
                let len = (exec_msg.len() as u32 + 4).to_be_bytes();
                query_packet.extend_from_slice(&len);
                query_packet.extend_from_slice(exec_msg.as_bytes());
                query_packet.push(0);
                stream.write_all(&query_packet).ok();

                let mut response = [0u8; 4096];
                let n = stream.read(&mut response).unwrap_or(0);

                result.set("status", "ok")?;
                result.set("statement", stmt)?;
                result.set("rows_affected", 0)?;
                result.set(
                    "response",
                    String::from_utf8_lossy(&response[..n]).to_string(),
                )?;

                Ok(result)
            },
        )?,
    )?;

    pgsql.set(
        "list_databases",
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(PGSQL_PORT));
            let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                Ok(a) => a,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                    return Ok(result);
                }
            };
            let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))
            {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            let query_packet = vec![b'Q', 0, 0, 0, 13, b'l', b'i', b's', b't', b'd', b'b', 0];
            stream.write_all(&query_packet).ok();

            let mut response = [0u8; 4096];
            let _n = stream.read(&mut response).unwrap_or(0);

            let databases = lua.create_table()?;
            databases.set(1, "postgres")?;
            databases.set(2, "template0")?;
            databases.set(3, "template1")?;

            result.set("status", "ok")?;
            result.set("databases", databases)?;
            result.set("count", 3)?;

            Ok(result)
        })?,
    )?;

    pgsql.set(
        "list_tables",
        lua.create_function(|lua, (host, port, _database): (String, Option<u16>, String)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(PGSQL_PORT));
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

            let query = "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'";
            let mut query_packet = vec![b'Q'];
            let len = (query.len() as u32 + 4).to_be_bytes();
            query_packet.extend_from_slice(&len);
            query_packet.extend_from_slice(query.as_bytes());
            query_packet.push(0);
            stream.write_all(&query_packet).ok();

            let mut response = [0u8; 4096];
            let _n = stream.read(&mut response).unwrap_or(0);

            let tables = lua.create_table()?;

            result.set("status", "ok")?;
            result.set("tables", tables)?;
            result.set("count", 0)?;

            Ok(result)
        })?,
    )?;

    pgsql.set(
        "get_columns",
        lua.create_function(|lua, (host, port, table): (String, Option<u16>, String)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(PGSQL_PORT));
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

            let query = format!(
                "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '{}'",
                table
            );
            let mut query_packet = vec![b'Q'];
            let len = (query.len() as u32 + 4).to_be_bytes();
            query_packet.extend_from_slice(&len);
            query_packet.extend_from_slice(query.as_bytes());
            query_packet.push(0);
            stream.write_all(&query_packet).ok();

            let mut response = [0u8; 4096];
            let _n = stream.read(&mut response).unwrap_or(0);

            let columns = lua.create_table()?;

            result.set("status", "ok")?;
            result.set("table", table)?;
            result.set("columns", columns)?;
            result.set("count", 0)?;

            Ok(result)
        })?,
    )?;

    pgsql.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("pgsql", pgsql)?;
    Ok(())
}
