//! NSE informix library wrapper
//!
//! Informix database support.
//! Based on Nmap's informix library.

use mlua::{Lua, Result as LuaResult, Table};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const INFORMIX_PORT: u16 = 9088;

pub fn register_informix_library(lua: &Lua) -> LuaResult<()> {
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
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(INFORMIX_PORT));

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

            let connect_str = format!("{}:INFORMIXSERVER\t\n", host);
            stream.write_all(connect_str.as_bytes()).ok();

            let mut response = [0u8; 256];
            let n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("host", host)?;
            result.set("port", port.unwrap_or(INFORMIX_PORT))?;
            result.set("connected", n > 0)?;

            Ok(result)
        })?,
    )?;

    informix.set(
        "execute",
        lua.create_function(|lua, (host, port, sql): (String, Option<u16>, String)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(INFORMIX_PORT));

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

            let exec_cmd = format!("execute\t{}\n", sql);
            stream.write_all(exec_cmd.as_bytes()).ok();

            let mut response = [0u8; 4096];
            let n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("rows_affected", 0)?;
            result.set(
                "response",
                String::from_utf8_lossy(&response[..n]).to_string(),
            )?;

            Ok(result)
        })?,
    )?;

    informix.set(
        "query",
        lua.create_function(|lua, (host, port, sql): (String, Option<u16>, String)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(INFORMIX_PORT));

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

            let query_cmd = format!("sqlexec\t{}\n", sql);
            stream.write_all(query_cmd.as_bytes()).ok();

            let mut response = [0u8; 8192];
            let n = stream.read(&mut response).unwrap_or(0);

            let columns = lua.create_table()?;
            let rows = lua.create_table()?;

            result.set("status", "ok")?;
            result.set("columns", columns)?;
            result.set("rows", rows)?;
            result.set("count", 0)?;
            result.set(
                "response",
                String::from_utf8_lossy(&response[..n]).to_string(),
            )?;

            Ok(result)
        })?,
    )?;

    informix.set(
        "list_databases",
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(INFORMIX_PORT));

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

            stream.write_all(b"databases\t\n").ok();

            let mut response = [0u8; 2048];
            let n = stream.read(&mut response).unwrap_or(0);

            let databases = lua.create_table()?;
            let response_str = String::from_utf8_lossy(&response[..n]);

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
        })?,
    )?;

    informix.set(
        "list_tables",
        lua.create_function(
            |lua, (host, port, _database): (String, Option<u16>, String)| {
                let result = lua.create_table()?;
                let addr = format!("{}:{}", host, port.unwrap_or(INFORMIX_PORT));

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

                stream.write_all(b"tables\t\n").ok();

                let mut response = [0u8; 4096];
                let n = stream.read(&mut response).unwrap_or(0);

                let tables = lua.create_table()?;
                let response_str = String::from_utf8_lossy(&response[..n]);

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
            },
        )?,
    )?;

    informix.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("informix", informix)?;
    Ok(())
}
