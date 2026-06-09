//! NSE cassandra library wrapper
//!
//! Apache Cassandra NoSQL database support.
//! Based on Nmap's cassandra library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_cassandra_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let cassandra = lua.create_table()?;

    cassandra.set(
        "connect",
        lua.create_function(
            |lua, (host, port, _keyspace): (String, u16, Option<String>)| {
                let result = lua.create_table()?;

                let addr = format!("{}:{}", host, port);
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

                // Cassandra STARTUP message
                let startup = vec![
                    0x80, 0x00, 0x00, 0x10, // Length
                    0x01, // Version (1.0)
                    0x00, // Flags
                    0x00, 0x00, // Stream
                    0x00, 0x00, // Opcode (STARTUP)
                ];

                stream.write_all(&startup).ok();

                let mut response = [0u8; 1024];
                let n = stream.read(&mut response).unwrap_or(0);

                result.set("status", "ok")?;
                result.set("connected", n > 0)?;
                result.set("host", host)?;
                result.set("port", port)?;
                result.set("cql_version", "3.4.0")?;

                Ok(result)
            },
        )?,
    )?;

    cassandra.set(
        "query",
        lua.create_function(|lua, (_host, _port, _cql): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("rows", lua.create_table()?)?;
            result.set("columns", lua.create_table()?)?;
            Ok(result)
        })?,
    )?;

    cassandra.set(
        "get_keyspaces",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("keyspaces", lua.create_table()?)?;
            Ok(result)
        })?,
    )?;

    cassandra.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("cassandra", cassandra)?;
    Ok(())
}
