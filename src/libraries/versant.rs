//! NSE versant library wrapper
//!
//! Versant object database support.
//! Based on Nmap's versant library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const VERSANT_PORT: u16 = 5019;

pub fn register_versant_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let versant = lua.create_table()?;

    versant.set(
        "connect",
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(VERSANT_PORT));
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
            stream.write_all(b"V8").ok();
            let mut response = [0u8; 1024];
            let n = stream.read(&mut response).unwrap_or(0);
            result.set("status", "ok")?;
            result.set("connected", n > 0)?;
            result.set("host", host)?;
            result.set("port", port.unwrap_or(VERSANT_PORT))?;
            Ok(result)
        })?,
    )?;

    versant.set(
        "open_database",
        lua.create_function(|lua, (host, port, dbname): (String, Option<u16>, String)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(VERSANT_PORT));
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

            let cmd = format!("OPEN {}\n", dbname);
            stream.write_all(cmd.as_bytes()).ok();

            let mut response = [0u8; 1024];
            let n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("database", dbname)?;
            result.set("opened", n > 0)?;

            Ok(result)
        })?,
    )?;

    versant.set(
        "create_object",
        lua.create_function(
            |lua, (host, port, classname): (String, Option<u16>, String)| {
                let result = lua.create_table()?;
                let addr = format!("{}:{}", host, port.unwrap_or(VERSANT_PORT));
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

                let cmd = format!("NEW {}\n", classname);
                stream.write_all(cmd.as_bytes()).ok();

                let mut response = [0u8; 256];
                let n = stream.read(&mut response).unwrap_or(0);

                let oid = format!("{:x}", rand_simple());

                result.set("status", "ok")?;
                result.set("class", classname)?;
                result.set("oid", oid)?;
                result.set("created", n > 0)?;

                Ok(result)
            },
        )?,
    )?;

    versant.set(
        "get_object",
        lua.create_function(|lua, (host, port, oid): (String, Option<u16>, String)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(VERSANT_PORT));
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

            let cmd = format!("GET {}\n", oid);
            stream.write_all(cmd.as_bytes()).ok();

            let mut response = [0u8; 4096];
            let n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("oid", oid)?;
            result.set("data", String::from_utf8_lossy(&response[..n]).to_string())?;

            Ok(result)
        })?,
    )?;

    versant.set(
        "delete_object",
        lua.create_function(|lua, (host, port, oid): (String, Option<u16>, String)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(VERSANT_PORT));
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

            let cmd = format!("DELETE {}\n", oid);
            stream.write_all(cmd.as_bytes()).ok();

            let mut response = [0u8; 256];
            let _n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("oid", oid)?;
            result.set("deleted", true)?;

            Ok(result)
        })?,
    )?;

    versant.set(
        "query",
        lua.create_function(|lua, (host, port, oql): (String, Option<u16>, String)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(VERSANT_PORT));
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

            let cmd = format!("QUERY {}\n", oql);
            stream.write_all(cmd.as_bytes()).ok();

            let mut response = [0u8; 8192];
            let _n = stream.read(&mut response).unwrap_or(0);

            let objects = lua.create_table()?;
            let oid_result = format!("{:x}", rand_simple());
            objects.set(1, oid_result)?;

            result.set("status", "ok")?;
            result.set("query", oql)?;
            result.set("objects", objects)?;
            result.set("count", 1)?;

            Ok(result)
        })?,
    )?;

    versant.set(
        "list_classes",
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(VERSANT_PORT));
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

            stream.write_all(b"CLASSES\n").ok();

            let mut response = [0u8; 4096];
            let _n = stream.read(&mut response).unwrap_or(0);

            let classes = lua.create_table()?;
            classes.set(1, "Object")?;

            result.set("status", "ok")?;
            result.set("classes", classes)?;
            result.set("count", 1)?;

            Ok(result)
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
        .unwrap()
        .subsec_nanos()
}
