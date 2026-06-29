//! NSE oops library wrapper
//!
//! Out-Of-Band (OOB) data processing support.
//! Based on Nmap's oops library.

use mlua::{Lua, Result as LuaResult, Table};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_oops_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let oops = lua.create_table()?;

    oops.set(
        "send",
        lua.create_function(|lua, (host, port, data): (String, u16, String)| {
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
            let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5))
            {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            match stream.write_all(data.as_bytes()) {
                Ok(_) => {
                    result.set("status", "ok")?;
                    result.set("bytes_sent", data.len())?;
                }
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                }
            }

            Ok(result)
        })?,
    )?;

    oops.set(
        "receive",
        lua.create_function(|lua, (host, port, timeout): (String, u16, Option<u32>)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port);

            let timeout_dur = Duration::from_millis(timeout.unwrap_or(5000) as u64);

            let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                Ok(a) => a,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                    return Ok(result);
                }
            };
            let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5))
            {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            stream
                .set_read_timeout(Some(timeout_dur))
                .unwrap_or_else(|e| tracing::warn!("Failed to set OOPS read timeout: {}", e));

            let mut buffer = vec![0u8; 65536];
            match stream.read(&mut buffer) {
                Ok(n) => {
                    result.set("status", "ok")?;
                    result.set("data", String::from_utf8_lossy(&buffer[..n]).to_string())?;
                    result.set("bytes_received", n)?;
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::TimedOut {
                        result.set("status", "timeout")?;
                        result.set("data", "")?;
                    } else {
                        result.set("status", "error")?;
                        result.set("error", e.to_string())?;
                    }
                }
            }

            Ok(result)
        })?,
    )?;

    oops.set(
        "send_and_receive",
        lua.create_function(
            |lua, (host, port, data, timeout): (String, u16, String, Option<u32>)| {
                let result = lua.create_table()?;
                let addr = format!("{}:{}", host, port);

                let timeout_dur = Duration::from_millis(timeout.unwrap_or(5000) as u64);

                let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                    Ok(a) => a,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                        return Ok(result);
                    }
                };
                let mut stream =
                    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5)) {
                        Ok(s) => s,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
                            return Ok(result);
                        }
                    };

                stream
                    .set_read_timeout(Some(timeout_dur))
                    .unwrap_or_else(|e| tracing::warn!("Failed to set OOPS read timeout: {}", e));
                stream
                    .set_write_timeout(Some(timeout_dur))
                    .unwrap_or_else(|e| tracing::warn!("Failed to set OOPS write timeout: {}", e));

                if let Err(e) = stream.write_all(data.as_bytes()) {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }

                let mut buffer = vec![0u8; 65536];
                match stream.read(&mut buffer) {
                    Ok(n) => {
                        result.set("status", "ok")?;
                        result.set("data", String::from_utf8_lossy(&buffer[..n]).to_string())?;
                        result.set("bytes_received", n)?;
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::TimedOut {
                            result.set("status", "timeout")?;
                            result.set("data", "")?;
                        } else {
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
                        }
                    }
                }

                Ok(result)
            },
        )?,
    )?;

    oops.set(
        "new",
        lua.create_function(|lua, (oob_type, data): (String, Option<String>)| {
            let pkt = lua.create_table()?;
            pkt.set("type", oob_type)?;
            pkt.set("data", data.unwrap_or_default())?;
            pkt.set(
                "timestamp",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            )?;
            Ok(pkt)
        })?,
    )?;

    oops.set(
        "set_data",
        lua.create_function(|_lua, (pkt, data): (Table, String)| {
            pkt.set("data", data)?;
            Ok(pkt)
        })?,
    )?;

    oops.set(
        "get_data",
        lua.create_function(|_lua, pkt: Table| pkt.get::<String>("data"))?,
    )?;

    oops.set(
        "set_type",
        lua.create_function(|_lua, (pkt, oob_type): (Table, String)| {
            pkt.set("type", oob_type)?;
            Ok(pkt)
        })?,
    )?;

    oops.set(
        "get_type",
        lua.create_function(|_lua, pkt: Table| pkt.get::<String>("type"))?,
    )?;

    oops.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("oops", oops)?;
    Ok(())
}
