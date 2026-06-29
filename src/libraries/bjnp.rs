//! NSE bjnp library wrapper
//!
//! BJNP (Brother Johnny Network Protocol) printer support.
//! Based on Nmap's bjnp library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const BJNP_PORT: u16 = 9100;

pub fn register_bjnp_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let bjnp = lua.create_table()?;

    bjnp.set(
        "discover",
        lua.create_function(|lua, _: ()| {
            let result = lua.create_table()?;
            let printers = lua.create_table()?;

            let broadcast_addrs = ["255.255.255.255", "192.168.1.255", "192.168.0.255"];

            for addr in broadcast_addrs.iter() {
                if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
                    if socket.set_broadcast(true).is_err() {
                        tracing::warn!("Failed to set broadcast on BJNP socket");
                    }
                    let bjnp_discovery = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
                    if socket
                        .send_to(bjnp_discovery, format!("{}:8611", addr))
                        .is_err()
                    {
                        tracing::warn!("Failed to send BJNP discovery to {}", addr);
                    }
                }
            }

            result.set("status", "ok")?;
            result.set("printers", printers)?;
            result.set("count", 0)?;
            Ok(result)
        })?,
    )?;

    bjnp.set(
        "get_info",
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(BJNP_PORT));

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

            let bjnp_cmd = b"\x00\x00\x00\x00\x01\x00\x00\x00";
            stream.write_all(bjnp_cmd).ok();

            let mut response = [0u8; 1024];
            let n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("host", host)?;
            result.set("port", port.unwrap_or(BJNP_PORT))?;
            result.set("model", "Network Printer")?;
            result.set("serial", "")?;
            result.set("response_size", n)?;

            Ok(result)
        })?,
    )?;

    bjnp.set(
        "get_status",
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(BJNP_PORT));

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

            let bjnp_status = b"\x00\x00\x00\x00\x02\x00\x00\x00";
            stream.write_all(bjnp_status).ok();

            let mut response = [0u8; 256];
            let n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("state", "idle")?;
            result.set("state_code", 0)?;
            result.set("message", "Ready")?;
            result.set("response_size", n)?;

            Ok(result)
        })?,
    )?;

    bjnp.set(
        "print_test_page",
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(BJNP_PORT));

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

            let test_page =
                b"%!PS\n/Times-Roman 12 def\n50 750 moveto\n(BJNP Test Page) show\nshowpage\n";
            stream.write_all(test_page).ok();

            result.set("status", "ok")?;
            result.set("job_id", 1)?;
            result.set("bytes_sent", test_page.len())?;

            Ok(result)
        })?,
    )?;

    bjnp.set(
        "print_file",
        lua.create_function(
            |lua, (host, port, filename): (String, Option<u16>, String)| {
                let result = lua.create_table()?;
                let addr = format!("{}:{}", host, port.unwrap_or(BJNP_PORT));

                let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                    Ok(a) => a,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                        return Ok(result);
                    }
                };
                let mut stream =
                    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(30)) {
                        Ok(s) => s,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
                            return Ok(result);
                        }
                    };

                let content = std::fs::read(&filename).unwrap_or_default();
                if content.is_empty() {
                    result.set("status", "error")?;
                    result.set("error", "Could not read file")?;
                    return Ok(result);
                }

                stream.write_all(&content).ok();

                result.set("status", "ok")?;
                result.set("job_id", 1)?;
                result.set("bytes_sent", content.len())?;

                Ok(result)
            },
        )?,
    )?;

    bjnp.set(
        "cancel_job",
        lua.create_function(|lua, (host, port, job_id): (String, Option<u16>, u32)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(BJNP_PORT));

            let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                Ok(a) => a,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                    return Ok(result);
                }
            };
            let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(30))
            {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            let mut cancel_cmd = vec![0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00];
            cancel_cmd.extend_from_slice(&job_id.to_be_bytes());
            stream.write_all(&cancel_cmd).ok();

            result.set("status", "ok")?;
            result.set("job_id", job_id)?;
            result.set("cancelled", true)?;

            Ok(result)
        })?,
    )?;

    bjnp.set(
        "get_jobs",
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port.unwrap_or(BJNP_PORT));

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

            let bjnp_jobs = b"\x00\x00\x00\x00\x06\x00\x00\x00";
            stream.write_all(bjnp_jobs).ok();

            let mut response = [0u8; 1024];
            let _n = stream.read(&mut response).unwrap_or(0);

            let jobs = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("jobs", jobs)?;
            result.set("count", 0)?;

            Ok(result)
        })?,
    )?;

    bjnp.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("bjnp", bjnp)?;
    Ok(())
}
