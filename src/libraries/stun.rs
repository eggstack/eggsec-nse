//! NSE stun library wrapper
//!
//! STUN (Session Traversal Utilities for NAT) protocol implementation.
//! Based on Nmap's stun library: https://nmap.org/nsedoc/lib/stun.html

use mlua::{Lua, Result as LuaResult};
use std::net::UdpSocket;
use std::time::Duration;
use tokio::net::UdpSocket as AsyncUdpSocket;

const STUN_PORT: u16 = 3478;
const STUN_MAGIC: u32 = 0x2112A442;

const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;

fn build_stun_request() -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&STUN_MAGIC.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet
}

fn parse_stun_response(data: &[u8]) -> Option<(String, u16)> {
    if data.len() < 20 {
        return None;
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic != STUN_MAGIC {
        return None;
    }
    let mut i = 20;
    while i + 4 <= data.len() {
        let attr_type = u16::from_be_bytes([data[i], data[i + 1]]);
        let attr_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        if attr_type == STUN_ATTR_MAPPED_ADDRESS && i + 8 <= data.len() {
            let family = data[i + 5];
            if family == 0x01 {
                let port = u16::from_be_bytes([data[i + 6], data[i + 7]]);
                let ip = format!(
                    "{}.{}.{}.{}",
                    data[i + 8],
                    data[i + 9],
                    data[i + 10],
                    data[i + 11]
                );
                return Some((ip, port));
            }
        }
        i += 4 + ((attr_len + 3) & !3);
    }
    None
}

pub fn register_stun_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let stun = lua.create_table()?;

    let new_fn = lua.create_function(|lua, host: Option<String>| {
        let s = lua.create_table()?;
        s.set(
            "host",
            host.unwrap_or_else(|| "stun.l.google.com".to_string()),
        )?;
        s.set("port", STUN_PORT)?;
        s.set("timeout", 5i64)?;
        Ok(s)
    })?;
    stun.set("new", new_fn)?;

    let bind_fn = lua.create_function(|lua, (host, port): (Option<String>, Option<u16>)| {
        let result = lua.create_table()?;
        let server = host.unwrap_or_else(|| "stun.l.google.com".to_string());
        let server_port = port.unwrap_or(STUN_PORT);
        let addr = format!("{}:{}", server, server_port);

        match UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => {
                socket.set_read_timeout(Some(Duration::from_secs(5))).ok();
                socket.set_write_timeout(Some(Duration::from_secs(5))).ok();
                let request = build_stun_request();
                match socket.send_to(&request, &addr) {
                    Ok(_) => {
                        let mut buf = [0u8; 1024];
                        match socket.recv_from(&mut buf) {
                            Ok((n, _)) => {
                                if let Some((mapped_ip, mapped_port)) =
                                    parse_stun_response(&buf[..n])
                                {
                                    result.set("success", true)?;
                                    result.set("mapped_address", mapped_ip)?;
                                    result.set("mapped_port", mapped_port)?;
                                } else {
                                    result.set("success", false)?;
                                    result.set("error", "Failed to parse STUN response")?;
                                }
                            }
                            Err(e) => {
                                result.set("success", false)?;
                                result.set("error", format!("Receive failed: {}", e))?;
                            }
                        }
                    }
                    Err(e) => {
                        result.set("success", false)?;
                        result.set("error", format!("Send failed: {}", e))?;
                    }
                }
            }
            Err(e) => {
                result.set("success", false)?;
                result.set("error", format!("Socket failed: {}", e))?;
            }
        }
        Ok(result)
    })?;
    stun.set("bind", bind_fn)?;

    let get_mapped_address_fn =
        lua.create_function(|lua, (host, port): (Option<String>, Option<u16>)| {
            let result = lua.create_table()?;
            let server = host.unwrap_or_else(|| "stun.l.google.com".to_string());
            let server_port = port.unwrap_or(STUN_PORT);
            let addr = format!("{}:{}", server, server_port);

            match UdpSocket::bind("0.0.0.0:0") {
                Ok(socket) => {
                    socket.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    let request = build_stun_request();
                    match socket.send_to(&request, &addr) {
                        Ok(_) => {
                            let mut buf = [0u8; 1024];
                            match socket.recv_from(&mut buf) {
                                Ok((n, _)) => {
                                    if let Some((mapped_ip, mapped_port)) =
                                        parse_stun_response(&buf[..n])
                                    {
                                        result.set("ip", mapped_ip)?;
                                        result.set("port", mapped_port)?;
                                    } else {
                                        result.set("error", "Failed to parse STUN response")?;
                                    }
                                }
                                Err(e) => {
                                    result.set("error", format!("Receive failed: {}", e))?;
                                }
                            }
                        }
                        Err(e) => {
                            result.set("error", format!("Send failed: {}", e))?;
                        }
                    }
                }
                Err(e) => {
                    result.set("error", format!("Socket failed: {}", e))?;
                }
            }
            Ok(result)
        })?;
    stun.set("get_mapped_address", get_mapped_address_fn)?;

    let is_nat_fn = lua.create_function(|_lua, (host, port): (Option<String>, Option<u16>)| {
        let server = host.unwrap_or_else(|| "stun.l.google.com".to_string());
        let server_port = port.unwrap_or(STUN_PORT);
        let addr = format!("{}:{}", server, server_port);

        match UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => {
                socket.set_read_timeout(Some(Duration::from_secs(5))).ok();
                socket.set_write_timeout(Some(Duration::from_secs(5))).ok();
                let request = build_stun_request();
                if socket.send_to(&request, &addr).is_ok() {
                    let mut buf = [0u8; 1024];
                    if let Ok((n, _)) = socket.recv_from(&mut buf) {
                        if parse_stun_response(&buf[..n]).is_some() {
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
            Err(_) => Ok(false),
        }
    })?;
    stun.set("is_nat", is_nat_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    stun.set("version", version_fn)?;

    let async_bind_fn =
        lua.create_function(|lua, (host, port): (Option<String>, Option<u16>)| {
            let runtime = tokio::runtime::Handle::current();
            let server = host.unwrap_or_else(|| "stun.l.google.com".to_string());
            let server_port = port.unwrap_or(STUN_PORT);

            runtime.block_on(async {
                let result = lua.create_table()?;
                let addr = format!("{}:{}", server, server_port);

                match AsyncUdpSocket::bind("0.0.0.0:0").await {
                    Ok(socket) => {
                        let request = build_stun_request();
                        match socket.send_to(&request, &addr).await {
                            Ok(_) => {
                                let mut buf = [0u8; 1024];
                                match socket.recv_from(&mut buf).await {
                                    Ok((n, _)) => {
                                        if let Some((mapped_ip, mapped_port)) =
                                            parse_stun_response(&buf[..n])
                                        {
                                            result.set("success", true)?;
                                            result.set("mapped_address", mapped_ip)?;
                                            result.set("mapped_port", mapped_port)?;
                                        } else {
                                            result.set("success", false)?;
                                            result.set("error", "Failed to parse STUN response")?;
                                        }
                                    }
                                    Err(e) => {
                                        result.set("success", false)?;
                                        result.set("error", format!("Receive failed: {}", e))?;
                                    }
                                }
                            }
                            Err(e) => {
                                result.set("success", false)?;
                                result.set("error", format!("Send failed: {}", e))?;
                            }
                        }
                    }
                    Err(e) => {
                        result.set("success", false)?;
                        result.set("error", format!("Socket failed: {}", e))?;
                    }
                }
                Ok(result)
            })
        })?;
    stun.set("bind_async", async_bind_fn)?;

    let async_get_mapped_address_fn =
        lua.create_function(|lua, (host, port): (Option<String>, Option<u16>)| {
            let runtime = tokio::runtime::Handle::current();
            let server = host.unwrap_or_else(|| "stun.l.google.com".to_string());
            let server_port = port.unwrap_or(STUN_PORT);

            runtime.block_on(async {
                let result = lua.create_table()?;
                let addr = format!("{}:{}", server, server_port);

                match AsyncUdpSocket::bind("0.0.0.0:0").await {
                    Ok(socket) => {
                        let request = build_stun_request();
                        match socket.send_to(&request, &addr).await {
                            Ok(_) => {
                                let mut buf = [0u8; 1024];
                                match socket.recv_from(&mut buf).await {
                                    Ok((n, _)) => {
                                        if let Some((mapped_ip, mapped_port)) =
                                            parse_stun_response(&buf[..n])
                                        {
                                            result.set("ip", mapped_ip)?;
                                            result.set("port", mapped_port)?;
                                        } else {
                                            result.set("error", "Failed to parse STUN response")?;
                                        }
                                    }
                                    Err(e) => {
                                        result.set("error", format!("Receive failed: {}", e))?;
                                    }
                                }
                            }
                            Err(e) => {
                                result.set("error", format!("Send failed: {}", e))?;
                            }
                        }
                    }
                    Err(e) => {
                        result.set("error", format!("Socket failed: {}", e))?;
                    }
                }
                Ok(result)
            })
        })?;
    stun.set("get_mapped_address_async", async_get_mapped_address_fn)?;

    globals.set("stun", stun)?;
    Ok(())
}
