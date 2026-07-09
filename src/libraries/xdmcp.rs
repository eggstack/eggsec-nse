//! NSE xdmcp library wrapper
//!
//! XDM (X Display Manager) Control Protocol support.
//! Based on Nmap's xdmcp library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::capabilities::NseCapabilityContext;
use crate::wrappers;

fn maybe_denied_xdmcp_tcp(
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

fn maybe_denied_xdmcp_udp(
    lua: &Lua,
    ctx: &NseCapabilityContext,
    host: &str,
    operation: &'static str,
) -> LuaResult<Option<mlua::Table>> {
    let decision = wrappers::check_network_udp(ctx, host, operation);
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

const XDMCP_PORT: u16 = 177;

// XDMCP message types
const BROADCAST_QUERY: u8 = 7;
const QUERY: u8 = 6;
const INDIRECT_QUERY: u8 = 8;
const BROADCAST_QUERY_MULTICAST: u8 = 9;
const REQUEST: u8 = 32;
const ACCEPT: u8 = 33;
const DECLINE: u8 = 34;
const MANAGE: u8 = 35;
const SAVE_YOURSELF: u8 = 38;

pub fn register_xdmcp_library(lua: &Lua, capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    let globals = lua.globals();
    let xdmcp = lua.create_table()?;

    // ==================== Helper Class ====================

    let helper = lua.create_table()?;

    helper.set(
        "new",
        lua.create_function(|lua, (host, port): (Option<String>, Option<u16>)| {
            let instance = lua.create_table()?;
            instance.set(
                "host",
                host.unwrap_or_else(|| "255.255.255.255".to_string()),
            )?;
            instance.set("port", port.unwrap_or(XDMCP_PORT))?;
            instance.set("connected", false)?;
            Ok(instance)
        })?,
    )?;

    xdmcp.set("Helper", helper)?;

    // ==================== Main Functions ====================

    // connect - Connect to XDM server and perform handshake
    let cap = capability_ctx.clone();
    xdmcp.set(
        "connect",
        lua.create_function(move |lua, (host, port): (String, Option<u16>)| {
            let result = lua.create_table()?;

            if let Some(denied) = maybe_denied_xdmcp_tcp(lua, &cap, &host, "xdmcp.connect")? {
                return Ok(denied);
            }

            let addr = format!("{}:{}", host, port.unwrap_or(XDMCP_PORT));
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

            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

            // Send XDMCP Query
            let query = create_broadcast_query();
            stream.write_all(&query).ok();

            // Read response
            let mut response = [0u8; 2048];
            match stream.read(&mut response) {
                Ok(n) if n > 0 => {
                    result.set("status", "ok")?;
                    result.set("connected", true)?;
                    result.set("host", host)?;
                    result.set("port", port.unwrap_or(XDMCP_PORT))?;

                    // Try to parse response
                    if let Some((name, status)) = parse_willing(&response[..n]) {
                        let session = lua.create_table()?;
                        session.set("name", name)?;
                        session.set("status", status)?;
                        result.set("session", session)?;
                    }
                }
                Ok(_) => {
                    result.set("status", "timeout")?;
                    result.set("connected", false)?;
                }
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                }
            }

            Ok(result)
        })?,
    )?;

    // request_login - Request XDM session
    let cap = capability_ctx.clone();
    xdmcp.set(
        "request_login",
        lua.create_function(
            move |lua, (host, port, user, password): (String, Option<u16>, String, Option<String>)| {
                let result = lua.create_table()?;

                if let Some(denied) = maybe_denied_xdmcp_tcp(lua, &cap, &host, "xdmcp.request_login")? {
                    return Ok(denied);
                }

                let addr = format!("{}:{}", host, port.unwrap_or(XDMCP_PORT));
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

                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

                // Send Request with authentication
                let request =
                    create_request(user.as_bytes(), password.unwrap_or_default().as_bytes());
                stream.write_all(&request).ok();

                // Read Accept or Decline
                let mut response = [0u8; 2048];
                match stream.read(&mut response) {
                    Ok(n) if n > 0 => {
                        let msg_type = response[4];
                        if msg_type == ACCEPT {
                            result.set("status", "ok")?;
                            result.set("authenticated", true)?;
                            result.set("session_id", 1)?;
                        } else if msg_type == DECLINE {
                            result.set("status", "error")?;
                            result.set("authenticated", false)?;
                            result.set("error", "Login declined")?;
                        } else {
                            result.set("status", "ok")?;
                            result.set("authenticated", false)?;
                        }
                    }
                    Ok(_) => {
                        result.set("status", "timeout")?;
                    }
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e.to_string())?;
                    }
                }

                Ok(result)
            },
        )?,
    )?;

    // broadcast_query - Send broadcast query to find XDM servers
    let cap = capability_ctx.clone();
    xdmcp.set(
        "broadcast_query",
        lua.create_function(move |lua, (host, port): (Option<String>, Option<u16>)| {
            let result = lua.create_table()?;

            let target = host.unwrap_or_else(|| "255.255.255.255".to_string());
            if let Some(denied) =
                maybe_denied_xdmcp_udp(lua, &cap, &target, "xdmcp.broadcast_query")?
            {
                return Ok(denied);
            }
            let target_port = port.unwrap_or(XDMCP_PORT);

            // Use UDP for broadcast
            let socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!("XDMCP: failed to bind UDP socket: {}", e);
                    None
                }
            };

            if socket.is_none() {
                result.set("status", "error")?;
                result.set("error", "Failed to create UDP socket")?;
                return Ok(result);
            }

            let socket = socket.unwrap();
            socket.set_broadcast(true).ok();
            socket.set_read_timeout(Some(Duration::from_secs(3))).ok();

            let query = create_broadcast_query();
            let addr = format!("{}:{}", target, target_port);

            match socket.send_to(&query, &addr) {
                Ok(_) => {
                    let servers = lua.create_table()?;
                    let mut count = 0;

                    // Collect responses
                    let mut buf = [0u8; 2048];
                    let deadline = std::time::Instant::now() + Duration::from_secs(3);

                    while std::time::Instant::now() < deadline {
                        socket
                            .set_read_timeout(Some(Duration::from_millis(500)))
                            .ok();
                        match socket.recv_from(&mut buf) {
                            Ok((len, src)) => {
                                if len > 0 {
                                    count += 1;
                                    let server = lua.create_table()?;
                                    let _ = server.set("address", src.to_string());

                                    if let Some(name) = parse_willing(&buf[..len]) {
                                        server.set("name", name.0)?;
                                        server.set("status", name.1)?;
                                    }

                                    servers.set(count, server)?;
                                }
                            }
                            Err(_) => break,
                        }
                    }

                    result.set("status", "ok")?;
                    result.set("servers", servers)?;
                    result.set("count", count)?;
                }
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                }
            }

            Ok(result)
        })?,
    )?;

    // get_display_number - Parse display number from X11 display string
    xdmcp.set(
        "get_display_number",
        lua.create_function(|_lua, display: String| {
            // Parse formats like ":0", ":0.0", "hostname:10"
            if let Some(colon_pos) = display.find(':') {
                if colon_pos + 1 < display.len() {
                    let after_colon = &display[colon_pos + 1..];
                    let display_num: String = after_colon
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .collect();

                    if let Ok(num) = display_num.parse::<u32>() {
                        return Ok(num);
                    }
                }
            }
            Ok(0)
        })?,
    )?;

    // parse_i18n - Parse internationalization string from packet
    xdmcp.set(
        "parse_i18n",
        lua.create_function(|lua, data: Vec<u8>| {
            let result = lua.create_table()?;

            if data.len() < 4 {
                result.set("status", "error")?;
                result.set("error", "Data too short")?;
                return Ok(result);
            }

            // Skip length prefix and extract string
            let len = u16::from_be_bytes([data[0], data[1]]) as usize;
            if data.len() >= 2 + len {
                let string_data = &data[2..2 + len];
                if let Ok(s) = String::from_utf8(string_data.to_vec()) {
                    result.set("status", "ok")?;
                    result.set("string", s)?;
                    return Ok(result);
                }
            }

            result.set("status", "error")?;
            result.set("error", "Failed to parse string")?;
            Ok(result)
        })?,
    )?;

    xdmcp.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("xdmcp", xdmcp)?;
    Ok(())
}

fn create_broadcast_query() -> Vec<u8> {
    let mut query = Vec::new();

    // Opcode (1 byte)
    query.push(BROADCAST_QUERY);

    // Length placeholder (2 bytes)
    query.extend_from_slice(&0u16.to_be_bytes());

    // Protocol version (2 bytes)
    query.extend_from_slice(&1u16.to_be_bytes());

    // Authorization name (empty)
    let auth_name = b"MIT-MAGIC-COOKIE-1";
    query.extend_from_slice(&(auth_name.len() as u16).to_be_bytes());
    query.extend_from_slice(auth_name);

    // Update length
    let len = (query.len() - 3) as u16;
    query[1..3].copy_from_slice(&len.to_be_bytes());

    query
}

fn create_request(user: &[u8], password: &[u8]) -> Vec<u8> {
    let mut request = Vec::new();

    // Opcode (1 byte)
    request.push(REQUEST);

    // Length placeholder (2 bytes)
    request.extend_from_slice(&0u16.to_be_bytes());

    // Display number
    request.extend_from_slice(&0u16.to_be_bytes());

    // Connection type (0 = Local)
    request.push(0);

    // Authentication name
    let auth_name = b"MIT-MAGIC-COOKIE-1";
    request.extend_from_slice(&(auth_name.len() as u16).to_be_bytes());
    request.extend_from_slice(auth_name);

    // Authentication data
    request.extend_from_slice(&(password.len() as u16).to_be_bytes());
    request.extend_from_slice(password);

    // Display name
    let display_name = b":0";
    request.extend_from_slice(&(display_name.len() as u16).to_be_bytes());
    request.extend_from_slice(display_name);

    // Username
    request.extend_from_slice(&(user.len() as u16).to_be_bytes());
    request.extend_from_slice(user);

    // Update length
    let len = (request.len() - 3) as u16;
    request[1..3].copy_from_slice(&len.to_be_bytes());

    request
}

fn parse_willing(data: &[u8]) -> Option<(String, String)> {
    if data.len() < 5 {
        return None;
    }

    // Message type should be willing (1)
    if data[4] != 1 {
        return None;
    }

    // Skip opcode (1) + length (2) + status type (1) = 4
    // Then we have hostname, status, display
    // Each string has a length prefix

    let mut offset = 5;

    // Hostname
    if offset + 2 > data.len() {
        return None;
    }
    let hostname_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    let hostname = if offset + hostname_len <= data.len() {
        String::from_utf8_lossy(&data[offset..offset + hostname_len]).to_string()
    } else {
        "unknown".to_string()
    };
    offset += hostname_len;

    // Status
    if offset + 2 > data.len() {
        return Some((hostname, "".to_string()));
    }
    let status_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    let status = if offset + status_len <= data.len() {
        String::from_utf8_lossy(&data[offset..offset + status_len]).to_string()
    } else {
        "".to_string()
    };

    Some((hostname, status))
}
