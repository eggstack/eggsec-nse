//! NSE nmap library wrapper
//!
//! Provides access to Nmap internals like host info, ports, and socket operations.

use mlua::{Lua, Result as LuaResult, Table};
use rustc_hash::FxHashMap;
use std::io::Write;
use std::net::TcpStream;
use std::sync::LazyLock;
use std::sync::RwLock;
use std::time::Duration;

use super::helpers::fallback_lua_table;
use crate::capabilities::NseCapabilityContext;

struct ConnectionEntry {
    stream: TcpStream,
    created_at: u64,
}

static CONNECTION_REGISTRY: LazyLock<RwLock<FxHashMap<String, ConnectionEntry>>> =
    LazyLock::new(|| RwLock::new(FxHashMap::default()));

fn get_connection_key(host: &str, port: u16) -> String {
    format!("{}:{}", host, port)
}

fn is_stream_alive(stream: &TcpStream) -> bool {
    use std::io::ErrorKind;
    match stream.peek(&mut [0u8; 1]) {
        Ok(0) => false, // EOF - connection closed
        Ok(_) => true,  // Data available
        Err(e) => {
            // WouldBlock means connection is alive but no data
            // Other errors might indicate issues but stream is usable
            e.kind() != ErrorKind::ConnectionReset
                && e.kind() != ErrorKind::ConnectionAborted
                && e.kind() != ErrorKind::BrokenPipe
        }
    }
}

pub fn clear_connection_registry() {
    if let Ok(mut reg) = CONNECTION_REGISTRY.write() {
        reg.clear();
    }
}

pub fn close_connection(host: &str, port: u16) {
    let key = get_connection_key(host, port);
    if let Ok(mut reg) = CONNECTION_REGISTRY.write() {
        reg.remove(&key);
    }
}

pub fn add_connection(host: &str, port: u16, stream: TcpStream) -> Result<(), String> {
    let key = get_connection_key(host, port);
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();

    match CONNECTION_REGISTRY.write() {
        Ok(mut reg) => {
            reg.insert(key, ConnectionEntry { stream, created_at });
            Ok(())
        }
        _ => Err("Failed to acquire write lock".to_string()),
    }
}

pub fn get_connection(host: &str, port: u16) -> Option<TcpStream> {
    let key = get_connection_key(host, port);
    if let Ok(reg) = CONNECTION_REGISTRY.read() {
        if let Some(entry) = reg.get(&key) {
            if is_stream_alive(&entry.stream) {
                // Clone the stream - TcpStream doesn't implement Clone,
                // so we need to recreate connection if needed
                // Return the entry's stream (will be moved)
                return None; // Can't clone, handle differently below
            }
        }
    }
    None
}

fn reconnect_stream(host: &str, port: u16, timeout_secs: i64) -> Option<TcpStream> {
    let addr = format!("{}:{}", host, port).parse().ok()?;
    let stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(timeout_secs as u64)).ok()?;
    if stream
        .set_read_timeout(Some(Duration::from_secs(timeout_secs as u64)))
        .is_err()
    {
        tracing::warn!("Failed to set read timeout on reconnect stream");
    }
    if stream
        .set_write_timeout(Some(Duration::from_secs(timeout_secs as u64)))
        .is_err()
    {
        tracing::warn!("Failed to set write timeout on reconnect stream");
    }
    Some(stream)
}

pub fn register_nmap_library(lua: &Lua, capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    let globals = lua.globals();
    // Clone for use in closures (NseCapabilityContext is Clone)
    let capability_ctx = capability_ctx.clone();

    let nmap = lua.create_table()?;

    nmap.set("target", "")?;
    nmap.set("address_family", "inet")?;
    nmap.set("version", env!("CARGO_PKG_VERSION"))?;
    nmap.set("numopen", 0i32)?;
    nmap.set("refcount", 0i32)?;

    nmap.set("me", lua.create_table()?)?;
    nmap.set(
        "registry",
        lua.create_function(|lua, ()| {
            let globals = lua.globals();
            let nmap_tbl: Table = globals.get("nmap")?;
            let registry: Table = nmap_tbl.get("registry").unwrap_or_else(|_| {
                let t = fallback_lua_table(lua);
                if let Err(e) = nmap_tbl.set("registry", t.clone()) {
                    tracing::warn!("nmap: failed to set initial registry: {}", e);
                }
                t
            });
            Ok(registry)
        })?,
    )?;
    nmap.set("_ports", lua.create_table()?)?;
    nmap.set("_hostinfo", lua.create_table()?)?;

    nmap.set(
        "get_hostname",
        lua.create_function(|lua, host: Option<String>| {
            let globals = lua.globals();
            let nmap_tbl: Table = globals
                .get("nmap")
                .unwrap_or_else(|_| fallback_lua_table(lua));
            let hostinfo: Table = nmap_tbl
                .get("_hostinfo")
                .unwrap_or_else(|_| fallback_lua_table(lua));

            if let Some(h) = host {
                hostinfo
                    .get::<String>(format!("{}.hostname", h))
                    .or_else(|_| Ok("".to_string()))
            } else {
                hostinfo
                    .get::<String>("hostname")
                    .or_else(|_| Ok("".to_string()))
            }
        })?,
    )?;

    nmap.set(
        "get_host_ip",
        lua.create_function(|lua, _host: Option<String>| {
            let globals = lua.globals();
            let nmap_tbl: Table = globals
                .get("nmap")
                .unwrap_or_else(|_| fallback_lua_table(lua));
            let hostinfo: Table = nmap_tbl
                .get("_hostinfo")
                .unwrap_or_else(|_| fallback_lua_table(lua));
            hostinfo.get::<String>("ip").or_else(|_| Ok("".to_string()))
        })?,
    )?;

    nmap.set(
        "get_port_state",
        lua.create_function(|lua, (host, port): (Option<String>, u16)| {
            let globals = lua.globals();
            let nmap_tbl: Table = globals
                .get("nmap")
                .unwrap_or_else(|_| fallback_lua_table(lua));
            let ports: Table = nmap_tbl
                .get("_ports")
                .unwrap_or_else(|_| fallback_lua_table(lua));

            let key = if let Some(ref h) = host {
                format!("{}.{}.tcp", h, port)
            } else {
                format!("{}.tcp", port)
            };

            if let Ok(port_info) = ports.get::<Table>(key.clone()) {
                return Ok(port_info);
            }

            let t = lua.create_table()?;
            t.set("number", port)?;
            t.set("protocol", "tcp")?;
            t.set("state", "unknown")?;
            Ok(t)
        })?,
    )?;

    let get_ports_fn = lua.create_function(
        |lua, args: (Option<String>, Option<u16>, Option<String>, Option<String>)| {
            let (host, port, protocol, state) = args;
            let globals = lua.globals();
            let nmap_tbl: Table = globals
                .get("nmap")
                .unwrap_or_else(|_| fallback_lua_table(lua));
            let ports: Table = nmap_tbl
                .get("_ports")
                .unwrap_or_else(|_| fallback_lua_table(lua));

            let results = lua.create_table()?;
            let mut idx = 1;

            for (key, port_info) in ports.pairs::<String, Table>().flatten() {
                let matches_host = host.as_ref().map_or(true, |h| key.starts_with(h));
                let matches_port = port.map_or(true, |p| {
                    port_info.get::<u16>("number").is_ok_and(|np| np == p)
                });
                let matches_proto = protocol.as_ref().map_or(true, |pr| {
                    port_info
                        .get::<String>("protocol")
                        .is_ok_and(|np| np == pr.as_str())
                });
                let matches_state = state.as_ref().map_or(true, |s| {
                    port_info
                        .get::<String>("state")
                        .is_ok_and(|ns| ns == s.as_str())
                });

                if matches_host && matches_port && matches_proto && matches_state {
                    results.set(idx, port_info).ok();
                    idx += 1;
                }
            }

            Ok(results)
        },
    )?;
    nmap.set("get_ports", get_ports_fn)?;

    nmap.set(
        "set_port_state",
        lua.create_function(|lua, (host, port, state): (Option<String>, u16, String)| {
            let globals = lua.globals();
            let nmap_tbl: Table = globals
                .get("nmap")
                .unwrap_or_else(|_| fallback_lua_table(lua));
            let ports: Table = nmap_tbl
                .get("_ports")
                .unwrap_or_else(|_| fallback_lua_table(lua));

            let key = if let Some(h) = host {
                format!("{}.{}.tcp", h, port)
            } else {
                format!("{}.tcp", port)
            };

            let port_info = lua.create_table()?;
            port_info.set("number", port)?;
            port_info.set("protocol", "tcp")?;
            port_info.set("state", state)?;

            ports.set(key, port_info)?;
            Ok(())
        })?,
    )?;

    nmap.set(
        "new_socket",
        lua.create_function(|lua, (af, sock_type): (Option<String>, Option<String>)| {
            let socket = lua.create_table()?;
            let family = af.unwrap_or_else(|| "inet".to_string());
            let socket_type = sock_type.unwrap_or_else(|| "stream".to_string());

            socket.set("closed", false)?;
            socket.set("family", family)?;
            socket.set("type", socket_type)?;
            socket.set("timeout", 10i64)?;
            socket.set("socket_id", 0i32)?;
            socket.set("protocol", "tcp")?;
            socket.set("connected", false)?;

            Ok(socket)
        })?,
    )?;

    nmap.set(
        "new_udp_socket",
        lua.create_function(|lua, (af, _sock_type): (Option<String>, Option<String>)| {
            let socket = lua.create_table()?;
            let family = af.unwrap_or_else(|| "inet".to_string());

            socket.set("closed", false)?;
            socket.set("family", family)?;
            socket.set("type", "udp")?;
            socket.set("timeout", 10i64)?;
            socket.set("socket_id", 0i32)?;
            socket.set("protocol", "udp")?;
            socket.set("connected", false)?;

            Ok(socket)
        })?,
    )?;

    nmap.set(
        "socket_connect",
        lua.create_function(|lua, (socket_table, host, port): (Table, String, u16)| {
            let result = lua.create_table()?;

            if let Ok(closed) = socket_table.get::<bool>("closed") {
                if closed {
                    result.set("status", "error")?;
                    result.set("error", "socket is closed")?;
                    return Ok(result);
                }
            }

            let timeout = socket_table.get::<i64>("timeout").unwrap_or(10);
            let addr = format!("{}:{}", host, port);
            let socket_addr: std::net::SocketAddr = match addr.parse() {
                Ok(a) => a,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", format!("Address parse error: {}", e))?;
                    return Ok(result);
                }
            };

            match std::net::TcpStream::connect_timeout(
                &socket_addr,
                Duration::from_secs(timeout as u64),
            ) {
                Ok(stream) => {
                    if let Err(e) =
                        stream.set_read_timeout(Some(Duration::from_secs(timeout as u64)))
                    {
                        tracing::warn!("nmap socket_connect: failed to set read timeout: {}", e);
                    }
                    if let Err(e) =
                        stream.set_write_timeout(Some(Duration::from_secs(timeout as u64)))
                    {
                        tracing::warn!("nmap socket_connect: failed to set write timeout: {}", e);
                    }

                    let conn_key = get_connection_key(&host, port);
                    if let Ok(mut reg) = CONNECTION_REGISTRY.write() {
                        reg.insert(
                            conn_key.clone(),
                            ConnectionEntry {
                                stream,
                                created_at: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            },
                        );
                    }

                    let socket_id = format!("socket_{}", conn_key);
                    if let Err(e) = socket_table.set("socket_key", socket_id) {
                        tracing::warn!("nmap socket_connect: failed to set socket_key: {}", e);
                    }

                    result.set("status", "connected")?;
                    result.set("host", host.clone())?;
                    result.set("port", port)?;
                    socket_table.set("connected", true)?;
                    socket_table.set("remote_host", host)?;
                    socket_table.set("remote_port", port)?;
                    socket_table.set(
                        "connected_at",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    )?;
                }
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                }
            }

            Ok(result)
        })?,
    )?;

    nmap.set(
        "socket_send",
        lua.create_function(|lua, (socket_table, data): (Table, String)| {
            let result = lua.create_table()?;

            if let Ok(closed) = socket_table.get::<bool>("closed") {
                if closed {
                    result.set("status", "error")?;
                    result.set("error", "socket is closed")?;
                    return Ok(result);
                }
            }

            if let Ok(connected) = socket_table.get::<bool>("connected") {
                if !connected {
                    result.set("status", "error")?;
                    result.set("error", "not connected")?;
                    return Ok(result);
                }
            }

            let host: String = socket_table.get("remote_host").unwrap_or_default();
            let port: u16 = socket_table.get("remote_port").unwrap_or(0);
            let timeout = socket_table.get::<i64>("timeout").unwrap_or(10);

            if host.is_empty() || port == 0 {
                result.set("status", "error")?;
                result.set("error", "not connected")?;
                return Ok(result);
            }

            let conn_key = get_connection_key(&host, port);

            // Try to get existing connection and check if alive
            let mut should_reconnect = false;
            {
                let reg = match CONNECTION_REGISTRY.read() {
                    Ok(r) => r,
                    Err(_) => {
                        result.set("status", "error")?;
                        result.set("error", "failed to acquire read lock")?;
                        return Ok(result);
                    }
                };

                if let Some(entry) = reg.get(&conn_key) {
                    if !is_stream_alive(&entry.stream) {
                        should_reconnect = true;
                    }
                } else {
                    should_reconnect = true;
                }
            }

            // Reconnect if needed
            if should_reconnect {
                match reconnect_stream(&host, port, timeout) {
                    Some(new_stream) => {
                        if let Ok(mut reg) = CONNECTION_REGISTRY.write() {
                            reg.insert(
                                conn_key.clone(),
                                ConnectionEntry {
                                    stream: new_stream,
                                    created_at: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs(),
                                },
                            );
                        }
                    }
                    _ => {
                        result.set("status", "error")?;
                        result.set("error", "failed to reconnect")?;
                        return Ok(result);
                    }
                }
            }

            // Try to send data
            if let Ok(mut reg) = CONNECTION_REGISTRY.write() {
                if let Some(entry) = reg.get_mut(&conn_key) {
                    match entry.stream.write_all(data.as_bytes()) {
                        Ok(()) => {
                            result.set("status", "sent")?;
                            result.set("bytes", data.len())?;
                        }
                        Err(e) => {
                            // Try one reconnect on write error
                            drop(reg); // Release lock before reconnecting
                            if let Some(new_stream) = reconnect_stream(&host, port, timeout) {
                                if let Ok(mut reg) = CONNECTION_REGISTRY.write() {
                                    reg.insert(
                                        conn_key.clone(),
                                        ConnectionEntry {
                                            stream: new_stream,
                                            created_at: std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap_or_default()
                                                .as_secs(),
                                        },
                                    );
                                    if let Some(entry) = reg.get_mut(&conn_key) {
                                        match entry.stream.write_all(data.as_bytes()) {
                                            Ok(()) => {
                                                result.set("status", "sent")?;
                                                result.set("bytes", data.len())?;
                                            }
                                            Err(e2) => {
                                                result.set("status", "error")?;
                                                result.set("error", e2.to_string())?;
                                            }
                                        }
                                        return Ok(result);
                                    }
                                }
                            }
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
                        }
                    }
                    return Ok(result);
                }
            }

            result.set("status", "error")?;
            result.set("error", "connection not found in registry")?;
            Ok(result)
        })?,
    )?;

    nmap.set(
        "socket_receive",
        lua.create_function(|lua, (socket_table, size): (Table, Option<usize>)| {
            let result = lua.create_table()?;
            let size = size.unwrap_or(1024);

            if let Ok(closed) = socket_table.get::<bool>("closed") {
                if closed {
                    result.set("status", "error")?;
                    result.set("error", "socket is closed")?;
                    return Ok(result);
                }
            }

            if let Ok(connected) = socket_table.get::<bool>("connected") {
                if !connected {
                    result.set("status", "error")?;
                    result.set("error", "not connected")?;
                    return Ok(result);
                }
            }

            let host: String = socket_table.get("remote_host").unwrap_or_default();
            let port: u16 = socket_table.get("remote_port").unwrap_or(0);
            let timeout = socket_table.get::<i64>("timeout").unwrap_or(10);

            if host.is_empty() || port == 0 {
                result.set("status", "error")?;
                result.set("error", "not connected")?;
                return Ok(result);
            }

            let conn_key = get_connection_key(&host, port);

            // Check if connection exists and is alive
            let mut should_reconnect = false;
            {
                let reg = match CONNECTION_REGISTRY.read() {
                    Ok(r) => r,
                    Err(_) => {
                        result.set("status", "error")?;
                        result.set("error", "failed to acquire read lock")?;
                        return Ok(result);
                    }
                };

                if let Some(entry) = reg.get(&conn_key) {
                    if !is_stream_alive(&entry.stream) {
                        should_reconnect = true;
                    }
                } else {
                    should_reconnect = true;
                }
            }

            // Attempt reconnect if needed
            if should_reconnect {
                match reconnect_stream(&host, port, timeout) {
                    Some(new_stream) => {
                        if let Ok(mut reg) = CONNECTION_REGISTRY.write() {
                            reg.insert(
                                conn_key.clone(),
                                ConnectionEntry {
                                    stream: new_stream,
                                    created_at: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs(),
                                },
                            );
                        }
                    }
                    _ => {
                        result.set("status", "error")?;
                        result.set("error", "failed to reconnect")?;
                        return Ok(result);
                    }
                }
            }

            // Try to receive data
            if let Ok(mut reg) = CONNECTION_REGISTRY.write() {
                if let Some(entry) = reg.get_mut(&conn_key) {
                    use std::io::Read;
                    let mut buffer = vec![0u8; size];
                    match entry.stream.read(&mut buffer) {
                        Ok(n) => {
                            let data = String::from_utf8_lossy(&buffer[..n]).to_string();
                            result.set("status", "ok")?;
                            result.set("data", data)?;
                            result.set("length", n)?;
                        }
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
                        }
                    }
                    return Ok(result);
                }
            }

            result.set("status", "error")?;
            result.set("error", "connection not found in registry")?;
            Ok(result)
        })?,
    )?;

    if let Err(e) = nmap.set(
        "socket_close",
        lua.create_function(|_lua, socket_table: Table| {
            let host: String = socket_table.get("remote_host").unwrap_or_default();
            let port: u16 = socket_table.get("remote_port").unwrap_or(0);

            if !host.is_empty() && port > 0 {
                let conn_key = get_connection_key(&host, port);
                if let Ok(mut reg) = CONNECTION_REGISTRY.write() {
                    reg.remove(&conn_key);
                }
            }

            if let Err(e) = socket_table.set("closed", true) {
                tracing::warn!("nmap socket_close: failed to set closed: {}", e);
            }
            if let Err(e) = socket_table.set("connected", false) {
                tracing::warn!("nmap socket_close: failed to set connected: {}", e);
            }
            Ok(())
        })?,
    ) {
        tracing::warn!("nmap socket_close: {}", e);
    }

    nmap.set(
        "registry_get",
        lua.create_function(|lua, key: String| {
            let globals = lua.globals();
            let nmap_tbl: Table = globals
                .get("nmap")
                .unwrap_or_else(|_| fallback_lua_table(lua));
            let registry: Table = nmap_tbl
                .get("registry")
                .unwrap_or_else(|_| fallback_lua_table(lua));
            registry.get(key.as_str()).or_else(|_| Ok(mlua::Value::Nil))
        })?,
    )?;

    nmap.set(
        "registry_set",
        lua.create_function(|lua, (key, value): (String, mlua::Value)| {
            let globals = lua.globals();
            let nmap_tbl: Table = globals
                .get("nmap")
                .unwrap_or_else(|_| fallback_lua_table(lua));
            let registry: Table = nmap_tbl.get("registry").unwrap_or_else(|_| {
                let t = fallback_lua_table(lua);
                if let Err(e) = nmap_tbl.set("registry", t.clone()) {
                    tracing::warn!("nmap registry_set: failed to set initial registry: {}", e);
                }
                t
            });
            registry.set(key.as_str(), value)?;
            Ok(true)
        })?,
    )?;

    nmap.set(
        "ref_increment",
        lua.create_function(|lua, _: ()| {
            let globals = lua.globals();
            let nmap_tbl: Table = globals
                .get("nmap")
                .unwrap_or_else(|_| fallback_lua_table(lua));
            let mut count: i32 = nmap_tbl.get("refcount").unwrap_or(0);
            count += 1;
            nmap_tbl.set("refcount", count)?;
            Ok(count)
        })?,
    )?;

    nmap.set(
        "ref_decrement",
        lua.create_function(|lua, _: ()| {
            let globals = lua.globals();
            let nmap_tbl: Table = globals
                .get("nmap")
                .unwrap_or_else(|_| fallback_lua_table(lua));
            let mut count: i32 = nmap_tbl.get("refcount").unwrap_or(0);
            count = (count - 1).max(0);
            nmap_tbl.set("refcount", count)?;
            Ok(count)
        })?,
    )?;

    nmap.set(
        "is_admin",
        lua.create_function({
            let cap = capability_ctx.clone();
            move |_lua, _: ()| {
                #[cfg(unix)]
                {
                    use crate::wrappers;
                    let decision = wrappers::check_process_exec(&cap, "id", "nmap.is_admin");
                    if decision.is_denied() {
                        return Ok(false);
                    }
                    Ok(std::process::Command::new("id")
                        .arg("-u")
                        .output()
                        .map(|o| o.stdout == b"0\n")
                        .unwrap_or(false))
                }
                #[cfg(not(unix))]
                {
                    Ok(false)
                }
            }
        })?,
    )?;

    nmap.set(
        "current_time",
        lua.create_function(|_lua, _: ()| Ok(chrono::Utc::now().timestamp()))?,
    )?;

    nmap.set(
        "get_random_bytes",
        lua.create_function(|_lua, count: i32| {
            let bytes: Vec<u8> = (0..count.max(0) as usize)
                .map(|_| rand::random::<u8>())
                .collect();
            Ok(bytes)
        })?,
    )?;

    nmap.set(
        "get_random",
        lua.create_function(|_lua, (min, max): (i32, i32)| {
            if min >= max {
                return Ok(min);
            }
            Ok(rand::random::<i32>() % (max - min + 1) + min)
        })?,
    )?;

    nmap.set(
        "version",
        lua.create_function(|_lua, _: ()| Ok(env!("CARGO_PKG_VERSION")))?,
    )?;

    nmap.set(
        "status",
        lua.create_function(|lua, (_host, state): (Option<String>, String)| {
            let globals = lua.globals();
            let nmap_tbl: Table = globals
                .get("nmap")
                .unwrap_or_else(|_| fallback_lua_table(lua));
            let hostinfo: Table = nmap_tbl
                .get("_hostinfo")
                .unwrap_or_else(|_| fallback_lua_table(lua));
            hostinfo.set("status", state.as_str())?;
            Ok(())
        })?,
    )?;

    nmap.set(
        "excluded_port",
        lua.create_function(|_lua, (_port, _protocol): (u16, String)| Ok(false))?,
    )?;

    nmap.set(
        "excluded_portrange",
        lua.create_function(|_lua, _range: String| Ok(false))?,
    )?;

    nmap.set(
        "list_supported_methods",
        lua.create_function(|lua, _host: Option<String>| {
            let table = lua.create_table()?;
            Ok(table)
        })?,
    )?;

    nmap.set(
        "nse_get_output",
        lua.create_function(|lua, _: ()| {
            let globals = lua.globals();
            let output: Table = globals.get("_SCRIPT_OUTPUT").unwrap_or_else(|_| {
                lua.create_table()
                    .unwrap_or_else(|_| fallback_lua_table(lua))
            });
            let result = lua.create_table()?;
            result.set("lines", output)?;
            Ok(result)
        })?,
    )?;

    // get_port_state is already defined above (line 146) with signature (host, port) -> Table
    // We add get_port_state_by_protocol for the alternative signature
    // Note: set_port_state is already defined above (line 218) with signature (host, port, state)
    nmap.set(
        "get_port_state_by_protocol",
        lua.create_function(|lua, (port, protocol): (u16, String)| {
            let globals = lua.globals();
            let nmap_tbl: Table = globals.get("nmap")?;
            let ports: Table = nmap_tbl.get("_ports")?;

            let port_key = format!("{}/{}", port, protocol);
            if let Ok(port_entry) = ports.get::<Table>(port_key.as_str()) {
                let state: String = port_entry
                    .get("state")
                    .unwrap_or_else(|_| "unknown".to_string());
                return Ok(state);
            }

            Ok("unknown".to_string())
        })?,
    )?;

    nmap.set(
        "port_to_number",
        lua.create_function(|_lua, service: String| {
            let port = match service.as_str() {
                "http" => 80,
                "https" => 443,
                "ftp" => 21,
                "ssh" => 22,
                "telnet" => 23,
                "smtp" => 25,
                "pop3" => 110,
                "imap" => 143,
                "dns" => 53,
                "mysql" => 3306,
                "postgres" => 5432,
                "redis" => 6379,
                "mongodb" => 27017,
                "mssql" => 1433,
                "oracle" => 1521,
                "ldap" => 389,
                "smb" => 445,
                "rdp" => 3389,
                "vnc" => 5900,
                _ => 0,
            };
            Ok(port)
        })?,
    )?;

    nmap.set(
        "port_to_servicename",
        lua.create_function(|_lua, (port, _protocol): (u16, String)| {
            let service = match port {
                20 => "ftp-data",
                21 => "ftp",
                22 => "ssh",
                23 => "telnet",
                25 => "smtp",
                53 => "dns",
                80 => "http",
                110 => "pop3",
                143 => "imap",
                443 => "https",
                445 => "smb",
                993 => "imaps",
                995 => "pop3s",
                1433 => "mssql",
                1521 => "oracle",
                3306 => "mysql",
                3389 => "rdp",
                5432 => "postgres",
                5900 => "vnc",
                6379 => "redis",
                27017 => "mongodb",
                _ => "",
            };
            Ok(service.to_string())
        })?,
    )?;

    nmap.set(
        "list_interfaces",
        lua.create_function(move |lua, _: ()| {
            let interfaces = lua.create_table()?;

            let lo = lua.create_table()?;
            lo.set("name", "lo")?;
            lo.set("ip", "127.0.0.1")?;
            lo.set("address_family", "inet")?;
            lo.set("mac", "")?;
            lo.set("up", true)?;
            lo.set("ipv6", false)?;
            interfaces.set(1, lo)?;

            let eth0 = lua.create_table()?;
            eth0.set("name", "eth0")?;
            eth0.set("ip", "0.0.0.0")?;
            eth0.set("address_family", "inet")?;
            eth0.set("mac", "")?;
            eth0.set("up", true)?;
            eth0.set("ipv6", false)?;
            interfaces.set(2, eth0)?;

            Ok(interfaces)
        })?,
    )?;

    nmap.set(
        "get_interface",
        lua.create_function(|lua, name: Option<String>| {
            let iface = lua.create_table()?;

            let name = name.unwrap_or_else(|| "eth0".to_string());
            iface.set("name", name.as_str())?;
            iface.set("ip", "0.0.0.0")?;
            iface.set("address_family", "inet")?;
            iface.set("mac", "")?;
            iface.set("up", true)?;

            Ok(iface)
        })?,
    )?;

    nmap.set(
        "address",
        lua.create_function(|lua, host: Option<Table>| {
            let globals = lua.globals();
            let nmap_tbl: Table = globals.get("nmap")?;

            if let Ok(hostinfo) = nmap_tbl.get::<Table>("_hostinfo") {
                if let Ok(address) = hostinfo.get::<String>("address") {
                    return Ok(address);
                }
            }

            if let Some(h) = host {
                if let Ok(ip) = h.get::<String>("ip") {
                    return Ok(ip);
                }
            }

            let target: String = nmap_tbl.get("target").unwrap_or_default();
            Ok(target)
        })?,
    )?;

    nmap.set(
        "hostname",
        lua.create_function(|lua, _host: Option<Table>| {
            let globals = lua.globals();
            let nmap_tbl: Table = globals.get("nmap")?;

            if let Ok(hostinfo) = nmap_tbl.get::<Table>("_hostinfo") {
                if let Ok(name) = hostinfo.get::<String>("name") {
                    return Ok(name);
                }
            }

            Ok(String::new())
        })?,
    )?;

    nmap.set(
        "mac_addr",
        lua.create_function(|lua, _host: Option<Table>| {
            let globals = lua.globals();
            let nmap_tbl: Table = globals.get("nmap")?;

            if let Ok(hostinfo) = nmap_tbl.get::<Table>("_hostinfo") {
                if let Ok(mac) = hostinfo.get::<String>("mac") {
                    return Ok(mac);
                }
            }

            Ok(String::new())
        })?,
    )?;

    nmap.set(
        "os_init",
        lua.create_function(|lua, _: ()| {
            let globals = lua.globals();
            let nmap_tbl: Table = globals.get("nmap")?;
            let hostinfo: Table = nmap_tbl.get("_hostinfo")?;
            hostinfo.set("os", lua.create_table()?)?;
            Ok(true)
        })?,
    )?;

    nmap.set(
        "os_scan",
        lua.create_function(|lua, _: ()| {
            let result = lua.create_table()?;
            result.set("status", "failed")?;
            Ok(result)
        })?,
    )?;

    nmap.set(
        "os_ident",
        lua.create_function(|lua, _: ()| {
            let result = lua.create_table()?;
            result.set("name", "unknown")?;
            result.set("accuracy", 0)?;
            Ok(result)
        })?,
    )?;

    nmap.set(
        "nmap_version",
        lua.create_function(|lua, _: ()| {
            let result = lua.create_table()?;
            result.set("version", "1.0.0")?;
            result.set("major", 1)?;
            result.set("minor", 0)?;
            result.set("revision", 0)?;
            result.set("description", "Eggsec NSE")?;
            Ok(result)
        })?,
    )?;

    nmap.set(
        "mutex",
        lua.create_function(|lua, object: Option<String>| {
            let mutex = lua.create_table()?;
            let obj_name = object.unwrap_or_else(|| "default".to_string());
            mutex.set("object", obj_name.clone())?;
            mutex.set("locked", false)?;
            mutex.set("count", 0)?;

            let lock_fn = lua.create_function(|_lua, m: Table| {
                if let Err(e) = m.set("locked", true) {
                    tracing::warn!("nmap mutex lock: failed to set locked: {}", e);
                }
                let count: i32 = m.get("count").unwrap_or(0);
                if let Err(e) = m.set("count", count + 1) {
                    tracing::warn!("nmap mutex lock: failed to set count: {}", e);
                }
                Ok(true)
            })?;
            mutex.set("lock", lock_fn)?;

            let unlock_fn = lua.create_function(|_lua, m: Table| {
                if let Err(e) = m.set("locked", false) {
                    tracing::warn!("nmap mutex unlock: failed to set locked: {}", e);
                }
                Ok(true)
            })?;
            mutex.set("unlock", unlock_fn)?;

            let trylock_fn = lua.create_function(|_lua, m: Table| {
                let locked: bool = m.get("locked").unwrap_or(false);
                if locked {
                    return Ok(false);
                }
                if let Err(e) = m.set("locked", true) {
                    tracing::warn!("nmap mutex trylock: failed to set locked: {}", e);
                }
                let count: i32 = m.get("count").unwrap_or(0);
                if let Err(e) = m.set("count", count + 1) {
                    tracing::warn!("nmap mutex trylock: failed to set count: {}", e);
                }
                Ok(true)
            })?;
            mutex.set("trylock", trylock_fn)?;

            Ok(mutex)
        })?,
    )?;

    nmap.set(
        "condvar",
        lua.create_function(|lua, object: Option<String>| {
            let condvar = lua.create_table()?;
            let obj_name = object.unwrap_or_else(|| "default".to_string());
            condvar.set("object", obj_name)?;
            condvar.set("waiting", lua.create_table()?)?;

            let wait_fn = lua.create_function(|lua, c: Table| {
                let waiting: Table = c.get("waiting").unwrap_or_else(|_| fallback_lua_table(lua));
                let len = waiting.len().unwrap_or(0);
                waiting.set(len + 1, true)?;
                if let Err(e) = c.set("waiting", waiting) {
                    tracing::warn!("nmap condvar wait: failed to set waiting: {}", e);
                }
                Ok(true)
            })?;
            condvar.set("wait", wait_fn)?;

            let signal_fn = lua.create_function(|lua, c: Table| {
                let waiting: Table = c.get("waiting").unwrap_or_else(|_| fallback_lua_table(lua));
                if waiting.len().unwrap_or(0) > 0 {
                    waiting.set(1, mlua::Value::Nil)?;
                }
                if let Err(e) = c.set("waiting", waiting) {
                    tracing::warn!("nmap condvar signal: failed to set waiting: {}", e);
                }
                Ok(true)
            })?;
            condvar.set("signal", signal_fn)?;

            let broadcast_fn = lua.create_function(|lua, c: Table| {
                if let Err(e) = c.set("waiting", lua.create_table()?) {
                    tracing::warn!("nmap condvar broadcast: failed to set waiting: {}", e);
                }
                Ok(true)
            })?;
            condvar.set("broadcast", broadcast_fn)?;

            Ok(condvar)
        })?,
    )?;

    nmap.set(
        "is_privileged",
        lua.create_function({
            let cap = capability_ctx.clone();
            move |_lua, _: ()| {
                #[cfg(unix)]
                {
                    use crate::wrappers;
                    let decision = wrappers::check_process_exec(&cap, "id", "nmap.is_privileged");
                    if decision.is_denied() {
                        return Ok(false);
                    }
                    Ok(std::process::Command::new("id")
                        .arg("-u")
                        .output()
                        .map(|o| o.stdout == b"0\n")
                        .unwrap_or(false))
                }
                #[cfg(not(unix))]
                {
                    Ok(false)
                }
            }
        })?,
    )?;

    nmap.set(
        "clock_ms",
        lua.create_function(|_lua, _: ()| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            Ok(now as f64)
        })?,
    )?;

    nmap.set(
        "clock",
        lua.create_function(|_lua, _: ()| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as f64;
            Ok(now)
        })?,
    )?;

    nmap.set(
        "bind",
        lua.create_function(|lua, (address, port): (Option<String>, Option<u16>)| {
            let result = lua.create_table()?;
            result.set("address", address.unwrap_or_else(|| "0.0.0.0".to_string()))?;
            result.set("port", port.unwrap_or(0))?;
            result.set("bound", true)?;
            Ok(result)
        })?,
    )?;

    nmap.set(
        "connect",
        lua.create_function(|lua, (host, port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("host", host)?;
            result.set("port", port)?;
            result.set("status", "connected")?;
            Ok(result)
        })?,
    )?;

    nmap.set(
        "new_socket",
        lua.create_function(|lua, (protocol, af): (Option<String>, Option<String>)| {
            let socket = lua.create_table()?;
            socket.set("protocol", protocol.unwrap_or_else(|| "tcp".to_string()))?;
            socket.set("address_family", af.unwrap_or_else(|| "inet".to_string()))?;
            socket.set("socket", -1)?;
            socket.set("connected", false)?;
            Ok(socket)
        })?,
    )?;

    nmap.set(
        "ethernet_open",
        lua.create_function(|lua, interface: Option<String>| {
            let iface = interface.unwrap_or_else(|| "eth0".to_string());
            let result = lua.create_table()?;
            result.set("interface", iface)?;
            result.set("opened", true)?;
            Ok(result)
        })?,
    )?;

    nmap.set(
        "ethernet_send",
        lua.create_function(|lua, (_handle, packet): (Table, String)| {
            let result = lua.create_table()?;
            result.set("sent", packet.len())?;
            result.set("status", "ok")?;
            Ok(result)
        })?,
    )?;

    nmap.set(
        "ip_send",
        lua.create_function(|lua, (packet, dst): (String, String)| {
            let result = lua.create_table()?;
            result.set("sent", packet.len())?;
            result.set("dst", dst)?;
            result.set("status", "ok")?;
            Ok(result)
        })?,
    )?;

    nmap.set(
        "new_dnet",
        lua.create_function(|lua, _: ()| {
            let result = lua.create_table()?;
            result.set("type", "dnet")?;
            result.set("opened", false)?;
            Ok(result)
        })?,
    )?;

    nmap.set(
        "log_write",
        lua.create_function(|_lua, (_file, _string): (String, String)| Ok(true))?,
    )?;

    nmap.set(
        "fetchfile",
        lua.create_function(|_lua, filename: String| {
            let paths = [
                format!("/usr/local/share/nmap/{}", filename),
                format!("/usr/share/nmap/{}", filename),
                format!("/opt/nmap/share/nmap/{}", filename),
            ];
            for path in paths {
                if std::path::Path::new(&path).exists() {
                    return Ok(path);
                }
            }
            Ok(String::new())
        })?,
    )?;

    nmap.set(
        "address_family",
        lua.create_function(|_lua, _: ()| Ok("inet".to_string()))?,
    )?;

    nmap.set("debugging", lua.create_function(|_lua, _: ()| Ok(0))?)?;

    nmap.set("verbosity", lua.create_function(|_lua, _: ()| Ok(0))?)?;

    nmap.set(
        "async_socket_connect",
        lua.create_async_function(
            |lua, (socket_table, host, port): (Table, String, u16)| async move {
                let result = lua.create_table()?;

                if let Ok(closed) = socket_table.get::<bool>("closed") {
                    if closed {
                        result.set("status", "error")?;
                        result.set("error", "socket is closed")?;
                        return Ok(result);
                    }
                }

                let timeout = socket_table.get::<i64>("timeout").unwrap_or(10);
                let addr = format!("{}:{}", host, port);

                match tokio::time::timeout(
                    std::time::Duration::from_secs(timeout as u64),
                    tokio::net::TcpStream::connect(&addr),
                )
                .await
                {
                    Ok(Ok(_stream)) => {
                        socket_table.set("connected", true)?;
                        socket_table.set("remote_host", host.clone())?;
                        socket_table.set("remote_port", port)?;

                        result.set("status", "connected")?;
                        result.set("host", host)?;
                        result.set("port", port)?;
                    }
                    Ok(Err(e)) => {
                        result.set("status", "error")?;
                        result.set("error", e.to_string())?;
                    }
                    Err(_) => {
                        result.set("status", "error")?;
                        result.set("error", "connection timeout")?;
                    }
                }

                Ok(result)
            },
        )?,
    )?;

    nmap.set(
        "async_socket_send",
        lua.create_async_function(|lua, (socket_table, data): (Table, String)| async move {
            let result = lua.create_table()?;

            if let Ok(closed) = socket_table.get::<bool>("closed") {
                if closed {
                    result.set("status", "error")?;
                    result.set("error", "socket is closed")?;
                    return Ok(result);
                }
            }

            if let Ok(connected) = socket_table.get::<bool>("connected") {
                if !connected {
                    result.set("status", "error")?;
                    result.set("error", "not connected")?;
                    return Ok(result);
                }
            }

            let host: String = socket_table.get("remote_host").unwrap_or_default();
            let port: u16 = socket_table.get("remote_port").unwrap_or(0);
            let timeout = socket_table.get::<i64>("timeout").unwrap_or(10);

            if host.is_empty() || port == 0 {
                result.set("status", "error")?;
                result.set("error", "not connected")?;
                return Ok(result);
            }

            let addr = format!("{}:{}", host, port);
            match tokio::time::timeout(
                std::time::Duration::from_secs(timeout as u64),
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            {
                Ok(Ok(mut stream)) => {
                    use tokio::io::AsyncWriteExt;
                    match stream.write_all(data.as_bytes()).await {
                        Ok(()) => {
                            result.set("status", "sent")?;
                            result.set("bytes", data.len())?;
                        }
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
                        }
                    }
                }
                Ok(Err(e)) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                }
                Err(_) => {
                    result.set("status", "error")?;
                    result.set("error", "connection timeout")?;
                }
            }

            Ok(result)
        })?,
    )?;

    nmap.set(
        "async_socket_receive",
        lua.create_async_function(
            |lua, (socket_table, size): (Table, Option<usize>)| async move {
                let result = lua.create_table()?;
                let size = size.unwrap_or(1024);

                if let Ok(closed) = socket_table.get::<bool>("closed") {
                    if closed {
                        result.set("status", "error")?;
                        result.set("error", "socket is closed")?;
                        return Ok(result);
                    }
                }

                if let Ok(connected) = socket_table.get::<bool>("connected") {
                    if !connected {
                        result.set("status", "error")?;
                        result.set("error", "not connected")?;
                        return Ok(result);
                    }
                }

                let host: String = socket_table.get("remote_host").unwrap_or_default();
                let port: u16 = socket_table.get("remote_port").unwrap_or(0);
                let timeout = socket_table.get::<i64>("timeout").unwrap_or(10);

                if host.is_empty() || port == 0 {
                    result.set("status", "error")?;
                    result.set("error", "not connected")?;
                    return Ok(result);
                }

                let addr = format!("{}:{}", host, port);
                match tokio::time::timeout(
                    std::time::Duration::from_secs(timeout as u64),
                    tokio::net::TcpStream::connect(&addr),
                )
                .await
                {
                    Ok(Ok(mut stream)) => {
                        use tokio::io::AsyncReadExt;
                        let mut buffer = vec![0u8; size];
                        match stream.read(&mut buffer).await {
                            Ok(n) => {
                                let data = String::from_utf8_lossy(&buffer[..n]).to_string();
                                result.set("status", "ok")?;
                                result.set("data", data)?;
                                result.set("length", n)?;
                            }
                            Err(e) => {
                                result.set("status", "error")?;
                                result.set("error", e.to_string())?;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        result.set("status", "error")?;
                        result.set("error", e.to_string())?;
                    }
                    Err(_) => {
                        result.set("status", "error")?;
                        result.set("error", "connection timeout")?;
                    }
                }

                Ok(result)
            },
        )?,
    )?;

    nmap.set(
        "clock",
        lua.create_function(|_lua, ()| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as f64;
            Ok(now)
        })?,
    )?;

    nmap.set(
        "clock_ms",
        lua.create_function(|_lua, ()| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as f64;
            Ok(now)
        })?,
    )?;

    nmap.set(
        "current_time",
        lua.create_function(|_lua, ()| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as f64;
            Ok(now)
        })?,
    )?;

    nmap.set(
        "list_interfaces",
        lua.create_function({
            let cap = capability_ctx.clone();
            move |_lua, ()| {
                let interfaces = _lua.create_table()?;

                #[cfg(unix)]
                {
                    use crate::wrappers;
                    let decision = wrappers::check_process_exec(&cap, "ip", "nmap.list_interfaces");
                    if decision.is_denied() {
                        // Return empty/fallback list when process exec is denied
                        let iface = _lua.create_table()?;
                        iface.set("device", "lo")?;
                        let addrs = _lua.create_table()?;
                        addrs.set(1, "127.0.0.1")?;
                        iface.set("addresses", addrs)?;
                        interfaces.set(1, iface)?;
                        return Ok(interfaces);
                    }
                    use std::process::Command;
                    if let Ok(output) = Command::new("ip").arg("addr").output() {
                        let output_str = String::from_utf8_lossy(&output.stdout);
                        let mut idx = 1;
                        for line in output_str.lines() {
                            if line.starts_with(|c: char| c.is_ascii_digit())
                                || line.starts_with("inet ")
                            {
                                let iface = _lua.create_table()?;
                                let name = line.split(':').next().unwrap_or("unknown").trim();
                                iface.set("device", name)?;
                                iface.set("addresses", _lua.create_table()?)?;
                                interfaces.set(idx, iface)?;
                                idx += 1;
                            }
                        }
                    }
                }

                #[cfg(windows)]
                {
                    use std::process::Command;
                    if let Ok(output) = Command::new("ipconfig").output() {
                        let output_str = String::from_utf8_lossy(&output.stdout);
                        let mut current_iface = _lua.create_table()?;
                        let mut idx = 1;
                        for line in output_str.lines() {
                            let trimmed = line.trim();
                            if trimmed.ends_with(':') && !trimmed.contains("adapter") {
                                if !current_iface.len().unwrap_or(0) == 0 {
                                    interfaces.set(idx, current_iface)?;
                                    idx += 1;
                                    current_iface = _lua.create_table()?;
                                }
                                let name = trimmed.trim_end_matches(':').trim();
                                current_iface.set("device", name)?;
                                current_iface.set("addresses", _lua.create_table()?)?;
                            }
                        }
                        if !current_iface.len().unwrap_or(0) == 0 {
                            interfaces.set(idx, current_iface)?;
                        }
                    }
                }

                if interfaces.len().unwrap_or(0) == 0 {
                    let iface = _lua.create_table()?;
                    iface.set("device", "lo")?;
                    let addrs = _lua.create_table()?;
                    addrs.set(1, "127.0.0.1")?;
                    iface.set("addresses", addrs)?;
                    interfaces.set(1, iface)?;
                }

                Ok(interfaces)
            }
        })?,
    )?;

    nmap.set(
        "get_interface",
        lua.create_function({
            let cap = capability_ctx.clone();
            move |_lua, (name,): (Option<String>,)| {
                let iface = _lua.create_table()?;

                if let Some(iface_name) = name {
                    if !iface_name
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                    {
                        return Err(mlua::Error::RuntimeError(
                            "Invalid interface name".to_string(),
                        ));
                    }
                    iface.set("device", iface_name.clone())?;

                    #[cfg(unix)]
                    {
                        use crate::wrappers;
                        let decision =
                            wrappers::check_process_exec(&cap, "ip", "nmap.get_interface");
                        if decision.is_denied() {
                            iface.set("addresses", _lua.create_table()?)?;
                            return Ok(iface);
                        }
                        use std::process::Command;
                        let output = Command::new("ip")
                            .arg("addr")
                            .arg("show")
                            .arg(&iface_name)
                            .output();

                        if let Ok(out) = output {
                            let output_str = String::from_utf8_lossy(&out.stdout);
                            let addrs = _lua.create_table()?;
                            let mut idx = 1;
                            for line in output_str.lines() {
                                if line.trim().starts_with("inet ") {
                                    let parts: Vec<&str> = line.split_whitespace().collect();
                                    if parts.len() >= 2 {
                                        addrs.set(idx, parts[1].to_string())?;
                                        idx += 1;
                                    }
                                }
                            }
                            iface.set("addresses", addrs)?;
                        }
                    }
                } else {
                    iface.set("device", "")?;
                    iface.set("addresses", _lua.create_table()?)?;
                }

                Ok(iface)
            }
        })?,
    )?;

    nmap.set(
        "get_target",
        lua.create_function(|lua, ()| {
            let globals = lua.globals();
            let nmap_tbl: Table = globals
                .get("nmap")
                .unwrap_or_else(|_| fallback_lua_table(lua));
            let target = nmap_tbl.get::<String>("target").unwrap_or_default();
            Ok(target)
        })?,
    )?;

    nmap.set(
        "version",
        lua.create_function(|_lua, ()| Ok(env!("CARGO_PKG_VERSION").to_string()))?,
    )?;

    nmap.set(
        "version_intensity",
        lua.create_function(|_lua, ()| Ok(7i32))?,
    )?;

    nmap.set(
        "version_table",
        lua.create_function(|_lua, ()| {
            let table = _lua.create_table()?;
            table.set("version", env!("CARGO_PKG_VERSION"))?;
            table.set("name", "eggsec")?;
            Ok(table)
        })?,
    )?;

    nmap.set("save_state", lua.create_function(|_lua, ()| Ok(0i32))?)?;

    nmap.set(
        "restore_state",
        lua.create_function(|_lua, state: i32| Ok(state))?,
    )?;

    nmap.set(
        "ref_increment",
        lua.create_function(|_lua, ()| {
            let globals = _lua.globals();
            let nmap_tbl: Table = globals
                .get("nmap")
                .unwrap_or_else(|_| fallback_lua_table(_lua));
            let refcount: i32 = nmap_tbl.get("refcount").unwrap_or(0);
            nmap_tbl.set("refcount", refcount + 1)?;
            Ok(refcount + 1)
        })?,
    )?;

    nmap.set(
        "ref_decrement",
        lua.create_function(|_lua, ()| {
            let globals = _lua.globals();
            let nmap_tbl: Table = globals
                .get("nmap")
                .unwrap_or_else(|_| fallback_lua_table(_lua));
            let refcount: i32 = nmap_tbl.get("refcount").unwrap_or(0);
            let new_count = (refcount - 1).max(0);
            nmap_tbl.set("refcount", new_count)?;
            Ok(new_count)
        })?,
    )?;

    globals.set("nmap", nmap)?;
    Ok(())
}
