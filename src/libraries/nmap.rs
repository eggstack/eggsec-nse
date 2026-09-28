//! NSE nmap library wrapper
//!
//! Provides access to Nmap internals like host info, ports, and socket operations.

use mlua::{Lua, Result as LuaResult, Table};
use rustc_hash::FxHashMap;
use std::sync::LazyLock;
use std::sync::RwLock;
use std::time::Duration;

use super::helpers::{fallback_lua_table, or_fallback_table};
use crate::capabilities::NseCapabilityContext;
use crate::providers::{
    broker_tcp_connect, broker_tcp_receive, broker_tcp_send, NativeTcpConnection, NseHostServices,
    NseIpAddress, NseResolvedEndpoint, NseTcpConnection, NseTransportProtocol,
};

/// M005B: the registry stores opaque provider handles plus the approved
/// endpoint identity. Native socket types appear only in the
/// `add_connection`/`get_connection` compatibility-shim signatures below
/// (no direct connects or resolution in this module).
struct ConnectionEntry {
    handle: Box<dyn NseTcpConnection>,
    // Approved endpoint identity + insertion metadata: audit trail for 005E
    // qualification (written on insert, not read on the hot path).
    #[allow(dead_code)]
    endpoint: NseResolvedEndpoint,
    #[allow(dead_code)]
    created_at: u64,
}

static CONNECTION_REGISTRY: LazyLock<RwLock<FxHashMap<String, ConnectionEntry>>> =
    LazyLock::new(|| RwLock::new(FxHashMap::default()));

fn get_connection_key(host: &str, port: u16) -> String {
    format!("{}:{}", host, port)
}

/// Internal registry metadata timestamp (not a Lua-visible clock read).
fn registry_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn is_handle_alive(handle: &dyn NseTcpConnection) -> bool {
    handle.is_alive()
}

fn insert_connection(key: &str, handle: Box<dyn NseTcpConnection>, endpoint: NseResolvedEndpoint) {
    if let Ok(mut reg) = CONNECTION_REGISTRY.write() {
        reg.insert(
            key.to_string(),
            ConnectionEntry {
                handle,
                endpoint,
                created_at: registry_timestamp(),
            },
        );
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

/// Compatibility shim: wrap a caller-supplied native stream as an opaque
/// handle. The endpoint identity is recovered from the peer address with
/// the registry label as the hostname. No new connection is made here.
pub fn add_connection(host: &str, port: u16, stream: std::net::TcpStream) -> Result<(), String> {
    let key = get_connection_key(host, port);
    let peer = stream
        .peer_addr()
        .map_err(|e| format!("add_connection: peer address unavailable: {e}"))?;
    let ip = NseIpAddress::parse(&peer.ip().to_string())
        .ok_or_else(|| "add_connection: unparseable peer address".to_string())?;
    let endpoint = NseResolvedEndpoint::new(host, ip, peer.port(), NseTransportProtocol::Tcp);
    insert_connection(
        &key,
        Box::new(NativeTcpConnection::from_std(stream, endpoint.clone())),
        endpoint,
    );
    Ok(())
}

pub fn get_connection(host: &str, port: u16) -> Option<std::net::TcpStream> {
    let key = get_connection_key(host, port);
    if let Ok(reg) = CONNECTION_REGISTRY.read() {
        if let Some(entry) = reg.get(&key) {
            if is_handle_alive(entry.handle.as_ref()) {
                // Opaque handles cannot be cloned out of the registry;
                // liveness is probed but ownership stays inside (parity
                // with the pre-provider behavior, which also returned None
                // here). Callers use `socket_send`/`socket_receive`.
                return None;
            }
        }
    }
    None
}

fn reconnect_stream(
    host: &str,
    port: u16,
    timeout_secs: i64,
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> Option<(Box<dyn NseTcpConnection>, NseResolvedEndpoint)> {
    let timeout = Duration::from_secs(timeout_secs.max(0) as u64);
    match broker_tcp_connect(ctx, services, host, port, timeout, "nmap.reconnect") {
        Ok(pair) => Some(pair),
        Err(e) => {
            tracing::warn!("nmap reconnect to {}:{} failed: {}", host, port, e);
            None
        }
    }
}

pub fn register_nmap_library(lua: &Lua, capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    register_nmap_library_with_services(
        lua,
        capability_ctx,
        &crate::providers::NseHostServices::native(),
    )
}

/// Provider-backed nmap registration.
///
/// Lua-visible time/random helpers (`current_time`, `get_random_bytes`,
/// `get_random`, `clock`, `clock_ms`) go through the broker. Socket
/// operations (`socket_connect`, `socket_send`, `socket_receive`, and the
/// async variants) go through the authority-preserving network broker and
/// store opaque handles in the connection registry. Internal registry
/// metadata timestamps remain native (not Lua-visible) and are inventoried
/// as residuals.
pub fn register_nmap_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &crate::providers::NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    // Clone for use in closures (NseCapabilityContext is Clone)
    let capability_ctx = capability_ctx.clone();
    let provider_services = services.clone();

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
            let registry: Table = match nmap_tbl.get("registry") {
                Ok(t) => t,
                Err(_) => {
                    let t = fallback_lua_table(lua)?;
                    if let Err(e) = nmap_tbl.set("registry", t.clone()) {
                        tracing::warn!("nmap: failed to set initial registry: {}", e);
                    }
                    t
                }
            };
            Ok(registry)
        })?,
    )?;
    nmap.set("_ports", lua.create_table()?)?;
    nmap.set("_hostinfo", lua.create_table()?)?;

    nmap.set(
        "get_hostname",
        lua.create_function(|lua, host: Option<String>| {
            let globals = lua.globals();
            let nmap_tbl: Table = or_fallback_table(globals.get("nmap"), lua)?;
            let hostinfo: Table = or_fallback_table(nmap_tbl.get("_hostinfo"), lua)?;

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
            let nmap_tbl: Table = or_fallback_table(globals.get("nmap"), lua)?;
            let hostinfo: Table = or_fallback_table(nmap_tbl.get("_hostinfo"), lua)?;
            hostinfo.get::<String>("ip").or_else(|_| Ok("".to_string()))
        })?,
    )?;

    nmap.set(
        "get_port_state",
        lua.create_function(|lua, (host, port): (Option<String>, u16)| {
            let globals = lua.globals();
            let nmap_tbl: Table = or_fallback_table(globals.get("nmap"), lua)?;
            let ports: Table = or_fallback_table(nmap_tbl.get("_ports"), lua)?;

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
            let nmap_tbl: Table = or_fallback_table(globals.get("nmap"), lua)?;
            let ports: Table = or_fallback_table(nmap_tbl.get("_ports"), lua)?;

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
            let nmap_tbl: Table = or_fallback_table(globals.get("nmap"), lua)?;
            let ports: Table = or_fallback_table(nmap_tbl.get("_ports"), lua)?;

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

    let cap_for_connect = capability_ctx.clone();
    let svc_for_connect = provider_services.clone();
    nmap.set(
        "socket_connect",
        lua.create_function(
            move |lua, (socket_table, host, port): (Table, String, u16)| {
                let result = lua.create_table()?;

                if let Ok(closed) = socket_table.get::<bool>("closed") {
                    if closed {
                        result.set("status", "error")?;
                        result.set("error", "socket is closed")?;
                        return Ok(result);
                    }
                }

                let timeout = socket_table.get::<i64>("timeout").unwrap_or(10);
                let timeout_d = Duration::from_secs(timeout.max(0) as u64);

                // Authority-preserving brokered connect: resolves, selects
                // the approved concrete endpoint, and connects exactly it.
                // Hostnames now resolve (previously only literal SocketAddr
                // strings were accepted); Lua shapes are unchanged.
                match broker_tcp_connect(
                    &cap_for_connect,
                    &svc_for_connect,
                    &host,
                    port,
                    timeout_d,
                    "nmap.socket_connect",
                ) {
                    Ok((handle, endpoint)) => {
                        let conn_key = get_connection_key(&host, port);
                        insert_connection(&conn_key, handle, endpoint);

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
                        socket_table.set("connected_at", registry_timestamp())?;
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

    let cap_for_send = capability_ctx.clone();
    let svc_for_send = provider_services.clone();
    nmap.set(
        "socket_send",
        lua.create_function(move |lua, (socket_table, data): (Table, String)| {
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
                    if !is_handle_alive(entry.handle.as_ref()) {
                        should_reconnect = true;
                    }
                } else {
                    should_reconnect = true;
                }
            }

            // Reconnect if needed
            if should_reconnect {
                match reconnect_stream(&host, port, timeout, &cap_for_send, &svc_for_send) {
                    Some((new_handle, new_endpoint)) => {
                        insert_connection(&conn_key, new_handle, new_endpoint);
                    }
                    _ => {
                        result.set("status", "error")?;
                        result.set("error", "failed to reconnect")?;
                        return Ok(result);
                    }
                }
            }

            // Try to send data through the broker (policy re-evaluated
            // against the concrete endpoint, bytes accounted).
            if let Ok(mut reg) = CONNECTION_REGISTRY.write() {
                if let Some(entry) = reg.get_mut(&conn_key) {
                    match broker_tcp_send(
                        &cap_for_send,
                        entry.handle.as_mut(),
                        data.as_bytes(),
                        "nmap.socket_send",
                    ) {
                        Ok(n) => {
                            result.set("status", "sent")?;
                            result.set("bytes", n)?;
                        }
                        Err(e) => {
                            // Try one reconnect on write error
                            drop(reg); // Release lock before reconnecting
                            if let Some((new_handle, new_endpoint)) =
                                reconnect_stream(&host, port, timeout, &cap_for_send, &svc_for_send)
                            {
                                insert_connection(&conn_key, new_handle, new_endpoint);
                                if let Ok(mut reg) = CONNECTION_REGISTRY.write() {
                                    if let Some(entry) = reg.get_mut(&conn_key) {
                                        match broker_tcp_send(
                                            &cap_for_send,
                                            entry.handle.as_mut(),
                                            data.as_bytes(),
                                            "nmap.socket_send",
                                        ) {
                                            Ok(n) => {
                                                result.set("status", "sent")?;
                                                result.set("bytes", n)?;
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

    let cap_for_recv = capability_ctx.clone();
    let svc_for_recv = provider_services.clone();
    nmap.set(
        "socket_receive",
        lua.create_function(move |lua, (socket_table, size): (Table, Option<usize>)| {
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
                    if !is_handle_alive(entry.handle.as_ref()) {
                        should_reconnect = true;
                    }
                } else {
                    should_reconnect = true;
                }
            }

            // Attempt reconnect if needed
            if should_reconnect {
                match reconnect_stream(&host, port, timeout, &cap_for_recv, &svc_for_recv) {
                    Some((new_handle, new_endpoint)) => {
                        insert_connection(&conn_key, new_handle, new_endpoint);
                    }
                    _ => {
                        result.set("status", "error")?;
                        result.set("error", "failed to reconnect")?;
                        return Ok(result);
                    }
                }
            }

            // Try to receive data through the broker (policy + accounting
            // on the concrete endpoint).
            if let Ok(mut reg) = CONNECTION_REGISTRY.write() {
                if let Some(entry) = reg.get_mut(&conn_key) {
                    match broker_tcp_receive(
                        &cap_for_recv,
                        entry.handle.as_mut(),
                        size,
                        "nmap.socket_receive",
                    ) {
                        Ok(data) => {
                            let text = String::from_utf8_lossy(&data).to_string();
                            let n = data.len();
                            result.set("status", "ok")?;
                            result.set("data", text)?;
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
            let nmap_tbl: Table = or_fallback_table(globals.get("nmap"), lua)?;
            let registry: Table = or_fallback_table(nmap_tbl.get("registry"), lua)?;
            registry.get(key.as_str()).or_else(|_| Ok(mlua::Value::Nil))
        })?,
    )?;

    nmap.set(
        "registry_set",
        lua.create_function(|lua, (key, value): (String, mlua::Value)| {
            let globals = lua.globals();
            let nmap_tbl: Table = or_fallback_table(globals.get("nmap"), lua)?;
            let registry: Table = match nmap_tbl.get("registry") {
                Ok(t) => t,
                Err(_) => {
                    let t = fallback_lua_table(lua)?;
                    if let Err(e) = nmap_tbl.set("registry", t.clone()) {
                        tracing::warn!("nmap registry_set: failed to set initial registry: {}", e);
                    }
                    t
                }
            };
            registry.set(key.as_str(), value)?;
            Ok(true)
        })?,
    )?;

    nmap.set(
        "ref_increment",
        lua.create_function(|lua, _: ()| {
            let globals = lua.globals();
            let nmap_tbl: Table = or_fallback_table(globals.get("nmap"), lua)?;
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
            let nmap_tbl: Table = or_fallback_table(globals.get("nmap"), lua)?;
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
            let svc = provider_services.clone();
            move |_lua, _: ()| {
                // Privilege probe via the process provider (platform
                // semantics localized in the native provider; denied
                // profiles fail closed to false, as before).
                Ok(
                    crate::providers::broker_is_privileged(&cap, &svc, "id", "nmap.is_admin")
                        .unwrap_or(false),
                )
            }
        })?,
    )?;

    {
        let cap_ctx = capability_ctx.clone();
        let svc = provider_services.clone();
        nmap.set(
            "current_time",
            lua.create_function(move |_lua, _: ()| {
                let ts =
                    crate::providers::broker_unix_timestamp(&cap_ctx, &svc, "nmap.current_time")
                        .unwrap_or_else(|_| chrono::Utc::now().timestamp());
                Ok(ts)
            })?,
        )?;
    }

    {
        let cap_ctx = capability_ctx.clone();
        let svc = provider_services.clone();
        nmap.set(
            "get_random_bytes",
            lua.create_function(move |_lua, count: i32| {
                let mut bytes = vec![0u8; count.max(0) as usize];
                crate::providers::broker_random_fill(
                    &cap_ctx,
                    &svc,
                    &mut bytes,
                    "nmap.get_random_bytes",
                )
                .map_err(|e| mlua::Error::RuntimeError(format!("Randomness denied: {e}")))?;
                Ok(bytes)
            })?,
        )?;
    }

    {
        let cap_ctx = capability_ctx.clone();
        let svc = provider_services.clone();
        nmap.set(
            "get_random",
            lua.create_function(move |_lua, (min, max): (i32, i32)| {
                if min >= max {
                    return Ok(min);
                }
                let r = crate::providers::broker_random_u32(&cap_ctx, &svc, "nmap.get_random")
                    .map_err(|e| mlua::Error::RuntimeError(format!("Randomness denied: {e}")))?;
                Ok((r as i32) % (max - min + 1) + min)
            })?,
        )?;
    };

    nmap.set(
        "version",
        lua.create_function(|_lua, _: ()| Ok(env!("CARGO_PKG_VERSION")))?,
    )?;

    nmap.set(
        "status",
        lua.create_function(|lua, (_host, state): (Option<String>, String)| {
            let globals = lua.globals();
            let nmap_tbl: Table = or_fallback_table(globals.get("nmap"), lua)?;
            let hostinfo: Table = or_fallback_table(nmap_tbl.get("_hostinfo"), lua)?;
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
            let output: Table = or_fallback_table(globals.get("_SCRIPT_OUTPUT"), lua)?;
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
                let waiting: Table = or_fallback_table(c.get("waiting"), lua)?;
                let len = waiting.len().unwrap_or(0);
                waiting.set(len + 1, true)?;
                if let Err(e) = c.set("waiting", waiting) {
                    tracing::warn!("nmap condvar wait: failed to set waiting: {}", e);
                }
                Ok(true)
            })?;
            condvar.set("wait", wait_fn)?;

            let signal_fn = lua.create_function(|lua, c: Table| {
                let waiting: Table = or_fallback_table(c.get("waiting"), lua)?;
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
            let svc = provider_services.clone();
            move |_lua, _: ()| {
                Ok(
                    crate::providers::broker_is_privileged(&cap, &svc, "id", "nmap.is_privileged")
                        .unwrap_or(false),
                )
            }
        })?,
    )?;

    {
        let cap_ctx = capability_ctx.clone();
        let svc = provider_services.clone();
        nmap.set(
            "clock_ms",
            lua.create_function(move |_lua, _: ()| {
                let ts = crate::providers::broker_unix_timestamp(&cap_ctx, &svc, "nmap.clock_ms")
                    .unwrap_or_else(|_| chrono::Utc::now().timestamp());
                Ok((ts as f64) * 1000.0)
            })?,
        )?;
    }

    {
        let cap_ctx = capability_ctx.clone();
        let svc = provider_services.clone();
        nmap.set(
            "clock",
            lua.create_function(move |_lua, _: ()| {
                let ts = crate::providers::broker_unix_timestamp(&cap_ctx, &svc, "nmap.clock")
                    .unwrap_or_else(|_| chrono::Utc::now().timestamp());
                Ok(ts as f64)
            })?,
        )?;
    }

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

    let cap_for_async_connect = capability_ctx.clone();
    let svc_for_async_connect = provider_services.clone();
    nmap.set(
        "async_socket_connect",
        lua.create_async_function(
            move |lua, (socket_table, host, port): (Table, String, u16)| {
                let cap = cap_for_async_connect.clone();
                let svc = svc_for_async_connect.clone();
                async move {
                    let result = lua.create_table()?;

                    if let Ok(closed) = socket_table.get::<bool>("closed") {
                        if closed {
                            result.set("status", "error")?;
                            result.set("error", "socket is closed")?;
                            return Ok(result);
                        }
                    }

                    let timeout = socket_table.get::<i64>("timeout").unwrap_or(10);
                    let timeout_d = Duration::from_secs(timeout.max(0) as u64);

                    // Brokered sync provider flow inside the async closure:
                    // bounded by the connect timeout, no detached tasks.
                    match broker_tcp_connect(
                        &cap,
                        &svc,
                        &host,
                        port,
                        timeout_d,
                        "nmap.async_socket_connect",
                    ) {
                        Ok((_handle, _endpoint)) => {
                            socket_table.set("connected", true)?;
                            socket_table.set("remote_host", host.clone())?;
                            socket_table.set("remote_port", port)?;

                            result.set("status", "connected")?;
                            result.set("host", host)?;
                            result.set("port", port)?;
                        }
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
                        }
                    }

                    Ok(result)
                }
            },
        )?,
    )?;

    let cap_for_async_send = capability_ctx.clone();
    let svc_for_async_send = provider_services.clone();
    nmap.set(
        "async_socket_send",
        lua.create_async_function(move |lua, (socket_table, data): (Table, String)| {
            let cap = cap_for_async_send.clone();
            let svc = svc_for_async_send.clone();
            async move {
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

                let timeout_d = Duration::from_secs(timeout.max(0) as u64);

                // Brokered connect + send (parity with the legacy
                // per-send fresh connection), then drop the handle.
                match broker_tcp_connect(
                    &cap,
                    &svc,
                    &host,
                    port,
                    timeout_d,
                    "nmap.async_socket_send",
                ) {
                    Ok((mut handle, _endpoint)) => {
                        match broker_tcp_send(
                            &cap,
                            handle.as_mut(),
                            data.as_bytes(),
                            "nmap.async_socket_send",
                        ) {
                            Ok(n) => {
                                result.set("status", "sent")?;
                                result.set("bytes", n)?;
                            }
                            Err(e) => {
                                result.set("status", "error")?;
                                result.set("error", e.to_string())?;
                            }
                        }
                    }
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e.to_string())?;
                    }
                }

                Ok(result)
            }
        })?,
    )?;

    let cap_for_async_recv = capability_ctx.clone();
    let svc_for_async_recv = provider_services.clone();
    nmap.set(
        "async_socket_receive",
        lua.create_async_function(move |lua, (socket_table, size): (Table, Option<usize>)| {
            let cap = cap_for_async_recv.clone();
            let svc = svc_for_async_recv.clone();
            async move {
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

                let timeout_d = Duration::from_secs(timeout.max(0) as u64);

                // Brokered connect + receive (parity with the legacy
                // per-receive fresh connection), then drop the handle.
                match broker_tcp_connect(
                    &cap,
                    &svc,
                    &host,
                    port,
                    timeout_d,
                    "nmap.async_socket_receive",
                ) {
                    Ok((mut handle, _endpoint)) => {
                        match broker_tcp_receive(
                            &cap,
                            handle.as_mut(),
                            size,
                            "nmap.async_socket_receive",
                        ) {
                            Ok(data) => {
                                let text = String::from_utf8_lossy(&data).to_string();
                                let n = data.len();
                                result.set("status", "ok")?;
                                result.set("data", text)?;
                                result.set("length", n)?;
                            }
                            Err(e) => {
                                result.set("status", "error")?;
                                result.set("error", e.to_string())?;
                            }
                        }
                    }
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e.to_string())?;
                    }
                }

                Ok(result)
            }
        })?,
    )?;

    {
        let cap_ctx = capability_ctx.clone();
        let svc = provider_services.clone();
        nmap.set(
            "clock",
            lua.create_function(move |_lua, ()| {
                let ts = crate::providers::broker_unix_timestamp(&cap_ctx, &svc, "nmap.clock")
                    .unwrap_or_else(|_| chrono::Utc::now().timestamp());
                Ok(ts as f64)
            })?,
        )?;
    }

    {
        let cap_ctx = capability_ctx.clone();
        let svc = provider_services.clone();
        nmap.set(
            "clock_ms",
            lua.create_function(move |_lua, ()| {
                let ts = crate::providers::broker_unix_timestamp(&cap_ctx, &svc, "nmap.clock_ms")
                    .unwrap_or_else(|_| chrono::Utc::now().timestamp());
                Ok((ts as f64) * 1000.0)
            })?,
        )?;
    }

    {
        let cap_ctx = capability_ctx.clone();
        let svc = provider_services.clone();
        nmap.set(
            "current_time",
            lua.create_function(move |_lua, ()| {
                let ts =
                    crate::providers::broker_unix_timestamp(&cap_ctx, &svc, "nmap.current_time")
                        .unwrap_or_else(|_| chrono::Utc::now().timestamp());
                Ok(ts as f64)
            })?,
        )?;
    }

    nmap.set(
        "list_interfaces",
        lua.create_function({
            let cap = capability_ctx.clone();
            let svc = provider_services.clone();
            move |_lua, ()| {
                let interfaces = _lua.create_table()?;

                // Interface enumeration via the process provider (platform
                // parsing localized in the native provider). Denied
                // profiles receive the loopback fallback, as before.
                // Shape note: one entry per interface with filled
                // addresses (the legacy parser emitted one entry per
                // matching output line, including bare address lines).
                let records = match crate::providers::broker_network_interfaces(
                    &cap,
                    &svc,
                    "ip",
                    "nmap.list_interfaces",
                ) {
                    Ok(records) => records,
                    Err(_) => {
                        let iface = _lua.create_table()?;
                        iface.set("device", "lo")?;
                        let addrs = _lua.create_table()?;
                        addrs.set(1, "127.0.0.1")?;
                        iface.set("addresses", addrs)?;
                        interfaces.set(1, iface)?;
                        return Ok(interfaces);
                    }
                };

                for (idx, record) in records.iter().enumerate() {
                    let iface = _lua.create_table()?;
                    iface.set("device", record.name.clone())?;
                    let addrs = _lua.create_table()?;
                    for (j, addr) in record.addresses.iter().enumerate() {
                        addrs.set(j + 1, addr.to_string())?;
                    }
                    iface.set("addresses", addrs)?;
                    interfaces.set(idx + 1, iface)?;
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
            let svc = provider_services.clone();
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

                    match crate::providers::broker_network_interfaces(
                        &cap,
                        &svc,
                        "ip",
                        "nmap.get_interface",
                    ) {
                        Ok(records) => {
                            let addrs = _lua.create_table()?;
                            if let Some(record) = records.iter().find(|r| r.name == iface_name) {
                                for (idx, addr) in record.addresses.iter().enumerate() {
                                    addrs.set(idx + 1, addr.to_string())?;
                                }
                            }
                            iface.set("addresses", addrs)?;
                        }
                        Err(_) => {
                            iface.set("addresses", _lua.create_table()?)?;
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
            let nmap_tbl: Table = or_fallback_table(globals.get("nmap"), lua)?;
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
            let nmap_tbl: Table = or_fallback_table(globals.get("nmap"), _lua)?;
            let refcount: i32 = nmap_tbl.get("refcount").unwrap_or(0);
            nmap_tbl.set("refcount", refcount + 1)?;
            Ok(refcount + 1)
        })?,
    )?;

    nmap.set(
        "ref_decrement",
        lua.create_function(|_lua, ()| {
            let globals = _lua.globals();
            let nmap_tbl: Table = or_fallback_table(globals.get("nmap"), _lua)?;
            let refcount: i32 = nmap_tbl.get("refcount").unwrap_or(0);
            let new_count = (refcount - 1).max(0);
            nmap_tbl.set("refcount", new_count)?;
            Ok(new_count)
        })?,
    )?;

    globals.set("nmap", nmap)?;
    Ok(())
}
