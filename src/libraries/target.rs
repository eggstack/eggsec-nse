//! NSE target library wrapper
//!
//! Utility functions for adding new discovered targets to Nmap scan queue.

use mlua::{Lua, Result as LuaResult};
use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};

static TARGET_QUEUE: std::sync::LazyLock<Arc<Mutex<Vec<String>>>> =
    std::sync::LazyLock::new(|| Arc::new(Mutex::new(Vec::new())));

pub fn register_target_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let target = lua.create_table()?;

    target.set(
        "add",
        lua.create_function(|lua, host: String| {
            if let Ok(mut queue) = TARGET_QUEUE.lock() {
                if !queue.contains(&host) {
                    queue.push(host.clone());
                }
            }
            let result = lua.create_table()?;
            result.set("host", host)?;
            result.set("status", "added")?;
            Ok(result)
        })?,
    )?;

    target.set(
        "add_with_port",
        lua.create_function(|lua, (host, port): (String, u16)| {
            let host_port = format!("{}:{}", host, port);
            if let Ok(mut queue) = TARGET_QUEUE.lock() {
                if !queue.contains(&host_port) {
                    queue.push(host_port);
                }
            }
            let result = lua.create_table()?;
            result.set("host", host)?;
            result.set("port", port)?;
            result.set("status", "added")?;
            Ok(result)
        })?,
    )?;

    target.set(
        "exclude",
        lua.create_function(|_lua, host: String| {
            if let Ok(mut queue) = TARGET_QUEUE.lock() {
                queue.retain(|h| h != &host);
            }
            Ok(true)
        })?,
    )?;

    target.set(
        "get",
        lua.create_function(|lua, _: ()| {
            let result = lua.create_table()?;
            if let Ok(queue) = TARGET_QUEUE.lock() {
                for (i, host) in queue.iter().enumerate() {
                    result.set(i + 1, host.clone())?;
                }
            }
            Ok(result)
        })?,
    )?;

    target.set(
        "count",
        lua.create_function(|_lua, _: ()| match TARGET_QUEUE.lock() {
            Ok(queue) => Ok(queue.len() as i32),
            _ => Ok(0),
        })?,
    )?;

    target.set(
        "clear",
        lua.create_function(|_lua, _: ()| {
            if let Ok(mut queue) = TARGET_QUEUE.lock() {
                queue.clear();
            }
            Ok(true)
        })?,
    )?;

    target.set(
        "exists",
        lua.create_function(|_lua, host: String| match TARGET_QUEUE.lock() {
            Ok(queue) => Ok(queue.contains(&host)),
            _ => Ok(false),
        })?,
    )?;

    target.set(
        "resolve",
        lua.create_function(|_lua, hostname: String| {
            if hostname.parse::<std::net::IpAddr>().is_ok() {
                return Ok(hostname);
            }

            let host_port = format!("{}:0", hostname);
            if let Ok(mut iter) = host_port.to_socket_addrs() {
                if let Some(addr) = iter.next() {
                    return Ok(addr.ip().to_string());
                }
            }

            Ok(hostname)
        })?,
    )?;

    target.set(
        "reverse",
        lua.create_function(|_lua, ip: String| {
            if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
                let octets = addr.octets();
                return Ok(format!(
                    "{}.{}.{}.{}.in-addr.arpa",
                    octets[3], octets[2], octets[1], octets[0]
                ));
            }
            Ok(String::new())
        })?,
    )?;

    globals.set("target", target)?;
    Ok(())
}

pub fn get_target_queue() -> Vec<String> {
    TARGET_QUEUE.lock().map(|q| q.clone()).unwrap_or_default()
}

pub fn clear_target_queue() {
    if let Ok(mut queue) = TARGET_QUEUE.lock() {
        queue.clear();
    }
}
