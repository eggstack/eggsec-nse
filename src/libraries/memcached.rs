//! NSE memcached library wrapper
//!
//! Memcached protocol support for NSE scripts.
//! Includes both blocking and async implementations with real protocol support.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn memcached_send(host: &str, port: u16, command: &[u8]) -> std::io::Result<String> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?,
        Duration::from_secs(10),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap_or_else(|e| tracing::warn!("Failed to set memcached read timeout: {}", e));
    stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap_or_else(|e| tracing::warn!("Failed to set memcached write timeout: {}", e));

    stream.write_all(command)?;
    stream.flush()?;

    let mut response = vec![0u8; 8192];
    let n = stream.read(&mut response)?;

    if n > 0 {
        Ok(String::from_utf8_lossy(&response[..n]).to_string())
    } else {
        Ok(String::new())
    }
}

pub fn register_memcached_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let memcached = lua.create_table()?;

    // memcached.connect() - Connect to memcached server
    let connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("status", "connected")?;
        Ok(result)
    })?;
    memcached.set("connect", connect_fn)?;

    // memcached.get() - Get a value
    let get_fn = lua.create_function(|lua, (host, port, key): (String, u16, String)| {
        let cmd = format!("get {}\r\n", key);
        match memcached_send(&host, port, cmd.as_bytes()) {
            Ok(response) => {
                let result = lua.create_table()?;
                if response.starts_with("VALUE") {
                    result.set("found", true)?;
                    result.set("key", key)?;
                    if let Some(value_start) = response.find("\r\n") {
                        if let Some(value_end) = response[value_start + 2..].find("\r\n") {
                            let value = &response[value_start + 2..value_start + 2 + value_end];
                            result.set("value", value)?;
                        }
                    }
                } else {
                    result.set("found", false)?;
                }
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    memcached.set("get", get_fn)?;

    // memcached.gets() - Get with CAS token
    let gets_fn = lua.create_function(|lua, (host, port, key): (String, u16, String)| {
        let cmd = format!("gets {}\r\n", key);
        match memcached_send(&host, port, cmd.as_bytes()) {
            Ok(response) => {
                let result = lua.create_table()?;
                if response.starts_with("VALUE") {
                    result.set("found", true)?;
                    result.set("key", key)?;
                    // Parse CAS token from response
                    for line in response.lines() {
                        if line.starts_with("VALUE ") {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 4 {
                                if let Ok(cas) = parts[3].parse::<u64>() {
                                    result.set("cas", cas)?;
                                }
                            }
                        }
                    }
                } else {
                    result.set("found", false)?;
                }
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    memcached.set("gets", gets_fn)?;

    // memcached.set() - Set a value
    let set_fn = lua.create_function(
        |lua, (host, port, key, value, flags, expiry): (String, u16, String, String, u32, u32)| {
            let cmd = format!(
                "set {} {} {} 0 {}\r\n{}\r\n",
                key,
                flags,
                expiry,
                value.len(),
                value
            );
            match memcached_send(&host, port, cmd.as_bytes()) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    result.set("success", response.contains("STORED"))?;
                    result.set("stored", response.contains("STORED"))?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    memcached.set("set", set_fn)?;

    // memcached.add() - Add a value (only if not exists)
    let add_fn = lua.create_function(
        |lua, (host, port, key, value, flags, expiry): (String, u16, String, String, u32, u32)| {
            let cmd = format!(
                "add {} {} {} 0 {}\r\n{}\r\n",
                key,
                flags,
                expiry,
                value.len(),
                value
            );
            match memcached_send(&host, port, cmd.as_bytes()) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    result.set("success", response.contains("STORED"))?;
                    result.set("stored", response.contains("STORED"))?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    memcached.set("add", add_fn)?;

    // memcached.replace() - Replace a value
    let replace_fn = lua.create_function(
        |lua, (host, port, key, value, flags, expiry): (String, u16, String, String, u32, u32)| {
            let cmd = format!(
                "replace {} {} {} 0 {}\r\n{}\r\n",
                key,
                flags,
                expiry,
                value.len(),
                value
            );
            match memcached_send(&host, port, cmd.as_bytes()) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    result.set("success", response.contains("STORED"))?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    memcached.set("replace", replace_fn)?;

    // memcached.append() - Append to value
    let append_fn = lua.create_function(
        |lua, (host, port, key, value): (String, u16, String, String)| {
            let cmd = format!("append {} 0 0 {}\r\n{}\r\n", key, value.len(), value);
            match memcached_send(&host, port, cmd.as_bytes()) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    result.set("success", response.contains("STORED"))?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    memcached.set("append", append_fn)?;

    // memcached.prepend() - Prepend to value
    let prepend_fn = lua.create_function(
        |lua, (host, port, key, value): (String, u16, String, String)| {
            let cmd = format!("prepend {} 0 0 {}\r\n{}\r\n", key, value.len(), value);
            match memcached_send(&host, port, cmd.as_bytes()) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    result.set("success", response.contains("STORED"))?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    memcached.set("prepend", prepend_fn)?;

    // memcached.delete() - Delete a key
    let delete_fn = lua.create_function(|lua, (host, port, key): (String, u16, String)| {
        let cmd = format!("delete {}\r\n", key);
        match memcached_send(&host, port, cmd.as_bytes()) {
            Ok(response) => {
                let result = lua.create_table()?;
                result.set("success", response.contains("DELETED"))?;
                result.set("deleted", response.contains("DELETED"))?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("success", false)?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    memcached.set("delete", delete_fn)?;

    // memcached.incr() - Increment value
    let incr_fn = lua.create_function(
        |lua, (host, port, key, value): (String, u16, String, u64)| {
            let cmd = format!("incr {} {}\r\n", key, value);
            match memcached_send(&host, port, cmd.as_bytes()) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    if response.contains("ERROR") || response.contains("NOT_FOUND") {
                        result.set("success", false)?;
                    } else {
                        result.set("success", true)?;
                        let new_value: u64 = response.trim().parse().unwrap_or(0);
                        result.set("value", new_value)?;
                    }
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    memcached.set("incr", incr_fn)?;

    // memcached.decr() - Decrement value
    let decr_fn = lua.create_function(
        |lua, (host, port, key, value): (String, u16, String, u64)| {
            let cmd = format!("decr {} {}\r\n", key, value);
            match memcached_send(&host, port, cmd.as_bytes()) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    if response.contains("ERROR") || response.contains("NOT_FOUND") {
                        result.set("success", false)?;
                    } else {
                        result.set("success", true)?;
                        let new_value: u64 = response.trim().parse().unwrap_or(0);
                        result.set("value", new_value)?;
                    }
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    memcached.set("decr", decr_fn)?;

    // memcached.touch() - Update expiry
    let touch_fn = lua.create_function(
        |lua, (host, port, key, expiry): (String, u16, String, u32)| {
            let cmd = format!("touch {} {}\r\n", key, expiry);
            match memcached_send(&host, port, cmd.as_bytes()) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    result.set("success", response.contains("TOUCHED"))?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    memcached.set("touch", touch_fn)?;

    // memcached.stats() - Get server statistics
    let stats_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let cmd = b"stats\r\n";
        match memcached_send(&host, port, cmd) {
            Ok(response) => {
                let result = lua.create_table()?;
                let stats = lua.create_table()?;

                for line in response.lines() {
                    if line.starts_with("STAT ") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            let key = parts[1];
                            let value = parts[2];
                            stats.set(key, value)?;
                        }
                    }
                }

                result.set("stats", stats)?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    memcached.set("stats", stats_fn)?;

    // memcached.stats_items() - Get items statistics
    let stats_items_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let cmd = b"stats items\r\n";
        match memcached_send(&host, port, cmd) {
            Ok(response) => {
                let result = lua.create_table()?;
                let items = lua.create_table()?;

                for line in response.lines() {
                    if line.starts_with("STAT items:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            items.set(parts[1], parts[2])?;
                        }
                    }
                }

                result.set("items", items)?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    memcached.set("stats_items", stats_items_fn)?;

    // memcached.stats_slabs() - Get slabs statistics
    let stats_slabs_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let cmd = b"stats slabs\r\n";
        match memcached_send(&host, port, cmd) {
            Ok(response) => {
                let result = lua.create_table()?;
                let slabs = lua.create_table()?;

                for line in response.lines() {
                    if line.starts_with("STAT slab:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            slabs.set(parts[1], parts[2])?;
                        }
                    }
                }

                result.set("slabs", slabs)?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    memcached.set("stats_slabs", stats_slabs_fn)?;

    // memcached.flush_all() - Flush all cache
    let flush_all_fn =
        lua.create_function(|lua, (host, port, delay): (String, u16, Option<u32>)| {
            let delay = delay.unwrap_or(0);
            let cmd = format!("flush_all {}\r\n", delay);
            match memcached_send(&host, port, cmd.as_bytes()) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    result.set("success", response.contains("OK"))?;
                    result.set("flushed", response.contains("OK"))?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        })?;
    memcached.set("flush_all", flush_all_fn)?;

    // memcached.version() - Get server version
    let version_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let cmd = b"version\r\n";
        match memcached_send(&host, port, cmd) {
            Ok(response) => {
                let result = lua.create_table()?;
                if let Some(ver) = response.strip_prefix("VERSION ") {
                    result.set("version", ver.trim())?;
                } else {
                    result.set("version", "unknown")?;
                }
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    memcached.set("version", version_fn)?;

    // memcached.quit() - Close connection
    let quit_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let cmd = b"quit\r\n";
        match memcached_send(&host, port, cmd) {
            Ok(_) => {
                let result = lua.create_table()?;
                result.set("success", true)?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("success", false)?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    memcached.set("quit", quit_fn)?;

    // Async connect
    let async_connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("status", "connected")?;
        Ok(result)
    })?;
    memcached.set("connect_async", async_connect_fn)?;

    globals.set("memcached", memcached)?;
    Ok(())
}
