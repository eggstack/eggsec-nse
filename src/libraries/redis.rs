//! NSE redis library wrapper
//!
//! Redis protocol support for NSE scripts.
//! Based on Nmap's redis library: https://nmap.org/nsedoc/lib/redis.html
//! Includes both blocking and async implementations with Redis AUTH support.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tokio::net::TcpStream as AsyncTcpStream;

use crate::capabilities::NseCapabilityContext;
use crate::wrappers;

fn maybe_denied_redis(
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

fn redis_command(addr: &str, cmd: &str) -> std::io::Result<String> {
    let socket_addr = addr
        .parse::<std::net::SocketAddr>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
    let mut stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    stream.write_all(cmd.as_bytes())?;
    stream.flush()?;

    let mut response = vec![0u8; 16384];
    let n = stream.read(&mut response)?;

    if n == 0 {
        return Ok(String::new());
    }

    Ok(String::from_utf8_lossy(&response[..n]).to_string())
}

fn redis_auth(addr: &str, password: &str) -> std::io::Result<bool> {
    let cmd = format!(
        "*2\r\n$4\r\nAUTH\r\n${}\r\n{}\r\n",
        password.len(),
        password
    );
    let response = redis_command(addr, &cmd)?;

    if response.starts_with("+OK") {
        Ok(true)
    } else if response.starts_with("-ERR") {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            response.trim(),
        ))
    } else {
        Ok(false)
    }
}

pub fn register_redis_library(lua: &Lua, capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    let globals = lua.globals();
    let redis = lua.create_table()?;

    let cap = capability_ctx.clone();
    let connect_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_redis(lua, &cap, &host, "redis.connect")? {
            return Ok(denied);
        }
        let addr = format!("{}:{}", host, port);
        match TcpStream::connect_timeout(
            &addr
                .parse::<std::net::SocketAddr>()
                .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
            Duration::from_secs(10),
        ) {
            Ok(_) => {
                let result = lua.create_table()?;
                result.set("host", host)?;
                result.set("port", port)?;
                result.set("status", "connected")?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("status", "error")?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    redis.set("connect", connect_fn)?;

    let cap = capability_ctx.clone();
    let async_connect_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_redis(lua, &cap, &host, "redis.connect_async")? {
            return Err(mlua::Error::RuntimeError(
                denied.get::<String>("error").unwrap_or_default(),
            ));
        }
        let addr = format!("{}:{}", host, port);

        tokio::runtime::Handle::current().block_on(async {
            match AsyncTcpStream::connect(&addr).await {
                Ok(_) => {
                    let r = lua.create_table()?;
                    r.set("host", host)?;
                    r.set("port", port)?;
                    r.set("status", "connected")?;
                    Ok(r)
                }
                Err(e) => {
                    let r = lua.create_table()?;
                    r.set("status", "error")?;
                    r.set("error", e.to_string())?;
                    Ok(r)
                }
            }
        })
    })?;
    redis.set("connect_async", async_connect_fn)?;

    let cap = capability_ctx.clone();
    let auth_fn =
        lua.create_function(move |lua, (host, port, password): (String, u16, String)| {
            if let Some(denied) = maybe_denied_redis(lua, &cap, &host, "redis.auth")? {
                return Ok(denied);
            }
            let addr = format!("{}:{}", host, port);
            match redis_auth(&addr, &password) {
                Ok(success) => {
                    let result = lua.create_table()?;
                    result.set("success", success)?;
                    result.set("status", "authenticated")?;
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
    redis.set("auth", auth_fn)?;

    let cap = capability_ctx.clone();
    let async_auth_fn =
        lua.create_function(move |lua, (host, port, password): (String, u16, String)| {
            if let Some(denied) = maybe_denied_redis(lua, &cap, &host, "redis.auth_async")? {
                return Err(mlua::Error::RuntimeError(
                    denied.get::<String>("error").unwrap_or_default(),
                ));
            }
            let addr = format!("{}:{}", host, port);

            tokio::runtime::Handle::current().block_on(async {
                let cmd = format!(
                    "*2\r\n$4\r\nAUTH\r\n${}\r\n{}\r\n",
                    password.len(),
                    password
                );

                let result = tokio::task::spawn_blocking(move || redis_command(&addr, &cmd)).await;

                match result {
                    Ok(Ok(response)) => {
                        let r = lua.create_table()?;
                        if response.starts_with("+OK") {
                            r.set("success", true)?;
                            r.set("status", "authenticated")?;
                        } else {
                            r.set("success", false)?;
                            r.set("error", response.trim())?;
                        }
                        Ok(r)
                    }
                    Ok(Err(e)) => {
                        let r = lua.create_table()?;
                        r.set("success", false)?;
                        r.set("error", e.to_string())?;
                        Ok(r)
                    }
                    Err(e) => {
                        let r = lua.create_table()?;
                        r.set("success", false)?;
                        r.set("error", e.to_string())?;
                        Ok(r)
                    }
                }
            })
        })?;
    redis.set("auth_async", async_auth_fn)?;

    let cap = capability_ctx.clone();
    let ping_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_redis(lua, &cap, &host, "redis.ping")? {
            return Ok(denied);
        }
        let addr = format!("{}:{}", host, port);
        match redis_command(&addr, "*1\r\n$4\r\nPING\r\n") {
            Ok(response) => {
                let result = lua.create_table()?;
                if response.starts_with("+PONG") {
                    result.set("status", "pong")?;
                    result.set("success", true)?;
                } else {
                    result.set("status", response.trim())?;
                    result.set("success", false)?;
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
    })?;
    redis.set("ping", ping_fn)?;

    let cap = capability_ctx.clone();
    let async_ping_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_redis(lua, &cap, &host, "redis.ping_async")? {
            return Err(mlua::Error::RuntimeError(
                denied.get::<String>("error").unwrap_or_default(),
            ));
        }
        let addr = format!("{}:{}", host, port);

        tokio::runtime::Handle::current().block_on(async {
            let cmd = "*1\r\n$4\r\nPING\r\n";

            let result = tokio::task::spawn_blocking(move || redis_command(&addr, cmd)).await;

            match result {
                Ok(Ok(response)) => {
                    let r = lua.create_table()?;
                    if response.starts_with("+PONG") {
                        r.set("status", "pong")?;
                        r.set("success", true)?;
                    } else {
                        r.set("status", response.trim())?;
                        r.set("success", false)?;
                    }
                    Ok(r)
                }
                Ok(Err(e)) => {
                    let r = lua.create_table()?;
                    r.set("success", false)?;
                    r.set("error", e.to_string())?;
                    Ok(r)
                }
                Err(e) => {
                    let r = lua.create_table()?;
                    r.set("success", false)?;
                    r.set("error", e.to_string())?;
                    Ok(r)
                }
            }
        })
    })?;
    redis.set("ping_async", async_ping_fn)?;

    let cap = capability_ctx.clone();
    let get_fn = lua.create_function(move |lua, (host, port, key): (String, u16, String)| {
        if let Some(denied) = maybe_denied_redis(lua, &cap, &host, "redis.get")? {
            return Ok(denied);
        }
        let addr = format!("{}:{}", host, port);
        let cmd = format!("*2\r\n$3\r\nGET\r\n${}\r\n{}\r\n", key.len(), key);

        match redis_command(&addr, &cmd) {
            Ok(response) => {
                let result = lua.create_table()?;
                if response.starts_with("+") {
                    result.set("value", response.trim_start_matches('+'))?;
                } else if response.starts_with("$") {
                    let lines: Vec<&str> = response.lines().collect();
                    if lines.len() > 2 {
                        result.set("value", lines[2])?;
                    } else {
                        result.set("value", "")?;
                    }
                } else if response.starts_with("-") {
                    result.set("error", response.trim_start_matches('-'))?;
                } else {
                    result.set("value", response.trim())?;
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
    redis.set("get", get_fn)?;

    let cap = capability_ctx.clone();
    let async_get_fn =
        lua.create_function(move |lua, (host, port, key): (String, u16, String)| {
            if let Some(denied) = maybe_denied_redis(lua, &cap, &host, "redis.get_async")? {
                return Err(mlua::Error::RuntimeError(
                    denied.get::<String>("error").unwrap_or_default(),
                ));
            }
            let addr = format!("{}:{}", host, port);

            tokio::runtime::Handle::current().block_on(async {
                let cmd = format!("*2\r\n$3\r\nGET\r\n${}\r\n{}\r\n", key.len(), key);

                let result = tokio::task::spawn_blocking(move || redis_command(&addr, &cmd)).await;

                match result {
                    Ok(Ok(response)) => {
                        let r = lua.create_table()?;
                        if response.starts_with("+") {
                            r.set("value", response.trim_start_matches('+'))?;
                        } else if response.starts_with("$") {
                            let lines: Vec<&str> = response.lines().collect();
                            if lines.len() > 2 {
                                r.set("value", lines[2])?;
                            } else {
                                r.set("value", "")?;
                            }
                        } else if response.starts_with("-") {
                            r.set("error", response.trim_start_matches('-'))?;
                        } else {
                            r.set("value", response.trim())?;
                        }
                        Ok(r)
                    }
                    Ok(Err(e)) => {
                        let r = lua.create_table()?;
                        r.set("error", e.to_string())?;
                        Ok(r)
                    }
                    Err(e) => {
                        let r = lua.create_table()?;
                        r.set("error", e.to_string())?;
                        Ok(r)
                    }
                }
            })
        })?;
    redis.set("get_async", async_get_fn)?;

    let cap = capability_ctx.clone();
    let set_fn = lua.create_function(
        move |lua, (host, port, key, value): (String, u16, String, String)| {
            if let Some(denied) = maybe_denied_redis(lua, &cap, &host, "redis.set")? {
                return Ok(denied);
            }
            let addr = format!("{}:{}", host, port);
            let cmd = format!(
                "*3\r\n$3\r\nSET\r\n${}\r\n{}\r\n${}\r\n{}\r\n",
                key.len(),
                key,
                value.len(),
                value
            );

            match redis_command(&addr, &cmd) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    if response.starts_with("+OK") {
                        result.set("success", true)?;
                    } else {
                        result.set("success", false)?;
                        result.set("error", response.trim())?;
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
    redis.set("set", set_fn)?;

    let cap = capability_ctx.clone();
    let async_set_fn = lua.create_function(
        move |lua, (host, port, key, value): (String, u16, String, String)| {
            if let Some(denied) = maybe_denied_redis(lua, &cap, &host, "redis.set_async")? {
                return Err(mlua::Error::RuntimeError(
                    denied.get::<String>("error").unwrap_or_default(),
                ));
            }
            let addr = format!("{}:{}", host, port);

            tokio::runtime::Handle::current().block_on(async {
                let cmd = format!(
                    "*3\r\n$3\r\nSET\r\n${}\r\n{}\r\n${}\r\n{}\r\n",
                    key.len(),
                    key,
                    value.len(),
                    value
                );

                let result = tokio::task::spawn_blocking(move || redis_command(&addr, &cmd)).await;

                match result {
                    Ok(Ok(response)) => {
                        let r = lua.create_table()?;
                        if response.starts_with("+OK") {
                            r.set("success", true)?;
                        } else {
                            r.set("success", false)?;
                            r.set("error", response.trim())?;
                        }
                        Ok(r)
                    }
                    Ok(Err(e)) => {
                        let r = lua.create_table()?;
                        r.set("success", false)?;
                        r.set("error", e.to_string())?;
                        Ok(r)
                    }
                    Err(e) => {
                        let r = lua.create_table()?;
                        r.set("success", false)?;
                        r.set("error", e.to_string())?;
                        Ok(r)
                    }
                }
            })
        },
    )?;
    redis.set("set_async", async_set_fn)?;

    let cap = capability_ctx.clone();
    let info_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_redis(lua, &cap, &host, "redis.info")? {
            return Ok(denied);
        }
        let addr = format!("{}:{}", host, port);

        match redis_command(&addr, "*1\r\n$4\r\nINFO\r\n") {
            Ok(response) => {
                let result = lua.create_table()?;
                if response.starts_with("$") {
                    let lines: Vec<&str> = response.lines().collect();
                    if lines.len() > 2 {
                        result.set("info", lines[2..].join("\n"))?;
                    } else {
                        result.set("info", response.trim())?;
                    }
                } else {
                    result.set("info", response.trim())?;
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
    redis.set("info", info_fn)?;

    let cap = capability_ctx.clone();
    let async_info_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_redis(lua, &cap, &host, "redis.info_async")? {
            return Err(mlua::Error::RuntimeError(
                denied.get::<String>("error").unwrap_or_default(),
            ));
        }
        let addr = format!("{}:{}", host, port);

        tokio::runtime::Handle::current().block_on(async {
            let cmd = "*1\r\n$4\r\nINFO\r\n";

            let result = tokio::task::spawn_blocking(move || redis_command(&addr, cmd)).await;

            match result {
                Ok(Ok(response)) => {
                    let r = lua.create_table()?;
                    if response.starts_with("$") {
                        let lines: Vec<&str> = response.lines().collect();
                        if lines.len() > 2 {
                            r.set("info", lines[2..].join("\n"))?;
                        } else {
                            r.set("info", response.trim())?;
                        }
                    } else {
                        r.set("info", response.trim())?;
                    }
                    Ok(r)
                }
                Ok(Err(e)) => {
                    let r = lua.create_table()?;
                    r.set("error", e.to_string())?;
                    Ok(r)
                }
                Err(e) => {
                    let r = lua.create_table()?;
                    r.set("error", e.to_string())?;
                    Ok(r)
                }
            }
        })
    })?;
    redis.set("info_async", async_info_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    redis.set("version", version_fn)?;

    globals.set("redis", redis)?;
    Ok(())
}
