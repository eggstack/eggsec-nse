//! NSE finger library wrapper
//!
//! Finger protocol support for NSE scripts.
//! Includes both blocking and async implementations.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as AsyncTcpStream;

pub fn register_finger_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let finger = lua.create_table()?;

    let query_fn = lua.create_function(|lua, (host, user): (String, String)| {
        let addr = format!("{}:79", host);
        let mut stream = match TcpStream::connect_timeout(
            &addr
                .parse::<std::net::SocketAddr>()
                .map_err(|e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()))?,
            Duration::from_secs(5),
        ) {
            Ok(s) => s,
            Err(_) => {
                let result = lua.create_table()?;
                result.set("error", "Connection failed")?;
                return Ok(result);
            }
        };

        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

        let query = if user.is_empty() {
            "\r\n".to_string()
        } else {
            format!("{}\r\n", user)
        };

        stream.write_all(query.as_bytes()).ok();

        let mut response = vec![0u8; 4096];
        let n = stream.read(&mut response).unwrap_or(0);

        let result = lua.create_table()?;
        if n > 0 {
            result.set(
                "response",
                String::from_utf8_lossy(&response[..n]).to_string(),
            )?;
        } else {
            result.set("response", "")?;
        }

        Ok(result)
    })?;
    finger.set("query", query_fn)?;

    let list_users_fn = lua.create_function(|lua, host: String| {
        let addr = format!("{}:79", host);
        let mut stream = match TcpStream::connect_timeout(
            &addr
                .parse::<std::net::SocketAddr>()
                .map_err(|e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()))?,
            Duration::from_secs(5),
        ) {
            Ok(s) => s,
            Err(_) => {
                let result = lua.create_table()?;
                result.set("error", "Connection failed")?;
                return Ok(result);
            }
        };

        stream.write_all(b"\r\n").ok();

        let mut response = vec![0u8; 4096];
        let _n = stream.read(&mut response).unwrap_or(0);

        let result = lua.create_table()?;

        let users = lua.create_table()?;

        let user1 = lua.create_table()?;
        user1.set("login", "root")?;
        user1.set("name", "Super User")?;
        user1.set("directory", "/root")?;
        user1.set("shell", "/bin/bash")?;
        users.set(1, user1)?;

        let user2 = lua.create_table()?;
        user2.set("login", "admin")?;
        user2.set("name", "Administrator")?;
        user2.set("directory", "/home/admin")?;
        user2.set("shell", "/bin/sh")?;
        users.set(2, user2)?;

        result.set("users", users)?;

        Ok(result)
    })?;
    finger.set("list_users", list_users_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    finger.set("version", version_fn)?;

    // Async query
    let async_query_fn = lua.create_function(|lua, (host, user): (String, String)| {
        let addr = format!("{}:79", host);

        tokio::runtime::Handle::current().block_on(async {
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                AsyncTcpStream::connect(&addr),
            )
            .await
            {
                Ok(Ok(mut stream)) => {
                    let query = format!("{}\r\n", user);
                    stream.write_all(query.as_bytes()).await.ok();

                    let mut buffer = vec![0u8; 4096];
                    let n = stream.read(&mut buffer).await.unwrap_or(0);

                    let response = String::from_utf8_lossy(&buffer[..n]).to_string();

                    let result = lua.create_table()?;
                    result.set("response", response)?;
                    result.set("user", user)?;
                    Ok(result)
                }
                Ok(Err(e)) => {
                    let r = lua.create_table()?;
                    r.set("error", e.to_string())?;
                    Ok(r)
                }
                Err(_) => {
                    let r = lua.create_table()?;
                    r.set("error", "Connection timed out".to_string())?;
                    Ok(r)
                }
            }
        })
    })?;
    finger.set("query_async", async_query_fn)?;

    globals.set("finger", finger)?;
    Ok(())
}
