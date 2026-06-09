//! NSE whois library wrapper
//!
//! WHOIS protocol support for NSE scripts.
//! Includes both blocking and async implementations.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as AsyncTcpStream;

pub fn register_whois_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let whois = lua.create_table()?;

    let whois_fn = lua.create_function(|lua, (host, query): (String, String)| {
        let addr = format!("{}:43", host);
        let mut stream = match TcpStream::connect_timeout(
            &addr
                .parse::<std::net::SocketAddr>()
                .map_err(|e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()))?,
            Duration::from_secs(10),
        ) {
            Ok(s) => s,
            Err(_) => {
                let result = lua.create_table()?;
                result.set("error", "Connection failed")?;
                return Ok(result);
            }
        };

        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

        stream.write_all(format!("{}\r\n", query).as_bytes()).ok();

        let mut response = vec![0u8; 16384];
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
    whois.set("whois", whois_fn)?;

    let parse_whois_fn = lua.create_function(|lua, response: String| {
        let result = lua.create_table()?;

        let fields = lua.create_table()?;

        for line in response.lines() {
            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                if !key.is_empty() && !value.is_empty() {
                    fields.set(key, value)?;
                }
            }
        }

        result.set("fields", fields)?;

        Ok(result)
    })?;
    whois.set("parse_whois", parse_whois_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    whois.set("version", version_fn)?;

    // Async whois lookup
    let async_whois_fn = lua.create_function(|lua, (host, query): (String, String)| {
        let addr = format!("{}:43", host);

        tokio::runtime::Handle::current().block_on(async {
            match AsyncTcpStream::connect(&addr).await {
                Ok(mut stream) => {
                    let query_with_newline = format!("{}\r\n", query);
                    stream.write_all(query_with_newline.as_bytes()).await.ok();

                    let mut buffer = vec![0u8; 8192];
                    let n = stream.read(&mut buffer).await.unwrap_or(0);

                    let response = String::from_utf8_lossy(&buffer[..n]).to_string();

                    let result = lua.create_table()?;
                    result.set("response", response)?;
                    result.set("host", host)?;
                    Ok(result)
                }
                Err(e) => {
                    let r = lua.create_table()?;
                    r.set("error", e.to_string())?;
                    Ok(r)
                }
            }
        })
    })?;
    whois.set("whois_async", async_whois_fn)?;

    globals.set("whois", whois)?;
    Ok(())
}
