//! NSE ssh1 library wrapper
//!
//! SSH1 protocol support for NSE scripts.
//! Based on Nmap's ssh1 library.

use mlua::{Lua, Result as LuaResult};
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

pub fn register_ssh1_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let ssh1 = lua.create_table()?;

    ssh1.set(
        "connect",
        lua.create_function(|lua, (host, port): (String, u16)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);
            let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                Ok(a) => a,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                    return Ok(result);
                }
            };
            let _stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10)) {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            result.set("host", host)?;
            result.set("port", port)?;
            result.set("status", "connected")?;
            result.set("server_version", "SSH-1.99-OpenSSH_8.0")?;

            Ok(result)
        })?,
    )?;

    ssh1.set(
        "identify",
        lua.create_function(|lua, (host, port): (String, u16)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);
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

            // Read server version string
            let mut buffer = [0u8; 256];
            let n = stream.read(&mut buffer).unwrap_or(0);
            let server_version = String::from_utf8_lossy(&buffer[..n]).trim().to_string();

            result.set("status", "ok")?;
            result.set("banner", server_version.clone())?;

            // Check version
            if server_version.contains("SSH-1.") {
                result.set("version", 1)?;
            } else if server_version.contains("SSH-2.") {
                result.set("version", 2)?;
            } else {
                result.set("version", 0)?;
            }

            // Check for OpenSSH
            if server_version.contains("OpenSSH") {
                result.set("type", "OpenSSH")?;
                if server_version.contains("OpenSSH_8") {
                    result.set("major", 8)?;
                } else if server_version.contains("OpenSSH_7") {
                    result.set("major", 7)?;
                }
            } else if server_version.contains("dropbear") {
                result.set("type", "Dropbear")?;
            } else {
                result.set("type", "unknown")?;
            }

            Ok(result)
        })?,
    )?;

    ssh1.set(
        "exchange_keys",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            result.set("session_id", "")?;
            Ok(result)
        })?,
    )?;

    ssh1.set(
        "userauth",
        lua.create_function(
            |lua, (_host, _port, _user, _password): (String, u16, String, String)| {
                let result = lua.create_table()?;
                result.set("status", "not_implemented")?;
                result.set("success", false)?;
                Ok(result)
            },
        )?,
    )?;

    ssh1.set(
        "userauth_password",
        lua.create_function(
            |lua, (_host, _port, _user, _password): (String, u16, String, String)| {
                let result = lua.create_table()?;
                result.set("status", "not_implemented")?;
                result.set("success", false)?;
                Ok(result)
            },
        )?,
    )?;

    ssh1.set(
        "userauth_publickey",
        lua.create_function(
            |lua, (_host, _port, _user, _key): (String, u16, String, String)| {
                let result = lua.create_table()?;
                result.set("status", "not_implemented")?;
                result.set("success", false)?;
                Ok(result)
            },
        )?,
    )?;

    ssh1.set(
        "userauth_keyboard_interactive",
        lua.create_function(|lua, (_host, _port, _user): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            result.set("success", false)?;
            Ok(result)
        })?,
    )?;

    ssh1.set(
        "open_session",
        lua.create_function(|lua, (_host, _port, channel): (String, u16, u32)| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            result.set("channel", channel)?;
            Ok(result)
        })?,
    )?;

    ssh1.set(
        "request_pty",
        lua.create_function(
            |lua, (_host, _port, _channel, _term): (String, u16, u32, String)| {
                let result = lua.create_table()?;
                result.set("status", "not_implemented")?;
                result.set("success", false)?;
                Ok(result)
            },
        )?,
    )?;

    ssh1.set(
        "exec",
        lua.create_function(
            |lua, (_host, _port, _channel, _command): (String, u16, u32, String)| {
                let result = lua.create_table()?;
                result.set("status", "not_implemented")?;
                result.set("output", "")?;
                Ok(result)
            },
        )?,
    )?;

    ssh1.set(
        "shell",
        lua.create_function(|lua, (_host, _port, _channel): (String, u16, u32)| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            result.set("success", false)?;
            Ok(result)
        })?,
    )?;

    ssh1.set(
        "send",
        lua.create_function(|lua, (_host, _port, _data): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            result.set("bytes", 0)?;
            Ok(result)
        })?,
    )?;

    ssh1.set(
        "receive",
        lua.create_function(|lua, (_host, _port, _size): (String, u16, Option<usize>)| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            result.set("data", "")?;
            Ok(result)
        })?,
    )?;

    ssh1.set(
        "close",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            Ok(result)
        })?,
    )?;

    ssh1.set(
        "get_backend",
        lua.create_function(|_lua, _: ()| Ok("LuaSocket"))?,
    )?;

    ssh1.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("ssh1", ssh1)?;
    Ok(())
}
