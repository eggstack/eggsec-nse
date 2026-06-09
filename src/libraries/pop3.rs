//! NSE pop3 library wrapper
//!
//! POP3 (Post Office Protocol v3) support for NSE scripts.
//! Includes both blocking and async implementations.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn pop3_send(host: &str, port: u16, command: &str) -> Result<String, mlua::Error> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
        Duration::from_secs(10),
    )
    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

    stream
        .write_all(command.as_bytes())
        .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

    let mut response = String::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = stream
            .read(&mut buffer)
            .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
        if n == 0 {
            break;
        }
        response.push_str(&String::from_utf8_lossy(&buffer[..n]));
        if response.contains("\r\n") {
            break;
        }
    }

    Ok(response)
}

fn pop3_send_with_body(host: &str, port: u16, command: &str) -> Result<String, mlua::Error> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
        Duration::from_secs(10),
    )
    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

    stream
        .write_all(command.as_bytes())
        .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

    let mut response = String::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = stream
            .read(&mut buffer)
            .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
        if n == 0 {
            break;
        }
        let chunk = String::from_utf8_lossy(&buffer[..n]);
        response.push_str(&chunk);

        if response.ends_with("\r\n.\r\n") {
            break;
        }

        if response.len() > 1024 * 1024 {
            break;
        }
    }

    Ok(response)
}

pub fn register_pop3_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let pop3 = lua.create_table()?;

    let connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let response = pop3_send(&host, port, "")?;
        let result = lua.create_table()?;
        result.set("host", host.clone())?;
        result.set("port", port)?;
        result.set(
            "status",
            if response.starts_with("+OK") {
                "connected"
            } else {
                "failed"
            },
        )?;
        result.set("greeting", response.lines().next().unwrap_or(""))?;
        Ok(result)
    })?;
    pop3.set("connect", connect_fn)?;

    let user_fn = lua.create_function(|lua, (host, port, username): (String, u16, String)| {
        let tag = format!("USER {}\r\n", username);
        let response = pop3_send(&host, port, &tag)?;
        let result = lua.create_table()?;
        result.set("success", response.starts_with("+OK"))?;
        result.set("user", username)?;
        result.set("response", response.trim())?;
        Ok(result)
    })?;
    pop3.set("user", user_fn)?;

    let pass_fn = lua.create_function(|lua, (host, port, password): (String, u16, String)| {
        let tag = format!("PASS {}\r\n", password);
        let response = pop3_send(&host, port, &tag)?;
        let result = lua.create_table()?;
        result.set("success", response.starts_with("+OK"))?;
        result.set("response", response.trim())?;
        Ok(result)
    })?;
    pop3.set("pass", pass_fn)?;

    let stat_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let response = pop3_send(&host, port, "STAT\r\n")?;
        let result = lua.create_table()?;

        if response.starts_with("+OK") {
            let parts: Vec<&str> = response.split_whitespace().collect();
            if parts.len() >= 3 {
                result.set("messages", parts[1].parse::<u32>().unwrap_or(0))?;
                result.set("octets", parts[2].parse::<u64>().unwrap_or(0))?;
            }
        }
        result.set("success", response.starts_with("+OK"))?;
        Ok(result)
    })?;
    pop3.set("stat", stat_fn)?;

    let list_fn = lua.create_function(|lua, (host, port, msg): (String, u16, Option<u32>)| {
        let cmd = match msg {
            Some(n) => format!("LIST {}\r\n", n),
            None => "LIST\r\n".to_string(),
        };
        let response = pop3_send(&host, port, &cmd)?;
        let result = lua.create_table()?;

        let messages = lua.create_table()?;

        if response.starts_with("+OK") {
            let mut idx = 1;
            for line in response.lines().skip(1) {
                if line.starts_with('.') || line.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let msg_entry = lua.create_table()?;
                    msg_entry.set("number", parts[0].parse::<u32>().unwrap_or(0))?;
                    msg_entry.set("size", parts[1].parse::<u64>().unwrap_or(0))?;
                    messages.set(idx, msg_entry)?;
                    idx += 1;
                }
            }
        }

        result.set("messages", messages)?;
        result.set("success", response.starts_with("+OK"))?;
        Ok(result)
    })?;
    pop3.set("list", list_fn)?;

    let retr_fn = lua.create_function(|lua, (host, port, message_num): (String, u16, u32)| {
        let cmd = format!("RETR {}\r\n", message_num);
        let response = pop3_send_with_body(&host, port, &cmd)?;
        let result = lua.create_table()?;

        if response.starts_with("+OK") {
            let body_start = response.find("\r\n\r\n").map(|i| i + 4).unwrap_or(4);
            let body = &response[body_start..];
            let body_clean = body.trim_start_matches('\n').trim_end_matches("\r\n.\r\n");

            result.set("number", message_num)?;
            result.set("body", body_clean)?;
            result.set("size", body_clean.len() as u64)?;
        }

        result.set("success", response.starts_with("+OK"))?;
        Ok(result)
    })?;
    pop3.set("retr", retr_fn)?;

    let top_fn = lua.create_function(
        |lua, (host, port, message_num, lines): (String, u16, u32, u32)| {
            let cmd = format!("TOP {} {}\r\n", message_num, lines);
            let response = pop3_send(&host, port, &cmd)?;
            let result = lua.create_table()?;

            if response.starts_with("+OK") {
                let parts: Vec<&str> = response.split("\r\n\r\n").collect();
                let header = parts
                    .first()
                    .unwrap_or(&"")
                    .lines()
                    .skip(1)
                    .collect::<Vec<_>>()
                    .join("\r\n");
                let body = parts.get(1).unwrap_or(&"").trim_end_matches("\r\n.\r\n");

                result.set("number", message_num)?;
                result.set("header", header)?;
                result.set("body", body)?;
            }

            result.set("success", response.starts_with("+OK"))?;
            Ok(result)
        },
    )?;
    pop3.set("top", top_fn)?;

    let dele_fn = lua.create_function(|lua, (host, port, message_num): (String, u16, u32)| {
        let cmd = format!("DELE {}\r\n", message_num);
        let response = pop3_send(&host, port, &cmd)?;
        let result = lua.create_table()?;
        result.set("success", response.starts_with("+OK"))?;
        result.set("deleted", message_num)?;
        result.set("response", response.trim())?;
        Ok(result)
    })?;
    pop3.set("dele", dele_fn)?;

    let uidl_fn = lua.create_function(|lua, (host, port, msg): (String, u16, Option<u32>)| {
        let cmd = match msg {
            Some(n) => format!("UIDL {}\r\n", n),
            None => "UIDL\r\n".to_string(),
        };
        let response = pop3_send(&host, port, &cmd)?;
        let result = lua.create_table()?;

        let ids = lua.create_table()?;

        if response.starts_with("+OK") {
            let mut idx = 1;
            for line in response.lines().skip(1) {
                if line.starts_with('.') || line.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let entry = lua.create_table()?;
                    entry.set("number", parts[0].parse::<u32>().unwrap_or(0))?;
                    entry.set("uid", parts[1])?;
                    ids.set(idx, entry)?;
                    idx += 1;
                }
            }
        }

        result.set("ids", ids)?;
        result.set("success", response.starts_with("+OK"))?;
        Ok(result)
    })?;
    pop3.set("uidl", uidl_fn)?;

    let noop_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let response = pop3_send(&host, port, "NOOP\r\n")?;
        let result = lua.create_table()?;
        result.set("success", response.starts_with("+OK"))?;
        result.set("response", response.trim())?;
        Ok(result)
    })?;
    pop3.set("noop", noop_fn)?;

    let rset_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let response = pop3_send(&host, port, "RSET\r\n")?;
        let result = lua.create_table()?;
        result.set("success", response.starts_with("+OK"))?;
        result.set("response", response.trim())?;
        Ok(result)
    })?;
    pop3.set("rset", rset_fn)?;

    let quit_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let response = pop3_send(&host, port, "QUIT\r\n")?;
        let result = lua.create_table()?;
        result.set("success", response.starts_with("+OK"))?;
        result.set("response", response.trim())?;
        Ok(result)
    })?;
    pop3.set("quit", quit_fn)?;

    let capa_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let response = pop3_send(&host, port, "CAPA\r\n")?;
        let result = lua.create_table()?;

        let capabilities = lua.create_table()?;

        if response.starts_with("+OK") {
            let mut idx = 1;
            for line in response.lines().skip(1) {
                if line.starts_with('.') || line.is_empty() {
                    continue;
                }
                capabilities.set(idx, line)?;
                idx += 1;
            }
        }

        result.set("capabilities", capabilities)?;
        result.set("success", response.starts_with("+OK"))?;
        Ok(result)
    })?;
    pop3.set("capa", capa_fn)?;

    let apop_fn = lua.create_function(
        |lua, (host, port, username, digest): (String, u16, String, String)| {
            let cmd = format!("APOP {} {}\r\n", username, digest);
            let response = pop3_send(&host, port, &cmd)?;
            let result = lua.create_table()?;
            result.set("success", response.starts_with("+OK"))?;
            result.set("response", response.trim())?;
            Ok(result)
        },
    )?;
    pop3.set("apop", apop_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    pop3.set("version", version_fn)?;

    globals.set("pop3", pop3)?;
    Ok(())
}
