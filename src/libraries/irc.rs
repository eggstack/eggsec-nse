//! NSE irc library wrapper
//!
//! IRC (Internet Relay Chat) protocol support.
//! Based on Nmap's irc library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_irc_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let irc = lua.create_table()?;

    // irc.connect() - Connect to IRC server
    irc.set(
        "connect",
        lua.create_function(|lua, (host, port, nick): (String, u16, String)| {
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

            stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

            // IRC NICK and USER
            stream
                .write_all(format!("NICK {}\r\n", nick).as_bytes())
                .ok();
            stream
                .write_all(format!("USER {} 0 * :Eggsec\r\n", nick).as_bytes())
                .ok();

            // Read welcome message
            let mut response = vec![0u8; 1024];
            let n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("connected", n > 0)?;
            result.set("nick", nick)?;

            Ok(result)
        })?,
    )?;

    // irc.join() - Join a channel
    irc.set(
        "join",
        lua.create_function(
            |lua, (host, port, nick, channel): (String, u16, String, String)| {
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
                let mut stream =
                    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10)) {
                        Ok(s) => s,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
                            return Ok(result);
                        }
                    };

                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

                // Send NICK and USER
                stream
                    .write_all(format!("NICK {}\r\n", nick).as_bytes())
                    .ok();
                stream
                    .write_all(format!("USER {} 0 * :Eggsec\r\n", nick).as_bytes())
                    .ok();

                // Wait a bit for registration
                std::thread::sleep(std::time::Duration::from_millis(500));

                // Join channel
                stream
                    .write_all(format!("JOIN {}\r\n", channel).as_bytes())
                    .ok();

                let mut response = vec![0u8; 1024];
                let n = stream.read(&mut response).unwrap_or(0);

                let response_str = String::from_utf8_lossy(&response[..n]).to_string();

                if response_str.contains("JOIN") || response_str.contains("353") {
                    result.set("success", true)?;
                    result.set("channel", channel)?;
                } else {
                    result.set("success", false)?;
                }

                Ok(result)
            },
        )?,
    )?;

    // irc.privmsg() - Send a private message
    irc.set(
        "privmsg",
        lua.create_function(
            |lua, (host, port, nick, target, message): (String, u16, String, String, String)| {
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
                let mut stream =
                    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10)) {
                        Ok(s) => s,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
                            return Ok(result);
                        }
                    };

                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

                // Send NICK and USER
                stream
                    .write_all(format!("NICK {}\r\n", nick).as_bytes())
                    .ok();
                stream
                    .write_all(format!("USER {} 0 * :Eggsec\r\n", nick).as_bytes())
                    .ok();

                // Wait a bit for registration
                std::thread::sleep(std::time::Duration::from_millis(500));

                // Send PRIVMSG
                stream
                    .write_all(format!("PRIVMSG {} :{}\r\n", target, message).as_bytes())
                    .ok();

                result.set("success", true)?;
                result.set("target", target)?;
                result.set("message", message)?;

                Ok(result)
            },
        )?,
    )?;

    // irc.part() - Leave a channel
    irc.set(
        "part",
        lua.create_function(
            |lua, (host, port, nick, channel): (String, u16, String, String)| {
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
                let mut stream =
                    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10)) {
                        Ok(s) => s,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
                            return Ok(result);
                        }
                    };

                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

                // Send NICK and USER
                stream
                    .write_all(format!("NICK {}\r\n", nick).as_bytes())
                    .ok();
                stream
                    .write_all(format!("USER {} 0 * :Eggsec\r\n", nick).as_bytes())
                    .ok();

                // Wait a bit for registration
                std::thread::sleep(std::time::Duration::from_millis(500));

                // Part channel
                stream
                    .write_all(format!("PART {}\r\n", channel).as_bytes())
                    .ok();

                result.set("success", true)?;
                result.set("channel", channel)?;

                Ok(result)
            },
        )?,
    )?;

    // irc.nick() - Change nickname
    irc.set(
        "nick",
        lua.create_function(|lua, (host, port, new_nick): (String, u16, String)| {
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

            stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

            // Send NICK
            stream
                .write_all(format!("NICK {}\r\n", new_nick).as_bytes())
                .ok();

            let mut response = vec![0u8; 512];
            let n = stream.read(&mut response).unwrap_or(0);

            let response_str = String::from_utf8_lossy(&response[..n]).to_string();

            if response_str.contains("NICK") || n > 0 {
                result.set("success", true)?;
                result.set("nick", new_nick)?;
            } else {
                result.set("success", false)?;
            }

            Ok(result)
        })?,
    )?;

    // irc.quit() - Quit IRC
    irc.set(
        "quit",
        lua.create_function(
            |lua, (host, port, nick, message): (String, u16, String, Option<String>)| {
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
                let mut stream =
                    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10)) {
                        Ok(s) => s,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
                            return Ok(result);
                        }
                    };

                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

                // Send NICK and USER
                stream
                    .write_all(format!("NICK {}\r\n", nick).as_bytes())
                    .ok();
                stream
                    .write_all(format!("USER {} 0 * :Eggsec\r\n", nick).as_bytes())
                    .ok();

                // Wait a bit for registration
                std::thread::sleep(std::time::Duration::from_millis(500));

                // Quit
                if let Some(msg) = message {
                    stream
                        .write_all(format!("QUIT :{}\r\n", msg).as_bytes())
                        .ok();
                } else {
                    stream.write_all(b"QUIT\r\n").ok();
                }

                result.set("success", true)?;

                Ok(result)
            },
        )?,
    )?;

    // irc.list() - List channels
    irc.set(
        "list",
        lua.create_function(
            |lua, (host, port, channel): (String, u16, Option<String>)| {
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
                let mut stream =
                    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10)) {
                        Ok(s) => s,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
                            return Ok(result);
                        }
                    };

                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

                // Send NICK and USER
                stream.write_all(b"NICK eggsec\r\n").ok();
                stream.write_all(b"USER eggsec 0 * :Eggsec\r\n").ok();

                // Wait a bit for registration
                std::thread::sleep(std::time::Duration::from_millis(500));

                // List channels
                if let Some(ch) = channel {
                    stream.write_all(format!("LIST {}\r\n", ch).as_bytes()).ok();
                } else {
                    stream.write_all(b"LIST\r\n").ok();
                }

                let mut response = vec![0u8; 4096];
                let n = stream.read(&mut response).unwrap_or(0);

                let channels = lua.create_table()?;
                let response_str = String::from_utf8_lossy(&response[..n]).to_string();

                for line in response_str.lines() {
                    if line.contains("323") || line.contains("322") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 4 {
                            let ch_name = parts.get(3).unwrap_or(&"").trim_start_matches(':');
                            if !ch_name.is_empty() {
                                let count = channels.len().unwrap_or(0) + 1;
                                channels.set(count, ch_name)?;
                            }
                        }
                    }
                }

                result.set("channels", channels)?;

                Ok(result)
            },
        )?,
    )?;

    // irc.whois() - Get user info
    irc.set(
        "whois",
        lua.create_function(|lua, (host, port, target): (String, u16, String)| {
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

            stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

            // Send NICK and USER
            stream.write_all(b"NICK eggsec\r\n").ok();
            stream.write_all(b"USER eggsec 0 * :Eggsec\r\n").ok();

            // Wait a bit for registration
            std::thread::sleep(std::time::Duration::from_millis(500));

            // WHOIS
            stream
                .write_all(format!("WHOIS {}\r\n", target).as_bytes())
                .ok();

            let mut response = vec![0u8; 2048];
            let n = stream.read(&mut response).unwrap_or(0);

            let response_str = String::from_utf8_lossy(&response[..n]).to_string();

            result.set("target", target)?;
            result.set("response", response_str.trim())?;

            Ok(result)
        })?,
    )?;

    irc.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("irc", irc)?;
    Ok(())
}
