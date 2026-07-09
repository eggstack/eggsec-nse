//! NSE smtp library wrapper
//!
//! SMTP protocol support for NSE scripts.
//! Based on Nmap's smtp library: https://nmap.org/nsedoc/lib/smtp.html
//! Includes both blocking and async implementations with real SMTP protocol support.

use mlua::{Lua, Result as LuaResult, Table};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::capabilities::NseCapabilityContext;
use crate::wrappers;

fn smtp_connect(host: &str, port: u16) -> std::io::Result<(TcpStream, String)> {
    let addr = format!("{}:{}", host, port);
    let socket_addr = addr
        .parse::<std::net::SocketAddr>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;

    let mut stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let mut buffer = vec![0u8; 1024];
    let n = stream.read(&mut buffer)?;

    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "No response from SMTP server",
        ));
    }

    let banner = String::from_utf8_lossy(&buffer[..n]).to_string();

    if !banner.starts_with("220") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid SMTP banner: {}", banner),
        ));
    }

    Ok((stream, banner))
}

fn smtp_login(
    stream: &mut TcpStream,
    host: &str,
    user: &str,
    password: &str,
) -> std::io::Result<bool> {
    stream.write_all(format!("EHLO {}\r\n", host).as_bytes())?;
    stream.flush()?;

    let mut response = vec![0u8; 1024];
    if stream.read(&mut response).is_err() {
        tracing::warn!("Failed to read SMTP EHLO response");
    }

    stream.write_all("AUTH LOGIN\r\n".to_string().as_bytes())?;
    stream.flush()?;

    response.clear();
    let n = stream.read(&mut response)?;
    if n == 0 || !String::from_utf8_lossy(&response[..n]).contains("334") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "SMTP AUTH LOGIN not supported",
        ));
    }

    use base64::Engine;
    let username_encoded = base64::engine::general_purpose::STANDARD.encode(user.as_bytes());
    stream.write_all(format!("{}\r\n", username_encoded).as_bytes())?;
    stream.flush()?;

    response.clear();
    let n = stream.read(&mut response)?;
    if n == 0 || !String::from_utf8_lossy(&response[..n]).contains("334") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Invalid username",
        ));
    }

    let password_encoded = base64::engine::general_purpose::STANDARD.encode(password.as_bytes());
    stream.write_all(format!("{}\r\n", password_encoded).as_bytes())?;
    stream.flush()?;

    response.clear();
    let n = stream.read(&mut response)?;

    if n > 0 {
        let response_str = String::from_utf8_lossy(&response[..n]);
        if response_str.starts_with("235") {
            return Ok(true);
        } else if response_str.starts_with("535") || response_str.starts_with("530") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                response_str.trim(),
            ));
        }
    }

    Ok(true)
}

fn smtp_send_mail(
    stream: &mut TcpStream,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
) -> std::io::Result<bool> {
    stream.write_all(format!("MAIL FROM:<{}>\r\n", from).as_bytes())?;
    stream.flush()?;

    let mut response = vec![0u8; 1024];
    let n = stream.read(&mut response)?;
    if n == 0 || !String::from_utf8_lossy(&response[..n]).starts_with("250") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "MAIL FROM failed",
        ));
    }

    stream.write_all(format!("RCPT TO:<{}>\r\n", to).as_bytes())?;
    stream.flush()?;

    response.clear();
    let n = stream.read(&mut response)?;
    if n == 0 || !String::from_utf8_lossy(&response[..n]).starts_with("250") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "RCPT TO failed",
        ));
    }

    stream.write_all(b"DATA\r\n")?;
    stream.flush()?;

    response.clear();
    let n = stream.read(&mut response)?;
    if n == 0 || !String::from_utf8_lossy(&response[..n]).starts_with("354") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "DATA command failed",
        ));
    }

    let full_body = if subject.is_empty() {
        format!("From: {}\r\nTo: {}\r\n\r\n{}\r\n.\r\n", from, to, body)
    } else {
        format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\n\r\n{}\r\n.\r\n",
            from, to, subject, body
        )
    };

    stream.write_all(full_body.as_bytes())?;
    stream.flush()?;

    response.clear();
    let n = stream.read(&mut response)?;

    if n > 0 && String::from_utf8_lossy(&response[..n]).starts_with("250") {
        Ok(true)
    } else {
        Err(std::io::Error::other("Failed to send message"))
    }
}

/// Check network TCP and return a denied error table, or Ok(None) if allowed.
fn maybe_denied_smtp(
    lua: &Lua,
    ctx: &NseCapabilityContext,
    host: &str,
    operation: &'static str,
) -> LuaResult<Option<Table>> {
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

pub fn register_smtp_library(lua: &Lua, capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    let globals = lua.globals();
    let smtp = lua.create_table()?;

    let cap = capability_ctx.clone();
    smtp.set(
        "connect",
        lua.create_function(move |lua, (host, port): (String, u16)| {
            if let Some(denied) = maybe_denied_smtp(lua, &cap, &host, "smtp.connect")? {
                return Ok(denied);
            }
            match smtp_connect(&host, port) {
                Ok((_stream, banner)) => {
                    let result = lua.create_table()?;
                    result.set("status", "connected")?;
                    result.set("banner", banner.trim())?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        })?,
    )?;

    let cap = capability_ctx.clone();
    smtp.set(
        "login",
        lua.create_function(
            move |lua, (host, user, password): (String, String, String)| {
                if let Some(denied) = maybe_denied_smtp(lua, &cap, &host, "smtp.login")? {
                    return Ok(denied);
                }
                let port = 25;
                match smtp_connect(&host, port) {
                    Ok((mut stream, _banner)) => {
                        match smtp_login(&mut stream, &host, &user, &password) {
                            Ok(success) => {
                                let result = lua.create_table()?;
                                result.set("success", success)?;
                                result.set("user", user)?;
                                Ok(result)
                            }
                            Err(e) => {
                                let result = lua.create_table()?;
                                result.set("success", false)?;
                                result.set("error", e.to_string())?;
                                Ok(result)
                            }
                        }
                    }
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", e.to_string())?;
                        Ok(result)
                    }
                }
            },
        )?,
    )?;

    let cap = capability_ctx.clone();
    smtp.set(
        "login_ex",
        lua.create_function(
            move |lua, (host, port, user, password): (String, u16, String, String)| {
                if let Some(denied) = maybe_denied_smtp(lua, &cap, &host, "smtp.login_ex")? {
                    return Ok(denied);
                }
                match smtp_connect(&host, port) {
                    Ok((mut stream, _banner)) => {
                        match smtp_login(&mut stream, &host, &user, &password) {
                            Ok(success) => {
                                let result = lua.create_table()?;
                                result.set("success", success)?;
                                result.set("user", user)?;
                                Ok(result)
                            }
                            Err(e) => {
                                let result = lua.create_table()?;
                                result.set("success", false)?;
                                result.set("error", e.to_string())?;
                                Ok(result)
                            }
                        }
                    }
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", e.to_string())?;
                        Ok(result)
                    }
                }
            },
        )?,
    )?;

    let cap = capability_ctx.clone();
    smtp.set(
        "send_mail",
        lua.create_function(
            move |lua,
                  (host, from, to, subject, body): (String, String, String, String, String)| {
                if let Some(denied) = maybe_denied_smtp(lua, &cap, &host, "smtp.send_mail")? {
                    return Ok(denied);
                }
                let port = 25;
                match smtp_connect(&host, port) {
                    Ok((mut stream, _banner)) => {
                        match smtp_send_mail(&mut stream, &from, &to, &subject, &body) {
                            Ok(success) => {
                                let result = lua.create_table()?;
                                result.set("success", success)?;
                                result.set("from", from)?;
                                result.set("to", to)?;
                                Ok(result)
                            }
                            Err(e) => {
                                let result = lua.create_table()?;
                                result.set("success", false)?;
                                result.set("error", e.to_string())?;
                                Ok(result)
                            }
                        }
                    }
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", e.to_string())?;
                        Ok(result)
                    }
                }
            },
        )?,
    )?;

    let cap = capability_ctx.clone();
    smtp.set(
        "send_mail_ex",
        lua.create_function(
            move |lua,
                  (host, port, from, to, subject, body): (
                String,
                u16,
                String,
                String,
                String,
                String,
            )| {
                if let Some(denied) = maybe_denied_smtp(lua, &cap, &host, "smtp.send_mail_ex")? {
                    return Ok(denied);
                }
                match smtp_connect(&host, port) {
                    Ok((mut stream, _banner)) => {
                        match smtp_send_mail(&mut stream, &from, &to, &subject, &body) {
                            Ok(success) => {
                                let result = lua.create_table()?;
                                result.set("success", success)?;
                                result.set("from", from)?;
                                result.set("to", to)?;
                                Ok(result)
                            }
                            Err(e) => {
                                let result = lua.create_table()?;
                                result.set("success", false)?;
                                result.set("error", e.to_string())?;
                                Ok(result)
                            }
                        }
                    }
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", e.to_string())?;
                        Ok(result)
                    }
                }
            },
        )?,
    )?;

    smtp.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    let cap = capability_ctx.clone();
    smtp.set(
        "connect_async",
        lua.create_function(move |lua, (host, port): (String, u16)| {
            if let Some(denied) = maybe_denied_smtp(lua, &cap, &host, "smtp.connect_async")? {
                return Err(mlua::Error::RuntimeError(
                    denied.get::<String>("error").unwrap_or_default(),
                ));
            }
            let host_clone = host.clone();

            tokio::runtime::Handle::current().block_on(async {
                let result =
                    tokio::task::spawn_blocking(move || smtp_connect(&host_clone, port)).await;

                match result {
                    Ok(Ok((_stream, banner))) => {
                        let r = lua.create_table()?;
                        r.set("status", "connected")?;
                        r.set("banner", banner.trim())?;
                        Ok(r)
                    }
                    Ok(Err(e)) => {
                        let r = lua.create_table()?;
                        r.set("status", "error")?;
                        r.set("error", e.to_string())?;
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
        })?,
    )?;

    let cap = capability_ctx.clone();
    smtp.set(
        "send_mail_async",
        lua.create_function(
            move |lua,
                  (host, from, to, subject, body): (String, String, String, String, String)| {
                if let Some(denied) =
                    maybe_denied_smtp(lua, &cap, &host, "smtp.send_mail_async")?
                {
                    return Err(mlua::Error::RuntimeError(
                        denied.get::<String>("error").unwrap_or_default(),
                    ));
                }
                let host_clone = host.clone();
                let from_clone = from.clone();
                let to_clone = to.clone();
                let subject_clone = subject.clone();
                let body_clone = body.clone();

                tokio::runtime::Handle::current().block_on(async {
                    let result = tokio::task::spawn_blocking(move || {
                        let port = 25;
                        let (mut stream, _banner) = smtp_connect(&host_clone, port)?;
                        smtp_send_mail(
                            &mut stream,
                            &from_clone,
                            &to_clone,
                            &subject_clone,
                            &body_clone,
                        )
                    })
                    .await;

                    match result {
                        Ok(Ok(success)) => {
                            let r = lua.create_table()?;
                            r.set("success", success)?;
                            r.set("from", from)?;
                            r.set("to", to)?;
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
        )?,
    )?;

    // smtp.vrfy() - Verify if a user exists
    let cap = capability_ctx.clone();
    smtp.set(
        "vrfy",
        lua.create_function(move |lua, (host, user): (String, String)| {
            if let Some(denied) = maybe_denied_smtp(lua, &cap, &host, "smtp.vrfy")? {
                return Ok(denied);
            }
            let port = 25;
            match smtp_connect(&host, port) {
                Ok((mut stream, _banner)) => {
                    stream
                        .write_all(format!("VRFY {}\r\n", user).as_bytes())
                        .ok();
                    stream.flush().ok();

                    let mut response = vec![0u8; 1024];
                    let n = stream.read(&mut response).unwrap_or(0);

                    let result = lua.create_table()?;
                    let response_str = String::from_utf8_lossy(&response[..n]).to_string();

                    if response_str.starts_with("250") {
                        result.set("exists", true)?;
                        result.set("response", response_str.trim())?;
                    } else if response_str.starts_with("550") || response_str.starts_with("501") {
                        result.set("exists", false)?;
                        result.set("response", response_str.trim())?;
                    } else {
                        result.set("exists", false)?;
                        result.set("response", response_str.trim())?;
                    }

                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("exists", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        })?,
    )?;

    // smtp.expn() - Expand a mailing list
    let cap = capability_ctx.clone();
    smtp.set(
        "expn",
        lua.create_function(move |lua, (host, list): (String, String)| {
            if let Some(denied) = maybe_denied_smtp(lua, &cap, &host, "smtp.expn")? {
                return Ok(denied);
            }
            let port = 25;
            match smtp_connect(&host, port) {
                Ok((mut stream, _banner)) => {
                    stream
                        .write_all(format!("EXPN {}\r\n", list).as_bytes())
                        .ok();
                    stream.flush().ok();

                    let mut response = vec![0u8; 4096];
                    let n = stream.read(&mut response).unwrap_or(0);

                    let result = lua.create_table()?;
                    let response_str = String::from_utf8_lossy(&response[..n]).to_string();

                    if response_str.starts_with("250") {
                        result.set("exists", true)?;

                        let members = lua.create_table()?;
                        for line in response_str.lines() {
                            if line.starts_with("250-") || line.starts_with("250 ") {
                                let addr = line
                                    .trim()
                                    .trim_start_matches("250-")
                                    .trim_start_matches("250 ");
                                if !addr.is_empty() && addr.contains('@') {
                                    let count = members.len().unwrap_or(0) + 1;
                                    members.set(count, addr)?;
                                }
                            }
                        }
                        result.set("members", members)?;
                    } else if response_str.starts_with("550") {
                        result.set("exists", false)?;
                        result.set("response", response_str.trim())?;
                    } else {
                        result.set("exists", false)?;
                        result.set("response", response_str.trim())?;
                    }

                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("exists", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        })?,
    )?;

    // smtp.help() - Get help information
    let cap = capability_ctx.clone();
    smtp.set(
        "help",
        lua.create_function(move |lua, (host, command): (String, Option<String>)| {
            if let Some(denied) = maybe_denied_smtp(lua, &cap, &host, "smtp.help")? {
                return Ok(denied);
            }
            let port = 25;
            match smtp_connect(&host, port) {
                Ok((mut stream, _banner)) => {
                    if let Some(cmd) = command {
                        if stream
                            .write_all(format!("HELP {}\r\n", cmd).as_bytes())
                            .is_err()
                        {
                            tracing::warn!("SMTP: Failed to send HELP {}", cmd);
                        }
                    } else {
                        if stream.write_all(b"HELP\r\n").is_err() {
                            tracing::warn!("SMTP: Failed to send HELP");
                        }
                    }
                    stream.flush().ok();

                    let mut response = vec![0u8; 4096];
                    let n = stream.read(&mut response).unwrap_or(0);

                    let result = lua.create_table()?;
                    result.set(
                        "response",
                        String::from_utf8_lossy(&response[..n]).trim().to_string(),
                    )?;

                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        })?,
    )?;

    // smtp.noop() - No operation (keep connection alive)
    let cap = capability_ctx.clone();
    smtp.set(
        "noop",
        lua.create_function(move |lua, (host, port): (String, u16)| {
            if let Some(denied) = maybe_denied_smtp(lua, &cap, &host, "smtp.noop")? {
                return Ok(denied);
            }
            match smtp_connect(&host, port) {
                Ok((mut stream, _banner)) => {
                    if stream.write_all(b"NOOP\r\n").is_err() {
                        tracing::warn!("SMTP: Failed to send NOOP");
                    }
                    stream.flush().ok();

                    let mut response = vec![0u8; 256];
                    let n = stream.read(&mut response).unwrap_or(0);

                    let result = lua.create_table()?;
                    let response_str = String::from_utf8_lossy(&response[..n]).to_string();

                    if response_str.starts_with("250") {
                        result.set("success", true)?;
                    } else {
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
        })?,
    )?;

    // smtp.rset() - Reset the session
    let cap = capability_ctx.clone();
    smtp.set(
        "rset",
        lua.create_function(move |lua, (host, port): (String, u16)| {
            if let Some(denied) = maybe_denied_smtp(lua, &cap, &host, "smtp.rset")? {
                return Ok(denied);
            }
            match smtp_connect(&host, port) {
                Ok((mut stream, _banner)) => {
                    if stream.write_all(b"RSET\r\n").is_err() {
                        tracing::warn!("SMTP: Failed to send RSET");
                    }
                    stream.flush().ok();

                    let mut response = vec![0u8; 256];
                    let n = stream.read(&mut response).unwrap_or(0);

                    let result = lua.create_table()?;
                    let response_str = String::from_utf8_lossy(&response[..n]).to_string();

                    if response_str.starts_with("250") {
                        result.set("success", true)?;
                    } else {
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
        })?,
    )?;

    // smtp.quit() - Close the connection
    let cap = capability_ctx.clone();
    smtp.set(
        "quit",
        lua.create_function(move |lua, (host, port): (String, u16)| {
            if let Some(denied) = maybe_denied_smtp(lua, &cap, &host, "smtp.quit")? {
                return Ok(denied);
            }
            match smtp_connect(&host, port) {
                Ok((mut stream, _banner)) => {
                    if stream.write_all(b"QUIT\r\n").is_err() {
                        tracing::warn!("SMTP: Failed to send QUIT");
                    }
                    stream.flush().ok();

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
        })?,
    )?;

    globals.set("smtp", smtp)?;
    Ok(())
}
