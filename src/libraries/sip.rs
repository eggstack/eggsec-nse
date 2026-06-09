//! NSE sip library wrapper
//!
//! SIP (Session Initiation Protocol) library for VoIP communications.
//! Based on Nmap's sip library concepts.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as AsyncTcpStream;

fn build_request(method: &str, uri: &str, headers: &[(String, String)], body: &str) -> String {
    let mut request = format!("{} {} SIP/2.0\r\n", method, uri);

    for (key, value) in headers {
        request.push_str(&format!("{}: {}\r\n", key, value));
    }

    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        request.push_str("\r\n");
        request.push_str(body);
    } else {
        request.push_str("\r\n");
    }

    request
}

pub fn register_sip_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let sip = lua.create_table()?;

    let new_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let s = lua.create_table()?;
        s.set("host", host)?;
        s.set("port", port)?;
        s.set("timeout", 5i64)?;
        Ok(s)
    })?;
    sip.set("new", new_fn)?;

    let options_fn =
        lua.create_function(|lua, (host, port, user): (String, u16, Option<String>)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);

            let headers = vec![
                ("Via".to_string(), "SIP/2.0/TCP".to_string()),
                ("Max-Forwards".to_string(), "70".to_string()),
                (
                    "From".to_string(),
                    format!("<sip:{}@{}>", user.as_deref().unwrap_or("nmap"), host),
                ),
                (
                    "To".to_string(),
                    format!("<sip:{}@{}>", user.as_deref().unwrap_or("nmap"), host),
                ),
                (
                    "Call-ID".to_string(),
                    format!("{}@{}", rand::random::<u64>(), host),
                ),
                ("CSeq".to_string(), "1 OPTIONS".to_string()),
                ("User-Agent".to_string(), "Nmap-SIP/1.0".to_string()),
                ("Accept".to_string(), "application/sdp".to_string()),
            ];

            let request = build_request("OPTIONS", "sip:any", &headers, "");

            match TcpStream::connect_timeout(
                &addr
                    .parse()
                    .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 5060))),
                Duration::from_secs(5),
            ) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

                    if let Err(e) = stream.write_all(request.as_bytes()) {
                        result.set("success", false)?;
                        result.set("error", format!("Send failed: {}", e))?;
                        return Ok(result);
                    }

                    let mut response = String::new();
                    if stream.read_to_string(&mut response).is_ok() {
                        result.set("success", true)?;
                        result.set("response", response.clone())?;

                        let status = response
                            .lines()
                            .next()
                            .unwrap_or("")
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("0")
                            .parse::<u16>()
                            .unwrap_or(0);

                        result.set("status", status)?;

                        if status == 200 {
                            let mut allow = Vec::new();
                            let mut server = String::new();

                            for line in response.lines() {
                                let line_lower = line.to_lowercase();
                                if line_lower.starts_with("allow:") {
                                    allow = line
                                        .split(':')
                                        .nth(1)
                                        .unwrap_or("")
                                        .split(',')
                                        .map(|s| s.trim().to_string())
                                        .collect();
                                }
                                if line_lower.starts_with("server:") {
                                    server =
                                        line.split(':').nth(1).unwrap_or("").trim().to_string();
                                }
                            }

                            result.set("allow", allow)?;
                            result.set("server", server)?;
                        }
                    } else {
                        result.set("success", false)?;
                        result.set("error", "Failed to read response")?;
                    }
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
            }

            Ok(result)
        })?;
    sip.set("options", options_fn)?;

    let invite_fn = lua.create_function(
        |lua, (host, port, from, to, body): (String, u16, String, String, Option<String>)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);

            let headers = vec![
                ("Via".to_string(), "SIP/2.0/TCP".to_string()),
                ("Max-Forwards".to_string(), "70".to_string()),
                ("From".to_string(), format!("<sip:{}@{}>", from, host)),
                ("To".to_string(), format!("<sip:{}@{}>", to, host)),
                (
                    "Call-ID".to_string(),
                    format!("{}@{}", rand::random::<u64>(), host),
                ),
                ("CSeq".to_string(), "1 INVITE".to_string()),
                ("User-Agent".to_string(), "Nmap-SIP/1.0".to_string()),
                (
                    "Contact".to_string(),
                    format!("<sip:{}@{}:{}>", from, host, port),
                ),
                ("Content-Type".to_string(), "application/sdp".to_string()),
            ];

            let request = build_request(
                "INVITE",
                &format!("sip:{}@{}", to, host),
                &headers,
                body.as_deref().unwrap_or(""),
            );

            match TcpStream::connect_timeout(
                &addr
                    .parse()
                    .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 5060))),
                Duration::from_secs(5),
            ) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

                    if let Err(e) = stream.write_all(request.as_bytes()) {
                        result.set("success", false)?;
                        result.set("error", format!("Send failed: {}", e))?;
                        return Ok(result);
                    }

                    let mut response = String::new();
                    if stream.read_to_string(&mut response).is_ok() {
                        result.set("success", true)?;
                        result.set("response", response)?;
                    } else {
                        result.set("success", false)?;
                        result.set("error", "Failed to read response")?;
                    }
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
            }

            Ok(result)
        },
    )?;
    sip.set("invite", invite_fn)?;

    let register_fn = lua.create_function(
        |lua, (host, port, user, password): (String, u16, String, String)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);

            let auth = format!("{}:{}", user, password);
            use base64::Engine;
            let auth_b64 = base64::engine::general_purpose::STANDARD.encode(auth.as_bytes());

            let headers = vec![
                ("Via".to_string(), "SIP/2.0/TCP".to_string()),
                ("Max-Forwards".to_string(), "70".to_string()),
                ("From".to_string(), format!("<sip:{}@{}>", user, host)),
                ("To".to_string(), format!("<sip:{}@{}>", user, host)),
                (
                    "Call-ID".to_string(),
                    format!("{}@{}", rand::random::<u64>(), host),
                ),
                ("CSeq".to_string(), "1 REGISTER".to_string()),
                ("User-Agent".to_string(), "Nmap-SIP/1.0".to_string()),
                (
                    "Contact".to_string(),
                    format!("<sip:{}@{}:{}>", user, host, port),
                ),
                ("Authorization".to_string(), format!("Basic {}", auth_b64)),
                ("Expires".to_string(), "3600".to_string()),
            ];

            let request = build_request("REGISTER", &format!("sip:{}", host), &headers, "");

            match TcpStream::connect_timeout(
                &addr
                    .parse()
                    .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 5060))),
                Duration::from_secs(5),
            ) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

                    if let Err(e) = stream.write_all(request.as_bytes()) {
                        result.set("success", false)?;
                        result.set("error", format!("Send failed: {}", e))?;
                        return Ok(result);
                    }

                    let mut response = String::new();
                    if stream.read_to_string(&mut response).is_ok() {
                        let resp_copy = response.clone();
                        result.set("success", true)?;
                        result.set("response", resp_copy)?;

                        let status = response
                            .lines()
                            .next()
                            .unwrap_or("")
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("0")
                            .parse::<u16>()
                            .unwrap_or(0);

                        result.set("status", status)?;
                    } else {
                        result.set("success", false)?;
                        result.set("error", "Failed to read response")?;
                    }
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
            }

            Ok(result)
        },
    )?;
    sip.set("register", register_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    sip.set("version", version_fn)?;

    let async_options_fn =
        lua.create_function(|lua, (host, port, user): (String, u16, Option<String>)| {
            let runtime = tokio::runtime::Handle::current();
            let host_clone = host.clone();

            runtime.block_on(async {
                let result = lua.create_table()?;

                let headers = vec![
                    ("Via".to_string(), "SIP/2.0/TCP".to_string()),
                    ("Max-Forwards".to_string(), "70".to_string()),
                    (
                        "From".to_string(),
                        format!("<sip:{}@{}>", user.as_deref().unwrap_or("nmap"), host_clone),
                    ),
                    (
                        "To".to_string(),
                        format!("<sip:{}@{}>", user.as_deref().unwrap_or("nmap"), host_clone),
                    ),
                    ("Call-ID".to_string(), "nmap-test".to_string()),
                    ("CSeq".to_string(), "1 OPTIONS".to_string()),
                    ("Accept".to_string(), "application/sdp".to_string()),
                ];

                let request = build_request(
                    "OPTIONS",
                    &format!("sip:{}@{}", user.as_deref().unwrap_or("*"), host_clone),
                    &headers,
                    "",
                );

                match AsyncTcpStream::connect(format!("{}:{}", host_clone, port)).await {
                    Ok(mut stream) => {
                        if let Err(e) = stream.write_all(request.as_bytes()).await {
                            result.set("success", false)?;
                            result.set("error", format!("Send failed: {}", e))?;
                            return Ok(result);
                        }

                        let mut response = String::new();
                        if stream.read_to_string(&mut response).await.is_ok() {
                            result.set("success", true)?;
                            result.set("response", response)?;
                        } else {
                            result.set("success", false)?;
                            result.set("error", "Failed to read response")?;
                        }
                    }
                    Err(e) => {
                        result.set("success", false)?;
                        result.set("error", format!("Connection failed: {}", e))?;
                    }
                }

                Ok(result)
            })
        })?;
    sip.set("options_async", async_options_fn)?;

    let async_invite_fn =
        lua.create_function(|lua, (host, port, user): (String, u16, Option<String>)| {
            let runtime = tokio::runtime::Handle::current();
            let host_clone = host.clone();

            runtime.block_on(async {
                let result = lua.create_table()?;

                let headers = vec![
                    ("Via".to_string(), "SIP/2.0/TCP".to_string()),
                    ("Max-Forwards".to_string(), "70".to_string()),
                    ("From".to_string(), format!("<sip:{}@{}>", user.as_deref().unwrap_or("nmap"), host_clone)),
                    ("To".to_string(), format!("<sip:{}@{}>", user.as_deref().unwrap_or("nmap"), host_clone)),
                    ("Call-ID".to_string(), "nmap-test".to_string()),
                    ("CSeq".to_string(), "1 INVITE".to_string()),
                    ("Content-Type".to_string(), "application/sdp".to_string()),
                ];

                let body = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=Test\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";
                let request = build_request("INVITE", &format!("sip:{}@{}", user.as_deref().unwrap_or("*"), host_clone), &headers, body);

                match AsyncTcpStream::connect(format!("{}:{}", host_clone, port)).await {
                    Ok(mut stream) => {
                        if let Err(e) = stream.write_all(request.as_bytes()).await {
                            result.set("success", false)?;
                            result.set("error", format!("Send failed: {}", e))?;
                            return Ok(result);
                        }

                        let mut response = String::new();
                        if stream.read_to_string(&mut response).await.is_ok() {
                            result.set("success", true)?;
                            result.set("response", response)?;
                        } else {
                            result.set("success", false)?;
                            result.set("error", "Failed to read response")?;
                        }
                    }
                    Err(e) => {
                        result.set("success", false)?;
                        result.set("error", format!("Connection failed: {}", e))?;
                    }
                }

                Ok(result)
            })
        })?;
    sip.set("invite_async", async_invite_fn)?;

    globals.set("sip", sip)?;
    Ok(())
}
