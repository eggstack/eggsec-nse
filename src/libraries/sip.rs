//! NSE sip library wrapper
//!
//! SIP (Session Initiation Protocol) library for VoIP communications.
//! Based on Nmap's sip library concepts.

use crate::brokered_stream::{broker_read_into, broker_send_all};
use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

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

/// Provider-backed sip registration.
///
/// `services` backs every TCP connect/send/receive path.

/// Brokered SIP exchange: connect + send request + read full response.
///
/// Replaces the per-entry `TcpStream::connect_timeout` + `write_all` +
/// `read_to_string` sequences. Reads loop until EOF with a 1MB cap,
/// matching `read_to_string` semantics. The error phases preserve the
/// callers' `Connection failed:` / `Send failed:` / read-failure shapes.
// The `Read` payload is intentionally discarded at one call site to preserve
// the original static `"Failed to read response"` error string.
#[allow(dead_code)]
enum SipExchangeError {
    Connect(String),
    Send(String),
    Read(String),
}

fn sip_exchange(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    host: &str,
    port: u16,
    request: &[u8],
    operation: &'static str,
) -> Result<String, SipExchangeError> {
    let (mut handle, _endpoint) =
        broker_tcp_connect(ctx, services, host, port, Duration::from_secs(5), operation)
            .map_err(SipExchangeError::Connect)?;
    let _ = handle.set_timeouts(Duration::from_secs(5));
    broker_send_all(ctx, handle.as_mut(), request, operation).map_err(SipExchangeError::Send)?;
    let mut out = Vec::new();
    loop {
        let mut chunk = vec![0u8; 65536];
        let n = broker_read_into(ctx, handle.as_mut(), &mut chunk, operation)
            .map_err(|e| SipExchangeError::Read(e.to_string()))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        if out.len() > 1024 * 1024 {
            break;
        }
    }
    String::from_utf8(out).map_err(|e| SipExchangeError::Read(e.to_string()))
}

pub fn register_sip_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
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

    let options_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, user): (String, u16, Option<String>)| {
            let result = lua.create_table()?;

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

            // Brokered exchange (authority-preserving resolve replaces the
            // literal-parse-plus-loopback-fallback); response shapes below
            // are unchanged.
            match sip_exchange(
                &ctx,
                &services,
                &host,
                port,
                request.as_bytes(),
                "sip.options",
            ) {
                Ok(response) => {
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
                                server = line.split(':').nth(1).unwrap_or("").trim().to_string();
                            }
                        }

                        result.set("allow", allow)?;
                        result.set("server", server)?;
                    }
                }
                Err(SipExchangeError::Send(e)) => {
                    result.set("success", false)?;
                    result.set("error", format!("Send failed: {}", e))?;
                    return Ok(result);
                }
                Err(SipExchangeError::Read(_)) => {
                    result.set("success", false)?;
                    result.set("error", "Failed to read response")?;
                }
                Err(SipExchangeError::Connect(e)) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
            }

            Ok(result)
        }
    })?;
    sip.set("options", options_fn)?;

    let invite_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, from, to, body): (String, u16, String, String, Option<String>)| {
            let result = lua.create_table()?;

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

            // Brokered exchange (authority-preserving resolve replaces the
            // literal-parse-plus-loopback-fallback); response shapes below
            // are unchanged.
            match sip_exchange(
                &ctx,
                &services,
                &host,
                port,
                request.as_bytes(),
                "sip.invite",
            ) {
                Ok(response) => {
                    result.set("success", true)?;
                    result.set("response", response)?;
                }
                Err(SipExchangeError::Send(e)) => {
                    result.set("success", false)?;
                    result.set("error", format!("Send failed: {}", e))?;
                    return Ok(result);
                }
                Err(SipExchangeError::Read(_)) => {
                    result.set("success", false)?;
                    result.set("error", "Failed to read response")?;
                }
                Err(SipExchangeError::Connect(e)) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
            }

            Ok(result)
        }
    })?;
    sip.set("invite", invite_fn)?;

    let register_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, user, password): (String, u16, String, String)| {
            let result = lua.create_table()?;

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

            // Brokered exchange (authority-preserving resolve replaces the
            // literal-parse-plus-loopback-fallback); response shapes below
            // are unchanged.
            match sip_exchange(
                &ctx,
                &services,
                &host,
                port,
                request.as_bytes(),
                "sip.register",
            ) {
                Ok(response) => {
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
                }
                Err(SipExchangeError::Send(e)) => {
                    result.set("success", false)?;
                    result.set("error", format!("Send failed: {}", e))?;
                    return Ok(result);
                }
                Err(SipExchangeError::Read(_)) => {
                    result.set("success", false)?;
                    result.set("error", "Failed to read response")?;
                }
                Err(SipExchangeError::Connect(e)) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
            }

            Ok(result)
        }
    })?;
    sip.set("register", register_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    sip.set("version", version_fn)?;

    // Async OPTIONS: previously bridged `AsyncTcpStream` through the ambient
    // runtime. Rewired to the brokered sync exchange (entry name kept).
    let async_options_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, user): (String, u16, Option<String>)| {
            let result = lua.create_table()?;

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
                ("Call-ID".to_string(), "nmap-test".to_string()),
                ("CSeq".to_string(), "1 OPTIONS".to_string()),
                ("Accept".to_string(), "application/sdp".to_string()),
            ];

            let request = build_request(
                "OPTIONS",
                &format!("sip:{}@{}", user.as_deref().unwrap_or("*"), host),
                &headers,
                "",
            );

            match sip_exchange(
                &ctx,
                &services,
                &host,
                port,
                request.as_bytes(),
                "sip.options_async",
            ) {
                Ok(response) => {
                    result.set("success", true)?;
                    result.set("response", response)?;
                }
                Err(SipExchangeError::Send(e)) => {
                    result.set("success", false)?;
                    result.set("error", format!("Send failed: {}", e))?;
                    return Ok(result);
                }
                Err(SipExchangeError::Read(_)) => {
                    result.set("success", false)?;
                    result.set("error", "Failed to read response")?;
                }
                Err(SipExchangeError::Connect(e)) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
            }

            Ok(result)
        }
    })?;
    sip.set("options_async", async_options_fn)?;

    // Async INVITE: previously bridged `AsyncTcpStream` through the ambient
    // runtime. Rewired to the brokered sync exchange (entry name kept).
    let async_invite_fn =
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, user): (String, u16, Option<String>)| {
                let result = lua.create_table()?;

                let headers = vec![
                    ("Via".to_string(), "SIP/2.0/TCP".to_string()),
                    ("Max-Forwards".to_string(), "70".to_string()),
                    ("From".to_string(), format!("<sip:{}@{}>", user.as_deref().unwrap_or("nmap"), host)),
                    ("To".to_string(), format!("<sip:{}@{}>", user.as_deref().unwrap_or("nmap"), host)),
                    ("Call-ID".to_string(), "nmap-test".to_string()),
                    ("CSeq".to_string(), "1 INVITE".to_string()),
                    ("Content-Type".to_string(), "application/sdp".to_string()),
                ];

                let body = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=Test\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";
                let request = build_request("INVITE", &format!("sip:{}@{}", user.as_deref().unwrap_or("*"), host), &headers, body);

                match sip_exchange(&ctx, &services, &host, port, request.as_bytes(), "sip.invite_async") {
                    Ok(response) => {
                        result.set("success", true)?;
                        result.set("response", response)?;
                    }
                    Err(SipExchangeError::Send(e)) => {
                        result.set("success", false)?;
                        result.set("error", format!("Send failed: {}", e))?;
                        return Ok(result);
                    }
                    Err(SipExchangeError::Read(_)) => {
                        result.set("success", false)?;
                        result.set("error", "Failed to read response")?;
                    }
                    Err(SipExchangeError::Connect(e)) => {
                        result.set("success", false)?;
                        result.set("error", format!("Connection failed: {}", e))?;
                    }
                }

                Ok(result)
            }
        })?;
    sip.set("invite_async", async_invite_fn)?;

    globals.set("sip", sip)?;
    Ok(())
}
