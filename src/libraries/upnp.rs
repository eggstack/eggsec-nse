//! NSE upnp library wrapper
//!
//! UPnP (Universal Plug and Play) discovery library.
//! Based on Nmap's upnp library concepts.

use crate::brokered_stream::{broker_read_into, broker_write_all};
use crate::capabilities::NseCapabilityContext;
use crate::providers::broker_tcp_connect;
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

use crate::wrappers;

const SSDP_ADDR: &str = "239.255.255.250";
const SSDP_PORT: u16 = 1900;

/// Check network TCP and return a denied error table, or Ok(None) if allowed.
fn maybe_denied_upnp(
    lua: &Lua,
    ctx: &NseCapabilityContext,
    host: &str,
    operation: &'static str,
) -> LuaResult<Option<mlua::Table>> {
    let decision = wrappers::check_network_tcp(ctx, host, operation);
    if !decision.is_allowed() {
        let result = lua.create_table()?;
        result.set("success", false)?;
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

pub fn register_upnp_library(lua: &Lua, capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    register_upnp_library_with_services(
        lua,
        capability_ctx,
        &crate::providers::NseHostServices::native(),
    )
}

/// Provider-backed UPnP registration.
///
/// Every TCP path (SSDP discovery, SOAP external-IP, async aliases) resolves
/// and connects through the broker (authority-preserving); the
/// `maybe_denied_upnp` gates stay in front of each entry. The description
/// fetch (`get_devices`) was already on the HTTP provider broker (M005C).
/// Read-until-EOF for the SSDP/SOAP exchanges (1MB cap).
///
/// Replaces the unbounded `read_to_string` loops: the originals only
/// terminated on a read timeout (EOF yields `Ok(0)` forever), so this keeps
/// the timeout-driven semantics while bounding memory.
fn upnp_read_all(
    ctx: &NseCapabilityContext,
    handle: &mut dyn crate::providers::NseTcpConnection,
    operation: &'static str,
) -> String {
    let mut out = String::new();
    loop {
        let mut chunk = vec![0u8; 8192];
        match broker_read_into(ctx, handle, &mut chunk, operation) {
            Ok(0) => break,
            Ok(n) => {
                out.push_str(&String::from_utf8_lossy(&chunk[..n]));
                if out.len() > 1024 * 1024 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    out
}

pub fn register_upnp_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &crate::providers::NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let upnp = lua.create_table()?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let discover_fn = lua.create_function(move |lua, search_target: Option<String>| {
        if let Some(denied) = maybe_denied_upnp(lua, &cap, SSDP_ADDR, "upnp.discover")? {
            return Ok(denied);
        }
        let result = lua.create_table()?;
        let target = search_target.unwrap_or_else(|| "ssdp:all".to_string());

        let request = format!(
            "M-SEARCH * HTTP/1.1\r\n\
             HOST: {}:{}\r\n\
             MAN: \"ssdp:discover\"\r\n\
             MX: 3\r\n\
             ST: {}\r\n\
             USER-AGENT: Nmap-UPnP/1.0\r\n\
             \r\n",
            SSDP_ADDR, SSDP_PORT, target
        );

        // The broker resolves the SSDP group address (authority-preserving);
        // the old literal-parse-plus-multicast-fallback form is gone.
        match broker_tcp_connect(
            &cap,
            &svc,
            SSDP_ADDR,
            SSDP_PORT,
            Duration::from_secs(3),
            "upnp.discover",
        ) {
            Ok((mut handle, _endpoint)) => {
                let _ = handle.set_timeouts(Duration::from_secs(10));

                if let Err(e) =
                    broker_write_all(&cap, handle.as_mut(), request.as_bytes(), "upnp.discover")
                {
                    result.set("success", false)?;
                    result.set("error", format!("Send failed: {}", e))?;
                    return Ok(result);
                }

                let response = upnp_read_all(&cap, handle.as_mut(), "upnp.discover");
                let devices = lua.create_table()?;
                let mut i = 1;

                let mut current_device = String::new();
                // Single pass over the full response: the old loop re-read
                // until a read timeout (bounded reads now live in
                // `upnp_read_all`). Each response block becomes one device
                // entry, capped at 10 like the old `i > 10` break.
                if !response.is_empty() {
                    for line in response.lines() {
                        let trimmed = line.trim();
                        if (trimmed.starts_with("HTTP/") || trimmed.starts_with("NOTIFY"))
                            && !current_device.is_empty()
                        {
                            let entry = lua.create_table()?;
                            for entry_line in current_device.lines() {
                                if entry_line.to_lowercase().starts_with("location:") {
                                    entry.set(
                                        "location",
                                        entry_line.split(':').nth(1).unwrap_or("").trim(),
                                    )?;
                                } else if entry_line.to_lowercase().starts_with("st:") {
                                    entry.set(
                                        "st",
                                        entry_line.split(':').nth(1).unwrap_or("").trim(),
                                    )?;
                                } else if entry_line.to_lowercase().starts_with("server:") {
                                    entry.set(
                                        "server",
                                        entry_line.split(':').nth(1).unwrap_or("").trim(),
                                    )?;
                                } else if entry_line.to_lowercase().starts_with("usn:") {
                                    entry.set(
                                        "usn",
                                        entry_line.split(':').nth(1).unwrap_or("").trim(),
                                    )?;
                                }
                            }
                            if entry.len().unwrap_or(0) > 0 {
                                devices.set(i, entry)?;
                                i += 1;
                                if i > 10 {
                                    break;
                                }
                            }
                            current_device.clear();
                        }
                        current_device.push_str(line);
                        current_device.push('\n');
                    }
                    if i <= 10 && !current_device.is_empty() {
                        let entry = lua.create_table()?;
                        for entry_line in current_device.lines() {
                            if entry_line.to_lowercase().starts_with("location:") {
                                entry.set(
                                    "location",
                                    entry_line.split(':').nth(1).unwrap_or("").trim(),
                                )?;
                            } else if entry_line.to_lowercase().starts_with("st:") {
                                entry
                                    .set("st", entry_line.split(':').nth(1).unwrap_or("").trim())?;
                            }
                        }
                        if entry.len().unwrap_or(0) > 0 {
                            devices.set(i, entry)?;
                            i += 1;
                        }
                    }
                }

                result.set("success", true)?;
                result.set("devices", devices)?;
                result.set("count", i - 1)?;
            }
            Err(e) => {
                result.set("success", false)?;
                result.set("error", format!("Discovery failed: {}", e))?;
            }
        }

        Ok(result)
    })?;
    upnp.set("discover", discover_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let get_devices_fn = lua.create_function(move |lua, location: String| {
        // Extract host from location URL for capability check
        let host = if location.starts_with("http") {
            location
                .split('/')
                .nth(2)
                .unwrap_or("unknown")
                .split(':')
                .next()
                .unwrap_or("unknown")
                .to_string()
        } else {
            location.split(':').next().unwrap_or(&location).to_string()
        };
        if let Some(denied) = maybe_denied_upnp(lua, &cap, &host, "upnp.get_devices")? {
            return Ok(denied);
        }
        let result = lua.create_table()?;

        let url = if location.starts_with("http") {
            location.clone()
        } else {
            format!("http://{}/", location)
        };

        // M005C: description fetch through the HTTP provider broker
        // (verified-TLS default preserved via profile gating; the legacy
        // unbounded `blocking::get` gains the 30s default bound).
        let req = crate::providers::NseHttpRequest {
            method: crate::providers::NseHttpMethod::Get,
            url,
            host: host.clone(),
            headers: Vec::new(),
            body: Vec::new(),
            timeout: std::time::Duration::from_secs(30),
            connect_timeout: std::time::Duration::from_secs(10),
            insecure_tls: cap.allows_insecure_tls(),
        };
        match crate::providers::broker_http_request(&cap, &svc, &req, "upnp.get_devices") {
            Ok(resp) => {
                let body = resp.body_text();
                let devices = lua.create_table()?;
                let mut i = 1;

                for line in body.lines() {
                    let line_lower = line.to_lowercase();
                    if line_lower.contains("service") || line_lower.contains("device") {
                        let entry = lua.create_table()?;
                        entry.set("raw", line.trim())?;
                        devices.set(i, entry)?;
                        i += 1;
                    }
                }

                result.set("success", true)?;
                result.set("devices", devices)?;
            }
            Err(e) => {
                result.set("success", false)?;
                result.set("error", format!("Request failed: {}", e.detail()))?;
            }
        }

        Ok(result)
    })?;
    upnp.set("get_devices", get_devices_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let get_external_ip_fn = lua.create_function(move |lua, location: Option<String>| {
        let result = lua.create_table()?;

        let loc = location.clone().unwrap_or_else(|| {
            "http://192.168.1.1:1900/ipc".to_string()
        });

        let host = loc.split('/').nth(2).unwrap_or("192.168.1.1");
        let check_host = host.split(':').next().unwrap_or(host);

        if let Some(denied) = maybe_denied_upnp(lua, &cap, check_host, "upnp.get_external_ip")? {
            return Ok(denied);
        }

        let soap_request = "<?xml version=\"1.0\"?>\
            <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
            <s:Body>\
            <u:GetExternalIPAddress xmlns=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
            </u:GetExternalIPAddress>\
            </s:Body>\
            </s:Envelope>";

        let host = loc.split('/').nth(2).unwrap_or("192.168.1.1");
        let path = loc.split(host).nth(1).unwrap_or("/upnp/control/WANIPConn1");

        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: text/xml; charset=\"utf-8\"\r\n\
             SOAPACTION: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            path, host, soap_request.len(), soap_request
        );

        // Port 80 is hardcoded as before (any URL-embedded port was
        // already ignored by the `split(':')` below); the broker resolves
        // the host part authority-preservingly.
        let soap_host = host.split(':').next().unwrap_or(host);

        match broker_tcp_connect(
            &cap,
            &svc,
            soap_host,
            80,
            Duration::from_secs(5),
            "upnp.get_external_ip",
        ) {
            Ok((mut handle, _endpoint)) => {
                let _ = handle.set_timeouts(Duration::from_secs(5));

                if let Err(e) = broker_write_all(&cap, handle.as_mut(), request.as_bytes(), "upnp.get_external_ip") {
                    result.set("success", false)?;
                    result.set("error", format!("Send failed: {}", e))?;
                    return Ok(result);
                }

                let response = upnp_read_all(&cap, handle.as_mut(), "upnp.get_external_ip");
                if !response.is_empty() {
                    if response.contains("200 OK") {
                        for line in response.lines() {
                            if line.contains("<NewExternalIPAddress>") {
                                let ip = line.split('>').nth(1)
                                    .unwrap_or("")
                                    .split('<')
                                    .next()
                                    .unwrap_or("");
                                result.set("success", true)?;
                                result.set("ip", ip)?;
                                return Ok(result);
                            }
                        }
                    }
                    result.set("success", false)?;
                    result.set("error", "Could not parse external IP")?;
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
    upnp.set("get_external_ip", get_external_ip_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    upnp.set("version", version_fn)?;

    // Async discovery: previously bridged `AsyncTcpStream` through the
    // ambient runtime. Rewired to the brokered sync path (entry name kept);
    // reads are bounded in `upnp_read_all` like the sync entry.
    let async_discover_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, search_target: Option<String>| {
            if let Some(denied) = maybe_denied_upnp(lua, &ctx, SSDP_ADDR, "upnp.discover_async")? {
                return Err(mlua::Error::RuntimeError(
                    denied.get::<String>("error").unwrap_or_default(),
                ));
            }
            let result = lua.create_table()?;
            let target = search_target.unwrap_or_else(|| "ssdp:all".to_string());

            let request = format!(
                "M-SEARCH * HTTP/1.1\r\n\
                 HOST: {}:{}\r\n\
                 MAN: \"ssdp:discover\"\r\n\
                 MX: 3\r\n\
                 ST: {}\r\n\
                 USER-AGENT: Nmap-UPnP/1.0\r\n\
                 \r\n",
                SSDP_ADDR, SSDP_PORT, target
            );

            match broker_tcp_connect(
                &ctx,
                &services,
                SSDP_ADDR,
                SSDP_PORT,
                Duration::from_secs(3),
                "upnp.discover_async",
            ) {
                Ok((mut handle, _endpoint)) => {
                    if let Err(e) = broker_write_all(
                        &ctx,
                        handle.as_mut(),
                        request.as_bytes(),
                        "upnp.discover_async",
                    ) {
                        result.set("success", false)?;
                        result.set("error", format!("Send failed: {}", e))?;
                        return Ok(result);
                    }

                    let response = upnp_read_all(&ctx, handle.as_mut(), "upnp.discover_async");
                    let devices = lua.create_table()?;
                    let i = 1;

                    if response.contains("HTTP/") || response.contains("NOTIFY") {
                        let entry = lua.create_table()?;
                        for line in response.lines() {
                            if line.to_lowercase().starts_with("location:") {
                                entry
                                    .set("location", line.split(':').nth(1).unwrap_or("").trim())?;
                            } else if line.to_lowercase().starts_with("st:") {
                                entry.set("st", line.split(':').nth(1).unwrap_or("").trim())?;
                            }
                        }
                        if entry.len().unwrap_or(0) > 0 {
                            devices.set(i, entry)?;
                        }
                    }

                    result.set("success", true)?;
                    result.set("devices", devices)?;
                    result.set("count", i - 1)?;
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Discovery failed: {}", e))?;
                }
            }

            Ok(result)
        }
    })?;
    upnp.set("discover_async", async_discover_fn)?;

    // Async external-IP: previously bridged `AsyncTcpStream` through the
    // ambient runtime. Rewired to the brokered sync path (entry name kept).
    let async_get_external_ip_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, location: Option<String>| {
            let loc_preview = location.clone().unwrap_or_else(|| {
                "http://192.168.1.1:1900/ipc".to_string()
            });
            let check_host = loc_preview
                .split('/')
                .nth(2)
                .unwrap_or("192.168.1.1")
                .split(':')
                .next()
                .unwrap_or("192.168.1.1");
            if let Some(denied) =
                maybe_denied_upnp(lua, &ctx, check_host, "upnp.get_external_ip_async")?
            {
                return Err(mlua::Error::RuntimeError(
                    denied.get::<String>("error").unwrap_or_default(),
                ));
            }
            let result = lua.create_table()?;

            let loc = location.unwrap_or_else(|| "http://192.168.1.1:1900/ipc".to_string());

            let soap_request = "<?xml version=\"1.0\"?>\
                <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
                <s:Body>\
                <u:GetExternalIPAddress xmlns=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
                </u:GetExternalIPAddress>\
                </s:Body>\
                </s:Envelope>";

            let host = loc.split('/').nth(2).unwrap_or("192.168.1.1");
            let path = loc.split(host).nth(1).unwrap_or("/upnp/control/WANIPConn1");

            let request = format!(
                "POST {} HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Type: text/xml; charset=\"utf-8\"\r\n\
                 SOAPACTION: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"\r\n\
                 Content-Length: {}\r\n\
                 \r\n\
                 {}",
                path, host, soap_request.len(), soap_request
            );

            // Port 80 hardcoded as before (URL-embedded ports were ignored).
            let soap_host = host.split(':').next().unwrap_or(host);

            match broker_tcp_connect(
                &ctx,
                &services,
                soap_host,
                80,
                Duration::from_secs(5),
                "upnp.get_external_ip_async",
            ) {
                Ok((mut handle, _endpoint)) => {
                    let _ = handle.set_timeouts(Duration::from_secs(5));

                    if let Err(e) = broker_write_all(&ctx, handle.as_mut(), request.as_bytes(), "upnp.get_external_ip_async") {
                        result.set("success", false)?;
                        result.set("error", format!("Send failed: {}", e))?;
                        return Ok(result);
                    }

                    let response = upnp_read_all(&ctx, handle.as_mut(), "upnp.get_external_ip_async");
                    if !response.is_empty() {
                        if response.contains("200 OK") {
                            for line in response.lines() {
                                if line.contains("<NewExternalIPAddress>") {
                                    let ip = line.split('>').nth(1)
                                        .unwrap_or("")
                                        .split('<')
                                        .next()
                                        .unwrap_or("");
                                    result.set("success", true)?;
                                    result.set("ip", ip)?;
                                    return Ok(result);
                                }
                            }
                        }
                        result.set("success", false)?;
                        result.set("error", "Could not parse external IP")?;
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
        }
    })?;
    upnp.set("get_external_ip_async", async_get_external_ip_fn)?;

    globals.set("upnp", upnp)?;
    Ok(())
}
