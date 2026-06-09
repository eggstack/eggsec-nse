//! NSE wsdd library wrapper
//!
//! Web Service Discovery (WS-Discovery) protocol.
//! Based on Nmap's wsdd library.

use mlua::{Lua, Result as LuaResult};
use std::net::UdpSocket;
use std::time::Duration;

const WS_DISCOVERY_PORT: u16 = 3702;
const WS_DISCOVERY_MULTICAST: &str = "239.255.255.250";

pub fn register_wsdd_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let wsdd = lua.create_table()?;

    // discover - Send WS-Discovery Probe to find devices
    wsdd.set(
        "discover",
        lua.create_function(|lua, (host, port, types): (Option<String>, Option<u16>, Option<String>)| {
            let result = lua.create_table()?;

            let addr = format!(
                "{}:{}",
                host.unwrap_or_else(|| WS_DISCOVERY_MULTICAST.to_string()),
                port.unwrap_or(WS_DISCOVERY_PORT)
            );

            let socket = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            socket.set_broadcast(true).ok();
            socket.set_read_timeout(Some(Duration::from_secs(5))).ok();

            // Build WS-Discovery Probe message
            let types_to_search = types.unwrap_or_else(|| "".to_string());
            let soap_body = if types_to_search.is_empty() {
                format!(
                    r#"<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action><wsa:MessageID>urn:uuid:{}</wsa:MessageID><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To></soap:Header><soap:Body><wsd:Probe/></soap:Body></soap:Envelope>"#,
                    uuid_v4()
                )
            } else {
                format!(
                    r#"<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action><wsa:MessageID>urn:uuid:{}</wsa:MessageID><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To></soap:Header><soap:Body><wsd:Probe><wsd:Types>{}</wsd:Types></wsd:Probe></soap:Body></soap:Envelope>"#,
                    uuid_v4(),
                    types_to_search
                )
            };

            let probe = soap_body.as_bytes();

            match socket.send_to(probe, &addr) {
                Ok(_) => {
                    let devices = lua.create_table()?;
                    let mut device_count = 0;

                    // Collect responses for a bit
                    let mut response_buf = [0u8; 8192];
                    let deadline = std::time::Instant::now() + Duration::from_secs(3);

                    while std::time::Instant::now() < deadline {
                        socket.set_read_timeout(Some(
                            Duration::from_secs(1)
                        )).ok();

                        match socket.recv_from(&mut response_buf) {
                            Ok((len, src_addr)) => {
                                if len > 0 {
                                    let response_str = String::from_utf8_lossy(&response_buf[..len]);

                                    // Parse the response to extract device info
                                    if let Some(device) = parse_wsdd_response(&response_str, src_addr.to_string()) {
                                        device_count += 1;
                                        let device_table = lua.create_table()?;
                                        device_table.set("address", device.0)?;
                                        device_table.set("types", device.1)?;
                                        device_table.set("metadata_version", device.2)?;
                                        devices.set(device_count, device_table)?;
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }

                    result.set("status", "ok")?;
                    result.set("devices", devices)?;
                    result.set("count", device_count)?;
                }
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                }
            }

            Ok(result)
        })?,
    )?;

    // resolve - Resolve a specific device address
    wsdd.set(
        "resolve",
        lua.create_function(|lua, (host, port, address): (Option<String>, Option<u16>, String)| {
            let result = lua.create_table()?;

            let addr = format!(
                "{}:{}",
                host.unwrap_or_else(|| WS_DISCOVERY_MULTICAST.to_string()),
                port.unwrap_or(WS_DISCOVERY_PORT)
            );

            let socket = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            socket.set_broadcast(true).ok();
            socket.set_read_timeout(Some(Duration::from_secs(3))).ok();

            // WS-Discovery Resolve
            let soap_body = format!(
                r#"<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action><wsa:MessageID>urn:uuid:{}</wsa:MessageID><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:ReplyTo><wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo></soap:Header><soap:Body><wsd:Resolve><wsa:Address>{}</wsa:Address></wsd:Resolve></soap:Body></soap:Envelope>"#,
                uuid_v4(),
                address
            );

            match socket.send_to(soap_body.as_bytes(), &addr) {
                Ok(_) => {
                    let mut response = [0u8; 4096];
                    match socket.recv_from(&mut response) {
                        Ok((len, _)) => {
                            let response_str = String::from_utf8_lossy(&response[..len]);

                            result.set("status", "ok")?;

                            // Try to extract XAddrs from response
                            if let Some(xaddrs) = extract_xaddrs(&response_str) {
                                result.set("xaddrs", xaddrs)?;
                            }

                            if let Some(types) = extract_types(&response_str) {
                                result.set("types", types)?;
                            }
                        }
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
                        }
                    }
                }
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                }
            }

            Ok(result)
        })?,
    )?;

    // Helper class
    let helper = lua.create_table()?;
    helper.set(
        "new",
        lua.create_function(|lua, (host, port): (Option<String>, Option<u16>)| {
            let instance = lua.create_table()?;
            instance.set(
                "host",
                host.unwrap_or_else(|| WS_DISCOVERY_MULTICAST.to_string()),
            )?;
            instance.set("port", port.unwrap_or(WS_DISCOVERY_PORT))?;
            Ok(instance)
        })?,
    )?;

    wsdd.set("Helper", helper)?;

    wsdd.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("wsdd", wsdd)?;
    Ok(())
}

// Simple UUID v4 generator
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:032x}", timestamp)
}

// Parse WS-Discovery ProbeMatches response
fn parse_wsdd_response(response: &str, addr: String) -> Option<(String, String, String)> {
    let types = extract_types(response).unwrap_or_default();
    let xaddrs = extract_xaddrs(response).unwrap_or_default();
    let _metadata_version = extract_metadata_version(response);

    Some((addr, types, xaddrs))
}

fn extract_types(response: &str) -> Option<String> {
    // Look for <wsd:Types> element
    if let Some(start) = response.find("<wsd:Types") {
        if let Some(end_tag) = response[start..].find("</wsd:Types>") {
            let content = &response[start..start + end_tag];
            // Extract content between > and </
            if let Some(gt) = content.find('>') {
                return Some(content[gt + 1..].trim().to_string());
            }
        }
    }
    // Try without namespace
    if let Some(start) = response.find("<Types") {
        if let Some(end_tag) = response[start..].find("</Types>") {
            let content = &response[start..start + end_tag];
            if let Some(gt) = content.find('>') {
                return Some(content[gt + 1..].trim().to_string());
            }
        }
    }
    None
}

fn extract_xaddrs(response: &str) -> Option<String> {
    // Look for <wsd:XAddrs> element
    if let Some(start) = response.find("<wsd:XAddrs") {
        if let Some(end_tag) = response[start..].find("</wsd:XAddrs>") {
            let content = &response[start..start + end_tag];
            if let Some(gt) = content.find('>') {
                return Some(content[gt + 1..].trim().to_string());
            }
        }
    }
    None
}

fn extract_metadata_version(response: &str) -> String {
    if let Some(start) = response.find("<wsd:MetadataVersion") {
        if let Some(end_tag) = response[start..].find("</wsd:MetadataVersion>") {
            let content = &response[start..start + end_tag];
            if let Some(gt) = content.find('>') {
                return content[gt + 1..].trim().to_string();
            }
        }
    }
    "1".to_string()
}
