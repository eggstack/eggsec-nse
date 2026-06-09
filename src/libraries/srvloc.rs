//! NSE srvloc library wrapper
//!
//! SLP (Service Location Protocol) support.
//! Based on Nmap's srvloc library.

use mlua::{Lua, Result as LuaResult};
use std::net::UdpSocket;
use std::time::Duration;

const SLP_PORT: u16 = 427;
const SLP_MULTICAST: &str = "239.255.255.253";

const SLP_MSG_TYPE_SRVRQST: u8 = 1;
const SLP_MSG_TYPE_SRVRPLY: u8 = 2;
const SLP_MSG_TYPE_DAADVERT: u8 = 7;
const SLP_MSG_TYPE_SAADVERT: u8 = 6;
const SLP_MSG_TYPE_ATTRRQST: u8 = 8;
const SLP_MSG_TYPE_ATTRRPLY: u8 = 9;

pub fn register_srvloc_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let srvloc = lua.create_table()?;

    // Helper function to create SLP message header
    fn create_slp_header(msg_type: u8, flags: u16, xid: u16) -> Vec<u8> {
        let mut header = Vec::new();
        // Version (1 byte)
        header.push(2);
        // Message type (1 byte)
        header.push(msg_type);
        // Length (3 bytes) - will be updated
        header.extend_from_slice(&[0x00, 0x00, 0x00]);
        // Flags (2 bytes)
        header.extend_from_slice(&flags.to_be_bytes());
        // Transaction ID (2 bytes)
        header.extend_from_slice(&xid.to_be_bytes());
        // Reserved (2 bytes)
        header.extend_from_slice(&[0x00, 0x00]);
        header
    }

    // daemon_status - Check if SLP Directory Agent is available
    srvloc.set(
        "daemon_status",
        lua.create_function(|lua, (host, port): (Option<String>, Option<u16>)| {
            let result = lua.create_table()?;

            let addr = format!(
                "{}:{}",
                host.unwrap_or_else(|| SLP_MULTICAST.to_string()),
                port.unwrap_or(SLP_PORT)
            );

            let socket = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            socket.set_read_timeout(Some(Duration::from_secs(3))).ok();

            // SLP DAAdvert message
            let mut request = create_slp_header(SLP_MSG_TYPE_DAADVERT, 0, 1);
            // Function ID (4 bytes)
            request.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            // Language tag length + tag
            request.extend_from_slice(&[0x05, 0x65, 0x6e, 0x00]); // "en" + null

            match socket.send_to(&request, &addr) {
                Ok(_) => {
                    let mut response = [0u8; 2048];
                    match socket.recv_from(&mut response) {
                        Ok((len, _)) => {
                            if len > 0 {
                                let msg_type = response[1];
                                if msg_type == SLP_MSG_TYPE_DAADVERT {
                                    result.set("status", "ok")?;
                                    result.set("da", true)?;
                                    result.set("type", "DA")?;
                                } else {
                                    result.set("status", "ok")?;
                                    result.set("da", false)?;
                                }
                            } else {
                                result.set("status", "timeout")?;
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

    // find_services - Discover services using SLP
    srvloc.set(
        "find_services",
        lua.create_function(
            |lua, (host, port, service_type): (Option<String>, Option<u16>, String)| {
                let result = lua.create_table()?;

                let addr = format!(
                    "{}:{}",
                    host.unwrap_or_else(|| SLP_MULTICAST.to_string()),
                    port.unwrap_or(SLP_PORT)
                );

                let socket = match UdpSocket::bind("0.0.0.0:0") {
                    Ok(s) => s,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e.to_string())?;
                        return Ok(result);
                    }
                };

                socket.set_read_timeout(Some(Duration::from_secs(5))).ok();

                // SLP Service Request
                let mut request = create_slp_header(SLP_MSG_TYPE_SRVRQST, 0, 100);

                // Prelist size (2 bytes) - 0
                request.extend_from_slice(&[0x00, 0x00]);

                // Service URL
                let service_url = format!("{}\0", service_type);
                let url_len = (service_url.len() as u16).to_be_bytes();
                request.extend_from_slice(&url_len);
                request.extend_from_slice(service_url.as_bytes());

                // Scope list
                request.extend_from_slice(&[0x00, 0x00]); // "default" scope

                // Predicate - none
                request.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

                // Language tag
                request.extend_from_slice(&[0x05, 0x65, 0x6e, 0x00]); // "en"

                match socket.send_to(&request, &addr) {
                    Ok(_) => {
                        let mut response = [0u8; 4096];
                        match socket.recv_from(&mut response) {
                            Ok((len, _)) => {
                                if len > 0 {
                                    result.set("status", "ok")?;

                                    let services = lua.create_table()?;
                                    let msg_type = response[1];

                                    if msg_type == SLP_MSG_TYPE_SRVRPLY {
                                        // Parse service URLs from response
                                        // Simplified parsing - in full impl would parse properly
                                        services.set(1, service_type)?;
                                        result.set("services", services)?;
                                        result.set("count", 1)?;
                                    } else {
                                        result.set("services", services)?;
                                        result.set("count", 0)?;
                                    }
                                } else {
                                    result.set("status", "timeout")?;
                                    result.set("services", lua.create_table()?)?;
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
            },
        )?,
    )?;

    // parse_service_url - Parse SLP service URL
    srvloc.set(
        "parse_service_url",
        lua.create_function(|lua, url: String| {
            let result = lua.create_table()?;

            // Basic URL parsing for SLP URLs
            // Format: service:service-type://[host[:port]]/[path]
            if let Some(rest) = url.strip_prefix("service:") {
                if let Some(colon_pos) = rest.find("://") {
                    let service_type = &rest[..colon_pos];
                    result.set("service_type", service_type)?;

                    let after_proto = &rest[colon_pos + 3..];
                    if let Some(slash_pos) = after_proto.find('/') {
                        let host_part = &after_proto[..slash_pos];
                        let path = &after_proto[slash_pos + 1..];

                        if let Some(colon_pos) = host_part.find(':') {
                            result.set("host", &host_part[..colon_pos])?;
                            if let Ok(port) = host_part[colon_pos + 1..].parse::<u16>() {
                                result.set("port", port)?;
                            }
                        } else {
                            result.set("host", host_part)?;
                        }
                        result.set("path", path)?;
                    } else {
                        result.set("host", after_proto)?;
                    }
                }
                result.set("original", url)?;
            } else {
                result.set("error", "Invalid SLP URL format")?;
            }

            Ok(result)
        })?,
    )?;

    // Helper class for SLP operations
    let helper = lua.create_table()?;

    helper.set(
        "new",
        lua.create_function(|lua, (host, port): (Option<String>, Option<u16>)| {
            let instance = lua.create_table()?;
            instance.set(
                "host",
                host.unwrap_or_else(|| "239.255.255.253".to_string()),
            )?;
            instance.set("port", port.unwrap_or(SLP_PORT))?;
            Ok(instance)
        })?,
    )?;

    srvloc.set("Helper", helper)?;

    srvloc.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("srvloc", srvloc)?;
    Ok(())
}
