//! NSE dhcp6 library wrapper
//!
//! DHCPv6 (Dynamic Host Configuration Protocol for IPv6) implementation.
//! Based on Nmap's dhcp6 library concepts.

use mlua::{Lua, Result as LuaResult};
use std::net::UdpSocket;
use std::time::Duration;
use tokio::net::UdpSocket as AsyncUdpSocket;

const DHCPV6_PORT: u16 = 546;
const DHCPV6_SERVER_PORT: u16 = 547;

const DHCPV6_SOLICIT: u8 = 1;
const DHCPV6_ADVERTISE: u8 = 2;
const DHCPV6_REQUEST: u8 = 3;
const DHCPV6_REPLY: u8 = 7;

fn build_dhcp6_message(msg_type: u8, transaction_id: &[u8; 3], options: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(msg_type);
    packet.extend_from_slice(transaction_id);
    packet.extend_from_slice(options);
    packet
}

pub fn register_dhcp6_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let dhcp6 = lua.create_table()?;

    let new_fn =
        lua.create_function(|lua, (host, interface): (Option<String>, Option<String>)| {
            let d = lua.create_table()?;
            d.set("host", host.unwrap_or_else(|| "ff02::1:2".to_string()))?;
            d.set("interface", interface.unwrap_or_default())?;
            d.set("port", DHCPV6_PORT)?;
            d.set("timeout", 5i64)?;
            Ok(d)
        })?;
    dhcp6.set("new", new_fn)?;

    let solicit_fn =
        lua.create_function(|lua, (host, duid): (Option<String>, Option<String>)| {
            let result = lua.create_table()?;

            let target = host.unwrap_or_else(|| "ff02::1:2".to_string());

            let transaction_id: [u8; 3] = [rand::random(), rand::random(), rand::random()];

            let mut options = Vec::new();
            options.extend_from_slice(&[0x01, 0x04, 0x00, 0x01]);

            if let Some(duid) = duid {
                let duid_bytes = duid.as_bytes();
                options.extend_from_slice(&(duid_bytes.len() as u16).to_be_bytes());
                options.extend_from_slice(duid_bytes);
            }

            let packet = build_dhcp6_message(DHCPV6_SOLICIT, &transaction_id, &options);

            match UdpSocket::bind("[::]:546") {
                Ok(socket) => {
                    socket.set_broadcast(true).ok();
                    socket.set_read_timeout(Some(Duration::from_secs(5))).ok();

                    match socket.send_to(&packet, format!("[{}]:{}", target, DHCPV6_SERVER_PORT)) {
                        Ok(_) => {
                            let mut buf = [0u8; 1024];
                            match socket.recv_from(&mut buf) {
                                Ok((n, _)) => {
                                    if n > 0 && buf[0] == DHCPV6_ADVERTISE {
                                        result.set("success", true)?;
                                        result.set(
                                            "transaction_id",
                                            format!(
                                                "{:02x}{:02x}{:02x}",
                                                transaction_id[0],
                                                transaction_id[1],
                                                transaction_id[2]
                                            ),
                                        )?;
                                        result.set("type", "advertise")?;
                                    } else {
                                        result.set("success", true)?;
                                        result.set("type", "solicit_sent")?;
                                    }
                                }
                                Err(e) => {
                                    result.set("success", true)?;
                                    result.set("type", "solicit_sent")?;
                                    result.set("error", format!("No response: {}", e))?;
                                }
                            }
                        }
                        Err(e) => {
                            result.set("success", false)?;
                            result.set("error", format!("Send failed: {}", e))?;
                        }
                    }
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Socket failed: {}", e))?;
                }
            }

            Ok(result)
        })?;
    dhcp6.set("solicit", solicit_fn)?;

    let request_fn = lua.create_function(
        |lua, (host, server_id, duid): (Option<String>, Option<String>, Option<String>)| {
            let result = lua.create_table()?;

            let target = host.unwrap_or_else(|| "ff02::1:2".to_string());

            let transaction_id: [u8; 3] = [rand::random(), rand::random(), rand::random()];

            let mut options = Vec::new();

            if let Some(sid) = server_id {
                let sid_bytes = sid.as_bytes();
                options.extend_from_slice(&[0x02, 0x00]);
                options.extend_from_slice(&(sid_bytes.len() as u16).to_be_bytes());
                options.extend_from_slice(sid_bytes);
            }

            options.extend_from_slice(&[0x01, 0x04, 0x00, 0x01]);

            if let Some(duid) = duid {
                let duid_bytes = duid.as_bytes();
                options.extend_from_slice(&(duid_bytes.len() as u16).to_be_bytes());
                options.extend_from_slice(duid_bytes);
            }

            let packet = build_dhcp6_message(DHCPV6_REQUEST, &transaction_id, &options);

            match UdpSocket::bind("[::]:546") {
                Ok(socket) => {
                    socket.set_broadcast(true).ok();
                    socket.set_read_timeout(Some(Duration::from_secs(5))).ok();

                    match socket.send_to(&packet, format!("[{}]:{}", target, DHCPV6_SERVER_PORT)) {
                        Ok(_) => {
                            let mut buf = [0u8; 1024];
                            match socket.recv_from(&mut buf) {
                                Ok((n, _)) => {
                                    if n > 0 && buf[0] == DHCPV6_REPLY {
                                        result.set("success", true)?;
                                        result.set("type", "reply")?;
                                    } else {
                                        result.set("success", true)?;
                                        result.set("type", "request_sent")?;
                                    }
                                }
                                Err(e) => {
                                    result.set("success", true)?;
                                    result.set("type", "request_sent")?;
                                    result.set("error", format!("No response: {}", e))?;
                                }
                            }
                        }
                        Err(e) => {
                            result.set("success", false)?;
                            result.set("error", format!("Send failed: {}", e))?;
                        }
                    }
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Socket failed: {}", e))?;
                }
            }

            Ok(result)
        },
    )?;
    dhcp6.set("request", request_fn)?;

    let discover_fn = lua.create_function(|lua, host: Option<String>| {
        let result = lua.create_table()?;
        result.set("type", "solicit")?;
        result.set("target", host.unwrap_or_else(|| "ff02::1:2".to_string()))?;
        result.set("port", DHCPV6_SERVER_PORT)?;
        Ok(result)
    })?;
    dhcp6.set("discover", discover_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    dhcp6.set("version", version_fn)?;

    let async_solicit_fn =
        lua.create_function(|lua, (host, duid): (Option<String>, Option<String>)| {
            let runtime = tokio::runtime::Handle::current();
            let target = host.unwrap_or_else(|| "ff02::1:2".to_string());

            runtime.block_on(async {
                let result = lua.create_table()?;

                let transaction_id: [u8; 3] = [rand::random(), rand::random(), rand::random()];

                let mut options = Vec::new();
                options.extend_from_slice(&[0x01, 0x04, 0x00, 0x01]);

                if let Some(duid) = duid {
                    let duid_bytes = duid.as_bytes();
                    options.extend_from_slice(&(duid_bytes.len() as u16).to_be_bytes());
                    options.extend_from_slice(duid_bytes);
                }

                let packet = build_dhcp6_message(DHCPV6_SOLICIT, &transaction_id, &options);

                match AsyncUdpSocket::bind("[::]:546").await {
                    Ok(socket) => {
                        match socket
                            .send_to(&packet, format!("[{}]:{}", target, DHCPV6_SERVER_PORT))
                            .await
                        {
                            Ok(_) => {
                                let mut buf = [0u8; 1024];
                                match tokio::time::timeout(
                                    Duration::from_secs(5),
                                    socket.recv_from(&mut buf),
                                )
                                .await
                                {
                                    Ok(Ok((n, _))) => {
                                        if n > 0 && buf[0] == DHCPV6_ADVERTISE {
                                            result.set("success", true)?;
                                            result.set(
                                                "transaction_id",
                                                format!(
                                                    "{:02x}{:02x}{:02x}",
                                                    transaction_id[0],
                                                    transaction_id[1],
                                                    transaction_id[2]
                                                ),
                                            )?;
                                            result.set("type", "advertise")?;
                                        } else {
                                            result.set("success", true)?;
                                            result.set("type", "solicit_sent")?;
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        result.set("success", true)?;
                                        result.set("type", "solicit_sent")?;
                                        result.set("error", format!("No response: {}", e))?;
                                    }
                                    Err(_) => {
                                        result.set("success", true)?;
                                        result.set("type", "solicit_sent")?;
                                        result.set("error", "Timeout waiting for response")?;
                                    }
                                }
                            }
                            Err(e) => {
                                result.set("success", false)?;
                                result.set("error", format!("Send failed: {}", e))?;
                            }
                        }
                    }
                    Err(e) => {
                        result.set("success", false)?;
                        result.set("error", format!("Socket failed: {}", e))?;
                    }
                }

                Ok(result)
            })
        })?;
    dhcp6.set("solicit_async", async_solicit_fn)?;

    let async_request_fn = lua.create_function(
        |lua, (host, server_id, duid): (Option<String>, Option<String>, Option<String>)| {
            let runtime = tokio::runtime::Handle::current();
            let target = host.unwrap_or_else(|| "ff02::1:2".to_string());

            runtime.block_on(async {
                let result = lua.create_table()?;

                let transaction_id: [u8; 3] = [rand::random(), rand::random(), rand::random()];

                let mut options = Vec::new();

                if let Some(sid) = server_id {
                    let sid_bytes = sid.as_bytes();
                    options.extend_from_slice(&[0x02, 0x00]);
                    options.extend_from_slice(&(sid_bytes.len() as u16).to_be_bytes());
                    options.extend_from_slice(sid_bytes);
                }

                options.extend_from_slice(&[0x01, 0x04, 0x00, 0x01]);

                if let Some(duid) = duid {
                    let duid_bytes = duid.as_bytes();
                    options.extend_from_slice(&(duid_bytes.len() as u16).to_be_bytes());
                    options.extend_from_slice(duid_bytes);
                }

                let packet = build_dhcp6_message(DHCPV6_REQUEST, &transaction_id, &options);

                match AsyncUdpSocket::bind("[::]:546").await {
                    Ok(socket) => {
                        match socket
                            .send_to(&packet, format!("[{}]:{}", target, DHCPV6_SERVER_PORT))
                            .await
                        {
                            Ok(_) => {
                                let mut buf = [0u8; 1024];
                                match tokio::time::timeout(
                                    Duration::from_secs(5),
                                    socket.recv_from(&mut buf),
                                )
                                .await
                                {
                                    Ok(Ok((n, _))) => {
                                        if n > 0 && buf[0] == DHCPV6_REPLY {
                                            result.set("success", true)?;
                                            result.set("type", "reply")?;
                                        } else {
                                            result.set("success", true)?;
                                            result.set("type", "request_sent")?;
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        result.set("success", true)?;
                                        result.set("type", "request_sent")?;
                                        result.set("error", format!("No response: {}", e))?;
                                    }
                                    Err(_) => {
                                        result.set("success", true)?;
                                        result.set("type", "request_sent")?;
                                        result.set("error", "Timeout waiting for response")?;
                                    }
                                }
                            }
                            Err(e) => {
                                result.set("success", false)?;
                                result.set("error", format!("Send failed: {}", e))?;
                            }
                        }
                    }
                    Err(e) => {
                        result.set("success", false)?;
                        result.set("error", format!("Socket failed: {}", e))?;
                    }
                }

                Ok(result)
            })
        },
    )?;
    dhcp6.set("request_async", async_request_fn)?;

    globals.set("dhcp6", dhcp6)?;
    Ok(())
}
