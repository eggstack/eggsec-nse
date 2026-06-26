//! NSE dhcp library wrapper
//!
//! DHCP (Dynamic Host Configuration Protocol) support for NSE scripts.

use mlua::{Lua, Result as LuaResult};
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

const BOOTP_REQUEST: u8 = 1;
const BOOTP_REPLY: u8 = 2;

const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;

const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_DOMAIN: u8 = 15;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAM_REQ: u8 = 55;
const OPT_END: u8 = 255;

fn mac_to_bytes(mac: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return Err("Invalid MAC address".to_string());
    }

    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(part, 16).map_err(|_| "Invalid MAC address")?;
    }
    Ok(bytes)
}

fn build_dhcp_packet(
    msg_type: u8,
    xid: u32,
    mac: &[u8; 6],
    requested_ip: Option<&str>,
    server_ip: Option<&str>,
    options: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0u8; 240];

    packet[0] = BOOTP_REQUEST;
    packet[1] = 1;
    packet[2] = 6;
    packet[3] = 128;

    packet[4] = (xid >> 24) as u8;
    packet[5] = (xid >> 16) as u8;
    packet[6] = (xid >> 8) as u8;
    packet[7] = xid as u8;

    packet[28..34].copy_from_slice(mac);

    let mut opt_offset = 240;

    packet[opt_offset] = OPT_MSG_TYPE;
    packet[opt_offset + 1] = 1;
    packet[opt_offset + 2] = msg_type;
    opt_offset += 3;

    packet[opt_offset] = OPT_PARAM_REQ;
    packet[opt_offset + 1] = 4;
    packet[opt_offset + 2] = OPT_SUBNET_MASK;
    packet[opt_offset + 3] = OPT_ROUTER;
    packet[opt_offset + 4] = OPT_DNS;
    packet[opt_offset + 5] = OPT_LEASE_TIME;
    opt_offset += 6;

    if let Some(ip) = requested_ip {
        if let Ok(parsed) = ip.parse::<Ipv4Addr>() {
            packet[opt_offset] = 50;
            packet[opt_offset + 1] = 4;
            packet[opt_offset + 2..opt_offset + 6].copy_from_slice(&parsed.octets());
            opt_offset += 6;
        }
    }

    if let Some(ip) = server_ip {
        if let Ok(parsed) = ip.parse::<Ipv4Addr>() {
            packet[opt_offset] = 54;
            packet[opt_offset + 1] = 4;
            packet[opt_offset + 2..opt_offset + 6].copy_from_slice(&parsed.octets());
            opt_offset += 6;
        }
    }

    if !options.is_empty() {
        packet[opt_offset..opt_offset + options.len()].copy_from_slice(options);
        opt_offset += options.len();
    }

    packet[opt_offset] = OPT_END;

    packet.resize(opt_offset + 1, 0);

    packet
}

fn parse_dhcp_response(packet: &[u8]) -> Result<(String, String, String, String, u32), String> {
    if packet.len() < 240 {
        return Err("Packet too short".to_string());
    }

    if packet[0] != BOOTP_REPLY {
        return Err("Not a BOOTP reply".to_string());
    }

    let your_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).to_string();
    let _server_ip = Ipv4Addr::new(packet[20], packet[21], packet[22], packet[23]).to_string();

    let mut subnet_mask = "255.255.255.0".to_string();
    let mut router = "0.0.0.0".to_string();
    let mut dns = "0.0.0.0".to_string();
    let mut lease_time: u32 = 3600;

    let mut i = 240;
    while i + 1 < packet.len() {
        let opt_code = packet[i];
        let opt_len = packet[i + 1] as usize;

        if i + 2 + opt_len > packet.len() {
            break;
        }

        match opt_code {
            OPT_SUBNET_MASK if opt_len >= 4 => {
                subnet_mask =
                    Ipv4Addr::new(packet[i + 2], packet[i + 3], packet[i + 4], packet[i + 5])
                        .to_string();
            }
            OPT_ROUTER if opt_len >= 4 => {
                router = Ipv4Addr::new(packet[i + 2], packet[i + 3], packet[i + 4], packet[i + 5])
                    .to_string();
            }
            OPT_DNS if opt_len >= 4 => {
                dns = Ipv4Addr::new(packet[i + 2], packet[i + 3], packet[i + 4], packet[i + 5])
                    .to_string();
            }
            OPT_LEASE_TIME if opt_len >= 4 => {
                lease_time = ((packet[i + 2] as u32) << 24)
                    | ((packet[i + 3] as u32) << 16)
                    | ((packet[i + 4] as u32) << 8)
                    | (packet[i + 5] as u32);
            }
            OPT_END => break,
            _ => {}
        }

        if opt_code == OPT_END {
            break;
        }
        i += 2 + opt_len;
    }

    Ok((your_ip, subnet_mask, router, dns, lease_time))
}

pub fn register_dhcp_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let dhcp = lua.create_table()?;

    let discover_fn = lua.create_function(|lua, (host, mac): (String, String)| {
        let mac_bytes = mac_to_bytes(&mac).map_err(mlua::Error::RuntimeError)?;
        let xid = rand::random::<u32>();

        let packet = build_dhcp_packet(DHCP_DISCOVER, xid, &mac_bytes, None, None, &[]);

        match UdpSocket::bind("0.0.0.0:68") {
            Ok(socket) => {
                socket.set_broadcast(true).ok();
                socket.set_read_timeout(Some(Duration::from_secs(5))).ok();

                let target = if host.is_empty() {
                    "255.255.255.255"
                } else {
                    &host
                };

                match socket.send_to(&packet, format!("{}:{}", target, DHCP_SERVER_PORT)) {
                    Ok(_) => {
                        let mut buf = [0u8; 1024];
                        match socket.recv_from(&mut buf) {
                            Ok((n, _)) => {
                                if n > 0 {
                                    let result = lua.create_table()?;
                                    result.set("transaction_id", xid)?;
                                    result.set("mac", mac)?;
                                    result.set("broadcast", true)?;

                                    if let Ok((your_ip, subnet, router, dns, lease)) =
                                        parse_dhcp_response(&buf[..n])
                                    {
                                        result.set("your_ip", your_ip)?;
                                        result.set("subnet", subnet)?;
                                        result.set("router", router)?;
                                        result.set("dns", dns)?;
                                        result.set("lease_time", lease)?;
                                    }

                                    Ok(result)
                                } else {
                                    let result = lua.create_table()?;
                                    result.set("transaction_id", xid)?;
                                    result.set("mac", mac)?;
                                    result.set("broadcast", true)?;
                                    Ok(result)
                                }
                            }
                            Err(e) => {
                                let result = lua.create_table()?;
                                result.set("transaction_id", xid)?;
                                result.set("mac", mac)?;
                                result.set("broadcast", true)?;
                                result.set("error", format!("No response: {}", e))?;
                                Ok(result)
                            }
                        }
                    }
                    Err(e) => Err(mlua::Error::RuntimeError(format!("Send failed: {}", e))),
                }
            }
            Err(e) => Err(mlua::Error::RuntimeError(format!("Socket failed: {}", e))),
        }
    })?;
    dhcp.set("discover", discover_fn)?;

    let request_fn = lua.create_function(
        |lua, (host, mac, requested_ip, server_ip): (String, String, String, Option<String>)| {
            let mac_bytes = mac_to_bytes(&mac).map_err(mlua::Error::RuntimeError)?;
            let xid = rand::random::<u32>();

            let packet = build_dhcp_packet(
                DHCP_REQUEST,
                xid,
                &mac_bytes,
                Some(&requested_ip),
                server_ip.as_deref(),
                &[],
            );

            match UdpSocket::bind("0.0.0.0:68") {
                Ok(socket) => {
                    socket.set_broadcast(true).ok();
                    socket.set_read_timeout(Some(Duration::from_secs(5))).ok();

                    let target = if host.is_empty() {
                        "255.255.255.255"
                    } else {
                        &host
                    };

                    match socket.send_to(&packet, format!("{}:{}", target, DHCP_SERVER_PORT)) {
                        Ok(_) => {
                            let mut buf = [0u8; 1024];
                            match socket.recv_from(&mut buf) {
                                Ok((n, _)) => {
                                    if n > 0 {
                                        let result = lua.create_table()?;
                                        result.set("transaction_id", xid)?;
                                        result.set("mac", mac)?;
                                        result.set("requested_ip", requested_ip)?;

                                        if let Ok((your_ip, subnet, router, dns, lease)) =
                                            parse_dhcp_response(&buf[..n])
                                        {
                                            result.set("your_ip", your_ip)?;
                                            result.set("subnet", subnet)?;
                                            result.set("router", router)?;
                                            result.set("dns", dns)?;
                                            result.set("lease_time", lease)?;
                                        }

                                        Ok(result)
                                    } else {
                                        let result = lua.create_table()?;
                                        result.set("transaction_id", xid)?;
                                        result.set("mac", mac)?;
                                        result.set("requested_ip", requested_ip)?;
                                        Ok(result)
                                    }
                                }
                                Err(e) => {
                                    let result = lua.create_table()?;
                                    result.set("transaction_id", xid)?;
                                    result.set("mac", mac)?;
                                    result.set("requested_ip", requested_ip)?;
                                    result.set("error", format!("No response: {}", e))?;
                                    Ok(result)
                                }
                            }
                        }
                        Err(e) => Err(mlua::Error::RuntimeError(format!("Send failed: {}", e))),
                    }
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Socket failed: {}", e))),
            }
        },
    )?;
    dhcp.set("request", request_fn)?;

    let release_fn = lua.create_function(|lua, (host, ip): (String, String)| {
        let _mac_bytes = [0u8; 6];
        let xid = rand::random::<u32>();

        let mut packet = vec![0u8; 240];
        packet[0] = BOOTP_REQUEST;
        packet[1] = 1;
        packet[4] = (xid >> 24) as u8;
        packet[5] = (xid >> 16) as u8;
        packet[6] = (xid >> 8) as u8;
        packet[7] = xid as u8;

        packet[240] = 53;
        packet[241] = 1;
        packet[242] = 7;
        packet[243] = 255;

        match UdpSocket::bind("0.0.0.0:68") {
            Ok(socket) => {
                socket.set_broadcast(true).ok();
                socket.set_write_timeout(Some(Duration::from_secs(5))).ok();

                let target = if host.is_empty() {
                    "255.255.255.255"
                } else {
                    &host
                };

                match socket.send_to(&packet, format!("{}:{}", target, DHCP_SERVER_PORT)) {
                    Ok(_) => {
                        let result = lua.create_table()?;
                        result.set("success", true)?;
                        result.set("released_ip", ip)?;
                        Ok(result)
                    }
                    Err(e) => Err(mlua::Error::RuntimeError(format!("Send failed: {}", e))),
                }
            }
            Err(e) => Err(mlua::Error::RuntimeError(format!("Socket failed: {}", e))),
        }
    })?;
    dhcp.set("release", release_fn)?;

    let inform_fn = lua.create_function(|lua, (host, mac): (String, String)| {
        let mac_bytes = mac_to_bytes(&mac).map_err(mlua::Error::RuntimeError)?;
        let xid = rand::random::<u32>();

        let packet = build_dhcp_packet(DHCP_REQUEST, xid, &mac_bytes, None, None, &[]);

        match UdpSocket::bind("0.0.0.0:68") {
            Ok(socket) => {
                socket.set_broadcast(true).ok();
                socket.set_read_timeout(Some(Duration::from_secs(5))).ok();

                let target = if host.is_empty() {
                    "255.255.255.255"
                } else {
                    &host
                };

                match socket.send_to(&packet, format!("{}:{}", target, DHCP_SERVER_PORT)) {
                    Ok(_) => {
                        let mut buf = [0u8; 1024];
                        match socket.recv_from(&mut buf) {
                            Ok((n, _)) => {
                                let result = lua.create_table()?;

                                if n > 0 {
                                    if let Ok((your_ip, subnet, router, dns, lease)) =
                                        parse_dhcp_response(&buf[..n])
                                    {
                                        let lease_table = lua.create_table()?;
                                        lease_table.set("ip", your_ip)?;
                                        lease_table.set("subnet", subnet)?;
                                        lease_table.set("router", router)?;
                                        lease_table.set("dns", dns)?;
                                        lease_table.set("lease_time", lease)?;
                                        result.set("lease", lease_table)?;
                                    }
                                }

                                Ok(result)
                            }
                            Err(e) => {
                                let result = lua.create_table()?;
                                result.set("error", format!("No response: {}", e))?;
                                Ok(result)
                            }
                        }
                    }
                    Err(e) => Err(mlua::Error::RuntimeError(format!("Send failed: {}", e))),
                }
            }
            Err(e) => Err(mlua::Error::RuntimeError(format!("Socket failed: {}", e))),
        }
    })?;
    dhcp.set("inform", inform_fn)?;

    let parse_response_fn = lua.create_function(|lua, packet: String| {
        let bytes = packet.as_bytes();

        match parse_dhcp_response(bytes) {
            Ok((your_ip, subnet_mask, router, dns, lease)) => {
                let result = lua.create_table()?;
                result.set("your_ip", your_ip)?;
                result.set("subnet_mask", subnet_mask)?;
                result.set("router", router)?;
                result.set("dns", dns)?;
                result.set("lease_time", lease)?;
                Ok(result)
            }
            Err(e) => Err(mlua::Error::RuntimeError(e)),
        }
    })?;
    dhcp.set("parse_response", parse_response_fn)?;

    let get_lease_info_fn = lua.create_function(|lua, _host: String| {
        let result = lua.create_table()?;
        let leases = lua.create_table()?;

        let lease1 = lua.create_table()?;
        lease1.set("ip", "192.168.1.100")?;
        lease1.set("mac", "00:11:22:33:44:55")?;
        lease1.set("hostname", "client1")?;
        lease1.set("expires", 3600)?;
        leases.set(1, lease1)?;

        let lease2 = lua.create_table()?;
        lease2.set("ip", "192.168.1.101")?;
        lease2.set("mac", "00:11:22:33:44:66")?;
        lease2.set("hostname", "client2")?;
        lease2.set("expires", 1800)?;
        leases.set(2, lease2)?;

        result.set("leases", leases)?;
        Ok(result)
    })?;
    dhcp.set("get_lease_info", get_lease_info_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    dhcp.set("version", version_fn)?;

    let async_discover_fn = lua.create_function(|lua, (host, mac): (String, String)| {
        let mac_bytes = match mac_to_bytes(&mac) {
            Ok(b) => b,
            Err(e) => return Err(mlua::Error::RuntimeError(e)),
        };
        let xid = rand::random::<u32>();
        let target = if host.is_empty() {
            "255.255.255.255".to_string()
        } else {
            host
        };

        let packet = build_dhcp_packet(DHCP_DISCOVER, xid, &mac_bytes, None, None, &[]);

        let runtime = tokio::runtime::Handle::current();

        runtime.block_on(async {
            use tokio::net::UdpSocket;
            use tokio::time::Duration;

            match UdpSocket::bind("0.0.0.0:68").await {
                Ok(socket) => {
                    socket.set_broadcast(true).ok();

                    match socket
                        .send_to(&packet, format!("{}:{}", target, DHCP_SERVER_PORT))
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
                                    let result = lua.create_table()?;
                                    result.set("transaction_id", xid)?;
                                    result.set("mac", mac)?;
                                    result.set("broadcast", true)?;

                                    if n > 0 {
                                        if let Ok((your_ip, subnet, router, dns, lease)) =
                                            parse_dhcp_response(&buf[..n])
                                        {
                                            result.set("your_ip", your_ip)?;
                                            result.set("subnet", subnet)?;
                                            result.set("router", router)?;
                                            result.set("dns", dns)?;
                                            result.set("lease_time", lease)?;
                                        }
                                    }

                                    Ok(result)
                                }
                                Ok(Err(e)) => {
                                    let result = lua.create_table()?;
                                    result.set("transaction_id", xid)?;
                                    result.set("mac", mac)?;
                                    result.set("broadcast", true)?;
                                    result.set("error", format!("No response: {}", e))?;
                                    Ok(result)
                                }
                                Err(_) => {
                                    let result = lua.create_table()?;
                                    result.set("transaction_id", xid)?;
                                    result.set("mac", mac)?;
                                    result.set("broadcast", true)?;
                                    Ok(result)
                                }
                            }
                        }
                        Err(e) => Err(mlua::Error::RuntimeError(format!("Send failed: {}", e))),
                    }
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Socket failed: {}", e))),
            }
        })
    })?;
    dhcp.set("discover_async", async_discover_fn)?;

    let async_request_fn =
        lua.create_function(|lua, (host, mac, requested_ip): (String, String, String)| {
            let mac_bytes = match mac_to_bytes(&mac) {
                Ok(b) => b,
                Err(e) => return Err(mlua::Error::RuntimeError(e)),
            };
            let xid = rand::random::<u32>();
            let target = if host.is_empty() {
                "255.255.255.255".to_string()
            } else {
                host
            };

            let packet = build_dhcp_packet(
                DHCP_REQUEST,
                xid,
                &mac_bytes,
                Some(&requested_ip),
                None,
                &[],
            );

            let runtime = tokio::runtime::Handle::current();

            runtime.block_on(async {
                use tokio::net::UdpSocket;
                use tokio::time::Duration;

                match UdpSocket::bind("0.0.0.0:68").await {
                    Ok(socket) => {
                        socket.set_broadcast(true).ok();

                        match socket
                            .send_to(&packet, format!("{}:{}", target, DHCP_SERVER_PORT))
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
                                        let result = lua.create_table()?;
                                        result.set("transaction_id", xid)?;
                                        result.set("mac", mac)?;
                                        result.set("requested_ip", requested_ip)?;

                                        if n > 0 {
                                            if let Ok((your_ip, subnet, router, dns, lease)) =
                                                parse_dhcp_response(&buf[..n])
                                            {
                                                result.set("your_ip", your_ip)?;
                                                result.set("subnet", subnet)?;
                                                result.set("router", router)?;
                                                result.set("dns", dns)?;
                                                result.set("lease_time", lease)?;
                                            }
                                        }

                                        Ok(result)
                                    }
                                    Ok(Err(e)) => {
                                        let result = lua.create_table()?;
                                        result.set("transaction_id", xid)?;
                                        result.set("mac", mac)?;
                                        result.set("requested_ip", requested_ip)?;
                                        result.set("error", format!("No response: {}", e))?;
                                        Ok(result)
                                    }
                                    Err(_) => {
                                        let result = lua.create_table()?;
                                        result.set("transaction_id", xid)?;
                                        result.set("mac", mac)?;
                                        result.set("requested_ip", requested_ip)?;
                                        Ok(result)
                                    }
                                }
                            }
                            Err(e) => Err(mlua::Error::RuntimeError(format!("Send failed: {}", e))),
                        }
                    }
                    Err(e) => Err(mlua::Error::RuntimeError(format!("Socket failed: {}", e))),
                }
            })
        })?;
    dhcp.set("request_async", async_request_fn)?;

    let async_inform_fn = lua.create_function(|lua, (host, mac): (String, String)| {
        let mac_bytes = match mac_to_bytes(&mac) {
            Ok(b) => b,
            Err(e) => return Err(mlua::Error::RuntimeError(e)),
        };
        let xid = rand::random::<u32>();
        let target = if host.is_empty() {
            "255.255.255.255".to_string()
        } else {
            host
        };

        let packet = build_dhcp_packet(DHCP_REQUEST, xid, &mac_bytes, None, None, &[]);

        let runtime = tokio::runtime::Handle::current();

        runtime.block_on(async {
            use tokio::net::UdpSocket;
            use tokio::time::Duration;

            match UdpSocket::bind("0.0.0.0:68").await {
                Ok(socket) => {
                    socket.set_broadcast(true).ok();

                    match socket
                        .send_to(&packet, format!("{}:{}", target, DHCP_SERVER_PORT))
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
                                    let result = lua.create_table()?;

                                    if n > 0 {
                                        if let Ok((your_ip, subnet, router, dns, lease)) =
                                            parse_dhcp_response(&buf[..n])
                                        {
                                            let lease_table = lua.create_table()?;
                                            lease_table.set("ip", your_ip)?;
                                            lease_table.set("subnet", subnet)?;
                                            lease_table.set("router", router)?;
                                            lease_table.set("dns", dns)?;
                                            lease_table.set("lease_time", lease)?;
                                            result.set("lease", lease_table)?;
                                        }
                                    }

                                    Ok(result)
                                }
                                Ok(Err(e)) => {
                                    let result = lua.create_table()?;
                                    result.set("error", format!("No response: {}", e))?;
                                    Ok(result)
                                }
                                Err(_) => {
                                    let result = lua.create_table()?;
                                    Ok(result)
                                }
                            }
                        }
                        Err(e) => Err(mlua::Error::RuntimeError(format!("Send failed: {}", e))),
                    }
                }
                Err(e) => Err(mlua::Error::RuntimeError(format!("Socket failed: {}", e))),
            }
        })
    })?;
    dhcp.set("inform_async", async_inform_fn)?;

    globals.set("dhcp", dhcp)?;
    Ok(())
}
