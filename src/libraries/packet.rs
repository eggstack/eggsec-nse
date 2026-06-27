//! NSE packet library wrapper
//!
//! Facilities for manipulating raw packets compatible with NSE.

use mlua::{Lua, Result as LuaResult};

use super::helpers::parse_hex_pairs;

pub fn register_packet_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let packet = lua.create_table()?;

    packet.set(
        "Frame",
        lua.create_function(
            |_lua,
             (mac_dst, mac_src, ether_type, payload): (
                Option<String>,
                Option<String>,
                Option<u16>,
                Option<String>,
            )| {
                let mut frame = Vec::new();

                let dst = mac_dst.unwrap_or_else(|| "000000000000".to_string());
                let src = mac_src.unwrap_or_else(|| "000000000000".to_string());
                let etype = ether_type.unwrap_or(0x0800);

                frame.extend(parse_hex_pairs(&dst));
                frame.extend(parse_hex_pairs(&src));

                frame.push((etype >> 8) as u8);
                frame.push(etype as u8);

                if let Some(p) = payload {
                    frame.extend_from_slice(p.as_bytes());
                }

                Ok(String::from_utf8_lossy(&frame).to_string())
            },
        )?,
    )?;

    packet.set(
        "in_cksum",
        lua.create_function(|_lua, data: String| {
            let bytes = data.as_bytes();
            let mut sum: u32 = 0;

            for i in (0..bytes.len()).step_by(2) {
                if i + 1 < bytes.len() {
                    sum += ((bytes[i] as u32) << 8) | (bytes[i + 1] as u32);
                } else {
                    sum += (bytes[i] as u32) << 8;
                }
            }

            while sum >> 16 != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            let checksum = !sum as u16;
            Ok(checksum as i32)
        })?,
    )?;

    packet.set(
        "mactobin",
        lua.create_function(|_lua, mac: String| {
            let result = parse_hex_pairs(&mac);
            Ok(String::from_utf8_lossy(&result).to_string())
        })?,
    )?;

    packet.set(
        "new",
        lua.create_function(|lua, (data, _force): (Option<String>, Option<bool>)| {
            let result = lua.create_table()?;
            if let Some(ref d) = data {
                result.set("data", d.clone())?;
                result.set("length", d.len())?;
            } else {
                result.set("length", 0)?;
            }
            Ok(result)
        })?,
    )?;

    packet.set(
        "build_ip_packet",
        lua.create_function(
            |_lua, (src, dst, payload, ttl): (String, String, Option<String>, Option<u8>)| {
                let mut packet = Vec::new();

                let version_ihl = 0x45; // IPv4, 20 byte header
                let tos = 0;
                let total_len = 20 + payload.as_ref().map(|p| p.len()).unwrap_or(0);
                let id = rand::random::<u16>();
                let flags_fragment = 0;
                let ttl = ttl.unwrap_or(64);
                let proto = 6; // TCP by default
                let checksum = 0;

                packet.push(version_ihl);
                packet.push(tos);
                packet.push((total_len >> 8) as u8);
                packet.push(total_len as u8);
                packet.push((id >> 8) as u8);
                packet.push(id as u8);
                packet.push((flags_fragment >> 8) as u8);
                packet.push(flags_fragment as u8);
                packet.push(ttl);
                packet.push(proto);
                packet.push((checksum >> 8) as u8);
                packet.push(checksum as u8);

                // Source and destination IPs
                for octet in src.split('.') {
                    packet.push(octet.parse().unwrap_or(0));
                }
                for octet in dst.split('.') {
                    packet.push(octet.parse().unwrap_or(0));
                }

                if let Some(p) = payload {
                    packet.extend_from_slice(p.as_bytes());
                }

                Ok(String::from_utf8_lossy(&packet).to_string())
            },
        )?,
    )?;

    packet.set(
        "build_tcp_packet",
        lua.create_function(
            |_lua,
             (src_port, dst_port, seq, ack, flags, payload): (
                u16,
                u16,
                u32,
                u32,
                u16,
                Option<String>,
            )| {
                let mut packet = Vec::new();

                let data_offset = 5; // 20 bytes = 5 * 4 bits
                let window = 65535;
                let checksum = 0;
                let urgent = 0;

                packet.push((src_port >> 8) as u8);
                packet.push(src_port as u8);
                packet.push((dst_port >> 8) as u8);
                packet.push(dst_port as u8);
                packet.push((seq >> 24) as u8);
                packet.push((seq >> 16) as u8);
                packet.push((seq >> 8) as u8);
                packet.push(seq as u8);
                packet.push((ack >> 24) as u8);
                packet.push((ack >> 16) as u8);
                packet.push((ack >> 8) as u8);
                packet.push(ack as u8);
                packet.push(((data_offset << 4) | ((flags >> 8) & 0x0F)) as u8);
                packet.push(flags as u8);
                packet.push((window >> 8) as u8);
                packet.push(window as u8);
                packet.push((checksum >> 8) as u8);
                packet.push(checksum as u8);
                packet.push((urgent >> 8) as u8);
                packet.push(urgent as u8);

                if let Some(p) = payload {
                    packet.extend_from_slice(p.as_bytes());
                }

                Ok(String::from_utf8_lossy(&packet).to_string())
            },
        )?,
    )?;

    packet.set(
        "build_udp_packet",
        lua.create_function(
            |_lua, (src_port, dst_port, payload): (u16, u16, Option<String>)| {
                let mut packet = Vec::new();

                let length = 8 + payload.as_ref().map(|p| p.len()).unwrap_or(0);
                let checksum = 0;

                packet.push((src_port >> 8) as u8);
                packet.push(src_port as u8);
                packet.push((dst_port >> 8) as u8);
                packet.push(dst_port as u8);
                packet.push((length >> 8) as u8);
                packet.push(length as u8);
                packet.push((checksum >> 8) as u8);
                packet.push(checksum as u8);

                if let Some(p) = payload {
                    packet.extend_from_slice(p.as_bytes());
                }

                Ok(String::from_utf8_lossy(&packet).to_string())
            },
        )?,
    )?;

    packet.set(
        "build_icmp_packet",
        lua.create_function(
            |_lua, (icmp_type, code, payload): (u8, u8, Option<String>)| {
                let mut packet = Vec::new();

                let checksum = 0;

                packet.push(icmp_type);
                packet.push(code);
                packet.push((checksum >> 8) as u8);
                packet.push(checksum as u8);
                packet.push(0); // ID
                packet.push(0);
                packet.push(0); // Sequence
                packet.push(0);

                if let Some(p) = payload {
                    packet.extend_from_slice(p.as_bytes());
                }

                Ok(String::from_utf8_lossy(&packet).to_string())
            },
        )?,
    )?;

    packet.set(
        "send",
        lua.create_function(|lua, (host, port, data): (String, u16, String)| {
            use std::net::UdpSocket;
            let result = lua.create_table()?;

            match UdpSocket::bind("0.0.0.0:0") {
                Ok(socket) => {
                    let addr = format!("{}:{}", host, port);
                    match socket.send_to(data.as_bytes(), &addr) {
                        Ok(n) => {
                            result.set("status", "ok")?;
                            result.set("sent", n)?;
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

    packet.set(
        "send_raw",
        lua.create_function(
            |lua, (_interface, _packet_data): (Option<String>, String)| {
                let result = lua.create_table()?;
                #[cfg(feature = "stress-testing")]
                {
                    use std::net::UdpSocket;

                    match UdpSocket::bind("0.0.0.0:0") {
                        Ok(socket) => {
                            socket.set_broadcast(true).ok();
                            match socket.send_to(_packet_data.as_bytes(), "255.255.255.255:0") {
                                Ok(n) => {
                                    result.set("status", "ok")?;
                                    result.set("sent", n)?;
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
                }
                #[cfg(not(feature = "stress-testing"))]
                {
                    result.set("status", "unavailable")?;
                    result.set(
                        "error",
                        "Raw sockets require stress-testing feature (root privileges)",
                    )?;
                    result.set("sent", 0)?;
                }
                Ok(result)
            },
        )?,
    )?;

    packet.set(
        "send_tcp",
        lua.create_function(|lua, (host, port, data): (String, u16, String)| {
            use std::io::{Read, Write};
            use std::net::TcpStream;
            use std::time::Duration;

            let result = lua.create_table()?;
            let addr = format!("{}:{}", host, port);

            match TcpStream::connect_timeout(
                &addr
                    .parse()
                    .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 80))),
                Duration::from_secs(5),
            ) {
                Ok(mut stream) => match stream.write_all(data.as_bytes()) {
                    Ok(()) => {
                        result.set("status", "ok")?;
                        result.set("sent", data.len())?;

                        let mut buf = vec![0u8; 1024];
                        if let Ok(n) = stream.read(&mut buf) {
                            result
                                .set("response", String::from_utf8_lossy(&buf[..n]).to_string())?;
                        }
                    }
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e.to_string())?;
                    }
                },
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                }
            }
            Ok(result)
        })?,
    )?;

    packet.set(
        "parse_ip",
        lua.create_function(|lua, data: String| {
            let bytes = data.as_bytes();
            let result = lua.create_table()?;

            if bytes.len() < 20 {
                result.set("error", "packet too short")?;
                return Ok(result);
            }

            let version = (bytes[0] >> 4) as i32;
            let ihl = (bytes[0] & 0x0F) as i32;
            let tos = bytes[1] as i32;
            let total_len = u16::from_be_bytes([bytes[2], bytes[3]]) as i32;
            let id = u16::from_be_bytes([bytes[4], bytes[5]]) as i32;
            let flags = (u16::from_be_bytes([bytes[6], bytes[7]]) >> 13) as i32;
            let offset = u16::from_be_bytes([bytes[6], bytes[7]]) as i32 & 0x1FFF;
            let ttl = bytes[8] as i32;
            let proto = bytes[9] as i32;
            let checksum = u16::from_be_bytes([bytes[10], bytes[11]]) as i32;

            let src_ip = format!("{}.{}.{}.{}", bytes[12], bytes[13], bytes[14], bytes[15]);
            let dst_ip = format!("{}.{}.{}.{}", bytes[16], bytes[17], bytes[18], bytes[19]);

            result.set("version", version)?;
            result.set("header_length", ihl * 4)?;
            result.set("tos", tos)?;
            result.set("length", total_len)?;
            result.set("id", id)?;
            result.set("flags", flags)?;
            result.set("offset", offset)?;
            result.set("ttl", ttl)?;
            result.set("protocol", proto)?;
            result.set("checksum", checksum)?;
            result.set("src_ip", src_ip)?;
            result.set("dst_ip", dst_ip)?;

            if bytes.len() > 20 {
                result.set("payload", String::from_utf8_lossy(&bytes[20..]).to_string())?;
            }

            Ok(result)
        })?,
    )?;

    globals.set("packet", packet)?;
    Ok(())
}
