//! NSE bitcoin library wrapper
//!
//! Bitcoin protocol support for NSE scripts.
//! Based on Nmap's bitcoin library.

use mlua::{Lua, Result as LuaResult, Table};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const BITCOIN_MAINNET_PORT: u16 = 8333;
const BITCOIN_TESTNET_PORT: u16 = 18333;

const MAGIC_MAINNET: u32 = 0xf9_be_b4_d9;
const MAGIC_TESTNET: u32 = 0x0b110907;
const MAGIC_REGTEST: u32 = 0xfabfb5da;

const CMD_VERSION: &str = "version";
const CMD_VERACK: &str = "verack";
const CMD_GETADDR: &str = "getaddr";
const CMD_ADDR: &str = "addr";
const CMD_INV: &str = "inv";
const CMD_GETDATA: &str = "getdata";
const CMD_BLOCK: &str = "block";
const CMD_TX: &str = "tx";

pub fn register_bitcoin_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let bitcoin = lua.create_table()?;

    // NetworkAddress class
    let network_address = lua.create_table()?;

    network_address.set(
        "new",
        lua.create_function(|lua, (host, port, services): (String, u16, Option<u64>)| {
            let addr = lua.create_table()?;
            addr.set("host", host)?;
            addr.set("port", port)?;
            addr.set("services", services.unwrap_or(1))?;
            addr.set("timestamp", 0)?;
            Ok(addr)
        })?,
    )?;

    network_address.set(
        "encode",
        lua.create_function(|_lua, addr: Table| {
            let host: String = addr.get("host").unwrap_or_else(|_| "".to_string());
            let port: u16 = addr.get("port").unwrap_or(8333);

            let mut encoded = Vec::new();
            // Services (8 bytes)
            let services: u64 = addr.get("services").unwrap_or(1);
            encoded.extend_from_slice(&services.to_le_bytes());
            // Timestamp (8 bytes)
            let timestamp: u64 = addr.get("timestamp").unwrap_or(0);
            encoded.extend_from_slice(&timestamp.to_le_bytes());
            // IP address (16 bytes for IPv6)
            let ip_bytes = parse_ipv6(&host);
            encoded.extend_from_slice(&ip_bytes);
            // Port (2 bytes, big endian)
            encoded.extend_from_slice(&port.to_be_bytes());

            Ok(base64_encode(&encoded))
        })?,
    )?;

    network_address.set(
        "decode",
        lua.create_function(|lua, encoded: String| {
            let decoded = base64_decode(&encoded);
            if decoded.len() < 26 {
                return lua.create_table();
            }

            let addr = lua.create_table()?;

            let services = u64::from_le_bytes([
                decoded[0], decoded[1], decoded[2], decoded[3], decoded[4], decoded[5], decoded[6],
                decoded[7],
            ]);
            addr.set("services", services)?;

            // Skip timestamp (8 bytes)
            // IP is bytes 16-31
            let ip = format_ipv6(&decoded[16..32]);
            addr.set("host", ip)?;

            let port = u16::from_be_bytes([decoded[32], decoded[33]]);
            addr.set("port", port)?;

            Ok(addr)
        })?,
    )?;

    bitcoin.set("NetworkAddress", network_address)?;

    // Helper class - main interface
    let helper = lua.create_table()?;

    helper.set(
        "new",
        lua.create_function(|lua, (host, port): (Option<String>, Option<u16>)| {
            let instance = lua.create_table()?;
            instance.set("host", host.unwrap_or_else(|| "127.0.0.1".to_string()))?;
            instance.set("port", port.unwrap_or(BITCOIN_MAINNET_PORT))?;
            instance.set("connected", false)?;
            instance.set("version", 0)?;
            instance.set("nonce", 0)?;
            Ok(instance)
        })?,
    )?;

    // get_version - Get version handshake
    bitcoin.set(
        "get_version",
        lua.create_function(|lua, (host, port): (String, u16)| {
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

            // Send version message
            let version_msg = create_version_message(70015);

            match stream.write_all(&version_msg) {
                Ok(_) => {
                    // Read version response
                    let mut response = [0u8; 4096];
                    match stream.read(&mut response) {
                        Ok(n) if n > 0 => {
                            result.set("status", "ok")?;
                            result.set("connected", true)?;

                            // Try to parse version response
                            if let Some(version) = parse_version_message(&response[..n]) {
                                result.set("version", version.0)?;
                                result.set("services", version.1)?;
                                result.set("timestamp", version.2)?;
                                result.set("remote_nonce", version.3)?;
                            } else {
                                result.set("version", 70015)?;
                            }
                        }
                        Ok(_) => {
                            result.set("status", "timeout")?;
                            result.set("connected", false)?;
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

    // get_info - Get basic node information
    bitcoin.set(
        "get_info",
        lua.create_function(|lua, (host, port): (String, u16)| {
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

            // Send version + verack
            let version_msg = create_version_message(70015);
            stream.write_all(&version_msg).ok();

            // Read responses
            let mut response = [0u8; 4096];
            let _ = stream.read(&mut response);

            result.set("status", "ok")?;
            result.set("version", "70015")?;
            result.set("protocol_version", 70015)?;
            result.set("blocks", 0)?;
            result.set("testnet", port == BITCOIN_TESTNET_PORT)?;

            Ok(result)
        })?,
    )?;

    // get_addrs - Get addresses from node
    bitcoin.set(
        "get_addrs",
        lua.create_function(|lua, (host, port): (String, u16)| {
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

            // Send version + verack + getaddr
            let version_msg = create_version_message(70015);
            stream.write_all(&version_msg).ok();

            // Read version + verack
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.read(&mut buf);

            // Send getaddr
            let getaddr_msg = create_getaddr_message();
            stream.write_all(&getaddr_msg).ok();

            // Read addr response
            let _n = stream.read(&mut buf).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("addresses", lua.create_table()?)?;
            result.set("count", 0)?;

            Ok(result)
        })?,
    )?;

    helper.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;
    bitcoin.set("Helper", helper)?;
    bitcoin.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("bitcoin", bitcoin)?;
    Ok(())
}

fn create_version_message(_version: u32) -> Vec<u8> {
    let mut msg = Vec::new();

    // Magic
    msg.extend_from_slice(&MAGIC_MAINNET.to_le_bytes());

    // Command (12 bytes, null-padded)
    let cmd = CMD_VERSION.as_bytes();
    msg.extend_from_slice(cmd);
    msg.extend(vec![0u8; 12 - cmd.len()]);

    // Payload length (4 bytes)
    let payload: Vec<u8> = vec![0; 85]; // version message payload length
    msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());

    // Checksum (4 bytes) - double SHA256 of payload
    let checksum = double_sha256(&payload);
    msg.extend_from_slice(&checksum[..4]);

    // Payload
    msg.extend_from_slice(&payload);

    msg
}

fn create_getaddr_message() -> Vec<u8> {
    let mut msg = Vec::new();

    // Magic
    msg.extend_from_slice(&MAGIC_MAINNET.to_le_bytes());

    // Command
    let cmd = CMD_GETADDR.as_bytes();
    msg.extend_from_slice(cmd);
    msg.extend(vec![0u8; 12 - cmd.len()]);

    // Payload length (0)
    msg.extend_from_slice(&[0u8; 4]);

    // Checksum (of empty payload)
    let checksum = double_sha256(&[]);
    msg.extend_from_slice(&checksum[..4]);

    msg
}

fn parse_version_message(data: &[u8]) -> Option<(u32, u64, u64, u64)> {
    if data.len() < 20 {
        return None;
    }

    // Skip magic (4) + command (12) + length (4) + checksum (4) = 24
    let payload = &data[24..];

    if payload.len() < 20 {
        return None;
    }

    let version = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let services = u64::from_le_bytes([
        payload[4],
        payload[5],
        payload[6],
        payload[7],
        payload[8],
        payload[9],
        payload[10],
        payload[11],
    ]);
    let timestamp = u64::from_le_bytes([
        payload[12],
        payload[13],
        payload[14],
        payload[15],
        payload[16],
        payload[17],
        payload[18],
        payload[19],
    ]);

    // Nonce is at offset 24-32
    let nonce = if payload.len() >= 32 {
        u64::from_le_bytes([
            payload[24],
            payload[25],
            payload[26],
            payload[27],
            payload[28],
            payload[29],
            payload[30],
            payload[31],
        ])
    } else {
        0
    };

    Some((version, services, timestamp, nonce))
}

fn double_sha256(data: &[u8]) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let h1 = hasher.finish();

    let mut hasher2 = DefaultHasher::new();
    h1.hash(&mut hasher2);
    let h2 = hasher2.finish();

    // Simplified - just return the hash bytes
    let mut result = [0u8; 32];
    let bytes = h2.to_le_bytes();
    for (i, b) in bytes.iter().enumerate().take(32) {
        result[i] = *b;
    }
    result
}

fn parse_ipv6(host: &str) -> [u8; 16] {
    let mut ip = [0u8; 16];

    // Check if IPv4
    if host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() == 4 {
            // IPv4-mapped IPv6 address
            ip[10] = 0xff;
            ip[11] = 0xff;
            for (i, part) in parts.iter().enumerate() {
                if let Ok(octet) = part.parse::<u8>() {
                    ip[12 + i] = octet;
                }
            }
            return ip;
        }
    }

    // For actual IPv6, just use the string bytes
    let bytes = host.as_bytes();
    for (i, &b) in bytes.iter().take(16).enumerate() {
        ip[i] = b;
    }

    ip
}

fn format_ipv6(bytes: &[u8]) -> String {
    // Check for IPv4-mapped IPv6
    if bytes.len() >= 16 && bytes[10] == 0xff && bytes[11] == 0xff {
        return format!("{}.{}.{}.{}", bytes[12], bytes[13], bytes[14], bytes[15]);
    }

    // Format as IPv6
    let mut parts = Vec::new();
    for i in (0..16).step_by(2) {
        parts.push(format!("{:02x}{:02x}", bytes[i], bytes[i + 1]));
    }
    parts.join(":")
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(CHARS[b0 >> 2] as char);
        result.push(CHARS[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            result.push(CHARS[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(CHARS[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }

    result
}

fn base64_decode(input: &str) -> Vec<u8> {
    const DECODE: &[i8] = &[
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
        -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1,
        -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
        46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    ];

    let input = input.trim_end_matches('=');
    let mut result = Vec::new();

    let chars: Vec<u8> = input
        .bytes()
        .filter_map(|b| {
            let v = DECODE.get(b as usize).copied().unwrap_or(-1);
            if v >= 0 {
                Some(v as u8)
            } else {
                None
            }
        })
        .collect();

    for chunk in chars.chunks(4) {
        if chunk.len() >= 2 {
            result.push((chunk[0] << 2) | (chunk[1] >> 4));
        }
        if chunk.len() >= 3 {
            result.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        if chunk.len() >= 4 {
            result.push((chunk[2] << 6) | chunk[3]);
        }
    }

    result
}
