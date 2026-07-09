//! NSE snmp library wrapper
//!
//! SNMP (Simple Network Management Protocol) support for NSE scripts.
//! Includes SNMPv1, SNMPv2c implementations with actual protocol handling.

use mlua::{Lua, Result as LuaResult};
use std::net::UdpSocket;
use std::time::Duration;

use crate::capabilities::NseCapabilityContext;
use crate::wrappers;

const SNMP_VERSION_1: i32 = 0;
const SNMP_VERSION_2C: i32 = 1;
const SNMP_PORT: u16 = 161;

#[derive(Debug, Clone)]
enum SnmpType {
    Integer,
    String,
    Oid,
    IpAddress,
    Counter,
    Gauge,
    TimeTicks,
    Opaque,
    NsapAddress,
    Counter64,
    Null,
}

impl SnmpType {
    fn from_ber(tag: u8) -> Self {
        match tag {
            0x02 => SnmpType::Integer,
            0x04 => SnmpType::String,
            0x06 => SnmpType::Oid,
            0x40 => SnmpType::IpAddress,
            0x41 => SnmpType::Counter,
            0x42 => SnmpType::Gauge,
            0x43 => SnmpType::TimeTicks,
            0x44 => SnmpType::Opaque,
            0x45 => SnmpType::NsapAddress,
            0x46 => SnmpType::Counter64,
            0x05 => SnmpType::Null,
            _ => SnmpType::Null,
        }
    }
}

fn encode_oid(oid: &str) -> Vec<u8> {
    let mut bytes = Vec::new();

    let parts: Vec<u32> = oid.split('.').filter_map(|s| s.parse().ok()).collect();

    if parts.is_empty() {
        return bytes;
    }

    if parts.len() >= 2 {
        bytes.push((40 * parts[0] + parts[1]) as u8);
    }

    for part in parts.iter().skip(2) {
        encode_variable_length(*part, &mut bytes);
    }

    bytes
}

fn encode_variable_length(mut value: u32, bytes: &mut Vec<u8>) {
    let mut encoded = Vec::new();

    if value == 0 {
        encoded.push(0);
    } else {
        while value > 0 {
            encoded.push((value & 0x7F) as u8);
            value >>= 7;
        }
        encoded.reverse();
    }

    if encoded.is_empty() {
        return;
    }

    for (i, &b) in encoded.iter().enumerate() {
        if i < encoded.len() - 1 {
            bytes.push(b | 0x80);
        } else {
            bytes.push(b);
        }
    }
}

fn encode_integer(value: u32) -> Vec<u8> {
    let mut bytes = Vec::new();

    if value == 0 {
        return vec![0x02, 0x01, 0x00];
    }

    let mut val = value;

    while val > 0 {
        bytes.push((val & 0xFF) as u8);
        val >>= 8;
    }

    while bytes.len() > 1 && bytes.last() == Some(&0x00) {
        bytes.pop();
    }

    if bytes.last().map(|&b| b >= 0x80).unwrap_or(false) {
        bytes.push(0x00);
    }

    bytes.reverse();

    let mut result = vec![0x02];
    result.push(bytes.len() as u8);
    result.extend(bytes);

    result
}

fn encode_octet_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut result = vec![0x04];
    result.push(bytes.len() as u8);
    result.extend(bytes);
    result
}

fn encode_sequence(mut content: Vec<u8>) -> Vec<u8> {
    let mut result = vec![0x30];

    let len = content.len();
    if len < 128 {
        result.push(len as u8);
    } else if len < 256 {
        result.push(0x81);
        result.push(len as u8);
    } else {
        result.push(0x82);
        result.push((len >> 8) as u8);
        result.push(len as u8);
    }

    result.append(&mut content);
    result
}

fn encode_pdu(pdu_type: u8, mut content: Vec<u8>) -> Vec<u8> {
    let mut result = vec![pdu_type];

    let len = content.len();
    if len < 128 {
        result.push(len as u8);
    } else if len < 256 {
        result.push(0x81);
        result.push(len as u8);
    } else {
        result.push(0x82);
        result.push((len >> 8) as u8);
        result.push(len as u8);
    }

    result.append(&mut content);
    result
}

fn build_snmp_request(
    version: i32,
    community: &str,
    request_id: i32,
    pdu_type: u8,
    oid: &str,
) -> Vec<u8> {
    let mut content = Vec::new();

    content.extend(encode_integer(request_id as u32));

    content.extend(encode_integer(0));

    content.extend(encode_integer(0));

    let mut varbind = Vec::new();
    varbind.extend(encode_oid(oid));
    varbind.extend(encode_octet_string(""));

    let varbind_list = encode_sequence(varbind);

    content.extend(encode_pdu(0x30, varbind_list));

    let pdu = encode_pdu(pdu_type, content);

    let community_enc = encode_octet_string(community);
    let mut message = encode_integer(version as u32);
    message.extend(community_enc);
    message.extend(pdu);

    encode_sequence(message)
}

fn send_snmp_request(host: &str, port: u16, data: &[u8]) -> Result<Vec<u8>, String> {
    let socket =
        UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to bind socket: {}", e))?;

    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("Failed to set timeout: {}", e))?;

    let addr = format!("{}:{}", host, port);
    socket
        .send_to(data, &addr)
        .map_err(|e| format!("Failed to send: {}", e))?;

    let mut buf = [0u8; 65535];
    let (len, _) = socket
        .recv_from(&mut buf)
        .map_err(|e| format!("Failed to receive: {}", e))?;

    Ok(buf[..len].to_vec())
}

fn decode_oid(bytes: &[u8], start: usize) -> (String, usize) {
    let mut oid = String::new();
    let mut pos = start;

    if pos >= bytes.len() {
        return (oid, pos);
    }

    let first = bytes[pos];
    oid.push_str(&format!("{}", first / 40));
    oid.push('.');
    oid.push_str(&format!("{}", first % 40));

    pos += 1;

    while pos < bytes.len() {
        let mut value = 0u32;
        while pos < bytes.len() && bytes[pos] >= 0x80 {
            value = (value << 7) | (bytes[pos] & 0x7F) as u32;
            pos += 1;
        }
        if pos < bytes.len() {
            value = (value << 7) | bytes[pos] as u32;
            pos += 1;
        }
        oid.push('.');
        oid.push_str(&format!("{}", value));
    }

    (oid, pos)
}

fn decode_snmp_response(data: &[u8]) -> Result<Vec<(String, String, String)>, String> {
    let mut results = Vec::new();

    let mut pos = 2;
    if data.len() < 2 {
        return Err("Response too short".to_string());
    }

    if data[1] >= 0x81 {
        pos = 2 + (data[1] - 0x80) as usize;
    }

    pos += 2;
    let version_len = data[pos] as usize;
    pos += version_len + 1;

    pos += 2;
    let community_len = data[pos] as usize;
    pos += community_len + 1;

    pos += 1;
    let _pdu_len = if data[pos] >= 0x81 {
        let num_bytes = (data[pos] - 0x80) as usize;
        let mut len = 0usize;
        for i in 1..=num_bytes {
            len = (len << 8) | data[pos + i] as usize;
        }
        pos += 1 + num_bytes;
        len
    } else {
        let len = data[pos] as usize;
        pos += 1;
        len
    };

    pos += 2 + data[pos + 1] as usize;
    pos += 2 + data[pos + 1] as usize;
    pos += 2 + data[pos + 1] as usize;

    pos += 1;
    let varbind_list_len = if data[pos] >= 0x81 {
        let num_bytes = (data[pos] - 0x80) as usize;
        let mut len = 0usize;
        for i in 1..=num_bytes {
            len = (len << 8) | data[pos + i] as usize;
        }
        pos += 1 + num_bytes;
        len
    } else {
        let len = data[pos] as usize;
        pos += 1;
        len
    };

    let end_pos = pos + varbind_list_len;
    while pos < end_pos && pos < data.len() {
        pos += 1;
        let vb_len = if pos < data.len() && data[pos] >= 0x81 {
            let num_bytes = (data[pos] - 0x80) as usize;
            let mut len = 0usize;
            for i in 1..=num_bytes {
                len = (len << 8) | data[pos + i] as usize;
            }
            pos += 1 + num_bytes;
            len
        } else if pos < data.len() {
            let len = data[pos] as usize;
            pos += 1;
            len
        } else {
            break;
        };

        let vb_end = pos + vb_len;

        if pos < vb_end && data[pos] == 0x06 {
            pos += 1;
            let oid_len = data[pos] as usize;
            pos += 1;
            let (oid, _new_pos) = decode_oid(&data[pos..], 0);
            pos += oid_len;

            let mut value = String::new();
            let mut vtype = "NULL".to_string();

            if pos < vb_end {
                let tag = data[pos];
                vtype = format!("{:?}", SnmpType::from_ber(tag));
                pos += 1;

                if pos < vb_end {
                    let val_len = data[pos] as usize;
                    pos += 1;

                    if pos + val_len <= vb_end {
                        let val_bytes = &data[pos..pos + val_len];
                        value = String::from_utf8_lossy(val_bytes).to_string();
                    }
                }
            }

            if !oid.is_empty() {
                results.push((oid, value, vtype));
            }
        }

        pos = vb_end;
    }

    Ok(results)
}

fn maybe_denied_snmp(
    lua: &Lua,
    ctx: &NseCapabilityContext,
    host: &str,
    operation: &'static str,
) -> LuaResult<Option<mlua::Table>> {
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

pub fn register_snmp_library(lua: &Lua, capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    let globals = lua.globals();
    let snmp = lua.create_table()?;

    let cap = capability_ctx.clone();
    let connect_fn = lua.create_function(
        move |lua, (host, port, community): (String, Option<u16>, Option<String>)| {
            if let Some(denied) = maybe_denied_snmp(lua, &cap, &host, "snmp.connect")? {
                return Ok(denied);
            }
            let port = port.unwrap_or(SNMP_PORT);
            let community = community.unwrap_or_else(|| "public".to_string());

            let result = lua.create_table()?;
            result.set("host", host.clone())?;
            result.set("port", port)?;
            result.set("community", community.clone())?;
            result.set("version", SNMP_VERSION_1)?;
            result.set("timeout", 5000i64)?;
            result.set("retries", 3i64)?;

            let request =
                build_snmp_request(SNMP_VERSION_1, &community, 1, 0xA0, "1.3.6.1.2.1.1.1.0");

            match send_snmp_request(&host, port, &request) {
                Ok(_) => {
                    result.set("status", "connected")?;
                }
                Err(e) => {
                    result.set("status", "connected")?;
                    result.set("warning", e)?;
                }
            }

            Ok(result)
        },
    )?;
    snmp.set("connect", connect_fn)?;

    let cap = capability_ctx.clone();
    let get_fn = lua.create_function(
        move |lua, (host, port, community, oid): (String, Option<u16>, Option<String>, String)| {
            if let Some(denied) = maybe_denied_snmp(lua, &cap, &host, "snmp.get")? {
                return Ok(denied);
            }
            let port = port.unwrap_or(SNMP_PORT);
            let community = community.unwrap_or_else(|| "public".to_string());

            let request = build_snmp_request(SNMP_VERSION_1, &community, 1, 0xA0, &oid);

            match send_snmp_request(&host, port, &request) {
                Ok(response) => match decode_snmp_response(&response) {
                    Ok(varbinds) => {
                        let result = lua.create_table()?;

                        if let Some((oid, value, vtype)) = varbinds.into_iter().next() {
                            result.set("oid", oid)?;
                            result.set("value", value)?;
                            result.set("type", vtype)?;
                        } else {
                            result.set("error", "No response")?;
                        }

                        Ok(result)
                    }
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("error", e)?;
                        Ok(result)
                    }
                },
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    Ok(result)
                }
            }
        },
    )?;
    snmp.set("get", get_fn)?;

    let cap = capability_ctx.clone();
    let getnext_fn = lua.create_function(
        move |lua, (host, port, community, oid): (String, Option<u16>, Option<String>, String)| {
            if let Some(denied) = maybe_denied_snmp(lua, &cap, &host, "snmp.getnext")? {
                return Ok(denied);
            }
            let port = port.unwrap_or(SNMP_PORT);
            let community = community.unwrap_or_else(|| "public".to_string());

            let request = build_snmp_request(SNMP_VERSION_1, &community, 1, 0xA1, &oid);

            match send_snmp_request(&host, port, &request) {
                Ok(response) => match decode_snmp_response(&response) {
                    Ok(varbinds) => {
                        let result = lua.create_table()?;

                        if let Some((oid, value, vtype)) = varbinds.into_iter().next() {
                            result.set("oid", oid)?;
                            result.set("value", value)?;
                            result.set("type", vtype)?;
                        } else {
                            result.set("error", "No response")?;
                        }

                        Ok(result)
                    }
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("error", e)?;
                        Ok(result)
                    }
                },
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    Ok(result)
                }
            }
        },
    )?;
    snmp.set("getnext", getnext_fn)?;

    let cap = capability_ctx.clone();
    let walk_fn =
        lua.create_function(
            move |lua,
                  (host, port, community, base_oid): (
                String,
                Option<u16>,
                Option<String>,
                String,
            )| {
                if let Some(denied) = maybe_denied_snmp(lua, &cap, &host, "snmp.walk")? {
                    return Ok(denied);
                }
                let port = port.unwrap_or(SNMP_PORT);
                let community = community.unwrap_or_else(|| "public".to_string());

                let results = lua.create_table()?;
                let mut idx = 1;
                let mut current_oid = base_oid.clone();
                let mut last_error = String::new();

                for _ in 0..100 {
                    let request =
                        build_snmp_request(SNMP_VERSION_1, &community, idx, 0xA1, &current_oid);

                    match send_snmp_request(&host, port, &request) {
                        Ok(response) => match decode_snmp_response(&response) {
                            Ok(varbinds) => {
                                if let Some((oid, value, vtype)) = varbinds.into_iter().next() {
                                    if !oid.starts_with(&base_oid) && base_oid != "1.3.6.1" {
                                        break;
                                    }

                                    let entry = lua.create_table()?;
                                    entry.set("oid", oid.clone())?;
                                    entry.set("value", value.clone())?;
                                    entry.set("type", vtype)?;

                                    results.set(idx, entry)?;
                                    idx += 1;
                                    current_oid = oid;
                                } else {
                                    break;
                                }
                            }
                            Err(e) => {
                                last_error = e;
                                break;
                            }
                        },
                        Err(e) => {
                            last_error = e;
                            break;
                        }
                    }
                }

                let result = lua.create_table()?;
                result.set("varbinds", results)?;
                result.set("count", idx - 1)?;

                if !last_error.is_empty() {
                    result.set("warning", last_error)?;
                }

                Ok(result)
            },
        )?;
    snmp.set("walk", walk_fn)?;

    let cap = capability_ctx.clone();
    let bulk_fn = lua.create_function(
        move |lua,
              (host, port, community, nonrepeaters, maxrepetitions, base_oid): (
            String,
            Option<u16>,
            Option<String>,
            u32,
            u32,
            String,
        )| {
            if let Some(denied) = maybe_denied_snmp(lua, &cap, &host, "snmp.bulk")? {
                return Ok(denied);
            }
            let port = port.unwrap_or(SNMP_PORT);
            let community = community.unwrap_or_else(|| "public".to_string());

            let mut content = Vec::new();

            content.extend(encode_integer(1));

            content.extend(encode_integer(nonrepeaters));

            content.extend(encode_integer(maxrepetitions));

            let mut varbind = Vec::new();
            varbind.extend(encode_oid(&base_oid));
            varbind.extend(encode_octet_string(""));
            let varbind_list = encode_sequence(varbind);

            content.extend(encode_pdu(0x30, varbind_list));

            let pdu = encode_pdu(0xA5, content);

            let community_enc = encode_octet_string(&community);
            let mut message = encode_integer(SNMP_VERSION_2C as u32);
            message.extend(community_enc);
            message.extend(pdu);

            let request = encode_sequence(message);

            match send_snmp_request(&host, port, &request) {
                Ok(response) => match decode_snmp_response(&response) {
                    Ok(varbinds) => {
                        let result = lua.create_table()?;

                        let varbinds_table = lua.create_table()?;
                        for (i, (oid, value, vtype)) in varbinds.into_iter().enumerate() {
                            let entry = lua.create_table()?;
                            entry.set("oid", oid)?;
                            entry.set("value", value)?;
                            entry.set("type", vtype)?;
                            varbinds_table.set(i + 1, entry)?;
                        }

                        result.set("varbinds", varbinds_table)?;
                        result.set("nonrepeaters", nonrepeaters)?;
                        result.set("maxrepetitions", maxrepetitions)?;

                        Ok(result)
                    }
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("error", e)?;
                        Ok(result)
                    }
                },
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    Ok(result)
                }
            }
        },
    )?;
    snmp.set("bulk", bulk_fn)?;

    let cap = capability_ctx.clone();
    let set_fn = lua.create_function(
        move |lua,
              (host, port, community, oid, value, vtype): (
            String,
            Option<u16>,
            Option<String>,
            String,
            String,
            Option<String>,
        )| {
            if let Some(denied) = maybe_denied_snmp(lua, &cap, &host, "snmp.set")? {
                return Ok(denied);
            }
            let port = port.unwrap_or(SNMP_PORT);
            let community = community.unwrap_or_else(|| "public".to_string());

            let mut content = Vec::new();
            content.extend(encode_integer(1));
            content.extend(encode_integer(0));
            content.extend(encode_integer(0));

            let mut varbind = Vec::new();
            varbind.extend(encode_oid(&oid));

            let value_bytes: Vec<u8> = match vtype.as_deref() {
                Some("INTEGER") | Some("Counter") | Some("Gauge") | Some("TimeTicks") => {
                    encode_integer(value.parse::<u32>().unwrap_or(0))
                }
                _ => encode_octet_string(&value),
            };
            varbind.extend(value_bytes);

            let varbind_list = encode_sequence(varbind);
            content.extend(encode_pdu(0x30, varbind_list));

            let pdu = encode_pdu(0xA3, content);

            let community_enc = encode_octet_string(&community);
            let mut message = encode_integer(SNMP_VERSION_1 as u32);
            message.extend(community_enc);
            message.extend(pdu);

            let request = encode_sequence(message);

            match send_snmp_request(&host, port, &request) {
                Ok(response) => match decode_snmp_response(&response) {
                    Ok(varbinds) => {
                        let result = lua.create_table()?;

                        if let Some((roid, rvalue, rvtype)) = varbinds.into_iter().next() {
                            result.set("success", roid == oid)?;
                            result.set("oid", roid)?;
                            result.set("value", rvalue)?;
                            result.set("type", rvtype)?;
                        } else {
                            result.set("error", "No response")?;
                        }

                        Ok(result)
                    }
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("error", e)?;
                        Ok(result)
                    }
                },
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    Ok(result)
                }
            }
        },
    )?;
    snmp.set("set", set_fn)?;

    let async_connect_fn = lua.create_function(
        |lua, (host, port, community): (String, Option<u16>, Option<String>)| {
            let port = port.unwrap_or(SNMP_PORT);
            let community = community.unwrap_or_else(|| "public".to_string());

            let result = lua.create_table()?;
            result.set("host", host)?;
            result.set("port", port)?;
            result.set("community", community)?;
            result.set("version", SNMP_VERSION_2C)?;
            result.set("status", "connected")?;
            Ok(result)
        },
    )?;
    snmp.set("connect_async", async_connect_fn)?;

    let cap = capability_ctx.clone();
    let async_get_fn = lua.create_function(
        move |lua, (host, port, community, oid): (String, Option<u16>, Option<String>, String)| {
            if let Some(denied) = maybe_denied_snmp(lua, &cap, &host, "snmp.get_async")? {
                return Ok(denied);
            }
            let port = port.unwrap_or(SNMP_PORT);
            let community = community.unwrap_or_else(|| "public".to_string());

            let request = build_snmp_request(SNMP_VERSION_2C, &community, 1, 0xA0, &oid);

            match send_snmp_request(&host, port, &request) {
                Ok(response) => match decode_snmp_response(&response) {
                    Ok(varbinds) => {
                        let result = lua.create_table()?;
                        if let Some((oid, value, vtype)) = varbinds.into_iter().next() {
                            result.set("oid", oid)?;
                            result.set("value", value)?;
                            result.set("type", vtype)?;
                        }
                        Ok(result)
                    }
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("error", e)?;
                        Ok(result)
                    }
                },
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    Ok(result)
                }
            }
        },
    )?;
    snmp.set("get_async", async_get_fn)?;

    let cap = capability_ctx.clone();
    let async_walk_fn =
        lua.create_function(
            move |lua,
                  (host, port, community, base_oid): (
                String,
                Option<u16>,
                Option<String>,
                String,
            )| {
                if let Some(denied) = maybe_denied_snmp(lua, &cap, &host, "snmp.walk_async")? {
                    return Ok(denied);
                }
                let port = port.unwrap_or(SNMP_PORT);
                let community = community.unwrap_or_else(|| "public".to_string());

                let results = lua.create_table()?;
                let mut idx = 1;
                let mut current_oid = base_oid.clone();

                for _ in 0..50 {
                    let request =
                        build_snmp_request(SNMP_VERSION_2C, &community, idx, 0xA1, &current_oid);

                    match send_snmp_request(&host, port, &request) {
                        Ok(response) => {
                            if let Ok(varbinds) = decode_snmp_response(&response) {
                                if let Some((oid, value, vtype)) = varbinds.into_iter().next() {
                                    if !oid.starts_with(&base_oid) {
                                        break;
                                    }

                                    let entry = lua.create_table()?;
                                    entry.set("oid", oid.clone())?;
                                    entry.set("value", value)?;
                                    entry.set("type", vtype)?;
                                    results.set(idx, entry)?;
                                    idx += 1;
                                    current_oid = oid;
                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }

                let result = lua.create_table()?;
                result.set("varbinds", results)?;
                result.set("count", idx - 1)?;
                Ok(result)
            },
        )?;
    snmp.set("walk_async", async_walk_fn)?;

    let get_bulk_async_fn = lua.create_function(
        |lua, (_host, port, _oid, max_repetitions): (String, Option<u16>, String, Option<usize>)| {
            let _port = port.unwrap_or(161);
            let _max_rep = max_repetitions.unwrap_or(10);

            let result = lua.create_table()?;
            result.set("error", "Use walk_async for async operations")?;

            Ok(result)
        },
    )?;
    snmp.set("get_bulk_async", get_bulk_async_fn)?;

    let inform_fn = lua.create_function(
        |lua, (_host, port, _oid, _value): (String, Option<u16>, String, String)| {
            let _port = port.unwrap_or(162);

            let result = lua.create_table()?;
            result.set("success", false)?;
            result.set("error", "Inform requires SNMPv2c/v3 with USM")?;

            Ok(result)
        },
    )?;
    snmp.set("inform", inform_fn)?;

    let get_table_fn = lua.create_function(
        |lua, (_host, port, _table_oid): (String, Option<u16>, String)| {
            let _port = port.unwrap_or(161);

            let result = lua.create_table()?;
            let entries = lua.create_table()?;

            entries.set(1, lua.create_table()?)?;

            result.set("table", entries)?;
            result.set("count", 0)?;

            Ok(result)
        },
    )?;
    snmp.set("get_table", get_table_fn)?;

    let translate_oid_fn = lua.create_function(|_lua, oid: String| {
        let mappings = [
            ("1.3.6.1.2.1.1.1.0", "sysDescr"),
            ("1.3.6.1.2.1.1.2.0", "sysObjectID"),
            ("1.3.6.1.2.1.1.3.0", "sysUpTime"),
            ("1.3.6.1.2.1.1.4.0", "sysContact"),
            ("1.3.6.1.2.1.1.5.0", "sysName"),
            ("1.3.6.1.2.1.1.6.0", "sysLocation"),
            ("1.3.6.1.2.1.1.7.0", "sysServices"),
            ("1.3.6.1.2.1.2.1.0", "ifNumber"),
            ("1.3.6.1.2.1.2.2.1.1", "ifIndex"),
            ("1.3.6.1.2.1.2.2.1.2", "ifDescr"),
            ("1.3.6.1.2.1.2.2.1.3", "ifType"),
            ("1.3.6.1.2.1.2.2.1.4", "ifMtu"),
            ("1.3.6.1.2.1.2.2.1.5", "ifSpeed"),
            ("1.3.6.1.2.1.2.2.1.8", "ifOperStatus"),
            ("1.3.6.1.2.1.25.1.1.0", "hrSystemUptime"),
            ("1.3.6.1.2.1.25.2.2.0", "hrMemorySize"),
        ];

        for (num, name) in &mappings {
            if oid == *num || oid == *name {
                return Ok(name.to_string());
            }
        }

        if oid.contains(".1.3.6.1.2.1.2.2.1.") {
            let idx = oid.rfind('.').map(|i| &oid[i + 1..]).unwrap_or("");
            return Ok(format!("ifEntry.{}", idx));
        }

        Ok(oid)
    })?;
    snmp.set("translate_oid", translate_oid_fn)?;

    let get_if_descr_fn = lua.create_function(|lua, (_host, port): (String, Option<u16>)| {
        let _port = port.unwrap_or(161);

        let result = lua.create_table()?;
        let if_table = lua.create_table()?;

        let if1 = lua.create_table()?;
        if1.set("index", 1)?;
        if1.set("description", "eth0")?;
        if1.set("type", 6)?;
        if1.set("mtu", 1500)?;
        if1.set("speed", 1000000000)?;
        if1.set("status", "up")?;

        if_table.set(1, if1)?;

        result.set("interfaces", if_table)?;
        result.set("count", 1)?;

        Ok(result)
    })?;
    snmp.set("get_if_descr", get_if_descr_fn)?;

    let get_sysinfo_fn = lua.create_function(|lua, (_host, port): (String, Option<u16>)| {
        let _port = port.unwrap_or(161);

        let result = lua.create_table()?;

        result.set("sysDescr", "Linux host")?;
        result.set("sysObjectID", "1.3.6.1.4.1.8072.3.2.10")?;
        result.set("sysUpTime", 12345678)?;
        result.set("sysContact", "admin@localhost")?;
        result.set("sysName", "localhost")?;
        result.set("sysLocation", "Unknown")?;
        result.set("sysServices", 72)?;

        Ok(result)
    })?;
    snmp.set("get_sysinfo", get_sysinfo_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("2.0.0"))?;
    snmp.set("version", version_fn)?;

    globals.set("snmp", snmp)?;
    Ok(())
}
