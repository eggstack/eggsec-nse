//! NSE asn1 library wrapper
//!
//! ASN.1 (Abstract Syntax Notation One) encoding/decoding.
//! Based on Nmap's asn1 library concepts.

use mlua::{Lua, Result as LuaResult};

use super::helpers::parse_hex_pairs;

pub fn register_asn1_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let asn1 = lua.create_table()?;

    let encode_fn = lua.create_function(|_lua, value: String| {
        let encoded: Vec<u8> = value.as_bytes().to_vec();

        let hex: String = encoded.iter().map(|b| format!("{:02X}", b)).collect();
        Ok(hex)
    })?;
    asn1.set("encode", encode_fn)?;

    let decode_fn = lua.create_function(|_lua, hex: String| {
        let bytes = parse_hex_pairs(&hex);
        let decoded = String::from_utf8_lossy(&bytes).to_string();
        Ok(decoded)
    })?;
    asn1.set("decode", decode_fn)?;

    let encode_integer_fn = lua.create_function(|_lua, value: i64| {
        let mut bytes = Vec::new();
        let mut v = value;

        if v == 0 {
            return Ok("00".to_string());
        }

        while v > 0 {
            bytes.push((v & 0xFF) as u8);
            v >>= 8;
        }
        bytes.reverse();

        let hex: String = bytes.iter().map(|b| format!("{:02X}", b)).collect();
        Ok(hex)
    })?;
    asn1.set("encode_integer", encode_integer_fn)?;

    let encode_oid_fn = lua.create_function(|_lua, oid: String| {
        let parts: Vec<u64> = oid.split('.').filter_map(|s| s.parse().ok()).collect();

        if parts.len() < 2 {
            return Ok(String::new());
        }

        let mut result = Vec::new();
        result.push(40 * parts[0] + parts[1]);

        for &p in &parts[2..] {
            let mut bytes = Vec::new();
            let mut v = p;

            bytes.push(v & 0x7F);
            v >>= 7;

            while v > 0 {
                bytes.push((v & 0x7F) | 0x80);
                v >>= 7;
            }

            bytes.reverse();
            result.extend_from_slice(&bytes);
        }

        let hex: String = result.iter().map(|b| format!("{:02X}", b)).collect();
        Ok(hex)
    })?;
    asn1.set("encode_oid", encode_oid_fn)?;

    let encode_length_fn = lua.create_function(|_lua, length: usize| {
        if length < 128 {
            return Ok(format!("{:02X}", length));
        }

        let mut bytes = Vec::new();
        let mut len = length;

        while len > 0 {
            bytes.push((len & 0xFF) as u8);
            len >>= 8;
        }
        bytes.reverse();

        let mut result = format!("{:02X}", 0x80 | bytes.len());
        result.extend(bytes.iter().map(|b| format!("{:02X}", b)));

        Ok(result)
    })?;
    asn1.set("encode_length", encode_length_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    asn1.set("version", version_fn)?;

    globals.set("asn1", asn1)?;
    Ok(())
}
