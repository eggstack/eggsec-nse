//! NSE asn1 library wrapper
//!
//! ASN.1 (Abstract Syntax Notation One) encoding/decoding.
//! Based on Nmap's asn1 library concepts.

use mlua::{Lua, Result as LuaResult};

use super::helpers::parse_hex_pairs;

fn encode_base128(value: u64, output: &mut Vec<u8>) {
    let mut bytes = vec![(value & 0x7F) as u8];
    let mut value = value >> 7;

    while value > 0 {
        bytes.push(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }

    output.extend(bytes.into_iter().rev());
}

fn parse_oid(oid: &str) -> LuaResult<Vec<u64>> {
    let mut parts = Vec::new();

    for part in oid.split('.') {
        if part.is_empty() {
            return Err(mlua::Error::RuntimeError(format!(
                "Invalid OID '{}': empty component",
                oid
            )));
        }

        let value = part.parse::<u64>().map_err(|_| {
            mlua::Error::RuntimeError(format!("Invalid OID '{}': non-numeric component", oid))
        })?;
        parts.push(value);
    }

    Ok(parts)
}

fn encode_oid_hex(oid: &str) -> LuaResult<String> {
    let parts = parse_oid(oid)?;

    if parts.len() < 2 {
        return Ok(String::new());
    }

    if parts[0] > 2 {
        return Err(mlua::Error::RuntimeError(format!(
            "Invalid OID '{}': first component must be 0, 1, or 2",
            oid
        )));
    }

    if parts[0] < 2 && parts[1] > 39 {
        return Err(mlua::Error::RuntimeError(format!(
            "Invalid OID '{}': second component must be less than 40 when first component is {}",
            oid, parts[0]
        )));
    }

    let mut result = Vec::new();
    encode_base128((parts[0] * 40) + parts[1], &mut result);

    for &part in &parts[2..] {
        encode_base128(part, &mut result);
    }

    Ok(result.iter().map(|b| format!("{:02X}", b)).collect())
}

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

    let encode_oid_fn = lua.create_function(|_lua, oid: String| encode_oid_hex(&oid))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_oid_uses_base128_for_large_components() {
        assert_eq!(
            encode_oid_hex("1.2.840.113549").expect("valid oid"),
            "2A864886F70D"
        );
    }

    #[test]
    fn encode_oid_uses_base128_for_large_second_component_under_first_two() {
        assert_eq!(encode_oid_hex("2.999").expect("valid oid"), "8837");
    }

    #[test]
    fn encode_oid_rejects_non_numeric_components() {
        assert!(encode_oid_hex("1.bad.840").is_err());
    }

    #[test]
    fn encode_oid_rejects_invalid_first_arc() {
        assert!(encode_oid_hex("3.1").is_err());
    }

    #[test]
    fn encode_oid_rejects_invalid_second_arc_for_first_zero_or_one() {
        assert!(encode_oid_hex("1.40").is_err());
    }
}
