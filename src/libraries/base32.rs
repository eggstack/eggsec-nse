//! NSE base32 library wrapper
//!
//! Base32 encoding and decoding following RFC 4648.
//! Based on Nmap's base32 library: https://nmap.org/nsedoc/lib/base32.html

use mlua::{Lua, Result as LuaResult};

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn encode_base32(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut output = String::new();
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for &byte in input {
        buffer = (buffer << 8) | (byte as u64);
        bits_left += 8;

        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            output.push(BASE32_ALPHABET[index] as char);
        }
    }

    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        output.push(BASE32_ALPHABET[index] as char);
    }

    output
}

fn decode_base32(input: &str) -> Option<Vec<u8>> {
    let input = input.to_uppercase().replace('=', "");
    if input.is_empty() {
        return Some(Vec::new());
    }

    let mut output = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits_left = 0;

    for c in input.chars() {
        let value = match c {
            'A'..='Z' => c as u64 - 'A' as u64,
            '2'..='7' => c as u64 - '2' as u64 + 26,
            _ => return None,
        };

        buffer = (buffer << 5) | value;
        bits_left += 5;

        if bits_left >= 8 {
            bits_left -= 8;
            output.push(((buffer >> bits_left) & 0xFF) as u8);
        }
    }

    Some(output)
}

pub fn register_base32_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let base32 = lua.create_table()?;

    let encode_fn = lua.create_function(|_lua, s: String| Ok(encode_base32(s.as_bytes())))?;
    base32.set("encode", encode_fn)?;

    let decode_fn = lua.create_function(|_lua, s: String| match decode_base32(&s) {
        Some(bytes) => Ok(String::from_utf8_lossy(&bytes).to_string()),
        None => Ok(String::new()),
    })?;
    base32.set("decode", decode_fn)?;

    let decrypt_fn = lua.create_function(|_lua, s: String| match decode_base32(&s) {
        Some(bytes) => Ok(String::from_utf8_lossy(&bytes).to_string()),
        None => Ok(String::new()),
    })?;
    base32.set("decrypt", decrypt_fn)?;

    let encrypt_fn = lua.create_function(|_lua, s: String| Ok(encode_base32(s.as_bytes())))?;
    base32.set("encrypt", encrypt_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    base32.set("version", version_fn)?;

    globals.set("base32", base32)?;
    Ok(())
}
