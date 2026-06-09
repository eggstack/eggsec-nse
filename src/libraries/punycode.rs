//! NSE punycode library wrapper
//!
//! Punycode encoding/decoding for internationalized domain names.
//! Based on Nmap's punycode library.

use mlua::{Lua, Result as LuaResult};

pub fn register_punycode_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let punycode = lua.create_table()?;

    let encode_fn = lua.create_function(|_lua, domain: String| {
        if domain.starts_with("xn--") {
            return Ok(domain);
        }

        let mut encoded = String::new();
        let mut has_non_ascii = false;

        for c in domain.chars() {
            if c.is_ascii() {
                encoded.push(c.to_ascii_lowercase());
            } else {
                has_non_ascii = true;
                encoded.push_str(&encode_codepoint(c as u32));
            }
        }

        if has_non_ascii {
            Ok(format!("xn--{}", encoded))
        } else {
            Ok(encoded)
        }
    })?;
    punycode.set("encode", encode_fn)?;

    let decode_fn = lua.create_function(|_lua, domain: String| {
        if let Some(encoded) = domain.strip_prefix("xn--") {
            let mut decoded = String::new();
            let mut buffer = String::new();

            for c in encoded.chars() {
                if c.is_ascii() {
                    if !buffer.is_empty() {
                        if let Some(cp) = decode_codepoint(&buffer) {
                            decoded.push(cp);
                        }
                        buffer.clear();
                    }
                    decoded.push(c);
                } else {
                    buffer.push(c);
                }
            }

            if !buffer.is_empty() {
                if let Some(cp) = decode_codepoint(&buffer) {
                    decoded.push(cp);
                }
            }

            Ok(decoded)
        } else {
            Ok(domain)
        }
    })?;
    punycode.set("decode", decode_fn)?;

    let is_punycode_fn =
        lua.create_function(|_lua, domain: String| Ok(domain.starts_with("xn--")))?;
    punycode.set("is_punycode", is_punycode_fn)?;

    let encode_uri_fn = lua.create_function(|_lua, uri: String| {
        let mut result = String::new();
        let mut has_host = false;
        let mut host_start = 0;

        if let Some(pos) = uri.find("://") {
            result.push_str(&uri[..pos + 3]);
            host_start = pos + 3;
            has_host = true;
        }

        if has_host {
            let host_end = uri.find('/').unwrap_or(uri.len());
            let host = &uri[host_start..host_end];
            let encoded = if host.starts_with("xn--") {
                host[4..].to_string()
            } else {
                let mut enc = String::new();
                for c in host.chars() {
                    if c.is_ascii() {
                        enc.push(c.to_ascii_lowercase());
                    } else {
                        enc.push_str(&encode_codepoint(c as u32));
                    }
                }
                enc
            };
            result.push_str(&encoded);

            if host_end < uri.len() {
                result.push_str(&uri[host_end..]);
            }
        } else {
            result = uri;
        }

        Ok(result)
    })?;
    punycode.set("encode_uri", encode_uri_fn)?;

    let to_ascii_fn = lua.create_function(|_lua, domain: String| {
        let ascii: String = domain
            .chars()
            .map(|c| {
                if c.is_ascii() {
                    c.to_ascii_lowercase()
                } else {
                    '?'
                }
            })
            .collect();
        Ok(ascii)
    })?;
    punycode.set("to_ascii", to_ascii_fn)?;

    let to_unicode_fn = lua.create_function(|_lua, domain: String| {
        let decoded = if let Some(encoded) = domain.strip_prefix("xn--") {
            let mut result = String::new();
            let mut buffer = String::new();

            for c in encoded.chars() {
                if c.is_ascii() {
                    if !buffer.is_empty() {
                        if let Some(cp) = decode_codepoint(&buffer) {
                            result.push(cp);
                        }
                        buffer.clear();
                    }
                    result.push(c);
                } else {
                    buffer.push(c);
                }
            }

            if !buffer.is_empty() {
                if let Some(cp) = decode_codepoint(&buffer) {
                    result.push(cp);
                }
            }
            result
        } else {
            domain
        };

        Ok(decoded)
    })?;
    punycode.set("to_unicode", to_unicode_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    punycode.set("version", version_fn)?;

    globals.set("punycode", punycode)?;
    Ok(())
}

fn encode_codepoint(cp: u32) -> String {
    let _base: u32 = 0xAC00;
    if cp < 128 {
        return format!("{:x}", cp);
    }

    let mut result = String::new();
    let mut n = cp;

    loop {
        let digit = (n % 35) as u8;
        n /= 35;

        let char = if digit < 26 {
            (b'a' + digit) as char
        } else {
            (b'0' + digit - 26) as char
        };
        result.push(char);

        if n == 0 {
            break;
        }
    }

    result
}

fn decode_codepoint(s: &str) -> Option<char> {
    let mut result: u32 = 0;
    let mut base: u32 = 35;

    for c in s.chars() {
        let digit = if c.is_ascii_alphanumeric() {
            if c.is_ascii_alphabetic() {
                (c.to_ascii_lowercase() as u32) - (b'a' as u32) + 26
            } else {
                (c as u32) - (b'0' as u32)
            }
        } else {
            return None;
        };

        result = result * base + digit;
        base = base.saturating_sub(1);
    }

    char::from_u32(result)
}
