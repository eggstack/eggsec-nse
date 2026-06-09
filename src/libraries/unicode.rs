//! NSE unicode library wrapper
//!
//! Unicode utilities.
//! Based on Nmap's unicode library: https://nmap.org/nsedoc/lib/unicode.html

use mlua::{Lua, Result as LuaResult};

const CP437_DECODE: &[u32] = &[
    0x00C7, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, 0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE,
    0x00EC, 0x00C4, 0x00C5, 0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, 0x00FF,
    0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192, 0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1,
    0x00D1, 0x00AA, 0x00BA, 0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB, 0x2591,
    0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255D,
    0x255C, 0x255B, 0x2510, 0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x00E9, 0x00FA, 0x00F9,
    0x00EC, 0x00F5, 0x00F2, 0x2580, 0x2584, 0x2588, 0x2594, 0x258C, 0x2590, 0x2550, 0x256C, 0x2567,
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588,
    0x2584, 0x258C, 0x2590, 0x2580, 0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4,
    0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229, 0x2261, 0x00B1, 0x2265, 0x2264,
    0x2320, 0x2321, 0x00F7, 0x2248, 0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x00B4, 0x00A8,
    0x2260, 0x00C3, 0x00A4, 0x00A6, 0x00A7, 0x00F1, 0x00B6, 0x00DE, 0x00BF, 0x00A9, 0x00AE, 0x2122,
    0x00B8, 0x00A0, 0x00C8, 0x00CA, 0x00CB, 0x00C0, 0x00C1, 0x00C2, 0x00C6, 0x00E4, 0x00E2, 0x00E0,
    0x00E6, 0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF, 0x00C9, 0x00CA, 0x00CB,
    0x00C8, 0x00CD, 0x00CE, 0x00CF, 0x00CC, 0x00D3, 0x00D4, 0x00F8, 0x00D2, 0x00DA, 0x00DB, 0x00D9,
    0x00D5, 0x00C5, 0x00E7, 0x00D8, 0x00D0, 0x00DE, 0x00FE, 0x00FA, 0x00F9, 0x00FB, 0x00FC, 0x00AE,
    0x00A2, 0x00A3, 0x00D5, 0x00B1, 0x00A6, 0x00A5, 0x00A7,
];

const CP437_ENCODE: &[(u32, u8)] = &[
    (0x00C7, 0x80),
    (0x00E9, 0x82),
    (0x00E2, 0x83),
    (0x00E4, 0x84),
    (0x00E0, 0x85),
    (0x00E5, 0x86),
    (0x00E7, 0x87),
    (0x00EA, 0x88),
    (0x00EB, 0x89),
    (0x00E8, 0x8A),
    (0x00EF, 0x8B),
    (0x00EE, 0x8C),
    (0x00EC, 0x8D),
    (0x00C4, 0x8E),
    (0x00C5, 0x8F),
    (0x00C9, 0x90),
    (0x00E6, 0x91),
    (0x00C6, 0x92),
    (0x00F4, 0x93),
    (0x00F6, 0x94),
    (0x00F2, 0x95),
    (0x00FB, 0x96),
    (0x00F9, 0x97),
    (0x00FF, 0x98),
    (0x00D6, 0x99),
    (0x00DC, 0x9A),
    (0x00A2, 0x9B),
    (0x00A3, 0x9C),
    (0x00A5, 0x9D),
    (0x20A7, 0x9E),
    (0x0192, 0x9F),
    (0x00E1, 0xA0),
    (0x00ED, 0xA1),
    (0x00F3, 0xA2),
    (0x00FA, 0xA3),
    (0x00F1, 0xA4),
    (0x00D1, 0xA5),
    (0x00AA, 0xA6),
    (0x00BA, 0xA7),
    (0x00BF, 0xA8),
    (0x2310, 0xA9),
    (0x00AC, 0xAA),
    (0x00BD, 0xAB),
    (0x00BC, 0xAC),
    (0x00A1, 0xAD),
    (0x00AB, 0xAE),
    (0x00BB, 0xAF),
    (0x2591, 0xB0),
    (0x2592, 0xB1),
    (0x2593, 0xB2),
    (0x2502, 0xB3),
    (0x2524, 0xB4),
    (0x2561, 0xB5),
    (0x2562, 0xB6),
    (0x2556, 0xB7),
    (0x2555, 0xB8),
    (0x2563, 0xB9),
    (0x2551, 0xBA),
    (0x2557, 0xBB),
    (0x255D, 0xBC),
    (0x255C, 0xBD),
    (0x255B, 0xBE),
    (0x2510, 0xBF),
    (0x2514, 0xC0),
    (0x2534, 0xC1),
    (0x252C, 0xC2),
    (0x251C, 0xC3),
    (0x2500, 0xC4),
    (0x253C, 0xC5),
    (0x00E9, 0xC6),
    (0x00FA, 0xC7),
    (0x00F9, 0xC8),
    (0x00EC, 0xC9),
    (0x00F5, 0xCA),
    (0x00F2, 0xCB),
    (0x2580, 0xCC),
    (0x2584, 0xCD),
    (0x2588, 0xCE),
    (0x2594, 0xCF),
    (0x258C, 0xD0),
    (0x2590, 0xD1),
    (0x2550, 0xD2),
    (0x256C, 0xD3),
    (0x2567, 0xD4),
    (0x2568, 0xD5),
    (0x2564, 0xD6),
    (0x2565, 0xD7),
    (0x2559, 0xD8),
    (0x2558, 0xD9),
    (0x2552, 0xDA),
    (0x2553, 0xDB),
    (0x256B, 0xDC),
    (0x256A, 0xDD),
    (0x2518, 0xDE),
    (0x250C, 0xDF),
    (0x2588, 0xE0),
    (0x2584, 0xE1),
    (0x258C, 0xE2),
    (0x2590, 0xE3),
    (0x2580, 0xE4),
    (0x03B1, 0xE5),
    (0x00DF, 0xE6),
    (0x0393, 0xE7),
    (0x03C0, 0xE8),
    (0x03A3, 0xE9),
    (0x03C3, 0xEA),
    (0x00B5, 0xEB),
    (0x03C4, 0xEC),
    (0x03A6, 0xED),
    (0x0398, 0xEE),
    (0x03A9, 0xEF),
    (0x03B4, 0xF0),
    (0x221E, 0xF1),
    (0x03C6, 0xF2),
    (0x03B5, 0xF3),
    (0x2229, 0xF4),
    (0x2261, 0xF5),
    (0x00B1, 0xF6),
    (0x2265, 0xF7),
    (0x2264, 0xF8),
    (0x2320, 0xF9),
    (0x2321, 0xFA),
    (0x00F7, 0xFB),
    (0x2248, 0xFC),
    (0x00B0, 0xFD),
    (0x2219, 0xFE),
    (0x00B7, 0xFF),
];

fn find_cp437_encode(cp: u32) -> Option<u8> {
    CP437_ENCODE
        .iter()
        .find(|(code, _)| *code == cp)
        .map(|(_, byte)| *byte)
}

pub fn register_unicode_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let unicode = lua.create_table()?;

    let to_utf8_fn = lua.create_function(|_lua, s: String| Ok(s))?;
    unicode.set("to_utf8", to_utf8_fn)?;

    let from_utf8_fn = lua.create_function(|_lua, s: String| Ok(s))?;
    unicode.set("from_utf8", from_utf8_fn)?;

    let utf8_enc_fn = lua.create_function(|_lua, cp: u32| {
        let mut buf = Vec::new();
        encode_utf8(cp, &mut buf);
        Ok(String::from_utf8_lossy(&buf).to_string())
    })?;
    unicode.set("utf8_enc", utf8_enc_fn)?;

    let utf8_dec_fn = lua.create_function(|_lua, (buf, pos): (String, usize)| {
        let bytes = buf.as_bytes();
        let pos = pos.saturating_sub(1);
        if pos >= bytes.len() {
            return Ok((false, 0));
        }
        match decode_utf8(&bytes[pos..]) {
            Some((cp, _)) => Ok((true, cp)),
            None => Ok((false, 0)),
        }
    })?;
    unicode.set("utf8_dec", utf8_dec_fn)?;

    let utf16_enc_fn = lua.create_function(|_lua, (cp, bigendian): (u32, Option<bool>)| {
        let be = bigendian.unwrap_or(false);
        let mut buf = Vec::new();
        encode_utf16(cp, &mut buf, be);
        let result: String = if be {
            String::from_utf8_lossy(&buf).to_string()
        } else {
            let le_bytes: Vec<u8> = buf
                .chunks(2)
                .flat_map(|c| c.iter().rev().copied())
                .collect();
            String::from_utf8_lossy(&le_bytes).to_string()
        };
        Ok(result)
    })?;
    unicode.set("utf16_enc", utf16_enc_fn)?;

    let utf16_dec_fn = lua.create_function(
        |_lua, (buf, pos, bigendian): (String, usize, Option<bool>)| {
            let be = bigendian.unwrap_or(false);
            let bytes = buf.as_bytes();
            let pos = (pos.saturating_sub(1) * 2).min(bytes.len().saturating_sub(1));

            if pos + 1 >= bytes.len() {
                return Ok((false, 0));
            }

            let cp = if be {
                ((bytes[pos] as u32) << 8) | (bytes[pos + 1] as u32)
            } else {
                (bytes[pos] as u32) | ((bytes[pos + 1] as u32) << 8)
            };

            Ok((true, cp))
        },
    )?;
    unicode.set("utf16_dec", utf16_dec_fn)?;

    let utf16to8_fn = lua.create_function(|_lua, from: String| {
        let bytes = from.as_bytes();
        let mut result = String::new();
        let mut pos = 0;

        while pos + 1 < bytes.len() {
            let cp = (bytes[pos] as u32) | ((bytes[pos + 1] as u32) << 8);
            let mut buf = Vec::new();
            encode_utf8(cp, &mut buf);
            result.push_str(&String::from_utf8_lossy(&buf));
            pos += 2;
        }

        Ok(result)
    })?;
    unicode.set("utf16to8", utf16to8_fn)?;

    let cp437_enc_fn = lua.create_function(|_lua, cp: u32| match find_cp437_encode(cp) {
        Some(b) => Ok(Some(b as u32)),
        None => Ok(None::<u32>),
    })?;
    unicode.set("cp437_enc", cp437_enc_fn)?;

    let cp437_dec_fn = lua.create_function(|_lua, (buf, pos): (String, usize)| {
        let bytes = buf.as_bytes();
        let pos = pos.saturating_sub(1);
        if pos >= bytes.len() {
            return Ok((false, 0));
        }
        let idx = bytes[pos] as usize;
        if idx < CP437_DECODE.len() {
            Ok((true, CP437_DECODE[idx]))
        } else {
            Ok((false, 0))
        }
    })?;
    unicode.set("cp437_dec", cp437_dec_fn)?;

    let chardet_fn = lua.create_function(|_lua, (buf, _len): (String, Option<usize>)| {
        let bytes = buf.as_bytes();

        if bytes.is_empty() {
            return Ok("ascii".to_string());
        }

        let mut has_high = false;
        let mut has_utf8 = true;

        for &byte in bytes {
            if byte >= 0x80 {
                has_high = true;
            }

            if byte & 0x80 == 0 {
                continue;
            } else if byte & 0xE0 == 0xC0 {
                continue;
            } else if byte & 0xF0 == 0xE0 {
                continue;
            } else if byte & 0xF8 == 0xF0 {
                continue;
            } else {
                has_utf8 = false;
            }
        }

        if has_utf8 && !has_high {
            Ok("ascii".to_string())
        } else if has_utf8 {
            Ok("UTF-8".to_string())
        } else if has_high {
            Ok("binary".to_string())
        } else {
            Ok("ascii".to_string())
        }
    })?;
    unicode.set("chardet", chardet_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    unicode.set("version", version_fn)?;

    globals.set("unicode", unicode)?;
    Ok(())
}

fn encode_utf8(cp: u32, buf: &mut Vec<u8>) {
    if cp < 0x80 {
        buf.push(cp as u8);
    } else if cp < 0x800 {
        buf.push(0xC0 | ((cp >> 6) & 0x1F) as u8);
        buf.push(0x80 | (cp & 0x3F) as u8);
    } else if cp < 0x10000 {
        buf.push(0xE0 | ((cp >> 12) & 0x0F) as u8);
        buf.push(0x80 | ((cp >> 6) & 0x3F) as u8);
        buf.push(0x80 | (cp & 0x3F) as u8);
    } else {
        buf.push(0xF0 | ((cp >> 18) & 0x07) as u8);
        buf.push(0x80 | ((cp >> 12) & 0x3F) as u8);
        buf.push(0x80 | ((cp >> 6) & 0x3F) as u8);
        buf.push(0x80 | (cp & 0x3F) as u8);
    }
}

fn decode_utf8(bytes: &[u8]) -> Option<(u32, usize)> {
    if bytes.is_empty() {
        return None;
    }

    let (cp, len) = if bytes[0] & 0x80 == 0 {
        (bytes[0] as u32, 1)
    } else if bytes[0] & 0xE0 == 0xC0 {
        if bytes.len() < 2 {
            return None;
        }
        let cp = ((bytes[0] & 0x1F) as u32) << 6 | ((bytes[1] & 0x3F) as u32);
        (cp, 2)
    } else if bytes[0] & 0xF0 == 0xE0 {
        if bytes.len() < 3 {
            return None;
        }
        let cp = ((bytes[0] & 0x0F) as u32) << 12
            | ((bytes[1] & 0x3F) as u32) << 6
            | ((bytes[2] & 0x3F) as u32);
        (cp, 3)
    } else if bytes[0] & 0xF8 == 0xF0 {
        if bytes.len() < 4 {
            return None;
        }
        let cp = ((bytes[0] & 0x07) as u32) << 18
            | ((bytes[1] & 0x3F) as u32) << 12
            | ((bytes[2] & 0x3F) as u32) << 6
            | ((bytes[3] & 0x3F) as u32);
        (cp, 4)
    } else {
        return None;
    };

    Some((cp, len))
}

fn encode_utf16(cp: u32, buf: &mut Vec<u8>, bigendian: bool) {
    if cp < 0x10000 {
        let bytes = if bigendian {
            vec![(cp >> 8) as u8, (cp & 0xFF) as u8]
        } else {
            vec![(cp & 0xFF) as u8, (cp >> 8) as u8]
        };
        buf.extend(bytes);
    } else {
        let cp = cp - 0x10000;
        let high = 0xD800 | ((cp >> 10) & 0x3FF);
        let low = 0xDC00 | (cp & 0x3FF);
        if bigendian {
            buf.push((high >> 8) as u8);
            buf.push((high & 0xFF) as u8);
            buf.push((low >> 8) as u8);
            buf.push((low & 0xFF) as u8);
        } else {
            buf.push((high & 0xFF) as u8);
            buf.push((high >> 8) as u8);
            buf.push((low & 0xFF) as u8);
            buf.push((low >> 8) as u8);
        }
    }
}
