//! NSE bin library wrapper
//!
//! Binary pack and unpack functions compatible with NSE.

use mlua::{Lua, Result as LuaResult, Table};

pub fn register_bin_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let bin = lua.create_table()?;

    bin.set(
        "pack",
        lua.create_function(|_lua, args: Table| {
            let format: String = args.get("format")?;
            let values: Table = args.get("values")?;

            let mut result = Vec::new();
            let chars: Vec<char> = format.chars().collect();
            let num_values = values.len().unwrap_or(0);
            let mut values_idx = 0;
            let mut i = 0;

            while i < chars.len() {
                let c = chars[i];

                if c == ' ' || c == '<' || c == '>' || c == '=' {
                    i += 1;
                    continue;
                }

                let mut count: usize = 1;
                if c.is_ascii_digit() {
                    let mut num_str = String::new();
                    while i < chars.len() && chars[i].is_ascii_digit() {
                        num_str.push(chars[i]);
                        i += 1;
                    }
                    count = num_str.parse().unwrap_or(1);
                    if i >= chars.len() {
                        break;
                    }
                    let _ = c;
                }

                match c {
                    'c' | 'b' | 'B' => {
                        for _ in 0..count {
                            if values_idx < num_values as usize {
                                if let Ok(v) = values.get::<i32>(values_idx + 1) {
                                    result.push(v as u8);
                                }
                                values_idx += 1;
                            }
                        }
                    }
                    'h' => {
                        for _ in 0..count {
                            if values_idx < num_values as usize {
                                if let Ok(v) = values.get::<i32>(values_idx + 1) {
                                    let bytes = (v as i16).to_le_bytes();
                                    result.extend_from_slice(&bytes);
                                }
                                values_idx += 1;
                            }
                        }
                    }
                    'H' => {
                        for _ in 0..count {
                            if values_idx < num_values as usize {
                                if let Ok(v) = values.get::<i32>(values_idx + 1) {
                                    let bytes = (v as u16).to_le_bytes();
                                    result.extend_from_slice(&bytes);
                                }
                                values_idx += 1;
                            }
                        }
                    }
                    'i' | 'l' => {
                        for _ in 0..count {
                            if values_idx < num_values as usize {
                                if let Ok(v) = values.get::<i32>(values_idx + 1) {
                                    result.extend_from_slice(&v.to_le_bytes());
                                }
                                values_idx += 1;
                            }
                        }
                    }
                    'I' | 'L' => {
                        for _ in 0..count {
                            if values_idx < num_values as usize {
                                if let Ok(v) = values.get::<u32>(values_idx + 1) {
                                    result.extend_from_slice(&v.to_le_bytes());
                                }
                                values_idx += 1;
                            }
                        }
                    }
                    's' if values_idx < num_values as usize => {
                        if let Ok(s) = values.get::<String>(values_idx + 1) {
                            result.extend_from_slice(s.as_bytes());
                            if count > s.len() {
                                for _ in s.len()..count {
                                    result.push(0);
                                }
                            }
                        }
                        values_idx += 1;
                    }
                    'x' => {
                        for _ in 0..count {
                            result.push(0);
                        }
                    }
                    'z' if values_idx < num_values as usize => {
                        if let Ok(s) = values.get::<String>(values_idx + 1) {
                            result.extend_from_slice(s.as_bytes());
                            result.push(0);
                        }
                        values_idx += 1;
                    }
                    _ => {}
                }
                i += 1;
            }

            Ok(result)
        })?,
    )?;

    bin.set(
        "unpack",
        lua.create_function(|lua, (format, data): (String, String)| {
            let data_bytes = data.as_bytes();
            let result = lua.create_table()?;
            let chars: Vec<char> = format.chars().collect();
            let mut offset = 0;
            let mut index = 1;
            let mut i = 0;

            while i < chars.len() {
                let c = chars[i];

                if c == ' ' || c == '<' || c == '>' || c == '=' {
                    i += 1;
                    continue;
                }

                let mut count: usize = 1;
                if c.is_ascii_digit() {
                    let mut num_str = String::new();
                    while i < chars.len() && chars[i].is_ascii_digit() {
                        num_str.push(chars[i]);
                        i += 1;
                    }
                    count = num_str.parse().unwrap_or(1);
                    if i >= chars.len() {
                        break;
                    }
                }

                match c {
                    'c' | 'b' | 'B' => {
                        for _ in 0..count {
                            if offset < data_bytes.len() {
                                result.set(index, data_bytes[offset] as i32)?;
                                offset += 1;
                                index += 1;
                            }
                        }
                    }
                    'h' => {
                        for _ in 0..count {
                            if offset + 2 <= data_bytes.len() {
                                let val = i16::from_le_bytes([
                                    data_bytes[offset],
                                    data_bytes[offset + 1],
                                ]);
                                result.set(index, val as i32)?;
                                offset += 2;
                                index += 1;
                            }
                        }
                    }
                    'H' => {
                        for _ in 0..count {
                            if offset + 2 <= data_bytes.len() {
                                let val = u16::from_le_bytes([
                                    data_bytes[offset],
                                    data_bytes[offset + 1],
                                ]);
                                result.set(index, val as i32)?;
                                offset += 2;
                                index += 1;
                            }
                        }
                    }
                    'i' | 'l' => {
                        for _ in 0..count {
                            if offset + 4 <= data_bytes.len() {
                                let val = i32::from_le_bytes([
                                    data_bytes[offset],
                                    data_bytes[offset + 1],
                                    data_bytes[offset + 2],
                                    data_bytes[offset + 3],
                                ]);
                                result.set(index, val)?;
                                offset += 4;
                                index += 1;
                            }
                        }
                    }
                    'I' | 'L' => {
                        for _ in 0..count {
                            if offset + 4 <= data_bytes.len() {
                                let val = u32::from_le_bytes([
                                    data_bytes[offset],
                                    data_bytes[offset + 1],
                                    data_bytes[offset + 2],
                                    data_bytes[offset + 3],
                                ]);
                                result.set(index, val)?;
                                offset += 4;
                                index += 1;
                            }
                        }
                    }
                    's' | 'z' => {
                        let mut s = String::new();
                        for _ in 0..count {
                            if offset < data_bytes.len() && data_bytes[offset] != 0 {
                                s.push(data_bytes[offset] as char);
                                offset += 1;
                            } else {
                                break;
                            }
                        }
                        result.set(index, s)?;
                        index += 1;
                    }
                    'x' => {
                        offset += count;
                    }
                    _ => {}
                }
                i += 1;
            }

            Ok(result)
        })?,
    )?;

    bin.set(
        "size",
        lua.create_function(|_lua, format: String| {
            let chars: Vec<char> = format.chars().collect();
            let mut size = 0;
            let mut i = 0;

            while i < chars.len() {
                let c = chars[i];

                if c == ' ' || c == '<' || c == '>' || c == '=' {
                    i += 1;
                    continue;
                }

                let mut count: usize = 1;
                if c.is_ascii_digit() {
                    let mut num_str = String::new();
                    while i < chars.len() && chars[i].is_ascii_digit() {
                        num_str.push(chars[i]);
                        i += 1;
                    }
                    count = num_str.parse().unwrap_or(1);
                }

                match c {
                    'c' | 'b' | 'B' | 'x' => size += count,
                    'h' | 'H' => size += count * 2,
                    'i' | 'l' | 'I' | 'L' => size += count * 4,
                    's' | 'z' => size += count,
                    _ => {}
                }
                i += 1;
            }

            Ok(size)
        })?,
    )?;

    globals.set("bin", bin)?;
    Ok(())
}
