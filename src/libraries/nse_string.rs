//! NSE string library wrapper
//!
//! String manipulation utilities for NSE scripts.
//! Based on Lua's string library extensions.

use mlua::{Lua, LuaResult};

pub fn register_string_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();

    let string = lua.create_table().expect("Failed to create string table");

    string.set(
        "unescape",
        lua.create_function(|_lua, s: String| {
            let mut result = String::new();
            let mut chars = s.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    if let Some(n) = chars.next() {
                        match n {
                            'n' => result.push('\n'),
                            'r' => result.push('\r'),
                            't' => result.push('\t'),
                            '\\' => result.push('\\'),
                            '"' => result.push('"'),
                            'x' => {
                                let hex: String = chars.by_ref().take(2).collect();
                                if let Ok(b) = u8::from_str_radix(&hex, 16) {
                                    result.push(b as char);
                                }
                            }
                            _ => result.push(n),
                        }
                    }
                } else {
                    result.push(c);
                }
            }
            Ok(result)
        })?,
    )?;

    string.set(
        "escape",
        lua.create_function(|_lua, s: String| {
            let result: String = s
                .chars()
                .map(|c| match c {
                    '\n' => "\\n".to_string(),
                    '\r' => "\\r".to_string(),
                    '\t' => "\\t".to_string(),
                    '\\' => "\\\\".to_string(),
                    '"' => "\\\"".to_string(),
                    c if c.is_control() => format!("\\x{:02x}", c as u8),
                    c => c.to_string(),
                })
                .collect();
            Ok(result)
        })?,
    )?;

    string.set(
        "random",
        lua.create_function(|_lua, (length, charset): (usize, Option<String>)| {
            let charset = charset.unwrap_or_else(|| {
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_string()
            });
            let chars: Vec<char> = charset.chars().collect();
            let result: String = (0..length.max(1))
                .map(|_| chars[rand::random::<usize>() % chars.len()])
                .collect();
            Ok(result)
        })?,
    )?;

    string.set(
        "random_alpha",
        lua.create_function(|_lua, length: usize| {
            let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let chars: Vec<char> = charset.chars().collect();
            let result: String = (0..length.max(1))
                .map(|_| chars[rand::random::<usize>() % chars.len()])
                .collect();
            Ok(result)
        })?,
    )?;

    string.set(
        "random_numeric",
        lua.create_function(|_lua, length: usize| {
            let charset = "0123456789";
            let chars: Vec<char> = charset.chars().collect();
            let result: String = (0..length.max(1))
                .map(|_| chars[rand::random::<usize>() % chars.len()])
                .collect();
            Ok(result)
        })?,
    )?;

    string.set(
        "random_alphanumeric",
        lua.create_function(|_lua, length: usize| {
            let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            let chars: Vec<char> = charset.chars().collect();
            let result: String = (0..length.max(1))
                .map(|_| chars[rand::random::<usize>() % chars.len()])
                .collect();
            Ok(result)
        })?,
    )?;

    globals.set("string", string)?;
    Ok(())
}
