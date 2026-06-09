//! NSE stringaux library wrapper
//!
//! Auxiliary string functions compatible with NSE.

use mlua::{Lua, Result as LuaResult, Table};

pub fn register_stringaux_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let stringaux = lua.create_table()?;

    stringaux.set(
        "strsplit",
        lua.create_function(|lua, (s, sep): (String, String)| {
            let parts: Vec<&str> = s.split(&sep).collect();
            let result = lua.create_table()?;
            for (i, part) in parts.iter().enumerate() {
                result.set(i + 1, *part)?;
            }
            Ok(result)
        })?,
    )?;

    stringaux.set(
        "strjoin",
        lua.create_function(|_lua, (parts, sep): (Table, String)| {
            let len = parts.len().unwrap_or(0);
            let mut result = String::new();

            for i in 1..=len {
                if let Ok(part) = parts.get::<String>(i) {
                    if i > 1 {
                        result.push_str(&sep);
                    }
                    result.push_str(&part);
                }
            }

            Ok(result)
        })?,
    )?;

    stringaux.set(
        "explode",
        lua.create_function(|lua, (s, sep): (String, String)| {
            let parts: Vec<&str> = s.split(&sep).collect();
            let result = lua.create_table()?;
            for (i, part) in parts.iter().enumerate() {
                result.set(i + 1, *part)?;
            }
            Ok(result)
        })?,
    )?;

    stringaux.set(
        "implode",
        lua.create_function(|_lua, (parts, sep): (Table, String)| {
            let len = parts.len().unwrap_or(0);
            let mut result = String::new();

            for i in 1..=len {
                if let Ok(part) = parts.get::<String>(i) {
                    if i > 1 {
                        result.push_str(&sep);
                    }
                    result.push_str(&part);
                }
            }

            Ok(result)
        })?,
    )?;

    stringaux.set(
        "strip_spaces",
        lua.create_function(|_lua, s: String| {
            let result = s.trim().to_string();
            Ok(result)
        })?,
    )?;

    stringaux.set(
        "split_by_chars",
        lua.create_function(|lua, (s, chars): (String, String)| {
            let parts: Vec<&str> = s.split(&chars).collect();
            let result = lua.create_table()?;
            for (i, part) in parts.iter().enumerate() {
                result.set(i + 1, part.trim())?;
            }
            Ok(result)
        })?,
    )?;

    stringaux.set(
        "to_upper",
        lua.create_function(|_lua, s: String| Ok(s.to_uppercase()))?,
    )?;

    stringaux.set(
        "to_lower",
        lua.create_function(|_lua, s: String| Ok(s.to_lowercase()))?,
    )?;

    stringaux.set(
        "starts_with",
        lua.create_function(|_lua, (s, prefix): (String, String)| Ok(s.starts_with(&prefix)))?,
    )?;

    stringaux.set(
        "ends_with",
        lua.create_function(|_lua, (s, suffix): (String, String)| Ok(s.ends_with(&suffix)))?,
    )?;

    stringaux.set(
        "contains",
        lua.create_function(|_lua, (s, sub): (String, String)| Ok(s.contains(&sub)))?,
    )?;

    stringaux.set(
        "replace",
        lua.create_function(|_lua, (s, old, new): (String, String, String)| {
            Ok(s.replace(&old, &new))
        })?,
    )?;

    stringaux.set(
        "trim",
        lua.create_function(|_lua, s: String| Ok(s.trim().to_string()))?,
    )?;

    stringaux.set(
        "trim_left",
        lua.create_function(|_lua, s: String| Ok(s.trim_start().to_string()))?,
    )?;

    stringaux.set(
        "trim_right",
        lua.create_function(|_lua, s: String| Ok(s.trim_end().to_string()))?,
    )?;

    stringaux.set(
        "pad_left",
        lua.create_function(|_lua, (s, len, pad): (String, usize, Option<String>)| {
            let pad_char = pad.unwrap_or_else(|| " ".to_string());
            let pad_char = pad_char.chars().next().unwrap_or(' ');
            let padding = pad_char.to_string().repeat(len.saturating_sub(s.len()));
            Ok(format!("{}{}", padding, s))
        })?,
    )?;

    stringaux.set(
        "pad_right",
        lua.create_function(|_lua, (s, len, pad): (String, f64, Option<String>)| {
            let pad_char = pad.unwrap_or_else(|| " ".to_string());
            let pad_char = pad_char.chars().next().unwrap_or(' ');
            let len = len as usize;
            let padding = pad_char.to_string().repeat(len.saturating_sub(s.len()));
            Ok(format!("{}{}", s, padding))
        })?,
    )?;

    stringaux.set(
        "reverse",
        lua.create_function(|_lua, s: String| {
            let rev: String = s.chars().rev().collect();
            Ok(rev)
        })?,
    )?;

    stringaux.set(
        "repeat",
        lua.create_function(|_lua, (s, n): (String, usize)| Ok(s.repeat(n)))?,
    )?;

    globals.set("stringaux", stringaux)?;
    Ok(())
}
