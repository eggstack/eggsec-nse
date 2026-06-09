//! NSE lpeg-utility library wrapper
//!
//! Utility functions for LPEG patterns.
//! Based on Nmap's lpeg-utility library.

use mlua::{Lua, Result as LuaResult};

pub fn register_lpeg_utility_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let lpeg_utility = lua.create_table()?;

    let capture_fn = lua.create_function(|lua, (pattern, text): (String, String)| {
        let result = lua.create_table()?;
        if text.contains(&pattern) {
            result.set(1, pattern.clone())?;
            result.set("match", pattern)?;
        }
        Ok(result)
    })?;
    lpeg_utility.set("capture", capture_fn)?;

    let find_fn = lua.create_function(|lua, (pattern, text): (String, String)| {
        if let Some(pos) = text.find(&pattern) {
            let result = lua.create_table()?;
            result.set(1, pos as u32 + 1)?;
            result.set(2, (pos + pattern.len()) as u32)?;
            Ok(result)
        } else {
            Ok(lua.create_table()?)
        }
    })?;
    lpeg_utility.set("find", find_fn)?;

    let split_fn = lua.create_function(|lua, (pattern, text): (String, String)| {
        let result = lua.create_table()?;
        let parts: Vec<&str> = text.split(&pattern).collect();

        for (i, part) in parts.iter().enumerate() {
            result.set(i + 1, part.to_string())?;
        }

        Ok(result)
    })?;
    lpeg_utility.set("split", split_fn)?;

    let replace_fn = lua.create_function(
        |_lua, (text, pattern, replacement): (String, String, String)| {
            let result = text.replace(&pattern, &replacement);
            Ok(result)
        },
    )?;
    lpeg_utility.set("replace", replace_fn)?;

    let gsub_fn = lua.create_function(
        |_lua, (text, pattern, replacement): (String, String, String)| {
            let result = text.replace(&pattern, &replacement);
            let count = text.matches(&pattern).count();
            Ok((result, count))
        },
    )?;
    lpeg_utility.set("gsub", gsub_fn)?;

    let match_simple_fn = lua.create_function(|_lua, (pattern, text): (String, String)| {
        if text.contains(&pattern) {
            Ok(true)
        } else {
            Ok(false)
        }
    })?;
    lpeg_utility.set("match", match_simple_fn)?;

    let ascii_range_fn = lua.create_function(|lua, (min, max): (u8, u8)| {
        let result = lua.create_table()?;

        let count = (max.saturating_sub(min) + 1) as usize;
        for i in 0..count {
            result.set(i + 1, (min + i as u8) as i32)?;
        }

        Ok(result)
    })?;
    lpeg_utility.set("ascii_range", ascii_range_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    lpeg_utility.set("version", version_fn)?;

    globals.set("lpeg-utility", lpeg_utility)?;
    Ok(())
}
