//! NSE idna library wrapper
//!
//! IDNA (Internationalized Domain Names in Applications) support.
//! Based on Nmap's idna library.

use mlua::{Lua, Result as LuaResult};

pub fn register_idna_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let idna = lua.create_table()?;

    idna.set(
        "to_ascii",
        lua.create_function(|_lua, domain: String| {
            // Simple ASCII conversion - in real impl would use proper IDNA algorithm
            let ascii = domain
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                        c.to_ascii_lowercase()
                    } else {
                        'x'
                    }
                })
                .collect::<String>();
            Ok(ascii)
        })?,
    )?;

    idna.set(
        "to_unicode",
        lua.create_function(|_lua, ascii_domain: String| {
            // Simple Unicode conversion - would use proper algorithm in full impl
            Ok(ascii_domain)
        })?,
    )?;

    idna.set(
        "is_ascii",
        lua.create_function(|_lua, domain: String| Ok(domain.is_ascii()))?,
    )?;

    idna.set(
        "is_valid",
        lua.create_function(|_lua, domain: String| {
            // Basic validation
            if domain.is_empty() || domain.len() > 253 {
                return Ok(false);
            }

            // Check for valid characters
            for label in domain.split('.') {
                if label.is_empty() || label.len() > 63 {
                    return Ok(false);
                }
                if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    return Ok(false);
                }
                if label.starts_with('-') || label.ends_with('-') {
                    return Ok(false);
                }
            }

            Ok(true)
        })?,
    )?;

    idna.set(
        "compare",
        lua.create_function(|_lua, (domain1, domain2): (String, String)| {
            let ascii1 = domain1.to_lowercase();
            let ascii2 = domain2.to_lowercase();
            Ok(ascii1 == ascii2)
        })?,
    )?;

    idna.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("idna", idna)?;
    Ok(())
}
