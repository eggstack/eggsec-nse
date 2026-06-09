//! NSE lpeg library wrapper
//!
//! LPEG (Lua Parsing Expression Grammars) pattern matching.
//! Based on Nmap's lpeg library: https://nmap.org/nsedoc/lib/lpeg.html
//!
//! # Implementation Note
//!
//! This is a **compatibility wrapper** that uses Rust's `regex` crate as a backend.
//! True LPeg (Lua Parsing Expression Grammars) is not available in this implementation.
//!
//! ## Differences from Nmap's LPeg:
//!
//! - **True LPeg grammars**: Not supported - only simple regex patterns work
//! - **Performance**: Regex may be slower than native LPeg for complex patterns
//! - **Pattern matching**: Uses Rust regex syntax, not LPeg syntax
//! - **Captures**: Limited capture group support compared to LPeg
//!
//! ## Scripts relying on LPeg may not work correctly if they:
//! - Use LPeg grammars (`:grammar()` method)
//! - Require advanced LPeg features like `lpeg.C()`, `lpeg.Cg()`, `lpeg.Cb()`
//! - Use LPeg's position captures or table captures
//!
//! For most common NSE scripts that only use basic pattern matching,
//! this implementation should work as a fallback.

use mlua::{Lua, Result as LuaResult, Table, Value};
use regex::RegexBuilder;

pub fn register_lpeg_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let lpeg = lua.create_table()?;

    // lpeg.P(pattern) - Create a pattern
    let p_fn = lua.create_function(|lua, pattern: String| {
        let pattern_table = lua.create_table()?;
        pattern_table.set("pattern", pattern.clone())?;
        pattern_table.set("type", "P")?;
        Ok(pattern_table)
    })?;
    lpeg.set("P", p_fn)?;

    // lpeg.R(range) - Create a range pattern
    let r_fn = lua.create_function(|lua, range: String| {
        let pattern_table = lua.create_table()?;
        pattern_table.set("range", range.clone())?;
        pattern_table.set("type", "R")?;
        Ok(pattern_table)
    })?;
    lpeg.set("R", r_fn)?;

    // lpeg.S(set) - Create a set pattern
    let s_fn = lua.create_function(|lua, set: String| {
        let pattern_table = lua.create_table()?;
        pattern_table.set("set", set.clone())?;
        pattern_table.set("type", "S")?;
        Ok(pattern_table)
    })?;
    lpeg.set("S", s_fn)?;

    // lpeg.V(varname) - Create a variable pattern
    let v_fn = lua.create_function(|lua, varname: String| {
        let pattern_table = lua.create_table()?;
        pattern_table.set("varname", varname.clone())?;
        pattern_table.set("type", "V")?;
        Ok(pattern_table)
    })?;
    lpeg.set("V", v_fn)?;

    // lpeg.C(capture) - Create a capture
    let c_fn = lua.create_function(|lua, pattern: Table| {
        let capture_table = lua.create_table()?;
        capture_table.set(
            "pattern",
            pattern.get::<String>("pattern").unwrap_or_default(),
        )?;
        capture_table.set("type", "C")?;
        Ok(capture_table)
    })?;
    lpeg.set("C", c_fn)?;

    // lpeg.Cf(capture, func) - Create a folding capture
    let cf_fn = lua.create_function(|lua, (pattern, _func): (Table, Table)| {
        let capture_table = lua.create_table()?;
        capture_table.set(
            "pattern",
            pattern.get::<String>("pattern").unwrap_or_default(),
        )?;
        capture_table.set("type", "Cf")?;
        Ok(capture_table)
    })?;
    lpeg.set("Cf", cf_fn)?;

    // lpeg.Cg(capture, name) - Create a named capture
    let cg_fn = lua.create_function(|lua, (pattern, name): (Table, String)| {
        let capture_table = lua.create_table()?;
        capture_table.set(
            "pattern",
            pattern.get::<String>("pattern").unwrap_or_default(),
        )?;
        capture_table.set("name", name)?;
        capture_table.set("type", "Cg")?;
        Ok(capture_table)
    })?;
    lpeg.set("Cg", cg_fn)?;

    // lpeg.Cmt(capture, func) - Create a match-time capture
    let cmt_fn = lua.create_function(|lua, (pattern, _func): (Table, Table)| {
        let capture_table = lua.create_table()?;
        capture_table.set(
            "pattern",
            pattern.get::<String>("pattern").unwrap_or_default(),
        )?;
        capture_table.set("type", "Cmt")?;
        Ok(capture_table)
    })?;
    lpeg.set("Cmt", cmt_fn)?;

    // lpeg.Cs(capture) - Create a substitution capture
    let cs_fn = lua.create_function(|lua, pattern: Table| {
        let capture_table = lua.create_table()?;
        capture_table.set(
            "pattern",
            pattern.get::<String>("pattern").unwrap_or_default(),
        )?;
        capture_table.set("type", "Cs")?;
        Ok(capture_table)
    })?;
    lpeg.set("Cs", cs_fn)?;

    // lpeg.Ct(capture) - Create a table capture
    let ct_fn = lua.create_function(|lua, pattern: Table| {
        let capture_table = lua.create_table()?;
        capture_table.set(
            "pattern",
            pattern.get::<String>("pattern").unwrap_or_default(),
        )?;
        capture_table.set("type", "Ct")?;
        Ok(capture_table)
    })?;
    lpeg.set("Ct", ct_fn)?;

    // lpeg.Cc(value) - Create a constant capture
    let cc_fn = lua.create_function(|lua, value: String| {
        let capture_table = lua.create_table()?;
        capture_table.set("value", value)?;
        capture_table.set("type", "Cc")?;
        Ok(capture_table)
    })?;
    lpeg.set("Cc", cc_fn)?;

    // lpeg.match(pattern, text) - Match pattern against text
    let match_fn = lua.create_function(|lua, (pattern, text): (Table, String)| {
        let pat = pattern.get::<String>("pattern").unwrap_or_default();

        match RegexBuilder::new(&pat).size_limit(50_000).build() {
            Ok(re) => {
                if let Some(m) = re.find(&text) {
                    let result = lua.create_table()?;
                    result.set(1, m.start() + 1)?; // Lua is 1-indexed
                    result.set(2, m.end())?;
                    result.set("match", m.as_str())?;
                    Ok(Value::Table(result))
                } else {
                    Ok(Value::Nil)
                }
            }
            Err(_) => Ok(Value::Nil),
        }
    })?;
    lpeg.set("match", match_fn)?;

    // lpeg.find(pattern, text) - Find pattern in text
    let find_fn = lua.create_function(
        |lua, (pattern, text, init): (Table, String, Option<usize>)| {
            let pat = pattern.get::<String>("pattern").unwrap_or_default();
            let start = init.unwrap_or(1).saturating_sub(1);

            if start < text.len() {
                match RegexBuilder::new(&pat).size_limit(50_000).build() {
                    Ok(re) => {
                        let search_text = &text[start..];
                        if let Some(m) = re.find(search_text) {
                            let result = lua.create_table()?;
                            result.set(1, start + m.start() + 1)?; // Lua is 1-indexed
                            result.set(2, start + m.end())?;
                            Ok(result)
                        } else {
                            Ok(lua.create_table()?)
                        }
                    }
                    Err(_) => Ok(lua.create_table()?),
                }
            } else {
                Ok(lua.create_table()?)
            }
        },
    )?;
    lpeg.set("find", find_fn)?;

    // lpeg.gsub(pattern, text, replacement) - Global substitution
    let gsub_fn = lua.create_function(
        |_lua, (pattern, text, replacement): (String, String, String)| match RegexBuilder::new(
            &pattern,
        )
        .size_limit(50_000)
        .build()
        {
            Ok(re) => {
                let new_str = re.replace_all(&text, replacement.as_str());
                let count = re.find_iter(&text).count();
                let result = _lua.create_table()?;
                result.set(1, new_str)?;
                result.set(2, count)?;
                Ok(result)
            }
            Err(e) => Err(mlua::Error::RuntimeError(e.to_string())),
        },
    )?;
    lpeg.set("gsub", gsub_fn)?;

    // lpeg.B(pattern) - Create a backtrack pattern
    let b_fn = lua.create_function(|lua, pattern: Table| {
        let pattern_table = lua.create_table()?;
        pattern_table.set(
            "pattern",
            pattern.get::<String>("pattern").unwrap_or_default(),
        )?;
        pattern_table.set("type", "B")?;
        Ok(pattern_table)
    })?;
    lpeg.set("B", b_fn)?;

    // lpeg.type(value) - Get the type of a pattern
    let type_fn = lua.create_function(|_lua, value: Value| match value {
        Value::Table(t) => match t.get::<String>("type") {
            Ok(t) => Ok(t),
            _ => match t.get::<String>("pattern") {
                Ok(_) => Ok("pattern".to_string()),
                _ => Ok("table".to_string()),
            },
        },
        _ => Ok("unknown".to_string()),
    })?;
    lpeg.set("type", type_fn)?;

    // lpeg.version() - Get version
    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    lpeg.set("version", version_fn)?;

    // lpeg.setmaxstack(size) - Set maximum stack size
    let setmaxstack_fn = lua.create_function(|_lua, size: usize| Ok(size))?;
    lpeg.set("setmaxstack", setmaxstack_fn)?;

    globals.set("lpeg", lpeg)?;
    Ok(())
}
