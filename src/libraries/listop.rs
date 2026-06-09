//! NSE listop library wrapper
//!
//! List operations utility functions.
//! Based on Nmap's listop library.

use mlua::{Lua, Result as LuaResult, Table};

pub fn register_listop_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let listop = lua.create_table()?;

    let concat_fn = lua.create_function(|_lua, (list, sep): (Table, Option<String>)| {
        let sep = sep.unwrap_or_default();
        let mut parts = Vec::new();
        for i in 1..=list.len().unwrap_or(0) {
            if let Ok(s) = list.get::<String>(i) {
                parts.push(s);
            }
        }
        Ok(parts.join(&sep))
    })?;
    listop.set("concat", concat_fn)?;

    let reverse_fn = lua.create_function(|lua, list: Table| {
        let len = list.len().unwrap_or(0);
        let result = lua.create_table()?;
        for i in 1..=len {
            if let Ok(v) = list.get::<mlua::Value>(i) {
                result.set(len - i + 1, v)?;
            }
        }
        Ok(result)
    })?;
    listop.set("reverse", reverse_fn)?;

    let join_fn = lua.create_function(|_lua, (list, sep): (Table, Option<String>)| {
        let sep = sep.unwrap_or_default();
        let mut parts = Vec::new();
        for i in 1..=list.len().unwrap_or(0) {
            if let Ok(s) = list.get::<String>(i) {
                parts.push(s);
            }
        }
        Ok(parts.join(&sep))
    })?;
    listop.set("join", join_fn)?;

    let slice_fn = lua.create_function(
        |lua, (list, start, end_val): (Table, Option<usize>, Option<usize>)| {
            let len = list.len().unwrap_or(0) as usize;
            let start = start.unwrap_or(1);
            let end_val = end_val.unwrap_or(len);

            let result = lua.create_table()?;
            let mut j = 1;
            for i in start..=end_val.min(len) {
                if let Ok(v) = list.get::<mlua::Value>(i) {
                    result.set(j, v)?;
                    j += 1;
                }
            }
            Ok(result)
        },
    )?;
    listop.set("slice", slice_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    listop.set("version", version_fn)?;

    globals.set("listop", listop)?;
    Ok(())
}
