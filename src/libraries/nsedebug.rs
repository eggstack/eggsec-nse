//! NSE nsedebug library wrapper
//!
//! Debugging functions for NSE scripts.

use mlua::{Lua, Result as LuaResult, Table};

pub fn register_nsedebug_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let nsedebug = lua.create_table()?;

    nsedebug.set(
        "trace",
        lua.create_function(|_lua, (level, msg): (Option<i32>, String)| {
            let level = level.unwrap_or(1);
            eprintln!("[NSE DEBUG {}] {}", level, msg);
            Ok(())
        })?,
    )?;

    nsedebug.set(
        "dump",
        lua.create_function(|lua, (name, value): (Option<String>, Table)| {
            let name = name.unwrap_or_else(|| "table".to_string());
            let dump = lua.create_table()?;
            dump.set("name", name)?;
            dump.set("type", "table")?;
            dump.set("size", value.len().unwrap_or(0))?;
            Ok(dump)
        })?,
    )?;

    nsedebug.set(
        "table",
        lua.create_function(|lua, t: Table| {
            let result = lua.create_table()?;
            result.set("type", "table")?;
            result.set("size", t.len().unwrap_or(0))?;
            Ok(result)
        })?,
    )?;

    nsedebug.set(
        "memory",
        lua.create_function(|lua, _: ()| {
            let result = lua.create_table()?;
            result.set("used", 0)?;
            result.set("peak", 0)?;
            Ok(result)
        })?,
    )?;

    nsedebug.set(
        "spending",
        lua.create_function(|_lua, enable: Option<bool>| Ok(enable.unwrap_or(false)))?,
    )?;

    // line - Print debug line number information
    nsedebug.set(
        "line",
        lua.create_function(|_lua, (level, msg): (Option<i32>, String)| {
            let level = level.unwrap_or(1);
            eprintln!("[NSE DEBUG:L{}] {}", level, msg);
            Ok(())
        })?,
    )?;

    // traceback - Print Lua traceback for debugging
    nsedebug.set(
        "traceback",
        lua.create_function(|_lua, (msg, level): (Option<String>, Option<i32>)| {
            let msg = msg.unwrap_or_else(|| "".to_string());
            let _level = level.unwrap_or(2);

            eprintln!("[NSE TRACEBACK] {}", msg);
            eprintln!("Stack trace (most recent call last):");
            // Note: Full traceback would require debug library access
            // which is not available in mlua by default

            Ok(())
        })?,
    )?;

    // get_memory_usage - Get current memory usage info
    nsedebug.set(
        "get_memory_usage",
        lua.create_function(|lua, _: ()| {
            let result = lua.create_table()?;

            // Estimate memory usage (simplified - actual implementation would track allocations)
            #[cfg(not(target_os = "windows"))]
            {
                use std::mem::size_of;
                // Rough estimation - not actual RSS
                result.set("allocated", size_of::<String>() * 1000)?;
                result.set("type", "estimated")?;
            }

            #[cfg(target_os = "windows")]
            {
                result.set("allocated", 0)?;
                result.set("type", "unavailable")?;
            }

            Ok(result)
        })?,
    )?;

    // count_objects - Count objects of a given type
    nsedebug.set(
        "count_objects",
        lua.create_function(|_lua, t: Table| {
            let mut count = 0;
            for _ in t.pairs::<mlua::Value, mlua::Value>() {
                count += 1;
            }
            Ok(count)
        })?,
    )?;

    globals.set("nsedebug", nsedebug)?;
    Ok(())
}
