//! NSE tab library wrapper
//!
//! Table formatting facilities compatible with NSE.

use mlua::{Lua, Result as LuaResult, Table};

use super::helpers::fallback_lua_table;

pub fn register_tab_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let tab = lua.create_table()?;

    tab.set(
        "new",
        lua.create_function(|lua, _: ()| {
            let t = lua.create_table()?;
            t.set("_rows", lua.create_table()?)?;
            t.set("_indent", 0)?;
            t.set("ordered", true)?;
            Ok(t)
        })?,
    )?;

    tab.set(
        "add_row",
        lua.create_function(|lua, (t, row): (Table, Table)| {
            let rows: Table = t.get("_rows").unwrap_or_else(|_| fallback_lua_table(lua));
            let row_num = rows.len().unwrap_or(0) + 1;
            rows.set(row_num, row)?;
            t.set("_rows", rows)?;

            Ok(t)
        })?,
    )?;

    tab.set(
        "add_separator",
        lua.create_function(|lua, t: Table| {
            let rows: Table = t.get("_rows").unwrap_or_else(|_| fallback_lua_table(lua));
            let row_num = rows.len().unwrap_or(0) + 1;

            let sep = lua.create_table()?;
            sep.set(1, "_separator")?;
            rows.set(row_num, sep)?;
            t.set("_rows", rows)?;

            Ok(t)
        })?,
    )?;

    tab.set(
        "set_indent",
        lua.create_function(|_lua, (t, indent): (Table, i32)| {
            t.set("_indent", indent)?;
            Ok(t)
        })?,
    )?;

    tab.set(
        "get_indent",
        lua.create_function(|_lua, t: Table| {
            let indent: i32 = t.get("_indent").unwrap_or(0);
            Ok(indent)
        })?,
    )?;

    tab.set(
        "size",
        lua.create_function(|lua, t: Table| {
            let rows: Table = t.get("_rows").unwrap_or_else(|_| fallback_lua_table(lua));
            let len = rows.len().unwrap_or(0) as i32;
            Ok(len)
        })?,
    )?;

    tab.set(
        "dump",
        lua.create_function(|lua, t: Table| {
            let rows: Table = t.get("_rows").unwrap_or_else(|_| fallback_lua_table(lua));
            let indent: i32 = t.get("_indent").unwrap_or(0);

            let indent_str = " ".repeat(indent as usize);
            let mut output = String::new();

            let len = rows.len().unwrap_or(0);
            for i in 1..=len {
                if let Ok(row) = rows.get::<Table>(i) {
                    if let Ok(first) = row.get::<String>(1) {
                        if first == "_separator" {
                            output.push_str(&indent_str);
                            output.push_str("---");
                            output.push('\n');
                            continue;
                        }
                    }

                    output.push_str(&indent_str);

                    let row_len = row.len().unwrap_or(0);
                    for j in 1..=row_len {
                        if let Ok(val) = row.get::<String>(j) {
                            output.push_str(&val);
                            if j < row_len {
                                output.push('\t');
                            }
                        }
                    }
                    output.push('\n');
                }
            }

            Ok(output)
        })?,
    )?;

    tab.set(
        "tostring",
        lua.create_function(|lua, _t: Table| {
            let result = lua.create_table()?;
            Ok(result)
        })?,
    )?;

    globals.set("tab", tab)?;
    Ok(())
}
