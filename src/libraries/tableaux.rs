//! NSE tableaux library wrapper
//!
//! Table manipulation utilities.
//! Based on Nmap's tableaux library: https://nmap.org/nsedoc/lib/tableaux.html

use mlua::{Lua, Result as LuaResult, Table, Value};

pub fn register_tableaux_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let tableaux = lua.create_table()?;

    // tableaux.keys(t) -> array of keys
    let keys_fn = lua.create_function(|lua, tbl: Table| {
        let result = lua.create_table()?;
        let mut i = 1;
        for (k, _) in tbl.pairs::<mlua::Value, mlua::Value>().flatten() {
            result.set(i, k)?;
            i += 1;
        }
        Ok(result)
    })?;
    tableaux.set("keys", keys_fn)?;

    // tableaux.values(t) -> array of values
    let values_fn = lua.create_function(|lua, tbl: Table| {
        let result = lua.create_table()?;
        let mut i = 1;
        for (_, v) in tbl.pairs::<mlua::Value, mlua::Value>().flatten() {
            result.set(i, v)?;
            i += 1;
        }
        Ok(result)
    })?;
    tableaux.set("values", values_fn)?;

    // tableaux.merge(t1, t2) -> merged table
    let merge_fn = lua.create_function(|lua, (t1, t2): (Table, Table)| {
        let result = lua.create_table()?;
        for (k, v) in t1.pairs::<mlua::Value, mlua::Value>().flatten() {
            result.set(k, v)?;
        }
        for (k, v) in t2.pairs::<mlua::Value, mlua::Value>().flatten() {
            result.set(k, v)?;
        }
        Ok(result)
    })?;
    tableaux.set("merge", merge_fn)?;

    // tableaux.is_array(t) -> boolean
    let is_array_fn = lua.create_function(|_lua, tbl: Table| {
        let len = tbl.len().unwrap_or(0);
        if len == 0 {
            return Ok(false);
        }
        for i in 1..=len {
            if tbl.get::<Value>(i).is_err() {
                return Ok(false);
            }
        }
        Ok(true)
    })?;
    tableaux.set("is_array", is_array_fn)?;

    // tableaux.contains(t, item, array?) -> boolean, index
    // Check for presence of a value in a table
    let contains_fn =
        lua.create_function(|lua, (tbl, item, array): (Table, Value, Option<bool>)| {
            let is_array_only = array.unwrap_or(false);

            if is_array_only {
                let len = tbl.len().unwrap_or(0) as usize;
                for i in 1..=len {
                    if let Ok(val) = tbl.get::<Value>(i) {
                        if val == item {
                            let result = lua.create_table()?;
                            result.set(1, true)?;
                            result.set(2, i)?;
                            return Ok(result);
                        }
                    }
                }
            } else {
                for (k, v) in tbl.pairs::<Value, Value>().flatten() {
                    if v == item {
                        let result = lua.create_table()?;
                        result.set(1, true)?;
                        result.set(2, k)?;
                        return Ok(result);
                    }
                }
            }

            let result = lua.create_table()?;
            result.set(1, false)?;
            result.set(2, Value::Nil)?;
            Ok(result)
        })?;
    tableaux.set("contains", contains_fn)?;

    // tableaux.invert(t) -> inverted table
    // Invert a one-to-one mapping
    let invert_fn = lua.create_function(|lua, tbl: Table| {
        let result = lua.create_table()?;
        for (k, v) in tbl.pairs::<Value, Value>().flatten() {
            result.set(v, k)?;
        }
        Ok(result)
    })?;
    tableaux.set("invert", invert_fn)?;

    // tableaux.shallow_tcopy(t) -> shallow copy
    // Copy one level of a table (by reference for nested tables)
    let shallow_tcopy_fn = lua.create_function(|lua, tbl: Table| {
        let result = lua.create_table()?;
        for (k, v) in tbl.pairs::<Value, Value>().flatten() {
            result.set(k, v)?;
        }
        Ok(result)
    })?;
    tableaux.set("shallow_tcopy", shallow_tcopy_fn)?;

    // tableaux.tcopy(t) -> deep copy
    // Recursively copy a table
    fn deep_copy_table(lua: &Lua, tbl: &Table) -> LuaResult<Table> {
        let result = lua.create_table()?;
        for (k, v) in tbl.pairs::<Value, Value>().flatten() {
            match v {
                Value::Table(t) => {
                    let copied = deep_copy_table(lua, &t)?;
                    result.set(k, Value::Table(copied))?;
                }
                _ => {
                    result.set(k, v)?;
                }
            }
        }
        Ok(result)
    }

    let tcopy_fn = lua.create_function(|lua, tbl: Table| deep_copy_table(lua, &tbl))?;
    tableaux.set("tcopy", tcopy_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0"))?;
    tableaux.set("version", version_fn)?;

    globals.set("tableaux", tableaux)?;
    Ok(())
}
