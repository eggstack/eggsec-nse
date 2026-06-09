//! NSE outlib library wrapper
//!
//! Helper functions for NSE script output.
//! Based on Nmap's outlib library: https://nmap.org/nsedoc/lib/outlib.html

use mlua::{Function, Lua, Result as LuaResult, Table};

pub fn register_outlib_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let outlib = lua.create_table()?;

    let list_sep_fn = lua.create_function(|_lua, (t, sep): (Table, Option<String>)| {
        let separator = sep.unwrap_or_else(|| ", ".to_string());

        let mut items = Vec::new();
        let len: usize = t.len().unwrap_or(0) as usize;

        for i in 1..=len {
            if let Ok(value) = t.get::<String>(i) {
                items.push(value);
            }
        }

        Ok(items.join(&separator))
    })?;
    outlib.set("list_sep", list_sep_fn)?;

    let sorted_by_key_fn =
        lua.create_function(|lua, (t, sortfunc): (Table, Option<Function>)| {
            let mut keys: Vec<String> = Vec::new();

            for (key, _) in t.pairs::<String, mlua::Value>().flatten() {
                keys.push(key);
            }

            if let Some(_func) = sortfunc {
                keys.sort();
            } else {
                keys.sort();
            }

            let result = lua.create_table()?;
            for key in keys.iter() {
                if let Ok(value) = t.get::<mlua::Value>(key.clone()) {
                    result.set(key.clone(), value)?;
                }
            }

            Ok(result)
        })?;
    outlib.set("sorted_by_key", sorted_by_key_fn)?;

    let format_output_fn = lua.create_function(|lua, (format_type, data): (String, Table)| {
        let result = lua.create_table()?;
        result.set("format", format_type)?;
        result.set("data", data)?;
        Ok(result)
    })?;
    outlib.set("format_output", format_output_fn)?;

    let to_xml_fn = lua.create_function(|_lua, data: Table| {
        let mut xml = String::from("<output>");

        for (key, value) in data.pairs::<String, mlua::Value>().flatten() {
            xml.push_str(&format!("<{}>", key));
            match value {
                mlua::Value::String(s) => xml.push_str(&s.to_string_lossy()),
                mlua::Value::Number(n) => xml.push_str(&n.to_string()),
                mlua::Value::Boolean(b) => xml.push_str(&b.to_string()),
                _ => {}
            }
            xml.push_str(&format!("</{}>", key));
        }

        xml.push_str("</output>");
        Ok(xml)
    })?;
    outlib.set("to_xml", to_xml_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    outlib.set("version", version_fn)?;

    globals.set("outlib", outlib)?;
    Ok(())
}
