//! NSE ls library wrapper
//!
//! ls (list) utility support.
//! Based on Nmap's ls library: https://nmap.org/nsedoc/lib/ls.html

use mlua::{Lua, Result as LuaResult, Table};

pub fn register_ls_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let ls = lua.create_table()?;

    let dir_fn = lua.create_function(|lua, path: String| {
        let entries = match std::fs::read_dir(&path) {
            Ok(rd) => {
                let result = lua.create_table()?;
                let mut count = 1;
                for entry in rd.flatten() {
                    if let Ok(file_type) = entry.file_type() {
                        let file_entry = lua.create_table()?;
                        file_entry.set("name", entry.file_name().to_string_lossy().to_string())?;

                        if let Ok(metadata) = entry.metadata() {
                            file_entry.set("size", metadata.len())?;
                            if let Ok(modified) = metadata.modified() {
                                if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH)
                                {
                                    file_entry.set("time", duration.as_secs())?;
                                }
                            }
                        }

                        if file_type.is_dir() {
                            file_entry.set("type", "dir")?;
                        } else if file_type.is_file() {
                            file_entry.set("type", "file")?;
                        } else if file_type.is_symlink() {
                            file_entry.set("type", "link")?;
                        }

                        result.set(count, file_entry)?;
                        count += 1;
                    }
                }
                result
            }
            Err(_) => lua.create_table()?,
        };

        Ok(entries)
    })?;
    ls.set("dir", dir_fn)?;

    let add_file_fn = lua.create_function(|lua, (output, file): (Table, Table)| {
        let output = output;

        let name: String = file.get("name").unwrap_or_default();
        let size: u64 = file.get("size").unwrap_or(0);
        let file_type: String = file.get("type").unwrap_or_else(|_| "file".to_string());

        let file_entry = lua.create_table()?;
        file_entry.set("name", name)?;
        file_entry.set("size", size)?;
        file_entry.set("type", file_type)?;

        if let Ok(time) = file.get::<u64>("time") {
            file_entry.set("time", time)?;
        }

        let len: usize = output.len().unwrap_or(0) as usize;
        output.set(len + 1, file_entry)?;

        Ok(output)
    })?;
    ls.set("add_file", add_file_fn)?;

    let config_fn =
        lua.create_function(|_lua, (argname, _default): (String, Option<String>)| {
            match argname.as_str() {
                "errors" => Ok("true".to_string()),
                "empty" => Ok("false".to_string()),
                "human" => Ok("false".to_string()),
                "maxdepth" => Ok("0".to_string()),
                "maxfiles" => Ok("10".to_string()),
                _ => Ok("".to_string()),
            }
        })?;
    ls.set("config", config_fn)?;

    let make_list_fn = lua.create_function(|lua, _: ()| {
        let result = lua.create_table()?;
        result.set("status", "ok")?;
        result.set("files", lua.create_table()?)?;
        result.set("total", 0)?;
        Ok(result)
    })?;
    ls.set("make_list", make_list_fn)?;

    ls.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("ls", ls)?;
    Ok(())
}
