//! NSE strbuf library wrapper
//!
//! String buffer facilities compatible with NSE.

use mlua::{Lua, Result as LuaResult};

pub fn register_strbuf_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let strbuf = lua.create_table()?;

    strbuf.set("new", lua.create_function(|_lua, _: ()| Ok(String::new()))?)?;

    strbuf.set("new_from", lua.create_function(|_lua, s: String| Ok(s))?)?;

    strbuf.set(
        "add",
        lua.create_function(|_lua, (buf, s): (String, String)| {
            let mut buf = buf;
            buf.push_str(&s);
            Ok(buf)
        })?,
    )?;

    strbuf.set("get", lua.create_function(|_lua, buf: String| Ok(buf))?)?;

    strbuf.set(
        "len",
        lua.create_function(|_lua, buf: String| Ok(buf.len()))?,
    )?;

    strbuf.set(
        "empty",
        lua.create_function(|_lua, buf: String| Ok(buf.is_empty()))?,
    )?;

    strbuf.set(
        "clear",
        lua.create_function(|_lua, _: ()| Ok(String::new()))?,
    )?;

    strbuf.set(
        "tostring",
        lua.create_function(|_lua, buf: String| Ok(buf))?,
    )?;

    globals.set("strbuf", strbuf)?;
    Ok(())
}
