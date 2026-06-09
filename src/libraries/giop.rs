//! NSE giop library wrapper
//!
//! GIOP (General Inter-ORB Protocol) support for CORBA.
//! Based on Nmap's giop library.

use mlua::{Lua, Result as LuaResult};

pub fn register_giop_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let giop = lua.create_table()?;

    giop.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("giop", giop)?;
    Ok(())
}
