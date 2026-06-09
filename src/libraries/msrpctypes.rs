//! NSE msrpctypes library wrapper
//!
//! MSRPC type definitions.
//! Based on Nmap's msrpctypes library.

use mlua::{Lua, Result as LuaResult};

pub fn register_msrpctypes_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let msrpctypes = lua.create_table()?;

    let unpack_int8_fn = lua.create_function(|_lua, data: String| {
        if !data.is_empty() {
            Ok(data.as_bytes()[0] as i8)
        } else {
            Ok(0i8)
        }
    })?;
    msrpctypes.set("unpack_int8", unpack_int8_fn)?;

    let unpack_uint8_fn = lua.create_function(|_lua, data: String| {
        if !data.is_empty() {
            Ok(data.as_bytes()[0])
        } else {
            Ok(0u8)
        }
    })?;
    msrpctypes.set("unpack_uint8", unpack_uint8_fn)?;

    let unpack_int16_fn = lua.create_function(|_lua, data: String| {
        if data.len() >= 2 {
            let bytes = &data.as_bytes()[..2];
            Ok(i16::from_le_bytes([bytes[0], bytes[1]]))
        } else {
            Ok(0i16)
        }
    })?;
    msrpctypes.set("unpack_int16", unpack_int16_fn)?;

    let unpack_uint16_fn = lua.create_function(|_lua, data: String| {
        if data.len() >= 2 {
            let bytes = &data.as_bytes()[..2];
            Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
        } else {
            Ok(0u16)
        }
    })?;
    msrpctypes.set("unpack_uint16", unpack_uint16_fn)?;

    let unpack_int32_fn = lua.create_function(|_lua, data: String| {
        if data.len() >= 4 {
            let bytes = &data.as_bytes()[..4];
            Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        } else {
            Ok(0i32)
        }
    })?;
    msrpctypes.set("unpack_int32", unpack_int32_fn)?;

    let unpack_uint32_fn = lua.create_function(|_lua, data: String| {
        if data.len() >= 4 {
            let bytes = &data.as_bytes()[..4];
            Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        } else {
            Ok(0u32)
        }
    })?;
    msrpctypes.set("unpack_uint32", unpack_uint32_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    msrpctypes.set("version", version_fn)?;

    globals.set("msrpctypes", msrpctypes)?;
    Ok(())
}
