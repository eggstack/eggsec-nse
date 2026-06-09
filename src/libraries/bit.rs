//! NSE bit library wrapper
//!
//! Provides bitwise operations compatible with NSE.

use mlua::{Lua, Result as LuaResult, Table};

pub fn register_bit_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let bit = lua.create_table()?;

    bit.set(
        "band",
        lua.create_function(|_lua, (a, b): (u32, u32)| Ok(a & b))?,
    )?;

    bit.set(
        "bor",
        lua.create_function(|_lua, (a, b): (u32, u32)| Ok(a | b))?,
    )?;

    bit.set(
        "bxor",
        lua.create_function(|_lua, (a, b): (u32, u32)| Ok(a ^ b))?,
    )?;

    bit.set("bnot", lua.create_function(|_lua, a: u32| Ok(!a))?)?;

    bit.set(
        "lshift",
        lua.create_function(|_lua, (a, b): (u32, u32)| Ok(a << b))?,
    )?;

    bit.set(
        "rshift",
        lua.create_function(|_lua, (a, b): (u32, u32)| Ok(a >> b))?,
    )?;

    bit.set(
        "arshift",
        lua.create_function(|_lua, (a, b): (i32, u32)| Ok(a >> b))?,
    )?;

    bit.set(
        "ucast",
        lua.create_function(|_lua, a: i64| Ok((a & 0xFFFFFFFF) as u32))?,
    )?;

    bit.set(
        "tobits",
        lua.create_function(|lua, str: String| {
            let bits: Vec<u32> = str
                .chars()
                .filter(|c| *c == '0' || *c == '1')
                .map(|c| if c == '1' { 1 } else { 0 })
                .collect();
            let result = lua.create_table()?;
            for (i, bit) in bits.iter().enumerate() {
                result.set(i + 1, *bit)?;
            }
            Ok(result)
        })?,
    )?;

    bit.set(
        "frombits",
        lua.create_function(|_lua, bits: Table| {
            let len = bits.len().unwrap_or(0);
            let mut result = String::new();
            for i in 1..=len {
                if let Ok(bit) = bits.get::<u32>(i) {
                    result.push(if bit != 0 { '1' } else { '0' });
                }
            }
            Ok(result)
        })?,
    )?;

    bit.set(
        "cast",
        lua.create_function(|_lua, (value, width): (i64, Option<u32>)| {
            let w = width.unwrap_or(32);
            let mask = (1u64 << w) - 1;
            Ok((value as u64 & mask) as i64)
        })?,
    )?;

    globals.set("bit", bit)?;
    Ok(())
}
