//! NSE bits library wrapper
//!
//! Bit manipulation library for NSE.
//! Based on Nmap's bits library.

use mlua::{Lua, Result as LuaResult};

pub fn register_bits_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let bits = lua.create_table()?;

    let not_fn = lua.create_function(|_lua, (n, size): (u32, Option<u32>)| {
        let size = size.unwrap_or(32);
        let mask = if size >= 32 {
            0xFFFFFFFF
        } else {
            (1 << size) - 1
        };
        Ok(!n & mask)
    })?;
    bits.set("bnot", not_fn)?;

    let and_fn = lua.create_function(|_lua, (a, b, size): (u32, u32, Option<u32>)| {
        let size = size.unwrap_or(32);
        let mask = if size >= 32 {
            0xFFFFFFFF
        } else {
            (1 << size) - 1
        };
        Ok(a & b & mask)
    })?;
    bits.set("band", and_fn)?;

    let or_fn = lua.create_function(|_lua, (a, b, size): (u32, u32, Option<u32>)| {
        let size = size.unwrap_or(32);
        let mask = if size >= 32 {
            0xFFFFFFFF
        } else {
            (1 << size) - 1
        };
        Ok((a | b) & mask)
    })?;
    bits.set("bor", or_fn)?;

    let xor_fn = lua.create_function(|_lua, (a, b, size): (u32, u32, Option<u32>)| {
        let size = size.unwrap_or(32);
        let mask = if size >= 32 {
            0xFFFFFFFF
        } else {
            (1 << size) - 1
        };
        Ok((a ^ b) & mask)
    })?;
    bits.set("bxor", xor_fn)?;

    let lshift_fn = lua.create_function(|_lua, (n, shift, size): (u32, u32, Option<u32>)| {
        let size = size.unwrap_or(32);
        let mask = if size >= 32 {
            0xFFFFFFFF
        } else {
            (1 << size) - 1
        };
        Ok((n << shift) & mask)
    })?;
    bits.set("lshift", lshift_fn)?;

    let rshift_fn =
        lua.create_function(|_lua, (n, shift, _size): (u32, u32, Option<u32>)| Ok(n >> shift))?;
    bits.set("rshift", rshift_fn)?;

    let reverse_fn = lua.create_function(|_lua, (n, size): (u32, Option<u32>)| {
        let size = size.unwrap_or(32) as usize;
        let mut result = 0u32;
        for i in 0..size {
            if n & (1 << i) != 0 {
                result |= 1 << (size - 1 - i);
            }
        }
        Ok(result)
    })?;
    bits.set("reverse", reverse_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    bits.set("version", version_fn)?;

    globals.set("bits", bits)?;
    Ok(())
}
