//! NSE rand library wrapper
//!
//! Provides random number generation compatible with NSE scripts.

use mlua::{Lua, Result as LuaResult, Table};

use crate::capabilities::NseCapabilityContext;
use crate::wrappers;

pub fn register_rand_library(lua: &Lua, capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    let globals = lua.globals();
    let rand = lua.create_table()?;

    let cap_ctx = capability_ctx.clone();
    let random_fn = lua.create_function(move |_lua, _: ()| {
        let decision = wrappers::check_randomness(&cap_ctx, "rand.random");
        if decision.is_denied() {
            return Err(mlua::Error::RuntimeError(format!(
                "Randomness generation denied: {}",
                decision.deny_reason().unwrap_or("policy violation")
            )));
        }
        Ok(rand::random::<f64>())
    })?;
    rand.set("random", random_fn)?;

    let cap_ctx = capability_ctx.clone();
    let uniform_fn = lua.create_function(move |_lua, (min, max): (f64, f64)| {
        let decision = wrappers::check_randomness(&cap_ctx, "rand.uniform");
        if decision.is_denied() {
            return Err(mlua::Error::RuntimeError(format!(
                "Randomness generation denied: {}",
                decision.deny_reason().unwrap_or("policy violation")
            )));
        }
        let r = rand::random::<f64>();
        Ok(min + r * (max - min))
    })?;
    rand.set("uniform", uniform_fn)?;

    let cap_ctx = capability_ctx.clone();
    let new_fn = lua.create_function(move |_lua, _seed: Option<u64>| {
        let decision = wrappers::check_randomness(&cap_ctx, "rand.new");
        if decision.is_denied() {
            return Err(mlua::Error::RuntimeError(format!(
                "Randomness generation denied: {}",
                decision.deny_reason().unwrap_or("policy violation")
            )));
        }
        let r = rand::random::<u32>();
        Ok(r as i32)
    })?;
    rand.set("new", new_fn)?;

    let cap_ctx = capability_ctx.clone();
    let bytes_fn = lua.create_function(move |_lua, count: usize| {
        let decision = wrappers::check_randomness(&cap_ctx, "rand.bytes");
        if decision.is_denied() {
            return Err(mlua::Error::RuntimeError(format!(
                "Randomness generation denied: {}",
                decision.deny_reason().unwrap_or("policy violation")
            )));
        }
        let bytes: Vec<u8> = (0..count).map(|_| rand::random::<u8>()).collect();
        Ok(bytes)
    })?;
    rand.set("bytes", bytes_fn)?;

    let cap_ctx = capability_ctx.clone();
    let bits_fn = lua.create_function(move |_lua, n: u32| {
        let decision = wrappers::check_randomness(&cap_ctx, "rand.bits");
        if decision.is_denied() {
            return Err(mlua::Error::RuntimeError(format!(
                "Randomness generation denied: {}",
                decision.deny_reason().unwrap_or("policy violation")
            )));
        }
        let r = rand::random::<u32>();
        Ok(r >> (32 - n.min(32)))
    })?;
    rand.set("bits", bits_fn)?;

    let cap_ctx = capability_ctx.clone();
    let int_fn = lua.create_function(move |_lua, (min, max): (i32, i32)| {
        let decision = wrappers::check_randomness(&cap_ctx, "rand.int");
        if decision.is_denied() {
            return Err(mlua::Error::RuntimeError(format!(
                "Randomness generation denied: {}",
                decision.deny_reason().unwrap_or("policy violation")
            )));
        }
        let r = rand::random::<u32>();
        let range = (max - min + 1) as u32;
        Ok(min + (r % range) as i32)
    })?;
    rand.set("int", int_fn)?;

    let cap_ctx = capability_ctx.clone();
    let shuffle_fn = lua.create_function(move |lua, list: Table| {
        let decision = wrappers::check_randomness(&cap_ctx, "rand.shuffle");
        if decision.is_denied() {
            return Err(mlua::Error::RuntimeError(format!(
                "Randomness generation denied: {}",
                decision.deny_reason().unwrap_or("policy violation")
            )));
        }

        let len: usize = list.len().unwrap_or(0) as usize;
        let mut items: Vec<String> = Vec::new();

        for i in 1..=len {
            if let Ok(v) = list.get::<String>(i) {
                items.push(v);
            }
        }

        for i in (1..items.len()).rev() {
            let j = (rand::random::<usize>()) % (i + 1);
            items.swap(i, j);
        }

        let result = lua.create_table()?;
        for (i, item) in items.iter().enumerate() {
            result.set(i + 1, item.clone())?;
        }

        Ok(result)
    })?;
    rand.set("shuffle", shuffle_fn)?;

    rand.set("precision", lua.create_function(|_lua, _: ()| Ok(16))?)?;

    globals.set("rand", rand)?;
    Ok(())
}
