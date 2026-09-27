//! NSE rand library wrapper
//!
//! Provides random number generation compatible with NSE scripts.

use mlua::{Lua, Result as LuaResult, Table};

use crate::capabilities::NseCapabilityContext;

pub fn register_rand_library(lua: &Lua, capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    register_rand_library_with_services(
        lua,
        capability_ctx,
        &crate::providers::NseHostServices::native(),
    )
}

/// Provider-backed randomness registration.
///
/// All byte generation goes through [`crate::providers::broker_random_fill`]
/// (or scalar broker helpers) so deterministic tests can replay one stream
/// while CiSafe denials never touch the provider.
pub fn register_rand_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &crate::providers::NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let rand = lua.create_table()?;

    let cap_ctx = capability_ctx.clone();
    let svc = services.clone();
    let random_fn = lua.create_function(move |_lua, _: ()| {
        crate::providers::broker_random_f64(&cap_ctx, &svc, "rand.random")
            .map_err(|e| mlua::Error::RuntimeError(format!("Randomness generation denied: {e}")))
    })?;
    rand.set("random", random_fn)?;

    let cap_ctx = capability_ctx.clone();
    let svc = services.clone();
    let uniform_fn = lua.create_function(move |_lua, (min, max): (f64, f64)| {
        let r = crate::providers::broker_random_f64(&cap_ctx, &svc, "rand.uniform")
            .map_err(|e| mlua::Error::RuntimeError(format!("Randomness generation denied: {e}")))?;
        Ok(min + r * (max - min))
    })?;
    rand.set("uniform", uniform_fn)?;

    let cap_ctx = capability_ctx.clone();
    let svc = services.clone();
    let new_fn = lua.create_function(move |_lua, _seed: Option<u64>| {
        let r = crate::providers::broker_random_u32(&cap_ctx, &svc, "rand.new")
            .map_err(|e| mlua::Error::RuntimeError(format!("Randomness generation denied: {e}")))?;
        Ok(r as i32)
    })?;
    rand.set("new", new_fn)?;

    let cap_ctx = capability_ctx.clone();
    let svc = services.clone();
    let bytes_fn = lua.create_function(move |_lua, count: usize| {
        let mut bytes = vec![0u8; count];
        crate::providers::broker_random_fill(&cap_ctx, &svc, &mut bytes, "rand.bytes")
            .map_err(|e| mlua::Error::RuntimeError(format!("Randomness generation denied: {e}")))?;
        Ok(bytes)
    })?;
    rand.set("bytes", bytes_fn)?;

    let cap_ctx = capability_ctx.clone();
    let svc = services.clone();
    let bits_fn = lua.create_function(move |_lua, n: u32| {
        let r = crate::providers::broker_random_u32(&cap_ctx, &svc, "rand.bits")
            .map_err(|e| mlua::Error::RuntimeError(format!("Randomness generation denied: {e}")))?;
        Ok(r >> (32 - n.min(32)))
    })?;
    rand.set("bits", bits_fn)?;

    let cap_ctx = capability_ctx.clone();
    let svc = services.clone();
    let int_fn = lua.create_function(move |_lua, (min, max): (i32, i32)| {
        let r = crate::providers::broker_random_u32(&cap_ctx, &svc, "rand.int")
            .map_err(|e| mlua::Error::RuntimeError(format!("Randomness generation denied: {e}")))?;
        let range = (max - min + 1) as u32;
        if range == 0 {
            return Ok(min);
        }
        Ok(min + (r % range) as i32)
    })?;
    rand.set("int", int_fn)?;

    let cap_ctx = capability_ctx.clone();
    let svc = services.clone();
    let shuffle_fn = lua.create_function(move |lua, list: Table| {
        let len: usize = list.len().unwrap_or(0) as usize;
        let mut items: Vec<String> = Vec::new();

        for i in 1..=len {
            if let Ok(v) = list.get::<String>(i) {
                items.push(v);
            }
        }

        for i in (1..items.len()).rev() {
            let mut buf = [0u8; 8];
            crate::providers::broker_random_fill(&cap_ctx, &svc, &mut buf, "rand.shuffle")
                .map_err(|e| {
                    mlua::Error::RuntimeError(format!("Randomness generation denied: {e}"))
                })?;
            let j = (u64::from_le_bytes(buf) as usize) % (i + 1);
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
