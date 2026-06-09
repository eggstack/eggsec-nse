//! NSE rand library wrapper
//!
//! Provides random number generation compatible with NSE scripts.

use mlua::{Lua, Result as LuaResult, Table};

pub fn register_rand_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let rand = lua.create_table()?;

    let random_fn = lua.create_function(|_lua, _: ()| Ok(rand::random::<f64>()))?;
    rand.set("random", random_fn)?;

    let uniform_fn = lua.create_function(|_lua, (min, max): (f64, f64)| {
        let r = rand::random::<f64>();
        Ok(min + r * (max - min))
    })?;
    rand.set("uniform", uniform_fn)?;

    let new_fn = lua.create_function(|_lua, _seed: Option<u64>| {
        let r = rand::random::<u32>();
        Ok(r as i32)
    })?;
    rand.set("new", new_fn)?;

    let bytes_fn = lua.create_function(|_lua, count: usize| {
        let bytes: Vec<u8> = (0..count).map(|_| rand::random::<u8>()).collect();
        Ok(bytes)
    })?;
    rand.set("bytes", bytes_fn)?;

    let bits_fn = lua.create_function(|_lua, n: u32| {
        let r = rand::random::<u32>();
        Ok(r >> (32 - n.min(32)))
    })?;
    rand.set("bits", bits_fn)?;

    let int_fn = lua.create_function(|_lua, (min, max): (i32, i32)| {
        let r = rand::random::<u32>();
        let range = (max - min + 1) as u32;
        Ok(min + (r % range) as i32)
    })?;
    rand.set("int", int_fn)?;

    let shuffle_fn = lua.create_function(|lua, list: Table| {
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
