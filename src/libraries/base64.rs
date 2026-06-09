//! NSE base64 library wrapper
//!
//! Provides Base64 encoding and decoding.

use base64::{engine::general_purpose, Engine as _};
use mlua::{Lua, Result as LuaResult};

pub fn register_base64_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let base64 = lua.create_table()?;

    base64.set(
        "encode",
        lua.create_function(|_lua, (input, wrap): (String, Option<bool>)| {
            let encoded = general_purpose::STANDARD.encode(input.as_bytes());

            if wrap.unwrap_or(false) {
                let wrapped: String = encoded
                    .chars()
                    .collect::<Vec<_>>()
                    .chunks(76)
                    .map(|c| c.iter().collect::<String>())
                    .collect::<Vec<_>>()
                    .join("\n");
                Ok(wrapped)
            } else {
                Ok(encoded)
            }
        })?,
    )?;

    base64.set(
        "decode",
        lua.create_function(|_lua, input: String| {
            let cleaned = input.replace(['\n', '\r', ' '], "");

            match general_purpose::STANDARD.decode(&cleaned) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(s) => Ok(s),
                    Err(e) => Err(mlua::Error::RuntimeError(format!("Invalid UTF-8: {}", e))),
                },
                Err(e) => Err(mlua::Error::RuntimeError(format!("Decode error: {}", e))),
            }
        })?,
    )?;

    base64.set(
        "encodes",
        lua.create_function(|_lua, input: String| {
            Ok(general_purpose::STANDARD.encode(input.as_bytes()))
        })?,
    )?;

    base64.set(
        "decodes",
        lua.create_function(|_lua, input: String| {
            let cleaned = input.replace(['\n', '\r', ' '], "");

            match general_purpose::STANDARD.decode(&cleaned) {
                Ok(bytes) => match String::from_utf8(bytes.clone()) {
                    Ok(s) => Ok(s),
                    Err(_) => Ok(format!("{:?}", bytes)),
                },
                Err(_) => Ok(String::new()),
            }
        })?,
    )?;

    base64.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("base64", base64)?;
    Ok(())
}
