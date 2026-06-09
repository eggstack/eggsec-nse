//! NSE sasl library wrapper
//!
//! SASL (Simple Authentication and Security Layer) library.
//! Based on Nmap's sasl library concepts.

use mlua::{Lua, Result as LuaResult};

pub fn register_sasl_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let sasl = lua.create_table()?;

    let list_mechanisms_fn = lua.create_function(|lua: &Lua, _: ()| {
        let result = lua.create_table()?;
        let mechanisms = lua.create_table()?;

        mechanisms.set(1, "PLAIN")?;
        mechanisms.set(2, "LOGIN")?;
        mechanisms.set(3, "CRAM-MD5")?;
        mechanisms.set(4, "DIGEST-MD5")?;
        mechanisms.set(5, "SCRAM-SHA-1")?;
        mechanisms.set(6, "SCRAM-SHA-256")?;

        result.set("success", true)?;
        result.set("mechanisms", mechanisms)?;

        Ok(result)
    })?;
    sasl.set("list_mechanisms", list_mechanisms_fn)?;

    let encode_plain_fn = lua.create_function(|_lua, (user, password): (String, String)| {
        let data = format!("\0{}\0{}", user, password);

        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(data.as_bytes());

        Ok(encoded)
    })?;
    sasl.set("encode_plain", encode_plain_fn)?;

    let encode_cram_md5_fn = lua.create_function(
        |_lua, (user, _password, challenge): (String, String, String)| {
            use base64::Engine;
            let _challenge_bytes =
                match base64::engine::general_purpose::STANDARD.decode(&challenge) {
                    Ok(b) => b,
                    Err(_) => return Ok(String::new()),
                };

            let response = format!("{} <challenge>", user);
            Ok(response)
        },
    )?;
    sasl.set("encode_cram_md5", encode_cram_md5_fn)?;

    let encode_digest_md5_fn = lua.create_function(
        |lua: &Lua, (user, realm, _password, _challenge): (String, String, String, String)| {
            let result = lua.create_table()?;

            result.set("username", user)?;
            result.set("realm", realm)?;
            result.set("nonce", "abc123")?;
            result.set("cnonce", "def456")?;
            result.set("nc", "00000001")?;
            result.set("qop", "auth")?;
            result.set("digest_uri", "smtp/localhost")?;

            Ok(result)
        },
    )?;
    sasl.set("encode_digest_md5", encode_digest_md5_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    sasl.set("version", version_fn)?;

    globals.set("sasl", sasl)?;
    Ok(())
}
