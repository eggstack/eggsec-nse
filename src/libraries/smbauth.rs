//! NSE smbauth library wrapper
//!
//! SMB authentication utilities for NSE scripts.
//! Based on Nmap's smbauth library.

use mlua::{Lua, Result as LuaResult};
use rustc_hash::FxHashMap;
use std::sync::{Mutex, OnceLock};

static HASH_STORE: OnceLock<Mutex<FxHashMap<String, (String, String)>>> = OnceLock::new();

pub fn register_smbauth_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let smbauth = lua.create_table()?;

    smbauth.set(
        "get_password_hash",
        lua.create_function(
            |lua, (domain, username, password): (String, String, String)| {
                // Simple NTLM hash simulation
                let hash_str = format!(
                    "{:x}",
                    simple_hash(&format!("{}{}:{}", domain, username, password))
                );

                let result = lua.create_table()?;
                result.set("hash", hash_str.clone())?;
                result.set("ntlm", hash_str)?;

                // LM hash (simplified)
                let lm_hash = format!("{:x}", simple_hash(&password.to_uppercase()));
                result.set("lm", lm_hash)?;

                Ok(result)
            },
        )?,
    )?;

    smbauth.set(
        "compute_lm_hash",
        lua.create_function(|_lua, password: String| {
            // Pad password to 14 chars
            let padded: String = password
                .to_uppercase()
                .chars()
                .take(14)
                .chain(std::iter::repeat('\0'))
                .take(14)
                .collect();

            let hash = format!("{:x}", simple_hash(&padded));
            Ok(hash)
        })?,
    )?;

    smbauth.set(
        "ntlmv1_session",
        lua.create_function(
            |lua, (domain, username, challenge, password): (String, String, String, String)| {
                let result = lua.create_table()?;

                // NTLMv1 response calculation (simplified)
                let nt_response = format!(
                    "{:x}",
                    simple_hash(&format!(
                        "{}{}:{}:{}",
                        domain, username, password, challenge
                    ))
                );
                let lm_response = format!(
                    "{:x}",
                    simple_hash(&format!("{}:{}", password.to_uppercase(), challenge))
                );

                result.set("nt_response", nt_response)?;
                result.set("lm_response", lm_response)?;

                Ok(result)
            },
        )?,
    )?;

    smbauth.set(
        "ntlmv2_session",
        lua.create_function(
            |lua, (_domain, _username, _challenge, _password): (String, String, String, String)| {
                let result = lua.create_table()?;
                result.set("nt_response", "not_implemented")?;
                result.set("lm_response", "not_implemented")?;
                Ok(result)
            },
        )?,
    )?;

    smbauth.set(
        "get_ntlm_challenge",
        lua.create_function(|_lua, _: ()| {
            // Generate a random 8-byte challenge
            let challenge: String = (0..8)
                .map(|_| {
                    let b = rand::random::<u8>();
                    format!("{:02x}", b)
                })
                .collect();
            Ok(challenge)
        })?,
    )?;

    smbauth.set(
        "signing_md5",
        lua.create_function(|_lua, (data, key): (String, String)| {
            use md5::{Digest, Md5};
            let mut hasher = Md5::new();
            hasher.update(data.as_bytes());
            hasher.update(key.as_bytes());
            let result = hasher.finalize();
            Ok(format!("{:x}", result))
        })?,
    )?;

    smbauth.set(
        "signing_hmac_md5",
        lua.create_function(|_lua, (data, key): (String, String)| {
            use md5::{Digest, Md5};
            let mut hasher = Md5::new();
            hasher.update(key.as_bytes());
            hasher.update(data.as_bytes());
            let result = hasher.finalize();
            Ok(format!("{:x}", result))
        })?,
    )?;

    smbauth.set(
        "encrypt_password",
        lua.create_function(|_lua, (password, key): (String, String)| {
            // Simple XOR encryption (not real encryption)
            let key_bytes: Vec<u8> = key.as_bytes().to_vec();
            let mut result = Vec::new();

            for (i, byte) in password.as_bytes().iter().enumerate() {
                result.push(byte ^ key_bytes[i % key_bytes.len()]);
            }

            Ok(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &result,
            ))
        })?,
    )?;

    smbauth.set(
        "get_domain_from_dns",
        lua.create_function(|_lua, dns_name: String| {
            // Extract domain from DNS name
            let parts: Vec<&str> = dns_name.split('.').collect();
            if parts.len() >= 2 {
                Ok(parts[parts.len() - 2..].join("."))
            } else {
                Ok(dns_name)
            }
        })?,
    )?;

    smbauth.set(
        "get_domain_from_principal",
        lua.create_function(|_lua, principal: String| {
            if let Some((domain, _)) = principal.split_once('\\') {
                Ok(domain.to_string())
            } else if let Some((_, user)) = principal.split_once('@') {
                if let Some((domain, _)) = user.split_once('.') {
                    Ok(domain.to_uppercase())
                } else {
                    Ok(user.to_uppercase())
                }
            } else {
                Ok("WORKGROUP".to_string())
            }
        })?,
    )?;

    smbauth.set(
        "get_username_from_principal",
        lua.create_function(|_lua, principal: String| {
            if let Some((_, user)) = principal.split_once('\\') {
                Ok(user.to_string())
            } else if let Some((name, _)) = principal.split_once('@') {
                Ok(name.to_string())
            } else {
                Ok(principal)
            }
        })?,
    )?;

    globals.set("smbauth", smbauth)?;
    Ok(())
}

fn simple_hash(s: &str) -> u128 {
    let mut hash: u128 = 0;
    for (i, byte) in s.bytes().enumerate() {
        hash = hash.wrapping_add((byte as u128).wrapping_mul((i as u128).wrapping_add(1)));
        hash = hash.rotate_left(5);
    }
    hash
}
