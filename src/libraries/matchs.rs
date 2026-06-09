//! NSE matchs library wrapper
//!
//! Pattern matching utilities.
//! Based on Nmap's matchs library.

use mlua::{Lua, Result as LuaResult};
use regex::RegexBuilder;

pub fn register_matchs_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let matchs = lua.create_table()?;

    let ip_fn = lua.create_function(|_lua, (pattern, ip): (String, String)| {
        let parts: Vec<&str> = pattern.split('/').collect();
        if parts.len() == 2 {
            if let Ok(cidr) = parts[1].parse::<u8>() {
                let ip_parts: Vec<&str> = parts[0].split('.').collect();
                if ip_parts.len() == 4 {
                    let ip_num: u32 = ip_parts
                        .iter()
                        .filter_map(|p| p.parse::<u8>().ok())
                        .enumerate()
                        .map(|(i, v)| (v as u32) << (24 - i * 8))
                        .sum();

                    let mask = !((1u32 << (32 - cidr)) - 1);
                    let test_ip: u32 = ip
                        .split('.')
                        .filter_map(|p| p.parse::<u8>().ok())
                        .enumerate()
                        .map(|(i, v)| (v as u32) << (24 - i * 8))
                        .sum();

                    return Ok((test_ip & mask) == (ip_num & mask));
                }
            }
        }
        Ok(pattern == ip)
    })?;
    matchs.set("ip", ip_fn)?;

    let wildcard_fn = lua.create_function(|_lua, (pattern, text): (String, String)| {
        let regex_pattern = pattern
            .replace('.', "\\.")
            .replace('*', ".*")
            .replace('?', ".");

        match RegexBuilder::new(&format!("^{}$", regex_pattern))
            .size_limit(50_000)
            .build()
        {
            Ok(re) => Ok(re.is_match(&text)),
            _ => Ok(pattern == text),
        }
    })?;
    matchs.set("wildcard", wildcard_fn)?;

    let regex_fn = lua.create_function(|_lua, (pattern, text): (String, String)| {
        match RegexBuilder::new(&pattern).size_limit(50_000).build() {
            Ok(re) => Ok(re.is_match(&text)),
            _ => Ok(false),
        }
    })?;
    matchs.set("regex", regex_fn)?;

    let cidr_fn = lua.create_function(|_lua, (cidr, ip): (String, String)| {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Ok(false);
        }

        let cidr_ip = parts[0];
        if let Ok(_cidr_num) = parts[1].parse::<u8>() {
            let cidr_parts: Vec<u8> = cidr_ip.split('.').filter_map(|p| p.parse().ok()).collect();

            let ip_parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();

            if cidr_parts.len() != 4 || ip_parts.len() != 4 {
                return Ok(false);
            }

            let cidr_num: u32 = cidr_parts
                .iter()
                .enumerate()
                .map(|(i, &v)| (v as u32) << (24 - i * 8))
                .sum();

            let ip_num: u32 = ip_parts
                .iter()
                .enumerate()
                .map(|(i, &v)| (v as u32) << (24 - i * 8))
                .sum();

            let mask = !((1u32 << (32 - cidr_num)) - 1);
            Ok((ip_num & mask) == (cidr_num & mask))
        } else {
            Ok(false)
        }
    })?;
    matchs.set("CIDR", cidr_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    matchs.set("version", version_fn)?;

    globals.set("matchs", matchs)?;
    Ok(())
}
