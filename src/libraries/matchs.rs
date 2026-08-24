//! NSE matchs library wrapper
//!
//! Pattern matching utilities.
//! Based on Nmap's matchs library.

use mlua::{Lua, Result as LuaResult};
use regex::RegexBuilder;

/// Parse a dotted-quad IPv4 string into its u32 representation.
/// Returns `None` unless exactly four valid octets are present.
fn parse_ipv4_u32(s: &str) -> Option<u32> {
    let octets: Vec<u8> = s.split('.').filter_map(|p| p.parse().ok()).collect();
    if octets.len() != 4 {
        return None;
    }
    Some(
        octets
            .iter()
            .enumerate()
            .map(|(i, &v)| (v as u32) << (24 - i * 8))
            .sum(),
    )
}

/// Convert a CIDR prefix length (0-32) into a netmask.
/// Returns `None` for out-of-range prefixes instead of shifting overflow.
fn cidr_prefix_mask(prefix: u8) -> Option<u32> {
    match prefix {
        0 => Some(0),
        p @ 1..=32 => Some(!((1u32 << (32 - p)) - 1)),
        _ => None,
    }
}

pub fn register_matchs_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let matchs = lua.create_table()?;

    let ip_fn = lua.create_function(|_lua, (pattern, ip): (String, String)| {
        let parts: Vec<&str> = pattern.split('/').collect();
        if parts.len() == 2 {
            if let Ok(cidr) = parts[1].parse::<u8>() {
                if let (Some(ip_num), Some(test_ip), Some(mask)) = (
                    parse_ipv4_u32(parts[0]),
                    parse_ipv4_u32(&ip),
                    cidr_prefix_mask(cidr),
                ) {
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

        // Parse the prefix length first; it drives the mask computation.
        let Ok(prefix_len) = parts[1].parse::<u8>() else {
            return Ok(false);
        };
        let (Some(cidr_num), Some(ip_num), Some(mask)) = (
            parse_ipv4_u32(parts[0]),
            parse_ipv4_u32(&ip),
            cidr_prefix_mask(prefix_len),
        ) else {
            return Ok(false);
        };

        Ok((ip_num & mask) == (cidr_num & mask))
    })?;
    matchs.set("CIDR", cidr_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    matchs.set("version", version_fn)?;

    globals.set("matchs", matchs)?;
    Ok(())
}
