//! NSE ipOps library wrapper
//!
//! Utility functions for manipulating and comparing IP addresses.
//! Based on Nmap's ipOps library.

use mlua::{Lua, Result as LuaResult};

pub fn register_ipops_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let ipops = lua.create_table()?;

    let get_localip_fn = lua.create_function(|lua, _: ()| {
        let result = lua.create_table()?;
        result.set("ip", "127.0.0.1")?;
        result.set("mac", "")?;
        Ok(result)
    })?;
    ipops.set("get_localip", get_localip_fn)?;

    let get_globalip_fn = lua.create_function(|_lua, _: ()| Ok(String::new()))?;
    ipops.set("get_globalip", get_globalip_fn)?;

    let ip_to_str_fn = lua.create_function(|_lua, ip: String| Ok(ip))?;
    ipops.set("ip_to_str", ip_to_str_fn)?;

    let str_to_ip_fn = lua.create_function(|_lua, ip: String| Ok(ip))?;
    ipops.set("str_to_ip", str_to_ip_fn)?;

    let get_byte_fn = lua.create_function(|_lua, (ip, n): (String, usize)| {
        let parts: Vec<&str> = ip.split('.').collect();
        if n < parts.len() {
            Ok(parts[n].parse::<u8>().map(|b| b as i32).unwrap_or(0))
        } else {
            Ok(0i32)
        }
    })?;
    ipops.set("get_byte", get_byte_fn)?;

    let is_private_fn = lua.create_function(|_lua, ip: String| {
        let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
        if parts.len() == 4 {
            if parts[0] == 10 {
                return Ok(true);
            }
            if parts[0] == 172 && (16..=31).contains(&parts[1]) {
                return Ok(true);
            }
            if parts[0] == 192 && parts[1] == 168 {
                return Ok(true);
            }
        }
        Ok(false)
    })?;
    ipops.set("is_private", is_private_fn)?;

    let is_ipv6_fn = lua.create_function(|_lua, ip: String| Ok(ip.contains(':')))?;
    ipops.set("is_ipv6", is_ipv6_fn)?;

    let cidr_to_mask_fn = lua.create_function(|_lua, bits: u8| {
        if bits >= 32 {
            Ok(0u32)
        } else {
            Ok(!((1u32 << (32 - bits)) - 1))
        }
    })?;
    ipops.set("cidr_to_mask", cidr_to_mask_fn)?;

    let get_network_fn = lua.create_function(|_lua, (ip, mask): (String, String)| {
        let ip_parts: Vec<u32> = ip
            .split('.')
            .filter_map(|p| p.parse::<u8>().ok())
            .map(|b| b as u32)
            .collect();
        let mask_parts: Vec<u32> = mask
            .split('.')
            .filter_map(|p| p.parse::<u8>().ok())
            .map(|b| b as u32)
            .collect();
        if ip_parts.len() == 4 && mask_parts.len() == 4 {
            let ip_num =
                (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3];
            let mask_num = (mask_parts[0] << 24)
                | (mask_parts[1] << 16)
                | (mask_parts[2] << 8)
                | mask_parts[3];
            let net_num = ip_num & mask_num;
            Ok(format!(
                "{}.{}.{}.{}",
                (net_num >> 24) & 0xFF,
                (net_num >> 16) & 0xFF,
                (net_num >> 8) & 0xFF,
                net_num & 0xFF
            ))
        } else {
            Ok(ip.to_string())
        }
    })?;
    ipops.set("get_network", get_network_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    ipops.set("version", version_fn)?;

    globals.set("ipOps", ipops)?;
    Ok(())
}
