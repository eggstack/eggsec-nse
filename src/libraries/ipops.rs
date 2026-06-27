//! NSE ipOps library wrapper
//!
//! Utility functions for manipulating and comparing IP addresses.
//! Based on Nmap's ipOps library.

use mlua::{Lua, Result as LuaResult};

fn parse_ipv4_octets(ip: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut count = 0;

    for part in ip.split('.') {
        if count == octets.len() {
            return None;
        }

        octets[count] = part.parse().ok()?;
        count += 1;
    }

    (count == octets.len()).then_some(octets)
}

fn ipv4_to_u32(octets: [u8; 4]) -> u32 {
    ((octets[0] as u32) << 24)
        | ((octets[1] as u32) << 16)
        | ((octets[2] as u32) << 8)
        | octets[3] as u32
}

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
        if let Some(parts) = parse_ipv4_octets(&ip) {
            return Ok(parts[0] == 10
                || (parts[0] == 172 && (16..=31).contains(&parts[1]))
                || (parts[0] == 192 && parts[1] == 168));
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
        if let (Some(ip_parts), Some(mask_parts)) =
            (parse_ipv4_octets(&ip), parse_ipv4_octets(&mask))
        {
            let ip_num = ipv4_to_u32(ip_parts);
            let mask_num = ipv4_to_u32(mask_parts);
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

#[cfg(test)]
mod tests {
    use super::*;
    use mlua::Lua;

    #[test]
    fn parse_ipv4_octets_requires_exactly_four_valid_octets() {
        assert_eq!(parse_ipv4_octets("192.168.1.10"), Some([192, 168, 1, 10]));
        assert_eq!(parse_ipv4_octets("192.168.1"), None);
        assert_eq!(parse_ipv4_octets("192.168.1.10.5"), None);
        assert_eq!(parse_ipv4_octets("192.168.bad.10"), None);
        assert_eq!(parse_ipv4_octets("192.168.999.10"), None);
    }

    #[test]
    fn is_private_does_not_ignore_malformed_octets() {
        let lua = Lua::new();
        register_ipops_library(&lua).expect("register ipOps");

        let private: bool = lua
            .load("return ipOps.is_private('10.bad.0.1.2')")
            .eval()
            .expect("script should run");
        assert!(!private);
    }

    #[test]
    fn get_network_does_not_ignore_malformed_octets() {
        let lua = Lua::new();
        register_ipops_library(&lua).expect("register ipOps");

        let network: String = lua
            .load("return ipOps.get_network('192.168.bad.5.9', '255.255.255.0')")
            .eval()
            .expect("script should run");
        assert_eq!(network, "192.168.bad.5.9");
    }
}
