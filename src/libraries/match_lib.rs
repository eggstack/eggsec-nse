//! NSE match library wrapper
//!
//! Provides pattern matching functions for portrules.

use mlua::{Lua, Result as LuaResult, Table};
use regex::RegexBuilder;
use rustc_hash::FxHashMap;
use std::sync::OnceLock;

static SERVICE_PATTERNS: OnceLock<FxHashMap<&'static str, Vec<&'static str>>> = OnceLock::new();

fn get_service_patterns() -> &'static FxHashMap<&'static str, Vec<&'static str>> {
    SERVICE_PATTERNS.get_or_init(|| {
        let mut m = FxHashMap::default();
        m.insert(
            "http",
            vec!["http", "https", "apache", "nginx", "iis", "web"],
        );
        m.insert("ftp", vec!["ftp", "vsftpd", "proftpd", "filezilla"]);
        m.insert("ssh", vec!["ssh", "openssh", "dropbear"]);
        m.insert("telnet", vec!["telnet", "cisco"]);
        m.insert("smtp", vec!["smtp", "postfix", "exim", "sendmail"]);
        m.insert("pop3", vec!["pop3", "dovecot", "courier"]);
        m.insert("imap", vec!["imap", "dovecot", "courier"]);
        m.insert("mysql", vec!["mysql", "mariadb"]);
        m.insert("postgres", vec!["postgres", "postgresql"]);
        m.insert("mongodb", vec!["mongodb", "mongod"]);
        m.insert("redis", vec!["redis"]);
        m.insert("ldap", vec!["ldap", "openldap"]);
        m.insert("smb", vec!["smb", "samba", "microsoft-ds"]);
        m.insert("snmp", vec!["snmp"]);
        m.insert("dns", vec!["dns", "bind", "named"]);
        m.insert("vnc", vec!["vnc", "x11"]);
        m.insert("rdp", vec!["rdp", "terminal", "3389"]);
        m.insert("sip", vec!["sip", "voip"]);
        m
    })
}

pub fn register_match_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let match_mod = lua.create_table()?;

    match_mod.set(
        "service",
        lua.create_function(
            |_lua, (_service_patterns, service): (Option<Table>, String)| {
                let patterns = get_service_patterns();
                let service_lower = service.to_lowercase();

                for (name, keywords) in patterns.iter() {
                    for keyword in keywords {
                        if service_lower.contains(keyword) {
                            return Ok(name.to_string());
                        }
                    }
                }

                Ok(String::new())
            },
        )?,
    )?;

    match_mod.set(
        "name",
        lua.create_function(|_lua, (name_patterns, name): (Option<Table>, String)| {
            if let Some(patterns) = name_patterns {
                for i in 1.. {
                    let pattern: String = match patterns.get(i) {
                        Ok(p) => p,
                        Err(_) => break,
                    };
                    let pattern_lower = pattern.to_lowercase();
                    let name_lower = name.to_lowercase();

                    if name_lower.contains(&pattern_lower) || pattern_lower.contains(&name_lower) {
                        return Ok(pattern);
                    }
                }
            }
            Ok(String::new())
        })?,
    )?;

    match_mod.set(
        "regex",
        lua.create_function(
            |_lua, (regex_pattern, text): (String, String)| match RegexBuilder::new(&regex_pattern)
                .size_limit(50_000)
                .build()
            {
                Ok(re) => {
                    if let Some(m) = re.find(&text) {
                        Ok(m.as_str().to_string())
                    } else {
                        Ok(String::new())
                    }
                }
                Err(_) => Ok(String::new()),
            },
        )?,
    )?;

    match_mod.set(
        "ip",
        lua.create_function(|_lua, (_ip_patterns, ip): (Option<Table>, String)| {
            if ip.contains('.') {
                let parts: Vec<&str> = ip.split('.').collect();
                if parts.len() == 4 {
                    return Ok(ip.to_string());
                }
            }
            Ok(String::new())
        })?,
    )?;

    match_mod.set(
        "port",
        lua.create_function(|_lua, port: i32| {
            if port > 0 && port <= 65535 {
                Ok(port)
            } else {
                Ok(0)
            }
        })?,
    )?;

    match_mod.set(
        "hosts",
        lua.create_function(|_lua, host: String| {
            if host.contains('/') {
                return Ok(host);
            }

            let parts: Vec<&str> = host.split(',').collect();
            if parts.len() > 1 {
                return Ok(host);
            }

            if host.parse::<std::net::Ipv4Addr>().is_ok() {
                return Ok(host);
            }

            if host.parse::<std::net::Ipv6Addr>().is_ok() {
                return Ok(host);
            }

            Ok(String::new())
        })?,
    )?;

    match_mod.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("match", match_mod)?;
    Ok(())
}
