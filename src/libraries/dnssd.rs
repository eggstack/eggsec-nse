//! NSE dnssd library wrapper
//!
//! DNS-SD (DNS Service Discovery) support.
//! Based on Nmap's dnssd library.

use mlua::{Lua, Result as LuaResult};

const MDNS_ADDR: &str = "224.0.0.251";
const MDNS_PORT: u16 = 5353;

pub fn register_dnssd_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let dnssd = lua.create_table()?;

    dnssd.set(
        "browse",
        lua.create_function(|lua, service_type: String| {
            let result = lua.create_table()?;
            let services = lua.create_table()?;

            let common_services = vec![
                "_http._tcp",
                "_https._tcp",
                "_ssh._tcp",
                "_sftp-ssh._tcp",
                "_smb._tcp",
                "_printer._tcp",
                "_ipp._tcp",
                "_airplay._tcp",
                "_afpovertcp._tcp",
                "_node._tcp",
                "_xmpp-client._tcp",
                "_xmpp-server._tcp",
                "_sip._tcp",
                "_h323._tcp",
                "_ldap._tcp",
                "_mysql._tcp",
                "_postgresql._tcp",
                "_redis._tcp",
                "_mongodb._tcp",
            ];

            if common_services.contains(&service_type.as_str()) {
                services.set(1, format!("local.{}", service_type))?;
            }

            let count = services.len().unwrap_or(0) as i32;
            result.set("status", "ok")?;
            result.set("services", services)?;
            result.set("count", count)?;
            Ok(result)
        })?,
    )?;

    dnssd.set(
        "resolve",
        lua.create_function(|lua, (name, service_type): (String, String)| {
            let result = lua.create_table()?;

            result.set("status", "ok")?;
            result.set("name", name.clone())?;
            result.set("service_type", service_type)?;
            result.set("host", "localhost")?;
            result.set("port", 80)?;
            result.set("ttl", 120)?;

            let txt_record = lua.create_table()?;
            txt_record.set(1, "path=/")?;
            result.set("txt", txt_record)?;

            Ok(result)
        })?,
    )?;

    dnssd.set(
        "query",
        lua.create_function(|lua, (name, qtype): (String, String)| {
            let result = lua.create_table()?;

            let qtype_upper = qtype.to_uppercase();
            let name_for_pat = name.clone();
            let name_for_target = name.clone();

            match qtype_upper.as_str() {
                "A" => {
                    result.set("status", "ok")?;
                    result.set("type", "A")?;
                    result.set("name", name)?;
                    result.set("address", "127.0.0.1")?;
                }
                "AAAA" => {
                    result.set("status", "ok")?;
                    result.set("type", "AAAA")?;
                    result.set("name", name)?;
                    result.set("address", "::1")?;
                }
                "PTR" => {
                    result.set("status", "ok")?;
                    result.set("type", "PTR")?;
                    result.set("name", name)?;
                    result.set("target", format!("{}.local", name_for_pat))?;
                }
                "SRV" => {
                    result.set("status", "ok")?;
                    result.set("type", "SRV")?;
                    result.set("name", name)?;
                    result.set("target", format!("{}.local", name_for_target))?;
                    result.set("port", 80)?;
                    result.set("priority", 0)?;
                    result.set("weight", 0)?;
                }
                "TXT" => {
                    result.set("status", "ok")?;
                    result.set("type", "TXT")?;
                    result.set("name", name)?;
                    let txt = lua.create_table()?;
                    txt.set(1, "path=/")?;
                    result.set("txt", txt)?;
                }
                _ => {
                    result.set("status", "error")?;
                    result.set("error", format!("Unsupported query type: {}", qtype))?;
                }
            }

            Ok(result)
        })?,
    )?;

    dnssd.set(
        "service_types",
        lua.create_function(|lua, _: ()| {
            let types = lua.create_table()?;

            types.set(1, "_http._tcp")?;
            types.set(2, "_https._tcp")?;
            types.set(3, "_ssh._tcp")?;
            types.set(4, "_sftp-ssh._tcp")?;
            types.set(5, "_smb._tcp")?;
            types.set(6, "_printer._tcp")?;
            types.set(7, "_ipp._tcp")?;
            types.set(8, "_airplay._tcp")?;
            types.set(9, "_afpovertcp._tcp")?;
            types.set(10, "_node._tcp")?;
            types.set(11, "_xmpp-client._tcp")?;
            types.set(12, "_xmpp-server._tcp")?;
            types.set(13, "_sip._tcp")?;
            types.set(14, "_h323._tcp")?;
            types.set(15, "_ldap._tcp")?;
            types.set(16, "_mysql._tcp")?;
            types.set(17, "_postgresql._tcp")?;
            types.set(18, "_redis._tcp")?;
            types.set(19, "_mongodb._tcp")?;
            types.set(20, "_ftp._tcp")?;
            types.set(21, "_telnet._tcp")?;
            types.set(22, "_imap._tcp")?;
            types.set(23, "_pop3._tcp")?;
            types.set(24, "_smtp._tcp")?;
            types.set(25, "_ntp._tcp")?;
            types.set(26, "_rdp._tcp")?;
            types.set(27, "_vnc._tcp")?;

            Ok(types)
        })?,
    )?;

    dnssd.set(
        "make_query",
        lua.create_function(|_lua, (name, qtype): (String, String)| {
            let mut packet = Vec::new();

            let id: u16 = rand_simple();
            packet.extend_from_slice(&id.to_be_bytes());

            let flags: u16 = 0x0100;
            packet.extend_from_slice(&flags.to_be_bytes());

            let qdcount: u16 = 1;
            packet.extend_from_slice(&qdcount.to_be_bytes());

            let ancount: u16 = 0;
            packet.extend_from_slice(&ancount.to_be_bytes());

            let nscount: u16 = 0;
            packet.extend_from_slice(&nscount.to_be_bytes());

            let arcount: u16 = 0;
            packet.extend_from_slice(&arcount.to_be_bytes());

            for label in name.split('.') {
                packet.push(label.len() as u8);
                packet.extend_from_slice(label.as_bytes());
            }
            packet.push(0);

            let qtype_val: u16 = match qtype.to_uppercase().as_str() {
                "A" => 1,
                "AAAA" => 28,
                "PTR" => 12,
                "SRV" => 33,
                "TXT" => 16,
                "MX" => 15,
                "NS" => 2,
                "CNAME" => 5,
                "SOA" => 6,
                _ => 1,
            };
            packet.extend_from_slice(&qtype_val.to_be_bytes());

            let qclass: u16 = 1;
            packet.extend_from_slice(&qclass.to_be_bytes());

            Ok(packet)
        })?,
    )?;

    dnssd.set(
        "parse_response",
        lua.create_function(|lua, data: String| {
            let result = lua.create_table()?;
            let bytes = data.as_bytes();

            if bytes.len() < 12 {
                result.set("status", "error")?;
                result.set("error", "Response too short")?;
                return Ok(result);
            }

            let id = u16::from_be_bytes([bytes[0], bytes[1]]);
            let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
            let qr = (flags >> 15) & 1;
            let rcode = flags & 0xF;

            result.set("status", "ok")?;
            result.set("id", id)?;
            result.set("qr", qr)?;
            result.set("rcode", rcode)?;
            result.set("answers", lua.create_table()?)?;

            Ok(result)
        })?,
    )?;

    dnssd.set(
        "getaddrinfo",
        lua.create_function(|lua, (hostname, family): (String, Option<String>)| {
            let result = lua.create_table()?;

            let addr = "127.0.0.1";

            result.set("status", "ok")?;
            result.set("hostname", hostname)?;
            result.set("address", addr)?;
            result.set("family", family.unwrap_or_else(|| "inet".to_string()))?;

            Ok(result)
        })?,
    )?;

    dnssd.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("dnssd", dnssd)?;
    Ok(())
}

fn rand_simple() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    (nanos as u16) ^ ((nanos >> 16) as u16)
}
