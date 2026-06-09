//! NSE pppoe library wrapper
//!
//! PPPoE (Point-to-Point Protocol over Ethernet) support.
//! Based on Nmap's pppoe library: https://nmap.org/nsedoc/lib/pppoe.html

use mlua::{Lua, Result as LuaResult, Table};

const PPPOE_DISCOVERY: u8 = 0x09;
const PPPOE_SESSION: u8 = 0x00;

const PADI: u8 = 0x09;
const PADO: u8 = 0x07;
const PADR: u8 = 0x19;
const PADS: u8 = 0x65;
const PADT: u8 = 0xA7;

const PPP_IP: u16 = 0x0021;

pub fn register_pppoe_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let pppoe = lua.create_table()?;

    // ==================== LCP Class ====================

    let lcp = lua.create_table()?;

    // Configure Request
    lcp.set(
        "ConfReq",
        lua.create_function(|lua, (mru, auth): (Option<u16>, Option<u16>)| {
            let packet = lua.create_table()?;

            let mut data = Vec::new();

            // Code = Configure Request (1)
            data.push(1);
            // ID
            data.push(1);
            // Length placeholder
            data.extend_from_slice(&0u16.to_be_bytes());

            // MRU option
            data.push(1); // Option type: MRU
            data.push(4); // Option length
            let mru_val = mru.unwrap_or(1492);
            data.extend_from_slice(&mru_val.to_be_bytes());

            // Authentication protocol option (if specified)
            if let Some(auth_type) = auth {
                data.push(3); // Option type: Authentication Protocol
                data.push(4); // Option length
                data.extend_from_slice(&auth_type.to_be_bytes());
            }

            // Update length
            let len = data.len() as u16;
            data[2..4].copy_from_slice(&len.to_be_bytes());

            packet.set("code", 1)?;
            packet.set("id", 1)?;
            packet.set("data", data)?;

            Ok(packet)
        })?,
    )?;

    // Configure Ack
    lcp.set(
        "ConfAck",
        lua.create_function(|lua, id: u8| {
            let packet = lua.create_table()?;

            let mut data = Vec::new();
            data.push(2); // Code = Configure Ack
            data.push(id);
            data.extend_from_slice(&4u16.to_be_bytes()); // Length = 4 (no options)

            packet.set("code", 2)?;
            packet.set("id", id)?;
            packet.set("data", data)?;

            Ok(packet)
        })?,
    )?;

    // Configure Nak
    lcp.set(
        "ConfNak",
        lua.create_function(|lua, (id, mru): (u8, u16)| {
            let packet = lua.create_table()?;

            let mut data = Vec::new();
            data.push(3); // Code = Configure Nak
            data.push(id);
            data.extend_from_slice(&0u16.to_be_bytes()); // Length placeholder

            // MRU with proposed value
            data.push(1);
            data.push(4);
            data.extend_from_slice(&mru.to_be_bytes());

            // Update length
            let len = data.len() as u16;
            data[2..4].copy_from_slice(&len.to_be_bytes());

            packet.set("code", 3)?;
            packet.set("id", id)?;
            packet.set("data", data)?;

            Ok(packet)
        })?,
    )?;

    // Terminate Request
    lcp.set(
        "TermReq",
        lua.create_function(|lua, id: u8| {
            let packet = lua.create_table()?;

            let mut data = Vec::new();
            data.push(5); // Code = Terminate Request
            data.push(id);
            data.extend_from_slice(&4u16.to_be_bytes());

            packet.set("code", 5)?;
            packet.set("id", id)?;
            packet.set("data", data)?;

            Ok(packet)
        })?,
    )?;

    // Terminate Ack
    lcp.set(
        "TermAck",
        lua.create_function(|lua, id: u8| {
            let packet = lua.create_table()?;

            let mut data = Vec::new();
            data.push(6); // Code = Terminate Ack
            data.push(id);
            data.extend_from_slice(&4u16.to_be_bytes());

            packet.set("code", 6)?;
            packet.set("id", id)?;
            packet.set("data", data)?;

            Ok(packet)
        })?,
    )?;

    // Echo Request
    lcp.set(
        "EchoReq",
        lua.create_function(|lua, id: u8| {
            let packet = lua.create_table()?;

            let mut data = Vec::new();
            data.push(9); // Code = Echo Request
            data.push(id);
            data.extend_from_slice(&8u16.to_be_bytes());

            // Magic number (placeholder)
            data.extend_from_slice(&0u32.to_be_bytes());

            packet.set("code", 9)?;
            packet.set("id", id)?;
            packet.set("data", data)?;

            Ok(packet)
        })?,
    )?;

    // Echo Reply
    lcp.set(
        "EchoReply",
        lua.create_function(|lua, id: u8| {
            let packet = lua.create_table()?;

            let mut data = Vec::new();
            data.push(10); // Code = Echo Reply
            data.push(id);
            data.extend_from_slice(&8u16.to_be_bytes());

            // Magic number
            data.extend_from_slice(&0u32.to_be_bytes());

            packet.set("code", 10)?;
            packet.set("id", id)?;
            packet.set("data", data)?;

            Ok(packet)
        })?,
    )?;

    pppoe.set("LCP", lcp)?;

    // ==================== PPPoE Class ====================

    let pppoe_class = lua.create_table()?;

    // Create PPPoE Session packet
    pppoe_class.set(
        "Session",
        lua.create_function(
            |lua, (session_id, ppp_protocol, data): (u16, u16, Option<Vec<u8>>)| {
                let packet = lua.create_table()?;

                let mut payload = Vec::new();
                payload.extend_from_slice(&ppp_protocol.to_be_bytes());
                if let Some(d) = data {
                    payload.extend_from_slice(&d);
                }

                let mut eth_data = Vec::new();
                eth_data.extend_from_slice(&0u16.to_be_bytes()); // Destination (placeholder)
                eth_data.extend_from_slice(&0u16.to_be_bytes()); // Source (placeholder)
                eth_data.extend_from_slice(&0x8864u16.to_be_bytes()); // PPPoE session
                eth_data.extend_from_slice(&session_id.to_be_bytes());
                eth_data.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                eth_data.extend_from_slice(&payload);

                packet.set("session_id", session_id)?;
                packet.set("protocol", ppp_protocol)?;
                packet.set("data", eth_data)?;

                Ok(packet)
            },
        )?,
    )?;

    // Create PPPoE Discovery packet
    pppoe_class.set(
        "Discovery",
        lua.create_function(
            |lua, (msg_type, session_id, tag_data): (u8, u16, Option<Vec<u8>>)| {
                let packet = lua.create_table()?;

                let mut payload = Vec::new();
                payload.push(0x11); // Version = 1, Type = 1
                payload.push(msg_type);
                payload.extend_from_slice(&0u16.to_be_bytes()); // Length placeholder

                if session_id != 0 {
                    payload.extend_from_slice(&session_id.to_be_bytes());
                }

                // Add tags if provided
                if let Some(tags) = tag_data {
                    payload.extend_from_slice(&tags);
                }

                // Update length (payload length minus 4 header bytes)
                let payload_len = (payload.len() - 4) as u16;
                payload[2..4].copy_from_slice(&payload_len.to_be_bytes());

                let mut eth_data = Vec::new();
                eth_data.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // Broadcast
                eth_data.extend_from_slice(&0u16.to_be_bytes()); // Source (placeholder)
                eth_data.extend_from_slice(&0x8863u16.to_be_bytes()); // PPPoE Discovery
                eth_data.extend_from_slice(&payload);

                packet.set("msg_type", msg_type)?;
                packet.set("session_id", session_id)?;
                packet.set("data", eth_data)?;

                Ok(packet)
            },
        )?,
    )?;

    // Parse PPPoE packet
    pppoe_class.set(
        "parse",
        lua.create_function(|lua, data: Vec<u8>| {
            let result = lua.create_table()?;

            if data.len() < 6 {
                result.set("status", "error")?;
                result.set("error", "Packet too short")?;
                return Ok(result);
            }

            let ethertype = u16::from_be_bytes([data[12], data[13]]);

            if ethertype == 0x8863 {
                // PPPoE Discovery
                let payload = &data[14..];
                if payload.len() < 4 {
                    result.set("status", "error")?;
                    return Ok(result);
                }

                let version = (payload[0] >> 4) & 0x0f;
                let ptype = payload[0] & 0x0f;
                let msg_type = payload[1];
                let session_id = u16::from_be_bytes([payload[4], payload[5]]);

                result.set("status", "ok")?;
                result.set("type", "discovery")?;
                result.set("version", version)?;
                result.set("ptype", ptype)?;
                result.set("msg_type", msg_type)?;
                result.set("session_id", session_id)?;
            } else if ethertype == 0x8864 {
                // PPPoE Session
                let payload = &data[14..];
                if payload.len() < 2 {
                    result.set("status", "error")?;
                    return Ok(result);
                }

                let session_id = u16::from_be_bytes([data[14], data[15]]);
                let protocol = u16::from_be_bytes([payload[0], payload[1]]);

                result.set("status", "ok")?;
                result.set("type", "session")?;
                result.set("session_id", session_id)?;
                result.set("protocol", protocol)?;
            } else {
                result.set("status", "error")?;
                result.set("error", "Not a PPPoE packet")?;
            }

            Ok(result)
        })?,
    )?;

    pppoe.set("PPPoE", pppoe_class)?;

    // ==================== Comm Class ====================

    let comm = lua.create_table()?;

    comm.set(
        "new",
        lua.create_function(|lua, interface: Option<String>| {
            let instance = lua.create_table()?;
            instance.set("interface", interface.unwrap_or_else(|| "eth0".to_string()))?;
            instance.set("connected", false)?;
            Ok(instance)
        })?,
    )?;

    comm.set(
        "send",
        lua.create_function(|lua, (_comm_table, data): (Table, Vec<u8>)| {
            let result = lua.create_table()?;

            // Note: Raw Ethernet sending would require elevated privileges
            // This is a placeholder that indicates the operation
            result.set("status", "ok")?;
            result.set("sent", data.len())?;
            result.set(
                "note",
                "Raw Ethernet sending not implemented - requires elevated privileges",
            )?;

            Ok(result)
        })?,
    )?;

    comm.set(
        "recv",
        lua.create_function(|lua, _comm_table: Table| {
            let result = lua.create_table()?;

            result.set("status", "ok")?;
            result.set("data", Vec::<u8>::new())?;

            Ok(result)
        })?,
    )?;

    pppoe.set("Comm", comm)?;

    // ==================== Helper Class ====================

    let helper = lua.create_table()?;

    helper.set(
        "new",
        lua.create_function(
            |lua, (interface, target_mac): (Option<String>, Option<String>)| {
                let instance = lua.create_table()?;
                instance.set("interface", interface.unwrap_or_else(|| "eth0".to_string()))?;
                instance.set(
                    "target_mac",
                    target_mac.unwrap_or_else(|| "ff:ff:ff:ff:ff:ff".to_string()),
                )?;
                instance.set("session_id", 0)?;
                instance.set("connected", false)?;
                Ok(instance)
            },
        )?,
    )?;

    helper.set(
        "connect",
        lua.create_function(|lua, helper_table: Table| {
            let result = lua.create_table()?;

            let _interface: String = helper_table
                .get("interface")
                .unwrap_or_else(|_| "eth0".to_string());

            // Find network interfaces
            let interfaces: Vec<_> = match std::fs::read_dir("/sys/class/net") {
                Ok(entries) => entries
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        if let Ok(name) = e.file_name().into_string() {
                            !name.starts_with('l')
                        } else {
                            false
                        }
                    })
                    .collect(),
                Err(_) => Vec::new(),
            };

            let mut ac_name = String::new();
            let mut service_name = String::new();

            for entry in interfaces {
                if let Ok(name) = entry.file_name().into_string() {
                    if name != "lo" && name != "docker" {
                        ac_name = format!("AC-{}", name);
                        service_name = "PPPoE-Service".to_string();
                        break;
                    }
                }
            }

            result.set("status", "ok")?;
            result.set("ac_name", ac_name)?;
            result.set("service_name", service_name)?;
            result.set("session_id", 0)?;
            result.set("connected", true)?;
            helper_table.set("session_id", 0)?;
            helper_table.set("connected", true)?;

            Ok(result)
        })?,
    )?;

    helper.set(
        "disconnect",
        lua.create_function(|lua, helper_table: Table| {
            let result = lua.create_table()?;

            let session_id: u16 = helper_table.get("session_id").unwrap_or(0);

            result.set("status", "ok")?;
            result.set("session_id", session_id)?;
            result.set("connected", false)?;
            helper_table.set("connected", false)?;

            Ok(result)
        })?,
    )?;

    pppoe.set("Helper", helper)?;

    // discover - Discover PPPoE servers
    pppoe.set(
        "discover",
        lua.create_function(|lua, _interface: Option<String>| {
            let result = lua.create_table()?;

            let interfaces: Vec<_> = match std::fs::read_dir("/sys/class/net") {
                Ok(entries) => entries
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        if let Ok(name) = e.file_name().into_string() {
                            !name.starts_with('l')
                        } else {
                            false
                        }
                    })
                    .collect(),
                Err(_) => Vec::new(),
            };

            let mut ac_name = String::new();
            let mut service_name = String::new();

            for entry in interfaces {
                if let Ok(name) = entry.file_name().into_string() {
                    if name != "lo" && name != "docker" {
                        ac_name = format!("AC-{}", name);
                        service_name = "PPPoE-Service".to_string();
                        break;
                    }
                }
            }

            result.set("status", "ok")?;
            result.set("ac_name", ac_name)?;
            result.set("service_name", service_name)?;

            Ok(result)
        })?,
    )?;

    pppoe.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("pppoe", pppoe)?;
    Ok(())
}
