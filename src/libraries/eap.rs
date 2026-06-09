//! NSE eap library wrapper
//!
//! EAP (Extensible Authentication Protocol) support.
//! Based on Nmap's eap library.

use mlua::{Lua, Result as LuaResult};

pub fn register_eap_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let eap = lua.create_table()?;

    eap.set(
        "types",
        lua.create_function(|lua, _: ()| {
            let types = lua.create_table()?;
            types.set(1, "EAP-Identity")?;
            types.set(4, "EAP-MD5")?;
            types.set(6, "EAP-GTC")?;
            types.set(13, "EAP-TLS")?;
            types.set(17, "EAP-SIM")?;
            types.set(18, "EAP-AKA")?;
            types.set(21, "EAP-TTLS")?;
            types.set(25, "EAP-PEAP")?;
            types.set(29, "EAP-MSCHAPV2")?;
            types.set(43, "EAP-FAST")?;
            types.set(48, "EAP-SIM")?;
            types.set(49, "EAP-AKA")?;
            types.set(50, "EAP-AKA'")?;
            types.set(51, "EAP-GPSK")?;
            types.set(52, "EAP-PWD")?;
            types.set(53, "EAP-SPEKE")?;
            types.set(54, "EAP-EKE")?;
            types.set(55, "EAP-IBUR")?;
            types.set(56, "EAP-SHA256")?;
            types.set(57, "EAP-TEAP")?;
            Ok(types)
        })?,
    )?;

    eap.set(
        "type_to_name",
        lua.create_function(|_lua, eap_type: u8| {
            let name = match eap_type {
                1 => "EAP-Identity",
                4 => "EAP-MD5",
                6 => "EAP-GTC",
                13 => "EAP-TLS",
                17 => "EAP-SIM",
                18 => "EAP-AKA",
                21 => "EAP-TTLS",
                25 => "EAP-PEAP",
                29 => "EAP-MSCHAPV2",
                43 => "EAP-FAST",
                48 => "EAP-SIM",
                49 => "EAP-AKA",
                50 => "EAP-AKA'",
                51 => "EAP-GPSK",
                52 => "EAP-PWD",
                53 => "EAP-SPEKE",
                54 => "EAP-EKE",
                55 => "EAP-IBUR",
                56 => "EAP-SHA256",
                57 => "EAP-TEAP",
                _ => "Unknown",
            };
            Ok(name)
        })?,
    )?;

    eap.set(
        "name_to_type",
        lua.create_function(|_lua, name: String| {
            let eap_type = match name.to_uppercase().as_str() {
                "EAP-IDENTITY" => 1,
                "EAP-MD5" => 4,
                "EAP-GTC" => 6,
                "EAP-TLS" => 13,
                "EAP-SIM" => 17,
                "EAP-AKA" => 18,
                "EAP-TTLS" => 21,
                "EAP-PEAP" => 25,
                "EAP-MSCHAPV2" => 29,
                "EAP-FAST" => 43,
                "EAP-AKA'" => 50,
                "EAP-GPSK" => 51,
                "EAP-PWD" => 52,
                "EAP-SPEKE" => 53,
                "EAP-EKE" => 54,
                "EAP-IBUR" => 55,
                "EAP-SHA256" => 56,
                "EAP-TEAP" => 57,
                _ => 0,
            };
            Ok(eap_type)
        })?,
    )?;

    eap.set(
        "parse_header",
        lua.create_function(|lua, data: String| {
            let result = lua.create_table()?;

            if data.len() < 4 {
                result.set("status", "error")?;
                result.set("errmsg", "Data too short for EAP header")?;
                return Ok(result);
            }

            let bytes = data.as_bytes();
            let code = bytes[0];
            let id = bytes[1];
            let length = ((bytes[2] as u16) << 8) | (bytes[3] as u16);

            let code_str = match code {
                1 => "Request",
                2 => "Response",
                3 => "Success",
                4 => "Failure",
                _ => "Unknown",
            };

            result.set("status", "ok")?;
            result.set("code", code)?;
            result.set("code_str", code_str)?;
            result.set("id", id)?;
            result.set("length", length)?;

            if data.len() >= 5 {
                let eap_type = bytes[4];
                result.set("type", eap_type)?;
            }

            Ok(result)
        })?,
    )?;

    eap.set(
        "build_identity_request",
        lua.create_function(|_lua, (id, identity): (u8, String)| {
            let mut packet = vec![1u8, id, 0, 0, 1];
            packet.extend(identity.as_bytes());
            let len = packet.len() as u16;
            packet[2] = (len >> 8) as u8;
            packet[3] = (len & 0xFF) as u8;
            Ok(packet)
        })?,
    )?;

    eap.set(
        "build_identity_response",
        lua.create_function(|_lua, (id, identity): (u8, String)| {
            let mut packet = vec![2u8, id, 0, 0, 1];
            packet.extend(identity.as_bytes());
            let len = packet.len() as u16;
            packet[2] = (len >> 8) as u8;
            packet[3] = (len & 0xFF) as u8;
            Ok(packet)
        })?,
    )?;

    eap.set(
        "build_success",
        lua.create_function(|_lua, id: u8| Ok(vec![3u8, id, 0, 4]))?,
    )?;

    eap.set(
        "build_failure",
        lua.create_function(|_lua, id: u8| Ok(vec![4u8, id, 0, 4]))?,
    )?;

    eap.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("eap", eap)?;
    Ok(())
}
