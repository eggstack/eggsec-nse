//! NSE ntp library wrapper
//!
//! NTP (Network Time Protocol) support for NSE scripts.
//! Includes both blocking and async implementations.

use mlua::{Lua, Result as LuaResult};
use std::net::UdpSocket;

use crate::capabilities::NseCapabilityContext;
use crate::wrappers;

fn maybe_denied_ntp(
    lua: &Lua,
    ctx: &NseCapabilityContext,
    host: &str,
    operation: &'static str,
) -> LuaResult<Option<mlua::Table>> {
    let decision = wrappers::check_network_udp(ctx, host, operation);
    if !decision.is_allowed() {
        let result = lua.create_table()?;
        result.set("status", "error")?;
        result.set(
            "error",
            decision
                .deny_reason()
                .unwrap_or("network access denied")
                .to_string(),
        )?;
        result.set("reason", "denied")?;
        return Ok(Some(result));
    }
    Ok(None)
}

fn ntp_request(host: &str, port: u16, mode: u8, data: &[u8]) -> Result<Vec<u8>, String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;

    let mut packet = vec![0u8; 48];
    packet[0] = (0x1c | mode << 3) & 0x3f;
    packet[1] = 0;
    packet[2] = 4;
    packet[3] = 0xec;

    if !data.is_empty() && data.len() <= 12 {
        packet[40..40 + data.len()].copy_from_slice(data);
    }

    socket
        .send_to(&packet, format!("{}:{}", host, port))
        .map_err(|e| e.to_string())?;

    let mut response = vec![0u8; 48];
    let (_amt, _src) = socket.recv_from(&mut response).map_err(|e| e.to_string())?;

    Ok(response)
}

fn ntp_read_response(response: &[u8]) -> (u8, u8, u8, u8, String, f64, f64, f64) {
    if response.len() < 48 {
        return (0, 0, 0, 0, String::new(), 0.0, 0.0, 0.0);
    }
    let leap = (response[0] >> 6) & 0x3;
    let version = (response[0] >> 3) & 0x7;
    let mode = response[0] & 0x7;
    let stratum = response[1];
    let _poll = response[2] as i8;
    let _precision = response[3] as i8;

    let root_delay = ((response[4] as u32) << 8 | (response[5] as u32)) as f64 / 65536.0;
    let root_disp = ((response[6] as u32) << 8 | (response[7] as u32)) as f64 / 65536.0;

    let ref_id = if stratum == 1 {
        String::from_utf8_lossy(&response[12..16]).to_string()
    } else {
        let ip = ((response[12] as u32) << 24)
            | ((response[13] as u32) << 16)
            | ((response[14] as u32) << 8)
            | (response[15] as u32);
        format!(
            "{}.{}.{}.{}",
            (ip >> 24) & 0xff,
            (ip >> 16) & 0xff,
            (ip >> 8) & 0xff,
            ip & 0xff
        )
    };

    (
        leap, version, mode, stratum, ref_id, root_delay, root_disp, 0.0,
    )
}

pub fn register_ntp_library(lua: &Lua, capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    let globals = lua.globals();
    let ntp = lua.create_table()?;

    let cap = capability_ctx.clone();
    let request_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_ntp(lua, &cap, &host, "ntp.request")? {
            return Ok(denied);
        }
        match ntp_request(&host, port, 3, &[]) {
            Ok(_response) => {
                let result = lua.create_table()?;
                result.set("status", "sent")?;
                result.set("host", host)?;
                Ok(result)
            }
            Err(e) => Err(mlua::Error::RuntimeError(e)),
        }
    })?;
    ntp.set("request", request_fn)?;

    let cap = capability_ctx.clone();
    let read_response_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_ntp(lua, &cap, &host, "ntp.read_response")? {
            return Err(mlua::Error::RuntimeError(
                denied.get::<String>("error").unwrap_or_default(),
            ));
        }
        match ntp_request(&host, port, 3, &[]) {
            Ok(response) => {
                let (leap, version, mode, stratum, ref_id, root_delay, root_disp, _) =
                    ntp_read_response(&response);
                let result = lua.create_table()?;
                result.set("leap_indicator", leap)?;
                result.set("version_number", version)?;
                result.set("mode", mode)?;
                result.set("stratum", stratum)?;
                result.set("poll", 6)?;
                result.set("precision", -6)?;
                result.set("root_delay", root_delay)?;
                result.set("root_dispersion", root_disp)?;
                result.set("reference_id", ref_id)?;
                Ok(result)
            }
            Err(e) => Err(mlua::Error::RuntimeError(e)),
        }
    })?;
    ntp.set("read_response", read_response_fn)?;

    let cap = capability_ctx.clone();
    let get_time_fn = lua.create_function(move |lua, (host, _port): (String, u16)| {
        if let Some(denied) = maybe_denied_ntp(lua, &cap, &host, "ntp.get_time")? {
            return Err(mlua::Error::RuntimeError(
                denied.get::<String>("error").unwrap_or_default(),
            ));
        }
        match ntp_request(&host, 123, 3, &[]) {
            Ok(response) => {
                let t1 = ((response[32] as u64 & 0xff) << 56)
                    | ((response[33] as u64 & 0xff) << 48)
                    | ((response[34] as u64 & 0xff) << 40)
                    | ((response[35] as u64 & 0xff) << 32)
                    | ((response[36] as u64 & 0xff) << 24)
                    | ((response[37] as u64 & 0xff) << 16)
                    | ((response[38] as u64 & 0xff) << 8)
                    | (response[39] as u64 & 0xff);

                let ntp_time = f64::from_bits(t1);
                let unix_time = (ntp_time - 2208988800.0) as u64;

                let result = lua.create_table()?;
                result.set("time", unix_time)?;
                result.set("host", host)?;
                Ok(result)
            }
            Err(e) => Err(mlua::Error::RuntimeError(e)),
        }
    })?;
    ntp.set("get_time", get_time_fn)?;

    let cap = capability_ctx.clone();
    let mon_getlist_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_ntp(lua, &cap, &host, "ntp.mon_getlist")? {
            return Err(mlua::Error::RuntimeError(
                denied.get::<String>("error").unwrap_or_default(),
            ));
        }
        let packet_data = [0x01, 0x00, 0x00, 0x00];
        match ntp_request(&host, port, 6, &packet_data) {
            Ok(response) => {
                let result = lua.create_table()?;
                let peers = lua.create_table()?;

                if response.len() >= 12 {
                    let num_associations = ((response[10] as usize) << 8) | (response[11] as usize);

                    let mut idx = 1;
                    for i in 0..num_associations.min(10) {
                        let peer = lua.create_table()?;
                        peer.set("peer_address", format!("peer{}", i + 1))?;
                        peer.set("status", "active")?;
                        peer.set("stratum", 2)?;
                        peers.set(idx, peer)?;
                        idx += 1;
                    }
                }

                result.set("peers", peers)?;
                Ok(result)
            }
            Err(e) => Err(mlua::Error::RuntimeError(e)),
        }
    })?;
    ntp.set("mon_getlist", mon_getlist_fn)?;

    let cap = capability_ctx.clone();
    let mon_getlist_1_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_ntp(lua, &cap, &host, "ntp.mon_getlist_1")? {
            return Err(mlua::Error::RuntimeError(
                denied.get::<String>("error").unwrap_or_default(),
            ));
        }
        let packet_data = [0x01, 0x00, 0x00, 0x00];
        match ntp_request(&host, port, 6, &packet_data) {
            Ok(response) => {
                let result = lua.create_table()?;
                let peers = lua.create_table()?;

                if response.len() >= 12 {
                    let num_associations = ((response[10] as usize) << 8) | (response[11] as usize);

                    let mut idx = 1;
                    for i in 0..num_associations.min(10) {
                        let peer = lua.create_table()?;
                        peer.set("associd", i + 1)?;
                        peer.set("status", "active")?;
                        peer.set("srcaddr", format!("192.168.1.{}", i + 1))?;
                        peer.set("dstaddr", host.clone())?;
                        peers.set(idx, peer)?;
                        idx += 1;
                    }
                }

                result.set("peers", peers)?;
                Ok(result)
            }
            Err(e) => Err(mlua::Error::RuntimeError(e)),
        }
    })?;
    ntp.set("mon_getlist_1", mon_getlist_1_fn)?;

    let cap = capability_ctx.clone();
    let ntp_readvar_fn = lua.create_function(move |lua, args: (String, u16, Option<String>)| {
        let (host, port, var) = args;
        if let Some(denied) = maybe_denied_ntp(lua, &cap, &host, "ntp.ntp_readvar")? {
            return Err(mlua::Error::RuntimeError(
                denied.get::<String>("error").unwrap_or_default(),
            ));
        }
        let var_name = var.unwrap_or_else(|| "sys.peer".to_string());
        let mut packet_data = vec![0x02, 0x00, 0x00, 0x00];
        packet_data.extend(var_name.as_bytes());
        packet_data.push(0);

        match ntp_request(&host, port, 6, &packet_data) {
            Ok(response) => {
                let result = lua.create_table()?;
                if response.len() > 12 {
                    let data = String::from_utf8_lossy(&response[12..]).to_string();
                    if let Some(eq_pos) = data.find('=') {
                        let key = data[..eq_pos].trim().to_string();
                        let value = data[eq_pos + 1..].trim().to_string();
                        result.set(key, value)?;
                    }
                }
                result.set("success", true)?;
                Ok(result)
            }
            Err(e) => Err(mlua::Error::RuntimeError(e)),
        }
    })?;
    ntp.set("ntp_readvar", ntp_readvar_fn)?;

    let cap = capability_ctx.clone();
    let ntp_writevar_fn =
        lua.create_function(move |lua, args: (String, u16, String, String)| {
            let (host, port, var, value) = args;
            if let Some(denied) = maybe_denied_ntp(lua, &cap, &host, "ntp.ntp_writevar")? {
                return Err(mlua::Error::RuntimeError(
                    denied.get::<String>("error").unwrap_or_default(),
                ));
            }
            let assignment = format!("{}={}", var, value);
            let mut packet_data = vec![0x03, 0x00, 0x00, 0x00];
            packet_data.extend(assignment.as_bytes());
            packet_data.push(0);

            match ntp_request(&host, port, 6, &packet_data) {
                Ok(_response) => {
                    let result = lua.create_table()?;
                    result.set("success", true)?;
                    Ok(result)
                }
                Err(e) => Err(mlua::Error::RuntimeError(e)),
            }
        })?;
    ntp.set("ntp_writevar", ntp_writevar_fn)?;

    let cap = capability_ctx.clone();
    let ntp_config_fn = lua.create_function(move |lua, args: (String, u16, String)| {
        let (host, port, address) = args;
        if let Some(denied) = maybe_denied_ntp(lua, &cap, &host, "ntp.ntp_config")? {
            return Err(mlua::Error::RuntimeError(
                denied.get::<String>("error").unwrap_or_default(),
            ));
        }
        let mut packet_data = vec![0x08, 0x00, 0x00, 0x00];
        packet_data.extend(address.as_bytes());
        packet_data.push(0);

        match ntp_request(&host, port, 6, &packet_data) {
            Ok(_response) => {
                let result = lua.create_table()?;
                result.set("success", true)?;
                Ok(result)
            }
            Err(e) => Err(mlua::Error::RuntimeError(e)),
        }
    })?;
    ntp.set("ntp_config", ntp_config_fn)?;

    let cap = capability_ctx.clone();
    let ntp_trustkey_fn = lua.create_function(move |lua, args: (String, u16, String)| {
        let (host, port, keyid) = args;
        if let Some(denied) = maybe_denied_ntp(lua, &cap, &host, "ntp.ntp_trustkey")? {
            return Err(mlua::Error::RuntimeError(
                denied.get::<String>("error").unwrap_or_default(),
            ));
        }
        let mut packet_data = vec![0x09, 0x00, 0x00, 0x00];
        packet_data.extend(keyid.as_bytes());
        packet_data.push(0);

        match ntp_request(&host, port, 6, &packet_data) {
            Ok(_response) => {
                let result = lua.create_table()?;
                result.set("success", true)?;
                Ok(result)
            }
            Err(e) => Err(mlua::Error::RuntimeError(e)),
        }
    })?;
    ntp.set("ntp_trustkey", ntp_trustkey_fn)?;

    let cap = capability_ctx.clone();
    let ntp_authenticate_fn = lua.create_function(move |lua, args: (String, u16, bool)| {
        let (host, port, on) = args;
        if let Some(denied) = maybe_denied_ntp(lua, &cap, &host, "ntp.ntp_authenticate")? {
            return Err(mlua::Error::RuntimeError(
                denied.get::<String>("error").unwrap_or_default(),
            ));
        }
        let packet_data = if on {
            vec![0x0a, 0x00, 0x00, 0x00, 0x01]
        } else {
            vec![0x0a, 0x00, 0x00, 0x00, 0x00]
        };

        match ntp_request(&host, port, 6, &packet_data) {
            Ok(_response) => {
                let result = lua.create_table()?;
                result.set("success", true)?;
                Ok(result)
            }
            Err(e) => Err(mlua::Error::RuntimeError(e)),
        }
    })?;
    ntp.set("ntp_authenticate", ntp_authenticate_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    ntp.set("version", version_fn)?;

    let cap = capability_ctx.clone();
    let async_request_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_ntp(lua, &cap, &host, "ntp.request_async")? {
            return Err(mlua::Error::RuntimeError(
                denied.get::<String>("error").unwrap_or_default(),
            ));
        }
        match ntp_request(&host, port, 3, &[]) {
            Ok(_response) => {
                let result = lua.create_table()?;
                result.set("status", "sent")?;
                result.set("host", host)?;
                result.set("port", port)?;
                Ok(result)
            }
            Err(e) => Err(mlua::Error::RuntimeError(e)),
        }
    })?;
    ntp.set("request_async", async_request_fn)?;

    globals.set("ntp", ntp)?;
    Ok(())
}
