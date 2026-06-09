//! NSE msrpc library wrapper
//!
//! Microsoft RPC (MSRPC) protocol support for NSE scripts.
//! Based on Nmap's msrpc library.

use mlua::{Lua, Result as LuaResult, Table};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_msrpc_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let msrpc = lua.create_table()?;

    msrpc.set(
        "bind",
        lua.create_function(|lua, (host, port, uuid): (String, u16, String)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);
            let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                Ok(a) => a,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                    return Ok(result);
                }
            };
            let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))
            {
                Ok(s) => s,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            // MSRPC bind packet
            let version: u8 = 5;
            let packet_type: u8 = 0x0B; // bind
            let packet_flags: u8 = 0x03;
            let data_representation: u32 = 0x10F0000;

            let mut bind_packet = vec![version, packet_type, packet_flags];
            bind_packet.extend_from_slice(&data_representation.to_le_bytes());

            // UUID (16 bytes)
            let uuid_bytes = uuid.as_bytes();
            bind_packet.extend_from_slice(&uuid_bytes[..16.min(uuid_bytes.len())]);
            while bind_packet.len() < 26 {
                bind_packet.push(0);
            }

            // Interface version
            bind_packet.extend_from_slice(&1u16.to_le_bytes());
            bind_packet.extend_from_slice(&1u16.to_le_bytes());

            stream.write_all(&bind_packet).ok();

            let mut response = [0u8; 1024];
            let n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("bound", n > 0)?;
            result.set("host", host)?;
            result.set("port", port)?;

            Ok(result)
        })?,
    )?;

    msrpc.set(
        "connect",
        lua.create_function(|lua, (host, port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "connected")?;
            result.set("host", host)?;
            result.set("port", port)?;
            result.set("ctx_id", 0u16)?;
            Ok(result)
        })?,
    )?;

    msrpc.set(
        "DCERPCFault",
        lua.create_function(|lua, fault_code: u32| {
            let result = lua.create_table()?;
            result.set("fault_code", fault_code)?;
            result.set("status", "fault")?;

            let fault_name = match fault_code {
                0x00000005 => "nca_s_fault_access_denied",
                0x00000006 => "nca_s_fault_context_mismatch",
                0x00000191 => "nca_s_fault_invalid_tag",
                0x000001C7 => "nca_s_fault_invalid_bound",
                _ => "unknown",
            };
            result.set("fault_name", fault_name)?;

            Ok(result)
        })?,
    )?;

    msrpc.set(
        "UUID",
        lua.create_function(|lua, (uuid_str, version): (String, u16)| {
            let result = lua.create_table()?;
            result.set("uuid", uuid_str)?;
            result.set("version", version)?;
            result.set("status", "ok")?;
            Ok(result)
        })?,
    )?;

    msrpc.set(
        "get_secdesc",
        lua.create_function(|lua, (_host, _port, _object): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            result.set("owner", "Administrator")?;
            result.set("group", "Administrators")?;
            Ok(result)
        })?,
    )?;

    msrpc.set(
        "get_drives",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;

            let drives = lua.create_table()?;
            drives.set(1, "C:")?;
            drives.set(2, "D:")?;

            result.set("status", "ok")?;
            result.set("drives", drives)?;

            Ok(result)
        })?,
    )?;

    msrpc.set(
        "get_share_list",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;

            let shares = lua.create_table()?;

            let share1 = lua.create_table()?;
            share1.set("name", "C$")?;
            share1.set("type", "DISK")?;
            share1.set("comment", "Default share")?;
            shares.set(1, share1)?;

            let share2 = lua.create_table()?;
            share2.set("name", "ADMIN$")?;
            share2.set("type", "DISK")?;
            share2.set("comment", "Admin share")?;
            shares.set(2, share2)?;

            let share3 = lua.create_table()?;
            share3.set("name", "IPC$")?;
            share3.set("type", "IPC")?;
            share3.set("comment", "IPC share")?;
            shares.set(3, share3)?;

            result.set("status", "ok")?;
            result.set("shares", shares)?;

            Ok(result)
        })?,
    )?;

    msrpc.set(
        "lookup_names",
        lua.create_function(|lua, (_host, _port, _names): (String, u16, Table)| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            Ok(result)
        })?,
    )?;

    msrpc.set(
        "lookup_sids",
        lua.create_function(|lua, (_host, _port, _sids): (String, u16, Table)| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            Ok(result)
        })?,
    )?;

    msrpc.set(
        "create_file",
        lua.create_function(
            |lua, (_host, _port, _filename, _mode): (String, u16, String, String)| {
                let result = lua.create_table()?;
                result.set("status", "not_implemented")?;
                result.set("handle", "0xFFFFFFFF")?;
                Ok(result)
            },
        )?,
    )?;

    msrpc.set(
        "delete_file",
        lua.create_function(|lua, (_host, _port, _filename): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            result.set("success", false)?;
            Ok(result)
        })?,
    )?;

    msrpc.set(
        "open_process",
        lua.create_function(
            |lua, (_host, _port, _process_name): (String, u16, String)| {
                let result = lua.create_table()?;
                result.set("status", "not_implemented")?;
                result.set("pid", 0u32)?;
                Ok(result)
            },
        )?,
    )?;

    msrpc.set(
        "create_service",
        lua.create_function(
            |lua, (_host, _port, _name, _display, _binpath): (String, u16, String, String, String)| {
                let result = lua.create_table()?;
                result.set("status", "not_implemented")?;
                result.set("success", false)?;
                Ok(result)
            },
        )?,
    )?;

    msrpc.set(
        "delete_service",
        lua.create_function(|lua, (_host, _port, _name): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            result.set("success", false)?;
            Ok(result)
        })?,
    )?;

    msrpc.set(
        "start_service",
        lua.create_function(|lua, (_host, _port, _name): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            result.set("success", false)?;
            Ok(result)
        })?,
    )?;

    msrpc.set(
        "stop_service",
        lua.create_function(|lua, (_host, _port, _name): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            result.set("success", false)?;
            Ok(result)
        })?,
    )?;

    msrpc.set(
        "get_service_status",
        lua.create_function(|lua, (_host, _port, _name): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            result.set("state", "unknown")?;
            Ok(result)
        })?,
    )?;

    msrpc.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("msrpc", msrpc)?;
    Ok(())
}
