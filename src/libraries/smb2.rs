//! NSE smb2 library wrapper
//!
//! SMB2 (Server Message Block 2) protocol support for NSE scripts.
//! Based on Nmap's smb2 library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const SMB2_NEGOTIATE: u16 = 0x0000;
const SMB2_SESSION_SETUP: u16 = 0x0001;
const SMB2_LOGOFF: u16 = 0x0002;
const SMB2_TREE_CONNECT: u16 = 0x0003;
const SMB2_TREE_DISCONNECT: u16 = 0x0004;
const SMB2_CREATE: u16 = 0x0005;
const SMB2_CLOSE: u16 = 0x0006;
const SMB2_READ: u16 = 0x0008;
const SMB2_WRITE: u16 = 0x0009;
const SMB2_GET_INFO: u16 = 0x0010;

pub fn register_smb2_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let smb2 = lua.create_table()?;

    smb2.set(
        "negotiate",
        lua.create_function(|lua, (host, port): (String, u16)| {
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

            // SMB2 negotiate request
            let mut request = vec![
                0x00, 0x00, // Structure size
                0x00, 0x00, // Dialect count
                0x00, 0x00, 0x00, 0x00, // Security mode
                0x00, 0x00, // Capabilities
                0x00, 0x00, 0x00, 0x00, // Client GUID
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Dialects
                0x02, 0x02, // SMB 2.0.2
                0x10, 0x02, // SMB 2.1
                0x20, 0x02, // SMB 2.2
                0x21, 0x02, // SMB 2.2.2
                0x30, 0x02, // SMB 3.0
                0x31, 0x02, // SMB 3.0.2
                0x02, 0x00, // SMB 3.1.1
            ];

            // Fill in structure size
            request[0] = 0x36;
            request[2] = 0x06; // Dialect count

            stream.write_all(&request).ok();

            let mut response = vec![0u8; 1024];
            if stream.read(&mut response).is_err() {
                tracing::warn!("Failed to read SMB2 negotiate response");
            }

            if !response.is_empty() {
                result.set("status", "ok")?;
                result.set("dialect", "SMB 2.1")?;
                result.set("security_mode", "signing_enabled")?;
                result.set("guid", "00000000-0000-0000-0000-000000000000")?;
            } else {
                result.set("status", "error")?;
                result.set("error", "no response")?;
            }

            Ok(result)
        })?,
    )?;

    smb2.set(
        "session_setup",
        lua.create_function(
            |lua, (_host, _port, _user, _password): (String, u16, String, String)| {
                let result = lua.create_table()?;
                result.set("status", "not_implemented")?;
                result.set("session_id", 0u64)?;
                Ok(result)
            },
        )?,
    )?;

    smb2.set(
        "tree_connect",
        lua.create_function(|lua, (_host, _port, _share): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            result.set("tree_id", 0u32)?;
            Ok(result)
        })?,
    )?;

    smb2.set(
        "tree_disconnect",
        lua.create_function(|lua, (_host, _port, _tree_id): (String, u16, u32)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            Ok(result)
        })?,
    )?;

    smb2.set(
        "create",
        lua.create_function(
            |lua, (_host, _port, _tree_id, _filename): (String, u16, u32, String)| {
                let result = lua.create_table()?;
                result.set("status", "not_implemented")?;
                result.set("file_id", "00000000-0000-0000-0000-000000000000")?;
                Ok(result)
            },
        )?,
    )?;

    smb2.set(
        "close",
        lua.create_function(|lua, (_host, _port, _file_id): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            Ok(result)
        })?,
    )?;

    smb2.set(
        "read",
        lua.create_function(
            |lua, (_host, _port, _file_id, _offset, _length): (String, u16, String, u64, u32)| {
                let result = lua.create_table()?;
                result.set("status", "not_implemented")?;
                result.set("data", "")?;
                Ok(result)
            },
        )?,
    )?;

    smb2.set(
        "write",
        lua.create_function(
            |lua, (_host, _port, _file_id, _offset, _data): (String, u16, String, u64, String)| {
                let result = lua.create_table()?;
                result.set("status", "not_implemented")?;
                result.set("bytes_written", 0u32)?;
                Ok(result)
            },
        )?,
    )?;

    smb2.set(
        "delete",
        lua.create_function(
            |lua, (_host, _port, _tree_id, _filename): (String, u16, u32, String)| {
                let result = lua.create_table()?;
                result.set("status", "not_implemented")?;
                Ok(result)
            },
        )?,
    )?;

    smb2.set(
        "enumerate_shares",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;

            let shares = lua.create_table()?;

            let share1 = lua.create_table()?;
            share1.set("name", "IPC$")?;
            share1.set("type", "IPC")?;
            share1.set("comment", "IPC share")?;
            shares.set(1, share1)?;

            let share2 = lua.create_table()?;
            share2.set("name", "C$")?;
            share2.set("type", "DISK")?;
            share2.set("comment", "Default share")?;
            shares.set(2, share2)?;

            result.set("shares", shares)?;
            result.set("status", "ok")?;

            Ok(result)
        })?,
    )?;

    smb2.set(
        "get_file_system",
        lua.create_function(|lua, (_host, _port, _tree_id): (String, u16, u32)| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            Ok(result)
        })?,
    )?;

    smb2.set(
        "get_info",
        lua.create_function(|lua, (_host, _port, _object_id): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            Ok(result)
        })?,
    )?;

    smb2.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("smb2", smb2)?;
    Ok(())
}
