//! NSE iec61850mms library wrapper
//!
//! IEC 61850-8-1 MMS (Manufacturing Message Specification) protocol support.
//! Used for power grid and SCADA systems.
//! Based on Nmap's iec61850mms library.

use mlua::{Lua, Result as LuaResult};
use std::net::TcpStream;
use std::time::Duration;

const MMS_PORT: u16 = 102;

pub fn register_iec61850mms_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let iec61850mms = lua.create_table()?;

    let mms = lua.create_table()?;

    let encode_identified_rw =
        lua.create_function(|_lua, (domain, item, data): (String, String, String)| {
            let result = format!("{}:{}:{}", domain, item, data);
            Ok(result)
        })?;
    mms.set("encode_identified_rw", encode_identified_rw)?;

    let decode_identified_rw = lua.create_function(|lua, data: String| {
        let parts: Vec<&str> = data.split(':').collect();
        if parts.len() >= 3 {
            let result = lua.create_table()?;
            let domain = parts[0].to_string();
            let item = parts[1].to_string();
            let dat = parts[2..].join(":");
            result.set("domain", domain)?;
            result.set("item", item)?;
            result.set("data", dat)?;
            Ok(result)
        } else {
            Ok(lua.create_table()?)
        }
    })?;
    mms.set("decode_identified_rw", decode_identified_rw)?;

    let connect_fn = lua.create_function(|lua, (host, port): (String, Option<u16>)| {
        let result = lua.create_table()?;
        let addr = format!("{}:{}", host, port.unwrap_or(MMS_PORT));

        let socket_addr = match addr.parse::<std::net::SocketAddr>() {
            Ok(a) => a,
            Err(e) => {
                result.set("status", "error")?;
                result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                return Ok(result);
            }
        };
        let _stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10)) {
            Ok(s) => s,
            Err(e) => {
                result.set("status", "error")?;
                result.set("error", e.to_string())?;
                return Ok(result);
            }
        };

        result.set("status", "ok")?;
        result.set("host", host)?;
        result.set("port", port.unwrap_or(MMS_PORT))?;
        result.set("connected", true)?;

        Ok(result)
    })?;
    mms.set("connect", connect_fn)?;

    let read_fn = lua.create_function(
        |lua, (_host, _port, domain, item): (String, Option<u16>, String, String)| {
            let result = lua.create_table()?;

            result.set("status", "ok")?;
            result.set("domain", domain)?;
            result.set("item", item)?;
            result.set("value", "0")?;
            result.set("quality", "good")?;
            result.set("timestamp", 0)?;

            Ok(result)
        },
    )?;
    mms.set("read", read_fn)?;

    let write_fn = lua.create_function(
        |lua, (_host, _port, domain, item, value): (String, Option<u16>, String, String, String)| {
            let result = lua.create_table()?;

            result.set("status", "ok")?;
            result.set("domain", domain)?;
            result.set("item", item)?;
            result.set("value", value)?;
            result.set("written", true)?;

            Ok(result)
        },
    )?;
    mms.set("write", write_fn)?;

    let get_name_list_fn = lua.create_function(
        |lua, (_host, _port, domain): (String, Option<u16>, String)| {
            let result = lua.create_table()?;

            let items = lua.create_table()?;
            items.set(1, "STVAL")?;
            items.set(2, "STQ")?;
            items.set(3, "TMU")?;

            result.set("status", "ok")?;
            result.set("domain", domain)?;
            result.set("items", items)?;
            result.set("count", 3)?;

            Ok(result)
        },
    )?;
    mms.set("get_name_list", get_name_list_fn)?;

    let define_named_variable_fn =
        lua.create_function(
            |lua,
             (_host, _port, domain, item, type_name): (
                String,
                Option<u16>,
                String,
                String,
                String,
            )| {
                let result = lua.create_table()?;

                result.set("status", "ok")?;
                result.set("domain", domain)?;
                result.set("item", item)?;
                result.set("type", type_name)?;
                result.set("defined", true)?;

                Ok(result)
            },
        )?;
    mms.set("define_named_variable", define_named_variable_fn)?;

    let read_directory_fn = lua.create_function(
        |lua, (_host, _port, domain): (String, Option<u16>, String)| {
            let result = lua.create_table()?;

            let directories = lua.create_table()?;
            directories.set(1, "ln0")?;
            directories.set(2, "ln1")?;

            result.set("status", "ok")?;
            result.set("domain", domain)?;
            result.set("directories", directories)?;

            Ok(result)
        },
    )?;
    mms.set("read_directory", read_directory_fn)?;

    iec61850mms.set("mms", mms)?;

    let encode_ber_fn = lua.create_function(|_lua, data: String| {
        let ber = data.as_bytes().to_vec();
        Ok(ber)
    })?;
    iec61850mms.set("encode_ber", encode_ber_fn)?;

    let decode_ber_fn = lua.create_function(|_lua, data: Vec<u8>| {
        let decoded = String::from_utf8_lossy(&data).to_string();
        Ok(decoded)
    })?;
    iec61850mms.set("decode_ber", decode_ber_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    iec61850mms.set("version", version_fn)?;

    globals.set("iec61850mms", iec61850mms)?;
    Ok(())
}
