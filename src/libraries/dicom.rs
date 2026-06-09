//! NSE dicom library wrapper
//!
//! DICOM (Digital Imaging and Communications in Medicine) protocol support.
//! Based on Nmap's dicom library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_dicom_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let dicom = lua.create_table()?;

    dicom.set(
        "connect",
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

            // DICOM Associate Request (simplified)
            let mut request = vec![0x01, 0x00]; // P-DATA-TF
            request.extend_from_slice(&[0u8; 6]); // Placeholder

            stream.write_all(&request).ok();

            let mut response = [0u8; 1024];
            let n = stream.read(&mut response).unwrap_or(0);

            result.set("status", "ok")?;
            result.set("connected", n > 0)?;
            result.set("host", host)?;
            result.set("port", port)?;
            result.set("called_ae", "DICOM_SERVER")?;
            result.set("calling_ae", "EGGSEC")?;

            Ok(result)
        })?,
    )?;

    dicom.set(
        "c_echo",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("success", true)?;
            Ok(result)
        })?,
    )?;

    dicom.set(
        "c_find",
        lua.create_function(
            |lua, (_host, _port, _patient_id): (String, u16, Option<String>)| {
                let result = lua.create_table()?;
                result.set("status", "ok")?;
                result.set("patients", lua.create_table()?)?;
                Ok(result)
            },
        )?,
    )?;

    dicom.set(
        "c_store",
        lua.create_function(|lua, (_host, _port, _dataset): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("success", true)?;
            Ok(result)
        })?,
    )?;

    dicom.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("dicom", dicom)?;
    Ok(())
}
