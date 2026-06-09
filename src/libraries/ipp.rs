//! NSE ipp library wrapper
//!
//! IPP (Internet Printing Protocol) support for NSE scripts.
//! Based on Nmap's ipp library: https://nmap.org/nsedoc/lib/ipp.html

use mlua::{Lua, Result as LuaResult, Table};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const IPP_PORT: u16 = 631;

fn build_ipp_request(operation_id: u16, printer_uri: &str) -> Vec<u8> {
    let mut request = Vec::new();

    request.extend_from_slice(&[0x01, 0x01]);
    request.extend_from_slice(&operation_id.to_be_bytes());
    request.extend_from_slice(&[0x00, 0x01]);

    let printer_uri_bytes = printer_uri.as_bytes();
    let uri_attr = build_attribute(0x45, printer_uri_bytes);
    request.extend_from_slice(&uri_attr);

    request
}

fn build_attribute(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut attr = Vec::new();
    let name = b"attributes-charset";
    attr.push(tag);
    attr.extend_from_slice(&(name.len() as u16).to_be_bytes());
    attr.extend_from_slice(name);
    attr.extend_from_slice(&[0x00]);
    attr.extend_from_slice(&(value.len() as u16).to_be_bytes());
    attr.extend_from_slice(value);
    attr
}

fn parse_ipp_response(data: &[u8], lua: &Lua) -> LuaResult<Table> {
    let result = lua.create_table()?;

    if data.len() < 8 {
        result.set("status", "error")?;
        result.set("error", "Response too short")?;
        return Ok(result);
    }

    let version_major = data[0];
    let version_minor = data[1];
    result.set("version", format!("{}.{}", version_major, version_minor))?;

    let status_code = u16::from_be_bytes([data[2], data[3]]);
    result.set("status_code", status_code)?;

    let status = match status_code {
        0x0000 => "successful",
        0x0001 => "client-error",
        0x0002 => "server-error",
        _ => "unknown",
    };
    result.set("status", status)?;

    let request_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    result.set("request_id", request_id)?;

    if data.len() > 8 {
        let attrs = lua.create_table()?;
        let mut i = 8;
        let mut attr_count = 0;

        while i + 2 < data.len() {
            let tag = data[i];
            if tag == 0x10 || tag == 0x11 || tag == 0x12 {
                break;
            }

            if i + 3 < data.len() {
                let name_len = u16::from_be_bytes([data[i + 1], data[i + 2]]) as usize;
                if i + 4 + name_len + 2 < data.len() {
                    let name = String::from_utf8_lossy(&data[i + 4..i + 4 + name_len]).to_string();
                    let val_len =
                        u16::from_be_bytes([data[i + 4 + name_len], data[i + 5 + name_len]])
                            as usize;

                    if i + 6 + name_len + val_len <= data.len() {
                        let value = &data[i + 6 + name_len..i + 6 + name_len + val_len];
                        let value_str = String::from_utf8_lossy(value).to_string();

                        if !name.is_empty() {
                            attr_count += 1;
                            attrs.set(attr_count, format!("{}: {}", name, value_str))?;

                            let key = name.replace('-', "_");
                            if key == "printer_name"
                                || key == "printer_uri"
                                || key == "printer_state"
                                || key == "printer_make_and_model"
                                || key == "printer_info"
                            {
                                attrs.set(key.as_str(), value_str)?;
                            }
                        }
                    }

                    i = i + 6 + name_len + val_len;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        if attr_count > 0 {
            result.set("attributes", attrs)?;
        }
    }

    Ok(result)
}

pub fn register_ipp_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let ipp = lua.create_table()?;

    ipp.set(
        "get_attributes",
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let port = port.unwrap_or(IPP_PORT);
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);
            let socket_addr: std::net::SocketAddr = match addr.parse() {
                Ok(a) => a,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
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

            stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

            let printer_uri = format!("ipp://{}:{}/ipp/print", host, port);
            let ipp_request = build_ipp_request(0x0B, &printer_uri);

            if let Err(e) = stream.write_all(&ipp_request) {
                result.set("status", "error")?;
                result.set("error", format!("Failed to send request: {}", e))?;
                return Ok(result);
            }

            let mut response = vec![0u8; 4096];
            match stream.read(&mut response) {
                Ok(n) => {
                    response.truncate(n);
                    let parsed = parse_ipp_response(&response, lua)?;

                    result.set("status", "ok")?;
                    result.set("host", host)?;
                    result.set("port", port)?;
                    result.set("printer_uri", printer_uri)?;

                    if let Ok(attrs) = parsed.get::<Table>("attributes") {
                        result.set("attributes", attrs)?;
                    }

                    if let Ok(version) = parsed.get::<String>("version") {
                        result.set("version", version)?;
                    }

                    if let Ok(status_code) = parsed.get::<u16>("status_code") {
                        result.set("status_code", status_code)?;
                    }
                }
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", format!("Failed to read response: {}", e))?;
                }
            }

            Ok(result)
        })?,
    )?;

    ipp.set(
        "parse_response",
        lua.create_function(|lua, data: String| {
            let bytes = data.into_bytes();
            parse_ipp_response(&bytes, lua)
        })?,
    )?;

    ipp.set(
        "supported_versions",
        lua.create_function(|lua, _: ()| {
            let versions = lua.create_table()?;
            versions.set(1, "1.0")?;
            versions.set(2, "1.1")?;
            versions.set(3, "2.0")?;
            versions.set(4, "2.1")?;
            versions.set(5, "2.2")?;
            versions.set(6, "2.3")?;
            Ok(versions)
        })?,
    )?;

    ipp.set(
        "supported_operations",
        lua.create_function(|lua, _: ()| {
            let ops = lua.create_table()?;
            ops.set("Print-Job", 0x0002)?;
            ops.set("Print-URI", 0x0003)?;
            ops.set("Validate-Job", 0x0004)?;
            ops.set("Create-Job", 0x0005)?;
            ops.set("Send-Document", 0x0006)?;
            ops.set("Send-URI", 0x0007)?;
            ops.set("Cancel-Job", 0x0008)?;
            ops.set("Get-Job-Attributes", 0x0009)?;
            ops.set("Get-Jobs", 0x000A)?;
            ops.set("Get-Printer-Attributes", 0x000B)?;
            ops.set("Hold-Job", 0x000C)?;
            ops.set("Release-Job", 0x000D)?;
            ops.set("Restart-Job", 0x000E)?;
            ops.set("Pause-Printer", 0x0010)?;
            ops.set("Resume-Printer", 0x0011)?;
            ops.set("Purge-Jobs", 0x0012)?;
            Ok(ops)
        })?,
    )?;

    ipp.set(
        "operation_status",
        lua.create_function(|lua, code: u16| {
            let result = lua.create_table()?;
            let status = match code {
                0x0000 => "successful",
                0x0001 => "server-error-internal-error",
                0x0002 => "server-error-operation-not-supported",
                0x0003 => "server-error-temporary-error",
                0x0004 => "server-error-version-not-supported",
                0x0005 => "server-error-device-error",
                0x0006 => "server-error-temporary-error",
                0x0007 => "server-error-not-found",
                0x0008 => "server-error-attribute-not-supported",
                0x0009 => "server-error-values-not-supported",
                0x000A => "client-error-bad-request",
                0x000B => "client-error-forbidden",
                0x000C => "client-error-not-authenticated",
                0x000D => "client-error-not-authorized",
                0x000E => "client-error-attributes-not-supported",
                0x000F => "client-error-attributes-values-not-supported",
                0x0010 => "client-error-attributes-not-supported",
                0x0011 => "client-error-attributes-values-not-supported",
                0x0012 => "client-error-bad-request",
                0x0013 => "client-error-conflicting-attributes",
                _ => "unknown",
            };
            result.set("code", code)?;
            result.set("status", status)?;
            Ok(result)
        })?,
    )?;

    ipp.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("ipp", ipp)?;
    Ok(())
}
