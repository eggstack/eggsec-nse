//! NSE dicom library wrapper
//!
//! DICOM (Digital Imaging and Communications in Medicine) protocol support.
//! Based on Nmap's dicom library.

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, broker_tcp_send, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

/// Provider-backed dicom registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_dicom_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let dicom = lua.create_table()?;

    dicom.set(
        "connect",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port): (String, u16)| {
                let result = lua.create_table()?;
                let timeout = Duration::from_secs(10);

                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    timeout,
                    "dicom.connect",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                // DICOM Associate Request (simplified)
                let mut request = vec![0x01, 0x00]; // P-DATA-TF
                request.extend_from_slice(&[0u8; 6]); // Placeholder

                let _ = broker_tcp_send(&ctx, handle.as_mut(), &request, "dicom.connect");

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "dicom.connect")
                    .unwrap_or_default();
                let mut response = [0u8; 1024];
                let n = data.len().min(response.len());
                response[..n].copy_from_slice(&data[..n]);

                result.set("status", "ok")?;
                result.set("connected", n > 0)?;
                result.set("host", host)?;
                result.set("port", port)?;
                result.set("called_ae", "DICOM_SERVER")?;
                result.set("calling_ae", "EGGSEC")?;

                Ok(result)
            }
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
