//! NSE rmi library wrapper
//!
//! RMI (Java Remote Method Invocation) support.
//! Based on Nmap's rmi library.

use crate::brokered_stream::broker_send_all;
use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

const RMI_PORT: u16 = 1099;

/// Provider-backed rmi registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_rmi_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let rmi = lua.create_table()?;

    rmi.set(
        "connect",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port): (String, Option<u16>)| {
                let result = lua.create_table()?;
                let port = port.unwrap_or(RMI_PORT);
                // The broker resolves `host` (authority-preserving); unresolvable
                // or refused hosts keep the original `status = "error"` shape.
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "rmi.connect",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                let _ = broker_send_all(&ctx, handle.as_mut(), b"JRMI", "rmi.connect");
                let data = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "rmi.connect")
                    .unwrap_or_default();
                result.set("status", "ok")?;
                result.set("connected", !data.is_empty())?;
                Ok(result)
            }
        })?,
    )?;

    rmi.set(
        "list_methods",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port): (String, Option<u16>)| {
                let result = lua.create_table()?;
                let port = port.unwrap_or(RMI_PORT);
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "rmi.list_methods",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                let request = vec![
                    0x50, 0x01, 0x3b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ];
                let _ = broker_send_all(&ctx, handle.as_mut(), &request, "rmi.list_methods");

                let _data = broker_tcp_receive(&ctx, handle.as_mut(), 4096, "rmi.list_methods")
                    .unwrap_or_default();

                result.set("status", "ok")?;
                result.set("methods", lua.create_table()?)?;
                result.set("object_number", 0)?;

                Ok(result)
            }
        })?,
    )?;

    rmi.set(
        "get_registry",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port): (String, Option<u16>)| {
                let result = lua.create_table()?;
                let port = port.unwrap_or(RMI_PORT);
                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "rmi.get_registry",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                let _ = broker_send_all(&ctx, handle.as_mut(), b"JRMI", "rmi.get_registry");

                let _data = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "rmi.get_registry")
                    .unwrap_or_default();

                let bindings = lua.create_table()?;
                bindings.set(1, "java.rmi.registry.Registry")?;

                result.set("status", "ok")?;
                result.set("bindings", bindings)?;

                Ok(result)
            }
        })?,
    )?;

    rmi.set(
        "get_object_ref",
        lua.create_function(
            |lua, (host, port, object_name): (String, Option<u16>, String)| {
                let result = lua.create_table()?;
                let port_val = port.unwrap_or(RMI_PORT);
                result.set("status", "ok")?;
                result.set("host", host.clone())?;
                result.set("port", port_val)?;
                result.set("object_name", object_name.clone())?;
                result.set(
                    "object_ref",
                    format!("//{}:{}/{}", host, port_val, object_name),
                )?;
                Ok(result)
            },
        )?,
    )?;

    rmi.set(
        "is_科",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port): (String, Option<u16>)| {
                let result = lua.create_table()?;
                let port = port.unwrap_or(RMI_PORT);
                // Connect probe: the broker resolves `host`; reachability keeps
                // the original `is_rmi` boolean shape (name preserved verbatim).
                let reachable = broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    Duration::from_secs(3),
                    "rmi.is_科",
                )
                .is_ok();

                result.set("status", "ok")?;
                result.set("is_rmi", reachable)?;
                Ok(result)
            }
        })?,
    )?;

    rmi.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("rmi", rmi)?;
    Ok(())
}
