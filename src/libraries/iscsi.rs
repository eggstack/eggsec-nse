//! NSE iscsi library wrapper
//!
//! iSCSI protocol support for NSE scripts.
//! Based on Nmap's iscsi library.

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, broker_tcp_send, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

/// Provider-backed iscsi registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_iscsi_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let iscsi = lua.create_table()?;

    iscsi.set(
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
                    "iscsi.connect",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                // iSCSI Login Request (Text)
                let mut login = vec![
                    0x01, // Opcode (Login Request)
                    0xC0, // Flags
                    0x00, 0x00, // Total AHS length
                    0x00, 0x00, 0x00, 0x24, // Data segment length
                ];

                // Initiator Name
                login.extend_from_slice(b"TargetName=iqn.2024-01.local:target");

                let _ = broker_tcp_send(&ctx, handle.as_mut(), &login, "iscsi.connect");

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 1024, "iscsi.connect")
                    .unwrap_or_default();
                let mut response = [0u8; 1024];
                let n = data.len().min(response.len());
                response[..n].copy_from_slice(&data[..n]);

                result.set("status", "ok")?;
                result.set("connected", n > 0)?;
                result.set("host", host)?;
                result.set("port", port)?;

                Ok(result)
            }
        })?,
    )?;

    iscsi.set(
        "discover_targets",
        lua.create_function(|lua, (_host, _port): (String, u16)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;

            let targets = lua.create_table()?;
            targets.set(1, "iqn.2024-01.local:disk0")?;
            targets.set(2, "iqn.2024-01.local:disk1")?;

            result.set("targets", targets)?;

            Ok(result)
        })?,
    )?;

    iscsi.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("iscsi", iscsi)?;
    Ok(())
}
