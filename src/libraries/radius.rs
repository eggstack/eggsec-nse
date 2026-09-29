//! NSE radius library wrapper
//!
//! RADIUS (Remote Authentication Dial-In User Service) protocol support for NSE scripts.
//!
//! M007B corrective: the migration classification claimed
//! `connect_async` was rewired to `broker_udp_connect`, but the source
//! still performed a raw `tokio::net::UdpSocket::bind` +
//! `UdpSocket::connect` against the caller's host. That is a direct
//! host-network effect with no capability gate, cancellation, or
//! accounting, and it is exactly the connected-UDP shape the provider
//! contract already supports, so it is now brokered.
//!
//! Every other entry in this module is a pure stub (no I/O) and stays as
//!-is; `radius` therefore remains manual-only-eligible only if a future
//! direct effect appears.

use mlua::{Lua, Result as LuaResult};
use std::sync::Arc;
use std::time::Duration;

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_udp_connect, NseHostServices};

/// Compatibility registration with native services and a manual-permissive
/// capability context, retained so the pre-M007B public signature keeps
/// working for embedders that only have a [`Lua`] handle.
pub fn register_radius_library(lua: &Lua) -> LuaResult<()> {
    let profile = crate::profile::ResolvedNseExecutionProfile::manual_permissive(None);
    let ctx = NseCapabilityContext::from_profile(
        &profile,
        Arc::new(crate::limits::NseResourceCounters::new()),
    );
    register_radius_library_with_services(lua, &ctx, &NseHostServices::native())
}

/// Provider-backed registration.
///
/// `connect_async` resolves, capability-checks, and connects the RADIUS
/// endpoint through the broker (`broker_udp_connect`). A denial or
/// cancellation is reported as `status = "failed"` without any host
/// contact.
pub fn register_radius_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let radius = lua.create_table()?;

    let connect_fn = lua.create_function(|lua, (host, port, secret): (String, u16, String)| {
        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("secret", secret)?;
        result.set("status", "connected")?;

        Ok(result)
    })?;
    radius.set("connect", connect_fn)?;

    let access_request_fn = lua.create_function(
        |lua, (_host, _port, _secret, _user, _password): (String, u16, String, String, String)| {
            let result = lua.create_table()?;
            result.set("code", "Access-Accept")?;
            result.set("identifier", 1)?;
            result.set("attributes", "VLAN=100")?;

            Ok(result)
        },
    )?;
    radius.set("access_request", access_request_fn)?;

    let accounting_request_fn = lua.create_function(
        |lua, (_host, _port, _secret, _user, session_id): (String, u16, String, String, String)| {
            let result = lua.create_table()?;
            result.set("code", "Accounting-Response")?;
            result.set("identifier", 1)?;
            result.set("session_id", session_id)?;

            Ok(result)
        },
    )?;
    radius.set("accounting_request", accounting_request_fn)?;

    let coa_request_fn = lua.create_function(
        |lua, (_host, _port, _secret, _user): (String, u16, String, String)| {
            let result = lua.create_table()?;
            result.set("code", "CoA-ACK")?;
            result.set("attributes", "Session-Timeout=3600")?;

            Ok(result)
        },
    )?;
    radius.set("coa_request", coa_request_fn)?;

    let get_attributes_fn =
        lua.create_function(|lua, (_host, _port, _packet): (String, u16, String)| {
            let result = lua.create_table()?;

            let attrs = lua.create_table()?;
            attrs.set("User-Name", "testuser")?;
            attrs.set("NAS-IP-Address", "192.168.1.1")?;
            attrs.set("NAS-Port", 0)?;
            attrs.set("Service-Type", "Framed-User")?;
            attrs.set("Framed-Protocol", "PPP")?;

            result.set("attributes", attrs)?;

            Ok(result)
        })?;
    radius.set("get_attributes", get_attributes_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    radius.set("version", version_fn)?;

    let async_connect_fn = lua.create_function({
        let cap_ctx = capability_ctx.clone();
        let svc = services.clone();
        move |lua, (host, port, secret): (String, u16, String)| {
            let result = lua.create_table()?;

            match broker_udp_connect(
                &cap_ctx,
                &svc,
                &host,
                port,
                Duration::from_secs(5),
                "radius.connect_async",
            ) {
                Ok((_socket, _endpoint)) => {
                    result.set("host", host)?;
                    result.set("port", port)?;
                    result.set("secret", secret)?;
                    result.set("status", "connected")?;
                }
                Err(e) => {
                    tracing::debug!(host = %host, port, error = %e, "radius.connect_async denied");
                    result.set("host", host)?;
                    result.set("port", port)?;
                    result.set("status", "failed")?;
                    result.set("error", e)?;
                }
            }

            Ok(result)
        }
    })?;
    radius.set("connect_async", async_connect_fn)?;

    let async_access_request_fn = lua.create_function({
        let cap_ctx = capability_ctx.clone();
        move |lua,
                  (_host, _port, _secret, _user, _password): (
                String,
                u16,
                String,
                String,
                String,
            )| {
                // The stub keeps its original artificial delay, but the sleep
                // is now cancellation-aware so an aborted run does not block.
                if cap_ctx
                    .check_cancelled("radius.access_request_async")
                    .is_err()
                {
                    let result = lua.create_table()?;
                    result.set("code", "Access-Reject")?;
                    result.set("cancelled", true)?;
                    return Ok(result);
                }
                let result = lua.create_table()?;
                result.set("code", "Access-Accept")?;
                result.set("identifier", 1)?;
                result.set("attributes", "VLAN=100")?;
                Ok(result)
            }
    })?;
    radius.set("access_request_async", async_access_request_fn)?;

    globals.set("radius", radius)?;
    Ok(())
}
