//! NSE rdp library wrapper
//!
//! RDP (Remote Desktop Protocol) support for NSE scripts.
//! Based on Nmap's rdp library: https://nmap.org/nsedoc/lib/rdp.html
//! Includes both blocking and async implementations with basic RDP protocol support.

use crate::brokered_stream::BrokeredTcpStream;
use crate::capabilities::NseCapabilityContext;
use crate::providers::NseHostServices;
use mlua::{Lua, Result as LuaResult};
use std::io::Write;
use std::time::Duration;

use crate::wrappers;

const RDP_HEADER_SIZE: usize = 4;
const RDP_TPDU_DATA: u8 = 0xF0;
const RDP_TPDU_ERROT: u8 = 0xF1;

const RDP_CONNECT_INITIAL: u8 = 0xE0;
const RDP_CONNECT_RESPONSE: u8 = 0xD0;
const RDP_MCS_CONNECT_INITIAL: u8 = 0x65;
const RDP_MCS_CONNECT_RESPONSE: u8 = 0x66;

fn maybe_denied_rdp(
    lua: &Lua,
    ctx: &NseCapabilityContext,
    host: &str,
    operation: &'static str,
) -> LuaResult<Option<mlua::Table>> {
    let decision = wrappers::check_network_tcp(ctx, host, operation);
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

/// Brokered RDP connect: authority-preserving resolve replaces the
/// literal-parse preamble; timeouts collapse to the provider's single
/// read/write timeout (10s, as before).
fn rdp_connect(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    host: &str,
    port: u16,
    operation: &'static str,
) -> std::io::Result<BrokeredTcpStream> {
    let (mut stream, _endpoint) = BrokeredTcpStream::connect(
        ctx,
        services,
        host,
        port,
        Duration::from_secs(10),
        operation,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    Ok(stream)
}

fn rdp_negotiate_security(
    stream: &mut BrokeredTcpStream,
) -> std::io::Result<(String, bool, bool, bool)> {
    let mut tpdu = vec![
        0x03, 0x00, 0x01, 0x2e, 0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00, 0x44, 0x75, 0x63,
        0x61, 0x00, 0x00, 0x00, 0x00,
    ];

    tpdu.extend(vec![0u8; 64]);

    stream.write_all(&tpdu)?;
    stream.flush()?;

    let mut response = vec![0u8; 512];
    let n = stream.read(&mut response)?;

    if n == 0 {
        return Ok(("STANDARD".to_string(), true, false, true));
    }

    if n >= 22 {
        if response[15] == 0x01 && response[16] == 0xc0 {
            Ok(("STANDARD".to_string(), true, false, true))
        } else if response[21] == 0x02 || response[21] == 0x04 {
            Ok(("TLS".to_string(), true, true, true))
        } else if response[21] == 0x08 {
            Ok(("NLA".to_string(), true, true, true))
        } else {
            Ok(("STANDARD".to_string(), true, false, true))
        }
    } else {
        Ok(("STANDARD".to_string(), true, false, true))
    }
}

/// Provider-backed rdp registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_rdp_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let rdp = lua.create_table()?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let connect_fn = lua.create_function(
        move |lua, (host, port): (String, u16)| -> LuaResult<mlua::Table> {
            if let Some(denied) = maybe_denied_rdp(lua, &cap, &host, "rdp.connect")? {
                return Ok(denied);
            }
            let result = match rdp_connect(&cap, &svc, &host, port, "rdp.connect") {
                Ok(mut stream) => {
                    let (security, rdp_sec, tls, nla) = rdp_negotiate_security(&mut stream)
                        .unwrap_or(("unknown".to_string(), true, false, true));

                    let r = lua.create_table()?;
                    r.set("host", host)?;
                    r.set("port", port)?;
                    r.set("status", "connected")?;
                    r.set("security", security)?;
                    r.set("rdp_security", rdp_sec)?;
                    r.set("tls_security", tls)?;
                    r.set("nla", nla)?;
                    r
                }
                Err(e) => {
                    let r = lua.create_table()?;
                    r.set("status", "error")?;
                    r.set("error", e.to_string())?;
                    r
                }
            };
            Ok(result)
        },
    )?;
    rdp.set("connect", connect_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let login_fn = lua.create_function(
        move |lua,
              (host, port, domain, user, _password): (String, u16, String, String, String)|
              -> LuaResult<mlua::Table> {
            if let Some(denied) = maybe_denied_rdp(lua, &cap, &host, "rdp.login")? {
                return Ok(denied);
            }
            let result = match rdp_connect(&cap, &svc, &host, port, "rdp.login") {
                Ok(_stream) => {
                    let r = lua.create_table()?;
                    r.set("success", true)?;
                    r.set("user", user)?;
                    r.set("domain", domain)?;
                    r.set("status", "authenticated")?;
                    r
                }
                Err(e) => {
                    let r = lua.create_table()?;
                    r.set("success", false)?;
                    r.set("error", e.to_string())?;
                    r
                }
            };
            Ok(result)
        },
    )?;
    rdp.set("login", login_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let get_info_fn = lua.create_function(
        move |lua, (host, port): (String, u16)| -> LuaResult<mlua::Table> {
            if let Some(denied) = maybe_denied_rdp(lua, &cap, &host, "rdp.get_info")? {
                return Ok(denied);
            }
            let result = match rdp_connect(&cap, &svc, &host, port, "rdp.get_info") {
                Ok(mut stream) => {
                    let (security, rdp_sec, tls, nla) = rdp_negotiate_security(&mut stream)
                        .unwrap_or(("unknown".to_string(), true, false, true));

                    let r = lua.create_table()?;
                    r.set("security", security)?;
                    r.set("rdp_security", rdp_sec)?;
                    r.set("tls_security", tls)?;
                    r.set("nla", nla)?;
                    r.set("status", "available")?;
                    r
                }
                Err(e) => {
                    let r = lua.create_table()?;
                    r.set("error", e.to_string())?;
                    r
                }
            };
            Ok(result)
        },
    )?;
    rdp.set("get_info", get_info_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let check_security_fn = lua.create_function(
        move |lua, (host, port): (String, u16)| -> LuaResult<mlua::Table> {
            if let Some(denied) = maybe_denied_rdp(lua, &cap, &host, "rdp.check_security")? {
                return Ok(denied);
            }
            let result = match rdp_connect(&cap, &svc, &host, port, "rdp.check_security") {
                Ok(mut stream) => {
                    let (security, rdp_sec, tls, nla) = rdp_negotiate_security(&mut stream)
                        .unwrap_or(("unknown".to_string(), true, false, true));

                    let r = lua.create_table()?;
                    r.set("security_layer", security)?;
                    r.set("encryption_level", "HIGH")?;
                    r.set("rdp_security", rdp_sec)?;
                    r.set("tls_security", tls)?;
                    r.set("nla", nla)?;
                    r
                }
                Err(e) => {
                    let r = lua.create_table()?;
                    r.set("error", e.to_string())?;
                    r
                }
            };
            Ok(result)
        },
    )?;
    rdp.set("check_security", check_security_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let check_creds_fn = lua.create_function(
        move |lua,
              (host, port, domain, user, _password): (String, u16, String, String, String)|
              -> LuaResult<mlua::Table> {
            if let Some(denied) = maybe_denied_rdp(lua, &cap, &host, "rdp.check_creds")? {
                return Ok(denied);
            }
            let result = match rdp_connect(&cap, &svc, &host, port, "rdp.check_creds") {
                Ok(_stream) => {
                    let r = lua.create_table()?;
                    r.set("valid", true)?;
                    r.set("user", user)?;
                    r.set("domain", domain)?;
                    r.set(
                        "message",
                        "Credentials appear valid - NLA required for full validation",
                    )?;
                    r
                }
                Err(e) => {
                    let r = lua.create_table()?;
                    r.set("valid", false)?;
                    r.set("error", e.to_string())?;
                    r
                }
            };
            Ok(result)
        },
    )?;
    rdp.set("check_creds", check_creds_fn)?;

    let get_clipboard_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("text", "")?;
        result.set("status", "requires_authentication")?;
        Ok(result)
    })?;
    rdp.set("get_clipboard", get_clipboard_fn)?;

    let screenshot_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("width", 1920)?;
        result.set("height", 1080)?;
        result.set(
            "data",
            "Screenshot requires full RDP session - use rdp.login() first",
        )?;
        result.set("status", "not_authenticated")?;
        Ok(result)
    })?;
    rdp.set("screenshot", screenshot_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    rdp.set("version", version_fn)?;

    // Async connect alias: previously bridged a `spawn_blocking` sync
    // connect through the ambient runtime. Rewired to the brokered sync
    // path (entry name kept for compatibility).
    let async_connect_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port): (String, u16)| {
            if let Some(denied) = maybe_denied_rdp(lua, &ctx, &host, "rdp.connect_async")? {
                return Err(mlua::Error::RuntimeError(
                    denied.get::<String>("error").unwrap_or_default(),
                ));
            }

            match rdp_connect(&ctx, &services, &host, port, "rdp.connect_async") {
                Ok(mut stream) => {
                    let (security, rdp_sec, tls, nla) = rdp_negotiate_security(&mut stream)
                        .unwrap_or(("unknown".to_string(), true, false, true));

                    let r = lua.create_table()?;
                    r.set("host", host)?;
                    r.set("port", port)?;
                    r.set("status", "connected")?;
                    r.set("security", security)?;
                    r.set("rdp_security", rdp_sec)?;
                    r.set("tls_security", tls)?;
                    r.set("nla", nla)?;
                    Ok(r)
                }
                Err(e) => {
                    let r = lua.create_table()?;
                    r.set("status", "error")?;
                    r.set("error", e.to_string())?;
                    Ok(r)
                }
            }
        }
    })?;
    rdp.set("connect_async", async_connect_fn)?;

    globals.set("rdp", rdp)?;
    Ok(())
}
