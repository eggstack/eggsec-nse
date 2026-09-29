//! NSE omp2 library wrapper
//!
//! OMP (OpenVAS Management Protocol) v2 support.
//! Based on Nmap's omp2 library: https://nmap.org/nsedoc/lib/omp2.html

use mlua::{Lua, Result as LuaResult, Table};

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, NseHostServices};

/// Provider-backed omp2 registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_omp2_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let omp2 = lua.create_table()?;

    let new_fn = lua.create_function(|lua, _: ()| {
        let session = lua.create_table()?;
        session.set("host", "")?;
        session.set("port", 9390)?;
        session.set("connected", false)?;
        session.set("authenticated", false)?;
        Ok(session)
    })?;
    omp2.set("Session", new_fn)?;

    // Connect probe: previously built a `TlsConnector` (never actually
    // handshaked — only a raw TCP connect-check ran) over a literally
    // parsed address. Rewired to an authority-preserving brokered probe;
    // the success/failure shapes are preserved. (`insecure_tls` no longer
    // applies: no TLS handshake runs on this path.)
    let connect_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, _user, _password): (String, u16, String, String)| {
            let result = lua.create_table()?;

            match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port,
                std::time::Duration::from_secs(5),
                "omp2.connect",
            ) {
                Ok((_handle, _endpoint)) => {
                    result.set("status", "ok")?;
                    result.set("connected", true)?;
                    result.set("host", host)?;
                    result.set("port", port)?;
                }
                Err(_) => {
                    result.set("status", "fail")?;
                    result.set("connected", false)?;
                    result.set("error", "Connection failed")?;
                }
            }

            Ok(result)
        }
    })?;
    omp2.set("connect", connect_fn)?;

    let authenticate_fn = lua.create_function(
        |lua, (session, username, _password): (Table, String, String)| {
            let result = lua.create_table()?;

            let host: String = session.get("host").unwrap_or_default();
            let _port: u16 = session.get("port").unwrap_or(9390);

            if host.is_empty() {
                result.set("status", "fail")?;
                result.set("authenticated", false)?;
                result.set("error", "Not connected")?;
                return Ok(result);
            }

            result.set("status", "ok")?;
            result.set("authenticated", true)?;
            result.set("username", username)?;

            Ok(result)
        },
    )?;
    omp2.set("authenticate", authenticate_fn)?;

    let ls_targets_fn = lua.create_function(|lua, _session: Table| {
        let result = lua.create_table()?;
        result.set("status", "ok")?;

        let targets = lua.create_table()?;
        targets.set(1, "localhost")?;
        result.set("targets", targets)?;

        Ok(result)
    })?;
    omp2.set("ls_targets", ls_targets_fn)?;

    let add_account_fn = lua.create_function(
        |_lua, (_host, _username, _password): (String, String, String)| Ok(true),
    )?;
    omp2.set("add_account", add_account_fn)?;

    let get_accounts_fn = lua.create_function(|lua, _host: String| lua.create_table())?;
    omp2.set("get_accounts", get_accounts_fn)?;

    let close_fn = lua.create_function(|_lua, _session: Table| Ok(true))?;
    omp2.set("close", close_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    omp2.set("version", version_fn)?;

    globals.set("omp2", omp2)?;
    Ok(())
}
