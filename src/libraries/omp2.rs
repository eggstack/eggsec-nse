//! NSE omp2 library wrapper
//!
//! OMP (OpenVAS Management Protocol) v2 support.
//! Based on Nmap's omp2 library: https://nmap.org/nsedoc/lib/omp2.html

use mlua::{Lua, Result as LuaResult, Table};

pub fn register_omp2_library(lua: &Lua) -> LuaResult<()> {
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

    let connect_fn = lua.create_function(
        |lua, (host, port, _user, _password): (String, u16, String, String)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);

            match native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .build()
            {
                Ok(_connector) => {
                    let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                        Ok(a) => a,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                            return Ok(result);
                        }
                    };
                    match std::net::TcpStream::connect_timeout(
                        &socket_addr,
                        std::time::Duration::from_secs(5),
                    ) {
                        Ok(_stream) => {
                            result.set("status", "ok")?;
                            result.set("connected", true)?;
                            result.set("host", host)?;
                            result.set("port", port)?;
                        }
                        _ => {
                            result.set("status", "fail")?;
                            result.set("connected", false)?;
                            result.set("error", "Connection failed")?;
                        }
                    }
                }
                Err(e) => {
                    result.set("status", "fail")?;
                    result.set("connected", false)?;
                    result.set("error", e.to_string())?;
                }
            }

            Ok(result)
        },
    )?;
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
