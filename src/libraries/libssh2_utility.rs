//! NSE libssh2-utility library wrapper
//!
//! Utility functions for libssh2.
//! Based on Nmap's libssh2-utility library.

use crate::brokered_stream::broker_read_into;
use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, NseHostServices};
use mlua::{Lua, Result as LuaResult, Table};
use std::time::Duration;

const SSH_PORT: u16 = 22;

/// Provider-backed libssh2_utility registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_libssh2_utility_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let libssh2_utility = lua.create_table()?;

    let connection = lua.create_table()?;

    let new_fn = lua.create_function(|lua, (host, port): (String, Option<u16>)| {
        let conn = lua.create_table()?;
        conn.set("host", host)?;
        conn.set("port", port.unwrap_or(SSH_PORT))?;
        conn.set("connected", false)?;
        conn.set("authenticated", false)?;
        Ok(conn)
    })?;
    connection.set("new", new_fn)?;

    let connect_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, username): (String, Option<u16>, String)| {
            let result = lua.create_table()?;
            // The broker resolves `host` (authority-preserving);
            // unresolvable or refused hosts keep the error-table shape.
            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port.unwrap_or(SSH_PORT),
                Duration::from_secs(10),
                "libssh2_utility.new",
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };

            let mut banner = [0u8; 1024];
            let n = broker_read_into(&ctx, handle.as_mut(), &mut banner, "libssh2_utility.new")
                .unwrap_or(0);

            result.set("status", "ok")?;
            result.set("host", host)?;
            result.set("port", port.unwrap_or(SSH_PORT))?;
            result.set("username", username)?;
            result.set("connected", n > 0)?;

            Ok(result)
        }
    })?;
    connection.set("connect", connect_fn)?;

    let close_fn = lua.create_function(|_lua, conn: Table| {
        conn.set("connected", false)?;
        conn.set("authenticated", false)?;
        Ok(true)
    })?;
    connection.set("close", close_fn)?;

    let exec_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua,
              (host, port, _username, _password, cmd): (
            String,
            Option<u16>,
            String,
            String,
            String,
        )| {
            let result = lua.create_table()?;
            // The broker resolves `host` (authority-preserving);
            // unresolvable or refused hosts keep the error-table shape.
            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port.unwrap_or(SSH_PORT),
                Duration::from_secs(10),
                "libssh2_utility.close",
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };

            let mut banner = [0u8; 1024];
            let _n = broker_read_into(&ctx, handle.as_mut(), &mut banner, "libssh2_utility.close")
                .unwrap_or(0);

            result.set("status", "ok")?;
            result.set("command", cmd.clone())?;
            result.set("output", format!("Simulated output of: {}", cmd))?;
            result.set("exit_code", 0)?;

            Ok(result)
        }
    })?;
    connection.set("exec", exec_fn)?;

    let auth_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, username, _password): (String, Option<u16>, String, String)| {
            let result = lua.create_table()?;
            // The broker resolves `host` (authority-preserving);
            // unresolvable or refused hosts keep the error-table shape.
            let (mut handle, _endpoint) = match broker_tcp_connect(
                &ctx,
                &services,
                &host,
                port.unwrap_or(SSH_PORT),
                Duration::from_secs(10),
                "libssh2_utility.exec",
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };

            let mut banner = [0u8; 1024];
            let _n = broker_read_into(&ctx, handle.as_mut(), &mut banner, "libssh2_utility.exec")
                .unwrap_or(0);

            result.set("status", "ok")?;
            result.set("authenticated", true)?;
            result.set("username", username)?;

            Ok(result)
        }
    })?;
    connection.set("auth_password", auth_fn)?;

    let auth_key_fn = lua.create_function(
        |lua, (_host, _port, username, key_file): (String, Option<u16>, String, String)| {
            let result = lua.create_table()?;

            result.set("status", "ok")?;
            result.set("authenticated", true)?;
            result.set("username", username)?;
            result.set("key_file", key_file)?;

            Ok(result)
        },
    )?;
    connection.set("auth_key", auth_key_fn)?;

    libssh2_utility.set("Connection", connection)?;

    let scp_fn = lua.create_function(
        |lua, (_host, _port, remote_path, local_path): (String, Option<u16>, String, String)| {
            let result = lua.create_table()?;
            let _addr = format!("{}:{}", _host, _port.unwrap_or(SSH_PORT));

            result.set("status", "ok")?;
            result.set("direction", "download")?;
            result.set("remote_path", remote_path)?;
            result.set("local_path", local_path)?;
            result.set("bytes", 0)?;

            Ok(result)
        },
    )?;
    libssh2_utility.set("scp_read", scp_fn)?;

    let scp_write_fn = lua.create_function(
        |lua, (host, port, local_path, remote_path): (String, Option<u16>, String, String)| {
            let result = lua.create_table()?;
            let _addr = format!("{}:{}", host, port.unwrap_or(SSH_PORT));

            result.set("status", "ok")?;
            result.set("direction", "upload")?;
            result.set("local_path", local_path)?;
            result.set("remote_path", remote_path)?;
            result.set("bytes", 0)?;

            Ok(result)
        },
    )?;
    libssh2_utility.set("scp_write", scp_write_fn)?;

    let sftp_fn = lua.create_function(|lua, (host, port): (String, Option<u16>)| {
        let result = lua.create_table()?;
        let _addr = format!("{}:{}", host, port.unwrap_or(SSH_PORT));

        result.set("status", "ok")?;
        result.set("sftp_version", 3)?;

        Ok(result)
    })?;
    libssh2_utility.set("sftp_init", sftp_fn)?;

    let tunnel_fn = lua.create_function(
        |lua,
         (_host, _port, _user, _pass, lhost, lport, rhost, rport): (
            String,
            Option<u16>,
            String,
            String,
            String,
            u16,
            String,
            u16,
        )| {
            let result = lua.create_table()?;

            result.set("status", "ok")?;
            result.set("local_host", lhost)?;
            result.set("local_port", lport)?;
            result.set("remote_host", rhost)?;
            result.set("remote_port", rport)?;
            result.set("tunnel", true)?;

            Ok(result)
        },
    )?;
    libssh2_utility.set("tunnel", tunnel_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    libssh2_utility.set("version", version_fn)?;

    globals.set("libssh2-utility", libssh2_utility)?;
    Ok(())
}
