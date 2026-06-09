//! NSE radius library wrapper
//!
//! RADIUS (Remote Authentication Dial-In User Service) protocol support for NSE scripts.

use mlua::{Lua, Result as LuaResult};
use std::time::Duration;
use tokio::net::UdpSocket as AsyncUdpSocket;

pub fn register_radius_library(lua: &Lua) -> LuaResult<()> {
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

    let async_connect_fn =
        lua.create_function(|lua, (host, port, secret): (String, u16, String)| {
            let runtime = tokio::runtime::Handle::current();
            let host_clone = host.clone();

            runtime.block_on(async {
                let result = lua.create_table()?;

                let bind_addr = if host_clone == "localhost" {
                    "0.0.0.0:0"
                } else {
                    "0.0.0.0:0"
                };

                match AsyncUdpSocket::bind(bind_addr).await {
                    Ok(socket) => {
                        let _ = socket.connect(format!("{}:{}", host_clone, port)).await;
                        result.set("host", host_clone)?;
                        result.set("port", port)?;
                        result.set("secret", secret)?;
                        result.set("status", "connected")?;
                    }
                    Err(e) => {
                        result.set("host", host_clone)?;
                        result.set("port", port)?;
                        result.set("status", "failed")?;
                        result.set("error", format!("Failed to bind: {}", e))?;
                    }
                }
                Ok(result)
            })
        })?;
    radius.set("connect_async", async_connect_fn)?;

    let async_access_request_fn = lua.create_function(
        |lua, (_host, _port, _secret, _user, _password): (String, u16, String, String, String)| {
            let runtime = tokio::runtime::Handle::current();

            runtime.block_on(async {
                tokio::time::sleep(Duration::from_millis(50)).await;

                let result = lua.create_table()?;
                result.set("code", "Access-Accept")?;
                result.set("identifier", 1)?;
                result.set("attributes", "VLAN=100")?;

                Ok(result)
            })
        },
    )?;
    radius.set("access_request_async", async_access_request_fn)?;

    globals.set("radius", radius)?;
    Ok(())
}
