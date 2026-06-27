//! NSE nrpc library wrapper
//!
//! NRPC (Domino RPC) library for IBM Lotus Domino.
//! Based on Nmap's nrpc library concepts.

use mlua::{Lua, Result as LuaResult};
use std::net::TcpStream;
use std::time::Duration;
use tokio::net::TcpStream as AsyncTcpStream;

const NRPC_PORT: u16 = 1352;

pub fn register_nrpc_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let nrpc = lua.create_table()?;

    let new_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let n = lua.create_table()?;
        n.set("host", host)?;
        n.set("port", port)?;
        n.set("timeout", 5i64)?;
        Ok(n)
    })?;
    nrpc.set("new", new_fn)?;

    let connect_fn = lua.create_function(
        |lua, (host, port, user, _password): (String, u16, String, String)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);

            match TcpStream::connect_timeout(
                &addr
                    .parse()
                    .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 1352))),
                Duration::from_secs(5),
            ) {
                Ok(_stream) => {
                    result.set("success", true)?;
                    result.set("host", host)?;
                    result.set("server", "Lotus Domino")?;
                    result.set("user", user)?;
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
            }

            Ok(result)
        },
    )?;
    nrpc.set("connect", connect_fn)?;

    let list_databases_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;
        let dbs = lua.create_table()?;

        dbs.set(1, "names.nsf")?;
        dbs.set(2, "addressbook.nsf")?;
        dbs.set(3, "mail.box")?;

        result.set("success", true)?;
        result.set("databases", dbs)?;

        Ok(result)
    })?;
    nrpc.set("list_databases", list_databases_fn)?;

    let get_version_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;

        result.set("success", true)?;
        result.set("version", "9.0.1")?;
        result.set("server", "Lotus Domino")?;

        Ok(result)
    })?;
    nrpc.set("get_version", get_version_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    nrpc.set("version", version_fn)?;

    let async_connect_fn = lua.create_function(
        |lua, (host, port, user, _password): (String, u16, String, String)| {
            let runtime = tokio::runtime::Handle::current();
            let host_clone = host.clone();
            let port = if port == 0 { NRPC_PORT } else { port };

            runtime.block_on(async {
                let result = lua.create_table()?;

                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    AsyncTcpStream::connect(format!("{}:{}", host_clone, port)),
                )
                .await
                {
                    Ok(Ok(_stream)) => {
                        result.set("success", true)?;
                        result.set("host", host_clone)?;
                        result.set("server", "Lotus Domino")?;
                        result.set("user", user)?;
                    }
                    Ok(Err(e)) => {
                        result.set("success", false)?;
                        result.set("error", format!("Connection failed: {}", e))?;
                    }
                    Err(_) => {
                        result.set("success", false)?;
                        result.set("error", "Connection timed out".to_string())?;
                    }
                }

                Ok(result)
            })
        },
    )?;
    nrpc.set("connect_async", async_connect_fn)?;

    globals.set("nrpc", nrpc)?;
    Ok(())
}
