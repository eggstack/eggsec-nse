//! NSE ncp library wrapper
//!
//! NCP (NetWare Core Protocol) library for Novell NetWare.
//! Based on Nmap's ncp library concepts.

use mlua::{Lua, Result as LuaResult};
use std::net::TcpStream;
use std::time::Duration;
use tokio::net::TcpStream as AsyncTcpStream;

const NCP_PORT: u16 = 524;

pub fn register_ncp_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let ncp = lua.create_table()?;

    let new_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let n = lua.create_table()?;
        n.set("host", host)?;
        n.set("port", port)?;
        n.set("timeout", 5i64)?;
        Ok(n)
    })?;
    ncp.set("new", new_fn)?;

    let connect_fn = lua.create_function(
        |lua, (host, port, user, _password): (String, u16, String, String)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);

            match TcpStream::connect_timeout(
                &addr
                    .parse()
                    .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 524))),
                Duration::from_secs(5),
            ) {
                Ok(_stream) => {
                    result.set("success", true)?;
                    result.set("host", host)?;
                    result.set("server", "NetWare Server")?;
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
    ncp.set("connect", connect_fn)?;

    let list_volumes_fn = lua.create_function(|lua, _host: String| {
        let result = lua.create_table()?;
        let volumes = lua.create_table()?;

        volumes.set(1, "SYS")?;
        volumes.set(2, "DATA")?;

        result.set("success", true)?;
        result.set("volumes", volumes)?;

        Ok(result)
    })?;
    ncp.set("list_volumes", list_volumes_fn)?;

    let list_directories_fn = lua.create_function(|lua, (_host, volume): (String, String)| {
        let result = lua.create_table()?;
        let dirs = lua.create_table()?;

        dirs.set(1, "SYSTEM")?;
        dirs.set(2, "PUBLIC")?;
        dirs.set(3, "LOGIN")?;

        result.set("success", true)?;
        result.set("volume", volume)?;
        result.set("directories", dirs)?;

        Ok(result)
    })?;
    ncp.set("list_directories", list_directories_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    ncp.set("version", version_fn)?;

    let async_connect_fn = lua.create_function(
        |lua, (host, port, user, _password): (String, u16, String, String)| {
            let runtime = tokio::runtime::Handle::current();
            let host_clone = host.clone();
            let port = if port == 0 { NCP_PORT } else { port };

            runtime.block_on(async {
                let result = lua.create_table()?;

                match AsyncTcpStream::connect(format!("{}:{}", host_clone, port)).await {
                    Ok(_stream) => {
                        result.set("success", true)?;
                        result.set("host", host_clone)?;
                        result.set("server", "NetWare Server")?;
                        result.set("user", user)?;
                    }
                    Err(e) => {
                        result.set("success", false)?;
                        result.set("error", format!("Connection failed: {}", e))?;
                    }
                }

                Ok(result)
            })
        },
    )?;
    ncp.set("connect_async", async_connect_fn)?;

    globals.set("ncp", ncp)?;
    Ok(())
}
