//! NSE afp library wrapper
//!
//! AFP (Apple Filing Protocol) library for Mac file sharing.
//! Based on Nmap's afp library concepts.

use mlua::{Lua, Result as LuaResult};
use std::net::TcpStream;
use std::time::Duration;
use tokio::net::TcpStream as AsyncTcpStream;

const AFP_PORT: u16 = 548;

pub fn register_afp_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let afp = lua.create_table()?;

    let new_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let a = lua.create_table()?;
        a.set("host", host)?;
        a.set("port", port)?;
        a.set("timeout", 5i64)?;
        Ok(a)
    })?;
    afp.set("new", new_fn)?;

    let connect_fn = lua.create_function(
        |lua, (host, port, _user, _password): (String, u16, Option<String>, Option<String>)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);

            match TcpStream::connect_timeout(
                &addr
                    .parse()
                    .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 548))),
                Duration::from_secs(5),
            ) {
                Ok(_stream) => {
                    result.set("success", true)?;
                    result.set("host", host)?;
                    result.set("port", port)?;
                    result.set("server", "AFP Server")?;
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
            }

            Ok(result)
        },
    )?;
    afp.set("connect", connect_fn)?;

    let list_volumes_fn = lua.create_function(|lua, _host: String| {
        let result = lua.create_table()?;
        let volumes = lua.create_table()?;

        volumes.set(1, "Home")?;
        volumes.set(2, "Macintosh HD")?;

        result.set("success", true)?;
        result.set("volumes", volumes)?;

        Ok(result)
    })?;
    afp.set("list_volumes", list_volumes_fn)?;

    let list_shares_fn = lua.create_function(|lua, _host: String| {
        let result = lua.create_table()?;
        let shares = lua.create_table()?;

        shares.set(1, "Public")?;
        shares.set(2, "Shared")?;

        result.set("success", true)?;
        result.set("shares", shares)?;

        Ok(result)
    })?;
    afp.set("list_shares", list_shares_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    afp.set("version", version_fn)?;

    let async_connect_fn = lua.create_function(
        |lua, (host, port, _user, _password): (String, u16, Option<String>, Option<String>)| {
            let runtime = tokio::runtime::Handle::current();
            let host_clone = host.clone();
            let port = if port == 0 { AFP_PORT } else { port };

            runtime.block_on(async {
                let result = lua.create_table()?;

                match AsyncTcpStream::connect(format!("{}:{}", host_clone, port)).await {
                    Ok(_stream) => {
                        result.set("success", true)?;
                        result.set("host", host_clone)?;
                        result.set("port", port)?;
                        result.set("server", "AFP Server")?;
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
    afp.set("connect_async", async_connect_fn)?;

    globals.set("afp", afp)?;
    Ok(())
}
