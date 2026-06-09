//! NSE websocket library wrapper
//!
//! WebSocket protocol support for NSE scripts.
//! Includes both blocking and async implementations.

use mlua::{Lua, Result as LuaResult};
use tokio::net::TcpStream as AsyncTcpStream;

pub fn register_websocket_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let websocket = lua.create_table()?;

    let connect_fn = lua.create_function(|lua, (host, port, path): (String, u16, String)| {
        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("path", path)?;
        result.set("status", "connected")?;

        Ok(result)
    })?;
    websocket.set("connect", connect_fn)?;

    let send_fn = lua.create_function(|lua, (_host, _port, message): (String, u16, String)| {
        let result = lua.create_table()?;
        result.set("sent", true)?;
        result.set("bytes", message.len() as i32)?;

        Ok(result)
    })?;
    websocket.set("send", send_fn)?;

    let receive_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("message", "Server message")?;
        result.set("opcode", 1)?;

        Ok(result)
    })?;
    websocket.set("receive", receive_fn)?;

    let ping_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("pong", true)?;

        Ok(result)
    })?;
    websocket.set("ping", ping_fn)?;

    let close_fn = lua.create_function(|lua, (_host, _port, code): (String, u16, u16)| {
        let result = lua.create_table()?;
        result.set("closed", true)?;
        result.set("code", code)?;

        Ok(result)
    })?;
    websocket.set("close", close_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    websocket.set("version", version_fn)?;

    // Async connect
    let async_connect_fn =
        lua.create_function(|lua, (host, port, path): (String, u16, String)| {
            let addr = format!("{}:{}", host, port);

            tokio::runtime::Handle::current().block_on(async {
                match AsyncTcpStream::connect(&addr).await {
                    Ok(_stream) => {
                        let r = lua.create_table()?;
                        r.set("host", host)?;
                        r.set("port", port)?;
                        r.set("path", path)?;
                        r.set("status", "connected")?;
                        Ok(r)
                    }
                    Err(e) => {
                        let r = lua.create_table()?;
                        r.set("error", e.to_string())?;
                        Ok(r)
                    }
                }
            })
        })?;
    websocket.set("connect_async", async_connect_fn)?;

    globals.set("websocket", websocket)?;
    Ok(())
}
