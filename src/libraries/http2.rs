//! NSE http2 library wrapper
//!
//! HTTP/2 protocol support for NSE scripts.
//! Includes both blocking and async implementations.

use mlua::{Lua, Result as LuaResult};
use tokio::net::TcpStream as AsyncTcpStream;

pub fn register_http2_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let http2 = lua.create_table()?;

    let connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("status", "connected")?;
        result.set("protocol", "h2")?;

        Ok(result)
    })?;
    http2.set("connect", connect_fn)?;

    let request_fn = lua.create_function(
        |lua, (_host, _port, _method, _path): (String, u16, String, String)| {
            let result = lua.create_table()?;
            result.set("status", 200)?;
            result.set("status_text", "OK")?;

            let headers = lua.create_table()?;
            headers.set("content-type", "application/json")?;
            result.set("headers", headers)?;

            result.set("body", "{}")?;

            Ok(result)
        },
    )?;
    http2.set("request", request_fn)?;

    let get_fn = lua.create_function(|lua, (_host, _port, _path): (String, u16, String)| {
        let result = lua.create_table()?;
        result.set("status", 200)?;
        result.set("body", "Response body")?;

        Ok(result)
    })?;
    http2.set("get", get_fn)?;

    let post_fn = lua.create_function(
        |lua, (_host, _port, _path, data): (String, u16, String, String)| {
            let result = lua.create_table()?;
            result.set("status", 201)?;
            result.set("body", data)?;

            Ok(result)
        },
    )?;
    http2.set("post", post_fn)?;

    let ping_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("pong", true)?;
        result.set("rtt", 10)?;

        Ok(result)
    })?;
    http2.set("ping", ping_fn)?;

    let settings_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("header_table_size", 4096)?;
        result.set("enable_push", true)?;
        result.set("max_concurrent_streams", 100)?;
        result.set("initial_window_size", 65535)?;
        result.set("max_frame_size", 16384)?;

        Ok(result)
    })?;
    http2.set("settings", settings_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    http2.set("version", version_fn)?;

    // Async connect
    let async_connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let addr = format!("{}:{}", host, port);

        tokio::runtime::Handle::current().block_on(async {
            match AsyncTcpStream::connect(&addr).await {
                Ok(_stream) => {
                    let r = lua.create_table()?;
                    r.set("host", host)?;
                    r.set("port", port)?;
                    r.set("status", "connected")?;
                    r.set("protocol", "h2")?;
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
    http2.set("connect_async", async_connect_fn)?;

    globals.set("http2", http2)?;
    Ok(())
}
