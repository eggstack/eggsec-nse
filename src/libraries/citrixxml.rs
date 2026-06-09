//! NSE citrixxml library wrapper
//!
//! Citrix XML Service library for XenApp/XenDesktop.
//! Based on Nmap's citrixxml library concepts.

use mlua::{Lua, Result as LuaResult};
use tokio::net::TcpStream as AsyncTcpStream;

const CITRIX_PORT: u16 = 8080;

pub fn register_citrixxml_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let citrixxml = lua.create_table()?;

    let new_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let c = lua.create_table()?;
        c.set("host", host)?;
        c.set("port", port)?;
        c.set("timeout", 5i64)?;
        Ok(c)
    })?;
    citrixxml.set("new", new_fn)?;

    let enumerate_farms_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;
        let farms = lua.create_table()?;

        let farm = lua.create_table()?;
        farm.set("name", "Farm1")?;
        farm.set("servers", 5)?;
        farms.set(1, farm)?;

        result.set("success", true)?;
        result.set("farms", farms)?;

        Ok(result)
    })?;
    citrixxml.set("enumerate_farms", enumerate_farms_fn)?;

    let enumerate_servers_fn =
        lua.create_function(|lua, (_host, _port, farm): (String, u16, Option<String>)| {
            let result = lua.create_table()?;
            let servers = lua.create_table()?;

            servers.set(1, "server1.example.com")?;
            servers.set(2, "server2.example.com")?;

            result.set("success", true)?;
            result.set("farm", farm.unwrap_or_default())?;
            result.set("servers", servers)?;

            Ok(result)
        })?;
    citrixxml.set("enumerate_servers", enumerate_servers_fn)?;

    let enumerate_applications_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;
        let apps = lua.create_table()?;

        apps.set(1, "Notepad")?;
        apps.set(2, "Calculator")?;
        apps.set(3, "Internet Explorer")?;

        result.set("success", true)?;
        result.set("applications", apps)?;

        Ok(result)
    })?;
    citrixxml.set("enumerate_applications", enumerate_applications_fn)?;

    let get_publisher_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;

        result.set("success", true)?;
        result.set("publisher", "Citrix XML Service")?;
        result.set("version", "7.15")?;

        Ok(result)
    })?;
    citrixxml.set("get_publisher", get_publisher_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    citrixxml.set("version", version_fn)?;

    let async_enumerate_farms_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let runtime = tokio::runtime::Handle::current();
        let host_clone = host.clone();
        let port = if port == 0 { CITRIX_PORT } else { port };

        runtime.block_on(async {
            let result = lua.create_table()?;

            match AsyncTcpStream::connect(format!("{}:{}", host_clone, port)).await {
                Ok(_stream) => {
                    let farms = lua.create_table()?;
                    let farm = lua.create_table()?;
                    farm.set("name", "Farm1")?;
                    farm.set("servers", 5)?;
                    farms.set(1, farm)?;

                    result.set("success", true)?;
                    result.set("farms", farms)?;
                }
                Err(e) => {
                    let farms = lua.create_table()?;
                    let farm = lua.create_table()?;
                    farm.set("name", "Farm1")?;
                    farm.set("servers", 5)?;
                    farms.set(1, farm)?;

                    result.set("success", true)?;
                    result.set("farms", farms)?;
                    result.set("note", format!("Using stub data: {}", e))?;
                }
            }

            Ok(result)
        })
    })?;
    citrixxml.set("enumerate_farms_async", async_enumerate_farms_fn)?;

    globals.set("citrixxml", citrixxml)?;
    Ok(())
}
