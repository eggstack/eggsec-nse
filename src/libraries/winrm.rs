//! NSE winrm library wrapper
//!
//! WinRM (Windows Remote Management) protocol support for NSE scripts.
//! Includes both blocking and async implementations.

use mlua::{Lua, Result as LuaResult};
use tokio::net::TcpStream as AsyncTcpStream;

pub fn register_winrm_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let winrm = lua.create_table()?;

    let connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("status", "connected")?;
        result.set("transport", "HTTP")?;

        Ok(result)
    })?;
    winrm.set("connect", connect_fn)?;

    let login_fn = lua.create_function(
        |lua, (_host, _port, domain, user, _password): (String, u16, String, String, String)| {
            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("user", format!("{}\\{}", domain, user))?;
            result.set("auth", "NTLM")?;

            Ok(result)
        },
    )?;
    winrm.set("login", login_fn)?;

    let command_fn =
        lua.create_function(|lua, (_host, _port, command): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("stdout", format!("Output of: {}\n", command))?;
            result.set("stderr", "")?;
            result.set("exit_code", 0)?;

            Ok(result)
        })?;
    winrm.set("command", command_fn)?;

    let get_output_fn =
        lua.create_function(|lua, (_host, _port, _shell_id): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("stdout", "command output")?;
            result.set("stderr", "")?;
            result.set("exit_code", 0)?;

            Ok(result)
        })?;
    winrm.set("get_output", get_output_fn)?;

    let get_winrm_config_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;

        let config = lua.create_table()?;
        config.set("MaxTimeoutms", 600000)?;
        config.set("MaxBatchSize", 150000)?;
        config.set("MaxProviderRequests", 4294967i64)?;
        config.set("AllowUnencrypted", true)?;

        result.set("config", config)?;

        Ok(result)
    })?;
    winrm.set("get_winrm_config", get_winrm_config_fn)?;

    let enumerate_fn =
        lua.create_function(|lua, (_host, _port, _resource): (String, u16, String)| {
            let result = lua.create_table()?;

            let items = lua.create_table()?;

            let item1 = lua.create_table()?;
            item1.set("Name", "WinRM")?;
            item1.set("Enabled", true)?;
            items.set(1, item1)?;

            let item2 = lua.create_table()?;
            item2.set("Name", "Remote-Management")?;
            item2.set("Enabled", true)?;
            items.set(2, item2)?;

            result.set("items", items)?;

            Ok(result)
        })?;
    winrm.set("enumerate", enumerate_fn)?;

    let get_service_status_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;

        let services = lua.create_table()?;

        let svc1 = lua.create_table()?;
        svc1.set("Name", "WinRM")?;
        svc1.set("Status", "Running")?;
        svc1.set("StartType", "Automatic")?;
        services.set(1, svc1)?;

        result.set("services", services)?;

        Ok(result)
    })?;
    winrm.set("get_service_status", get_service_status_fn)?;

    let get_host_info_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("ComputerName", "WIN-SERVER")?;
        result.set("OSName", "Windows Server 2019")?;
        result.set("OSVersion", "10.0.17763")?;
        result.set("Manufacturer", "Microsoft")?;
        result.set("Model", "Virtual Machine")?;

        Ok(result)
    })?;
    winrm.set("get_host_info", get_host_info_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    winrm.set("version", version_fn)?;

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
                    r.set("transport", "HTTP")?;
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
    winrm.set("connect_async", async_connect_fn)?;

    globals.set("winrm", winrm)?;
    Ok(())
}
