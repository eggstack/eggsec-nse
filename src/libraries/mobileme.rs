//! NSE mobileme library wrapper
//!
//! Apple MobileMe service support.
//! Based on Nmap's mobileme library: https://nmap.org/nsedoc/lib/mobileme.html

use mlua::{Lua, Result as LuaResult};

pub fn register_mobileme_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let mobileme = lua.create_table()?;

    let new_fn = lua.create_function(|lua, (username, password): (String, String)| {
        let mobileme = lua.create_table()?;
        mobileme.set("host", "fmipmobile.icloud.com")?;
        mobileme.set("port", 443)?;
        mobileme.set("username", username)?;
        mobileme.set("password", password)?;
        mobileme.set("connected", false)?;
        Ok(mobileme)
    })?;
    mobileme.set("new", new_fn)?;

    let login_fn = lua.create_function(|lua, (username, password): (String, String)| {
        let result = lua.create_table()?;

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build();

        match client {
            Ok(client) => {
                let url = format!(
                    "https://fmipmobile.icloud.com/fmipservice/device/{}/initClient",
                    username
                );

                let body = format!(
                    r#"{{"clientContext":{{"appName":"FindMyiPhone","appVersion":"1.3","buildVersion":"145","deviceUDID":"unknown"}},"username":"{}","password":"{}"}}"#,
                    username, password
                );

                match client.post(&url)
                    .header("Content-Type", "application/json")
                    .body(body)
                    .send()
                {
                    Ok(response) => {
                        if response.status().is_success() {
                            result.set("status", "ok")?;
                            result.set("authenticated", true)?;
                            result.set("session_id", "session_placeholder")?;
                        } else {
                            result.set("status", "fail")?;
                            result.set("authenticated", false)?;
                            result.set("error", format!("HTTP {}", response.status()))?;
                        }
                    }
                    Err(e) => {
                        result.set("status", "fail")?;
                        result.set("authenticated", false)?;
                        result.set("error", e.to_string())?;
                    }
                }
            }
            Err(e) => {
                result.set("status", "fail")?;
                result.set("authenticated", false)?;
                result.set("error", e.to_string())?;
            }
        }

        Ok(result)
    })?;
    mobileme.set("login", login_fn)?;

    let get_devices_fn = lua.create_function(|lua, _username: String| {
        let result = lua.create_table()?;
        result.set("status", "ok")?;

        let devices = lua.create_table()?;
        devices.set(1, "device_placeholder")?;
        result.set("devices", devices)?;

        Ok(result)
    })?;
    mobileme.set("getDevices", get_devices_fn)?;

    let send_message_fn = lua.create_function(
        |lua, (_username, device_id, message): (String, String, String)| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("message", message)?;
            result.set("device_id", device_id)?;

            Ok(result)
        },
    )?;
    mobileme.set("sendMessage", send_message_fn)?;

    mobileme.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("mobileme", mobileme)?;
    Ok(())
}
