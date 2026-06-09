//! NSE upnp library wrapper
//!
//! UPnP (Universal Plug and Play) discovery library.
//! Based on Nmap's upnp library concepts.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as AsyncTcpStream;

const SSDP_ADDR: &str = "239.255.255.250";
const SSDP_PORT: u16 = 1900;

pub fn register_upnp_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let upnp = lua.create_table()?;

    let discover_fn = lua.create_function(|lua, search_target: Option<String>| {
        let result = lua.create_table()?;
        let target = search_target.unwrap_or_else(|| "ssdp:all".to_string());

        let request = format!(
            "M-SEARCH * HTTP/1.1\r\n\
             HOST: {}:{}\r\n\
             MAN: \"ssdp:discover\"\r\n\
             MX: 3\r\n\
             ST: {}\r\n\
             USER-AGENT: Nmap-UPnP/1.0\r\n\
             \r\n",
            SSDP_ADDR, SSDP_PORT, target
        );

        match TcpStream::connect_timeout(
            &format!("{}:{}", SSDP_ADDR, SSDP_PORT)
                .parse()
                .unwrap_or_else(|_| std::net::SocketAddr::from(([239, 255, 255, 250], 1900))),
            Duration::from_secs(3),
        ) {
            Ok(mut stream) => {
                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();

                if let Err(e) = stream.write_all(request.as_bytes()) {
                    result.set("success", false)?;
                    result.set("error", format!("Send failed: {}", e))?;
                    return Ok(result);
                }

                let mut response = String::new();
                let devices = lua.create_table()?;
                let mut i = 1;

                let mut current_device = String::new();
                while stream.read_to_string(&mut response).is_ok() && !response.is_empty() {
                    if response.contains("HTTP/") || response.contains("NOTIFY") {
                        if !current_device.is_empty() {
                            let entry = lua.create_table()?;

                            for line in current_device.lines() {
                                if line.to_lowercase().starts_with("location:") {
                                    entry.set(
                                        "location",
                                        line.split(':').nth(1).unwrap_or("").trim(),
                                    )?;
                                } else if line.to_lowercase().starts_with("st:") {
                                    entry.set("st", line.split(':').nth(1).unwrap_or("").trim())?;
                                } else if line.to_lowercase().starts_with("server:") {
                                    entry.set(
                                        "server",
                                        line.split(':').nth(1).unwrap_or("").trim(),
                                    )?;
                                } else if line.to_lowercase().starts_with("usn:") {
                                    entry
                                        .set("usn", line.split(':').nth(1).unwrap_or("").trim())?;
                                }
                            }

                            if entry.len().unwrap_or(0) > 0 {
                                devices.set(i, entry)?;
                                i += 1;
                            }
                        }
                        current_device.clear();
                    }
                    current_device.push_str(&response);
                    current_device.push('\n');

                    if current_device.contains("HTTP/1.1 200 OK")
                        || current_device.contains("NOTIFY *")
                    {
                        break;
                    }

                    if i > 10 {
                        break;
                    }
                }

                if !current_device.is_empty() {
                    let entry = lua.create_table()?;
                    for line in current_device.lines() {
                        if line.to_lowercase().starts_with("location:") {
                            entry.set("location", line.split(':').nth(1).unwrap_or("").trim())?;
                        } else if line.to_lowercase().starts_with("st:") {
                            entry.set("st", line.split(':').nth(1).unwrap_or("").trim())?;
                        }
                    }
                    if entry.len().unwrap_or(0) > 0 {
                        devices.set(i, entry)?;
                    }
                }

                result.set("success", true)?;
                result.set("devices", devices)?;
                result.set("count", i - 1)?;
            }
            Err(e) => {
                result.set("success", false)?;
                result.set("error", format!("Discovery failed: {}", e))?;
            }
        }

        Ok(result)
    })?;
    upnp.set("discover", discover_fn)?;

    let get_devices_fn = lua.create_function(|lua, location: String| {
        let result = lua.create_table()?;

        let url = if location.starts_with("http") {
            location.clone()
        } else {
            format!("http://{}/", location)
        };

        match reqwest::blocking::get(&url) {
            Ok(resp) => match resp.text() {
                Ok(body) => {
                    let devices = lua.create_table()?;
                    let mut i = 1;

                    for line in body.lines() {
                        let line_lower = line.to_lowercase();
                        if line_lower.contains("service") || line_lower.contains("device") {
                            let entry = lua.create_table()?;
                            entry.set("raw", line.trim())?;
                            devices.set(i, entry)?;
                            i += 1;
                        }
                    }

                    result.set("success", true)?;
                    result.set("devices", devices)?;
                }
                _ => {
                    result.set("success", false)?;
                    result.set("error", "Failed to parse response")?;
                }
            },
            Err(e) => {
                result.set("success", false)?;
                result.set("error", format!("Request failed: {}", e))?;
            }
        }

        Ok(result)
    })?;
    upnp.set("get_devices", get_devices_fn)?;

    let get_external_ip_fn = lua.create_function(|lua, location: Option<String>| {
        let result = lua.create_table()?;

        let loc = location.unwrap_or_else(|| {
            "http://192.168.1.1:1900/ipc".to_string()
        });

        let soap_request = "<?xml version=\"1.0\"?>\
            <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
            <s:Body>\
            <u:GetExternalIPAddress xmlns=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
            </u:GetExternalIPAddress>\
            </s:Body>\
            </s:Envelope>";

        let host = loc.split('/').nth(2).unwrap_or("192.168.1.1");
        let path = loc.split(host).nth(1).unwrap_or("/upnp/control/WANIPConn1");

        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Content-Type: text/xml; charset=\"utf-8\"\r\n\
             SOAPACTION: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            path, host, soap_request.len(), soap_request
        );

        let addr = format!("{}:80", host.split(':').next().unwrap_or(host));

        match TcpStream::connect_timeout(
            &addr.parse().unwrap_or_else(|_| std::net::SocketAddr::from(([192,168,1,1], 80))),
            Duration::from_secs(5),
        ) {
            Ok(mut stream) => {
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

                if let Err(e) = stream.write_all(request.as_bytes()) {
                    result.set("success", false)?;
                    result.set("error", format!("Send failed: {}", e))?;
                    return Ok(result);
                }

                let mut response = String::new();
                if stream.read_to_string(&mut response).is_ok() {
                    if response.contains("200 OK") {
                        for line in response.lines() {
                            if line.contains("<NewExternalIPAddress>") {
                                let ip = line.split('>').nth(1)
                                    .unwrap_or("")
                                    .split('<')
                                    .next()
                                    .unwrap_or("");
                                result.set("success", true)?;
                                result.set("ip", ip)?;
                                return Ok(result);
                            }
                        }
                    }
                    result.set("success", false)?;
                    result.set("error", "Could not parse external IP")?;
                } else {
                    result.set("success", false)?;
                    result.set("error", "Failed to read response")?;
                }
            }
            Err(e) => {
                result.set("success", false)?;
                result.set("error", format!("Connection failed: {}", e))?;
            }
        }

        Ok(result)
    })?;
    upnp.set("get_external_ip", get_external_ip_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    upnp.set("version", version_fn)?;

    let async_discover_fn = lua.create_function(|lua, search_target: Option<String>| {
        let runtime = tokio::runtime::Handle::current();
        let target = search_target.unwrap_or_else(|| "ssdp:all".to_string());

        runtime.block_on(async {
            let result = lua.create_table()?;

            let request = format!(
                "M-SEARCH * HTTP/1.1\r\n\
                 HOST: {}:{}\r\n\
                 MAN: \"ssdp:discover\"\r\n\
                 MX: 3\r\n\
                 ST: {}\r\n\
                 USER-AGENT: Nmap-UPnP/1.0\r\n\
                 \r\n",
                SSDP_ADDR, SSDP_PORT, target
            );

            match AsyncTcpStream::connect(format!("{}:{}", SSDP_ADDR, SSDP_PORT)).await {
                Ok(mut stream) => {
                    if let Err(e) = stream.write_all(request.as_bytes()).await {
                        result.set("success", false)?;
                        result.set("error", format!("Send failed: {}", e))?;
                        return Ok(result);
                    }

                    let mut response = String::new();
                    let devices = lua.create_table()?;
                    let i = 1;

                    match stream.read_to_string(&mut response).await {
                        Ok(_) => {
                            if response.contains("HTTP/") || response.contains("NOTIFY") {
                                let entry = lua.create_table()?;
                                for line in response.lines() {
                                    if line.to_lowercase().starts_with("location:") {
                                        entry.set(
                                            "location",
                                            line.split(':').nth(1).unwrap_or("").trim(),
                                        )?;
                                    } else if line.to_lowercase().starts_with("st:") {
                                        entry.set(
                                            "st",
                                            line.split(':').nth(1).unwrap_or("").trim(),
                                        )?;
                                    }
                                }
                                if entry.len().unwrap_or(0) > 0 {
                                    devices.set(i, entry)?;
                                }
                            }
                        }
                        Err(e) => {
                            result.set("success", false)?;
                            result.set("error", format!("Read failed: {}", e))?;
                            return Ok(result);
                        }
                    }

                    result.set("success", true)?;
                    result.set("devices", devices)?;
                    result.set("count", i - 1)?;
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Discovery failed: {}", e))?;
                }
            }

            Ok(result)
        })
    })?;
    upnp.set("discover_async", async_discover_fn)?;

    let async_get_external_ip_fn = lua.create_function(|lua, location: Option<String>| {
        let runtime = tokio::runtime::Handle::current();

        runtime.block_on(async {
            let result = lua.create_table()?;

            let loc = location.unwrap_or_else(|| "http://192.168.1.1:1900/ipc".to_string());

            let soap_request = "<?xml version=\"1.0\"?>\
                <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
                <s:Body>\
                <u:GetExternalIPAddress xmlns=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
                </u:GetExternalIPAddress>\
                </s:Body>\
                </s:Envelope>";

            let host = loc.split('/').nth(2).unwrap_or("192.168.1.1");
            let path = loc.split(host).nth(1).unwrap_or("/upnp/control/WANIPConn1");

            let request = format!(
                "POST {} HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Type: text/xml; charset=\"utf-8\"\r\n\
                 SOAPACTION: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"\r\n\
                 Content-Length: {}\r\n\
                 \r\n\
                 {}",
                path, host, soap_request.len(), soap_request
            );

            let addr = format!("{}:80", host.split(':').next().unwrap_or(host));

            match AsyncTcpStream::connect(&addr).await {
                Ok(mut stream) => {
                    if let Err(e) = stream.write_all(request.as_bytes()).await {
                        result.set("success", false)?;
                        result.set("error", format!("Send failed: {}", e))?;
                        return Ok(result);
                    }

                    let mut response = String::new();
                    if stream.read_to_string(&mut response).await.is_ok() {
                        if response.contains("200 OK") {
                            for line in response.lines() {
                                if line.contains("<NewExternalIPAddress>") {
                                    let ip = line.split('>').nth(1)
                                        .unwrap_or("")
                                        .split('<')
                                        .next()
                                        .unwrap_or("");
                                    result.set("success", true)?;
                                    result.set("ip", ip)?;
                                    return Ok(result);
                                }
                            }
                        }
                        result.set("success", false)?;
                        result.set("error", "Could not parse external IP")?;
                    } else {
                        result.set("success", false)?;
                        result.set("error", "Failed to read response")?;
                    }
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
            }

            Ok(result)
        })
    })?;
    upnp.set("get_external_ip_async", async_get_external_ip_fn)?;

    globals.set("upnp", upnp)?;
    Ok(())
}
