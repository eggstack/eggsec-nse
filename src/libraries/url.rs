//! NSE url library wrapper
//!
//! Provides URL parsing and manipulation functions.

use mlua::{Lua, Result as LuaResult, Table};
use url::Url;

pub fn register_url_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let url_mod = lua.create_table()?;

    url_mod.set(
        "parse",
        lua.create_function(|lua, url_str: String| {
            let parsed = Url::parse(&url_str);

            match parsed {
                Ok(url) => {
                    let result = lua.create_table()?;

                    result.set("scheme", url.scheme())?;
                    result.set("host", url.host_str().unwrap_or(""))?;
                    result.set("port", url.port().unwrap_or(0))?;
                    result.set("path", url.path())?;
                    result.set("query", url.query().unwrap_or(""))?;
                    result.set("fragment", url.fragment().unwrap_or(""))?;
                    result.set("user", url.username())?;

                    if let Some(password) = url.password() {
                        result.set("password", password)?;
                    }

                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("scheme", "")?;
                    result.set("host", "")?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        })?,
    )?;

    url_mod.set(
        "get_path",
        lua.create_function(|_lua, url_str: String| {
            if let Ok(url) = Url::parse(&url_str) {
                Ok(url.path().to_string())
            } else {
                Ok(String::new())
            }
        })?,
    )?;

    url_mod.set(
        "get_host",
        lua.create_function(|_lua, url_str: String| {
            if let Ok(url) = Url::parse(&url_str) {
                Ok(url.host_str().unwrap_or("").to_string())
            } else {
                Ok(String::new())
            }
        })?,
    )?;

    url_mod.set(
        "get_port",
        lua.create_function(|_lua, url_str: String| {
            if let Ok(url) = Url::parse(&url_str) {
                Ok(url.port().unwrap_or(0) as i32)
            } else {
                Ok(0i32)
            }
        })?,
    )?;

    url_mod.set(
        "build",
        lua.create_function(|_lua, parts: Table| {
            let scheme: String = parts.get("scheme").unwrap_or_else(|_| "http".to_string());
            let host: String = parts.get("host").unwrap_or_default();
            let port: u16 = parts.get("port").unwrap_or(0);
            let path: String = parts.get("path").unwrap_or_else(|_| "/".to_string());
            let query: String = parts.get("query").unwrap_or_default();

            let url = if port > 0 {
                format!("{}://{}:{}{}?{}", scheme, host, port, path, query)
            } else {
                format!("{}://{}{}?{}", scheme, host, path, query)
            };

            Ok(url)
        })?,
    )?;

    url_mod.set(
        "absolute",
        lua.create_function(|_lua, (base, relative): (String, String)| {
            let base_url = Url::parse(&base);

            match base_url {
                Ok(base) => match base.join(&relative) {
                    Ok(abs) => Ok(abs.to_string()),
                    Err(_) => Ok(relative),
                },
                Err(_) => Ok(relative),
            }
        })?,
    )?;

    url_mod.set(
        "encode",
        lua.create_function(|_lua, s: String| Ok(urlencoding::encode(&s).to_string()))?,
    )?;

    url_mod.set(
        "decode",
        lua.create_function(|_lua, s: String| {
            Ok(urlencoding::decode(&s).map(|d| d.to_string()).unwrap_or(s))
        })?,
    )?;

    url_mod.set(
        "parse_query",
        lua.create_function(|lua, query: String| {
            let params = lua.create_table()?;

            for pair in query.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    let decoded_key = urlencoding::decode(key)
                        .map(|k| k.to_string())
                        .unwrap_or_else(|_| key.to_string());
                    let decoded_val = urlencoding::decode(value)
                        .map(|v| v.to_string())
                        .unwrap_or_else(|_| value.to_string());
                    params.set(decoded_key, decoded_val)?;
                }
            }

            Ok(params)
        })?,
    )?;

    url_mod.set(
        "build_query",
        lua.create_function(|_lua, params: Table| {
            let mut pairs = Vec::new();

            for (key, value) in params.pairs::<String, String>().flatten() {
                let encoded_key = urlencoding::encode(&key);
                let encoded_val = urlencoding::encode(&value);
                pairs.push(format!("{}={}", encoded_key, encoded_val));
            }

            Ok(pairs.join("&"))
        })?,
    )?;

    url_mod.set(
        "get_domain",
        lua.create_function(|_lua, host: String| {
            let parts: Vec<&str> = host.split('.').collect();
            if parts.len() >= 2 {
                Ok(parts[parts.len() - 2..].join("."))
            } else {
                Ok(host)
            }
        })?,
    )?;

    url_mod.set(
        "get_tld",
        lua.create_function(|_lua, host: String| {
            let parts: Vec<&str> = host.split('.').collect();
            if !parts.is_empty() {
                Ok(parts.last().unwrap_or(&"").to_string())
            } else {
                Ok(String::new())
            }
        })?,
    )?;

    globals.set("url", url_mod)?;
    Ok(())
}
