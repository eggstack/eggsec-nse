//! NSE brute library wrapper
//!
//! Provides brute-force authentication utilities for NSE scripts.
//! Based on Nmap's brute library: https://nmap.org/nsedoc/lib/brute.html

use mlua::{Lua, Result as LuaResult, Table};
use rustc_hash::FxHashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

use super::helpers::fallback_lua_table;
use crate::capabilities::NseCapabilityContext;
use crate::wrappers;

static CREDS_STORE: std::sync::LazyLock<Mutex<FxHashMap<String, Vec<(String, String)>>>> =
    std::sync::LazyLock::new(|| Mutex::new(FxHashMap::default()));

static ACCOUNT_STORE: std::sync::LazyLock<Mutex<Vec<(String, String, bool)>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

pub fn register_brute_library(lua: &Lua, capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    let globals = lua.globals();
    let brute = lua.create_table()?;

    brute.set(
        "new_iterator",
        lua.create_function(|lua, (_driver, _options): (Table, Option<Table>)| {
            let iterator = lua.create_table()?;
            iterator.set("driver", "custom")?;
            iterator.set("initialized", true)?;
            Ok(iterator)
        })?,
    )?;

    brute.set(
        "new_account",
        lua.create_function(|lua, (username, password): (String, String)| {
            let account = lua.create_table()?;
            account.set("username", username.clone())?;
            account.set("password", password.clone())?;

            if let Ok(mut store) = ACCOUNT_STORE.lock() {
                store.push((username, password, false));
            }

            Ok(account)
        })?,
    )?;

    brute.set(
        "add_credentials",
        lua.create_function(|_lua, (username, password): (String, String)| {
            if let Ok(mut store) = CREDS_STORE.lock() {
                let entry = store.entry("default".to_string()).or_insert_with(Vec::new);
                entry.push((username, password));
            }
            Ok(true)
        })?,
    )?;

    brute.set(
        "save_credentials",
        lua.create_function(|_lua, _: ()| Ok(true))?,
    )?;

    brute.set(
        "serialized_credentials",
        lua.create_function(|lua, _: ()| {
            let result = lua.create_table()?;

            if let Ok(store) = CREDS_STORE.lock() {
                let mut i = 1;
                for (_, creds) in store.iter() {
                    for (username, password) in creds {
                        let entry = lua.create_table()?;
                        entry.set("username", username.clone())?;
                        entry.set("password", password.clone())?;
                        result.set(i, entry)?;
                        i += 1;
                    }
                }
            }

            Ok(result)
        })?,
    )?;

    let ctx = capability_ctx.clone();
    brute.set(
        "username_iterator",
        lua.create_function(move |lua, (_driver, filename): (Table, Option<String>)| {
            let usernames = lua.create_table()?;

            let user_list = if let Some(ref f) = filename {
                wrappers::nse_fs_read_to_string(&ctx, f)
                    .ok()
                    .map(|content| {
                        content
                            .lines()
                            .map(|s| s.to_string())
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_else(get_default_usernames)
            } else {
                get_default_usernames()
            };

            for (i, user) in user_list.iter().enumerate() {
                usernames.set(i + 1, user.clone())?;
            }

            Ok(usernames)
        })?,
    )?;

    let ctx = capability_ctx.clone();
    brute.set(
        "password_iterator",
        lua.create_function(move |lua, (_driver, filename): (Table, Option<String>)| {
            let passwords = lua.create_table()?;

            let pass_list = if let Some(ref f) = filename {
                wrappers::nse_fs_read_to_string(&ctx, f)
                    .ok()
                    .map(|content| {
                        content
                            .lines()
                            .map(|s| s.to_string())
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_else(get_default_passwords)
            } else {
                get_default_passwords()
            };

            for (i, pass) in pass_list.iter().enumerate() {
                passwords.set(i + 1, pass.clone())?;
            }

            Ok(passwords)
        })?,
    )?;

    let ctx = capability_ctx.clone();
    brute.set(
        "file_iterator",
        lua.create_function(move |lua, filename: String| {
            let lines = lua.create_table()?;

            if let Ok(content) = wrappers::nse_fs_read_to_string(&ctx, &filename) {
                for (i, line) in content.lines().enumerate() {
                    if !line.trim().is_empty() {
                        lines.set(i + 1, line.trim().to_string())?;
                    }
                }
            }

            Ok(lines)
        })?,
    )?;

    brute.set(
        "pin_iterator",
        lua.create_function(|lua, (_driver, options): (Table, Option<Table>)| {
            let pins = lua.create_table()?;

            let min_len = options
                .as_ref()
                .and_then(|o| o.get::<u32>("min").ok())
                .unwrap_or(4);
            let max_len = options
                .as_ref()
                .and_then(|o| o.get::<u32>("max").ok())
                .unwrap_or(6);

            for len in min_len..=max_len {
                let count = 10u32.pow(len);
                for i in 0..count.min(1000) {
                    let pin = format!("{:0>width$}", i, width = len as usize);
                    let idx = pins.len().unwrap_or(0) as usize + 1;
                    pins.set(idx, pin)?;
                }
            }

            Ok(pins)
        })?,
    )?;

    brute.set(
        "serial_pass_iterator",
        lua.create_function(|lua, (_driver, options): (Table, Option<Table>)| {
            let passwords = lua.create_table()?;

            let base = options
                .as_ref()
                .and_then(|o| o.get::<String>("base").ok())
                .unwrap_or_else(|| "password".to_string());

            let start = options
                .as_ref()
                .and_then(|o| o.get::<u32>("start").ok())
                .unwrap_or(0);
            let count = options
                .as_ref()
                .and_then(|o| o.get::<u32>("count").ok())
                .unwrap_or(100);

            for i in start..(start + count) {
                let pass = format!("{}{}", base, i);
                passwords.set((i - start + 1) as usize, pass)?;
            }

            Ok(passwords)
        })?,
    )?;

    brute.set(
        "libcurl_iterator",
        lua.create_function(|lua, (_driver, options): (Table, Option<Table>)| {
            let iterator = lua.create_table()?;
            iterator.set("driver", "libcurl")?;
            iterator.set(
                "options",
                options.unwrap_or_else(|| fallback_lua_table(lua)),
            )?;
            Ok(iterator)
        })?,
    )?;

    brute.set(
        "tcp_get_words",
        lua.create_function(
            |lua, (_host, _port, options): (String, u16, Option<Table>)| {
                let result = lua.create_table()?;

                let delay = options
                    .as_ref()
                    .and_then(|o| o.get::<u64>("delay").ok())
                    .unwrap_or(1000);

                std::thread::sleep(std::time::Duration::from_millis(delay));

                result.set("status", "timeout")?;
                result.set("words", lua.create_table()?)?;

                Ok(result)
            },
        )?,
    )?;

    brute.set(
        "tcp_get_words_ex",
        lua.create_function(
            |lua, (_host, _port, _options): (String, u16, Option<Table>)| {
                let result = lua.create_table()?;
                result.set("status", "timeout")?;
                result.set("words", lua.create_table()?)?;
                Ok(result)
            },
        )?,
    )?;

    brute.set(
        "tcp_send_words",
        lua.create_function(
            |lua, (_host, _port, words, _options): (String, u16, Table, Option<Table>)| {
                let result = lua.create_table()?;
                result.set("status", "sent")?;
                result.set("count", words.len().unwrap_or(0))?;
                Ok(result)
            },
        )?,
    )?;

    brute.set(
        "http_auth",
        lua.create_function(
            |lua, (host, port, uri, username, password): (String, u16, String, String, String)| {
                let result = lua.create_table()?;

                let client = match reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .danger_accept_invalid_certs(true)
                    .build()
                {
                    Ok(c) => c,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", format!("Failed to create HTTP client: {}", e))?;
                        return Ok(result);
                    }
                };

                let url = format!("http://{}:{}{}", host, port, uri);
                let response = client
                    .get(&url)
                    .basic_auth(&username, Some(&password))
                    .send();

                match response {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        result.set("status", if status == 200 { "ok" } else { "fail" })?;
                        result.set("code", status)?;
                        result.set("success", status == 200)?;
                    }
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e.to_string())?;
                    }
                }

                Ok(result)
            },
        )?,
    )?;

    brute.set(
        "http_form_auth",
        lua.create_function(
            |lua,
             (_host, _port, _form_path, _username_field, _password_field, _username, _password): (
                String,
                u16,
                String,
                String,
                String,
                String,
                String,
            )| {
                let result = lua.create_table()?;
                result.set("success", false)?;
                result.set("status", "not_implemented")?;
                Ok(result)
            },
        )?,
    )?;

    brute.set(
        "ldap_login",
        lua.create_function(
            |lua, (_host, _port, _dn, _username, _password): (String, u16, String, String, String)| {
                let result = lua.create_table()?;
                result.set("success", false)?;
                result.set("status", "not_implemented")?;
                Ok(result)
            },
        )?,
    )?;

    brute.set(
        "smb_login",
        lua.create_function(
            |lua,
             (host, port, domain, username, password): (
                String,
                u16,
                String,
                String,
                String,
            )| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);
            let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                Ok(a) => a,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                    return Ok(result);
                }
                };
                let mut stream = match TcpStream::connect_timeout(
                    &socket_addr,
                    Duration::from_secs(10),
                ) {
                Ok(s) => s,
                Err(e) => {
                    result.set("success", false)?;
                    result.set("status", "error")?;
                    result.set("error", format!("connection failed: {}", e))?;
                    return Ok(result);
                }
            };

            stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

            let negotiate_request = build_smb_negotiate();
            if let Err(e) = stream.write_all(&negotiate_request) {
                result.set("success", false)?;
                result.set("status", "error")?;
                result.set("error", format!("negotiate failed: {}", e))?;
                return Ok(result);
            }

            let mut response = vec![0u8; 1024];
            match stream.read(&mut response) {
                Ok(n) if n >= 32 && response[9] == 0x00 => {}
                _ => {
                    result.set("success", false)?;
                    result.set("status", "error")?;
                    result.set("error", "negotiate failed")?;
                    return Ok(result);
                }
            }

            let session_setup = build_smb_session_setup(&username, &password, &domain);
            if let Err(e) = stream.write_all(&session_setup) {
                result.set("success", false)?;
                result.set("status", "error")?;
                result.set("error", format!("session setup failed: {}", e))?;
                return Ok(result);
            }

            let mut response = vec![0u8; 1024];
            match stream.read(&mut response) {
                Ok(n) if n >= 32 => {
                    let nt_status = u32::from_le_bytes([response[5], response[6], response[7], response[8]]);
                    if nt_status == 0 {
                        result.set("success", true)?;
                        result.set("status", "ok")?;
                    } else {
                        result.set("success", false)?;
                        result.set("status", "fail")?;
                    }
                }
                _ => {
                    result.set("success", false)?;
                    result.set("status", "error")?;
                    result.set("error", "session setup failed")?;
                }
            }

            Ok(result)
        },
        )?,
    )?;

    brute.set(
        "mysql_login",
        lua.create_function(
            |lua, (host, port, username, password): (String, u16, String, String)| {
                let result = lua.create_table()?;

                let addr = format!("{}:{}", host, port);
                let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                    Ok(a) => a,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                        return Ok(result);
                    }
                };
                let mut stream =
                    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10)) {
                        Ok(s) => s,
                        Err(e) => {
                            result.set("success", false)?;
                            result.set("status", "error")?;
                            result.set("error", format!("connection failed: {}", e))?;
                            return Ok(result);
                        }
                    };

                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

                let mut handshake = vec![0u8; 256];
                match stream.read(&mut handshake) {
                    Ok(n) if n > 0 => {}
                    _ => {
                        result.set("success", false)?;
                        result.set("status", "error")?;
                        result.set("error", "handshake failed")?;
                        return Ok(result);
                    }
                }

                if handshake.len() < 4 || handshake[0] != 0x0a {
                    result.set("success", false)?;
                    result.set("status", "error")?;
                    result.set("error", "invalid handshake")?;
                    return Ok(result);
                }

                let salt_1 = extract_mysql_salt(&handshake, 1);
                let salt_2 = extract_mysql_salt(&handshake, 2);

                let response =
                    build_mysql_handshake_response(&username, &password, &salt_1, &salt_2);
                if let Err(e) = stream.write_all(&response) {
                    result.set("success", false)?;
                    result.set("status", "error")?;
                    result.set("error", format!("auth failed: {}", e))?;
                    return Ok(result);
                }

                let mut auth_response = vec![0u8; 1024];
                match stream.read(&mut auth_response) {
                    Ok(n) if n >= 4 => {
                        if auth_response[0] == 0x00 || auth_response[0] == 0xff {
                            result.set("success", auth_response[0] == 0x00)?;
                            if auth_response[0] == 0x00 {
                                result.set("status", "ok")?;
                            } else {
                                result.set("status", "fail")?;
                                if n > 7 {
                                    let msg = String::from_utf8_lossy(&auth_response[7..n]);
                                    result.set("error", msg.to_string())?;
                                }
                            }
                        } else {
                            result.set("success", false)?;
                            result.set("status", "error")?;
                        }
                    }
                    _ => {
                        result.set("success", false)?;
                        result.set("status", "error")?;
                        result.set("error", "auth response failed")?;
                    }
                }

                Ok(result)
            },
        )?,
    )?;

    brute.set(
        "postgres_login",
        lua.create_function(
            |lua, (host, port, username, password): (String, u16, String, String)| {
                let result = lua.create_table()?;

                let addr = format!("{}:{}", host, port);
                let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                    Ok(a) => a,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                        return Ok(result);
                    }
                };
                let mut stream =
                    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10)) {
                        Ok(s) => s,
                        Err(e) => {
                            result.set("success", false)?;
                            result.set("status", "error")?;
                            result.set("error", format!("connection failed: {}", e))?;
                            return Ok(result);
                        }
                    };

                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

                let startup = build_postgres_startup(&username);
                if let Err(e) = stream.write_all(&startup) {
                    result.set("success", false)?;
                    result.set("status", "error")?;
                    result.set("error", format!("startup failed: {}", e))?;
                    return Ok(result);
                }

                let mut response = vec![0u8; 1024];
                match stream.read(&mut response) {
                    Ok(n) if n >= 8 => {
                        if response[0] == b'R' && n >= 12 {
                            let auth_type = u32::from_be_bytes([
                                response[5],
                                response[6],
                                response[7],
                                response[8],
                            ]);
                            if auth_type == 5 {
                                let salt = &response[9..13];
                                let md5_response =
                                    build_postgres_md5_response(&username, &password, salt);
                                if let Err(e) = stream.write_all(&md5_response) {
                                    result.set("success", false)?;
                                    result.set("status", "error")?;
                                    result.set("error", format!("auth failed: {}", e))?;
                                    return Ok(result);
                                }

                                let mut final_response = vec![0u8; 1024];
                                match stream.read(&mut final_response) {
                                    Ok(m) if m >= 8 => {
                                        if final_response[0] == b'R' {
                                            let auth_result = u32::from_be_bytes([
                                                final_response[5],
                                                final_response[6],
                                                final_response[7],
                                                final_response[8],
                                            ]);
                                            if auth_result == 0 {
                                                result.set("success", true)?;
                                                result.set("status", "ok")?;
                                            } else {
                                                result.set("success", false)?;
                                                result.set("status", "fail")?;
                                            }
                                        } else if final_response[0] == b'E' {
                                            result.set("success", false)?;
                                            result.set("status", "fail")?;
                                        } else {
                                            result.set("success", false)?;
                                            result.set("status", "error")?;
                                        }
                                    }
                                    _ => {
                                        result.set("success", false)?;
                                        result.set("status", "error")?;
                                        result.set("error", "auth response failed")?;
                                    }
                                }
                            } else if auth_type == 0 {
                                result.set("success", true)?;
                                result.set("status", "ok")?;
                            } else {
                                result.set("success", false)?;
                                result.set("status", "error")?;
                                result.set(
                                    "error",
                                    format!("unsupported auth type: {}", auth_type),
                                )?;
                            }
                        } else {
                            result.set("success", false)?;
                            result.set("status", "error")?;
                            result.set("error", "invalid startup response")?;
                        }
                    }
                    _ => {
                        result.set("success", false)?;
                        result.set("status", "error")?;
                        result.set("error", "startup response failed")?;
                    }
                }

                Ok(result)
            },
        )?,
    )?;

    brute.set(
        "redis_login",
        lua.create_function(|lua, (host, port, password): (String, u16, String)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);
            let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                Ok(a) => a,
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                    return Ok(result);
                }
            };
            let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))
            {
                Ok(s) => s,
                Err(e) => {
                    result.set("success", false)?;
                    result.set("status", "error")?;
                    result.set("error", format!("connection failed: {}", e))?;
                    return Ok(result);
                }
            };

            stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

            let ping = b"*1\r\n$4\r\nPING\r\n";
            if let Err(e) = stream.write_all(ping) {
                result.set("success", false)?;
                result.set("status", "error")?;
                result.set("error", format!("ping failed: {}", e))?;
                return Ok(result);
            }

            let mut response = vec![0u8; 64];
            if let Ok(n) = stream.read(&mut response) {
                if n == 0 || !response[..n.min(2)].starts_with(b"+PONG") {
                    result.set("success", false)?;
                    result.set("status", "error")?;
                    result.set("error", "ping failed")?;
                    return Ok(result);
                }
            }

            let auth_cmd = format!(
                "*2\r\n$4\r\nAUTH\r\n${}\r\n{}\r\n",
                password.len(),
                password
            );
            if let Err(e) = stream.write_all(auth_cmd.as_bytes()) {
                result.set("success", false)?;
                result.set("status", "error")?;
                result.set("error", format!("auth failed: {}", e))?;
                return Ok(result);
            }

            let mut auth_response = vec![0u8; 64];
            match stream.read(&mut auth_response) {
                Ok(n) if n > 0 => {
                    if auth_response[0] == b'+' {
                        result.set("success", true)?;
                        result.set("status", "ok")?;
                    } else if auth_response[0] == b'-' {
                        result.set("success", false)?;
                        result.set("status", "fail")?;
                        result.set(
                            "error",
                            String::from_utf8_lossy(&auth_response[1..n]).to_string(),
                        )?;
                    } else {
                        result.set("success", false)?;
                        result.set("status", "error")?;
                    }
                }
                _ => {
                    result.set("success", false)?;
                    result.set("status", "error")?;
                    result.set("error", "auth response failed")?;
                }
            }

            Ok(result)
        })?,
    )?;

    brute.set(
        "ftp_login",
        lua.create_function(
            |lua, (host, port, username, password): (String, u16, String, String)| {
                let result = lua.create_table()?;

                let addr = format!("{}:{}", host, port);
                let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                    Ok(a) => a,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                        return Ok(result);
                    }
                };
                let mut stream =
                    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10)) {
                        Ok(s) => s,
                        Err(e) => {
                            result.set("success", false)?;
                            result.set("status", "error")?;
                            result.set("error", format!("connection failed: {}", e))?;
                            return Ok(result);
                        }
                    };

                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

                let mut response = vec![0u8; 256];
                match stream.read(&mut response) {
                    Ok(n) if n >= 3 => {
                        if response[0] != b'2' {
                            result.set("success", false)?;
                            result.set("status", "error")?;
                            result.set(
                                "error",
                                format!(
                                    "unexpected welcome: {}",
                                    String::from_utf8_lossy(&response[..n])
                                ),
                            )?
                        }
                    }
                    _ => {
                        result.set("success", false)?;
                        result.set("status", "error")?;
                        result.set("error", "welcome failed")?;
                        return Ok(result);
                    }
                }

                let user_cmd = format!("USER {}\r\n", username);
                if let Err(e) = stream.write_all(user_cmd.as_bytes()) {
                    result.set("success", false)?;
                    result.set("status", "error")?;
                    result.set("error", format!("user failed: {}", e))?;
                    return Ok(result);
                }

                let mut response = vec![0u8; 256];
                match stream.read(&mut response) {
                    Ok(n) if n >= 3 => {
                        if response[0] == b'3' {
                            let pass_cmd = format!("PASS {}\r\n", password);
                            if let Err(e) = stream.write_all(pass_cmd.as_bytes()) {
                                result.set("success", false)?;
                                result.set("status", "error")?;
                                result.set("error", format!("pass failed: {}", e))?;
                                return Ok(result);
                            }

                            let mut response = vec![0u8; 256];
                            match stream.read(&mut response) {
                                Ok(m) if m >= 3 => {
                                    if response[0] == b'2' {
                                        result.set("success", true)?;
                                        result.set("status", "ok")?;
                                    } else {
                                        result.set("success", false)?;
                                        result.set("status", "fail")?;
                                    }
                                }
                                _ => {
                                    result.set("success", false)?;
                                    result.set("status", "error")?;
                                    result.set("error", "pass response failed")?;
                                }
                            }
                        } else if response[0] == b'2' {
                            result.set("success", true)?;
                            result.set("status", "ok")?;
                        } else {
                            result.set("success", false)?;
                            result.set("status", "fail")?;
                        }
                    }
                    _ => {
                        result.set("success", false)?;
                        result.set("status", "error")?;
                        result.set("error", "user response failed")?;
                    }
                }

                Ok(result)
            },
        )?,
    )?;

    brute.set(
        "ssh_login",
        lua.create_function(
            |lua, (host, port, username, password): (String, u16, String, String)| {
                let result = lua.create_table()?;

                let addr = format!("{}:{}", host, port);
                let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                    Ok(a) => a,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                        return Ok(result);
                    }
                };
                let mut stream =
                    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10)) {
                        Ok(s) => s,
                        Err(e) => {
                            result.set("success", false)?;
                            result.set("status", "error")?;
                            result.set("error", format!("connection failed: {}", e))?;
                            return Ok(result);
                        }
                    };

                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

                let mut banner = vec![0u8; 256];
                match stream.read(&mut banner) {
                    Ok(n) if n > 0 => {
                        if !banner[..n.min(6)].starts_with(b"SSH-") {
                            result.set("success", false)?;
                            result.set("status", "error")?;
                            result.set("error", "not an SSH server")?;
                            return Ok(result);
                        }
                    }
                    _ => {
                        result.set("success", false)?;
                        result.set("status", "error")?;
                        result.set("error", "banner failed")?;
                        return Ok(result);
                    }
                }

                let ssh_version = b"SSH-2.0-Eggsec_0.1\r\n";
                if let Err(e) = stream.write_all(ssh_version) {
                    result.set("success", false)?;
                    result.set("status", "error")?;
                    result.set("error", format!("version exchange failed: {}", e))?;
                    return Ok(result);
                }

                let mut kex_init = vec![0u8; 1024];
                match stream.read(&mut kex_init) {
                    Ok(n) if n > 0 => {}
                    _ => {
                        result.set("success", false)?;
                        result.set("status", "error")?;
                        result.set("error", "kex init failed")?;
                        return Ok(result);
                    }
                }

                let service_request = vec![
                    0x00, 0x00, 0x00, 0x0c, 0x14, 0x00, 0x00, 0x00, 0x07, b'u', b's', b'e', b'r',
                    b'a', b'u', b't', b'h',
                ];

                if let Err(e) = stream.write_all(&service_request) {
                    result.set("success", false)?;
                    result.set("status", "error")?;
                    result.set("error", format!("service request failed: {}", e))?;
                    return Ok(result);
                }

                let mut service_accept = vec![0u8; 64];
                match stream.read(&mut service_accept) {
                    Ok(n) if n >= 5 => {}
                    _ => {
                        result.set("success", false)?;
                        result.set("status", "error")?;
                        result.set("error", "service accept failed")?;
                        return Ok(result);
                    }
                }

                let user_len = username.len() as u32;
                let pass_len = password.len() as u32;
                let _auth_request_len = 1 + user_len + 1 + pass_len + 50;

                let mut auth_request = vec![0u8; 4];
                auth_request
                    .extend_from_slice(&[0x00, 0x00, 0x00, 0x34, 0x32, 0x00, 0x00, 0x00, 0x00]);

                auth_request.push(user_len as u8);
                auth_request.extend_from_slice(username.as_bytes());
                auth_request.push(0x00);

                auth_request.extend_from_slice(&[0x00, 0x00, 0x00, 0x0e]);
                auth_request.extend_from_slice(b"password");
                auth_request.push(0x00);

                auth_request.extend_from_slice(&[0x00]);
                auth_request.extend(pass_len.to_be_bytes());
                auth_request.extend_from_slice(password.as_bytes());

                if let Err(e) = stream.write_all(&auth_request) {
                    result.set("success", false)?;
                    result.set("status", "error")?;
                    result.set("error", format!("auth request failed: {}", e))?;
                    return Ok(result);
                }

                let mut auth_response = vec![0u8; 64];
                match stream.read(&mut auth_response) {
                    Ok(n) if n >= 5 => {
                        if auth_response[4] == 0x00 || auth_response[4] == 0x01 {
                            result.set("success", true)?;
                            result.set("status", "ok")?;
                        } else {
                            result.set("success", false)?;
                            result.set("status", "fail")?;
                        }
                    }
                    _ => {
                        result.set("success", false)?;
                        result.set("status", "error")?;
                        result.set("error", "auth response failed")?;
                    }
                }

                Ok(result)
            },
        )?,
    )?;

    brute.set(
        "account_exists",
        lua.create_function(|_lua, (username, password): (String, String)| {
            if let Ok(store) = ACCOUNT_STORE.lock() {
                for (u, p, _) in store.iter() {
                    if u == &username && p == &password {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        })?,
    )?;

    brute.set(
        "add_account",
        lua.create_function(|_lua, (username, password): (String, String)| {
            if let Ok(mut store) = ACCOUNT_STORE.lock() {
                store.push((username, password, true));
            }
            Ok(true)
        })?,
    )?;

    brute.set(
        "get_username",
        lua.create_function(|_lua, (creds, index): (Table, usize)| {
            let username: String = creds.get(index).unwrap_or_default();
            Ok(username)
        })?,
    )?;

    brute.set(
        "get_password",
        lua.create_function(|_lua, (creds, index): (Table, usize)| {
            let password: String = creds.get(index).unwrap_or_default();
            Ok(password)
        })?,
    )?;

    brute.set(
        "max_workers",
        lua.create_function(|_lua, workers: Option<i32>| Ok(workers.unwrap_or(32)))?,
    )?;

    brute.set("pause", lua.create_function(|_lua, _: ()| Ok(()))?)?;

    brute.set("resume", lua.create_function(|_lua, _: ()| Ok(()))?)?;

    brute.set("thread_num", lua.create_function(|_lua, _: ()| Ok(1))?)?;

    brute.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("brute", brute)?;
    Ok(())
}

fn get_default_usernames() -> Vec<String> {
    vec![
        "root".to_string(),
        "admin".to_string(),
        "user".to_string(),
        "test".to_string(),
        "guest".to_string(),
        "administrator".to_string(),
        "oracle".to_string(),
        "postgres".to_string(),
        "mysql".to_string(),
        "ftpuser".to_string(),
    ]
}

fn get_default_passwords() -> Vec<String> {
    vec![
        "password".to_string(),
        "123456".to_string(),
        "12345678".to_string(),
        "123456789".to_string(),
        "qwerty".to_string(),
        "abc123".to_string(),
        "monkey".to_string(),
        "1234567".to_string(),
        "letmein".to_string(),
        "trustno1".to_string(),
    ]
}

fn build_smb_negotiate() -> Vec<u8> {
    let mut request = vec![
        0x00, 0x00, 0x00, 0x4c, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    ];
    request.extend(vec![0u8; 24]);
    request.extend_from_slice(b"NT LM 0.12\0");
    request
}

fn build_smb_session_setup(username: &str, password: &str, domain: &str) -> Vec<u8> {
    let mut request = vec![0u8; 32 + 512];
    request[0] = 0x00;
    request[1] = 0x00;
    let len = 32 + 3 + username.len() + 1 + password.len() + 1 + domain.len() + 1;
    request[2] = (len & 0xff) as u8;
    request[3] = ((len >> 8) & 0xff) as u8;
    request[4] = 0xff;
    request[5] = 0x53;
    request[6] = 0x4d;
    request[7] = 0x42;
    request[8] = 0x73;
    request[9] = 0x00;
    request[28] = 0x0e;

    let mut offset = 32;

    request[offset] = 0x11;
    request[offset + 1] = 0x00;
    offset += 2;

    request[offset] = 0x00;
    request[offset + 1] = 0x00;
    offset += 2;

    let os_len = b"Unix".len();
    request[offset] = os_len as u8;
    request[offset + 1] = 0x00;
    offset += 2;

    request[offset..offset + 4].copy_from_slice(b"Unix");
    offset += 4;

    let lm_len = b"Ubuntu".len();
    request[offset] = lm_len as u8;
    request[offset + 1] = 0x00;
    offset += 2;

    request[offset..offset + 6].copy_from_slice(b"Ubuntu");
    offset += 6;

    let domain_len = domain.len() + 1;
    request[offset] = domain_len as u8;
    request[offset + 1] = 0x00;
    offset += 2;

    request[offset..offset + domain.len()].copy_from_slice(domain.as_bytes());
    offset += domain.len();
    request[offset] = 0x00;
    offset += 1;

    let user_len = username.len() + 1;
    request[offset] = user_len as u8;
    request[offset + 1] = 0x00;
    offset += 2;

    request[offset..offset + username.len()].copy_from_slice(username.as_bytes());
    offset += username.len();
    request[offset] = 0x00;
    offset += 1;

    let pass_len = password.len();
    if pass_len > 0 {
        request[offset] = pass_len as u8;
        request[offset + 1] = 0x00;
        offset += 2;

        request[offset..offset + pass_len].copy_from_slice(password.as_bytes());
        offset += pass_len;
    } else {
        request[offset] = 0x01;
        request[offset + 1] = 0x00;
        offset += 2;
        request[offset] = 0x00;
        offset += 1;
    }

    request.truncate(offset);
    request
}

fn extract_mysql_salt(handshake: &[u8], idx: usize) -> Vec<u8> {
    let mut offset = 0;
    for _i in 0..idx {
        if offset >= handshake.len() {
            return vec![];
        }
        if handshake[offset] == 0x00 {
            offset += 1;
            continue;
        }
        let len = handshake[offset] as usize;
        offset += 1;
        offset += len;
    }

    if offset >= handshake.len() || handshake[offset] == 0x00 {
        return vec![];
    }
    let len = handshake[offset] as usize;
    offset += 1;
    if offset + len <= handshake.len() {
        handshake[offset..offset + len].to_vec()
    } else {
        vec![]
    }
}

fn build_mysql_handshake_response(
    username: &str,
    password: &str,
    salt_1: &[u8],
    salt_2: &[u8],
) -> Vec<u8> {
    let mut response = vec![0u8; 512];

    response[0] = 0x01;

    let mut offset = 1;

    if password.is_empty() {
        response[offset] = 0x00;
        offset += 1;
    } else {
        let mut salt = salt_1.to_vec();
        salt.extend_from_slice(salt_2);

        let password_hash = mysql_password_hash(password, &salt);

        response[offset] = password_hash.len() as u8;
        offset += 1;
        response[offset..offset + password_hash.len()].copy_from_slice(&password_hash);
        offset += password_hash.len();
    }

    response[offset] = 0x00;
    offset += 1;

    let user_bytes = username.as_bytes();
    response[offset..offset + user_bytes.len()].copy_from_slice(user_bytes);
    offset += user_bytes.len();
    response[offset] = 0x00;
    offset += 1;

    response[4] = 0x00;
    response[5] = 0x00;
    response[6] = 0x00;
    response[7] = 0x00;

    let _total_len = offset;
    response
}

fn mysql_password_hash(password: &str, salt: &[u8]) -> Vec<u8> {
    use sha1::{Digest, Sha1};

    let password_bytes = password.as_bytes();

    let mut hash1 = Sha1::new();
    hash1.update(password_bytes);
    let hash1_result: [u8; 20] = hash1.finalize().into();

    let mut hash2 = Sha1::new();
    hash2.update(hash1_result);
    let hash2_result: [u8; 20] = hash2.finalize().into();

    let mut combined = Vec::with_capacity(salt.len() + 20);
    combined.extend_from_slice(salt);
    combined.extend_from_slice(&hash2_result);

    let mut hash3 = Sha1::new();
    hash3.update(&combined);
    let hash3_result: [u8; 20] = hash3.finalize().into();

    let mut result = [0u8; 20];
    for i in 0..20 {
        result[i] = hash1_result[i] ^ hash3_result[i];
    }

    result.to_vec()
}

fn build_postgres_startup(username: &str) -> Vec<u8> {
    let mut startup = Vec::new();

    // Protocol version 3.0 (placeholder for length)
    startup.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // Version 3.0
    startup.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);

    // user key
    startup.extend_from_slice(b"user");
    startup.push(0x00);
    // user value
    startup.extend_from_slice(username.as_bytes());
    startup.push(0x00);

    // terminator
    startup.push(0x00);

    let len = startup.len() as u32;
    startup[0] = ((len >> 24) & 0xff) as u8;
    startup[1] = ((len >> 16) & 0xff) as u8;
    startup[2] = ((len >> 8) & 0xff) as u8;
    startup[3] = (len & 0xff) as u8;

    startup
}

fn build_postgres_md5_response(username: &str, password: &str, salt: &[u8]) -> Vec<u8> {
    use md5::{Digest, Md5};

    let step1_input = format!("{}{}", password, username);
    let mut hash1 = Md5::new();
    hash1.update(step1_input.as_bytes());
    let hash1_hex = format!("md5{:032x}", hash1.finalize());

    let mut hash2 = Md5::new();
    hash2.update(hash1_hex.as_bytes());
    hash2.update(salt);
    let md5_str = format!("md5{:032x}", hash2.finalize());

    let mut response = vec![b'p', b'w', b'd'];
    response.extend_from_slice(md5_str.as_bytes());
    response.push(0x00);

    let len = (response.len() + 4) as u32;
    let mut packet = vec![0u8; 4];
    packet[0] = ((len >> 24) & 0xff) as u8;
    packet[1] = ((len >> 16) & 0xff) as u8;
    packet[2] = ((len >> 8) & 0xff) as u8;
    packet[3] = (len & 0xff) as u8;
    packet.extend(response);

    packet
}
