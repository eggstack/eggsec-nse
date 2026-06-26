//! NSE tns library wrapper
//!
//! Oracle TNS (Transparent Network Substrate) protocol implementation.
//! Based on Nmap's tns library concepts.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as AsyncTcpStream;

const TNS_PORT: u16 = 1521;

fn build_tns_connect(service_name: &str, _user: &str, _password: &str) -> Vec<u8> {
    let mut packet = Vec::new();

    packet.extend_from_slice(&0x01u8.to_be_bytes());
    packet.extend_from_slice(&0x00u8.to_be_bytes());

    let data = format!(
        "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME={})(SERVER=DEDICATED)(CID=(PROGRAM=)(HOST=)(USER=nmap)))(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521)))",
        service_name
    );

    let data_len = data.len() + 10;
    packet.extend_from_slice(&(data_len as u16).to_be_bytes());
    packet.extend_from_slice(&0x00u16.to_be_bytes());

    packet.extend_from_slice(data.as_bytes());

    packet
}

fn build_tns_command(command: &str) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&0x06u8.to_be_bytes());
    packet.extend_from_slice(&0x00u8.to_be_bytes());
    let len = command.len() + 10;
    packet.extend_from_slice(&(len as u16).to_be_bytes());
    packet.extend_from_slice(&0x00u16.to_be_bytes());
    packet.extend_from_slice(command.as_bytes());
    packet
}

pub fn register_tns_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let tns = lua.create_table()?;

    let new_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let t = lua.create_table()?;
        t.set("host", host)?;
        t.set("port", port)?;
        t.set("timeout", 5i64)?;
        Ok(t)
    })?;
    tns.set("new", new_fn)?;

    let connect_fn = lua.create_function(
        |lua, (host, port, service): (String, u16, Option<String>)| {
            let result = lua.create_table()?;

            let service_name = service.unwrap_or_else(|| "ORCL".to_string());
            let addr = format!("{}:{}", host, port);

            match TcpStream::connect_timeout(
                &addr
                    .parse()
                    .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 1521))),
                Duration::from_secs(5),
            ) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

                    let connect_packet = build_tns_connect(&service_name, "", "");

                    if let Err(e) = stream.write_all(&connect_packet) {
                        result.set("success", false)?;
                        result.set("error", format!("Send failed: {}", e))?;
                        return Ok(result);
                    }

                    let mut response = [0u8; 1024];
                    match stream.read(&mut response) {
                        Ok(n) => {
                            if n > 0 {
                                result.set("success", true)?;
                                result.set("service", service_name.clone())?;
                                result.set("host", host)?;
                                result.set("port", port)?;

                                let banner = format!("Oracle Database {} TNS", service_name);
                                result.set("banner", banner)?;
                            } else {
                                result.set("success", false)?;
                                result.set("error", "Empty response")?;
                            }
                        }
                        Err(e) => {
                            result.set("success", true)?;
                            result.set("note", "Connection established but no response")?;
                            result.set("error", format!("Read failed: {}", e))?;
                        }
                    }
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
            }

            Ok(result)
        },
    )?;
    tns.set("connect", connect_fn)?;

    let login_fn = lua.create_function(
        |lua, (host, port, service, user, password): (String, u16, String, String, String)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);

            match TcpStream::connect_timeout(
                &addr
                    .parse()
                    .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 1521))),
                Duration::from_secs(5),
            ) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

                    let connect_packet = build_tns_connect(&service, &user, &password);

                    if let Err(e) = stream.write_all(&connect_packet) {
                        result.set("success", false)?;
                        result.set("error", format!("Send failed: {}", e))?;
                        return Ok(result);
                    }

                    let mut response = [0u8; 1024];
                    if let Ok(n) = stream.read(&mut response) {
                        if n > 0 {
                            result.set("success", true)?;
                            result.set("user", user)?;
                            result.set("service", service)?;
                        }
                    } else {
                        result.set("success", true)?;
                        result.set("note", "Login packet sent")?;
                    }
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
            }

            Ok(result)
        },
    )?;
    tns.set("login", login_fn)?;

    let execute_fn = lua.create_function(
        |lua, (host, port, service, sql): (String, u16, String, String)| {
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);

            match TcpStream::connect_timeout(
                &addr
                    .parse()
                    .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 1521))),
                Duration::from_secs(5),
            ) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

                    if stream.write_all(&build_tns_connect(&service, "", "")).is_err() {
                        tracing::warn!("Failed to send TNS connect packet");
                    }

                    let cmd_packet = build_tns_command(&sql);

                    if let Err(e) = stream.write_all(&cmd_packet) {
                        result.set("success", false)?;
                        result.set("error", format!("Send failed: {}", e))?;
                        return Ok(result);
                    }

                    let mut response = [0u8; 4096];
                    match stream.read(&mut response) {
                        Ok(n) => {
                            result.set("success", true)?;
                            result.set("rows_affected", 0)?;
                            result.set("sql", sql)?;

                            let output = String::from_utf8_lossy(&response[..n]).to_string();
                            result.set("output", output)?;
                        }
                        Err(e) => {
                            result.set("success", false)?;
                            result.set("error", format!("Read failed: {}", e))?;
                        }
                    }
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
            }

            Ok(result)
        },
    )?;
    tns.set("execute", execute_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    tns.set("version", version_fn)?;

    let async_connect_fn = lua.create_function(
        |lua, (host, port, service): (String, u16, Option<String>)| {
            let runtime = tokio::runtime::Handle::current();
            let host_clone = host.clone();
            let service_name = service.unwrap_or_else(|| "ORCL".to_string());
            let port = if port == 0 { TNS_PORT } else { port };

            runtime.block_on(async {
                let result = lua.create_table()?;

                match AsyncTcpStream::connect(format!("{}:{}", host_clone, port)).await {
                    Ok(mut stream) => {
                        let connect_packet = build_tns_connect(&service_name, "", "");

                        if let Err(e) = stream.write_all(&connect_packet).await {
                            result.set("success", false)?;
                            result.set("error", format!("Send failed: {}", e))?;
                            return Ok(result);
                        }

                        let mut response = [0u8; 1024];
                        match stream.read(&mut response).await {
                            Ok(n) => {
                                if n > 0 {
                                    result.set("success", true)?;
                                    result.set("service", service_name.clone())?;
                                    result.set("host", host_clone)?;
                                    result.set("port", port)?;

                                    let banner = format!("Oracle Database {} TNS", service_name);
                                    result.set("banner", banner)?;
                                } else {
                                    result.set("success", false)?;
                                    result.set("error", "Empty response")?;
                                }
                            }
                            Err(e) => {
                                result.set("success", true)?;
                                result.set("note", "Connection established but no response")?;
                                result.set("error", format!("Read failed: {}", e))?;
                            }
                        }
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
    tns.set("connect_async", async_connect_fn)?;

    let async_execute_fn = lua.create_function(
        |lua, (host, port, service, sql): (String, u16, String, String)| {
            let runtime = tokio::runtime::Handle::current();
            let host_clone = host.clone();
            let port = if port == 0 { TNS_PORT } else { port };

            runtime.block_on(async {
                let result = lua.create_table()?;

                match AsyncTcpStream::connect(format!("{}:{}", host_clone, port)).await {
                    Ok(mut stream) => {
                        if stream.write_all(&build_tns_connect(&service, "", "")).await.is_err() {
                            tracing::warn!("Failed to send TNS connect packet");
                        }

                        let cmd_packet = build_tns_command(&sql);

                        if let Err(e) = stream.write_all(&cmd_packet).await {
                            result.set("success", false)?;
                            result.set("error", format!("Send failed: {}", e))?;
                            return Ok(result);
                        }

                        let mut response = [0u8; 4096];
                        match stream.read(&mut response).await {
                            Ok(n) => {
                                result.set("success", true)?;
                                result.set("rows_affected", 0)?;
                                result.set("sql", sql)?;

                                let output = String::from_utf8_lossy(&response[..n]).to_string();
                                result.set("output", output)?;
                            }
                            Err(e) => {
                                result.set("success", false)?;
                                result.set("error", format!("Read failed: {}", e))?;
                            }
                        }
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
    tns.set("execute_async", async_execute_fn)?;

    globals.set("tns", tns)?;
    Ok(())
}
