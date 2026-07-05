//! NSE comm library wrapper
//!
//! Provides low-level socket communication for banner grabbing and data exchange.

use crate::capabilities::NseCapabilityContext;
use crate::wrappers;
use mlua::{Lua, Result as LuaResult, Table};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as AsyncTcpStream;
use tokio::time::timeout;

pub fn register_comm_library(lua: &Lua, capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    let globals = lua.globals();

    let capability_ctx = capability_ctx.clone();

    let comm = lua.create_table()?;

    comm.set(
        "get_banner",
        lua.create_function({
            let capability_ctx = capability_ctx.clone();
            move |lua, (host, port, _options): (String, u16, Option<Table>)| {
                let decision =
                    wrappers::check_network_tcp(&capability_ctx, &host, "comm.get_banner");
                if decision.is_denied() {
                    let result = lua.create_table()?;
                    result.set("data", "")?;
                    return Ok(result);
                }

                let timeout = Duration::from_secs(5);
                let addr = format!("{}:{}", host, port);

                match addr.parse() {
                    Ok(socket_addr) => match TcpStream::connect_timeout(&socket_addr, timeout) {
                        Ok(mut stream) => {
                            if stream.set_read_timeout(Some(timeout)).is_err() {
                                tracing::warn!("Failed to set read timeout on comm stream");
                            }

                            std::thread::sleep(Duration::from_millis(500));

                            let mut buf = vec![0u8; 4096];
                            match stream.read(&mut buf) {
                                Ok(n) => {
                                    let data = String::from_utf8_lossy(&buf[..n]).to_string();
                                    let result = lua.create_table()?;
                                    result.set("data", data)?;
                                    Ok(result)
                                }
                                Err(_) => {
                                    let result = lua.create_table()?;
                                    result.set("data", "")?;
                                    Ok(result)
                                }
                            }
                        }
                        Err(_) => {
                            let result = lua.create_table()?;
                            result.set("data", "")?;
                            Ok(result)
                        }
                    },
                    Err(_) => {
                        let result = lua.create_table()?;
                        result.set("data", "")?;
                        Ok(result)
                    }
                }
            }
        })?,
    )?;

    comm.set(
        "exchange",
        lua.create_function({
            let capability_ctx = capability_ctx.clone();
            move |lua, (host, port, data, _options): (String, u16, String, Option<Table>)| {
                let decision = wrappers::check_network_tcp(&capability_ctx, &host, "comm.exchange");
                if decision.is_denied() {
                    let result = lua.create_table()?;
                    result.set("data", "")?;
                    return Ok(result);
                }

                let timeout = Duration::from_secs(5);
                let addr = format!("{}:{}", host, port);

                match addr.parse() {
                    Ok(socket_addr) => match TcpStream::connect_timeout(&socket_addr, timeout) {
                        Ok(mut stream) => {
                            if stream.set_read_timeout(Some(timeout)).is_err() {
                                tracing::warn!("Failed to set read timeout on comm stream");
                            }
                            if stream.set_write_timeout(Some(timeout)).is_err() {
                                tracing::warn!("Failed to set write timeout on comm stream");
                            }

                            if stream.write_all(data.as_bytes()).is_err() {
                                let result = lua.create_table()?;
                                result.set("data", "")?;
                                return Ok(result);
                            }

                            std::thread::sleep(Duration::from_millis(500));

                            let mut buf = vec![0u8; 4096];
                            match stream.read(&mut buf) {
                                Ok(n) => {
                                    let response = String::from_utf8_lossy(&buf[..n]).to_string();
                                    let result = lua.create_table()?;
                                    result.set("data", response)?;
                                    Ok(result)
                                }
                                Err(_) => {
                                    let result = lua.create_table()?;
                                    result.set("data", "")?;
                                    Ok(result)
                                }
                            }
                        }
                        Err(_) => {
                            let result = lua.create_table()?;
                            result.set("data", "")?;
                            Ok(result)
                        }
                    },
                    Err(_) => {
                        let result = lua.create_table()?;
                        result.set("data", "")?;
                        Ok(result)
                    }
                }
            }
        })?,
    )?;

    comm.set(
        "tryssl",
        lua.create_function({
            let capability_ctx = capability_ctx.clone();
            move |lua, (host, port, _data, _options): (String, u16, String, Option<Table>)| {
                let decision = wrappers::check_dns(&capability_ctx, &host, "comm.tryssl");
                if decision.is_denied() {
                    let result = lua.create_table()?;
                    result.set("status", 0i32)?;
                    result.set("data", "DNS resolution denied by capability policy")?;
                    return Ok(result);
                }

                let url = format!("https://{}:{}", host, port);

                let client = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .danger_accept_invalid_certs(true)
                    .build();

                match client {
                    Ok(c) => match c.get(&url).send() {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let body = resp.text().unwrap_or_default();

                            let result = lua.create_table()?;
                            result.set("status", status as i32)?;
                            result.set("data", body)?;
                            Ok(result)
                        }
                        Err(e) => {
                            let result = lua.create_table()?;
                            result.set("status", 0i32)?;
                            result.set("data", e.to_string())?;
                            Ok(result)
                        }
                    },
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("status", 0i32)?;
                        result.set("data", e.to_string())?;
                        Ok(result)
                    }
                }
            }
        })?,
    )?;

    comm.set("close", lua.create_function(|_, _socket: Table| Ok(()))?)?;

    comm.set(
        "get_banner_async",
        lua.create_function({
            let capability_ctx = capability_ctx.clone();
            move |lua, (host, port, _options): (String, u16, Option<Table>)| {
                let decision =
                    wrappers::check_network_tcp(&capability_ctx, &host, "comm.get_banner_async");
                if decision.is_denied() {
                    let result = lua.create_table()?;
                    result.set("data", "")?;
                    return Ok(result);
                }

                let runtime = tokio::runtime::Handle::current();
                let host_clone = host.clone();

                runtime.block_on(async {
                    let result = lua.create_table()?;
                    let connect_result = timeout(
                        Duration::from_secs(5),
                        AsyncTcpStream::connect(format!("{}:{}", host_clone, port)),
                    )
                    .await;

                    match connect_result {
                        Ok(Ok(mut stream)) => {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            let mut buf = vec![0u8; 4096];
                            match stream.read(&mut buf).await {
                                Ok(n) => {
                                    let data = String::from_utf8_lossy(&buf[..n]).to_string();
                                    result.set("data", data)?;
                                }
                                Err(_) => {
                                    result.set("data", "")?;
                                }
                            }
                        }
                        Ok(Err(_)) => {
                            result.set("data", "")?;
                        }
                        Err(_) => {
                            result.set("data", "")?;
                        }
                    }
                    Ok(result)
                })
            }
        })?,
    )?;

    comm.set(
        "exchange_async",
        lua.create_function({
            let capability_ctx = capability_ctx.clone();
            move |lua, (host, port, data, _options): (String, u16, String, Option<Table>)| {
                let decision =
                    wrappers::check_network_tcp(&capability_ctx, &host, "comm.exchange_async");
                if decision.is_denied() {
                    let result = lua.create_table()?;
                    result.set("data", "")?;
                    return Ok(result);
                }

                let runtime = tokio::runtime::Handle::current();
                let host_clone = host.clone();

                runtime.block_on(async {
                    let result = lua.create_table()?;
                    let connect_result = timeout(
                        Duration::from_secs(5),
                        AsyncTcpStream::connect(format!("{}:{}", host_clone, port)),
                    )
                    .await;

                    match connect_result {
                        Ok(Ok(mut stream)) => {
                            if stream.write_all(data.as_bytes()).await.is_err() {
                                result.set("data", "")?;
                                return Ok(result);
                            }

                            tokio::time::sleep(Duration::from_millis(500)).await;

                            let mut buf = vec![0u8; 4096];
                            match stream.read(&mut buf).await {
                                Ok(n) => {
                                    let response = String::from_utf8_lossy(&buf[..n]).to_string();
                                    result.set("data", response)?;
                                }
                                Err(_) => {
                                    result.set("data", "")?;
                                }
                            }
                        }
                        Ok(Err(_)) => {
                            result.set("data", "")?;
                        }
                        Err(_) => {
                            result.set("data", "")?;
                        }
                    }
                    Ok(result)
                })
            }
        })?,
    )?;

    globals.set("comm", comm)?;
    Ok(())
}
