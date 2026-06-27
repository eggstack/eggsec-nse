//! Common helper utilities for NSE libraries
//!
//! Provides reusable abstractions to reduce code duplication across NSE protocol libraries.

use mlua::{Lua, Result as LuaResult, Table};
use native_tls::TlsConnector;
use native_tls::TlsStream;
use std::net::TcpStream;
use std::time::Duration;

pub use mlua::Table as LuaTable;

pub fn create_tls_connector(
    accept_invalid_certs: bool,
    accept_invalid_hostnames: bool,
) -> Result<TlsConnector, String> {
    TlsConnector::builder()
        .danger_accept_invalid_certs(accept_invalid_certs)
        .danger_accept_invalid_hostnames(accept_invalid_hostnames)
        .build()
        .map_err(|e| e.to_string())
}

pub fn tls_connect(
    host: &str,
    port: u16,
    accept_invalid_certs: bool,
    accept_invalid_hostnames: bool,
) -> Result<(TcpStream, TlsConnector), String> {
    let connector = create_tls_connector(accept_invalid_certs, accept_invalid_hostnames)?;
    let addr = make_addr(host, port);
    let socket_addr = parse_socket_addr(&addr)?;
    let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))
        .map_err(|e| e.to_string())?;
    Ok((stream, connector))
}

pub fn make_addr(host: &str, port: u16) -> String {
    format!("{}:{}", host, port)
}

pub fn tcp_connect_with_timeout(
    host: &str,
    port: u16,
    timeout_secs: u64,
) -> std::io::Result<TcpStream> {
    let addr = make_addr(host, port);
    let socket_addr = addr
        .parse::<std::net::SocketAddr>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;

    let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(timeout_secs))?;
    stream.set_read_timeout(Some(Duration::from_secs(timeout_secs)))?;
    stream.set_write_timeout(Some(Duration::from_secs(timeout_secs)))?;

    Ok(stream)
}

pub fn parse_socket_addr(addr: &str) -> Result<std::net::SocketAddr, String> {
    addr.parse::<std::net::SocketAddr>()
        .map_err(|e| e.to_string())
}

#[inline]
pub fn parse_response_code(response: &str, expected: &[&str]) -> bool {
    expected.iter().any(|code| response.starts_with(code))
}

pub fn create_http_client(
    timeout_secs: u64,
    accept_invalid_certs: bool,
    accept_invalid_hostnames: bool,
) -> reqwest::blocking::Client {
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(30));

    if accept_invalid_certs {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if accept_invalid_hostnames {
        builder = builder.danger_accept_invalid_hostnames(true);
    }

    builder
        .build()
        .unwrap_or_else(|_| reqwest::blocking::Client::new())
}

pub fn create_async_http_client(
    timeout_secs: u64,
    accept_invalid_certs: bool,
    accept_invalid_hostnames: bool,
) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(30));

    if accept_invalid_certs {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if accept_invalid_hostnames {
        builder = builder.danger_accept_invalid_hostnames(true);
    }

    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}

pub fn spawn_blocking<T, F>(f: F) -> tokio::task::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
}

pub fn error_result(lua: &Lua, error: impl Into<String>) -> LuaResult<Table> {
    let table = lua.create_table()?;
    table.set("success", false)?;
    table.set("error", error.into())?;
    Ok(table)
}

pub fn ok_result(lua: &Lua) -> LuaResult<Table> {
    let table = lua.create_table()?;
    table.set("success", true)?;
    Ok(table)
}

pub fn status_result(lua: &Lua, status: &str) -> LuaResult<Table> {
    let table = lua.create_table()?;
    table.set("status", status)?;
    Ok(table)
}

pub fn status_error_result(lua: &Lua, status: &str, error: impl Into<String>) -> LuaResult<Table> {
    let table = lua.create_table()?;
    table.set("status", status)?;
    table.set("error", error.into())?;
    Ok(table)
}

pub fn simple_connect_result(lua: &Lua, status: &str) -> LuaResult<Table> {
    let table = lua.create_table()?;
    table.set("status", status)?;
    Ok(table)
}

pub fn simple_error_result(lua: &Lua, error: impl Into<String>) -> LuaResult<Table> {
    let table = lua.create_table()?;
    table.set("error", error.into())?;
    Ok(table)
}

pub fn connection_error_result(
    lua: &Lua,
    host: &str,
    port: u16,
    error: impl Into<String>,
) -> LuaResult<Table> {
    let table = lua.create_table()?;
    table.set("host", host)?;
    table.set("port", port)?;
    table.set("status", "error")?;
    table.set("error", error.into())?;
    Ok(table)
}
