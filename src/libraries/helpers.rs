//! Common helper utilities for NSE libraries
//!
//! Provides reusable abstractions to reduce code duplication across NSE protocol libraries.

#[cfg(all(feature = "nse", doctest))]
mod withdrawn_api_guards {
    //! Compiler-enforced absence of the API withdrawn in 0.3.0.
    //!
    //! `tls_connect` and `tcp_connect_with_timeout` were `pub` on 0.1.0 and
    //! 0.2.0 and returned a raw `std::net::TcpStream` from an unmediated
    //! `connect_timeout`, so a consumer calling them bypassed the runtime's
    //! capability decision, cancellation, accounting, and provider-selection
    //! boundary (ADR-0004 §8). They are permanently withdrawn, with no
    //! replacement and no deprecated alias: connection work goes through
    //! `broker_tcp_connect` / `broker_dns_lookup`.
    //!
    //! `make_addr` and `parse_socket_addr` went with them; both are pure and
    //! trivially inlinable, and no crate-internal caller remains.
    //!
    //! These are `compile_fail` doctests, so they are checked by the compiler
    //! over the *whole* crate rather than by a text scan. That matters: the
    //! `nse_production_code()` view in `scripts/check-boundaries.sh` truncates
    //! each file at its first `mod tests` marker, and this file carries
    //! production items below its test module, so a name restored there would
    //! be invisible to any prefix-based scan. The text-level backstop for the
    //! rest of the specialized zone is the untruncated sweep in that script.
    //!
    //! The first block is a control: it proves `libraries::helpers` itself
    //! resolves, so the `compile_fail` blocks below cannot pass merely because
    //! the crate failed to build for an unrelated reason.
    //!
    //! ```no_run
    //! use eggsec_nse::libraries::helpers;
    //! assert!(helpers::parse_hex_pairs("41") == vec![0x41]);
    //! ```
    //!
    //! ```compile_fail
    //! use eggsec_nse::libraries::helpers::tls_connect;
    //! ```
    //!
    //! ```compile_fail
    //! use eggsec_nse::libraries::helpers::tcp_connect_with_timeout;
    //! ```
    //!
    //! ```compile_fail
    //! use eggsec_nse::libraries::helpers::make_addr;
    //! ```
    //!
    //! ```compile_fail
    //! use eggsec_nse::libraries::helpers::parse_socket_addr;
    //! ```
}

use mlua::{Lua, Result as LuaResult, Table};
use native_tls::TlsConnector;
use std::time::Duration;

pub use mlua::Table as LuaTable;

pub fn fallback_lua_table(lua: &Lua) -> LuaResult<Table> {
    lua.create_table().map_err(|e| {
        tracing::warn!("failed to create fallback Lua table: {}", e);
        e
    })
}

/// Resolve `result` or, on lookup failure, create a fallback table.
///
/// Propagates Lua OOM as `Err` instead of panicking.
pub fn or_fallback_table<E>(result: Result<Table, E>, lua: &Lua) -> LuaResult<Table> {
    match result {
        Ok(table) => Ok(table),
        Err(_) => fallback_lua_table(lua),
    }
}

pub fn parse_hex_pairs(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .filter_map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Some((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

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

// M007B: the dead direct-connect helpers (`tls_connect`,
// `tcp_connect_with_timeout` and their `make_addr`/`parse_socket_addr`
// plumbing) were removed. They had zero production callers and kept this
// file in the direct-socket residual pin; provider-backed callers use the
// broker fns (or `BrokeredTcpStream` where `Read`/`Write` is required).
// Removal is recorded for the M007C compatibility gate.

#[inline]
pub fn parse_response_code(response: &str, expected: &[&str]) -> bool {
    expected.iter().any(|code| response.starts_with(code))
}

pub fn create_http_client(
    timeout_secs: u64,
    accept_invalid_certs: bool,
    accept_invalid_hostnames: bool,
) -> reqwest::blocking::Client {
    crate::install_tls_provider();
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
    crate::install_tls_provider();
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

#[cfg(test)]
mod tests {
    use super::parse_hex_pairs;

    #[test]
    fn parse_hex_pairs_decodes_valid_pairs() {
        assert_eq!(parse_hex_pairs("48656c6c6f"), b"Hello");
        assert_eq!(parse_hex_pairs("DEadBEEF"), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_hex_pairs_ignores_incomplete_and_invalid_pairs() {
        assert_eq!(parse_hex_pairs("4"), Vec::<u8>::new());
        assert_eq!(parse_hex_pairs("410"), vec![0x41]);
        assert_eq!(parse_hex_pairs("41zz42"), vec![0x41, 0x42]);
    }

    #[test]
    fn parse_hex_pairs_handles_non_ascii_without_panicking() {
        assert_eq!(parse_hex_pairs("41é42"), vec![0x41, 0x42]);
    }
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
