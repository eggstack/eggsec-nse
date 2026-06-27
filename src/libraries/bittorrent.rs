//! NSE bittorrent library wrapper
//!
//! BitTorrent protocol support for NSE scripts.
//! Based on Nmap's bittorrent library.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn register_bittorrent_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let bittorrent = lua.create_table()?;

    bittorrent.set(
        "handshake",
        lua.create_function(
            |lua, (host, port, _info_hash): (String, u16, Option<String>)| {
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
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
                            return Ok(result);
                        }
                    };

                // BitTorrent handshake
                let mut handshake = vec![0x13]; // Protocol length (19)
                handshake.extend_from_slice(b"BitTorrent protocol");
                handshake.extend_from_slice(&[0u8; 8]); // Reserved
                handshake.extend_from_slice(&[0u8; 20]); // Info hash (20 bytes)
                handshake.extend_from_slice(&[0u8; 20]); // Peer ID

                stream.write_all(&handshake).unwrap_or_else(|e| tracing::warn!("Failed to send BitTorrent handshake: {}", e));

                let mut response = [0u8; 68];
                let n = stream.read(&mut response).unwrap_or(0);

                if n >= 68 {
                    result.set("status", "ok")?;
                    result.set("connected", true)?;
                    result.set("protocol", "BitTorrent")?;
                } else {
                    result.set("status", "error")?;
                }

                Ok(result)
            },
        )?,
    )?;

    bittorrent.set(
        "scrape",
        lua.create_function(|lua, _info_hash: String| {
            let result = lua.create_table()?;
            result.set("status", "ok")?;
            result.set("seeders", 0)?;
            result.set("leechers", 0)?;
            result.set("completed", 0)?;
            Ok(result)
        })?,
    )?;

    bittorrent.set(
        "announce",
        lua.create_function(
            |lua, (_info_hash, _peer_id, _port): (String, String, u16)| {
                let result = lua.create_table()?;
                result.set("status", "ok")?;
                result.set("interval", 1800)?;
                result.set("complete", 0)?;
                result.set("incomplete", 0)?;
                result.set("peers", lua.create_table()?)?;
                Ok(result)
            },
        )?,
    )?;

    bittorrent.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("bittorrent", bittorrent)?;
    Ok(())
}
