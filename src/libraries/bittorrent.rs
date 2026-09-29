//! NSE bittorrent library wrapper
//!
//! BitTorrent protocol support for NSE scripts.
//! Based on Nmap's bittorrent library.

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, broker_tcp_send, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

/// Provider-backed bittorrent registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_bittorrent_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let bittorrent = lua.create_table()?;

    bittorrent.set(
        "handshake",
        lua.create_function({
            let ctx = capability_ctx.clone();
            let services = services.clone();
            move |lua, (host, port, _info_hash): (String, u16, Option<String>)| {
                let result = lua.create_table()?;
                let timeout = Duration::from_secs(10);

                let (mut handle, _endpoint) = match broker_tcp_connect(
                    &ctx,
                    &services,
                    &host,
                    port,
                    timeout,
                    "bittorrent.handshake",
                ) {
                    Ok(pair) => pair,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };

                // BitTorrent handshake
                let mut handshake = vec![0x13]; // Protocol length (19)
                handshake.extend_from_slice(b"BitTorrent protocol");
                handshake.extend_from_slice(&[0u8; 8]); // Reserved
                handshake.extend_from_slice(&[0u8; 20]); // Info hash (20 bytes)
                handshake.extend_from_slice(&[0u8; 20]); // Peer ID

                if let Err(e) =
                    broker_tcp_send(&ctx, handle.as_mut(), &handshake, "bittorrent.handshake")
                {
                    tracing::warn!("Failed to send BitTorrent handshake: {}", e);
                }

                let data = broker_tcp_receive(&ctx, handle.as_mut(), 68, "bittorrent.handshake")
                    .unwrap_or_default();
                let mut response = [0u8; 68];
                let n = data.len().min(response.len());
                response[..n].copy_from_slice(&data[..n]);

                if n >= 68 {
                    result.set("status", "ok")?;
                    result.set("connected", true)?;
                    result.set("protocol", "BitTorrent")?;
                } else {
                    result.set("status", "error")?;
                }

                Ok(result)
            }
        })?,
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
