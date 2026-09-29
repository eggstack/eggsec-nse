//! NSE target library wrapper
//!
//! Utility functions for adding new discovered targets to Nmap scan queue.
//!
//! M007B corrective: `target.resolve` previously called
//! `std::net::ToSocketAddrs::to_socket_addrs` directly. That made the
//! library a direct host-network effect site (a DNS query leaving the
//! process) while the effect manifest classified it `Pure`, so the
//! name was exposed to `AgentSafe`/`CiSafe` with no capability check,
//! no cancellation, and no accounting.
//!
//! Resolution now goes through [`broker_dns_lookup`] (M005B), which
//! applies the `DnsResolution` capability gate, cancellation, and
//! resource accounting before the injected [`NseDnsProvider`] is
//! touched. The literal-IP fast path is unchanged and performs no
//! provider call.

use mlua::{Lua, Result as LuaResult};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_dns_lookup, NseDnsRecordType, NseHostServices};

static TARGET_QUEUE: std::sync::LazyLock<Arc<Mutex<Vec<String>>>> =
    std::sync::LazyLock::new(|| Arc::new(Mutex::new(Vec::new())));

/// Clear per-run library globals so back-to-back scans do not
/// leak state (handles, sessions, compiled patterns) between runs.
pub fn reset_for_run() {
    if let Ok(mut s) = TARGET_QUEUE.lock() {
        s.clear();
    }
}

/// Compatibility registration with native services and a manual-permissive
/// capability context.
///
/// Retained so the pre-M007B public signature keeps working for embedders
/// that only have a [`Lua`] handle. `ExecutorCore` uses
/// [`register_target_library_with_services`] so the runtime profile,
/// capability context, and injected providers apply.
pub fn register_target_library(lua: &Lua) -> LuaResult<()> {
    let profile = crate::profile::ResolvedNseExecutionProfile::manual_permissive(None);
    let ctx = NseCapabilityContext::from_profile(
        &profile,
        Arc::new(crate::limits::NseResourceCounters::new()),
    );
    register_target_library_with_services(lua, &ctx, &NseHostServices::native())
}

/// Provider-backed registration.
///
/// `services.dns()` backs `target.resolve`; the DNS capability gate,
/// cancellation, and accounting are applied by the broker. Every other
/// `target` entry is in-memory bookkeeping with no host effect.
pub fn register_target_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let target = lua.create_table()?;
    let cap_ctx = capability_ctx.clone();
    let svc = services.clone();

    target.set(
        "add",
        lua.create_function(|lua, host: String| {
            if let Ok(mut queue) = TARGET_QUEUE.lock() {
                if !queue.contains(&host) {
                    queue.push(host.clone());
                }
            }
            let result = lua.create_table()?;
            result.set("host", host)?;
            result.set("status", "added")?;
            Ok(result)
        })?,
    )?;

    target.set(
        "add_with_port",
        lua.create_function(|lua, (host, port): (String, u16)| {
            let host_port = format!("{}:{}", host, port);
            if let Ok(mut queue) = TARGET_QUEUE.lock() {
                if !queue.contains(&host_port) {
                    queue.push(host_port);
                }
            }
            let result = lua.create_table()?;
            result.set("host", host)?;
            result.set("port", port)?;
            result.set("status", "added")?;
            Ok(result)
        })?,
    )?;

    target.set(
        "exclude",
        lua.create_function(|_lua, host: String| {
            if let Ok(mut queue) = TARGET_QUEUE.lock() {
                queue.retain(|h| h != &host);
            }
            Ok(true)
        })?,
    )?;

    target.set(
        "get",
        lua.create_function(|lua, _: ()| {
            let result = lua.create_table()?;
            if let Ok(queue) = TARGET_QUEUE.lock() {
                for (i, host) in queue.iter().enumerate() {
                    result.set(i + 1, host.clone())?;
                }
            }
            Ok(result)
        })?,
    )?;

    target.set(
        "count",
        lua.create_function(|_lua, _: ()| match TARGET_QUEUE.lock() {
            Ok(queue) => Ok(queue.len() as i32),
            _ => Ok(0),
        })?,
    )?;

    target.set(
        "clear",
        lua.create_function(|_lua, _: ()| {
            if let Ok(mut queue) = TARGET_QUEUE.lock() {
                queue.clear();
            }
            Ok(true)
        })?,
    )?;

    target.set(
        "exists",
        lua.create_function(|_lua, host: String| match TARGET_QUEUE.lock() {
            Ok(queue) => Ok(queue.contains(&host)),
            _ => Ok(false),
        })?,
    )?;

    target.set(
        "resolve",
        lua.create_function(move |_lua, hostname: String| {
            if hostname.parse::<IpAddr>().is_ok() {
                return Ok(hostname);
            }

            for record in [NseDnsRecordType::A, NseDnsRecordType::Aaaa] {
                if let Ok(answer) =
                    broker_dns_lookup(&cap_ctx, &svc, &hostname, record, "target.resolve")
                {
                    if let Some(first) = answer.addresses().first() {
                        return Ok(first.to_string());
                    }
                }
            }

            Ok(hostname)
        })?,
    )?;

    target.set(
        "reverse",
        lua.create_function(|_lua, ip: String| {
            if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
                let octets = addr.octets();
                return Ok(format!(
                    "{}.{}.{}.{}.in-addr.arpa",
                    octets[3], octets[2], octets[1], octets[0]
                ));
            }
            Ok(String::new())
        })?,
    )?;

    globals.set("target", target)?;
    Ok(())
}

pub fn get_target_queue() -> Vec<String> {
    TARGET_QUEUE.lock().map(|q| q.clone()).unwrap_or_default()
}

pub fn clear_target_queue() {
    if let Ok(mut queue) = TARGET_QUEUE.lock() {
        queue.clear();
    }
}
