//! NSE dns library wrapper
//!
//! Provides DNS query functionality compatible with NSE scripts.
//!
//! M005B: all resolution goes through the injected [`NseDnsProvider`] via
//! the capability-aware [`broker_dns_lookup`] broker. The process-global
//! Hickory resolver is gone; the native provider owns one resolver per
//! instance. Literal-IP fast paths stay local (no provider call) and Lua
//! result shapes are unchanged.

use mlua::{Lua, Result as LuaResult};

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_dns_lookup, NseDnsRecordType, NseHostServices, NseIpAddress};

pub fn register_dns_library(lua: &Lua, capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    register_dns_library_with_services(lua, capability_ctx, &NseHostServices::native())
}

/// Provider-backed DNS registration.
///
/// `services.dns()` backs every `resolve`/`query`/`forward`/`ptr` call;
/// deterministic tests inject [`MapDnsProvider`](crate::providers::MapDnsProvider).
pub fn register_dns_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let dns = lua.create_table()?;
    let cap_ctx = capability_ctx.clone();
    let svc = services.clone();
    dns.set(
        "resolve",
        lua.create_function(
            move |lua, (hostname, query_type): (String, Option<String>)| {
                let qtype = query_type.unwrap_or_else(|| "A".to_string());

                if NseIpAddress::parse(&hostname).is_some() {
                    let result = lua.create_table()?;
                    result.set("type", qtype.as_str())?;
                    result.set("address", hostname.clone())?;
                    return Ok(result);
                }

                match broker_dns_lookup(
                    &cap_ctx,
                    &svc,
                    &hostname,
                    NseDnsRecordType::parse(&qtype),
                    "dns.resolve",
                ) {
                    Ok(answer) => {
                        let result = lua.create_table()?;
                        result.set("type", qtype.as_str())?;

                        let answers = lua.create_table()?;
                        for (i, display) in answer.displays().iter().enumerate() {
                            answers.set(i + 1, display.clone())?;
                        }
                        result.set("answers", answers)?;

                        if let Some(first) = answer.displays().first() {
                            result.set("address", first.clone())?;
                        }

                        Ok(result)
                    }
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("type", qtype.as_str())?;
                        if e.contains("denied") || e.contains("not allowed") {
                            result.set("error", format!("DNS resolution denied: {e}"))?;
                        } else {
                            result.set("error", format!("DNS lookup failed: {e}"))?;
                        }
                        Ok(result)
                    }
                }
            },
        )?,
    )?;

    dns.set(
        "reverse",
        lua.create_function(|lua, ip: String| {
            let result = lua.create_table()?;

            if let Some(addr) = NseIpAddress::parse(&ip) {
                result.set("name", addr.reverse_dns_name())?;
                result.set("status", "ok")?;
            } else {
                result.set("status", "error")?;
                result.set("error", "Invalid IP address")?;
            }

            Ok(result)
        })?,
    )?;

    let cap_ctx = capability_ctx.clone();
    let svc = services.clone();
    dns.set(
        "query",
        lua.create_function(move |lua, (name, qtype): (String, Option<String>)| {
            let qt = qtype.unwrap_or_else(|| "A".to_string());

            let result = lua.create_table()?;
            result.set("name", name.as_str())?;
            result.set("type", qt.as_str())?;

            match broker_dns_lookup(
                &cap_ctx,
                &svc,
                &name,
                NseDnsRecordType::parse(&qt),
                "dns.query",
            ) {
                Ok(answer) => {
                    result.set("status", "ok")?;
                    let answers = lua.create_table()?;
                    for (i, display) in answer.displays().iter().enumerate() {
                        answers.set(i + 1, display.clone())?;
                    }
                    result.set("answers", answers)?;
                }
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e)?;
                }
            }

            Ok(result)
        })?,
    )?;

    dns.set(
        "axfr",
        lua.create_function(|lua, (_domain, _server): (String, String)| {
            let result = lua.create_table()?;
            result.set("status", "error")?;
            result.set("error", "AXFR requires zone transfer enabled on DNS server")?;
            Ok(result)
        })?,
    )?;

    dns.set(
        "getnameservers",
        lua.create_function(|_lua, _host: Option<String>| {
            let nameservers = _lua.create_table()?;
            nameservers.set(1, "8.8.8.8")?;
            nameservers.set(2, "8.8.4.4")?;
            nameservers.set(3, "1.1.1.1")?;
            Ok(nameservers)
        })?,
    )?;

    dns.set(
        "checkversion",
        lua.create_function(|_lua, _: ()| Ok("1.0.0".to_string()))?,
    )?;

    dns.set(
        "version",
        lua.create_function(|_lua, _: ()| Ok("1.0.0".to_string()))?,
    )?;

    let cap_ctx = capability_ctx.clone();
    let svc = services.clone();
    dns.set(
        "forward",
        lua.create_function(move |lua, (hostname, _server): (String, Option<String>)| {
            let result = lua.create_table()?;

            match broker_dns_lookup(
                &cap_ctx,
                &svc,
                &hostname,
                NseDnsRecordType::A,
                "dns.forward",
            ) {
                Ok(answer) => {
                    result.set("status", "ok")?;
                    let addresses = lua.create_table()?;
                    for (i, display) in answer.displays().iter().enumerate() {
                        addresses.set(i + 1, display.clone())?;
                    }
                    result.set("addresses", addresses)?;
                }
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e)?;
                }
            }
            Ok(result)
        })?,
    )?;

    let cap_ctx = capability_ctx.clone();
    let svc = services.clone();
    dns.set(
        "ptr",
        lua.create_function(move |lua, ip: String| {
            let dns_reverse = lua.create_table()?;

            let Some(addr) = NseIpAddress::parse(&ip) else {
                dns_reverse.set("status", "error")?;
                dns_reverse.set("error", "Invalid IP address")?;
                return Ok(dns_reverse);
            };

            match broker_dns_lookup(
                &cap_ctx,
                &svc,
                &addr.reverse_dns_name(),
                NseDnsRecordType::Ptr,
                "dns.ptr",
            ) {
                Ok(answer) => {
                    let result = lua.create_table()?;
                    result.set("status", "ok")?;
                    if let Some(first) = answer.displays().first() {
                        result.set("name", first.clone())?;
                    }
                    Ok(result)
                }
                Err(e) => {
                    // Preserve the legacy shapes: denial sets a bare `error`
                    // key; lookup failures set `status = "error"` + `error`.
                    if e.contains("denied") || e.contains("not allowed") {
                        dns_reverse.set("error", e)?;
                    } else {
                        let result = lua.create_table()?;
                        result.set("status", "error")?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                    Ok(dns_reverse)
                }
            }
        })?,
    )?;

    globals.set("dns", dns)?;
    Ok(())
}
