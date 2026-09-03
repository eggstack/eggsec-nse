//! NSE dns library wrapper
//!
//! Provides DNS query functionality compatible with NSE scripts.

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioResolver;
use mlua::{Lua, Result as LuaResult};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use crate::capabilities::NseCapabilityContext;
use crate::wrappers;

static RESOLVER: OnceLock<TokioResolver> = OnceLock::new();

fn get_resolver() -> Result<&'static TokioResolver, String> {
    if let Some(resolver) = RESOLVER.get() {
        return Ok(resolver);
    }
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::default(),
        hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
    )
    .with_options({
        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(5);
        opts.attempts = 2;
        opts
    })
    .build()
    .map_err(|e| {
        tracing::warn!("failed to initialize DNS resolver: {}", e);
        e.to_string()
    })?;
    // If another thread won the init race, drop ours and use theirs.
    let _ = RESOLVER.set(resolver);
    RESOLVER
        .get()
        .ok_or_else(|| "DNS resolver unavailable after init".to_string())
}

pub fn register_dns_library(lua: &Lua, capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    let globals = lua.globals();
    let dns = lua.create_table()?;
    let cap_ctx = capability_ctx.clone();
    dns.set(
        "resolve",
        lua.create_function(
            move |lua, (hostname, query_type): (String, Option<String>)| {
                let qtype = query_type.unwrap_or_else(|| "A".to_string());

                if hostname.parse::<Ipv4Addr>().is_ok() || hostname.parse::<Ipv6Addr>().is_ok() {
                    let result = lua.create_table()?;
                    result.set("type", qtype.as_str())?;
                    result.set("address", hostname.clone())?;
                    return Ok(result);
                }

                let runtime = tokio::runtime::Handle::current();
                let hostname_clone = hostname.clone();
                let qtype_clone = qtype.clone();

                let decision = wrappers::check_dns(&cap_ctx, &hostname_clone, "dns.resolve");
                if decision.is_denied() {
                    let result = lua.create_table()?;
                    result.set("type", qtype_clone.as_str())?;
                    result.set(
                        "error",
                        format!(
                            "DNS resolution denied: {}",
                            decision.deny_reason().unwrap_or("policy violation")
                        ),
                    )?;
                    return Ok(result);
                }

                runtime.block_on(async {
                    let record_type = match qtype_clone.to_uppercase().as_str() {
                        "A" => RecordType::A,
                        "AAAA" => RecordType::AAAA,
                        "MX" => RecordType::MX,
                        "TXT" => RecordType::TXT,
                        "NS" => RecordType::NS,
                        "SOA" => RecordType::SOA,
                        "PTR" => RecordType::PTR,
                        "CNAME" => RecordType::CNAME,
                        "ANY" => RecordType::ANY,
                        _ => RecordType::A,
                    };

                    let resolver = match get_resolver() {
                        Ok(r) => r,
                        Err(e) => {
                            let result = lua.create_table()?;
                            result.set("type", qtype_clone.as_str())?;
                            result.set("error", format!("DNS resolver unavailable: {}", e))?;
                            return Ok(result);
                        }
                    };
                    match resolver.lookup(hostname_clone.clone(), record_type).await {
                        Ok(lookup) => {
                            let result = lua.create_table()?;
                            result.set("type", qtype_clone.as_str())?;

                            let answers = lua.create_table()?;
                            for (i, record) in lookup.answers().iter().enumerate() {
                                answers.set(i + 1, record.data.to_string())?;
                            }
                            result.set("answers", answers)?;

                            if !lookup.answers().is_empty() {
                                result.set("address", lookup.answers()[0].data.to_string())?;
                            }

                            Ok(result)
                        }
                        Err(e) => {
                            let result = lua.create_table()?;
                            result.set("type", qtype_clone.as_str())?;
                            result.set("error", format!("DNS lookup failed: {}", e))?;
                            Ok(result)
                        }
                    }
                })
            },
        )?,
    )?;

    dns.set(
        "reverse",
        lua.create_function(|lua, ip: String| {
            let result = lua.create_table()?;

            if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
                let octets = ipv4.octets();
                let reversed = format!(
                    "{}.{}.{}.{}.in-addr.arpa",
                    octets[3], octets[2], octets[1], octets[0]
                );
                result.set("name", reversed)?;
                result.set("status", "ok")?;
            } else if let Ok(ipv6) = ip.parse::<Ipv6Addr>() {
                let segments: Vec<String> = ipv6
                    .segments()
                    .iter()
                    .flat_map(|s| format!("{:04x}", s).chars().collect::<Vec<_>>())
                    .rev()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>();
                let reversed = format!("{}.ip6.arpa", segments.join("."));
                result.set("name", reversed)?;
                result.set("status", "ok")?;
            } else {
                result.set("status", "error")?;
                result.set("error", "Invalid IP address")?;
            }

            Ok(result)
        })?,
    )?;

    let cap_ctx = capability_ctx.clone();
    dns.set(
        "query",
        lua.create_function(move |lua, (name, qtype): (String, Option<String>)| {
            let qt = qtype.unwrap_or_else(|| "A".to_string());
            let runtime = tokio::runtime::Handle::current();
            let name_clone = name.clone();
            let qt_clone = qt.clone();

            let decision = wrappers::check_dns(&cap_ctx, &name_clone, "dns.query");
            if decision.is_denied() {
                let result = lua.create_table()?;
                result.set("name", name_clone.as_str())?;
                result.set("type", qt_clone.as_str())?;
                result.set(
                    "error",
                    format!(
                        "DNS resolution denied: {}",
                        decision.deny_reason().unwrap_or("policy violation")
                    ),
                )?;
                return Ok(result);
            }

            runtime.block_on(async {
                let record_type = match qt_clone.to_uppercase().as_str() {
                    "A" => RecordType::A,
                    "AAAA" => RecordType::AAAA,
                    "MX" => RecordType::MX,
                    "TXT" => RecordType::TXT,
                    "NS" => RecordType::NS,
                    "SOA" => RecordType::SOA,
                    "PTR" => RecordType::PTR,
                    "CNAME" => RecordType::CNAME,
                    "ANY" => RecordType::ANY,
                    _ => RecordType::A,
                };

                let result = lua.create_table()?;
                result.set("name", name_clone.as_str())?;
                result.set("type", qt_clone.as_str())?;

                let resolver = match get_resolver() {
                    Ok(r) => r,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", format!("DNS resolver unavailable: {}", e))?;
                        return Ok(result);
                    }
                };
                match resolver.lookup(name_clone.clone(), record_type).await {
                    Ok(lookup) => {
                        result.set("status", "ok")?;
                        let answers = lua.create_table()?;
                        for (i, record) in lookup.answers().iter().enumerate() {
                            answers.set(i + 1, record.data.to_string())?;
                        }
                        result.set("answers", answers)?;
                    }
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e.to_string())?;
                    }
                }

                Ok(result)
            })
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
    dns.set(
        "forward",
        lua.create_function(move |lua, (hostname, _server): (String, Option<String>)| {
            let result = lua.create_table()?;

            let runtime = tokio::runtime::Handle::current();
            let hostname_clone = hostname.clone();

            let decision = wrappers::check_dns(&cap_ctx, &hostname_clone, "dns.forward");
            if decision.is_denied() {
                result.set(
                    "error",
                    format!(
                        "DNS resolution denied: {}",
                        decision.deny_reason().unwrap_or("policy violation")
                    ),
                )?;
                return Ok(result);
            }

            runtime.block_on(async {
                let resolver = match get_resolver() {
                    Ok(r) => r,
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", format!("DNS resolver unavailable: {}", e))?;
                        return Ok(result);
                    }
                };
                match resolver.lookup(hostname_clone.clone(), RecordType::A).await {
                    Ok(lookup) => {
                        result.set("status", "ok")?;
                        let addresses = lua.create_table()?;
                        for (i, record) in lookup.answers().iter().enumerate() {
                            addresses.set(i + 1, record.data.to_string())?;
                        }
                        result.set("addresses", addresses)?;
                    }
                    Err(e) => {
                        result.set("status", "error")?;
                        result.set("error", e.to_string())?;
                    }
                }
                Ok(result)
            })
        })?,
    )?;

    let cap_ctx = capability_ctx.clone();
    dns.set(
        "ptr",
        lua.create_function(move |lua, ip: String| {
            let dns_reverse = lua.create_table()?;

            if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
                let octets = ipv4.octets();
                let reversed = format!(
                    "{}.{}.{}.{}.in-addr.arpa",
                    octets[3], octets[2], octets[1], octets[0]
                );

                let runtime = tokio::runtime::Handle::current();
                let reversed_clone = reversed.clone();

                let decision = wrappers::check_dns(&cap_ctx, &reversed_clone, "dns.ptr");
                if decision.is_denied() {
                    dns_reverse.set(
                        "error",
                        format!(
                            "DNS resolution denied: {}",
                            decision.deny_reason().unwrap_or("policy violation")
                        ),
                    )?;
                    return Ok(dns_reverse);
                }

                return runtime.block_on(async {
                    let result = lua.create_table()?;

                    let resolver = match get_resolver() {
                        Ok(r) => r,
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", format!("DNS resolver unavailable: {}", e))?;
                            return Ok(result);
                        }
                    };
                    match resolver
                        .lookup(reversed_clone.clone(), RecordType::PTR)
                        .await
                    {
                        Ok(lookup) => {
                            result.set("status", "ok")?;
                            if let Some(record) = lookup.answers().first() {
                                result.set("name", record.data.to_string())?;
                            }
                        }
                        Err(e) => {
                            result.set("status", "error")?;
                            result.set("error", e.to_string())?;
                        }
                    }

                    Ok(result)
                });
            }

            dns_reverse.set("status", "error")?;
            dns_reverse.set("error", "Invalid IP address")?;
            Ok(dns_reverse)
        })?,
    )?;

    globals.set("dns", dns)?;
    Ok(())
}
