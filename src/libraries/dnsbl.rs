//! NSE dnsbl library wrapper
//!
//! DNS Blacklist library for querying DNSBL services.
//! Based on Nmap's dnsbl library concepts.
//!
//! M007B corrective: this module used to resolve DNSBL names two ways,
//! both of them direct host-network effects outside the provider
//! contract:
//!
//! - `std::net::ToSocketAddrs::to_socket_addrs` in `check`/`check_multi`;
//! - a process-global `hickory_resolver::TokioResolver` in `check_async`.
//!
//! Both now go through [`broker_dns_lookup`], so the `DnsResolution`
//! capability gate, cancellation, and resource accounting all apply
//! before the injected [`NseDnsProvider`] is touched. Lua result shapes
//! are unchanged.

use mlua::{Lua, Result as LuaResult, Table};
use std::sync::Arc;

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_dns_lookup, NseDnsAnswer, NseDnsRecordType, NseHostServices};

static DNSBL_SERVERS: &[&str] = &[
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "cbl.abuseat.org",
    "b.barracudacentral.org",
    "dnsbl.cyberlogic.net",
    "dnsbl.inps.de",
    "nikula.example.bl.speedtronic.net",
];

static DNSBL_CATEGORIES: &[(&str, &str)] = &[
    ("spam", "Spam source"),
    ("open_proxy", "Open proxy"),
    ("web_spam", "Web spam"),
    ("tor_exit", "Tor exit node"),
    ("malware", "Malware distribution"),
    ("phishing", "Phishing site"),
    ("bot", "Bot/C&C"),
];

fn reverse_ip(ip: &str) -> String {
    ip.split('.').rev().collect::<Vec<_>>().join(".")
}

/// Map a DNSBL answer's `127.0.0.x.x` return codes onto the Nmap-style
/// category/description vocabulary used by the Lua surface.
fn classify_codes(answer: &NseDnsAnswer) -> (bool, Vec<&'static str>, String) {
    let mut listed = false;
    let mut categories: Vec<&'static str> = Vec::new();
    let mut details = String::new();

    for address in answer.addresses() {
        let ip_str = address.to_string();
        if !ip_str.starts_with("127.") {
            continue;
        }
        listed = true;
        let code: u8 = ip_str
            .split('.')
            .next_back()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        match code {
            1 => {
                categories.push("spam");
                details.push_str("Spam source ");
            }
            2 => {
                categories.push("open_proxy");
                details.push_str("Open Proxy ");
            }
            3 => {
                categories.push("web_spam");
                details.push_str("Web Spam ");
            }
            4 => {
                categories.push("tor_exit");
                details.push_str("Tor Exit Node ");
            }
            5..=7 => {
                categories.push("malware");
                details.push_str("Malware ");
            }
            8 => {
                categories.push("phishing");
                details.push_str("Phishing ");
            }
            9..=10 => {
                categories.push("bot");
                details.push_str("Bot/C&C ");
            }
            _ => {
                details.push_str(&format!("Code {} ", code));
            }
        }
    }

    (listed, categories, details.trim().to_string())
}

/// Compatibility registration with native services and a manual-permissive
/// capability context.
///
/// `ExecutorCore` does not register `dnsbl` today (see
/// `scripts/nse-registration-compat-entries.txt`); this entry point is
/// retained so embedders that register it explicitly keep working.
pub fn register_dnsbl_library(lua: &Lua) -> LuaResult<()> {
    let profile = crate::profile::ResolvedNseExecutionProfile::manual_permissive(None);
    let ctx = NseCapabilityContext::from_profile(
        &profile,
        Arc::new(crate::limits::NseResourceCounters::new()),
    );
    register_dnsbl_library_with_services(lua, &ctx, &NseHostServices::native())
}

/// Provider-backed registration.
///
/// Every DNSBL lookup goes through [`broker_dns_lookup`]; a denial or
/// cancellation returns "not listed" without contacting the resolver.
pub fn register_dnsbl_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let dnsbl = lua.create_table()?;

    let check_fn = lua.create_function({
        let cap_ctx = capability_ctx.clone();
        let svc = services.clone();
        move |lua, (ip, server): (String, Option<String>)| {
            let result = lua.create_table()?;

            let target = if let Some(srv) = server {
                format!("{}.{}", reverse_ip(&ip), srv)
            } else {
                format!("{}.zen.spamhaus.org", reverse_ip(&ip))
            };

            match broker_dns_lookup(&cap_ctx, &svc, &target, NseDnsRecordType::A, "dnsbl.check") {
                Ok(answer) => {
                    let (listed, categories, details) = classify_codes(&answer);

                    result.set("listed", listed)?;
                    result.set("ip", ip)?;

                    let cats = lua.create_table()?;
                    for (i, cat) in categories.iter().enumerate() {
                        cats.set(i + 1, *cat)?;
                    }
                    result.set("categories", cats)?;
                    result.set("details", details)?;
                }
                Err(e) => {
                    tracing::debug!(target = %target, error = %e, "dnsbl.check resolution failed");
                    result.set("listed", false)?;
                    result.set("ip", ip)?;
                    result.set("categories", lua.create_table()?)?;
                    result.set("details", "Not listed")?;
                }
            }

            Ok(result)
        }
    })?;
    dnsbl.set("check", check_fn.clone())?;

    let check_multi_fn = lua.create_function({
        let cap_ctx = capability_ctx.clone();
        let svc = services.clone();
        move |lua, (ip, servers): (String, Option<Table>)| {
            let result = lua.create_table()?;

            let server_list: Vec<String> = if let Some(srv_table) = servers {
                let mut list = Vec::new();
                for entry in srv_table.pairs::<i32, String>() {
                    match entry {
                        Ok((_, srv)) => list.push(srv),
                        Err(e) => {
                            tracing::debug!(error = %e, "dnsbl.check_multi skipped unreadable entry")
                        }
                    }
                }
                if list.is_empty() {
                    DNSBL_SERVERS.iter().map(|s| s.to_string()).collect()
                } else {
                    list
                }
            } else {
                DNSBL_SERVERS.iter().map(|s| s.to_string()).collect()
            };

            let mut any_listed = false;
            let all_results = lua.create_table()?;

            for srv in server_list {
                let target = format!("{}.{}", reverse_ip(&ip), srv);

                let srv_result = lua.create_table()?;
                srv_result.set("server", srv.clone())?;

                match broker_dns_lookup(
                    &cap_ctx,
                    &svc,
                    &target,
                    NseDnsRecordType::A,
                    "dnsbl.check_multi",
                ) {
                    Ok(answer) => {
                        let (listed, _, _) = classify_codes(&answer);
                        let categories: Vec<u8> = answer
                            .addresses()
                            .iter()
                            .map(|a| a.to_string())
                            .filter(|ip_str| ip_str.starts_with("127."))
                            .filter_map(|ip_str| {
                                ip_str
                                    .split('.')
                                    .next_back()
                                    .and_then(|s| s.parse::<u8>().ok())
                            })
                            .collect();

                        srv_result.set("listed", listed)?;

                        let cats = lua.create_table()?;
                        for (i, code) in categories.iter().enumerate() {
                            cats.set(i + 1, *code)?;
                        }
                        srv_result.set("codes", cats)?;

                        if listed {
                            any_listed = true;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            target = %target,
                            error = %e,
                            "dnsbl.check_multi resolution failed"
                        );
                        srv_result.set("listed", false)?;
                    }
                }

                let len = all_results.len().unwrap_or(0) as usize;
                all_results.set(len + 1, srv_result)?;
            }

            result.set("ip", ip)?;
            result.set("listed", any_listed)?;
            result.set("results", all_results)?;

            Ok(result)
        }
    })?;
    dnsbl.set("check_multi", check_multi_fn)?;

    let get_servers_fn = lua.create_function(|lua, _: ()| {
        let servers = lua.create_table()?;

        for (i, srv) in DNSBL_SERVERS.iter().enumerate() {
            servers.set(i + 1, *srv)?;
        }

        Ok(servers)
    })?;
    dnsbl.set("get_servers", get_servers_fn)?;

    let get_categories_fn = lua.create_function(|lua, _: ()| {
        let categories = lua.create_table()?;

        for (name, desc) in DNSBL_CATEGORIES {
            let entry = lua.create_table()?;
            entry.set("name", *name)?;
            entry.set("description", *desc)?;

            let len = categories.len().unwrap_or(0) as usize;
            categories.set(len + 1, entry)?;
        }

        Ok(categories)
    })?;
    dnsbl.set("get_categories", get_categories_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    dnsbl.set("version", version_fn)?;

    // `check_async` used to bridge into a process-global hickory resolver.
    // The brokered lookup is synchronous by contract, so the alias now
    // shares the exact same provider-backed path (M007B bridge-removal
    // pattern used across the migrated protocol cohort).
    dnsbl.set("check_async", check_fn)?;

    globals.set("dnsbl", dnsbl)?;
    Ok(())
}
