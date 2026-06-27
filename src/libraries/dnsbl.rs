//! NSE dnsbl library wrapper
//!
//! DNS Blacklist library for querying DNSBL services.
//! Based on Nmap's dnsbl library concepts.

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioResolver;
use mlua::{Lua, Result as LuaResult, Table};
use std::sync::OnceLock;
use std::time::Duration;

static DNSBL_RESOLVER: OnceLock<TokioResolver> = OnceLock::new();

fn get_resolver() -> &'static TokioResolver {
    DNSBL_RESOLVER.get_or_init(|| {
        let config = ResolverConfig::default();
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(3);
        opts.attempts = 1;
        TokioResolver::builder_with_config(
            config,
            hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
        )
        .with_options(opts)
        .build()
        .unwrap_or_default()
    })
}

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

pub fn register_dnsbl_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let dnsbl = lua.create_table()?;

    let check_fn = lua.create_function(|lua, (ip, server): (String, Option<String>)| {
        let result = lua.create_table()?;

        let target = if let Some(srv) = server {
            format!("{}.{}", reverse_ip(&ip), srv)
        } else {
            format!("{}.zen.spamhaus.org", reverse_ip(&ip))
        };

        match std::net::ToSocketAddrs::to_socket_addrs(&target) {
            Ok(addrs) => {
                let mut listed = false;
                let mut categories = Vec::new();
                let mut details = String::new();

                for addr in addrs {
                    listed = true;
                    let ip_str = addr.ip().to_string();

                    if ip_str.starts_with("127.") {
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
                }

                result.set("listed", listed)?;
                result.set("ip", ip)?;

                let cats = lua.create_table()?;
                for (i, cat) in categories.iter().enumerate() {
                    cats.set(i + 1, *cat)?;
                }
                result.set("categories", cats)?;
                result.set("details", details.trim().to_string())?;
            }
            Err(_) => {
                result.set("listed", false)?;
                result.set("ip", ip)?;
                result.set("categories", lua.create_table()?)?;
                result.set("details", "Not listed")?;
            }
        }

        Ok(result)
    })?;
    dnsbl.set("check", check_fn)?;

    let check_multi_fn = lua.create_function(|lua, (ip, servers): (String, Option<Table>)| {
        let result = lua.create_table()?;

        let server_list: Vec<String> = if let Some(srv_table) = servers {
            let mut list = Vec::new();
            for (_, srv) in srv_table.pairs::<i32, String>().flatten() {
                list.push(srv);
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

            match std::net::ToSocketAddrs::to_socket_addrs(&target) {
                Ok(addrs) => {
                    let mut listed = false;
                    let mut categories = Vec::new();

                    for addr in addrs {
                        let ip_str = addr.ip().to_string();
                        if ip_str.starts_with("127.") {
                            listed = true;
                            let code: u8 = ip_str
                                .split('.')
                                .next_back()
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0);

                            if code > 0 {
                                categories.push(code);
                            }
                        }
                    }

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
                Err(_) => {
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

    let async_check_fn = lua.create_function(|lua, (ip, server): (String, Option<String>)| {
        let runtime = tokio::runtime::Handle::current();

        runtime.block_on(async {
            let result = lua.create_table()?;

            let target = if let Some(srv) = server {
                format!("{}.{}", reverse_ip(&ip), srv)
            } else {
                format!("{}.zen.spamhaus.org", reverse_ip(&ip))
            };

            match get_resolver().lookup_ip(&target).await {
                Ok(lookup) => {
                    let mut listed = false;
                    let mut categories = Vec::new();
                    let mut details = String::new();

                    for addr in lookup.iter() {
                        listed = true;
                        let ip_str = addr.to_string();

                        if let Some(code_str) = ip_str.split('.').next_back() {
                            if let Ok(code) = code_str.parse::<u8>() {
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
                        }
                    }

                    result.set("listed", listed)?;
                    result.set("ip", ip)?;

                    let cats = lua.create_table()?;
                    for (i, cat) in categories.iter().enumerate() {
                        cats.set(i + 1, *cat)?;
                    }
                    result.set("categories", cats)?;
                    result.set("details", details.trim().to_string())?;
                }
                Err(_) => {
                    result.set("listed", false)?;
                    result.set("ip", ip)?;
                    result.set("categories", lua.create_table()?)?;
                    result.set("details", "Not listed")?;
                }
            }

            Ok(result)
        })
    })?;
    dnsbl.set("check_async", async_check_fn)?;

    globals.set("dnsbl", dnsbl)?;
    Ok(())
}
