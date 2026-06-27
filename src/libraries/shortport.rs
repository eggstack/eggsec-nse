//! NSE shortport library wrapper
//!
//! Functions for building short portrules.
//! Based on Nmap's shortport library: https://nmap.org/nsedoc/lib/shortport.html

use mlua::{Lua, Result as LuaResult, Table, Value};
use std::sync::LazyLock;
use regex::Regex;

static SHORTPORT_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    let patterns = [
        r"^\d+$",     // just a port number
        r"^\d+-\d+$", // port range
        r"^tcp$",
        r"^udp$",
        r"^sctp$", // protocols
        r"^http$",
        r"^https?$", // common services
        r"^ssh$",
        r"^ftp$",
        r"^smtp$",
        r"^mysql$",
        r"^postgres$",
        r"^redis$",
        r"^mongodb$",
        r"^oracle$",
        r"^mssql$",
    ];
    patterns.iter().filter_map(|p| Regex::new(p).ok()).collect()
});

fn value_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.to_string_lossy().to_string()),
        _ => None,
    }
}

fn parse_proto_state(v: Option<Value>) -> Option<String> {
    v.and_then(|vv| value_to_string(&vv))
}

const WELL_KNOWN_SERVICES: &[(&str, &[u16])] = &[
    ("http", &[80, 8080, 8000, 8888, 3000, 5000]),
    ("https", &[443, 8443, 9443]),
    ("ftp", &[21, 20]),
    ("ssh", &[22]),
    ("telnet", &[23]),
    ("smtp", &[25, 587, 465]),
    ("pop3", &[110, 995]),
    ("imap", &[143, 993]),
    ("mysql", &[3306]),
    ("redis", &[6379]),
    ("mongodb", &[27017, 27018, 27019]),
    ("mssql", &[1433]),
    ("postgres", &[5432, 5433]),
    ("oracle", &[1521]),
    ("ldap", &[389, 636]),
    ("kerberos", &[88]),
    ("dns", &[53]),
    ("snmp", &[161, 162]),
    ("samba", &[139, 445]),
    ("rdp", &[3389]),
    ("vnc", &[5900, 5901]),
    ("git", &[9418]),
    ("svn", &[3690]),
    ("irc", &[6667, 6668, 6669]),
    ("ntp", &[123]),
    ("syslog", &[514]),
    ("rsh", &[514]),
    ("finger", &[79]),
    ("whois", &[43]),
];

fn parse_port_spec(value: &Value) -> Vec<u16> {
    let mut ports = Vec::new();

    match value {
        Value::Number(n) => {
            let n = *n as u32;
            if n <= u16::MAX as u32 {
                ports.push(n as u16);
            }
        }
        Value::String(s) => {
            let s = s.to_string_lossy();
            for part in s.split(',') {
                let part = part.trim();
                if let Some((start, end)) = part.split_once('-') {
                    let start: u16 = match start.trim().parse() {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let end: u16 = match end.trim().parse() {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if start > end {
                        continue;
                    }
                    ports.extend(start..=end);
                } else if let Ok(port) = part.parse::<u16>() {
                    ports.push(port);
                }
            }
        }
        Value::Table(t) => {
            let len = t.len().unwrap_or(0);
            for i in 1..=len {
                if let Ok(v) = t.get::<Value>(i) {
                    ports.extend(parse_port_spec(&v));
                }
            }
        }
        _ => {}
    }

    ports
}

fn parse_service_spec(value: &Value) -> Vec<String> {
    let mut services = Vec::new();

    match value {
        Value::String(s) => {
            let s = s.to_string_lossy();
            for part in s.split(',') {
                services.push(part.trim().to_lowercase());
            }
        }
        Value::Table(t) => {
            let len = t.len().unwrap_or(0);
            for i in 1..=len {
                if let Ok(s) = t.get::<String>(i) {
                    services.push(s.to_lowercase());
                }
            }
        }
        _ => {}
    }

    services
}

fn get_ports_for_service(service: &str) -> Option<&'static [u16]> {
    for (name, ports) in WELL_KNOWN_SERVICES {
        if *name == service {
            return Some(ports);
        }
    }
    None
}

fn match_service_on_port(service: &str, port: u16) -> bool {
    get_ports_for_service(service)
        .map(|ports| ports.contains(&port))
        .unwrap_or(false)
}

fn check_nmap_ports<F>(
    lua: &Lua,
    ports: &[u16],
    proto: Option<&str>,
    state: Option<&str>,
    mut check: F,
) -> bool
where
    F: FnMut(u16, Option<&str>, Option<&str>, Option<&str>) -> bool,
{
    let globals = lua.globals();
    let nmap_result: Result<Table, _> = globals.get("nmap");

    if let Ok(nmap) = nmap_result {
        let ports_result: Result<Table, _> = nmap.get("_ports");
        if let Ok(ports_table) = ports_result {
            let len = ports_table.len().unwrap_or(0);
            for i in 1..=len {
                if let Ok(p) = ports_table.get::<Table>(i) {
                    let port_num: Option<u16> = p.get("number").ok();
                    let port_proto: Option<String> = p.get("protocol").ok();
                    let port_state: Option<String> = p.get("state").ok();
                    let port_service: Option<String> = p.get("service").ok();

                    if let Some(num) = port_num {
                        if !ports.is_empty() && !ports.contains(&num) {
                            continue;
                        }

                        let matches_proto =
                            proto.map_or(true, |pr| port_proto.as_ref().is_some_and(|np| np == pr));
                        let matches_state =
                            state.map_or(true, |s| port_state.as_ref().is_some_and(|ns| ns == s));

                        if matches_proto
                            && matches_state
                            && check(
                                num,
                                port_proto.as_deref(),
                                port_state.as_deref(),
                                port_service.as_deref(),
                            )
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }

    false
}

fn portnumber_match(lua: &Lua, ports: &[u16], proto: Option<&str>, state: Option<&str>) -> bool {
    check_nmap_ports(lua, ports, proto, state, |_, _, _, _| true)
}

fn service_match(lua: &Lua, services: &[String], proto: Option<&str>, state: Option<&str>) -> bool {
    let found = check_nmap_ports(lua, &[], proto, state, |_, _, _, svc| {
        if let Some(s) = svc {
            let s_lower = s.to_lowercase();
            for req in services {
                if s_lower.contains(req) || req.contains(&s_lower) {
                    return true;
                }
            }
        }
        false
    });

    if found {
        return true;
    }

    for req in services {
        if check_nmap_ports(lua, &[], proto, state, |port, _, _, _| {
            match_service_on_port(req, port)
        }) {
            return true;
        }
    }

    false
}

pub fn register_shortport_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let shortport = lua.create_table()?;

    // portnumber
    let portnumber_fn = lua.create_function(
        |lua, (ports, protos, states): (Value, Option<Value>, Option<Value>)| {
            let requested = parse_port_spec(&ports);
            let proto = parse_proto_state(protos);
            let state = parse_proto_state(states);
            Ok(
                portnumber_match(lua, &requested, proto.as_deref(), state.as_deref())
                    || requested.is_empty(),
            )
        },
    )?;
    shortport.set("portnumber", portnumber_fn)?;

    // service
    let service_fn = lua.create_function(
        |lua, (services, protos, states): (Value, Option<Value>, Option<Value>)| {
            let requested = parse_service_spec(&services);
            let proto = parse_proto_state(protos);
            let state = parse_proto_state(states);
            Ok(
                service_match(lua, &requested, proto.as_deref(), state.as_deref())
                    || requested.is_empty(),
            )
        },
    )?;
    shortport.set("service", service_fn)?;

    // ssl
    let ssl_fn = lua.create_function(|lua, (ports, protos): (Value, Option<Value>)| {
        let requested = parse_port_spec(&ports);
        let proto = parse_proto_state(protos);
        let https_ports = [443, 8443, 9443, 465, 993, 995];
        let found = check_nmap_ports(lua, &requested, proto.as_deref(), None, |port, _, _, _| {
            https_ports.contains(&port)
        });
        Ok(found || requested.is_empty())
    })?;
    shortport.set("ssl", ssl_fn)?;

    // http
    let http_fn = lua.create_function(|lua, (ports, protos): (Value, Option<Value>)| {
        let requested = parse_port_spec(&ports);
        let proto = parse_proto_state(protos);
        let found = check_nmap_ports(lua, &requested, proto.as_deref(), None, |port, _, _, _| {
            matches!(
                port,
                80 | 8080 | 8000 | 8888 | 3000 | 5000 | 81 | 8008 | 8123
            )
        });
        Ok(found || requested.is_empty())
    })?;
    shortport.set("http", http_fn)?;

    // ftp
    let ftp_fn = lua.create_function(|lua, (ports, protos): (Value, Option<Value>)| {
        let requested = parse_port_spec(&ports);
        let proto = parse_proto_state(protos);
        let found = check_nmap_ports(lua, &requested, proto.as_deref(), None, |port, _, _, _| {
            matches!(port, 20 | 21)
        });
        Ok(found || requested.is_empty())
    })?;
    shortport.set("ftp", ftp_fn)?;

    // ssh
    let ssh_fn = lua.create_function(|lua, (ports, protos): (Value, Option<Value>)| {
        let requested = parse_port_spec(&ports);
        let proto = parse_proto_state(protos);
        let found = check_nmap_ports(lua, &requested, proto.as_deref(), None, |port, _, _, _| {
            port == 22
        });
        Ok(found || requested.is_empty())
    })?;
    shortport.set("ssh", ssh_fn)?;

    // telnet
    let telnet_fn = lua.create_function(|lua, (ports, protos): (Value, Option<Value>)| {
        let requested = parse_port_spec(&ports);
        let proto = parse_proto_state(protos);
        let found = check_nmap_ports(lua, &requested, proto.as_deref(), None, |port, _, _, _| {
            port == 23
        });
        Ok(found || requested.is_empty())
    })?;
    shortport.set("telnet", telnet_fn)?;

    // smtp
    let smtp_fn = lua.create_function(|lua, (ports, protos): (Value, Option<Value>)| {
        let requested = parse_port_spec(&ports);
        let proto = parse_proto_state(protos);
        let found = check_nmap_ports(lua, &requested, proto.as_deref(), None, |port, _, _, _| {
            matches!(port, 25 | 587 | 465 | 2525)
        });
        Ok(found || requested.is_empty())
    })?;
    shortport.set("smtp", smtp_fn)?;

    // pop3
    let pop3_fn = lua.create_function(|lua, (ports, protos): (Value, Option<Value>)| {
        let requested = parse_port_spec(&ports);
        let proto = parse_proto_state(protos);
        let found = check_nmap_ports(lua, &requested, proto.as_deref(), None, |port, _, _, _| {
            matches!(port, 110 | 995)
        });
        Ok(found || requested.is_empty())
    })?;
    shortport.set("pop3", pop3_fn)?;

    // imap
    let imap_fn = lua.create_function(|lua, (ports, protos): (Value, Option<Value>)| {
        let requested = parse_port_spec(&ports);
        let proto = parse_proto_state(protos);
        let found = check_nmap_ports(lua, &requested, proto.as_deref(), None, |port, _, _, _| {
            matches!(port, 143 | 993)
        });
        Ok(found || requested.is_empty())
    })?;
    shortport.set("imap", imap_fn)?;

    // mysql
    let mysql_fn = lua.create_function(|lua, (ports, protos): (Value, Option<Value>)| {
        let requested = parse_port_spec(&ports);
        let proto = parse_proto_state(protos);
        let found = check_nmap_ports(lua, &requested, proto.as_deref(), None, |port, _, _, _| {
            port == 3306
        });
        Ok(found || requested.is_empty())
    })?;
    shortport.set("mysql", mysql_fn)?;

    // redis
    let redis_fn = lua.create_function(|lua, (ports, protos): (Value, Option<Value>)| {
        let requested = parse_port_spec(&ports);
        let proto = parse_proto_state(protos);
        let found = check_nmap_ports(lua, &requested, proto.as_deref(), None, |port, _, _, _| {
            port == 6379
        });
        Ok(found || requested.is_empty())
    })?;
    shortport.set("redis", redis_fn)?;

    // mongodb
    let mongodb_fn = lua.create_function(|lua, (ports, protos): (Value, Option<Value>)| {
        let requested = parse_port_spec(&ports);
        let proto = parse_proto_state(protos);
        let found = check_nmap_ports(lua, &requested, proto.as_deref(), None, |port, _, _, _| {
            matches!(port, 27017 | 27018 | 27019 | 28017)
        });
        Ok(found || requested.is_empty())
    })?;
    shortport.set("mongodb", mongodb_fn)?;

    // port - alias for portnumber
    let port_fn = lua.create_function(
        |lua, (ports, protos, states): (Value, Option<Value>, Option<Value>)| {
            let requested = parse_port_spec(&ports);
            let proto = parse_proto_state(protos);
            let state = parse_proto_state(states);
            Ok(portnumber_match(
                lua,
                &requested,
                proto.as_deref(),
                state.as_deref(),
            ))
        },
    )?;
    shortport.set("port", port_fn)?;

    // number - alias for portnumber
    let number_fn = lua.create_function(
        |lua, (ports, protos, states): (Value, Option<Value>, Option<Value>)| {
            let requested = parse_port_spec(&ports);
            let proto = parse_proto_state(protos);
            let state = parse_proto_state(states);
            Ok(portnumber_match(
                lua,
                &requested,
                proto.as_deref(),
                state.as_deref(),
            ))
        },
    )?;
    shortport.set("number", number_fn)?;

    // version
    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    shortport.set("version", version_fn)?;

    // regex - matches port/host expressions against regex patterns
    let regex_fn = lua.create_function(|_lua, (port_expr, host_expr): (Value, Value)| {
        let port_str = match port_expr {
            Value::String(s) => Some(s.to_string_lossy().to_string()),
            Value::Nil => None,
            _ => None,
        };

        let host_str = match host_expr {
            Value::String(s) => Some(s.to_string_lossy().to_string()),
            Value::Nil => None,
            _ => None,
        };

        let expr = port_str.or(host_str);

        if let Some(expr) = expr {
            for re in SHORTPORT_PATTERNS.iter() {
                if re.is_match(&expr) {
                    return Ok(true);
                }
            }

            // Check if it looks like a valid expression
            if !expr.is_empty()
                && (expr
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '/' || c == ':' || c == '*'))
            {
                return Ok(true);
            }
        }

        Ok(false)
    })?;
    shortport.set("regex", regex_fn)?;

    // _service
    let service2_fn = lua.create_function(
        |lua, (service_spec, proto, state): (Value, Option<Value>, Option<Value>)| {
            let services = parse_service_spec(&service_spec);
            let proto = parse_proto_state(proto);
            let state = parse_proto_state(state);
            Ok(service_match(
                lua,
                &services,
                proto.as_deref(),
                state.as_deref(),
            ))
        },
    )?;
    shortport.set("_service", service2_fn)?;

    // or - returns true if any predicate returns true
    let or_fn = lua.create_function(|_lua, predicates: Vec<Value>| {
        for pred in predicates {
            if let Value::Function(f) = pred {
                if let Ok(mlua::Value::Boolean(true)) = f.call(()) {
                    return Ok(true);
                }
            } else if let Value::Boolean(b) = pred {
                if b {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    })?;
    shortport.set("or", or_fn)?;

    // and - returns true if all predicates return true
    let and_fn = lua.create_function(|_lua, predicates: Vec<Value>| {
        let all_true = !predicates.is_empty();
        for pred in predicates {
            if let Value::Function(f) = pred {
                if let Ok(mlua::Value::Boolean(false)) = f.call(()) {
                    return Ok(false);
                }
            } else if let Value::Boolean(b) = pred {
                if !b {
                    return Ok(false);
                }
            }
        }
        Ok(all_true)
    })?;
    shortport.set("and", and_fn)?;

    // not - returns boolean negation
    let not_fn = lua.create_function(|_lua, val: Value| {
        if let Value::Function(f) = val {
            if let Ok(mlua::Value::Boolean(b)) = f.call(()) {
                return Ok(!b);
            }
        } else if let Value::Boolean(b) = val {
            return Ok(!b);
        }
        Ok(true)
    })?;
    shortport.set("not", not_fn)?;

    // true
    let true_fn = lua.create_function(|_lua, _: ()| Ok(true))?;
    shortport.set("true", true_fn)?;

    // false
    let false_fn = lua.create_function(|_lua, _: ()| Ok(false))?;
    shortport.set("false", false_fn)?;

    // only - returns true only if port matches exactly (no default behavior)
    let only_fn = lua.create_function(
        |lua, (ports, protos, states): (Value, Option<Value>, Option<Value>)| {
            let requested = parse_port_spec(&ports);
            let proto = parse_proto_state(protos);
            let state = parse_proto_state(states);
            Ok(portnumber_match(
                lua,
                &requested,
                proto.as_deref(),
                state.as_deref(),
            ))
        },
    )?;
    shortport.set("only", only_fn)?;

    // tcp - matches TCP ports only
    let tcp_fn = lua.create_function(|lua, (ports, states): (Value, Option<Value>)| {
        let requested = parse_port_spec(&ports);
        let state = parse_proto_state(states);
        Ok(portnumber_match(
            lua,
            &requested,
            Some("tcp"),
            state.as_deref(),
        ))
    })?;
    shortport.set("tcp", tcp_fn)?;

    // udp - matches UDP ports only
    let udp_fn = lua.create_function(|lua, (ports, states): (Value, Option<Value>)| {
        let requested = parse_port_spec(&ports);
        let state = parse_proto_state(states);
        Ok(portnumber_match(
            lua,
            &requested,
            Some("udp"),
            state.as_deref(),
        ))
    })?;
    shortport.set("udp", udp_fn)?;

    // sctp - matches SCTP ports only
    let sctp_fn = lua.create_function(|lua, (ports, states): (Value, Option<Value>)| {
        let requested = parse_port_spec(&ports);
        let state = parse_proto_state(states);
        Ok(portnumber_match(
            lua,
            &requested,
            Some("sctp"),
            state.as_deref(),
        ))
    })?;
    shortport.set("sctp", sctp_fn)?;

    // any - matches any port
    let any_fn = lua.create_function(|_lua, _: ()| Ok(true))?;
    shortport.set("any", any_fn)?;

    // notftp - matches ports that are NOT FTP
    let notftp_fn = lua.create_function(|lua, (ports, protos): (Value, Option<Value>)| {
        let requested = parse_port_spec(&ports);
        let proto = parse_proto_state(protos);
        let found = check_nmap_ports(lua, &requested, proto.as_deref(), None, |port, _, _, _| {
            matches!(port, 20 | 21)
        });
        Ok(!found || requested.is_empty())
    })?;
    shortport.set("notftp", notftp_fn)?;

    // notssh - matches ports that are NOT SSH
    let notssh_fn = lua.create_function(|lua, (ports, protos): (Value, Option<Value>)| {
        let requested = parse_port_spec(&ports);
        let proto = parse_proto_state(protos);
        let found = check_nmap_ports(lua, &requested, proto.as_deref(), None, |port, _, _, _| {
            port == 22
        });
        Ok(!found || requested.is_empty())
    })?;
    shortport.set("notssh", notssh_fn)?;

    // nothttp - matches ports that are NOT HTTP
    let nothttp_fn = lua.create_function(|lua, (ports, protos): (Value, Option<Value>)| {
        let requested = parse_port_spec(&ports);
        let proto = parse_proto_state(protos);
        let found = check_nmap_ports(lua, &requested, proto.as_deref(), None, |port, _, _, _| {
            matches!(
                port,
                80 | 8080 | 8000 | 8888 | 3000 | 5000 | 81 | 8008 | 8123
            )
        });
        Ok(!found || requested.is_empty())
    })?;
    shortport.set("nothttp", nothttp_fn)?;

    // list - matches ports in a list
    let list_fn = lua.create_function(
        |lua, (ports, protos, states): (Value, Option<Value>, Option<Value>)| {
            let requested = parse_port_spec(&ports);
            let proto = parse_proto_state(protos);
            let state = parse_proto_state(states);
            Ok(portnumber_match(
                lua,
                &requested,
                proto.as_deref(),
                state.as_deref(),
            ))
        },
    )?;
    shortport.set("list", list_fn)?;

    globals.set("shortport", shortport)?;
    Ok(())
}
