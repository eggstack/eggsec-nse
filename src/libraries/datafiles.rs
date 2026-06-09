//! NSE datafiles library wrapper
//!
//! Provides access to Nmap data files like protocols, services, and RPC info.

use mlua::{Lua, Result as LuaResult};
use rustc_hash::FxHashMap;
use std::sync::OnceLock;

static PROTOCOLS: OnceLock<FxHashMap<&'static str, u16>> = OnceLock::new();
static SERVICES: OnceLock<FxHashMap<&'static str, (u16, &'static str)>> = OnceLock::new();

fn get_protocols() -> &'static FxHashMap<&'static str, u16> {
    PROTOCOLS.get_or_init(|| {
        let mut m = FxHashMap::default();
        m.insert("tcp", 6u16);
        m.insert("udp", 17u16);
        m.insert("icmp", 1u16);
        m.insert("gre", 47u16);
        m.insert("esp", 50u16);
        m.insert("ah", 51u16);
        m.insert("ipv6", 41u16);
        m.insert("ipv6-route", 43u16);
        m.insert("ipsec", 50u16);
        m.insert("vrrp", 112u16);
        m.insert("l2tp", 115u16);
        m.insert("sctp", 132u16);
        m
    })
}

fn get_services() -> &'static FxHashMap<&'static str, (u16, &'static str)> {
    SERVICES.get_or_init(|| {
        let mut m = FxHashMap::default();
        m.insert("http", (80, "tcp"));
        m.insert("https", (443, "tcp"));
        m.insert("ftp", (21, "tcp"));
        m.insert("telnet", (23, "tcp"));
        m.insert("smtp", (25, "tcp"));
        m.insert("pop3", (110, "tcp"));
        m.insert("imap", (143, "tcp"));
        m.insert("smb", (445, "tcp"));
        m.insert("mysql", (3306, "tcp"));
        m.insert("postgres", (5432, "tcp"));
        m.insert("redis", (6379, "tcp"));
        m.insert("dns", (53, "udp"));
        m.insert("ntp", (123, "udp"));
        m.insert("snmp", (161, "udp"));
        m.insert("ldap", (389, "tcp"));
        m.insert("ldaps", (636, "tcp"));
        m.insert("kafka", (9092, "tcp"));
        m.insert("elasticsearch", (9200, "tcp"));
        m.insert("rabbitmq", (5672, "tcp"));
        m.insert("memcached", (11211, "tcp"));
        m.insert("vnc", (5900, "tcp"));
        m.insert("rdp", (3389, "tcp"));
        m.insert("winrm", (5985, "tcp"));
        m.insert("winrms", (5986, "tcp"));
        m.insert("mssql", (1433, "tcp"));
        m.insert("oracle", (1521, "tcp"));
        m.insert("ftp-data", (20, "tcp"));
        m.insert("smtps", (465, "tcp"));
        m.insert("pop3s", (995, "tcp"));
        m.insert("imaps", (993, "tcp"));
        m.insert("sip", (5060, "udp"));
        m.insert("sips", (5061, "tcp"));
        m.insert("dhcp", (67, "udp"));
        m.insert("tftp", (69, "udp"));
        m.insert("rpcbind", (111, "tcp"));
        m.insert("nfs", (2049, "tcp"));
        m.insert("rsync", (873, "tcp"));
        m.insert("mysqlx", (33060, "tcp"));
        m.insert("postgresql", (5432, "tcp"));
        m.insert("couchdb", (5984, "tcp"));
        m.insert("grafana", (3000, "tcp"));
        m.insert("prometheus", (9090, "tcp"));
        m.insert("jenkins", (8080, "tcp"));
        m.insert("jmx", (9010, "tcp"));
        m.insert("docker", (2375, "tcp"));
        m.insert("kubernetes", (6443, "tcp"));
        m.insert("etcd", (2379, "tcp"));
        m.insert("consul", (8500, "tcp"));
        m.insert("zookeeper", (2181, "tcp"));
        m.insert("cassandra", (9042, "tcp"));
        m.insert("hbase", (16000, "tcp"));
        m.insert("hdfs", (9870, "tcp"));
        m.insert("zabbix", (10051, "tcp"));
        m.insert("nginx", (80, "tcp"));
        m.insert("apache", (80, "tcp"));
        m.insert("tomcat", (8080, "tcp"));
        m.insert("weblogic", (7001, "tcp"));
        m.insert("websphere", (9080, "tcp"));
        m.insert("caddy", (2019, "tcp"));
        m.insert("haproxy", (8404, "tcp"));
        m.insert("minio", (9000, "tcp"));
        m.insert("git", (9418, "tcp"));
        m.insert("mercurial", (8000, "tcp"));
        m.insert("svn", (3690, "tcp"));
        m.insert("npm", (4873, "tcp"));
        m.insert("reverse-proxy", (8888, "tcp"));
        m.insert("raw", (6667, "tcp"));
        m.insert("irc", (6667, "tcp"));
        m.insert("xmpp", (5222, "tcp"));
        m.insert("kerberos", (88, "tcp"));
        m.insert("kpasswd", (464, "tcp"));
        m.insert("activemq", (61616, "tcp"));
        m.insert("activemq-amqp", (5672, "tcp"));
        m.insert("activemq-stomp", (61613, "tcp"));
        m
    })
}

pub fn register_datafiles_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let datafiles = lua.create_table()?;

    datafiles.set(
        "get_protocols",
        lua.create_function(|_lua, _: ()| {
            let protocols = _lua.create_table()?;
            let map = get_protocols();

            let mut i = 1;
            for (name, number) in map {
                let entry = _lua.create_table()?;
                entry.set("name", *name)?;
                entry.set("number", *number)?;
                protocols.set(i, entry)?;
                i += 1;
            }

            Ok(protocols)
        })?,
    )?;

    datafiles.set(
        "get_services",
        lua.create_function(|_lua, _: ()| {
            let services = _lua.create_table()?;
            let map = get_services();

            let mut i = 1;
            for (name, (port, proto)) in map {
                let entry = _lua.create_table()?;
                entry.set("name", *name)?;
                entry.set("port", *port)?;
                entry.set("protocol", *proto)?;
                services.set(i, entry)?;
                i += 1;
            }

            Ok(services)
        })?,
    )?;

    datafiles.set(
        "get_rpc",
        lua.create_function(|_lua, _: ()| {
            let rpc = _lua.create_table()?;

            let entries = [
                ("100000", "portmapper", "2,3,4"),
                ("100001", "rstatd", "2,3,4"),
                ("100002", "rusersd", "2,3"),
                ("100003", "nfs", "2,3,4"),
                ("100004", "ypserv", "2"),
                ("100005", "mountd", "1,2,3,4"),
                ("100006", "nfs_acl", "2,3"),
                ("100007", "ypbind", "2,3"),
                ("100008", "wall", "1"),
                ("100009", "yppasswd", "1"),
                ("100010", "etherstatd", "1"),
                ("100011", "rquotad", "1,2"),
                ("100012", "sprayd", "1"),
                ("100017", "llockmgr", "1,2,3"),
                ("100018", "nfsd", "2,3,4"),
                ("100020", "status", "1,2,3"),
                ("100021", "nfs_acl", "2,3"),
                ("100022", "cmsd", "1,2"),
                ("100023", "ttdbserverd", "1"),
                ("100024", "nfsd", "4"),
            ];

            let mut i = 1;
            for (number, name, versions) in entries {
                let entry = _lua.create_table()?;
                entry.set("number", number)?;
                entry.set("name", name)?;
                entry.set("versions", versions)?;
                rpc.set(i, entry)?;
                i += 1;
            }

            Ok(rpc)
        })?,
    )?;

    datafiles.set(
        "get_mac_prefixes",
        lua.create_function(|_lua, _: ()| {
            let prefixes = _lua.create_table()?;

            let entries = [
                ("000000", "Xerox"),
                ("000001", "Xerox"),
                ("000002", "Xerox"),
                ("00000C", "Cisco"),
                ("0001E7", "Juniper"),
                ("0002B3", "Nortel"),
                ("000347", "Alcatel"),
                ("00061B", "Dell"),
                ("000CF1", "Dell"),
                ("0011BB", "Hewlett-Packard"),
                ("001320", "IBM"),
                ("00155D", "Microsoft"),
                ("001E68", "Quanta"),
                ("002170", "Quanta"),
                ("002436", "Apple"),
                ("0025AE", "Microsoft"),
                ("0026AB", "D-Link"),
                ("002710", "Linksys"),
                ("002719", "Netgear"),
                ("003018", "Supermicro"),
                ("0050F2", "Microsoft"),
                ("001A2B", "Unknown"),
                ("001E52", "Cisco-Linksys"),
                ("001F33", "Cisco-Linksys"),
                ("00223F", "Cisco-Linksys"),
                ("002354", "Cisco-Linksys"),
            ];

            let mut i = 1;
            for (prefix, vendor) in entries {
                let entry = _lua.create_table()?;
                entry.set("prefix", prefix)?;
                entry.set("vendor", vendor)?;
                prefixes.set(i, entry)?;
                i += 1;
            }

            Ok(prefixes)
        })?,
    )?;

    datafiles.set(
        "get_ip_protos",
        lua.create_function(|_lua, _: ()| {
            let protos = _lua.create_table()?;

            let entries = [
                (1, "icmp"),
                (6, "tcp"),
                (17, "udp"),
                (47, "gre"),
                (50, "esp"),
                (51, "ah"),
                (58, "icmpv6"),
                (89, "ospf"),
                (115, "l2tp"),
                (132, "sctp"),
            ];

            for (number, name) in entries {
                let entry = _lua.create_table()?;
                entry.set("number", number)?;
                entry.set("name", name)?;
                protos.set(number, entry)?;
            }

            Ok(protos)
        })?,
    )?;

    datafiles.set(
        "parse_nmap_services",
        lua.create_function(|lua, filename: Option<String>| {
            let services = lua.create_table()?;

            let default_paths = [
                "/usr/local/share/nmap/nmap-services",
                "/usr/share/nmap/nmap-services",
                "/opt/nmap/share/nmap/nmap-services",
            ];

            let content = if let Some(ref f) = filename {
                std::fs::read_to_string(f).ok()
            } else {
                for path in &default_paths {
                    if let Ok(_c) = std::fs::read_to_string(path) {
                        break;
                    }
                }
                None
            };

            if let Some(c) = content {
                for line in c.lines() {
                    if line.starts_with('#') || line.is_empty() {
                        continue;
                    }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let name = parts[0];
                        let port_proto = parts[1];
                        if let Some((port, proto)) = port_proto.split_once('/') {
                            let entry = lua.create_table()?;
                            entry.set("name", name).ok();
                            entry.set("port", port).ok();
                            entry.set("protocol", proto).ok();
                            services.set(name, entry).ok();
                        }
                    }
                }
            }

            Ok(services)
        })?,
    )?;

    datafiles.set(
        "parse_nmap_protocols",
        lua.create_function(|lua, filename: Option<String>| {
            let protocols = lua.create_table()?;

            let _default_paths = [
                "/usr/local/share/nmap/nmap-protocols",
                "/usr/share/nmap/nmap-protocols",
                "/opt/nmap/share/nmap/nmap-protocols",
            ];

            let content = if let Some(ref f) = filename {
                std::fs::read_to_string(f).ok()
            } else {
                None
            };

            if let Some(c) = content {
                for line in c.lines() {
                    if line.starts_with('#') || line.is_empty() {
                        continue;
                    }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let name = parts[0];
                        let number: u16 = parts[1].parse().unwrap_or(0);
                        if number > 0 {
                            let entry = lua.create_table()?;
                            entry.set("name", name).ok();
                            entry.set("number", number).ok();
                            protocols.set(number as i32, entry).ok();
                        }
                    }
                }
            }

            Ok(protocols)
        })?,
    )?;

    globals.set("datafiles", datafiles)?;
    Ok(())
}
