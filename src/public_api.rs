//! NSE Public API - Exposes NSE libraries for use by eggsec core
//!
//! This module provides public APIs to NSE libraries for use by other
//! eggsec tools (scanner, fuzzer, etc.)
//!
//! # Usage
//!
//! ```ignore
//! use eggsec::nse::api::*;
//!
//! // CVE lookup
//! let cve = nse_vulns_lookup("CVE-2017-0144")?;
//!
//! // SSL Certificate
//! let cert = nse_sslcert_get("example.com", 443)?;
//!
//! // HTTP Request
//! let response = nse_http_get("example.com", 80, "/")?;
//! ```

pub mod api;

pub use api::{
    nse_dns_resolve,
    nse_dns_reverse,
    nse_http_get,
    nse_http_post,
    nse_http_request,
    nse_mysql_get_version,
    nse_redis_ping,
    nse_smb_get_info,
    nse_snmp_get_sysinfo,
    nse_ssh_get_info,
    nse_sslcert_get,
    nse_sslcert_get_chain,
    nse_vulns_is_known,
    nse_vulns_lookup,
    nse_vulns_search,
    // DNS
    NseDnsResult,
    NseHttpRequest,
    NseHttpResponse,
    // MySQL
    NseMysqlResult,
    // Redis
    NseRedisResult,
    // SMB
    NseSmbResult,
    // SNMP
    NseSnmpResult,
    // SSH
    NseSshResult,
    NseSslCertResult,
    NseVulnResult,
};

pub mod prelude {
    pub use super::api::*;
}
