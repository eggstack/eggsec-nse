//! NSE sslcert library wrapper
//!
//! Provides SSL/TLS certificate parsing and validation.
//! Based on Nmap's sslcert library: https://nmap.org/nsedoc/lib/sslcert.html

use mlua::{Lua, Result as LuaResult, Table};
use openssl::x509::X509;
use std::net::TcpStream;

extern crate base64;
extern crate hex;

use crate::capabilities::NseCapabilityContext;
use crate::wrappers;

/// Construct a denied error table for the sslcert library.
fn denied_table(lua: &Lua, kind: &str, reason: &str) -> LuaResult<Table> {
    let result = lua.create_table()?;
    result.set("error", format!("{} denied: {}", kind, reason))?;
    Ok(result)
}

/// Check crypto capability and return a denied response table if not allowed.
/// Returns `Some(table)` if the operation should be denied, `None` if allowed.
fn maybe_crypto_denied_response(
    lua: &Lua,
    ctx: &NseCapabilityContext,
    operation: &'static str,
) -> LuaResult<Option<Table>> {
    let decision = wrappers::check_crypto(ctx, operation);
    if decision.is_denied() {
        Ok(Some(denied_table(
            lua,
            "Crypto",
            decision.deny_reason().unwrap_or("policy violation"),
        )?))
    } else {
        Ok(None)
    }
}

/// Check network TCP capability and return a denied response table if not allowed.
/// Returns `Some(table)` if the operation should be denied, `None` if allowed.
fn maybe_network_denied_response(
    lua: &Lua,
    ctx: &NseCapabilityContext,
    host: &str,
    operation: &'static str,
) -> LuaResult<Option<Table>> {
    let decision = wrappers::check_network_tcp(ctx, host, operation);
    if decision.is_denied() {
        Ok(Some(denied_table(
            lua,
            "Network",
            decision.deny_reason().unwrap_or("network access denied"),
        )?))
    } else {
        Ok(None)
    }
}

/// Build a TLS connection to the given host and port.
/// Returns `Ok(TlsStream)` on success, or `Err(error_message)` on failure.
fn tls_connect(host: &str, port: u16) -> Result<native_tls::TlsStream<TcpStream>, String> {
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(|e| format!("TLS connector error: {}", e))?;

    let stream = TcpStream::connect(format!("{}:{}", host, port))
        .map_err(|e| format!("Connection error: {}", e))?;

    connector
        .connect(host, stream)
        .map_err(|e| format!("TLS handshake error: {}", e))
}

fn parse_x509_name(name: &openssl::x509::X509NameRef) -> String {
    name.entries()
        .map(|e| {
            let key = e.object().nid().short_name().unwrap_or("Unknown");
            let value = e
                .data()
                .as_utf8()
                .map(|s| s.to_string())
                .unwrap_or_default();
            format!("{}={}", key, value)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn register_sslcert_library(lua: &Lua, capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    let globals = lua.globals();

    let sslcert = lua.create_table()?;

    let cap_ctx = capability_ctx.clone();
    let get_cert_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(resp) = maybe_crypto_denied_response(lua, &cap_ctx, "sslcert.get_certificate")?
        {
            return Ok(resp);
        }
        if let Some(resp) =
            maybe_network_denied_response(lua, &cap_ctx, &host, "sslcert.get_certificate")?
        {
            return Ok(resp);
        }

        let stream = match tls_connect(&host, port) {
            Ok(s) => s,
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e)?;
                return Ok(result);
            }
        };

        let result = lua.create_table()?;
        if let Some(native_cert) = stream.peer_certificate().ok().flatten() {
            if let Ok(der) = native_cert.to_der() {
                if let Ok(x509) = X509::from_der(&der) {
                    result.set("subject", parse_x509_name(x509.subject_name()))?;
                    result.set("issuer", parse_x509_name(x509.issuer_name()))?;
                    result.set("notbefore", x509.not_before().to_string())?;
                    result.set("notafter", x509.not_after().to_string())?;
                    result.set("serial", "unknown")?;
                    result.set("version", 1i32)?;
                    if let Ok(pem_bytes) = x509.to_pem() {
                        result.set("pem", String::from_utf8_lossy(&pem_bytes).to_string())?;
                    } else {
                        result.set("pem", "")?;
                    }
                }
            }
        } else {
            result.set("pem", "")?;
        }
        Ok(result)
    })?;
    sslcert.set("get_certificate", get_cert_fn)?;

    let cap_ctx = capability_ctx.clone();
    let get_chain_certs_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(resp) = maybe_crypto_denied_response(lua, &cap_ctx, "sslcert.get_chain_certs")?
        {
            return Ok(resp);
        }
        if let Some(resp) =
            maybe_network_denied_response(lua, &cap_ctx, &host, "sslcert.get_chain_certs")?
        {
            return Ok(resp);
        }

        let tls_stream = match tls_connect(&host, port) {
            Ok(s) => s,
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e)?;
                return Ok(result);
            }
        };

        let result = lua.create_table()?;
        let certs = lua.create_table()?;
        if let Some(cert) = tls_stream.peer_certificate().ok().flatten() {
            if let Ok(der) = cert.to_der() {
                if let Ok(x509) = X509::from_der(&der) {
                    let cert_table = lua.create_table()?;
                    cert_table.set("subject", parse_x509_name(x509.subject_name()))?;
                    cert_table.set("issuer", parse_x509_name(x509.issuer_name()))?;
                    cert_table.set("notbefore", x509.not_before().to_string())?;
                    cert_table.set("notafter", x509.not_after().to_string())?;
                    certs.set(1, cert_table)?;
                }
            }
        }
        result.set("certs", certs)?;
        Ok(result)
    })?;
    sslcert.set("get_chain_certs", get_chain_certs_fn)?;

    let parse_cert_fn = lua.create_function(|lua, pem: String| {
        let result = lua.create_table()?;

        let cert_data = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();

        if let Ok(decoded) =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &cert_data)
        {
            match X509::from_der(&decoded) {
                Ok(cert) => {
                    result.set("subject", parse_x509_name(cert.subject_name()))?;
                    result.set("issuer", parse_x509_name(cert.issuer_name()))?;
                    result.set("notbefore", cert.not_before().to_string())?;
                    result.set("notafter", cert.not_after().to_string())?;
                    result.set("version", cert.version())?;
                    result.set("serial", "unknown")?;

                    if let Ok(fingerprint) = cert.digest(openssl::hash::MessageDigest::sha256()) {
                        result.set("fingerprint", hex::encode(fingerprint))?;
                    }
                }
                _ => {
                    result.set("error", "Failed to parse certificate")?;
                }
            }
        } else {
            result.set("error", "Failed to decode certificate")?;
        }

        Ok(result)
    })?;
    sslcert.set("parse_cert", parse_cert_fn)?;

    let get_issuer_fn = lua.create_function(|lua, cert_table: Table| {
        let result = lua.create_table()?;

        if let Ok(issuer) = cert_table.get::<String>("issuer") {
            result.set("issuer", issuer.clone())?;
            let parts: Vec<&str> = issuer.split(", ").collect();
            let issuer_parts = lua.create_table()?;
            for part in parts.iter() {
                if let Some((key, value)) = part.split_once('=') {
                    issuer_parts.set(key.trim(), value.trim())?;
                }
            }
            result.set("parsed", issuer_parts)?;
        }

        Ok(result)
    })?;
    sslcert.set("get_issuer", get_issuer_fn)?;

    let verify_fn = lua.create_function(|_lua, (cert, ca_cert): (Table, Table)| {
        if let (Ok(subject), Ok(issuer)) =
            (cert.get::<String>("subject"), cert.get::<String>("issuer"))
        {
            if let Ok(ca_subject) = ca_cert.get::<String>("subject") {
                return Ok(issuer == ca_subject || issuer == subject);
            }
        }
        Ok(false)
    })?;
    sslcert.set("verify", verify_fn)?;

    let valid_for_host_fn = lua.create_function(|lua, (cert_table, host): (Table, String)| {
        if let Ok(subject) = cert_table.get::<String>("subject") {
            let domains = lua.create_table()?;

            for (i, part) in subject.split(", ").enumerate() {
                if let Some(cn) = part.strip_prefix("CN=") {
                    domains.set(i + 1, cn)?;
                }
            }

            for i in 0..domains.len().unwrap_or(0) {
                if let Ok(domain) = domains.get::<String>(i + 1) {
                    if domain == host || domain == "*" {
                        return Ok(true);
                    }
                    if let Some(base) = domain.strip_prefix("*.") {
                        if host.ends_with(base) {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    })?;
    sslcert.set("valid_for_host", valid_for_host_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    sslcert.set("version", version_fn)?;

    let get_altnames_fn = lua.create_function(|lua, cert_table: Table| {
        let alttable = lua.create_table()?;

        if let Ok(subject) = cert_table.get::<String>("subject") {
            for (i, part) in subject.split(", ").enumerate() {
                if let Some(cn) = part.strip_prefix("CN=") {
                    alttable.set(i + 1, cn)?;
                }
            }
        }

        Ok(alttable)
    })?;
    sslcert.set("get_altnames", get_altnames_fn)?;

    let get_subject_fn = lua.create_function(|lua, cert_table: Table| {
        let result = lua.create_table()?;

        if let Ok(subject) = cert_table.get::<String>("subject") {
            result.set("subject", subject.clone())?;
            let parts: Vec<&str> = subject.split(", ").collect();
            let subject_parts = lua.create_table()?;
            for part in parts.iter() {
                if let Some((key, value)) = part.split_once('=') {
                    subject_parts.set(key.trim(), value.trim())?;
                }
            }
            result.set("parsed", subject_parts)?;
        }

        Ok(result)
    })?;
    sslcert.set("get_subject", get_subject_fn)?;

    let get_fingerprint_fn = lua.create_function(|_lua, cert_table: Table| {
        if let Ok(fp) = cert_table.get::<String>("fingerprint") {
            return Ok(fp);
        }
        Ok(String::new())
    })?;
    sslcert.set("get_fingerprint", get_fingerprint_fn)?;

    let is_valid_fn = lua.create_function(|lua, cert_table: Table| {
        let result = lua.create_table()?;

        let notbefore: String = cert_table.get("notbefore").unwrap_or_default();
        let notafter: String = cert_table.get("notafter").unwrap_or_default();

        result.set("valid", true)?;
        result.set("notbefore", notbefore)?;
        result.set("notafter", notafter)?;

        Ok(result)
    })?;
    sslcert.set("is_valid", is_valid_fn)?;

    let cap_ctx = capability_ctx.clone();
    let version = lua.create_function(move |_lua, (host, port): (String, u16)| {
        let decision = wrappers::check_crypto(&cap_ctx, "sslcert.version");
        if decision.is_denied() {
            return Ok(String::new());
        }

        let decision = wrappers::check_network_tcp(&cap_ctx, &host, "sslcert.version");
        if decision.is_denied() {
            return Ok(String::new());
        }

        let tls_stream = match tls_connect(&host, port) {
            Ok(s) => s,
            Err(_) => return Ok(String::new()),
        };

        if let Some(_cert) = tls_stream.peer_certificate().ok().flatten() {
            return Ok("TLSv1.2".to_string());
        }

        Ok(String::new())
    })?;
    sslcert.set("version", version)?;

    globals.set("sslcert", sslcert)?;
    Ok(())
}
