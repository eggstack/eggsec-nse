//! NSE pop3 library wrapper
//!
//! POP3 (Post Office Protocol v3) support for NSE scripts.
//! Includes both blocking and async implementations.

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, broker_tcp_receive, broker_tcp_send, NseHostServices};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

fn pop3_send(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    host: &str,
    port: u16,
    command: &str,
    operation: &'static str,
) -> Result<String, mlua::Error> {
    // The broker resolves `host` (authority-preserving) instead of requiring
    // a literal `SocketAddr` string. Connection/refused/denied failures keep
    // the original `RuntimeError` shape via the `?` call sites below.
    let (mut handle, _endpoint) = broker_tcp_connect(
        ctx,
        services,
        host,
        port,
        Duration::from_secs(10),
        operation,
    )
    .map_err(mlua::Error::runtime)?;

    // The provider exposes a single read/write timeout (original: read 30s,
    // write 10s); keep the larger bound and note the delta.
    handle
        .set_timeouts(Duration::from_secs(30))
        .map_err(|e| mlua::Error::runtime(e.to_string()))?;

    let mut written = 0;
    let bytes = command.as_bytes();
    while written < bytes.len() {
        let n = broker_tcp_send(ctx, handle.as_mut(), &bytes[written..], operation)
            .map_err(mlua::Error::runtime)?;
        if n == 0 {
            return Err(mlua::Error::runtime("pop3: send wrote zero bytes"));
        }
        written += n;
    }

    let mut response = String::new();
    loop {
        // The original performed repeated `read` calls until NUL/EOF or the
        // first CRLF; an empty broker receive means EOF.
        let data = broker_tcp_receive(ctx, handle.as_mut(), 8192, operation)
            .map_err(mlua::Error::runtime)?;
        if data.is_empty() {
            break;
        }
        response.push_str(&String::from_utf8_lossy(&data));
        if response.contains("\r\n") {
            break;
        }
    }

    Ok(response)
}

fn pop3_send_with_body(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    host: &str,
    port: u16,
    command: &str,
    operation: &'static str,
) -> Result<String, mlua::Error> {
    let (mut handle, _endpoint) = broker_tcp_connect(
        ctx,
        services,
        host,
        port,
        Duration::from_secs(10),
        operation,
    )
    .map_err(mlua::Error::runtime)?;

    handle
        .set_timeouts(Duration::from_secs(30))
        .map_err(|e| mlua::Error::runtime(e.to_string()))?;

    let mut written = 0;
    let bytes = command.as_bytes();
    while written < bytes.len() {
        let n = broker_tcp_send(ctx, handle.as_mut(), &bytes[written..], operation)
            .map_err(mlua::Error::runtime)?;
        if n == 0 {
            return Err(mlua::Error::runtime("pop3: send wrote zero bytes"));
        }
        written += n;
    }

    let mut response = String::new();

    loop {
        let data = broker_tcp_receive(ctx, handle.as_mut(), 8192, operation)
            .map_err(mlua::Error::runtime)?;
        if data.is_empty() {
            break;
        }
        let chunk = String::from_utf8_lossy(&data);
        response.push_str(&chunk);

        if response.ends_with("\r\n.\r\n") {
            break;
        }

        if response.len() > 1024 * 1024 {
            break;
        }
    }

    Ok(response)
}

/// Reject POP3 argument values containing CR/LF so Lua-supplied
/// credentials cannot inject additional protocol commands.
fn reject_crlf(value: &str, field: &str) -> Result<(), mlua::Error> {
    if value.contains('\r') || value.contains('\n') {
        return Err(mlua::Error::RuntimeError(format!(
            "pop3: {} must not contain CR or LF",
            field
        )));
    }
    Ok(())
}

/// Provider-backed pop3 registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_pop3_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let pop3 = lua.create_table()?;

    let connect_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port): (String, u16)| {
            let response = pop3_send(&ctx, &services, &host, port, "", "pop3.connect")?;
            let result = lua.create_table()?;
            result.set("host", host.clone())?;
            result.set("port", port)?;
            result.set(
                "status",
                if response.starts_with("+OK") {
                    "connected"
                } else {
                    "failed"
                },
            )?;
            result.set("greeting", response.lines().next().unwrap_or(""))?;
            Ok(result)
        }
    })?;
    pop3.set("connect", connect_fn)?;

    let user_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, username): (String, u16, String)| {
            reject_crlf(&username, "username")?;
            let tag = format!("USER {}\r\n", username);
            let response = pop3_send(&ctx, &services, &host, port, &tag, "pop3.user")?;
            let result = lua.create_table()?;
            result.set("success", response.starts_with("+OK"))?;
            result.set("user", username)?;
            result.set("response", response.trim())?;
            Ok(result)
        }
    })?;
    pop3.set("user", user_fn)?;

    let pass_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, password): (String, u16, String)| {
            reject_crlf(&password, "password")?;
            let tag = format!("PASS {}\r\n", password);
            let response = pop3_send(&ctx, &services, &host, port, &tag, "pop3.pass")?;
            let result = lua.create_table()?;
            result.set("success", response.starts_with("+OK"))?;
            result.set("response", response.trim())?;
            Ok(result)
        }
    })?;
    pop3.set("pass", pass_fn)?;

    let stat_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port): (String, u16)| {
            let response = pop3_send(&ctx, &services, &host, port, "STAT\r\n", "pop3.stat")?;
            let result = lua.create_table()?;

            if response.starts_with("+OK") {
                let parts: Vec<&str> = response.split_whitespace().collect();
                if parts.len() >= 3 {
                    result.set("messages", parts[1].parse::<u32>().unwrap_or(0))?;
                    result.set("octets", parts[2].parse::<u64>().unwrap_or(0))?;
                }
            }
            result.set("success", response.starts_with("+OK"))?;
            Ok(result)
        }
    })?;
    pop3.set("stat", stat_fn)?;

    let list_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, msg): (String, u16, Option<u32>)| {
            let cmd = match msg {
                Some(n) => format!("LIST {}\r\n", n),
                None => "LIST\r\n".to_string(),
            };
            let response = pop3_send(&ctx, &services, &host, port, &cmd, "pop3.list")?;
            let result = lua.create_table()?;

            let messages = lua.create_table()?;

            if response.starts_with("+OK") {
                let mut idx = 1;
                for line in response.lines().skip(1) {
                    if line.starts_with('.') || line.is_empty() {
                        continue;
                    }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let msg_entry = lua.create_table()?;
                        msg_entry.set("number", parts[0].parse::<u32>().unwrap_or(0))?;
                        msg_entry.set("size", parts[1].parse::<u64>().unwrap_or(0))?;
                        messages.set(idx, msg_entry)?;
                        idx += 1;
                    }
                }
            }

            result.set("messages", messages)?;
            result.set("success", response.starts_with("+OK"))?;
            Ok(result)
        }
    })?;
    pop3.set("list", list_fn)?;

    let retr_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, message_num): (String, u16, u32)| {
            let cmd = format!("RETR {}\r\n", message_num);
            let response = pop3_send_with_body(&ctx, &services, &host, port, &cmd, "pop3.retr")?;
            let result = lua.create_table()?;

            if response.starts_with("+OK") {
                let body_start = response.find("\r\n\r\n").map(|i| i + 4).unwrap_or(4);
                let body = &response[body_start..];
                let body_clean = body.trim_start_matches('\n').trim_end_matches("\r\n.\r\n");

                result.set("number", message_num)?;
                result.set("body", body_clean)?;
                result.set("size", body_clean.len() as u64)?;
            }

            result.set("success", response.starts_with("+OK"))?;
            Ok(result)
        }
    })?;
    pop3.set("retr", retr_fn)?;

    let top_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, message_num, lines): (String, u16, u32, u32)| {
            let cmd = format!("TOP {} {}\r\n", message_num, lines);
            let response = pop3_send(&ctx, &services, &host, port, &cmd, "pop3.top")?;
            let result = lua.create_table()?;

            if response.starts_with("+OK") {
                let parts: Vec<&str> = response.split("\r\n\r\n").collect();
                let header = parts
                    .first()
                    .unwrap_or(&"")
                    .lines()
                    .skip(1)
                    .collect::<Vec<_>>()
                    .join("\r\n");
                let body = parts.get(1).unwrap_or(&"").trim_end_matches("\r\n.\r\n");

                result.set("number", message_num)?;
                result.set("header", header)?;
                result.set("body", body)?;
            }

            result.set("success", response.starts_with("+OK"))?;
            Ok(result)
        }
    })?;
    pop3.set("top", top_fn)?;

    let dele_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, message_num): (String, u16, u32)| {
            let cmd = format!("DELE {}\r\n", message_num);
            let response = pop3_send(&ctx, &services, &host, port, &cmd, "pop3.dele")?;
            let result = lua.create_table()?;
            result.set("success", response.starts_with("+OK"))?;
            result.set("deleted", message_num)?;
            result.set("response", response.trim())?;
            Ok(result)
        }
    })?;
    pop3.set("dele", dele_fn)?;

    let uidl_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, msg): (String, u16, Option<u32>)| {
            let cmd = match msg {
                Some(n) => format!("UIDL {}\r\n", n),
                None => "UIDL\r\n".to_string(),
            };
            let response = pop3_send(&ctx, &services, &host, port, &cmd, "pop3.uidl")?;
            let result = lua.create_table()?;

            let ids = lua.create_table()?;

            if response.starts_with("+OK") {
                let mut idx = 1;
                for line in response.lines().skip(1) {
                    if line.starts_with('.') || line.is_empty() {
                        continue;
                    }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let entry = lua.create_table()?;
                        entry.set("number", parts[0].parse::<u32>().unwrap_or(0))?;
                        entry.set("uid", parts[1])?;
                        ids.set(idx, entry)?;
                        idx += 1;
                    }
                }
            }

            result.set("ids", ids)?;
            result.set("success", response.starts_with("+OK"))?;
            Ok(result)
        }
    })?;
    pop3.set("uidl", uidl_fn)?;

    let noop_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port): (String, u16)| {
            let response = pop3_send(&ctx, &services, &host, port, "NOOP\r\n", "pop3.noop")?;
            let result = lua.create_table()?;
            result.set("success", response.starts_with("+OK"))?;
            result.set("response", response.trim())?;
            Ok(result)
        }
    })?;
    pop3.set("noop", noop_fn)?;

    let rset_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port): (String, u16)| {
            let response = pop3_send(&ctx, &services, &host, port, "RSET\r\n", "pop3.rset")?;
            let result = lua.create_table()?;
            result.set("success", response.starts_with("+OK"))?;
            result.set("response", response.trim())?;
            Ok(result)
        }
    })?;
    pop3.set("rset", rset_fn)?;

    let quit_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port): (String, u16)| {
            let response = pop3_send(&ctx, &services, &host, port, "QUIT\r\n", "pop3.quit")?;
            let result = lua.create_table()?;
            result.set("success", response.starts_with("+OK"))?;
            result.set("response", response.trim())?;
            Ok(result)
        }
    })?;
    pop3.set("quit", quit_fn)?;

    let capa_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port): (String, u16)| {
            let response = pop3_send(&ctx, &services, &host, port, "CAPA\r\n", "pop3.capa")?;
            let result = lua.create_table()?;

            let capabilities = lua.create_table()?;

            if response.starts_with("+OK") {
                let mut idx = 1;
                for line in response.lines().skip(1) {
                    if line.starts_with('.') || line.is_empty() {
                        continue;
                    }
                    capabilities.set(idx, line)?;
                    idx += 1;
                }
            }

            result.set("capabilities", capabilities)?;
            result.set("success", response.starts_with("+OK"))?;
            Ok(result)
        }
    })?;
    pop3.set("capa", capa_fn)?;

    let apop_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, username, digest): (String, u16, String, String)| {
            reject_crlf(&username, "username")?;
            reject_crlf(&digest, "digest")?;
            let cmd = format!("APOP {} {}\r\n", username, digest);
            let response = pop3_send(&ctx, &services, &host, port, &cmd, "pop3.apop")?;
            let result = lua.create_table()?;
            result.set("success", response.starts_with("+OK"))?;
            result.set("response", response.trim())?;
            Ok(result)
        }
    })?;
    pop3.set("apop", apop_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    pop3.set("version", version_fn)?;

    globals.set("pop3", pop3)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{NseExecutionLimits, NseResourceCounters};
    use crate::profile::{
        NseExecutionProfileKind, NseModulePolicy, NseNetworkPolicy, NseScriptPolicy,
    };
    use std::sync::Arc;

    fn test_context() -> NseCapabilityContext {
        NseCapabilityContext::new(
            NseExecutionProfileKind::ManualPermissive,
            NseNetworkPolicy::AllowAllManual,
            NseScriptPolicy {
                allow_builtin_scripts: true,
                allow_script_files: true,
                allowed_script_roots: Vec::new(),
                allow_conventional_nmap_paths: true,
                max_script_bytes: None,
            },
            NseModulePolicy {
                allow_builtin_modules: true,
                allow_filesystem_modules: true,
                allowed_module_roots: Vec::new(),
                max_module_bytes: None,
            },
            crate::SandboxConfig::default(),
            NseExecutionLimits::default(),
            crate::NseCancellationToken::new(),
            Arc::new(NseResourceCounters::new()),
        )
    }

    #[test]
    fn user_pass_apop_reject_crlf_before_network() {
        let lua = Lua::new();
        let ctx = test_context();
        register_pop3_library_with_services(&lua, &ctx, &NseHostServices::native())
            .expect("pop3 library must register");
        for chunk in [
            r#"return pop3.user("127.0.0.1", 9, "alice\r\nDELE 1")"#,
            r#"return pop3.pass("127.0.0.1", 9, "s3cret\nQUIT")"#,
            r#"return pop3.apop("127.0.0.1", 9, "alice", "d\ngest")"#,
        ] {
            let err = lua
                .load(chunk)
                .call::<mlua::Table>(())
                .expect_err("CRLF credentials must be rejected");
            assert!(
                err.to_string().contains("must not contain CR or LF"),
                "unexpected error: {}",
                err
            );
        }
    }
}
