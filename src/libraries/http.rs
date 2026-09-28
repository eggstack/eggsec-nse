//! NSE http library wrapper
//!
//! Provides HTTP client functionality compatible with NSE scripts.
//!
//! M005C: all request execution goes through the injected
//! [`NseHttpProvider`] via the capability-aware [`broker_http_request`]
//! broker. The process-global HTTP clients and TLS-accept flags are
//! gone; TLS intent travels per request from the capability profile, and
//! connection pooling lives in the per-bundle native provider. Lua method
//! and result shapes are unchanged.

use mlua::{Lua, Result as LuaResult, Table};
use std::time::Duration;

use super::helpers::or_fallback_table;
use crate::capabilities::NseCapabilityContext;
use crate::providers::{
    broker_http_request, NseHostServices, NseHttpError, NseHttpMethod, NseHttpRequest,
    NseHttpResponse,
};
use crate::wrappers;

// Legacy process-global TLS flags: no callers remain. Retained as
// deprecated no-op shims so downstream code keeps compiling; per-run TLS
// intent is profile-gated through the broker request DTO.
#[deprecated(
    note = "TLS intent is now per-run and profile-gated; this flag no longer affects execution"
)]
pub fn set_accept_invalid_certs(_accept: bool) {}

/// See [`set_accept_invalid_certs`].
#[deprecated(
    note = "TLS intent is now per-run and profile-gated; this flag no longer affects execution"
)]
pub fn set_accept_invalid_hostnames(_accept: bool) {}

fn build_url(host: &str, port: u16, path: &str) -> String {
    if host.starts_with("http") {
        format!("{}{}", host.trim_end_matches('/'), path)
    } else {
        let scheme = if port == 443 || port == 8443 || port == 9443 {
            "https"
        } else {
            "http"
        };
        format!("{}://{}:{}{}", scheme, host, port, path)
    }
}

/// Build a provider request from Lua-level inputs.
///
/// TLS intent comes from the capability profile (never scripts); unknown
/// methods fall back to GET at this layer to preserve legacy leniency
/// (`NseHttpMethod::parse` itself fails closed for direct broker callers).
fn provider_request(
    ctx: &NseCapabilityContext,
    method: NseHttpMethod,
    url: String,
    host: &str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    timeout: Duration,
) -> NseHttpRequest {
    NseHttpRequest {
        method,
        url,
        host: host.to_string(),
        headers,
        body,
        timeout: timeout.max(Duration::from_secs(1)),
        connect_timeout: Duration::from_secs(10),
        insecure_tls: ctx.allows_insecure_tls(),
    }
}

fn build_response(lua: &Lua, resp: &NseHttpResponse) -> LuaResult<Table> {
    let result = lua.create_table()?;

    result.set("status", resp.status as i32)?;

    let headers_table = lua.create_table()?;
    let headers_map = lua.create_table()?;
    for (i, (k, v)) in resp.headers.iter().enumerate() {
        headers_table.set(i + 1, format!("{}: {}", k, v))?;
        headers_map.set(k.clone(), v.clone())?;
    }
    result.set("headers", headers_table)?;
    result.set("header", headers_map)?;

    result.set("version", resp.version.clone())?;

    if (300..400).contains(&resp.status) {
        if let Some(location) = resp.header("location") {
            result.set("location", location.to_string())?;
        }
    }

    let https = resp.final_url.starts_with("https");
    result.set("body", resp.body_text())?;

    result.set("https", https)?;

    Ok(result)
}

fn error_response(lua: &Lua, err: &NseHttpError) -> LuaResult<Table> {
    let result = lua.create_table()?;
    result.set("status", 0i32)?;
    result.set("error", err.detail())?;
    result.set("reason", err.reason())?;
    Ok(result)
}

fn denied_response(lua: &Lua, reason: &str) -> LuaResult<Table> {
    let result = lua.create_table()?;
    result.set("status", 0i32)?;
    result.set("error", reason.to_string())?;
    result.set("reason", "denied")?;
    Ok(result)
}

/// Check network TCP capability and return a denied response table if not allowed.
/// Returns `Some(table)` if the request should be denied, `None` if allowed.
fn maybe_denied_response(
    lua: &Lua,
    ctx: &NseCapabilityContext,
    host: &str,
    operation: &'static str,
) -> LuaResult<Option<Table>> {
    let decision = wrappers::check_network_tcp(ctx, host, operation);
    if !decision.is_allowed() {
        Ok(Some(denied_response(
            lua,
            decision.deny_reason().unwrap_or("network access denied"),
        )?))
    } else {
        Ok(None)
    }
}

pub fn register_http_library(lua: &Lua, capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    register_http_library_with_services(lua, capability_ctx, &NseHostServices::native())
}

/// Provider-backed HTTP registration.
///
/// `services.http()` executes every request; deterministic tests inject
/// [`MockHttpProvider`](crate::providers::MockHttpProvider).
pub fn register_http_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    crate::install_tls_provider();
    let globals = lua.globals();
    let http = lua.create_table()?;

    let ctx = capability_ctx.clone();
    let svc = services.clone();
    http.set(
        "get",
        lua.create_function(
            move |lua, (host, port, path, options): (String, u16, String, Option<Table>)| {
                if let Some(resp) = maybe_denied_response(lua, &ctx, &host, "http.get")? {
                    return Ok(resp);
                }

                let url = build_url(&host, port, &path);
                // Legacy `get` honors only the options timeout.
                let timeout = options
                    .as_ref()
                    .and_then(|o| o.get::<u64>("timeout").ok())
                    .map(Duration::from_secs)
                    .unwrap_or(Duration::from_secs(30));
                let req = provider_request(
                    &ctx,
                    NseHttpMethod::Get,
                    url,
                    &host,
                    Vec::new(),
                    Vec::new(),
                    timeout,
                );

                match broker_http_request(&ctx, &svc, &req, "http.get") {
                    Ok(resp) => build_response(lua, &resp),
                    Err(e) => error_response(lua, &e),
                }
            },
        )?,
    )?;

    let ctx = capability_ctx.clone();
    let svc = services.clone();
    http.set(
        "post",
        lua.create_function(
            move |lua,
                  (host, port, path, data, options): (
                String,
                u16,
                String,
                String,
                Option<Table>,
            )| {
                if let Some(resp) = maybe_denied_response(lua, &ctx, &host, "http.post")? {
                    return Ok(resp);
                }

                let url = build_url(&host, port, &path);
                let timeout = options
                    .as_ref()
                    .and_then(|o| o.get::<u64>("timeout").ok())
                    .map(Duration::from_secs)
                    .unwrap_or(Duration::from_secs(30));
                let req = provider_request(
                    &ctx,
                    NseHttpMethod::Post,
                    url,
                    &host,
                    Vec::new(),
                    data.into_bytes(),
                    timeout,
                );

                match broker_http_request(&ctx, &svc, &req, "http.post") {
                    Ok(resp) => build_response(lua, &resp),
                    Err(e) => error_response(lua, &e),
                }
            },
        )?,
    )?;

    let ctx = capability_ctx.clone();
    let svc = services.clone();
    http.set(
        "put",
        lua.create_function(
            move |lua,
                  (host, port, path, data, options): (
                String,
                u16,
                String,
                String,
                Option<Table>,
            )| {
                if let Some(resp) = maybe_denied_response(lua, &ctx, &host, "http.put")? {
                    return Ok(resp);
                }

                let url = build_url(&host, port, &path);
                let timeout = options
                    .as_ref()
                    .and_then(|o| o.get::<u64>("timeout").ok())
                    .map(Duration::from_secs)
                    .unwrap_or(Duration::from_secs(30));
                let req = provider_request(
                    &ctx,
                    NseHttpMethod::Put,
                    url,
                    &host,
                    Vec::new(),
                    data.into_bytes(),
                    timeout,
                );

                match broker_http_request(&ctx, &svc, &req, "http.put") {
                    Ok(resp) => build_response(lua, &resp),
                    Err(e) => error_response(lua, &e),
                }
            },
        )?,
    )?;

    let ctx = capability_ctx.clone();
    let svc = services.clone();
    http.set(
        "delete",
        lua.create_function(
            move |lua, (host, port, path, _options): (String, u16, String, Option<Table>)| {
                if let Some(resp) = maybe_denied_response(lua, &ctx, &host, "http.delete")? {
                    return Ok(resp);
                }

                let url = build_url(&host, port, &path);
                let req = provider_request(
                    &ctx,
                    NseHttpMethod::Delete,
                    url,
                    &host,
                    Vec::new(),
                    Vec::new(),
                    Duration::from_secs(30),
                );

                match broker_http_request(&ctx, &svc, &req, "http.delete") {
                    Ok(resp) => build_response(lua, &resp),
                    Err(e) => error_response(lua, &e),
                }
            },
        )?,
    )?;

    let ctx = capability_ctx.clone();
    let svc = services.clone();
    http.set(
        "head",
        lua.create_function(move |lua, (host, port, path): (String, u16, String)| {
            if let Some(resp) = maybe_denied_response(lua, &ctx, &host, "http.head")? {
                return Ok(resp);
            }

            let url = build_url(&host, port, &path);
            let req = provider_request(
                &ctx,
                NseHttpMethod::Head,
                url,
                &host,
                Vec::new(),
                Vec::new(),
                Duration::from_secs(30),
            );

            match broker_http_request(&ctx, &svc, &req, "http.head") {
                Ok(resp) => {
                    // Legacy `head` returns status + line headers only.
                    let result = lua.create_table()?;
                    result.set("status", resp.status as i32)?;

                    let headers_table = lua.create_table()?;
                    for (i, (k, v)) in resp.headers.iter().enumerate() {
                        headers_table.set(i + 1, format!("{}: {}", k, v))?;
                    }
                    result.set("headers", headers_table)?;

                    Ok(result)
                }
                Err(e) => error_response(lua, &e),
            }
        })?,
    )?;

    let ctx = capability_ctx.clone();
    let svc = services.clone();
    http.set(
        "options",
        lua.create_function(move |lua, (host, port, path): (String, u16, String)| {
            if let Some(resp) = maybe_denied_response(lua, &ctx, &host, "http.options")? {
                return Ok(resp);
            }

            let url = build_url(&host, port, &path);
            let req = provider_request(
                &ctx,
                NseHttpMethod::Options,
                url,
                &host,
                Vec::new(),
                Vec::new(),
                Duration::from_secs(30),
            );

            match broker_http_request(&ctx, &svc, &req, "http.options") {
                Ok(resp) => build_response(lua, &resp),
                Err(e) => error_response(lua, &e),
            }
        })?,
    )?;

    let ctx = capability_ctx.clone();
    let svc = services.clone();
    http.set(
        "request",
        lua.create_function(
            move |lua,
                  (method, host, port, path, options): (
                String,
                String,
                u16,
                String,
                Option<Table>,
            )| {
                if let Some(resp) = maybe_denied_response(lua, &ctx, &host, "http.request")? {
                    return Ok(resp);
                }

                let url = build_url(&host, port, &path);
                // Legacy leniency: unknown methods fall back to GET.
                let parsed = NseHttpMethod::parse(&method).unwrap_or(NseHttpMethod::Get);

                let mut headers = Vec::new();
                let mut body = Vec::new();
                if let Some(opts) = options {
                    if let Ok(b) = opts.get::<String>("body") {
                        body = b.into_bytes();
                    }
                    if let Ok(headers_table) = opts.get::<Table>("headers") {
                        for (k, v) in headers_table.pairs::<String, String>().flatten() {
                            headers.push((k, v));
                        }
                    }
                    if let Ok(auth) = opts.get::<String>("authorization") {
                        headers.push(("Authorization".to_string(), auth));
                    }
                    if let Ok(ua) = opts.get::<String>("useragent") {
                        headers.push(("User-Agent".to_string(), ua));
                    }
                }
                let req = provider_request(
                    &ctx,
                    parsed,
                    url,
                    &host,
                    headers,
                    body,
                    Duration::from_secs(30),
                );

                match broker_http_request(&ctx, &svc, &req, "http.request") {
                    Ok(resp) => build_response(lua, &resp),
                    Err(e) => error_response(lua, &e),
                }
            },
        )?,
    )?;

    http.set(
        "ourl",
        lua.create_function(
            |_lua, (scheme, host, port, path): (String, String, u16, String)| {
                let port_str =
                    if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
                        String::new()
                    } else {
                        format!(":{}", port)
                    };

                let path = if path.is_empty() { "/" } else { &path };
                Ok(format!("{}://{}{}{}", scheme, host, port_str, path))
            },
        )?,
    )?;

    http.set(
        "useragent",
        lua.create_function(|_lua, ua: Option<String>| {
            if let Some(ua) = ua {
                Ok(ua)
            } else {
                Ok("Mozilla/5.0 (compatible; Nmap/1.0)".to_string())
            }
        })?,
    )?;

    http.set(
        "add_auth",
        lua.create_function(|_lua, (request, user, password): (Table, String, String)| {
            use base64::Engine;
            let credentials = format!("{}:{}", user, password);
            let encoded = base64::engine::general_purpose::STANDARD.encode(&credentials);
            let header = format!("Basic {}", encoded);
            request.set("authorization", header)?;
            Ok(request)
        })?,
    )?;

    http.set(
        "auth_required",
        lua.create_function(|lua, response: Table| {
            let status: i32 = response.get("status").unwrap_or(0);
            let _headers: Table = or_fallback_table(response.get("headers"), lua)?;

            Ok(status == 401)
        })?,
    )?;

    http.set(
        "redirect_location",
        lua.create_function(|_lua, response: Table| {
            let location: Option<String> = response.get("location").ok();
            Ok(location.unwrap_or_default())
        })?,
    )?;

    http.set(
        "get_cookie",
        lua.create_function(|lua, (response, name): (Table, String)| {
            let header: Table = or_fallback_table(response.get("header"), lua)?;
            let cookies: Option<String> = header
                .get("set-cookie")
                .or_else(|_| header.get("Set-Cookie"))
                .ok();

            if let Some(cookie_str) = cookies {
                for part in cookie_str.split(';') {
                    let pair: Vec<&str> = part.splitn(2, '=').collect();
                    if pair.len() == 2 && pair[0].trim() == name {
                        return Ok(pair[1].trim().to_string());
                    }
                }
            }

            Ok(String::new())
        })?,
    )?;

    http.set(
        "set_cookie",
        lua.create_function(|lua, (request, name, value): (Table, String, String)| {
            let cookie = format!("{}={}", name, value);
            let header: Table = or_fallback_table(request.get("headers"), lua)?;
            header.set("Cookie", cookie)?;
            Ok(request)
        })?,
    )?;

    http.set(
        "capture_error",
        lua.create_function(|_lua, response: Table| {
            let error: Option<String> = response.get("error").ok();
            let reason: Option<String> = response.get("reason").ok();

            if let Some(e) = error {
                return Ok(e);
            }
            if let Some(r) = reason {
                return Ok(r);
            }

            Ok(String::new())
        })?,
    )?;

    http.set(
        "is_https",
        lua.create_function(|_lua, response: Table| {
            let https: bool = response.get("https").unwrap_or(false);
            let _status: i32 = response.get("status").unwrap_or(0);
            let url: Option<String> = response.get("url").ok();

            Ok(https || url.map(|u| u.starts_with("https")).unwrap_or(false))
        })?,
    )?;

    let ctx = capability_ctx.clone();
    let svc = services.clone();
    http.set(
        "post_host",
        lua.create_function(
            move |lua,
                  (host, port, path, data, options): (
                String,
                u16,
                String,
                String,
                Option<Table>,
            )| {
                if let Some(resp) = maybe_denied_response(lua, &ctx, &host, "http.post_host")? {
                    return Ok(resp);
                }

                let url = build_url(&host, port, &path);

                let timeout = options
                    .as_ref()
                    .and_then(|o| o.get::<u64>("timeout").ok())
                    .map(Duration::from_secs)
                    .unwrap_or(Duration::from_secs(30));

                let mut headers = Vec::new();
                if let Some(opts) = options {
                    if let Ok(headers_table) = opts.get::<Table>("headers") {
                        for (k, v) in headers_table.pairs::<String, String>().flatten() {
                            headers.push((k, v));
                        }
                    }
                }
                let req = provider_request(
                    &ctx,
                    NseHttpMethod::Post,
                    url,
                    &host,
                    headers,
                    data.into_bytes(),
                    timeout,
                );

                match broker_http_request(&ctx, &svc, &req, "http.post_host") {
                    Ok(resp) => build_response(lua, &resp),
                    Err(e) => error_response(lua, &e),
                }
            },
        )?,
    )?;

    let ctx = capability_ctx.clone();
    let svc = services.clone();
    http.set(
        "put_data",
        lua.create_function(
            move |lua,
                  (host, port, path, data, options): (
                String,
                u16,
                String,
                String,
                Option<Table>,
            )| {
                if let Some(resp) = maybe_denied_response(lua, &ctx, &host, "http.put_data")? {
                    return Ok(resp);
                }

                let url = build_url(&host, port, &path);

                let timeout = options
                    .as_ref()
                    .and_then(|o| o.get::<u64>("timeout").ok())
                    .map(Duration::from_secs)
                    .unwrap_or(Duration::from_secs(30));

                let mut headers = Vec::new();
                if let Some(opts) = options {
                    if let Ok(headers_table) = opts.get::<Table>("headers") {
                        for (k, v) in headers_table.pairs::<String, String>().flatten() {
                            headers.push((k, v));
                        }
                    }
                }
                let req = provider_request(
                    &ctx,
                    NseHttpMethod::Put,
                    url,
                    &host,
                    headers,
                    data.into_bytes(),
                    timeout,
                );

                match broker_http_request(&ctx, &svc, &req, "http.put_data") {
                    Ok(resp) => build_response(lua, &resp),
                    Err(e) => error_response(lua, &e),
                }
            },
        )?,
    )?;

    http.set(
        "new_request",
        lua.create_function(|lua, options: Option<Table>| {
            let request = lua.create_table()?;

            request.set("method", "GET")?;
            request.set("host", "")?;
            request.set("port", 80)?;
            request.set("path", "/")?;
            request.set("headers", lua.create_table()?)?;

            if let Some(opts) = options {
                if let Ok(method) = opts.get::<String>("method") {
                    request.set("method", method)?;
                }
                if let Ok(host) = opts.get::<String>("host") {
                    request.set("host", host)?;
                }
                if let Ok(port) = opts.get::<u16>("port") {
                    request.set("port", port)?;
                }
                if let Ok(path) = opts.get::<String>("path") {
                    request.set("path", path)?;
                }
            }

            Ok(request)
        })?,
    )?;

    http.set(
        "clone_request",
        lua.create_function(|lua, request: Table| {
            let cloned = lua.create_table()?;

            let method: String = request.get("method").unwrap_or_else(|_| "GET".to_string());
            let host: String = request.get("host").unwrap_or_default();
            let port: u16 = request.get("port").unwrap_or(80);
            let path: String = request.get("path").unwrap_or_else(|_| "/".to_string());
            let headers: Table = or_fallback_table(request.get("headers"), lua)?;

            cloned.set("method", method)?;
            cloned.set("host", host)?;
            cloned.set("port", port)?;
            cloned.set("path", path)?;
            cloned.set("headers", headers)?;

            Ok(cloned)
        })?,
    )?;

    http.set(
        "validate",
        lua.create_function(|lua, response: Table| {
            let status: i32 = response.get("status").unwrap_or(0);
            let body: String = response.get("body").unwrap_or_default();

            let result = lua.create_table()?;
            result.set("valid", (200..400).contains(&status))?;
            result.set("status", status)?;
            result.set("has_body", !body.is_empty())?;

            if let Ok(headers) = response.get::<Table>("headers") {
                let content_type: Option<String> = headers.get("content-type").ok();
                result.set("content_type", content_type.unwrap_or_default())?;
            }

            Ok(result)
        })?,
    )?;

    // Async HTTP functions (for use with async executor).
    //
    // The provider contract is synchronous; these closures call the broker
    // inline with bounded timeouts (no detached tasks). Concurrency
    // characteristics differ from the previous true-async client; the
    // completion/error shapes are unchanged.
    let ctx = capability_ctx.clone();
    let svc = services.clone();
    http.set(
        "async_get",
        lua.create_function(move |lua, (host, port, path): (String, u16, String)| {
            if let Some(resp) = maybe_denied_response(lua, &ctx, &host, "http.async_get")? {
                return Ok(resp);
            }

            let url = build_url(&host, port, &path);
            let req = provider_request(
                &ctx,
                NseHttpMethod::Get,
                url,
                &host,
                Vec::new(),
                Vec::new(),
                Duration::from_secs(30),
            );

            match broker_http_request(&ctx, &svc, &req, "http.async_get") {
                Ok(resp) => build_response(lua, &resp),
                Err(e) => error_response(lua, &e),
            }
        })?,
    )?;

    let ctx = capability_ctx.clone();
    let svc = services.clone();
    http.set(
        "async_post",
        lua.create_function(
            move |lua, (host, port, path, data): (String, u16, String, String)| {
                if let Some(resp) = maybe_denied_response(lua, &ctx, &host, "http.async_post")? {
                    return Ok(resp);
                }

                let url = build_url(&host, port, &path);
                let req = provider_request(
                    &ctx,
                    NseHttpMethod::Post,
                    url,
                    &host,
                    Vec::new(),
                    data.into_bytes(),
                    Duration::from_secs(30),
                );

                match broker_http_request(&ctx, &svc, &req, "http.async_post") {
                    Ok(resp) => build_response(lua, &resp),
                    Err(e) => error_response(lua, &e),
                }
            },
        )?,
    )?;

    let ctx = capability_ctx.clone();
    let svc = services.clone();
    http.set(
        "async_request",
        lua.create_function(
            move |lua, (method, host, port, path): (String, String, u16, String)| {
                if let Some(resp) = maybe_denied_response(lua, &ctx, &host, "http.async_request")? {
                    return Ok(resp);
                }

                let url = build_url(&host, port, &path);
                let parsed = NseHttpMethod::parse(&method).unwrap_or(NseHttpMethod::Get);
                let req = provider_request(
                    &ctx,
                    parsed,
                    url,
                    &host,
                    Vec::new(),
                    Vec::new(),
                    Duration::from_secs(30),
                );

                match broker_http_request(&ctx, &svc, &req, "http.async_request") {
                    Ok(resp) => build_response(lua, &resp),
                    Err(e) => error_response(lua, &e),
                }
            },
        )?,
    )?;

    globals.set("http", http)?;
    Ok(())
}
