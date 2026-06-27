//! NSE http library wrapper
//!
//! Provides HTTP client functionality compatible with NSE scripts.

use mlua::{Lua, Result as LuaResult, Table};
use reqwest::blocking::Client;
use reqwest::Client as AsyncClient;
use rustc_hash::FxHashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;
use std::time::Duration;

use super::helpers::fallback_lua_table;

static ACCEPT_INVALID_CERTS: AtomicBool = AtomicBool::new(true);
static ACCEPT_INVALID_HOSTNAMES: AtomicBool = AtomicBool::new(true);

pub fn set_accept_invalid_certs(accept: bool) {
    ACCEPT_INVALID_CERTS.store(accept, Ordering::SeqCst);
}

pub fn set_accept_invalid_hostnames(accept: bool) {
    ACCEPT_INVALID_HOSTNAMES.store(accept, Ordering::SeqCst);
}

fn build_client(accept_invalid_certs: bool, accept_invalid_hostnames: bool) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(30));

    if accept_invalid_certs {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if accept_invalid_hostnames {
        builder = builder.danger_accept_invalid_hostnames(true);
    }

    builder.build().unwrap_or_else(|_| Client::new())
}

static HTTP_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    build_client(
        ACCEPT_INVALID_CERTS.load(Ordering::SeqCst),
        ACCEPT_INVALID_HOSTNAMES.load(Ordering::SeqCst),
    )
});

static HTTPS_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    build_client(
        ACCEPT_INVALID_CERTS.load(Ordering::SeqCst),
        ACCEPT_INVALID_HOSTNAMES.load(Ordering::SeqCst),
    )
});

// Async HTTP client for async functions
static ASYNC_HTTP_CLIENT: LazyLock<AsyncClient> = LazyLock::new(|| {
    let accept_invalid_certs = ACCEPT_INVALID_CERTS.load(Ordering::SeqCst);
    let accept_invalid_hostnames = ACCEPT_INVALID_HOSTNAMES.load(Ordering::SeqCst);

    let mut builder = AsyncClient::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(30));

    if accept_invalid_certs {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if accept_invalid_hostnames {
        builder = builder.danger_accept_invalid_hostnames(true);
    }

    builder.build().unwrap_or_else(|_| AsyncClient::new())
});

static ASYNC_HTTPS_CLIENT: LazyLock<AsyncClient> = LazyLock::new(|| {
    let accept_invalid_certs = ACCEPT_INVALID_CERTS.load(Ordering::SeqCst);
    let accept_invalid_hostnames = ACCEPT_INVALID_HOSTNAMES.load(Ordering::SeqCst);

    let mut builder = AsyncClient::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(30));

    if accept_invalid_certs {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if accept_invalid_hostnames {
        builder = builder.danger_accept_invalid_hostnames(true);
    }

    builder.build().unwrap_or_else(|_| AsyncClient::new())
});

fn get_client(url: &str) -> &'static Client {
    if url.starts_with("https") {
        &HTTPS_CLIENT
    } else {
        &HTTP_CLIENT
    }
}

fn get_async_client(url: &str) -> &'static AsyncClient {
    if url.starts_with("https") {
        &ASYNC_HTTPS_CLIENT
    } else {
        &ASYNC_HTTP_CLIENT
    }
}

fn make_client(timeout_secs: u64) -> Client {
    make_client_with_tls(timeout_secs, None, None)
}

fn make_client_with_tls(
    timeout_secs: u64,
    accept_invalid_certs: Option<bool>,
    accept_invalid_hostnames: Option<bool>,
) -> Client {
    let global_accept_certs = ACCEPT_INVALID_CERTS.load(Ordering::SeqCst);
    let global_accept_hostnames = ACCEPT_INVALID_HOSTNAMES.load(Ordering::SeqCst);

    let use_invalid_certs = accept_invalid_certs.unwrap_or(global_accept_certs);
    let use_invalid_hostnames = accept_invalid_hostnames.unwrap_or(global_accept_hostnames);

    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .connect_timeout(Duration::from_secs(10));

    if use_invalid_certs {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if use_invalid_hostnames {
        builder = builder.danger_accept_invalid_hostnames(true);
    }

    builder.build().unwrap_or_else(|_| Client::new())
}

fn parse_options(opts: Option<&Table>) -> (FxHashMap<String, String>, Duration) {
    let mut headers = FxHashMap::default();
    let timeout = Duration::from_secs(30);

    if let Some(opts) = opts {
        if let Ok(timeout_val) = opts.get::<u64>("timeout") {
            return (headers, Duration::from_secs(timeout_val));
        }
        if let Ok(headers_table) = opts.get::<Table>("headers") {
            for (k, v) in headers_table.pairs::<String, String>().flatten() {
                headers.insert(k, v);
            }
        }
    }

    (headers, timeout)
}

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

fn build_response(lua: &Lua, resp: reqwest::blocking::Response) -> LuaResult<Table> {
    let result = lua.create_table()?;

    let status = resp.status().as_u16();
    result.set("status", status as i32)?;

    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let headers_table = lua.create_table()?;
    let headers_map = lua.create_table()?;
    for (i, (k, v)) in headers.iter().enumerate() {
        headers_table.set(i + 1, format!("{}: {}", k, v))?;
        headers_map.set(k.clone(), v.clone())?;
    }
    result.set("headers", headers_table)?;
    result.set("header", headers_map)?;

    let version = resp.version();
    result.set("version", format!("{:?}", version))?;

    if (300..400).contains(&status) {
        if let Some(location) = resp.headers().get("location") {
            if let Ok(loc) = location.to_str() {
                result.set("location", loc.to_string())?;
            }
        }
    }

    let https = resp.url().scheme() == "https";
    if let Ok(body) = resp.text() {
        result.set("body", body)?;
    }

    result.set("https", https)?;

    Ok(result)
}

fn build_response_async(lua: &Lua, resp: reqwest::Response) -> LuaResult<Table> {
    let result = lua.create_table()?;

    let status = resp.status().as_u16();
    result.set("status", status as i32)?;

    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let headers_table = lua.create_table()?;
    let headers_map = lua.create_table()?;
    for (i, (k, v)) in headers.iter().enumerate() {
        headers_table.set(i + 1, format!("{}: {}", k, v))?;
        headers_map.set(k.clone(), v.clone())?;
    }
    result.set("headers", headers_table)?;
    result.set("header", headers_map)?;

    let version = resp.version();
    result.set("version", format!("{:?}", version))?;

    if (300..400).contains(&status) {
        if let Some(location) = resp.headers().get("location") {
            if let Ok(loc) = location.to_str() {
                result.set("location", loc.to_string())?;
            }
        }
    }

    let https = resp.url().scheme() == "https";

    // For async response, we need to use block_on to get body
    let body = tokio::runtime::Handle::current()
        .block_on(resp.text())
        .unwrap_or_default();
    result.set("body", body)?;

    result.set("https", https)?;

    Ok(result)
}

fn error_response(lua: &Lua, err: reqwest::Error) -> LuaResult<Table> {
    let result = lua.create_table()?;
    result.set("status", 0i32)?;
    result.set("error", err.to_string())?;
    if err.is_timeout() {
        result.set("reason", "timeout")?;
    } else if err.is_connect() {
        result.set("reason", "connection")?;
    } else {
        result.set("reason", "request")?;
    }
    Ok(result)
}

pub fn register_http_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let http = lua.create_table()?;

    http.set(
        "get",
        lua.create_function(
            |lua, (host, port, path, options): (String, u16, String, Option<Table>)| {
                let url = build_url(&host, port, &path);

                let client = if let Some(opts) = options.as_ref() {
                    match opts.get::<u64>("timeout") {
                        Ok(timeout) => make_client_with_tls(timeout, None, None),
                        _ => get_client(&url).clone(),
                    }
                } else {
                    get_client(&url).clone()
                };

                match client.get(&url).send() {
                    Ok(resp) => build_response(lua, resp),
                    Err(e) => error_response(lua, e),
                }
            },
        )?,
    )?;

    http.set(
        "post",
        lua.create_function(
            |lua,
             (host, port, path, data, options): (
                String,
                u16,
                String,
                String,
                Option<Table>,
            )| {
                let url = build_url(&host, port, &path);

                let client = if let Some(opts) = options.as_ref() {
                    match opts.get::<u64>("timeout") { Ok(timeout) => {
                        make_client_with_tls(timeout, None, None)
                    } _ => {
                        get_client(&url).clone()
                    }}
                } else {
                    get_client(&url).clone()
                };

                match client.post(&url).body(data).send() {
                    Ok(resp) => build_response(lua, resp),
                    Err(e) => error_response(lua, e),
                }
            },
        )?,
    )?;

    http.set(
        "put",
        lua.create_function(
            |lua,
             (host, port, path, data, options): (
                String,
                u16,
                String,
                String,
                Option<Table>,
            )| {
                let url = build_url(&host, port, &path);

                let client = if let Some(opts) = options.as_ref() {
                    match opts.get::<u64>("timeout") { Ok(timeout) => {
                        make_client_with_tls(timeout, None, None)
                    } _ => {
                        get_client(&url).clone()
                    }}
                } else {
                    get_client(&url).clone()
                };

                match client.put(&url).body(data).send() {
                    Ok(resp) => build_response(lua, resp),
                    Err(e) => error_response(lua, e),
                }
            },
        )?,
    )?;

    http.set(
        "delete",
        lua.create_function(
            |lua, (host, port, path, _options): (String, u16, String, Option<Table>)| {
                let url = build_url(&host, port, &path);
                let client = get_client(&url).clone();

                match client.delete(&url).send() {
                    Ok(resp) => build_response(lua, resp),
                    Err(e) => error_response(lua, e),
                }
            },
        )?,
    )?;

    http.set(
        "head",
        lua.create_function(|lua, (host, port, path): (String, u16, String)| {
            let url = build_url(&host, port, &path);
            let client = get_client(&url).clone();

            match client.head(&url).send() {
                Ok(resp) => {
                    let result = lua.create_table()?;
                    result.set("status", resp.status().as_u16() as i32)?;

                    let headers: Vec<(String, String)> = resp
                        .headers()
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                        .collect();

                    let headers_table = lua.create_table()?;
                    for (i, (k, v)) in headers.iter().enumerate() {
                        headers_table.set(i + 1, format!("{}: {}", k, v))?;
                    }
                    result.set("headers", headers_table)?;

                    Ok(result)
                }
                Err(e) => error_response(lua, e),
            }
        })?,
    )?;

    http.set(
        "options",
        lua.create_function(|lua, (host, port, path): (String, u16, String)| {
            let url = build_url(&host, port, &path);
            let client = get_client(&url).clone();

            match client.request(reqwest::Method::OPTIONS, &url).send() {
                Ok(resp) => build_response(lua, resp),
                Err(e) => error_response(lua, e),
            }
        })?,
    )?;

    http.set(
        "request",
        lua.create_function(
            |lua,
             (method, host, port, path, options): (
                String,
                String,
                u16,
                String,
                Option<Table>,
            )| {
                let url = build_url(&host, port, &path);

                let client = get_client(&url).clone();

                let mut req =
                    client.request(method.parse().unwrap_or(reqwest::Method::GET), &url);

                if let Some(opts) = options {
                    if let Ok(body) = opts.get::<String>("body") {
                        req = req.body(body);
                    }
                    if let Ok(headers) = opts.get::<Table>("headers") {
                        for (k, v) in headers.pairs::<String, String>().flatten() {
                            req = req.header(&k, &v);
                        }
                    }
                    if let Ok(auth) = opts.get::<String>("authorization") {
                        req = req.header("Authorization", &auth);
                    }
                    if let Ok(ua) = opts.get::<String>("useragent") {
                        req = req.header("User-Agent", &ua);
                    }
                }

                match req.send() {
                    Ok(resp) => build_response(lua, resp),
                    Err(e) => error_response(lua, e),
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
            let _headers: Table = response.get("headers").unwrap_or_else(|_| {
                lua.create_table()
                    .unwrap_or_else(|_| fallback_lua_table(lua))
            });

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
            let header: Table = response.get("header").unwrap_or_else(|_| {
                lua.create_table()
                    .unwrap_or_else(|_| fallback_lua_table(lua))
            });
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
            let header: Table = request.get("headers").unwrap_or_else(|_| {
                lua.create_table()
                    .unwrap_or_else(|_| fallback_lua_table(lua))
            });
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

    http.set(
        "post_host",
        lua.create_function(
            |lua, (host, port, path, data, options): (String, u16, String, String, Option<Table>)| {
                let url = build_url(&host, port, &path);

                let timeout = options
                    .as_ref()
                    .and_then(|o| o.get::<u64>("timeout").ok())
                    .unwrap_or(30);

                let client = make_client_with_tls(timeout, None, None);

                let mut req = client.post(&url).body(data);

                if let Some(opts) = options {
                    if let Ok(headers) = opts.get::<Table>("headers") {
                        for (k, v) in headers.pairs::<String, String>().flatten() {
                            req = req.header(&k, &v);
                        }
                    }
                }

                match req.send() {
                    Ok(resp) => build_response(lua, resp),
                    Err(e) => error_response(lua, e),
                }
            },
        )?,
    )?;

    http.set(
        "put_data",
        lua.create_function(
            |lua, (host, port, path, data, options): (String, u16, String, String, Option<Table>)| {
                let url = build_url(&host, port, &path);

                let timeout = options
                    .as_ref()
                    .and_then(|o| o.get::<u64>("timeout").ok())
                    .unwrap_or(30);

                let client = make_client_with_tls(timeout, None, None);

                let mut req = client.put(&url).body(data);

                if let Some(opts) = options {
                    if let Ok(headers) = opts.get::<Table>("headers") {
                        for (k, v) in headers.pairs::<String, String>().flatten() {
                            req = req.header(&k, &v);
                        }
                    }
                }

                match req.send() {
                    Ok(resp) => build_response(lua, resp),
                    Err(e) => error_response(lua, e),
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
            let headers: Table = request.get("headers").unwrap_or_else(|_| {
                lua.create_table()
                    .unwrap_or_else(|_| fallback_lua_table(lua))
            });

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

    // Async HTTP functions (for use with async executor)
    // These use reqwest's async client internally
    http.set(
        "async_get",
        lua.create_function(|lua, (host, port, path): (String, u16, String)| {
            let url = build_url(&host, port, &path);
            let client = get_async_client(&url).clone();

            // Run blocking HTTP call in a tokio spawn
            let result = tokio::runtime::Handle::current().block_on(async {
                match client.get(&url).send().await {
                    Ok(resp) => build_response_async(lua, resp),
                    Err(e) => error_response(lua, e),
                }
            });

            result
        })?,
    )?;

    http.set(
        "async_post",
        lua.create_function(
            |lua, (host, port, path, data): (String, u16, String, String)| {
                let url = build_url(&host, port, &path);
                let client = get_async_client(&url).clone();

                let result = tokio::runtime::Handle::current().block_on(async {
                    match client.post(&url).body(data).send().await {
                        Ok(resp) => build_response_async(lua, resp),
                        Err(e) => error_response(lua, e),
                    }
                });

                result
            },
        )?,
    )?;

    http.set(
        "async_request",
        lua.create_function(
            |lua, (method, host, port, path): (String, String, u16, String)| {
                let url = build_url(&host, port, &path);
                let client = get_async_client(&url).clone();

                let result = tokio::runtime::Handle::current().block_on(async {
                    let req = client.request(method.parse().unwrap_or(reqwest::Method::GET), &url);
                    match req.send().await {
                        Ok(resp) => build_response_async(lua, resp),
                        Err(e) => error_response(lua, e),
                    }
                });

                result
            },
        )?,
    )?;

    globals.set("http", http)?;
    Ok(())
}
