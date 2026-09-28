//! NSE httppipeline library wrapper
//!
//! HTTP pipelining support for sending multiple requests without waiting for each response.
//! Based on Nmap's httppipeline functionality: https://nmap.org/nsedoc/lib/http.html
//!
//! M005C: every pipelined request executes through the injected
//! [`NseHttpProvider`] via the broker. The shared-client build (with
//! profile-gated TLS intent) is preserved per request; pooling lives in
//! the per-bundle native provider.

use mlua::{Lua, Result as LuaResult, Table};
use std::time::Duration;

use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_http_request, NseHostServices, NseHttpMethod, NseHttpRequest};
use crate::wrappers;

pub fn register_httppipeline_library(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
) -> LuaResult<()> {
    register_httppipeline_library_with_services(lua, capability_ctx, &NseHostServices::native())
}

/// Provider-backed httppipeline registration.
pub fn register_httppipeline_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let httppipeline = lua.create_table()?;

    // httppipeline.new(host, port, options?) -> pipeline
    let new_fn =
        lua.create_function(|lua, (host, port, options): (String, u16, Option<Table>)| {
            let timeout = options
                .as_ref()
                .and_then(|o| o.get::<u64>("timeout").ok())
                .unwrap_or(30);

            let max_pipelined = options
                .as_ref()
                .and_then(|o| o.get::<usize>("maxpipelined").ok())
                .unwrap_or(40);

            let pipeline = lua.create_table()?;
            pipeline.set("host", host.clone())?;
            pipeline.set("port", port)?;
            pipeline.set("timeout", timeout)?;
            pipeline.set("max_pipelined", max_pipelined)?;
            pipeline.set("requests", lua.create_table()?)?;

            Ok(pipeline)
        })?;
    httppipeline.set("new", new_fn)?;

    // httppipeline.add(pipeline, method, path, options?) -> request_id
    let add_fn = lua.create_function(
        |lua, (pipeline, method, path, options): (Table, String, String, Option<Table>)| {
            let requests: Table = pipeline.get("requests")?;

            let request_id = requests.len()? + 1;

            let request_tbl = lua.create_table()?;
            request_tbl.set("method", method)?;
            request_tbl.set("path", path)?;

            if let Some(opts) = options {
                if let Ok(headers) = opts.get::<Table>("headers") {
                    request_tbl.set("headers", headers)?;
                }
                if let Ok(body) = opts.get::<String>("body") {
                    request_tbl.set("body", body)?;
                }
                if let Ok(timeout) = opts.get::<u64>("timeout") {
                    request_tbl.set("timeout", timeout)?;
                }
            }

            requests.set(request_id, request_tbl)?;

            Ok(request_id)
        },
    )?;
    httppipeline.set("add", add_fn)?;

    // httppipeline.go(pipeline) -> responses
    let cap = capability_ctx.clone();
    let svc = services.clone();
    let go_fn = lua.create_function(move |lua, pipeline: Table| {
        let host: String = pipeline.get("host")?;
        let port: u16 = pipeline.get("port")?;

        let decision = wrappers::check_network_tcp(&cap, &host, "httppipeline.go");
        if !decision.is_allowed() {
            let err_tbl = lua.create_table()?;
            err_tbl.set("status", 0)?;
            err_tbl.set(
                "error",
                decision
                    .deny_reason()
                    .unwrap_or("network access denied")
                    .to_string(),
            )?;
            err_tbl.set("reason", "denied")?;
            let responses = lua.create_table()?;
            responses.set(1, err_tbl)?;
            return Ok(responses);
        }

        let timeout = pipeline.get::<u64>("timeout").unwrap_or(30);
        let requests: Table = pipeline.get("requests")?;

        let count = requests.len()? as usize;
        if count == 0 {
            return lua.create_table();
        }

        let scheme = if port == 443 { "https" } else { "http" };
        let base_url = format!("{}://{}:{}", scheme, host, port);
        let insecure = cap.allows_insecure_tls();

        let responses = lua.create_table()?;

        for i in 1..=count as i64 {
            if let Ok(req) = requests.get::<Table>(i) {
                let method: String = req.get("method").unwrap_or_else(|_| "GET".to_string());
                let path: String = req.get("path").unwrap_or_else(|_| "/".to_string());

                let full_url = format!("{}{}", base_url, path);
                // Legacy leniency: unknown methods fall back to GET.
                let parsed = NseHttpMethod::parse(&method).unwrap_or(NseHttpMethod::Get);

                let mut headers = Vec::new();
                if let Ok(headers_table) = req.get::<Table>("headers") {
                    for (k, v) in headers_table.pairs::<String, String>().flatten() {
                        headers.push((k, v));
                    }
                }
                let body = req
                    .get::<String>("body")
                    .map(|b| b.into_bytes())
                    .unwrap_or_default();
                let req_timeout = req
                    .get::<u64>("timeout")
                    .map(Duration::from_secs)
                    .unwrap_or(Duration::from_secs(timeout));
                let http_req = NseHttpRequest {
                    method: parsed,
                    url: full_url.clone(),
                    host: host.clone(),
                    headers,
                    body,
                    timeout: req_timeout.max(Duration::from_secs(1)),
                    connect_timeout: Duration::from_secs(10),
                    insecure_tls: insecure,
                };

                let resp_tbl = lua.create_table()?;

                match broker_http_request(&cap, &svc, &http_req, "httppipeline.go") {
                    Ok(r) => {
                        resp_tbl.set("status", r.status as i32)?;
                        resp_tbl.set("url", full_url)?;

                        let headers = lua.create_table()?;
                        for (k, v) in &r.headers {
                            if let Err(e) = headers.set(k.clone(), v.clone()) {
                                tracing::debug!(
                                    "nse httppipeline: failed to set response header: {}",
                                    e
                                );
                            }
                        }
                        resp_tbl.set("headers", headers)?;

                        resp_tbl.set("body", r.body_text())?;
                    }
                    Err(e) => {
                        resp_tbl.set("status", 0)?;
                        resp_tbl.set("error", e.to_string())?;
                    }
                }

                responses.set(i, resp_tbl)?;
            }
        }

        Ok(responses)
    })?;
    httppipeline.set("go", go_fn)?;

    // httppipeline.reset(pipeline)
    let reset_fn = lua.create_function(|lua, pipeline: Table| {
        pipeline.set("requests", lua.create_table()?)?;
        Ok(())
    })?;
    httppipeline.set("reset", reset_fn)?;

    // httppipeline.count(pipeline) -> count
    let count_fn = lua.create_function(|_lua, pipeline: Table| {
        let requests: Table = pipeline.get("requests")?;
        let len = requests.len()?;
        Ok(len as usize)
    })?;
    httppipeline.set("count", count_fn)?;

    // httppipeline.check_pipeline_support(host, port) -> boolean
    let check_pipeline_support_fn =
        lua.create_function(|_lua, (_host, _port): (String, u16)| Ok(true))?;
    httppipeline.set("check_pipeline_support", check_pipeline_support_fn)?;

    // httppipeline.get_pipeline(host, port) -> pipeline
    let get_pipeline_fn = lua.create_function(
        |lua, (host, port, _options): (String, u16, Option<Table>)| {
            let pipeline = lua.create_table()?;
            pipeline.set("host", host)?;
            pipeline.set("port", port)?;
            pipeline.set("timeout", 30)?;
            pipeline.set("max_pipelined", 40)?;
            pipeline.set("requests", lua.create_table()?)?;

            Ok(pipeline)
        },
    )?;
    httppipeline.set("get_pipeline", get_pipeline_fn)?;

    // httppipeline.queue(host, port, requests) -> responses
    let cap = capability_ctx.clone();
    let svc = services.clone();
    let queue_fn =
        lua.create_function(move |lua, (host, port, requests): (String, u16, Table)| {
            let decision = wrappers::check_network_tcp(&cap, &host, "httppipeline.queue");
            if !decision.is_allowed() {
                let err_tbl = lua.create_table()?;
                err_tbl.set("status", 0)?;
                err_tbl.set(
                    "error",
                    decision
                        .deny_reason()
                        .unwrap_or("network access denied")
                        .to_string(),
                )?;
                err_tbl.set("reason", "denied")?;
                let responses = lua.create_table()?;
                responses.set(1, err_tbl)?;
                return Ok(responses);
            }

            let timeout = 30u64;

            let scheme = if port == 443 { "https" } else { "http" };
            let base_url = format!("{}://{}:{}", scheme, host, port);
            let insecure = cap.allows_insecure_tls();

            let responses = lua.create_table()?;
            let count = requests.len()? as usize;

            for i in 1..=count as i64 {
                if let Ok(req) = requests.get::<Table>(i) {
                    let method: String = req.get("method").unwrap_or_else(|_| "GET".to_string());
                    let path: String = req.get("path").unwrap_or_else(|_| "/".to_string());

                    let full_url = format!("{}{}", base_url, path);
                    let parsed = NseHttpMethod::parse(&method).unwrap_or(NseHttpMethod::Get);
                    let http_req = NseHttpRequest {
                        method: parsed,
                        url: full_url,
                        host: host.clone(),
                        headers: Vec::new(),
                        body: Vec::new(),
                        timeout: Duration::from_secs(timeout),
                        connect_timeout: Duration::from_secs(10),
                        insecure_tls: insecure,
                    };

                    let resp_tbl = lua.create_table()?;

                    match broker_http_request(&cap, &svc, &http_req, "httppipeline.queue") {
                        Ok(r) => {
                            resp_tbl.set("status", r.status as i32)?;
                            resp_tbl.set("body", r.body_text())?;
                        }
                        Err(e) => {
                            resp_tbl.set("status", 0)?;
                            resp_tbl.set("error", e.detail())?;
                        }
                    }

                    responses.set(i, resp_tbl)?;
                }
            }

            Ok(responses)
        })?;
    httppipeline.set("queue", queue_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0"))?;
    httppipeline.set("version", version_fn)?;

    globals.set("httppipeline", httppipeline)?;
    Ok(())
}
