//! NSE httpspider library wrapper
//!
//! Provides web crawling and page parsing functionality for NSE scripts.
//! Based on Nmap's httpspider library: https://nmap.org/nsedoc/lib/httpspider.html

use mlua::{Lua, Result as LuaResult, Table};
use rustc_hash::{FxHashMap, FxHashSet};
use scraper::{Html, Selector};
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;
use url::Url;

static CRAWLERS: LazyLock<Mutex<FxHashMap<String, CrawlerState>>> =
    LazyLock::new(|| Mutex::new(FxHashMap::default()));
static CRAWLER_COUNTER: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));

struct CrawlerState {
    host: String,
    port: u16,
    base_url: String,
    queue: Vec<String>,
    visited: FxHashSet<String>,
    max_depth: usize,
    max_pages: usize,
    pages_visited: usize,
    current_depth: usize,
    within_host: bool,
    within_domain: bool,
    noblacklist: bool,
    usehead: bool,
    timeout: u64,
    stopped: bool,
    useragent: String,
}

fn get_next_id() -> String {
    let mut counter = CRAWLER_COUNTER.lock().unwrap_or_else(|e| e.into_inner());
    *counter += 1;
    format!("crawler_{}", *counter)
}

pub fn register_httpspider_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let httpspider = lua.create_table()?;

    // iswithinhost - Check if URL is within the same host
    httpspider.set(
        "iswithinhost",
        lua.create_function(|_lua, (url, host): (String, String)| {
            if let Ok(parsed) = Url::parse(&url) {
                if let Some(url_host) = parsed.host_str() {
                    return Ok(url_host == host || url_host.ends_with(&format!(".{}", host)));
                }
            }
            Ok(false)
        })?,
    )?;

    // iswithindomain - Check if URL is within the same domain
    httpspider.set(
        "iswithindomain",
        lua.create_function(|_lua, (url, domain): (String, String)| {
            if let Ok(parsed) = Url::parse(&url) {
                if let Some(url_domain) = parsed.domain() {
                    return Ok(
                        url_domain == domain || url_domain.ends_with(&format!(".{}", domain))
                    );
                }
            }
            Ok(false)
        })?,
    )?;

    // isresource - Check if URL matches a resource type
    httpspider.set(
        "isresource",
        lua.create_function(|_lua, (url, ext): (String, String)| {
            if let Ok(parsed) = Url::parse(&url) {
                if let Some(mut path) = parsed.path_segments() {
                    if let Some(filename) = path.next_back() {
                        if let Some(file_ext) = filename.rsplit('.').next() {
                            return Ok(file_ext.to_lowercase() == ext.to_lowercase());
                        }
                    }
                }
            }
            Ok(false)
        })?,
    )?;

    // parse - Parse HTML and extract links and forms
    httpspider.set(
        "parse",
        lua.create_function(|lua, (html, base_url): (String, String)| {
            let result = lua.create_table()?;
            let links = lua.create_table()?;
            let forms = lua.create_table()?;

            // Extract links
            if let Ok(selector) = Selector::parse("a[href]") {
                let doc = Html::parse_document(&html);
                for element in doc.select(&selector) {
                    if let Some(href) = element.value().attr("href") {
                        if let Ok(base) = Url::parse(&base_url) {
                            if let Ok(abs) = base.join(href) {
                                let idx = links.len().unwrap_or(0) + 1;
                                links.set(idx, abs.to_string())?;
                            }
                        }
                    }
                }
            }

            // Extract forms
            if let Ok(selector) = Selector::parse("form") {
                let doc = Html::parse_document(&html);
                for (form_idx, element) in doc.select(&selector).enumerate() {
                    let form = lua.create_table()?;
                    form.set("action", element.value().attr("action").unwrap_or(""))?;
                    form.set(
                        "method",
                        element
                            .value()
                            .attr("method")
                            .unwrap_or("get")
                            .to_uppercase(),
                    )?;

                    let inputs = lua.create_table()?;
                    if let Ok(input_selector) = Selector::parse("input[name]") {
                        for (input_idx, input) in element.select(&input_selector).enumerate() {
                            let input_info = lua.create_table()?;
                            input_info.set("name", input.value().attr("name").unwrap_or(""))?;
                            input_info.set("type", input.value().attr("type").unwrap_or("text"))?;
                            input_info.set("value", input.value().attr("value").unwrap_or(""))?;
                            inputs.set(input_idx + 1, input_info)?;
                        }
                    }
                    form.set("inputs", inputs)?;
                    forms.set(form_idx + 1, form)?;
                }
            }

            result.set("links", links)?;
            result.set("forms", forms)?;
            result.set("base_url", base_url)?;

            Ok(result)
        })?,
    )?;

    // fetch - Fetch a URL
    httpspider.set(
        "fetch",
        lua.create_function(|lua, (url, options): (String, Option<Table>)| {
            let result = lua.create_table()?;

            let timeout = options
                .as_ref()
                .and_then(|o| o.get::<u64>("timeout").ok())
                .unwrap_or(10);

            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(timeout))
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .build();

            match client {
                Ok(c) => {
                    let response = c.get(&url).send();
                    match response {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            result.set("status", status as i32)?;
                            result.set("url", url.clone())?;

                            if status == 200 {
                                if let Ok(body) = resp.text() {
                                    result.set("body", body)?;
                                    result.set("headers", lua.create_table()?)?;
                                }
                            }
                        }
                        Err(e) => {
                            result.set("status", 0)?;
                            result.set("error", e.to_string())?;
                        }
                    }
                }
                Err(e) => {
                    result.set("status", 0)?;
                    result.set("error", e.to_string())?;
                }
            }

            Ok(result)
        })?,
    )?;

    // filter - Check if URL should be filtered
    httpspider.set(
        "filter",
        lua.create_function(|_lua, url: String| {
            let blacklist = [
                ".jpg", ".jpeg", ".png", ".gif", ".css", ".js", ".ico", ".svg", ".woff", ".woff2",
                ".ttf", ".eot", ".mp4", ".pdf",
            ];

            for ext in blacklist.iter() {
                if url.to_lowercase().ends_with(ext) {
                    return Ok(false);
                }
            }
            Ok(true)
        })?,
    )?;

    // allowed - Check if HTTP status code indicates success
    httpspider.set(
        "allowed",
        lua.create_function(|_lua, status: i32| Ok((200..400).contains(&status)))?,
    )?;

    // get_url - Construct full URL from path
    httpspider.set(
        "get_url",
        lua.create_function(|_lua, (path, base): (String, String)| {
            if path.starts_with("http://") || path.starts_with("https://") {
                return Ok(path);
            }

            if let Ok(base_url) = Url::parse(&base) {
                if let Ok(full) = base_url.join(&path) {
                    return Ok(full.to_string());
                }
            }

            Ok(path)
        })?,
    )?;

    // response_code_exists - Check if status code exists
    httpspider.set(
        "response_code_exists",
        lua.create_function(|_lua, status: i32| {
            Ok(matches!(status, 200..=399 | 401..=403 | 405 | 407 | 500..=599))
        })?,
    )?;

    // version
    httpspider.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("httpspider", httpspider)?;
    Ok(())
}
