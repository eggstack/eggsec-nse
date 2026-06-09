//! NSE re (regex) library wrapper
//!
//! Provides regex functionality compatible with NSE scripts.
//! Based on Nmap's re library: https://nmap.org/nsedoc/lib/re.html

use mlua::{Lua, Result as LuaResult, Table, Value};
use regex::{Regex, RegexBuilder};
use rustc_hash::FxHashMap;
use std::sync::Mutex;

static COMPILED_PATTERNS: std::sync::LazyLock<Mutex<FxHashMap<String, Regex>>> =
    std::sync::LazyLock::new(|| Mutex::new(FxHashMap::default()));

fn parse_options(options: &str) -> (bool, bool) {
    let mut case_insensitive = false;
    let mut multiline = false;

    for c in options.chars() {
        match c {
            'i' => case_insensitive = true,
            'm' => multiline = true,
            _ => {}
        }
    }

    (case_insensitive, multiline)
}

fn build_regex(pattern: &str, options: &str) -> Result<Regex, String> {
    let (case_insensitive, multiline) = parse_options(options);

    let mut regex_pattern = String::new();

    if multiline {
        regex_pattern.push_str("(?m)");
    }
    if case_insensitive {
        regex_pattern.push_str("(?i)");
    }
    regex_pattern.push_str(pattern);

    RegexBuilder::new(&regex_pattern)
        .multi_line(multiline)
        .case_insensitive(case_insensitive)
        .size_limit(100_000)
        .build()
        .map_err(|e| e.to_string())
}

fn capture_to_lua(lua: &Lua, regex: &Regex, text: &str, caps: Option<&Table>) -> LuaResult<Table> {
    let result = lua.create_table()?;

    if let Some(captures) = regex.captures(text) {
        let full_match = captures.get(0).map(|m| m.as_str()).unwrap_or("");
        result.set(0, full_match)?;

        for (i, name) in regex.capture_names().enumerate() {
            if i == 0 {
                continue;
            }

            if let Some(m) = captures.get(i) {
                if let Some(n) = name {
                    result.set(n, m.as_str())?;
                } else {
                    result.set(i, m.as_str())?;
                }
            }
        }

        if let Some(cap_table) = caps {
            for (name, index) in cap_table.pairs::<String, i32>().flatten() {
                if let Some(m) = captures.get(index as usize) {
                    result.set(name, m.as_str())?;
                }
            }
        }
    }

    Ok(result)
}

pub fn register_re_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let re = lua.create_table()?;

    // re.match(str, pattern [, options]) -> table or nil
    let match_fn = lua.create_function(
        |lua, (s, pattern, options): (String, String, Option<String>)| {
            let opts = options.unwrap_or_default();
            let regex = match build_regex(&pattern, &opts) {
                Ok(r) => r,
                Err(_) => return Ok(Value::Nil),
            };

            if regex.is_match(&s) {
                Ok(Value::Table(capture_to_lua(lua, &regex, &s, None)?))
            } else {
                Ok(Value::Nil)
            }
        },
    )?;
    re.set("match", match_fn)?;

    // re.find(str, pattern [, options]) -> start, end, captures...
    let find_fn = lua.create_function(
        |lua, (s, pattern, options): (String, String, Option<String>)| {
            let opts = options.unwrap_or_default();
            let regex = match build_regex(&pattern, &opts) {
                Ok(r) => r,
                Err(_) => {
                    let r = lua.create_table()?;
                    r.set(1, Value::Nil)?;
                    return Ok(Value::Table(r));
                }
            };

            if let Some(m) = regex.find(&s) {
                let result = lua.create_table()?;
                // Nmap's re.find returns (end, start) - not (start, end)!
                result.set(1, m.end())?; // end first (Nmap order)
                result.set(2, m.start() + 1)?; // start second (Lua 1-indexed)

                if let Some(caps) = regex.captures(m.as_str()) {
                    for (i, name) in regex.capture_names().enumerate() {
                        if i == 0 {
                            continue;
                        }
                        if let Some(cap) = caps.get(i) {
                            if let Some(n) = name {
                                result.set(n, cap.as_str())?;
                            } else {
                                result.set(i + 2, cap.as_str())?;
                            }
                        }
                    }
                }

                Ok(Value::Table(result))
            } else {
                // Return nil for both positions (Nmap behavior)
                let r = lua.create_table()?;
                r.set(1, Value::Nil)?;
                r.set(2, Value::Nil)?;
                Ok(Value::Table(r))
            }
        },
    )?;
    re.set("find", find_fn)?;

    // re.gsub(str, pattern, replacement [, options]) -> newstr, count
    let gsub_fn = lua.create_function(
        |_lua, (s, pattern, replacement, options): (String, String, String, Option<String>)| {
            let opts = options.unwrap_or_default();
            let regex = match build_regex(&pattern, &opts) {
                Ok(r) => r,
                Err(e) => return Err(mlua::Error::RuntimeError(e)),
            };

            let count = regex.find_iter(&s).count();
            let new_str = regex.replace_all(&s, replacement.as_str());

            let result = _lua.create_table()?;
            result.set(1, new_str)?;
            result.set(2, count)?;

            Ok(result)
        },
    )?;
    re.set("gsub", gsub_fn)?;

    // re.split(str, pattern [, options]) -> table
    let split_fn = lua.create_function(
        |lua, (s, pattern, options): (String, String, Option<String>)| {
            let opts = options.unwrap_or_default();
            let regex = match build_regex(&pattern, &opts) {
                Ok(r) => r,
                Err(_) => return lua.create_table(),
            };

            let result = lua.create_table()?;
            let mut index = 1;

            for part in regex.split(&s) {
                result.set(index, part)?;
                index += 1;
            }

            Ok(result)
        },
    )?;
    re.set("split", split_fn)?;

    // re.compile(pattern [, options]) -> pattern
    let compile_fn = lua.create_function(|lua, (pattern, options): (String, Option<String>)| {
        let opts = options.unwrap_or_default();

        match build_regex(&pattern, &opts) {
            Ok(regex) => {
                let id = format!("{:p}", &regex);
                if let Ok(mut patterns) = COMPILED_PATTERNS.lock() {
                    patterns.insert(id.clone(), regex);
                }

                let result = lua.create_table()?;
                result.set("pattern", pattern)?;
                result.set("options", opts)?;
                result.set("id", id)?;

                Ok(result)
            }
            Err(e) => Err(mlua::Error::RuntimeError(e)),
        }
    })?;
    re.set("compile", compile_fn)?;

    // re.find_newlines(str, pattern) -> table
    let find_newlines_fn = lua.create_function(|lua, (s, pattern): (String, String)| {
        let regex = match RegexBuilder::new(&pattern).size_limit(50_000).build() {
            Ok(r) => r,
            Err(_) => return lua.create_table(),
        };

        let result = lua.create_table()?;
        let mut index = 1;

        for m in regex.find_iter(&s) {
            let entry = lua.create_table()?;
            entry.set("start", m.start() + 1)?;
            entry.set("end", m.end())?;
            entry.set("text", m.as_str())?;
            result.set(index, entry)?;
            index += 1;
        }

        Ok(result)
    })?;
    re.set("find_newlines", find_newlines_fn)?;

    // re.updatelocale() -> boolean
    // Updates character classes for locale-aware matching
    // Rust regex doesn't directly support this, but we provide a stub for compatibility
    let updatelocale_fn = lua.create_function(|_lua, ()| Ok(true))?;
    re.set("updatelocale", updatelocale_fn)?;

    // re.version() -> string
    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0"))?;
    re.set("version", version_fn)?;

    globals.set("re", re)?;
    Ok(())
}
