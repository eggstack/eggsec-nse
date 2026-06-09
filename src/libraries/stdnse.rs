//! NSE stdnse (Standard NSE Functions) library
//!
//! Provides standard utility functions that NSE scripts depend on.

use mlua::{Lua, Result as LuaResult, Table, Value};

pub fn register_stdlib(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();

    let stdnse = lua.create_table()?;

    stdnse.set("verbose", 1)?;
    stdnse.set("silent", false)?;
    stdnse.set("script_args", "")?;
    stdnse.set("args", lua.create_table()?)?;
    stdnse.set("loglevel", "normal")?;
    stdnse.set("debug_enabled", false)?;
    stdnse.set("script_name", "")?;
    stdnse.set("base_coroutine", lua.create_table()?)?;
    stdnse.set("_threads", lua.create_table()?)?;
    stdnse.set("interactive", false)?;

    let format_output_fn =
        lua.create_function(|_lua, (output, options): (Table, Option<Table>)| {
            let separator = options
                .and_then(|o| o.get::<String>("separator").ok())
                .unwrap_or_else(|| "\n".to_string());

            let mut lines = Vec::new();
            let mut severity = "ok".to_string();

            for (k, v) in output.pairs::<Value, Value>().flatten() {
                let key = k.to_string().unwrap_or_default();
                let val = v.to_string().unwrap_or_default();
                if key == "severity" || key == "status" {
                    severity = val;
                } else {
                    lines.push(format!("{}: {}", key, val));
                }
            }

            let result = if lines.is_empty() {
                String::new()
            } else {
                lines.join(&separator)
            };
            Ok((result, severity))
        })?;
    stdnse.set("format_output", format_output_fn)?;

    let output_table_fn = lua.create_function(|lua, table: Option<Table>| match table {
        Some(t) => Ok(Value::Table(t)),
        None => Ok(Value::Table(lua.create_table()?)),
    })?;
    stdnse.set("output_table", output_table_fn)?;

    let debug_fn = lua.create_function(|lua, msg: String| {
        let globals = lua.globals();
        if let Ok(stdnse_tbl) = globals.get::<Table>("stdnse") {
            if let Ok(debug_enabled) = stdnse_tbl.get::<bool>("debug_enabled") {
                if debug_enabled {
                    eprintln!("DEBUG: {}", msg);
                }
            }
        }
        Ok(())
    })?;
    stdnse.set("debug", debug_fn)?;

    let verbose_fn = lua.create_function(|lua, msg: String| {
        let globals = lua.globals();
        if let Ok(stdnse_tbl) = globals.get::<Table>("stdnse") {
            if let Ok(verbose_val) = stdnse_tbl.get::<i32>("verbose") {
                if verbose_val > 0 {
                    println!("{}", msg);
                }
            }
        }
        Ok(())
    })?;
    stdnse.set("verbose1", verbose_fn)?;

    let verbose2_fn = lua.create_function(|lua, msg: String| {
        let globals = lua.globals();
        if let Ok(stdnse_tbl) = globals.get::<Table>("stdnse") {
            if let Ok(verbose_val) = stdnse_tbl.get::<i32>("verbose") {
                if verbose_val > 1 {
                    println!("{}", msg);
                }
            }
        }
        Ok(())
    })?;
    stdnse.set("verbose2", verbose2_fn)?;

    let verbose3_fn = lua.create_function(|lua, msg: String| {
        let globals = lua.globals();
        if let Ok(stdnse_tbl) = globals.get::<Table>("stdnse") {
            if let Ok(verbose_val) = stdnse_tbl.get::<i32>("verbose") {
                if verbose_val > 2 {
                    println!("{}", msg);
                }
            }
        }
        Ok(())
    })?;
    stdnse.set("verbose3", verbose3_fn)?;

    let verbose4_fn = lua.create_function(|lua, msg: String| {
        let globals = lua.globals();
        if let Ok(stdnse_tbl) = globals.get::<Table>("stdnse") {
            if let Ok(verbose_val) = stdnse_tbl.get::<i32>("verbose") {
                if verbose_val > 3 {
                    println!("{}", msg);
                }
            }
        }
        Ok(())
    })?;
    stdnse.set("verbose4", verbose4_fn)?;

    let return_true_fn = lua.create_function(|_lua, _: ()| Ok(true))?;
    stdnse.set("return_true", return_true_fn)?;

    let return_false_fn = lua.create_function(|_lua, _: ()| Ok(false))?;
    stdnse.set("return_false", return_false_fn)?;

    let test_callback_fn =
        lua.create_function(|_lua, (callback, value): (mlua::Function, String)| {
            let result: mlua::Value = callback.call(value.clone())?;
            Ok(result)
        })?;
    stdnse.set("test_callback", test_callback_fn)?;

    let base64_fn = lua.create_function(|_lua, s: String| {
        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD.encode(s))
    })?;
    stdnse.set("base64", base64_fn)?;

    let unbase64_fn = lua.create_function(|_lua, s: String| {
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(&s) {
            Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).to_string()),
            Err(_) => Ok(String::new()),
        }
    })?;
    stdnse.set("unbase64", unbase64_fn)?;

    let hex_fn = lua.create_function(|_lua, s: String| {
        Ok(s.bytes().map(|b| format!("{:02x}", b)).collect::<String>())
    })?;
    stdnse.set("hex_to_bytes", hex_fn)?;

    let unhex_fn = lua.create_function(|_lua, s: String| {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect();
        Ok(String::from_utf8_lossy(&bytes).to_string())
    })?;
    stdnse.set("unhex", unhex_fn)?;

    let strsplit_fn = lua.create_function(|_lua, (s, sep): (String, String)| {
        let parts: Vec<String> = s.split(&sep).map(|s| s.to_string()).collect();
        Ok(parts)
    })?;
    stdnse.set("strsplit", strsplit_fn)?;

    let verb_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    stdnse.set("version", verb_fn)?;

    let sleep_fn = lua.create_function(|_lua, seconds: f64| {
        std::thread::sleep(std::time::Duration::from_secs_f64(seconds));
        Ok(())
    })?;
    stdnse.set("sleep", sleep_fn)?;

    let clock_fn = lua.create_function(|_lua, _: ()| Ok(chrono::Utc::now().timestamp() as f64))?;
    stdnse.set("clock", clock_fn)?;

    let get_time_fn = lua.create_function(|_lua, _: ()| {
        let now = chrono::Utc::now();
        Ok(now.format("%Y-%m-%d %H:%M:%S").to_string())
    })?;
    stdnse.set("get_time", get_time_fn)?;

    let usleep_fn = lua.create_function(|_lua, microseconds: u64| {
        std::thread::sleep(std::time::Duration::from_micros(microseconds));
        Ok(())
    })?;
    stdnse.set("usleep", usleep_fn)?;

    let format_fn = lua.create_function(|_lua, (fmt, args): (String, Table)| {
        let mut result = String::new();
        let mut chars = fmt.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '%' {
                match chars.next() {
                    Some('s') => {
                        let arg_key = result.matches('%').count() + 1;
                        match args.get::<String>(arg_key) {
                            Ok(val) => {
                                result.push_str(&val);
                            }
                            _ => {
                                result.push_str("%s");
                            }
                        }
                    }
                    Some('d') => {
                        let arg_key = result.matches('%').count() + 1;
                        match args.get::<i64>(arg_key) {
                            Ok(val) => {
                                result.push_str(&val.to_string());
                            }
                            _ => {
                                result.push_str("%d");
                            }
                        }
                    }
                    Some(c2) => {
                        result.push('%');
                        result.push(c2);
                    }
                    None => result.push('%'),
                }
            } else {
                result.push(c);
            }
        }

        Ok(result)
    })?;
    stdnse.set("format", format_fn)?;

    let tohex_fn = lua.create_function(|_lua, (s, upper): (String, Option<bool>)| {
        let bytes = s.as_bytes();
        let hex: String = bytes
            .iter()
            .map(|b| {
                if upper.unwrap_or(false) {
                    format!("{:02X}", b)
                } else {
                    format!("{:02x}", b)
                }
            })
            .collect();
        Ok(hex)
    })?;
    stdnse.set("tohex", tohex_fn)?;

    let fromhex_fn = lua.create_function(|_lua, s: String| {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect();
        Ok(String::from_utf8_lossy(&bytes).to_string())
    })?;
    stdnse.set("fromhex", fromhex_fn)?;

    let random_string_fn = lua.create_function(|_lua, length: usize| {
        use rand::Rng;
        let charset: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            .chars()
            .collect();
        let mut rng = rand::thread_rng();
        let result: String = (0..length)
            .map(|_| charset[rng.gen_range(0..charset.len())])
            .collect();
        Ok(result)
    })?;
    stdnse.set("random_string", random_string_fn)?;

    let linspace_fn = lua.create_function(|lua, (start, stop, num): (f64, f64, usize)| {
        let num = num.max(1);
        let step = (stop - start) / (num - 1) as f64;
        let result = lua.create_table()?;
        for i in 0..num {
            let value = if i == num - 1 {
                stop
            } else {
                start + step * i as f64
            };
            result.set(i + 1, value)?;
        }
        Ok(result)
    })?;
    stdnse.set("linspace", linspace_fn)?;

    let is_visible_fn = lua.create_function(|_lua, _: ()| Ok(true))?;
    stdnse.set("is_visible", is_visible_fn)?;

    let nsleep_fn = lua.create_function(|_lua, nanoseconds: u64| {
        std::thread::sleep(std::time::Duration::from_nanos(nanoseconds));
        Ok(())
    })?;
    stdnse.set("nsleep", nsleep_fn)?;

    let action_fn = lua.create_function(|lua, func: mlua::Function| {
        let globals = lua.globals();
        globals.set("action", func)?;
        Ok(())
    })?;
    stdnse.set("action", action_fn)?;

    let do_action_fn = lua.create_function(|lua, (host, port): (Table, Table)| {
        let globals = lua.globals();
        if let Ok(action) = globals.get::<mlua::Function>("action") {
            action.call::<mlua::Value>((host, port))?;
        }
        Ok(mlua::Value::Nil)
    })?;
    stdnse.set("do_action", do_action_fn)?;

    let register_prerule_fn = lua.create_function(|lua, func: mlua::Function| {
        let globals = lua.globals();
        globals.set("prerule", func)?;
        Ok(())
    })?;
    stdnse.set("register_prerule", register_prerule_fn)?;

    let register_postrule_fn = lua.create_function(|lua, func: mlua::Function| {
        let globals = lua.globals();
        globals.set("postrule", func)?;
        Ok(())
    })?;
    stdnse.set("register_postrule", register_postrule_fn)?;

    let register_portrule_fn = lua.create_function(|lua, func: mlua::Function| {
        let globals = lua.globals();
        globals.set("portrule", func)?;
        Ok(())
    })?;
    stdnse.set("register_portrule", register_portrule_fn)?;

    let register_hostrule_fn = lua.create_function(|lua, func: mlua::Function| {
        let globals = lua.globals();
        globals.set("hostrule", func)?;
        Ok(())
    })?;
    stdnse.set("register_hostrule", register_hostrule_fn)?;

    let verbosity_fn = lua.create_function(|lua, level: Option<i32>| {
        let globals = lua.globals();
        let stdnse_tbl: Table = globals.get("stdnse")?;
        if let Some(lvl) = level {
            stdnse_tbl.set("verbose", lvl)?;
        }
        let verbose: i32 = stdnse_tbl.get("verbose").unwrap_or(1);
        Ok(verbose)
    })?;
    stdnse.set("verbosity", verbosity_fn)?;

    let silent_fn = lua.create_function(|lua, silent: Option<bool>| {
        let globals = lua.globals();
        let stdnse_tbl: Table = globals.get("stdnse")?;
        if let Some(s) = silent {
            stdnse_tbl.set("silent", s)?;
        }
        let silent: bool = stdnse_tbl.get("silent").unwrap_or(false);
        Ok(silent)
    })?;
    stdnse.set("silent", silent_fn)?;

    let debug_enabled_fn = lua.create_function(|lua, enable: Option<bool>| {
        let globals = lua.globals();
        let stdnse_tbl: Table = globals.get("stdnse")?;
        if let Some(e) = enable {
            stdnse_tbl.set("debug_enabled", e)?;
        }
        let debug: bool = stdnse_tbl.get("debug_enabled").unwrap_or(false);
        Ok(debug)
    })?;
    stdnse.set("debug_enabled", debug_enabled_fn)?;

    let get_checked_host_fn = lua.create_function(|lua, _: ()| {
        let globals = lua.globals();
        let nmap_tbl: Table = globals.get("nmap")?;
        let hostinfo: Table = nmap_tbl.get("_hostinfo")?;
        Ok(hostinfo)
    })?;
    stdnse.set("get_checked_host", get_checked_host_fn)?;

    let get_checked_port_fn = lua.create_function(|lua, _: ()| {
        let globals = lua.globals();
        let nmap_tbl: Table = globals.get("nmap")?;
        let ports: Table = nmap_tbl.get("_ports")?;
        Ok(ports)
    })?;
    stdnse.set("get_checked_port", get_checked_port_fn)?;

    let get_port_state_fn = lua.create_function(|lua, (_host, port): (Option<String>, u16)| {
        let globals = lua.globals();
        let nmap_tbl: Table = globals.get("nmap")?;
        let ports: Table = nmap_tbl.get("_ports")?;

        let key = format!("{}.tcp", port);
        if let Ok(port_info) = ports.get::<Table>(key) {
            return Ok(port_info);
        }

        let t = lua.create_table()?;
        t.set("number", port)?;
        t.set("protocol", "tcp")?;
        t.set("state", "unknown")?;
        Ok(t)
    })?;
    stdnse.set("get_port_state", get_port_state_fn)?;

    let status_fn = lua.create_function(|_lua, (code, message): (i32, String)| {
        let status = match code {
            0 => "ERROR",
            1 => "FAILED",
            2 => "UNKNOWN",
            3 => "OPEN",
            4 => "OPEN|FILTERED",
            5 => "FILTERED",
            6 => "CLOSED",
            7 => "CLOSED|FILTERED",
            _ => "UNKNOWN",
        };
        Ok(format!("{}: {}", status, message))
    })?;
    stdnse.set("status", status_fn)?;

    stdnse.set("output", lua.create_table()?)?;
    stdnse.set("_suppress_errors", false)?;

    let output_add_fn = lua.create_function(|lua, (key, value): (String, Value)| {
        let globals = lua.globals();
        let stdnse_tbl: Table = globals.get("stdnse")?;

        let output: Table = stdnse_tbl.get("output")?;
        output.set(key.clone(), value.clone())?;

        let script_output: Table = globals.get("_SCRIPT_OUTPUT").unwrap_or_else(|_| {
            lua.create_table()
                .unwrap_or_else(|_| lua.create_table().unwrap())
        });
        let len = script_output.len().unwrap_or(0) + 1;
        script_output.set(len, format!("{}: {:?}", key, value))?;

        Ok(())
    })?;
    stdnse.set("output_add", output_add_fn)?;

    let suppress_errors_fn = lua.create_function(|lua, suppress: Option<bool>| {
        let globals = lua.globals();
        let stdnse_tbl: Table = globals.get("stdnse")?;

        if let Some(s) = suppress {
            stdnse_tbl.set("_suppress_errors", s)?;
        }

        let suppressed: bool = stdnse_tbl.get("_suppress_errors").unwrap_or(false);
        Ok(suppressed)
    })?;
    stdnse.set("suppress_errors", suppress_errors_fn)?;

    let raise_error_fn = lua.create_function(|_lua, (msg, suppress): (String, Option<bool>)| {
        if suppress.unwrap_or(false) {
            return Ok(());
        }
        Err(mlua::Error::RuntimeError(msg))
    })?;
    stdnse.set("raise_error", raise_error_fn)?;

    let format_direrror_fn =
        lua.create_function(|_lua, err: String| Ok(format!("ERROR: {}", err)))?;
    stdnse.set("format_direrror", format_direrror_fn)?;

    let format_verbose_fn = lua.create_function(|lua, (verbose, normal): (String, String)| {
        let globals = lua.globals();
        if let Ok(stdnse_tbl) = globals.get::<Table>("stdnse") {
            if let Ok(verbose_val) = stdnse_tbl.get::<i32>("verbose") {
                if verbose_val > 0 {
                    return Ok(verbose);
                }
            }
        }
        Ok(normal)
    })?;
    stdnse.set("format_verbose", format_verbose_fn)?;

    let format_debug_fn = lua.create_function(|lua, (debug, normal): (String, String)| {
        let globals = lua.globals();
        if let Ok(stdnse_tbl) = globals.get::<Table>("stdnse") {
            if let Ok(debug_val) = stdnse_tbl.get::<bool>("debug_enabled") {
                if debug_val {
                    return Ok(debug);
                }
            }
        }
        Ok(normal)
    })?;
    stdnse.set("format_debug", format_debug_fn)?;

    let get_script_args_fn = lua.create_function(|lua, key: Option<String>| {
        let globals = lua.globals();
        let stdnse_tbl: Table = globals.get("stdnse")?;

        if let Ok(args_table) = stdnse_tbl.get::<Table>("args") {
            if let Some(k) = key {
                if let Ok(val) = args_table.get::<String>(k.as_str()) {
                    return Ok(val);
                }
            } else {
                if let Ok(all_args) = stdnse_tbl.get::<String>("script_args") {
                    return Ok(all_args);
                }
            }
        }

        Ok(String::new())
    })?;
    stdnse.set("get_script_args", get_script_args_fn)?;

    let get_script_name_fn = lua.create_function(|lua, _: ()| {
        let globals = lua.globals();
        let stdnse_tbl: Table = globals.get("stdnse")?;
        let name: String = stdnse_tbl.get("script_name").unwrap_or_default();
        Ok(name)
    })?;
    stdnse.set("get_script_name", get_script_name_fn)?;

    let get_hostname_fn = lua.create_function(|lua, host: Option<Table>| {
        let globals = lua.globals();
        let nmap_tbl: Table = globals.get("nmap")?;

        if let Ok(hostinfo) = nmap_tbl.get::<Table>("_hostinfo") {
            if let Ok(name) = hostinfo.get::<String>("name") {
                if !name.is_empty() {
                    return Ok(name);
                }
            }
        }

        if let Some(h) = host {
            if let Ok(ip) = h.get::<String>("ip") {
                return Ok(ip);
            }
            if let Ok(address) = h.get::<String>("address") {
                return Ok(address);
            }
        }

        let target: String = nmap_tbl.get("target").unwrap_or_default();
        Ok(target)
    })?;
    stdnse.set("get_hostname", get_hostname_fn)?;

    let make_buffer_fn = lua.create_function(
        |lua, (socket, sep, buffer_size): (Value, Option<String>, Option<usize>)| {
            let buffer = lua.create_table()?;
            let sep = sep.unwrap_or_else(|| "\n".to_string());
            let size = buffer_size.unwrap_or(4096);

            buffer.set("socket", socket)?;
            buffer.set("separator", sep)?;
            buffer.set("buffer", "")?;
            buffer.set("buffer_size", size)?;

            Ok(buffer)
        },
    )?;
    stdnse.set("make_buffer", make_buffer_fn)?;

    let get_timeout_fn = lua.create_function(
        |_lua, (host, max_timeout, min_timeout): (Option<String>, Option<i64>, Option<i64>)| {
            let max = max_timeout.unwrap_or(10000);
            let min = min_timeout.unwrap_or(2000);

            let timeout = if let Some(h) = host {
                if h.contains('.') || h.contains(':') {
                    max
                } else {
                    min
                }
            } else {
                min
            };

            Ok(timeout)
        },
    )?;
    stdnse.set("get_timeout", get_timeout_fn)?;

    let clock_ms_fn = lua.create_function(|_lua, _: ()| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        Ok(now as f64)
    })?;
    stdnse.set("clock_ms", clock_ms_fn)?;

    let clock_us_fn = lua.create_function(|_lua, _: ()| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros();
        Ok(now as f64)
    })?;
    stdnse.set("clock_us", clock_us_fn)?;

    let parse_timespec_fn = lua.create_function(|_lua, timespec: String| {
        let timespec = timespec.trim();
        let mut multiplier = 1.0;

        if timespec.ends_with("s") {
            multiplier = 1.0;
        } else if timespec.ends_with("ms") {
            multiplier = 0.001;
        } else if timespec.ends_with("us") || timespec.ends_with("μs") {
            multiplier = 0.000001;
        } else if timespec.ends_with("m") {
            multiplier = 60.0;
        } else if timespec.ends_with("h") {
            multiplier = 3600.0;
        } else if timespec.ends_with("d") {
            multiplier = 86400.0;
        }

        let num_part: f64 = timespec
            .trim_end_matches(|c: char| c.is_alphabetic())
            .parse()
            .unwrap_or(0.0);
        Ok(num_part * multiplier)
    })?;
    stdnse.set("parse_timespec", parse_timespec_fn)?;

    let silent_require_fn = lua.create_function(|lua, name: String| {
        let globals = lua.globals();

        let known_modules = [
            "stdnse",
            "nmap",
            "http",
            "socket",
            "ssl",
            "tls",
            "shortport",
            "comm",
            "sslcert",
            "mysql",
            "postgres",
            "mssql",
            "redis",
            "mongodb",
            "ldap",
            "smb",
            "snmp",
            "ftp",
            "smtp",
            "dns",
            "ssh",
            "ssh2",
            "datafiles",
            "url",
            "json",
            "base64",
            "datetime",
            "rand",
            "bit",
            "io",
            "os",
            "strbuf",
            "tab",
            "stringaux",
            "vulns",
            "creds",
            "unpwdb",
            "http",
            "httpspider",
            "regex",
            "openssl",
        ];

        if known_modules.iter().any(|&m| m == name) {
            return Ok(true);
        }

        if let Ok(req_modules) = globals.get::<Table>("_REQUIRE_MODULES") {
            if let Ok(_) = req_modules.get::<mlua::Value>(name.as_str()) {
                return Ok(true);
            }
        }

        if let Ok(nmap_lib) = globals.get::<Table>("nmap") {
            if let Ok(_) = nmap_lib.get::<mlua::Value>(name.as_str()) {
                return Ok(true);
            }
        }

        Ok(false)
    })?;
    stdnse.set("silent_require", silent_require_fn)?;

    let seeall_fn = lua.create_function(|lua, env: Table| {
        let globals = lua.globals();
        for (k, v) in globals.pairs::<String, mlua::Value>().flatten() {
            let _ = env.set(k, v);
        }
        Ok(env)
    })?;
    stdnse.set("seeall", seeall_fn)?;

    let pretty_printer_fn = lua.create_function(|lua, obj: Value| {
        let result = lua.create_table()?;

        fn format_value(lua: &Lua, value: &Value, depth: usize) -> String {
            match value {
                Value::Nil => "nil".to_string(),
                Value::Boolean(b) => b.to_string(),
                Value::Number(n) => n.to_string(),
                Value::String(s) => s.to_string_lossy().to_string(),
                Value::Table(t) => {
                    let mut s = String::from("{ ");
                    let len = t.len().unwrap_or(0);
                    for i in 1..=len.min(10) {
                        if let Ok(v) = t.get::<Value>(i) {
                            s.push_str(&format_value(lua, &v, depth + 1));
                            s.push_str(", ");
                        }
                    }
                    if len > 10 {
                        s.push_str(&format!("... {} more", len - 10));
                    }
                    s.push_str(" }");
                    s
                }
                Value::Function(f) => format!("<function: {:?}>", f),
                Value::UserData(u) => format!("<userdata: {:?}>", u),
                Value::Thread(_) => "<thread>".to_string(),
                _ => "<unknown>".to_string(),
            }
        }

        result.set("formatted", format_value(lua, &obj, 0))?;
        Ok(result)
    })?;
    stdnse.set("pretty_printer", pretty_printer_fn)?;

    let get_checked_host_count_fn = lua.create_function(|lua, _: ()| {
        let globals = lua.globals();
        let nmap_tbl: Table = globals.get("nmap")?;
        let hostinfo: Table = nmap_tbl.get("_hostinfo")?;
        let checked: Vec<String> = hostinfo.get("checked_hosts").unwrap_or_else(|_| Vec::new());
        Ok(checked.len() as i64)
    })?;
    stdnse.set("get_checked_host_count", get_checked_host_count_fn)?;

    let get_checked_port_count_fn = lua.create_function(|lua, _: ()| {
        let globals = lua.globals();
        let nmap_tbl: Table = globals.get("nmap")?;
        let ports: Table = nmap_tbl.get("_ports")?;
        let len = ports.len().unwrap_or(0);
        Ok(len)
    })?;
    stdnse.set("get_checked_port_count", get_checked_port_count_fn)?;

    let base_fn = lua.create_function(|lua, _: ()| {
        let globals = lua.globals();
        let stdnse_tbl: Table = globals.get("stdnse")?;
        let base: Table = stdnse_tbl
            .get("base_coroutine")
            .unwrap_or_else(|_| lua.create_table().unwrap());
        Ok(base)
    })?;
    stdnse.set("base", base_fn)?;

    let module_fn = lua.create_function(|lua, name: String| {
        let env = lua.create_table()?;
        env.set("_NAME", name.clone())?;
        env.set("_PACKAGE", name.clone())?;

        let globals = lua.globals();
        env.set("_G", globals)?;

        Ok(env)
    })?;
    stdnse.set("module", module_fn)?;

    use rustc_hash::FxHashMap;
    use std::sync::Mutex;

    static THREAD_RESULTS: std::sync::LazyLock<Mutex<FxHashMap<i64, String>>> =
        std::sync::LazyLock::new(|| Mutex::new(FxHashMap::default()));

    let new_thread_fn =
        lua.create_function(|_lua, (_func, _args): (mlua::Function, Option<Table>)| {
            let thread_id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as i64;

            // Spawn a background thread that executes the function
            // Note: We can't pass mlua::Function across threads, so we'll execute a callback pattern
            // In a full implementation, you'd use a separate Lua state per thread

            std::thread::spawn(move || {
                // The thread runs in background
                // For proper implementation, this would need its own Lua state
                // Results would be communicated via channels
                std::thread::sleep(std::time::Duration::from_millis(10));
            });

            let result = _lua.create_table()?;
            result.set("thread_id", thread_id)?;
            result.set("status", "running")?;

            let globals = _lua.globals();
            if let Ok(stdnse_tbl) = globals.get::<Table>("stdnse") {
                let threads: Table = stdnse_tbl
                    .get("_threads")
                    .unwrap_or_else(|_| _lua.create_table().unwrap());
                let thread_info = _lua.create_table()?;
                thread_info.set("id", thread_id)?;
                thread_info.set("status", "running")?;
                let _ = threads.set(thread_id.to_string(), thread_info);
                let _ = stdnse_tbl.set("_threads", threads);
            }

            Ok(result)
        })?;
    stdnse.set("new_thread", new_thread_fn)?;

    let get_thread_count_fn = lua.create_function(|lua, _: ()| {
        let globals = lua.globals();
        if let Ok(stdnse_tbl) = globals.get::<Table>("stdnse") {
            let threads: Table = stdnse_tbl
                .get("_threads")
                .unwrap_or_else(|_| lua.create_table().unwrap());
            let count = threads.len().unwrap_or(0);
            return Ok(count as i32);
        }
        Ok(0)
    })?;
    stdnse.set("get_thread_count", get_thread_count_fn)?;

    let wait_thread_fn = lua.create_function(|lua, thread_id: Option<i64>| {
        // In a real implementation with proper thread communication, we'd get the result
        // For now, just return nil
        if let Some(tid) = thread_id {
            if let Ok(results) = THREAD_RESULTS.lock() {
                if let Some(result) = results.get(&tid) {
                    if let Ok(s) = lua.create_string(result) {
                        return Ok(mlua::Value::String(s));
                    }
                }
            }
        }
        Ok(mlua::Value::Nil)
    })?;
    stdnse.set("wait_thread", wait_thread_fn)?;

    let kill_thread_fn = lua.create_function(|_lua, thread_id: Option<i64>| {
        if let Some(tid) = thread_id {
            if let Ok(mut results) = THREAD_RESULTS.lock() {
                results.remove(&tid);
            }
        }
        Ok(true)
    })?;
    stdnse.set("kill_thread", kill_thread_fn)?;

    let registry_add_array_fn = lua.create_function(|lua, (keys, value): (Table, String)| {
        let globals = lua.globals();
        let nmap_tbl: Table = globals
            .get("nmap")
            .unwrap_or_else(|_| lua.create_table().unwrap());
        let registry: Table = nmap_tbl
            .get("registry")
            .unwrap_or_else(|_| lua.create_table().unwrap());

        let len = keys.len().unwrap_or(0);
        if len == 0 {
            return Ok(registry);
        }

        let mut current_key = String::new();
        for i in 1..=len {
            if let Ok(key) = keys.get::<String>(i) {
                current_key = key;
            }
        }

        let arr = registry
            .get::<Table>(current_key.clone())
            .unwrap_or_else(|_| lua.create_table().unwrap());
        let arr_len = arr.len().unwrap_or(0) as usize;
        arr.set(arr_len + 1, value).unwrap_or(());

        let _ = registry.set(current_key, arr);
        let _ = nmap_tbl.set("registry", registry);

        let result = lua.create_table()?;
        result.set("success", true)?;
        Ok(result)
    })?;
    stdnse.set("registry_add_array", registry_add_array_fn)?;

    let registry_add_table_fn = lua.create_function(|lua, (keys, value): (Table, Table)| {
        let globals = lua.globals();
        let nmap_tbl: Table = globals
            .get("nmap")
            .unwrap_or_else(|_| lua.create_table().unwrap());
        let registry: Table = nmap_tbl
            .get("registry")
            .unwrap_or_else(|_| lua.create_table().unwrap());

        let len = keys.len().unwrap_or(0);
        if len == 0 {
            return Ok(registry);
        }

        let mut current_key = String::new();
        for i in 1..=len {
            if let Ok(key) = keys.get::<String>(i) {
                current_key = key;
            }
        }

        let _ = registry.set(current_key, value);
        let _ = nmap_tbl.set("registry", registry);

        let result = lua.create_table()?;
        result.set("success", true)?;
        Ok(result)
    })?;
    stdnse.set("registry_add_table", registry_add_table_fn)?;

    let get_script_interfaces_fn =
        lua.create_function(|lua, filter_func: Option<mlua::Function>| {
            let interfaces = lua.create_table()?;

            let lo = lua.create_table()?;
            lo.set("name", "lo")?;
            lo.set("ip", "127.0.0.1")?;
            lo.set("address_family", "inet")?;
            lo.set("mac", "")?;
            lo.set("up", true)?;
            lo.set("ipv6", false)?;
            lo.set("device", "lo")?;

            if let Some(ref f) = filter_func {
                if let Ok(result) = f.call::<mlua::Value>(lo.clone()) {
                    if result.as_boolean().unwrap_or(true) {
                        interfaces.set(1, lo)?;
                    }
                }
            } else {
                interfaces.set(1, lo)?;
            }

            let eth0 = lua.create_table()?;
            eth0.set("name", "eth0")?;
            eth0.set("ip", "0.0.0.0")?;
            eth0.set("address_family", "inet")?;
            eth0.set("mac", "")?;
            eth0.set("up", true)?;
            eth0.set("ipv6", false)?;
            eth0.set("device", "eth0")?;

            if let Some(ref f) = filter_func {
                if let Ok(result) = f.call::<mlua::Value>(eth0.clone()) {
                    if result.as_boolean().unwrap_or(true) {
                        let len = interfaces.len().unwrap_or(0) as usize;
                        interfaces.set(len + 1, eth0)?;
                    }
                }
            } else {
                let len = interfaces.len().unwrap_or(0) as usize;
                interfaces.set(len + 1, eth0)?;
            }

            Ok(interfaces)
        })?;
    stdnse.set("get_script_interfaces", get_script_interfaces_fn)?;

    // Additional utility functions
    let time_fn = lua.create_function(|_lua, _: ()| Ok(chrono::Utc::now().timestamp() as f64))?;
    stdnse.set("time", time_fn)?;

    let bind_fn = lua.create_function(|lua, (port, proto): (u16, Option<String>)| {
        let result = lua.create_table()?;
        result.set("port", port)?;
        result.set("protocol", proto.unwrap_or_else(|| "tcp".to_string()))?;
        result.set("bound", true)?;
        Ok(result)
    })?;
    stdnse.set("bind", bind_fn)?;

    let urandom_fn = lua.create_function(|_lua, length: usize| {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..length).map(|_| rng.r#gen()).collect();
        Ok(String::from_utf8_lossy(&bytes).to_string())
    })?;
    stdnse.set("urandom", urandom_fn)?;

    let crypt_fn = lua.create_function(|_lua, (password, salt): (String, String)| {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        password.hash(&mut hasher);
        salt.hash(&mut hasher);
        let hash = hasher.finish();
        Ok(format!("{:x}", hash))
    })?;
    stdnse.set("crypt", crypt_fn)?;

    let compar_fn = lua.create_function(|_lua, (a, b): (String, String)| Ok(a == b))?;
    stdnse.set("compar", compar_fn)?;

    let cmp_fn = lua.create_function(|_lua, (a, b): (i64, i64)| {
        if a < b {
            Ok(-1)
        } else if a > b {
            Ok(1)
        } else {
            Ok(0)
        }
    })?;
    stdnse.set("cmp", cmp_fn)?;

    let lshift_fn = lua.create_function(|_lua, (value, shift): (u64, u32)| Ok(value << shift))?;
    stdnse.set("lshift", lshift_fn)?;

    let rshift_fn = lua.create_function(|_lua, (value, shift): (u64, u32)| Ok(value >> shift))?;
    stdnse.set("rshift", rshift_fn)?;

    let band_fn = lua.create_function(|_lua, (a, b): (u64, u64)| Ok(a & b))?;
    stdnse.set("band", band_fn)?;

    let bor_fn = lua.create_function(|_lua, (a, b): (u64, u64)| Ok(a | b))?;
    stdnse.set("bor", bor_fn)?;

    let bxor_fn = lua.create_function(|_lua, (a, b): (u64, u64)| Ok(a ^ b))?;
    stdnse.set("bxor", bxor_fn)?;

    let bnot_fn = lua.create_function(|_lua, value: u64| Ok(!value))?;
    stdnse.set("bnot", bnot_fn)?;

    let dirty_bind_fn =
        lua.create_function(|lua, (address, port): (Option<String>, Option<u16>)| {
            let result = lua.create_table()?;
            result.set("address", address.unwrap_or_else(|| "0.0.0.0".to_string()))?;
            result.set("port", port.unwrap_or(0))?;
            result.set("bound", true)?;
            Ok(result)
        })?;
    stdnse.set("dirty_bind", dirty_bind_fn)?;

    let dirty_connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("status", "connected")?;
        Ok(result)
    })?;
    stdnse.set("dirty_connect", dirty_connect_fn)?;

    let process_stdin_fn = lua.create_function(|_lua, _: ()| Ok(false))?;
    stdnse.set("process_stdin", process_stdin_fn)?;

    let process_stdout_fn = lua.create_function(|_lua, _: ()| Ok(true))?;
    stdnse.set("process_stdout", process_stdout_fn)?;

    let process_stderr_fn = lua.create_function(|_lua, _: ()| Ok(true))?;
    stdnse.set("process_stderr", process_stderr_fn)?;

    let require_fn = lua.create_function(|lua, module: String| {
        let globals = lua.globals();

        // Check if already loaded
        if let Ok(modules) = globals.get::<Table>("_REQUIRE_MODULES") {
            if let Ok(_) = modules.get::<mlua::Value>(module.as_str()) {
                return Ok(true);
            }
        }

        // Check globals
        if let Ok(_) = globals.get::<mlua::Value>(module.as_str()) {
            return Ok(true);
        }

        Ok(false)
    })?;
    stdnse.set("require", require_fn)?;

    let provide_fn = lua.create_function(|lua, (module, exports): (String, Option<Table>)| {
        let globals = lua.globals();
        let exports = exports.unwrap_or_else(|| lua.create_table().unwrap());

        let exports_clone = exports.clone();

        globals.set(module.clone(), exports)?;

        if let Ok(modules) = globals.get::<Table>("_REQUIRE_MODULES") {
            let _ = modules.set(module, exports_clone);
        }

        Ok(true)
    })?;
    stdnse.set("provide", provide_fn)?;

    let using_nse_fn = lua.create_function(|_lua, _: ()| Ok(true))?;
    stdnse.set("using_nse", using_nse_fn)?;

    // Add common string manipulation functions
    let strcontains_fn =
        lua.create_function(|_lua, (text, pattern): (String, String)| Ok(text.contains(&pattern)))?;
    stdnse.set("strcontains", strcontains_fn)?;

    let ends_with_fn =
        lua.create_function(|_lua, (text, suffix): (String, String)| Ok(text.ends_with(&suffix)))?;
    stdnse.set("ends_with", ends_with_fn)?;

    let starts_with_fn = lua
        .create_function(|_lua, (text, prefix): (String, String)| Ok(text.starts_with(&prefix)))?;
    stdnse.set("starts_with", starts_with_fn)?;

    // Add min/max functions for numbers
    let min_fn = lua.create_function(|_lua, (a, b): (f64, f64)| Ok(a.min(b)))?;
    stdnse.set("min", min_fn)?;

    let max_fn = lua.create_function(|_lua, (a, b): (f64, f64)| Ok(a.max(b)))?;
    stdnse.set("max", max_fn)?;

    // Add urlencode/urldecode functions
    let urlencode_fn =
        lua.create_function(|_lua, text: String| Ok(urlencoding::encode(&text).to_string()))?;
    stdnse.set("urlencode", urlencode_fn)?;

    let urldecode_fn =
        lua.create_function(|_lua, text: String| match urlencoding::decode(&text) {
            Ok(decoded) => Ok(decoded.to_string()),
            Err(_) => Ok(text),
        })?;
    stdnse.set("urldecode", urldecode_fn)?;

    // Add base64url encoding/decoding (URL-safe base64)
    let base64url_encode_fn = lua.create_function(|_lua, text: String| {
        use base64::Engine;
        Ok(base64::engine::general_purpose::URL_SAFE.encode(text))
    })?;
    stdnse.set("base64url_encode", base64url_encode_fn)?;

    let base64url_decode_fn = lua.create_function(|_lua, text: String| {
        use base64::Engine;
        match base64::engine::general_purpose::URL_SAFE.decode(&text) {
            Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).to_string()),
            Err(_) => Ok(String::new()),
        }
    })?;
    stdnse.set("base64url_decode", base64url_decode_fn)?;

    // Add has_prefix/has_suffix (alias for starts_with/ends_with)
    let has_prefix_fn = lua
        .create_function(|_lua, (text, prefix): (String, String)| Ok(text.starts_with(&prefix)))?;
    stdnse.set("has_prefix", has_prefix_fn)?;

    let has_suffix_fn =
        lua.create_function(|_lua, (text, suffix): (String, String)| Ok(text.ends_with(&suffix)))?;
    stdnse.set("has_suffix", has_suffix_fn)?;

    // Add contains function (alias for strcontains)
    let contains_fn =
        lua.create_function(|_lua, (text, pattern): (String, String)| Ok(text.contains(&pattern)))?;
    stdnse.set("contains", contains_fn)?;

    globals.set("stdnse", stdnse)?;
    Ok(())
}
