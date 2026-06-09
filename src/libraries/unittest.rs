//! NSE unittest library wrapper
//!
//! Unit testing support for NSE libraries and scripts.
//! Based on Nmap's unittest library: https://nmap.org/nsedoc/lib/unittest.html

use mlua::{Lua, Result as LuaResult, Value};
use rustc_hash::FxHashMap;
use std::sync::Mutex;

static TEST_RESULTS: std::sync::LazyLock<Mutex<FxHashMap<String, Vec<TestResult>>>> =
    std::sync::LazyLock::new(|| Mutex::new(FxHashMap::default()));

#[derive(Debug)]
struct TestResult {
    name: String,
    passed: bool,
    message: String,
}

pub fn register_unittest_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let unittest = lua.create_table()?;

    let test_fn = lua.create_function(
        |_lua, (name, passed, message): (String, bool, Option<String>)| {
            let msg = if let Some(m) = message {
                m
            } else if passed {
                "OK".to_string()
            } else {
                "Failed".to_string()
            };

            let result = TestResult {
                name: name.clone(),
                passed,
                message: msg,
            };

            if let Ok(mut results) = TEST_RESULTS.lock() {
                results
                    .entry("current".to_string())
                    .or_insert_with(Vec::new)
                    .push(result);
            }

            Ok(passed)
        },
    )?;
    unittest.set("test", test_fn)?;

    let expect_fn = lua.create_function(
        |_lua, (name, actual, expected, message): (String, Value, Value, Option<String>)| {
            let actual_str = format!("{:?}", actual);
            let expected_str = format!("{:?}", expected);
            let passed = actual_str == expected_str;

            let msg = message.unwrap_or_else(|| {
                if passed {
                    format!("{}: expected {}, got {}", name, expected_str, actual_str)
                } else {
                    format!("{}: expected {}, got {}", name, expected_str, actual_str)
                }
            });

            let result = TestResult {
                name: name.clone(),
                passed,
                message: msg,
            };

            if let Ok(mut results) = TEST_RESULTS.lock() {
                results
                    .entry("current".to_string())
                    .or_insert_with(Vec::new)
                    .push(result);
            }

            Ok(passed)
        },
    )?;
    unittest.set("expect", expect_fn)?;

    let assert_fn = lua.create_function(
        |_lua, (name, condition, message): (String, bool, Option<String>)| {
            if !condition {
                let msg = message.unwrap_or_else(|| format!("Assertion failed: {}", name));

                let result = TestResult {
                    name: name.clone(),
                    passed: false,
                    message: msg,
                };

                if let Ok(mut results) = TEST_RESULTS.lock() {
                    results
                        .entry("current".to_string())
                        .or_insert_with(Vec::new)
                        .push(result);
                }

                return Err(mlua::Error::RuntimeError(format!(
                    "Assertion failed: {}",
                    name
                )));
            }

            let result = TestResult {
                name: name.clone(),
                passed: true,
                message: message.unwrap_or_else(|| "OK".to_string()),
            };

            if let Ok(mut results) = TEST_RESULTS.lock() {
                results
                    .entry("current".to_string())
                    .or_insert_with(Vec::new)
                    .push(result);
            }

            Ok(true)
        },
    )?;
    unittest.set("assert", assert_fn)?;

    let compare_fn =
        lua.create_function(|_lua, (name, actual, expected): (String, Value, Value)| {
            let actual_str = format!("{:?}", actual);
            let expected_str = format!("{:?}", expected);
            let passed = actual_str == expected_str;

            if !passed {
                return Err(mlua::Error::RuntimeError(format!(
                    "{}: expected {}, got {}",
                    name, expected_str, actual_str
                )));
            }

            Ok(passed)
        })?;
    unittest.set("compare", compare_fn)?;

    let results_fn = lua.create_function(|lua, test_name: Option<String>| {
        let results = lua.create_table()?;

        if let Ok(map) = TEST_RESULTS.lock() {
            let key = test_name.unwrap_or_else(|| "current".to_string());

            if let Some(test_results) = map.get(&key) {
                for (i, result) in test_results.iter().enumerate() {
                    let entry = lua.create_table()?;
                    entry.set("name", result.name.clone())?;
                    entry.set("passed", result.passed)?;
                    entry.set("message", result.message.clone())?;
                    results.set(i + 1, entry)?;
                }
            }
        }

        Ok(results)
    })?;
    unittest.set("results", results_fn)?;

    let summary_fn = lua.create_function(|lua, test_name: Option<String>| {
        let summary = lua.create_table()?;

        if let Ok(map) = TEST_RESULTS.lock() {
            let key = test_name.unwrap_or_else(|| "current".to_string());

            if let Some(test_results) = map.get(&key) {
                let total = test_results.len();
                let passed = test_results.iter().filter(|r| r.passed).count();
                let failed = total - passed;

                summary.set("total", total)?;
                summary.set("passed", passed)?;
                summary.set("failed", failed)?;
                summary.set(
                    "success_rate",
                    if total > 0 {
                        (passed as f64 / total as f64) * 100.0
                    } else {
                        0.0
                    },
                )?;
            } else {
                summary.set("total", 0)?;
                summary.set("passed", 0)?;
                summary.set("failed", 0)?;
                summary.set("success_rate", 0.0)?;
            }
        }

        Ok(summary)
    })?;
    unittest.set("summary", summary_fn)?;

    let passed_fn = lua.create_function(|lua, test_name: Option<String>| {
        let passed = lua.create_table()?;

        if let Ok(map) = TEST_RESULTS.lock() {
            let key = test_name.unwrap_or_else(|| "current".to_string());

            if let Some(test_results) = map.get(&key) {
                for (i, result) in test_results.iter().enumerate() {
                    if result.passed {
                        passed.set(i + 1, result.name.clone())?;
                    }
                }
            }
        }

        Ok(passed)
    })?;
    unittest.set("passed", passed_fn)?;

    let failed_fn = lua.create_function(|lua, test_name: Option<String>| {
        let failed = lua.create_table()?;

        if let Ok(map) = TEST_RESULTS.lock() {
            let key = test_name.unwrap_or_else(|| "current".to_string());

            if let Some(test_results) = map.get(&key) {
                for (i, result) in test_results.iter().enumerate() {
                    if !result.passed {
                        failed.set(i + 1, result.name.clone())?;
                    }
                }
            }
        }

        Ok(failed)
    })?;
    unittest.set("failed", failed_fn)?;

    let clear_fn = lua.create_function(|_lua, test_name: Option<String>| {
        if let Ok(mut map) = TEST_RESULTS.lock() {
            let key = test_name.unwrap_or_else(|| "current".to_string());
            map.remove(&key);
        }
        Ok(true)
    })?;
    unittest.set("clear", clear_fn)?;

    let reset_fn = lua.create_function(|_lua, _: ()| {
        if let Ok(mut map) = TEST_RESULTS.lock() {
            map.clear();
        }
        Ok(true)
    })?;
    unittest.set("reset", reset_fn)?;

    let log_fn = lua.create_function(|_lua, (level, message): (Option<String>, String)| {
        let lvl = level.unwrap_or_else(|| "info".to_string());
        match lvl.as_str() {
            "debug" => eprintln!("[DEBUG] {}", message),
            "info" => println!("[INFO] {}", message),
            "warn" => eprintln!("[WARN] {}", message),
            "error" => eprintln!("[ERROR] {}", message),
            _ => println!("[INFO] {}", message),
        }
        Ok(())
    })?;
    unittest.set("log", log_fn)?;

    let test_suite_fn = lua.create_function(|_lua, name: String| {
        if let Ok(mut results) = TEST_RESULTS.lock() {
            results.remove(&name);
            results.entry(name.clone()).or_insert_with(Vec::new);
        }
        Ok(true)
    })?;
    unittest.set("test_suite", test_suite_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    unittest.set("version", version_fn)?;

    globals.set("unittest", unittest)?;
    Ok(())
}
