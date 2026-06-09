//! mlua 0.11 Compatibility Layer
//!
//! This module provides a clean abstraction for working with mlua 0.11's stricter API.
//! It handles the common patterns needed across all NSE library wrappers.
//!
//! ## Usage
//!
//! Add `#[macro_use] mod compat;` at the top of your library file, then use:
//! - `set_fn!(table, "name", lua, |lua, arg1, arg2| { ... })` - for functions that return Result
//! - `try_set_fn!(table, "name", lua, |lua, arg1, arg2| { ... })` - for functions that might fail
//! - `value_to_string(&Value)` - for converting LuaString to String
//! - `table_get_opt::<T>(table, key)` - for safe table gets

use mlua::{Table, Value};

/// Convert a Lua Value (specifically LuaString) to a Rust String
/// In mlua 0.11, LuaString doesn't implement Display, so we use to_string_lossy
pub fn value_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.to_string_lossy().to_string()),
        _ => None,
    }
}

/// Convert an optional Lua Value to an optional String
pub fn opt_value_to_string(v: Option<&Value>) -> Option<String> {
    v.and_then(value_to_string)
}

/// Parse an Option<Value> as a proto/state string (common pattern in shortport)
pub fn parse_proto_state(v: Option<Value>) -> Option<String> {
    v.and_then(|vv| value_to_string(&vv))
}

/// Safely get a value from a table, returning Option
pub fn table_get<T: mlua::FromLua>(table: &Table, key: &str) -> Option<T> {
    table.get(key).ok()
}

/// Safely get a value from a table by index
pub fn table_get_index<T: mlua::FromLua>(table: &Table, index: usize) -> Option<T> {
    table.get(index).ok()
}

/// Get table length safely (mlua 0.11 returns Result)
pub fn table_len(table: &Table) -> usize {
    table.len().unwrap_or(0) as usize
}

/// Helper macro to set a function on a table (strict mode - returns Result)
/// Usage: set_fn!(table, "function_name", lua, |lua, arg1, arg2| { ... })
#[macro_export]
macro_rules! set_fn {
    // No arguments
    ($table:expr_2021, $name:expr_2021, $lua:expr_2021, |$lua_arg:ident| $body:expr_2021) => {{
        let func = $lua.create_function(|$lua_arg| $body)?;
        $table.set($name, func)?;
    }};
    // Single argument
    ($table:expr_2021, $name:expr_2021, $lua:expr_2021, |$lua_arg:ident, $arg1:ident| $body:expr_2021) => {{
        let func = $lua.create_function(|$lua_arg, $arg1| $body)?;
        $table.set($name, func)?;
    }};
    // Multiple arguments
    ($table:expr_2021, $name:expr_2021, $lua:expr_2021, |$lua_arg:ident, $($arg:ident),*| $body:expr_2021) => {{
        let func = $lua.create_function(|$lua_arg, ($($arg,)*)| $body)?;
        $table.set($name, func)?;
    }};
}

/// Helper macro to set a function on a table (soft mode - ignores errors)
/// Usage: try_set_fn!(table, "function_name", lua, |lua, arg1, arg2| { ... })
#[macro_export]
macro_rules! try_set_fn {
    // No arguments
    ($table:expr_2021, $name:expr_2021, $lua:expr_2021, |$lua_arg:ident| $body:expr_2021) => {{
        if let Ok(func) = $lua.create_function(|$lua_arg| $body) {
            let _ = $table.set($name, func);
        }
    }};
    // Single argument
    ($table:expr_2021, $name:expr_2021, $lua:expr_2021, |$lua_arg:ident, $arg1:ident| $body:expr_2021) => {{
        if let Ok(func) = $lua.create_function(|$lua_arg, $arg1| $body) {
            let _ = $table.set($name, func);
        }
    }};
    // Multiple arguments (captures rest as tuple)
    ($table:expr_2021, $name:expr_2021, $lua:expr_2021, |$lua_arg:ident, $($arg:ident),*| $body:expr_2021) => {{
        if let Ok(func) = $lua.create_function(|$lua_arg, ($($arg,)*)| $body) {
            let _ = $table.set($name, func);
        }
    }};
}

/// Helper macro to set a simple value on a table (soft mode)
#[macro_export]
macro_rules! try_set {
    ($table:expr_2021, $name:expr_2021, $value:expr_2021) => {{
        let _ = $table.set($name, $value);
    }};
}

/// Helper macro to set a value that returns Result (soft mode)
#[macro_export]
macro_rules! try_set_result {
    ($table:expr_2021, $name:expr_2021, $value:expr_2021) => {{
        if let Ok(v) = $value {
            let _ = $table.set($name, v);
        }
    }};
}

/// Helper to create a table and set it as a global
#[macro_export]
macro_rules! create_global_table {
    ($lua:expr_2021, $name:expr_2021) => {{
        let table = $lua.create_table()?;
        $lua.globals().set($name, table)?;
        table
    }};
}

/// Version of create_global_table that ignores errors
#[macro_export]
macro_rules! try_create_global_table {
    ($lua:expr_2021, $name:expr_2021) => {{
        if let Ok(table) = $lua.create_table() {
            let _ = $lua.globals().set($name, table);
            Some(table)
        } else {
            None
        }
    }};
}
