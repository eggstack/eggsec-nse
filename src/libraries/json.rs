//! NSE json library wrapper
//!
//! Provides JSON encode/decode functions.

use mlua::{Lua, Result as LuaResult, Table, Value};
use serde_json::{self, Value as JsonValue};

pub fn register_json_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let json = lua.create_table()?;

    fn lua_value_to_json(lua: &Lua, value: Value) -> mlua::Result<JsonValue> {
        match value {
            Value::Nil => Ok(JsonValue::Null),
            Value::Boolean(b) => Ok(JsonValue::Bool(b)),
            Value::Number(n) => Ok(JsonValue::Number(
                serde_json::Number::from_f64(n).unwrap_or(serde_json::Number::from(0)),
            )),
            Value::String(s) => Ok(JsonValue::String(s.to_string_lossy().to_string())),
            Value::Table(t) => {
                let mut obj = serde_json::Map::new();
                let mut is_array = true;

                let mut keys: Vec<serde_json::Value> = Vec::new();
                for (k, _v) in t.pairs::<Value, Value>().flatten() {
                    match k {
                        Value::Number(n) => {
                            keys.push(serde_json::Value::Number(
                                serde_json::Number::from_f64(n)
                                    .unwrap_or(serde_json::Number::from(0)),
                            ));
                        }
                        Value::String(s) => {
                            keys.push(serde_json::Value::String(s.to_string_lossy().to_string()));
                            is_array = false;
                        }
                        _ => {
                            is_array = false;
                        }
                    }
                }

                if is_array && !keys.is_empty() {
                    let mut arr = Vec::new();
                    for i in 1..=keys.len() {
                        if let Ok(v) = t.get::<Value>(i) {
                            arr.push(lua_value_to_json(lua, v)?);
                        }
                    }
                    Ok(JsonValue::Array(arr))
                } else {
                    for (k, v) in t.pairs::<Value, Value>().flatten() {
                        let key = match k {
                            Value::String(s) => s.to_string_lossy().to_string(),
                            Value::Number(n) => n.to_string(),
                            _ => continue,
                        };
                        obj.insert(key, lua_value_to_json(lua, v)?);
                    }
                    Ok(JsonValue::Object(obj))
                }
            }
            _ => Ok(JsonValue::Null),
        }
    }

    fn json_to_lua_value(lua: &Lua, value: JsonValue) -> mlua::Result<Value> {
        match value {
            JsonValue::Null => Ok(Value::Nil),
            JsonValue::Bool(b) => Ok(Value::Boolean(b)),
            JsonValue::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(Value::Number(i as f64))
                } else if let Some(f) = n.as_f64() {
                    Ok(Value::Number(f))
                } else {
                    Ok(Value::Number(0.0))
                }
            }
            JsonValue::String(s) => Ok(Value::String(lua.create_string(&s)?)),
            JsonValue::Array(arr) => {
                let t = lua.create_table()?;
                for (i, v) in arr.iter().enumerate() {
                    t.set(i + 1, json_to_lua_value(lua, v.clone())?)?;
                }
                Ok(Value::Table(t))
            }
            JsonValue::Object(obj) => {
                let t = lua.create_table()?;
                for (k, v) in obj.iter() {
                    t.set(k.as_str(), json_to_lua_value(lua, v.clone())?)?;
                }
                Ok(Value::Table(t))
            }
        }
    }

    json.set(
        "encode",
        lua.create_function(|lua, value: Value| {
            let json_val = lua_value_to_json(lua, value)?;
            match serde_json::to_string(&json_val) {
                Ok(s) => Ok(s),
                Err(e) => Err(mlua::Error::RuntimeError(e.to_string())),
            }
        })?,
    )?;

    json.set(
        "decode",
        lua.create_function(|lua, json_str: String| {
            match serde_json::from_str::<JsonValue>(&json_str) {
                Ok(value) => json_to_lua_value(lua, value),
                Err(e) => Err(mlua::Error::RuntimeError(e.to_string())),
            }
        })?,
    )?;

    json.set(
        "to_table",
        lua.create_function(|lua, json_str: String| {
            match serde_json::from_str::<JsonValue>(&json_str) {
                Ok(value) => json_to_lua_value(lua, value),
                Err(_) => Ok(Value::Nil),
            }
        })?,
    )?;

    json.set(
        "from_table",
        lua.create_function(|lua, table: Table| {
            let json_val = lua_value_to_json(lua, Value::Table(table))?;
            match serde_json::to_string(&json_val) {
                Ok(s) => Ok(s),
                Err(e) => Err(mlua::Error::RuntimeError(e.to_string())),
            }
        })?,
    )?;

    json.set("null", lua.create_function(|_lua, _: ()| Ok(Value::Nil))?)?;

    json.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("json", json)?;
    Ok(())
}
