//! NSE formulas library wrapper
//!
//! Formula functions for various calculations.
//! Based on Nmap's formulas library.

use mlua::{Lua, Result as LuaResult, Table};

pub fn register_formulas_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let formulas = lua.create_table()?;

    let entropy_fn = lua.create_function(|_lua, s: String| {
        let mut freq = [0u32; 256];
        for byte in s.bytes() {
            freq[byte as usize] += 1;
        }
        let len = s.len() as f64;
        let mut entropy = 0.0;
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        Ok(entropy)
    })?;
    formulas.set("entropy", entropy_fn)?;

    let avg_fn = lua.create_function(|_lua, values: Table| {
        let len = values.len().unwrap_or(0) as f64;
        if len == 0.0 {
            return Ok(0.0);
        }
        let mut sum = 0.0;
        for i in 1..=values.len().unwrap_or(0) {
            if let Ok(v) = values.get::<f64>(i) {
                sum += v;
            }
        }
        Ok(sum / len)
    })?;
    formulas.set("avg", avg_fn)?;

    let stddev_fn = lua.create_function(|_lua, values: Table| {
        let len = values.len().unwrap_or(0) as f64;
        if len == 0.0 {
            return Ok(0.0);
        }
        let mut sum = 0.0;
        for i in 1..=values.len().unwrap_or(0) {
            if let Ok(v) = values.get::<f64>(i) {
                sum += v;
            }
        }
        let mean = sum / len;
        let mut variance = 0.0;
        for i in 1..=values.len().unwrap_or(0) {
            if let Ok(v) = values.get::<f64>(i) {
                let diff = v - mean;
                variance += diff * diff;
            }
        }
        Ok((variance / len).sqrt())
    })?;
    formulas.set("stddev", stddev_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0"))?;
    formulas.set("version", version_fn)?;

    globals.set("formulas", formulas)?;
    Ok(())
}
