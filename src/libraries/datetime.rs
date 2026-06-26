//! NSE datetime library wrapper
//!
//! Date and time utilities for NSE scripts.
//! Based on Nmap's datetime library.

use mlua::{Lua, Result as LuaResult};

pub fn register_datetime_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();

    let datetime = lua.create_table().expect("Failed to create datetime table");

    datetime.set(
        "now",
        lua.create_function(|_lua, _: ()| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            Ok(now)
        })?,
    )?;

    datetime.set(
        "current_time",
        lua.create_function(|_lua, _: ()| {
            let now = chrono::Utc::now();
            Ok(now.format("%Y-%m-%d %H:%M:%S").to_string())
        })?,
    )?;

    datetime.set(
        "timestamp",
        lua.create_function(|_lua, _: ()| {
            let now = chrono::Utc::now().timestamp();
            Ok(now)
        })?,
    )?;

    datetime.set(
        "parse_timespec",
        lua.create_function(|_lua, timespec: String| {
            let timespec = timespec.to_lowercase();

            let seconds: i64 = if timespec.contains('s') {
                timespec.replace("s", "").parse().unwrap_or(0)
            } else if timespec.contains('m') {
                timespec.replace("m", "").parse::<i64>().unwrap_or(0) * 60
            } else if timespec.contains('h') {
                timespec.replace("h", "").parse::<i64>().unwrap_or(0) * 3600
            } else if timespec.contains('d') {
                timespec.replace("d", "").parse::<i64>().unwrap_or(0) * 86400
            } else {
                timespec.parse().unwrap_or(0)
            };

            Ok(seconds)
        })?,
    )?;

    datetime.set(
        "format_time",
        lua.create_function(|_lua, (timestamp, format): (i64, String)| {
            use chrono::{TimeZone, Utc};
            let dt = Utc.timestamp_opt(timestamp, 0).single();
            match dt {
                Some(d) => Ok(d.format(&format).to_string()),
                None => Ok("".to_string()),
            }
        })?,
    )?;

    datetime.set(
        "format_date",
        lua.create_function(|_lua, (timestamp, format): (i64, String)| {
            use chrono::{TimeZone, Utc};
            let dt = Utc.timestamp_opt(timestamp, 0).single();
            match dt {
                Some(d) => Ok(d.format(&format).to_string()),
                None => Ok("".to_string()),
            }
        })?,
    )?;

    datetime.set(
        "isotime",
        lua.create_function(|_lua, timestamp: Option<i64>| {
            let ts = timestamp.unwrap_or_else(|| chrono::Utc::now().timestamp());
            use chrono::{TimeZone, Utc};
            let dt = Utc.timestamp_opt(ts, 0).single();
            match dt {
                Some(d) => Ok(d.to_rfc3339()),
                None => Ok("".to_string()),
            }
        })?,
    )?;

    datetime.set(
        "to_epoch",
        lua.create_function(
            |_lua, (year, month, day, hour, min, sec): (i32, i32, i32, i32, i32, i32)| {
                use chrono::{TimeZone, Utc};
                let dt = Utc
                    .with_ymd_and_hms(
                        year,
                        month as u32,
                        day as u32,
                        hour as u32,
                        min as u32,
                        sec as u32,
                    )
                    .single();
                match dt {
                    Some(d) => Ok(d.timestamp()),
                    None => Ok(0i64),
                }
            },
        )?,
    )?;

    datetime.set(
        "diff",
        lua.create_function(|_lua, (t1, t2): (i64, i64)| Ok(t1 - t2))?,
    )?;

    globals.set("datetime", datetime)?;
    Ok(())
}
