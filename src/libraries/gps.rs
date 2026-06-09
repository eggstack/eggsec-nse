//! NSE gps library wrapper
//!
//! GPS (Global Positioning System) protocol support.
//! Based on Nmap's gps library.

use mlua::{Lua, Result as LuaResult};

pub fn register_gps_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let gps = lua.create_table()?;

    gps.set(
        "parse_nmea",
        lua.create_function(|lua, nmea: String| {
            let result = lua.create_table()?;

            if !nmea.starts_with('$') {
                result.set("status", "error")?;
                result.set("errmsg", "Invalid NMEA sentence - no $ prefix")?;
                return Ok(result);
            }

            let parts: Vec<&str> = nmea.split(',').collect();
            let sentence_type = parts.first().unwrap_or(&"").to_string();

            result.set("raw", nmea.clone())?;
            result.set("type", sentence_type.clone())?;

            match sentence_type.as_str() {
                "$GPGGA" | "$GNGGA" => {
                    result.set("status", "ok")?;
                    if parts.len() >= 10 {
                        if let Some(lat) = parts.get(1) {
                            result.set("latitude", lat.to_string())?;
                        }
                        if let Some(lat_dir) = parts.get(2) {
                            result.set("latitude_dir", lat_dir.to_string())?;
                        }
                        if let Some(lon) = parts.get(3) {
                            result.set("longitude", lon.to_string())?;
                        }
                        if let Some(lon_dir) = parts.get(4) {
                            result.set("longitude_dir", lon_dir.to_string())?;
                        }
                        if let Some(quality) = parts.get(6) {
                            result.set("quality", quality.to_string())?;
                        }
                        if let Some(satellites) = parts.get(7) {
                            result.set("satellites", satellites.to_string())?;
                        }
                        if let Some(altitude) = parts.get(9) {
                            result.set("altitude", altitude.to_string())?;
                        }
                    }
                    result.set("sentence", "GGA")?;
                }
                "$GPRMC" | "$GNRMC" => {
                    result.set("status", "ok")?;
                    if parts.len() >= 10 {
                        if let Some(status) = parts.get(2) {
                            result.set("valid", *status == "A")?;
                        }
                        if let Some(lat) = parts.get(3) {
                            result.set("latitude", lat.to_string())?;
                        }
                        if let Some(lat_dir) = parts.get(4) {
                            result.set("latitude_dir", lat_dir.to_string())?;
                        }
                        if let Some(lon) = parts.get(5) {
                            result.set("longitude", lon.to_string())?;
                        }
                        if let Some(lon_dir) = parts.get(6) {
                            result.set("longitude_dir", lon_dir.to_string())?;
                        }
                        if let Some(speed) = parts.get(7) {
                            result.set("speed_knots", speed.to_string())?;
                        }
                        if let Some(course) = parts.get(8) {
                            result.set("course", course.to_string())?;
                        }
                    }
                    result.set("sentence", "RMC")?;
                }
                "$GPVTG" | "$GNVTG" => {
                    result.set("status", "ok")?;
                    if parts.len() >= 9 {
                        if let Some(course) = parts.get(1) {
                            result.set("course_true", course.to_string())?;
                        }
                        if let Some(course_mag) = parts.get(3) {
                            result.set("course_magnetic", course_mag.to_string())?;
                        }
                        if let Some(speed_knots) = parts.get(5) {
                            result.set("speed_knots", speed_knots.to_string())?;
                        }
                        if let Some(speed_kph) = parts.get(7) {
                            result.set("speed_kph", speed_kph.to_string())?;
                        }
                    }
                    result.set("sentence", "VTG")?;
                }
                "$GPGSA" | "$GNGSA" => {
                    result.set("status", "ok")?;
                    result.set("sentence", "GSA")?;
                }
                "$GPGSV" | "$GNGSV" => {
                    result.set("status", "ok")?;
                    result.set("sentence", "GSV")?;
                }
                "$GPGLL" | "$GNGLL" => {
                    result.set("status", "ok")?;
                    result.set("sentence", "GLL")?;
                }
                _ => {
                    result.set("status", "ok")?;
                    result.set("valid", true)?;
                }
            }

            Ok(result)
        })?,
    )?;

    gps.set(
        "parse_gga",
        lua.create_function(|lua, nmea: String| {
            let result = lua.create_table()?;
            let parts: Vec<&str> = nmea.split(',').collect();

            if parts.len() < 10 || parts.first().map(|s| *s != "$GPGGA").unwrap_or(true) {
                result.set("status", "error")?;
                return Ok(result);
            }

            result.set("status", "ok")?;
            if let Some(lat) = parts.get(1) {
                result.set("latitude", lat.to_string())?;
            }
            if let Some(lat_dir) = parts.get(2) {
                result.set("latitude_dir", lat_dir.to_string())?;
            }
            if let Some(lon) = parts.get(3) {
                result.set("longitude", lon.to_string())?;
            }
            if let Some(lon_dir) = parts.get(4) {
                result.set("longitude_dir", lon_dir.to_string())?;
            }
            if let Some(quality) = parts.get(6) {
                result.set("quality", quality.to_string())?;
            }
            if let Some(satellites) = parts.get(7) {
                result.set("satellites", satellites.to_string())?;
            }
            if let Some(altitude) = parts.get(9) {
                result.set("altitude", altitude.to_string())?;
            }

            Ok(result)
        })?,
    )?;

    gps.set(
        "parse_rmc",
        lua.create_function(|lua, nmea: String| {
            let result = lua.create_table()?;
            let parts: Vec<&str> = nmea.split(',').collect();

            if parts.len() < 10 || parts.first().map(|s| *s != "$GPRMC").unwrap_or(true) {
                result.set("status", "error")?;
                return Ok(result);
            }

            result.set("status", "ok")?;
            if let Some(status) = parts.get(2) {
                result.set("valid", *status == "A")?;
            }
            if let Some(lat) = parts.get(3) {
                result.set("latitude", lat.to_string())?;
            }
            if let Some(lat_dir) = parts.get(4) {
                result.set("latitude_dir", lat_dir.to_string())?;
            }
            if let Some(lon) = parts.get(5) {
                result.set("longitude", lon.to_string())?;
            }
            if let Some(lon_dir) = parts.get(6) {
                result.set("longitude_dir", lon_dir.to_string())?;
            }
            if let Some(speed) = parts.get(7) {
                result.set("speed_knots", speed.to_string())?;
            }
            if let Some(course) = parts.get(8) {
                result.set("course", course.to_string())?;
            }

            Ok(result)
        })?,
    )?;

    gps.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    gps.set(
        "coordinates_to_dd",
        lua.create_function(
            |lua, (lat, lat_dir, lon, lon_dir): (String, String, String, String)| {
                let result = lua.create_table()?;

                fn nmea_to_dd(coord: &str, dir: &str) -> Option<f64> {
                    if coord.len() < 4 {
                        return None;
                    }
                    let degrees: f64 = coord[..2].parse().ok()?;
                    let minutes: f64 = coord[2..].parse().ok()?;
                    let mut dd = degrees + minutes / 60.0;
                    if dir == "S" || dir == "W" {
                        dd = -dd;
                    }
                    Some(dd)
                }

                if let Some(lat_dd) = nmea_to_dd(&lat, &lat_dir) {
                    result.set("latitude", lat_dd)?;
                }
                if let Some(lon_dd) = nmea_to_dd(&lon, &lon_dir) {
                    result.set("longitude", lon_dd)?;
                }

                Ok(result)
            },
        )?,
    )?;

    globals.set("gps", gps)?;
    Ok(())
}
