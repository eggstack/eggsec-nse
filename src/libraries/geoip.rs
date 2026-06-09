//! NSE geoip library wrapper
//!
//! Provides GeoIP lookups for NSE scripts.
//! Based on Nmap's geoip library.

use mlua::{Lua, Result as LuaResult};

pub fn register_geoip_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let geoip = lua.create_table()?;

    geoip.set(
        "lookup",
        lua.create_function(|lua, _ip: String| {
            let result = lua.create_table()?;
            result.set("status", "not_available")?;
            result.set("error", "GeoIP database not available in NSE context")?;
            Ok(result)
        })?,
    )?;

    geoip.set(
        "lookup_coords",
        lua.create_function(|lua, _ip: String| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            Ok(result)
        })?,
    )?;

    geoip.set(
        "lookup_city",
        lua.create_function(|lua, _ip: String| {
            let result = lua.create_table()?;
            result.set("status", "not_implemented")?;
            Ok(result)
        })?,
    )?;

    geoip.set(
        "lookup_country",
        lua.create_function(|_lua, _ip: String| Ok(String::new()))?,
    )?;

    geoip.set(
        "lookup_asn",
        lua.create_function(|_lua, _ip: String| Ok(String::new()))?,
    )?;

    geoip.set(
        "country_code_by_addr",
        lua.create_function(|_lua, _ip: String| Ok(String::new()))?,
    )?;

    geoip.set(
        "country_name_by_addr",
        lua.create_function(|_lua, _ip: String| Ok(String::new()))?,
    )?;

    geoip.set(
        "country_code_by_name",
        lua.create_function(|_lua, _hostname: String| Ok(String::new()))?,
    )?;

    geoip.set(
        "country_name_by_name",
        lua.create_function(|_lua, _hostname: String| Ok(String::new()))?,
    )?;

    geoip.set(
        "region_by_addr",
        lua.create_function(|_lua, _ip: String| Ok(String::new()))?,
    )?;

    geoip.set(
        "city_by_addr",
        lua.create_function(|_lua, _ip: String| Ok(String::new()))?,
    )?;

    geoip.set(
        "org_by_addr",
        lua.create_function(|_lua, _ip: String| Ok(String::new()))?,
    )?;

    geoip.set(
        "asn_by_addr",
        lua.create_function(|_lua, _ip: String| Ok(String::new()))?,
    )?;

    geoip.set(
        "lat_lon_by_addr",
        lua.create_function(|lua, _ip: String| {
            let result = lua.create_table()?;
            Ok(result)
        })?,
    )?;

    geoip.set(
        "timezone_by_addr",
        lua.create_function(|_lua, _ip: String| Ok(String::new()))?,
    )?;

    geoip.set(
        "info_by_addr",
        lua.create_function(|lua, ip: String| {
            let result = lua.create_table()?;
            result.set("ip", ip)?;
            result.set("status", "not_available")?;
            Ok(result)
        })?,
    )?;

    geoip.set(
        "distance",
        lua.create_function(|_lua, (lat1, lon1, lat2, lon2): (f64, f64, f64, f64)| {
            // Haversine formula for distance
            let r = 6371.0; // Earth's radius in km

            let d_lat = (lat2 - lat1).to_radians();
            let d_lon = (lon2 - lon1).to_radians();

            let a = (d_lat / 2.0).sin().powi(2)
                + lat1.to_radians().cos() * lat2.to_radians().cos() * (d_lon / 2.0).sin().powi(2);
            let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

            let distance = r * c;
            Ok(distance)
        })?,
    )?;

    geoip.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("geoip", geoip)?;
    Ok(())
}
