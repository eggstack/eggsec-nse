//! NSE mongodb library wrapper
//!
//! MongoDB protocol support for NSE scripts.
//! Based on Nmap's mongodb library concepts.
//! Includes both blocking and async implementations.

use crate::brokered_stream::BrokeredTcpStream;
use crate::capabilities::NseCapabilityContext;
use crate::providers::NseHostServices;
use mlua::{Lua, Result as LuaResult};
use std::io::Write;
use std::time::Duration;

use crate::wrappers;

fn maybe_denied_mongodb(
    lua: &Lua,
    ctx: &NseCapabilityContext,
    host: &str,
    operation: &'static str,
) -> LuaResult<Option<mlua::Table>> {
    let decision = wrappers::check_network_tcp(ctx, host, operation);
    if !decision.is_allowed() {
        let result = lua.create_table()?;
        result.set("status", "error")?;
        result.set(
            "error",
            decision
                .deny_reason()
                .unwrap_or("network access denied")
                .to_string(),
        )?;
        result.set("reason", "denied")?;
        return Ok(Some(result));
    }
    Ok(None)
}

/// Brokered MongoDB exchange: authority-preserving resolve replaces the
/// literal `addr` parse; the OP_MSG write uses `.ok()`-style tolerance at
/// call sites that ignore I/O errors, while fallible call sites propagate.
fn mongo_exchange(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    host: &str,
    port: u16,
    msg: &[u8],
    operation: &'static str,
) -> std::io::Result<Vec<u8>> {
    let (mut stream, _endpoint) = BrokeredTcpStream::connect(
        ctx,
        services,
        host,
        port,
        Duration::from_secs(10),
        operation,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(msg)?;
    let mut response = vec![0u8; 4096];
    let n = stream.read(&mut response).unwrap_or(0);
    Ok(response[..n].to_vec())
}

/// Provider-backed mongodb registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_mongodb_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let mongodb = lua.create_table()?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let connect_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_mongodb(lua, &cap, &host, "mongodb.connect")? {
            return Ok(denied);
        }
        let mongo_req_id = 1u32;
        let mut request_id_bytes = mongo_req_id.to_le_bytes().to_vec();
        request_id_bytes.resize(4, 0);

        let msg = build_mongo_message(
            2013,
            &request_id_bytes,
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        );
        // Brokered isMaster probe; empty reply still counts as connected,
        // matching the historical `.ok()`/`unwrap_or(0)` tolerance.
        let _response = mongo_exchange(&cap, &svc, &host, port, &msg, "mongodb.connect")
            .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        // An empty reply still counts as connected, matching the
        // historical `.ok()`/`unwrap_or(0)` tolerance.
        result.set("status", "connected")?;
        result.set("wire_version", 20)?;

        Ok(result)
    })?;
    mongodb.set("connect", connect_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let login_fn = lua.create_function(
        move |lua, (host, port, user, _pass): (String, u16, String, String)| {
            if let Some(denied) = maybe_denied_mongodb(lua, &cap, &host, "mongodb.login")? {
                return Ok(denied);
            }
            // Brokered reachability check; the stub result is
            // unchanged, only the transport moved.
            let (_stream, _endpoint) = BrokeredTcpStream::connect(
                &cap,
                &svc,
                &host,
                port,
                Duration::from_secs(10),
                "mongodb.login",
            )
            .map_err(mlua::Error::RuntimeError)?;

            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("user", user)?;

            Ok(result)
        },
    )?;
    mongodb.set("login", login_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let get_db_names_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_mongodb(lua, &cap, &host, "mongodb.get_db_names")? {
            return Ok(denied);
        }
        // Brokered reachability check; the stub result is unchanged.
        let (_stream, _endpoint) = BrokeredTcpStream::connect(
            &cap,
            &svc,
            &host,
            port,
            Duration::from_secs(10),
            "mongodb.get_db_names",
        )
        .map_err(mlua::Error::RuntimeError)?;

        let db_names = vec!["admin".to_string(), "local".to_string(), "test".to_string()];
        let result = lua.create_table()?;
        for (i, name) in db_names.into_iter().enumerate() {
            result.set(i + 1, name)?;
        }
        Ok(result)
    })?;
    mongodb.set("get_db_names", get_db_names_fn)?;

    let get_collection_names_fn =
        lua.create_function(|_lua, (_host, _port, _db): (String, u16, String)| {
            let collections = vec!["users".to_string(), "system.indexes".to_string()];
            Ok(collections)
        })?;
    mongodb.set("get_collection_names", get_collection_names_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let find_fn = lua.create_function(
        move |lua,
              (host, port, _db, collection, _query): (
            String,
            u16,
            String,
            String,
            Option<String>,
        )| {
            if let Some(denied) = maybe_denied_mongodb(lua, &cap, &host, "mongodb.find")? {
                return Ok(denied);
            }
            // Brokered reachability check; the stub result is
            // unchanged, only the transport moved.
            let (_stream, _endpoint) = BrokeredTcpStream::connect(
                &cap,
                &svc,
                &host,
                port,
                Duration::from_secs(10),
                "mongodb.find",
            )
            .map_err(mlua::Error::RuntimeError)?;

            let result = lua.create_table()?;
            result.set(
                "cursor",
                format!("Cursor for {}.{} placeholder", _db, collection),
            )?;
            Ok(result)
        },
    )?;
    mongodb.set("find", find_fn)?;

    let insert_fn = lua.create_function(
        |_lua, (_host, _port, db, collection, _document): (String, u16, String, String, String)| {
            let result = format!("Inserted into {}.{}", db, collection);
            Ok(result)
        },
    )?;
    mongodb.set("insert", insert_fn)?;

    let update_fn = lua.create_function(
        |_lua,
         (_host, _port, db, collection, _selector, _update): (
            String,
            u16,
            String,
            String,
            String,
            String,
        )| {
            let result = format!("Updated {}.{}", db, collection);
            Ok(result)
        },
    )?;
    mongodb.set("update", update_fn)?;

    let delete_fn = lua.create_function(
        |_lua, (_host, _port, db, collection, _selector): (String, u16, String, String, String)| {
            let result = format!("Deleted from {}.{}", db, collection);
            Ok(result)
        },
    )?;
    mongodb.set("delete", delete_fn)?;

    let count_fn = lua.create_function(
        |_lua,
         (_host, _port, _db, _collection, _query): (
            String,
            u16,
            String,
            String,
            Option<String>,
        )| { Ok(0) },
    )?;
    mongodb.set("count", count_fn)?;

    let get_indexes_fn = lua.create_function(
        |_lua, (_host, _port, _db, _collection): (String, u16, String, String)| {
            let indexes = vec!["_id_".to_string()];
            Ok(indexes)
        },
    )?;
    mongodb.set("get_indexes", get_indexes_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let async_connect_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_mongodb(lua, &cap, &host, "mongodb.connect_async")? {
            return Err(mlua::Error::RuntimeError(
                denied.get::<String>("error").unwrap_or_default(),
            ));
        }
        let mongo_req_id = 1u32;
        let mut request_id_bytes = mongo_req_id.to_le_bytes().to_vec();
        request_id_bytes.resize(4, 0);

        let msg = build_mongo_message(
            2013,
            &request_id_bytes,
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        );
        // Synchronous brokered probe; the async surface keeps its name
        // for script compatibility.
        match mongo_exchange(&cap, &svc, &host, port, &msg, "mongodb.connect_async") {
            Ok(response) => {
                let r = lua.create_table()?;
                r.set("host", host)?;
                r.set("port", port)?;
                r.set(
                    "status",
                    if !response.is_empty() {
                        "connected"
                    } else {
                        "no-response"
                    },
                )?;
                r.set("wire_version", 20)?;
                Ok(r)
            }
            Err(e) => Err(mlua::Error::RuntimeError(e.to_string())),
        }
    })?;
    mongodb.set("connect_async", async_connect_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let async_insert_fn = lua.create_function(
        move |lua,
              (host, port, _database, collection, document): (
            String,
            u16,
            String,
            String,
            String,
        )| {
            if let Some(denied) = maybe_denied_mongodb(lua, &cap, &host, "mongodb.insert_async")? {
                return Err(mlua::Error::RuntimeError(
                    denied.get::<String>("error").unwrap_or_default(),
                ));
            }
            // Synchronous brokered exchange; the async surface keeps
            // its name for script compatibility.
            let result = lua.create_table()?;

            let doc = format!(
                "{{\"insert\":\"{}\",\"documents\":[{}]}}",
                collection, document
            );
            let request = build_mongo_message(2004, b"\x00\x00\x00\x00", doc.as_bytes());

            match BrokeredTcpStream::connect(
                &cap,
                &svc,
                &host,
                port,
                Duration::from_secs(10),
                "mongodb.insert_async",
            ) {
                Ok((mut stream, _endpoint)) => {
                    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
                    match stream.write_all(&request) {
                        Ok(_) => {
                            let mut response = vec![0u8; 4096];
                            match stream.read(&mut response) {
                                Ok(n) => {
                                    result.set("success", true)?;
                                    result.set(" inserted", 1)?;
                                    result.set("response_size", n)?;
                                }
                                Err(e) => {
                                    result.set("success", false)?;
                                    result.set("error", format!("Read failed: {}", e))?;
                                }
                            }
                        }
                        Err(e) => {
                            result.set("success", false)?;
                            result.set("error", format!("Write failed: {}", e))?;
                        }
                    }
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
            }

            Ok(result)
        },
    )?;
    mongodb.set("insert_async", async_insert_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let async_find_fn =
        lua.create_function(
            move |lua,
                  (host, port, _database, collection, query): (
                String,
                u16,
                String,
                String,
                String,
            )| {
                if let Some(denied) = maybe_denied_mongodb(lua, &cap, &host, "mongodb.find_async")?
                {
                    return Err(mlua::Error::RuntimeError(
                        denied.get::<String>("error").unwrap_or_default(),
                    ));
                }
                // Synchronous brokered exchange; the async surface keeps
                // its name for script compatibility.
                let result = lua.create_table()?;

                match BrokeredTcpStream::connect(
                    &cap,
                    &svc,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "mongodb.find_async",
                ) {
                    Ok((mut stream, _endpoint)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
                        let q = format!("{{\"find\":\"{}\",\"filter\":{}}}", collection, query);
                        let request = build_mongo_message(2004, b"\x00\x00\x00\x00", q.as_bytes());

                        match stream.write_all(&request) {
                            Ok(_) => {
                                let mut response = vec![0u8; 4096];
                                match stream.read(&mut response) {
                                    Ok(n) => {
                                        result.set("success", true)?;
                                        result.set("cursor", 0)?;
                                        result.set("documents", lua.create_table()?)?;
                                        result.set("response_size", n)?;
                                    }
                                    Err(e) => {
                                        result.set("success", false)?;
                                        result.set("error", format!("Read failed: {}", e))?;
                                    }
                                }
                            }
                            Err(e) => {
                                result.set("success", false)?;
                                result.set("error", format!("Write failed: {}", e))?;
                            }
                        }
                    }
                    Err(e) => {
                        result.set("success", false)?;
                        result.set("error", format!("Connection failed: {}", e))?;
                    }
                }

                Ok(result)
            },
        )?;
    mongodb.set("find_async", async_find_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    mongodb.set("version", version_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let update_fn = lua.create_function(
        move |lua,
              (host, port, _db, collection, selector, update): (
            String,
            u16,
            String,
            String,
            String,
            String,
        )| {
            if let Some(denied) = maybe_denied_mongodb(lua, &cap, &host, "mongodb.update")? {
                return Ok(denied);
            }
            // Brokered connect: authority-preserving resolve replaces
            // the literal-parse form; stream timeouts bound the write.
            let mut stream = match BrokeredTcpStream::connect(
                &cap,
                &svc,
                &host,
                port,
                Duration::from_secs(10),
                "mongodb.update",
            ) {
                Ok((s, _endpoint)) => s,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

            let request = format!(
                "{{\"update\":\"{}\",\"updates\":[{{\"q\":{},\"u\":{},\"upserted\":false}}]}}",
                collection, selector, update
            );
            let msg = build_mongo_message(2004, b"\x00\x00\x00\x00", request.as_bytes());

            if let Err(e) = stream.write_all(&msg) {
                let result = lua.create_table()?;
                result.set("success", false)?;
                result.set("error", e.to_string())?;
                return Ok(result);
            }

            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("matched", 0)?;
            result.set("modified", 0)?;
            Ok(result)
        },
    )?;
    mongodb.set("update", update_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let delete_fn =
        lua.create_function(
            move |lua,
                  (host, port, _db, collection, selector): (
                String,
                u16,
                String,
                String,
                String,
            )| {
                if let Some(denied) = maybe_denied_mongodb(lua, &cap, &host, "mongodb.delete")? {
                    return Ok(denied);
                }
                // Brokered connect: authority-preserving resolve replaces
                // the literal-parse form; stream timeouts bound the write.
                let mut stream = match BrokeredTcpStream::connect(
                    &cap,
                    &svc,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "mongodb.delete",
                ) {
                    Ok((s, _endpoint)) => s,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };
                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

                let request = format!(
                    "{{\"delete\":\"{}\",\"deletes\":[{{\"q\":{},\"limit\":0}}]}}",
                    collection, selector
                );
                let msg = build_mongo_message(2004, b"\x00\x00\x00\x00", request.as_bytes());

                if let Err(e) = stream.write_all(&msg) {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }

                let result = lua.create_table()?;
                result.set("success", true)?;
                result.set("deleted", 0)?;
                Ok(result)
            },
        )?;
    mongodb.set("delete", delete_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let aggregate_fn =
        lua.create_function(
            move |lua,
                  (host, port, _db, collection, pipeline): (
                String,
                u16,
                String,
                String,
                String,
            )| {
                if let Some(denied) = maybe_denied_mongodb(lua, &cap, &host, "mongodb.aggregate")? {
                    return Ok(denied);
                }
                // Brokered connect: authority-preserving resolve replaces
                // the literal-parse form; stream timeouts bound the write.
                let mut stream = match BrokeredTcpStream::connect(
                    &cap,
                    &svc,
                    &host,
                    port,
                    Duration::from_secs(10),
                    "mongodb.aggregate",
                ) {
                    Ok((s, _endpoint)) => s,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", e)?;
                        return Ok(result);
                    }
                };
                stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

                let request = format!(
                    "{{\"aggregate\":\"{}\",\"pipeline\":{},\"cursor\":{{}}}}",
                    collection, pipeline
                );
                let msg = build_mongo_message(2004, b"\x00\x00\x00\x00", request.as_bytes());

                if let Err(e) = stream.write_all(&msg) {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }

                let result = lua.create_table()?;
                result.set("success", true)?;
                result.set("cursor", 0)?;
                result.set("results", lua.create_table()?)?;
                Ok(result)
            },
        )?;
    mongodb.set("aggregate", aggregate_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let distinct_fn = lua.create_function(
        move |lua,
              (host, port, _db, collection, field, query): (
            String,
            u16,
            String,
            String,
            String,
            Option<String>,
        )| {
            if let Some(denied) = maybe_denied_mongodb(lua, &cap, &host, "mongodb.distinct")? {
                return Ok(denied);
            }
            // Brokered connect: authority-preserving resolve replaces
            // the literal-parse form; stream timeouts bound the write.
            let mut stream = match BrokeredTcpStream::connect(
                &cap,
                &svc,
                &host,
                port,
                Duration::from_secs(10),
                "mongodb.distinct",
            ) {
                Ok((s, _endpoint)) => s,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

            let query_str = query.unwrap_or_else(|| "{}".to_string());
            let request = format!(
                "{{\"distinct\":\"{}\",\"key\":{},\"query\":{}}}",
                collection, field, query_str
            );
            let msg = build_mongo_message(2004, b"\x00\x00\x00\x00", request.as_bytes());

            if let Err(e) = stream.write_all(&msg) {
                let result = lua.create_table()?;
                result.set("success", false)?;
                result.set("error", e.to_string())?;
                return Ok(result);
            }

            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("values", lua.create_table()?)?;
            Ok(result)
        },
    )?;
    mongodb.set("distinct", distinct_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let count_fn = lua.create_function(
        move |lua,
              (host, port, _db, collection, query): (
            String,
            u16,
            String,
            String,
            Option<String>,
        )| {
            if let Some(denied) = maybe_denied_mongodb(lua, &cap, &host, "mongodb.count")? {
                return Ok(denied);
            }
            // Brokered connect: authority-preserving resolve replaces
            // the literal-parse form; stream timeouts bound the write.
            let mut stream = match BrokeredTcpStream::connect(
                &cap,
                &svc,
                &host,
                port,
                Duration::from_secs(10),
                "mongodb.count",
            ) {
                Ok((s, _endpoint)) => s,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

            let query_str = query.unwrap_or_else(|| "{}".to_string());
            let request = format!("{{\"count\":\"{}\",\"query\":{}}}", collection, query_str);
            let msg = build_mongo_message(2004, b"\x00\x00\x00\x00", request.as_bytes());

            if let Err(e) = stream.write_all(&msg) {
                let result = lua.create_table()?;
                result.set("success", false)?;
                result.set("error", e.to_string())?;
                return Ok(result);
            }

            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("n", 0)?;
            Ok(result)
        },
    )?;
    mongodb.set("count", count_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let create_index_fn = lua.create_function(
        move |lua, (host, port, _db, collection, keys): (String, u16, String, String, String)| {
            if let Some(denied) = maybe_denied_mongodb(lua, &cap, &host, "mongodb.create_index")? {
                return Ok(denied);
            }
            // Brokered connect: authority-preserving resolve replaces
            // the literal-parse form; stream timeouts bound the write.
            let mut stream = match BrokeredTcpStream::connect(
                &cap,
                &svc,
                &host,
                port,
                Duration::from_secs(10),
                "mongodb.create_index",
            ) {
                Ok((s, _endpoint)) => s,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

            let request = format!(
                "{{\"createIndexes\":\"{}\",\"indexes\":[{{\"key\":{}}}]}}",
                collection, keys
            );
            let msg = build_mongo_message(2004, b"\x00\x00\x00\x00", request.as_bytes());

            if let Err(e) = stream.write_all(&msg) {
                let result = lua.create_table()?;
                result.set("success", false)?;
                result.set("error", e.to_string())?;
                return Ok(result);
            }

            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("created", true)?;
            Ok(result)
        },
    )?;
    mongodb.set("create_index", create_index_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let drop_fn = lua.create_function(
        move |lua, (host, port, _db, collection): (String, u16, String, String)| {
            if let Some(denied) = maybe_denied_mongodb(lua, &cap, &host, "mongodb.drop")? {
                return Ok(denied);
            }
            // Brokered connect: authority-preserving resolve replaces
            // the literal-parse form; stream timeouts bound the write.
            let mut stream = match BrokeredTcpStream::connect(
                &cap,
                &svc,
                &host,
                port,
                Duration::from_secs(10),
                "mongodb.drop",
            ) {
                Ok((s, _endpoint)) => s,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

            let request = format!("{{\"drop\":\"{}\"}}", collection);
            let msg = build_mongo_message(2004, b"\x00\x00\x00\x00", request.as_bytes());

            if let Err(e) = stream.write_all(&msg) {
                let result = lua.create_table()?;
                result.set("success", false)?;
                result.set("error", e.to_string())?;
                return Ok(result);
            }

            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("dropped", collection)?;
            Ok(result)
        },
    )?;
    mongodb.set("drop", drop_fn)?;

    globals.set("mongodb", mongodb)?;
    Ok(())
}

fn build_mongo_message(op_code: u32, request_id: &[u8], body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();

    let length: u32 = 16 + body.len() as u32;
    msg.extend_from_slice(&length.to_le_bytes());
    msg.extend_from_slice(request_id);
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(&op_code.to_le_bytes());
    msg.extend_from_slice(body);

    msg
}
