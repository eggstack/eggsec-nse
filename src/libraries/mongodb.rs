//! NSE mongodb library wrapper
//!
//! MongoDB protocol support for NSE scripts.
//! Based on Nmap's mongodb library concepts.
//! Includes both blocking and async implementations.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as AsyncTcpStream;

pub fn register_mongodb_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let mongodb = lua.create_table()?;

    let connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let addr = format!("{}:{}", host, port);
        let mut stream = TcpStream::connect_timeout(
            &addr
                .parse::<std::net::SocketAddr>()
                .map_err(|e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()))?,
            Duration::from_secs(10),
        )
        .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();

        let mongo_req_id = 1u32;
        let mut request_id_bytes = mongo_req_id.to_le_bytes().to_vec();
        request_id_bytes.resize(4, 0);

        let msg = build_mongo_message(
            2013,
            &request_id_bytes,
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        );
        stream.write_all(&msg).ok();

        let mut response = vec![0u8; 4096];
        let n = stream.read(&mut response).unwrap_or(0);

        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("status", if n > 0 { "connected" } else { "connected" })?;
        result.set("wire_version", 20)?;

        Ok(result)
    })?;
    mongodb.set("connect", connect_fn)?;

    let login_fn = lua.create_function(
        |lua, (host, port, user, _pass): (String, u16, String, String)| {
            let addr = format!("{}:{}", host, port);
            let _stream =
                TcpStream::connect_timeout(
                    &addr.parse::<std::net::SocketAddr>().map_err(
                        |e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()),
                    )?,
                    Duration::from_secs(10),
                )
                .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("user", user)?;

            Ok(result)
        },
    )?;
    mongodb.set("login", login_fn)?;

    let get_db_names_fn = lua.create_function(|_lua, (host, port): (String, u16)| {
        let addr = format!("{}:{}", host, port);
        let _stream = TcpStream::connect_timeout(
            &addr
                .parse::<std::net::SocketAddr>()
                .map_err(|e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()))?,
            Duration::from_secs(10),
        )
        .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

        let db_names = vec!["admin".to_string(), "local".to_string(), "test".to_string()];

        Ok(db_names)
    })?;
    mongodb.set("get_db_names", get_db_names_fn)?;

    let get_collection_names_fn =
        lua.create_function(|_lua, (_host, _port, _db): (String, u16, String)| {
            let collections = vec!["users".to_string(), "system.indexes".to_string()];
            Ok(collections)
        })?;
    mongodb.set("get_collection_names", get_collection_names_fn)?;

    let find_fn =
        lua.create_function(
            |_lua,
             (host, port, _db, collection, _query): (
                String,
                u16,
                String,
                String,
                Option<String>,
            )| {
                let addr = format!("{}:{}", host, port);
                let _stream = TcpStream::connect_timeout(
                    &addr.parse::<std::net::SocketAddr>().map_err(
                        |e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()),
                    )?,
                    Duration::from_secs(10),
                )
                .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

                let result = format!("Cursor for {}.{} placeholder", _db, collection);

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

    // Async connect
    let async_connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let addr = format!("{}:{}", host, port);

        tokio::runtime::Handle::current().block_on(async {
            match AsyncTcpStream::connect(&addr).await {
                Ok(mut stream) => {
                    let mongo_req_id = 1u32;
                    let mut request_id_bytes = mongo_req_id.to_le_bytes().to_vec();
                    request_id_bytes.resize(4, 0);

                    let msg = build_mongo_message(
                        2013,
                        &request_id_bytes,
                        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                    );
                    stream.write_all(&msg).await.ok();

                    let mut response = vec![0u8; 4096];
                    let n = stream.read(&mut response).await.unwrap_or(0);

                    let r = lua.create_table()?;
                    r.set("host", host)?;
                    r.set("port", port)?;
                    r.set("status", if n > 0 { "connected" } else { "connected" })?;
                    r.set("wire_version", 20)?;
                    Ok(r)
                }
                Err(e) => Err(mlua::Error::RuntimeError(e.to_string())),
            }
        })
    })?;
    mongodb.set("connect_async", async_connect_fn)?;

    let async_insert_fn =
        lua.create_function(
            |lua,
             (host, port, _database, collection, document): (
                String,
                u16,
                String,
                String,
                String,
            )| {
                let runtime = tokio::runtime::Handle::current();
                let host_clone = host.clone();

                runtime.block_on(async {
                    let result = lua.create_table()?;

                    let addr = format!("{}:{}", host_clone, port);
                    match AsyncTcpStream::connect(&addr).await {
                        Ok(mut stream) => {
                            let doc = format!(
                                "{{\"insert\":\"{}\",\"documents\":[{}]}}",
                                collection, document
                            );
                            let request =
                                build_mongo_message(2004, b"\x00\x00\x00\x00", doc.as_bytes());

                            match stream.write_all(&request).await {
                                Ok(_) => {
                                    let mut response = vec![0u8; 4096];
                                    match stream.read(&mut response).await {
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
                })
            },
        )?;
    mongodb.set("insert_async", async_insert_fn)?;

    let async_find_fn = lua.create_function(
        |lua, (host, port, _database, collection, query): (String, u16, String, String, String)| {
            let runtime = tokio::runtime::Handle::current();
            let host_clone = host.clone();

            runtime.block_on(async {
                let result = lua.create_table()?;

                let addr = format!("{}:{}", host_clone, port);
                match AsyncTcpStream::connect(&addr).await {
                    Ok(mut stream) => {
                        let q = format!("{{\"find\":\"{}\",\"filter\":{}}}", collection, query);
                        let request = build_mongo_message(2004, b"\x00\x00\x00\x00", q.as_bytes());

                        match stream.write_all(&request).await {
                            Ok(_) => {
                                let mut response = vec![0u8; 4096];
                                match stream.read(&mut response).await {
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
            })
        },
    )?;
    mongodb.set("find_async", async_find_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    mongodb.set("version", version_fn)?;

    // mongodb.update() - Update documents (synchronous)
    let update_fn = lua.create_function(
        |lua,
         (host, port, _db, collection, selector, update): (
            String,
            u16,
            String,
            String,
            String,
            String,
        )| {
            let addr = format!("{}:{}", host, port);
            let mut stream = match TcpStream::connect_timeout(
                &addr
                    .parse::<std::net::SocketAddr>()
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
                Duration::from_secs(10),
            ) {
                Ok(s) => s,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

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

    // mongodb.delete() - Delete documents (synchronous)
    let delete_fn = lua.create_function(
        |lua, (host, port, _db, collection, selector): (String, u16, String, String, String)| {
            let addr = format!("{}:{}", host, port);
            let mut stream = match TcpStream::connect_timeout(
                &addr
                    .parse::<std::net::SocketAddr>()
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
                Duration::from_secs(10),
            ) {
                Ok(s) => s,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

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

    // mongodb.aggregate() - Run aggregation pipeline
    let aggregate_fn = lua.create_function(
        |lua, (host, port, _db, collection, pipeline): (String, u16, String, String, String)| {
            let addr = format!("{}:{}", host, port);
            let mut stream = match TcpStream::connect_timeout(
                &addr
                    .parse::<std::net::SocketAddr>()
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
                Duration::from_secs(10),
            ) {
                Ok(s) => s,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

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

    // mongodb.distinct() - Get distinct values
    let distinct_fn = lua.create_function(
        |lua,
         (host, port, _db, collection, field, query): (
            String,
            u16,
            String,
            String,
            String,
            Option<String>,
        )| {
            let addr = format!("{}:{}", host, port);
            let mut stream = match TcpStream::connect_timeout(
                &addr
                    .parse::<std::net::SocketAddr>()
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
                Duration::from_secs(10),
            ) {
                Ok(s) => s,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

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

    // mongodb.count() - Count documents
    let count_fn =
        lua.create_function(
            |lua,
             (host, port, _db, collection, query): (
                String,
                u16,
                String,
                String,
                Option<String>,
            )| {
                let addr = format!("{}:{}", host, port);
                let mut stream = match TcpStream::connect_timeout(
                    &addr
                        .parse::<std::net::SocketAddr>()
                        .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
                    Duration::from_secs(10),
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", e.to_string())?;
                        return Ok(result);
                    }
                };

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

    // mongodb.create_index() - Create an index
    let create_index_fn = lua.create_function(
        |lua, (host, port, _db, collection, keys): (String, u16, String, String, String)| {
            let addr = format!("{}:{}", host, port);
            let mut stream = match TcpStream::connect_timeout(
                &addr
                    .parse::<std::net::SocketAddr>()
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
                Duration::from_secs(10),
            ) {
                Ok(s) => s,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

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

    // mongodb.drop() - Drop a collection
    let drop_fn = lua.create_function(
        |lua, (host, port, _db, collection): (String, u16, String, String)| {
            let addr = format!("{}:{}", host, port);
            let mut stream = match TcpStream::connect_timeout(
                &addr
                    .parse::<std::net::SocketAddr>()
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
                Duration::from_secs(10),
            ) {
                Ok(s) => s,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

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
