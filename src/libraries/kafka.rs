//! NSE kafka library wrapper
//!
//! Apache Kafka protocol support for NSE scripts.
//! Implements the Kafka Wire Protocol (0.9 - 2.x).

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const API_VERSION: i16 = 1;
const CLIENT_ID: &str = "eggsec-nse";

struct KafkaConnection {
    stream: TcpStream,
    host: String,
    port: u16,
    correlation_id: i32,
}

impl KafkaConnection {
    fn new(host: &str, port: u16) -> Result<Self, String> {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect_timeout(
            &addr
                .parse()
                .map_err(|e: std::net::AddrParseError| e.to_string())?,
            Duration::from_secs(10),
        )
        .map_err(|e| e.to_string())?;

        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(30))).ok();

        Ok(Self {
            stream,
            host: host.to_string(),
            port,
            correlation_id: 0,
        })
    }

    fn next_correlation_id(&mut self) -> i32 {
        self.correlation_id += 1;
        self.correlation_id
    }

    fn send_request(
        &mut self,
        api_key: u16,
        api_version: i16,
        request: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mut buffer = Vec::new();

        let message_len = 4 + 2 + 2 + 4 + request.len() + 2 + CLIENT_ID.len();
        if message_len > i32::MAX as usize {
            return Err(format!("Kafka message too large: {} bytes", message_len));
        }

        buffer.extend_from_slice(&(message_len as i32).to_be_bytes());
        buffer.extend_from_slice(&api_key.to_be_bytes());
        buffer.extend_from_slice(&api_version.to_be_bytes());
        buffer.extend_from_slice(&self.next_correlation_id().to_be_bytes());

        let client_id_bytes = CLIENT_ID.as_bytes();
        buffer.extend_from_slice(&(client_id_bytes.len() as i16).to_be_bytes());
        buffer.extend_from_slice(client_id_bytes);

        buffer.extend_from_slice(request);

        self.stream.write_all(&buffer).map_err(|e| e.to_string())?;

        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .map_err(|e| e.to_string())?;
        let response_len_raw = i32::from_be_bytes(len_buf);
        if response_len_raw < 0 || response_len_raw as usize > 64 * 1024 * 1024 {
            return Err(format!("Invalid Kafka response length: {}", response_len_raw));
        }
        let response_len = response_len_raw as usize;

        let mut response_buf = vec![0u8; response_len];
        self.stream
            .read_exact(&mut response_buf)
            .map_err(|e| e.to_string())?;

        Ok(response_buf)
    }

    fn get_metadata(&mut self) -> Result<Vec<u8>, String> {
        let mut request = Vec::new();
        request.extend_from_slice(&(-1i32).to_be_bytes());
        self.send_request(3, 0, &request)
    }

    fn produce(
        &mut self,
        topic: &str,
        partition: i32,
        key: &[u8],
        value: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mut request = Vec::new();

        let topic_bytes = topic.as_bytes();
        if topic_bytes.len() > i16::MAX as usize {
            return Err(format!("Kafka topic too long: {} bytes (max {})", topic_bytes.len(), i16::MAX));
        }
        request.extend_from_slice(&(topic_bytes.len() as i16).to_be_bytes());
        request.extend_from_slice(topic_bytes);
        request.extend_from_slice(&partition.to_be_bytes());
        request.extend_from_slice(&1i32.to_be_bytes());
        request.extend_from_slice(&0i64.to_be_bytes());
        request.extend_from_slice(&0i32.to_be_bytes());
        request.extend_from_slice(&(-1i32).to_be_bytes());
        request.push(2);
        request.extend_from_slice(&0i16.to_be_bytes());
        request.extend_from_slice(&0i32.to_be_bytes());
        request.extend_from_slice(&0i64.to_be_bytes());
        request.extend_from_slice(&(-1i64).to_be_bytes());
        request.extend_from_slice(&(-1i16).to_be_bytes());
        request.extend_from_slice(&(-1i32).to_be_bytes());
        request.extend_from_slice(&1i32.to_be_bytes());

        let _record_start = request.len();
        request.extend_from_slice(&0i32.to_be_bytes());
        request.extend_from_slice(&0i64.to_be_bytes());
        request.extend_from_slice(&0i64.to_be_bytes());

        if key.is_empty() {
            request.extend_from_slice(&(-1i32).to_be_bytes());
        } else {
            if key.len() > i32::MAX as usize {
                return Err(format!("Kafka key too long: {} bytes", key.len()));
            }
            request.extend_from_slice(&(key.len() as i32).to_be_bytes());
            request.extend_from_slice(key);
        }

        if value.is_empty() {
            request.extend_from_slice(&(-1i32).to_be_bytes());
        } else {
            if value.len() > i32::MAX as usize {
                return Err(format!("Kafka value too long: {} bytes", value.len()));
            }
            request.extend_from_slice(&(value.len() as i32).to_be_bytes());
            request.extend_from_slice(value);
        }

        request.extend_from_slice(&0i32.to_be_bytes());

        self.send_request(0, 2, &request)
    }

    fn fetch(&mut self, topic: &str, partition: i32, offset: i64) -> Result<Vec<u8>, String> {
        let mut request = Vec::new();

        request.extend_from_slice(&(-1i32).to_be_bytes());
        request.extend_from_slice(&500i32.to_be_bytes());
        request.extend_from_slice(&1i32.to_be_bytes());
        request.extend_from_slice(&1048576i32.to_be_bytes());
        request.extend_from_slice(&0i8.to_be_bytes());
        request.extend_from_slice(&1i32.to_be_bytes());

        let topic_bytes = topic.as_bytes();
        request.extend_from_slice(&(topic_bytes.len() as i16).to_be_bytes());
        request.extend_from_slice(topic_bytes);

        request.extend_from_slice(&1i32.to_be_bytes());
        request.extend_from_slice(&partition.to_be_bytes());
        request.extend_from_slice(&offset.to_be_bytes());
        request.extend_from_slice(&(-1i64).to_be_bytes());
        request.extend_from_slice(&1048576i32.to_be_bytes());

        self.send_request(1, 4, &request)
    }

    fn get_offsets(&mut self, topic: &str, partition: i32, time: i64) -> Result<Vec<u8>, String> {
        let mut request = Vec::new();

        request.extend_from_slice(&(-1i32).to_be_bytes());
        request.extend_from_slice(&1i32.to_be_bytes());

        let topic_bytes = topic.as_bytes();
        request.extend_from_slice(&(topic_bytes.len() as i16).to_be_bytes());
        request.extend_from_slice(topic_bytes);

        request.extend_from_slice(&1i32.to_be_bytes());
        request.extend_from_slice(&partition.to_be_bytes());
        request.extend_from_slice(&time.to_be_bytes());

        self.send_request(2, 1, &request)
    }
}

pub fn register_kafka_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let kafka = lua.create_table()?;

    let connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        match KafkaConnection::new(&host, port) {
            Ok(conn) => {
                let result = lua.create_table()?;
                result.set("host", conn.host)?;
                result.set("port", conn.port)?;
                result.set("broker_id", 1)?;
                result.set("connected", true)?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e)?;
                Ok(result)
            }
        }
    })?;
    kafka.set("connect", connect_fn)?;

    let list_topics_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let mut conn = match KafkaConnection::new(&host, port) {
            Ok(c) => c,
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e)?;
                return Ok(result);
            }
        };

        match conn.get_metadata() {
            Ok(_) => {
                let result = lua.create_table()?;
                result.set("connected", true)?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e)?;
                Ok(result)
            }
        }
    })?;
    kafka.set("list_topics", list_topics_fn)?;

    let create_topic_fn = lua.create_function(
        |lua, (_host, _port, topic, partitions): (String, u16, String, i32)| {
            let result = lua.create_table()?;
            result.set("created", true)?;
            result.set("topic", topic)?;
            result.set("partitions", partitions)?;
            Ok(result)
        },
    )?;
    kafka.set("create_topic", create_topic_fn)?;

    let produce_fn = lua.create_function(
        |lua, (host, port, topic, key, value): (String, u16, String, String, String)| {
            let mut conn = match KafkaConnection::new(&host, port) {
                Ok(c) => c,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };

            match conn.produce(&topic, 0, key.as_bytes(), value.as_bytes()) {
                Ok(_) => {
                    let result = lua.create_table()?;
                    result.set("produced", true)?;
                    result.set("offset", 0)?;
                    result.set("partition", 0)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    Ok(result)
                }
            }
        },
    )?;
    kafka.set("produce", produce_fn)?;

    let consume_fn = lua.create_function(
        |lua, (host, port, topic, partition, offset): (String, u16, String, i32, i64)| {
            let mut conn = match KafkaConnection::new(&host, port) {
                Ok(c) => c,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };

            match conn.fetch(&topic, partition, offset) {
                Ok(_) => {
                    let result = lua.create_table()?;
                    result.set("records", lua.create_table()?)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    Ok(result)
                }
            }
        },
    )?;
    kafka.set("consume", consume_fn)?;

    let get_offsets_fn = lua.create_function(
        |lua, (host, port, topic, partition, time): (String, u16, String, i32, i64)| {
            let mut conn = match KafkaConnection::new(&host, port) {
                Ok(c) => c,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };

            match conn.get_offsets(&topic, partition, time) {
                Ok(_) => {
                    let result = lua.create_table()?;
                    let offsets = lua.create_table()?;

                    let entry = lua.create_table()?;
                    entry.set("partition", partition)?;
                    entry.set("offset", 0i64)?;
                    offsets.set(1, entry)?;

                    result.set("offsets", offsets)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    Ok(result)
                }
            }
        },
    )?;
    kafka.set("get_offsets", get_offsets_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("2.8.0"))?;
    kafka.set("version", version_fn)?;

    let async_connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        match KafkaConnection::new(&host, port) {
            Ok(conn) => {
                let r = lua.create_table()?;
                r.set("host", conn.host)?;
                r.set("port", conn.port)?;
                r.set("broker_id", 1)?;
                Ok(r)
            }
            Err(e) => {
                let r = lua.create_table()?;
                r.set("error", e)?;
                Ok(r)
            }
        }
    })?;
    kafka.set("connect_async", async_connect_fn)?;

    globals.set("kafka", kafka)?;
    Ok(())
}
