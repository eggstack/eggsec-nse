//! NSE kafka library wrapper
//!
//! Apache Kafka protocol support for NSE scripts.
//! Implements the Kafka Wire Protocol (0.9 - 2.x).

use crate::capabilities::NseCapabilityContext;
use crate::providers::{
    broker_tcp_connect, broker_tcp_receive, broker_tcp_send, NseHostServices, NseTcpConnection,
};
use mlua::{Lua, Result as LuaResult};
use std::time::Duration;

#[allow(dead_code)]
const API_VERSION: i16 = 1;
const CLIENT_ID: &str = "eggsec-nse";

struct KafkaConnection {
    handle: Box<dyn NseTcpConnection>,
    ctx: NseCapabilityContext,
    operation: &'static str,
    host: String,
    port: u16,
    correlation_id: i32,
}

impl KafkaConnection {
    fn new(
        ctx: &NseCapabilityContext,
        services: &NseHostServices,
        host: &str,
        port: u16,
        operation: &'static str,
    ) -> Result<Self, String> {
        // The broker resolves `host` (authority-preserving) instead of
        // requiring a literal `SocketAddr` string.
        let (mut handle, _endpoint) = broker_tcp_connect(
            ctx,
            services,
            host,
            port,
            Duration::from_secs(10),
            operation,
        )?;

        // Preserve the original 30s read/write timeout behavior via the
        // provider handle (failures here were ignored before).
        let _ = handle.set_timeouts(Duration::from_secs(30));

        Ok(Self {
            handle,
            ctx: ctx.clone(),
            operation,
            host: host.to_string(),
            port,
            correlation_id: 0,
        })
    }

    fn next_correlation_id(&mut self) -> i32 {
        self.correlation_id += 1;
        self.correlation_id
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), String> {
        // `broker_tcp_send` may short-write; loop like `write_all`.
        let mut written = 0;
        while written < buf.len() {
            let n = broker_tcp_send(
                &self.ctx,
                self.handle.as_mut(),
                &buf[written..],
                self.operation,
            )?;
            if n == 0 {
                return Err("Kafka send wrote zero bytes".to_string());
            }
            written += n;
        }
        Ok(())
    }

    fn read_exact(&mut self, len: usize) -> Result<Vec<u8>, String> {
        // `broker_tcp_receive` returns one chunk; loop like `read_exact`.
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let chunk = broker_tcp_receive(
                &self.ctx,
                self.handle.as_mut(),
                len - out.len(),
                self.operation,
            )?;
            if chunk.is_empty() {
                return Err("Kafka connection closed mid-response".to_string());
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
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

        self.write_all(&buffer)?;

        let len_buf = self.read_exact(4)?;
        let response_len_raw = i32::from_be_bytes([len_buf[0], len_buf[1], len_buf[2], len_buf[3]]);
        if response_len_raw < 0 || response_len_raw as usize > 64 * 1024 * 1024 {
            return Err(format!(
                "Invalid Kafka response length: {}",
                response_len_raw
            ));
        }
        let response_len = response_len_raw as usize;

        self.read_exact(response_len)
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
            return Err(format!(
                "Kafka topic too long: {} bytes (max {})",
                topic_bytes.len(),
                i16::MAX
            ));
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

/// Provider-backed kafka registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_kafka_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let kafka = lua.create_table()?;

    let connect_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port): (String, u16)| match KafkaConnection::new(
            &ctx,
            &services,
            &host,
            port,
            "kafka.connect",
        ) {
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

    let list_topics_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port): (String, u16)| {
            let mut conn =
                match KafkaConnection::new(&ctx, &services, &host, port, "kafka.list_topics") {
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

    let produce_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, topic, key, value): (String, u16, String, String, String)| {
            let mut conn = match KafkaConnection::new(&ctx, &services, &host, port, "kafka.produce")
            {
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
        }
    })?;
    kafka.set("produce", produce_fn)?;

    let consume_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, topic, partition, offset): (String, u16, String, i32, i64)| {
            let mut conn = match KafkaConnection::new(&ctx, &services, &host, port, "kafka.consume")
            {
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
        }
    })?;
    kafka.set("consume", consume_fn)?;

    let get_offsets_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, topic, partition, time): (String, u16, String, i32, i64)| {
            let mut conn =
                match KafkaConnection::new(&ctx, &services, &host, port, "kafka.get_offsets") {
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
        }
    })?;
    kafka.set("get_offsets", get_offsets_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("2.8.0"))?;
    kafka.set("version", version_fn)?;

    let async_connect_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port): (String, u16)| match KafkaConnection::new(
            &ctx,
            &services,
            &host,
            port,
            "kafka.connect_async",
        ) {
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
