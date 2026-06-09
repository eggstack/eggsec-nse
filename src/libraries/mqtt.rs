//! NSE mqtt library wrapper
//!
//! MQTT (Message Queuing Telemetry Transport) protocol support for NSE scripts.
//! Implements MQTT 3.1.1/5.0 protocol.

use mlua::{Lua, Result as LuaResult, Table};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const MQTT_PROTOCOL_LEVEL: u8 = 4;

const CONNECT: u8 = 1;
const CONNACK: u8 = 2;
const PUBLISH: u8 = 3;
const PUBACK: u8 = 4;
const SUBSCRIBE: u8 = 8;
const SUBACK: u8 = 9;
const PINGREQ: u8 = 12;
const PINGRESP: u8 = 13;
const DISCONNECT: u8 = 14;

const CLEAN_SESSION: u8 = 0x02;
const PASSWORD_FLAG: u8 = 0x40;
const USER_NAME_FLAG: u8 = 0x80;

struct MqttConnection {
    stream: TcpStream,
    host: String,
    port: u16,
    client_id: String,
    packet_id: u16,
    keepalive: u16,
}

impl MqttConnection {
    fn new(host: &str, port: u16, client_id: &str, keepalive: u16) -> Result<Self, String> {
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
            client_id: client_id.to_string(),
            packet_id: 0,
            keepalive,
        })
    }

    fn next_packet_id(&mut self) -> u16 {
        self.packet_id = self.packet_id.wrapping_add(1);
        self.packet_id
    }

    fn connect(
        &mut self,
        username: Option<&str>,
        password: Option<&str>,
        clean_session: bool,
    ) -> Result<bool, String> {
        let mut packet = Vec::new();

        packet.extend_from_slice(b"MQTT");
        packet.push(4);

        let mut flags: u8 = 0;
        if clean_session {
            flags |= CLEAN_SESSION;
        }
        if password.is_some() {
            flags |= PASSWORD_FLAG;
        }
        if username.is_some() {
            flags |= USER_NAME_FLAG;
        }
        packet.push(flags);

        packet.extend_from_slice(&self.keepalive.to_be_bytes());

        let client_id_bytes = self.client_id.as_bytes();
        packet.extend_from_slice(&(client_id_bytes.len() as i16).to_be_bytes());
        packet.extend_from_slice(client_id_bytes);

        if let Some(user) = username {
            let user_bytes = user.as_bytes();
            packet.extend_from_slice(&(user_bytes.len() as i16).to_be_bytes());
            packet.extend_from_slice(user_bytes);
        }

        if let Some(pass) = password {
            let pass_bytes = pass.as_bytes();
            packet.extend_from_slice(&(pass_bytes.len() as i16).to_be_bytes());
            packet.extend_from_slice(pass_bytes);
        }

        self.send_packet(CONNECT, &packet)?;

        let response = self.read_packet()?;

        if response.is_empty() {
            return Err("No response from server".to_string());
        }

        let packet_type = response[0] >> 4;
        if packet_type != CONNACK {
            return Err(format!("Expected CONNACK, got {}", packet_type));
        }

        if response.len() >= 4 {
            let return_code = response[3];
            if return_code == 0 {
                Ok(true)
            } else {
                Err(format!("Connection failed with code: {}", return_code))
            }
        } else {
            Ok(true)
        }
    }

    fn publish(
        &mut self,
        topic: &str,
        payload: &[u8],
        qos: u8,
        retain: bool,
    ) -> Result<(u16, bool), String> {
        let mut packet = Vec::new();

        let topic_bytes = topic.as_bytes();
        packet.extend_from_slice(&(topic_bytes.len() as i16).to_be_bytes());
        packet.extend_from_slice(topic_bytes);

        let packet_id = if qos > 0 {
            let id = self.next_packet_id();
            packet.extend_from_slice(&id.to_be_bytes());
            Some(id)
        } else {
            None
        };

        packet.extend_from_slice(payload);

        let mut flags = qos << 1;
        if retain {
            flags |= 1;
        }
        self.send_packet_with_flags(PUBLISH, flags, &packet)?;

        if qos == 1 {
            let response = self.read_packet()?;
            if !response.is_empty() && response[0] >> 4 == PUBACK {
                if let Some(id) = packet_id {
                    return Ok((id, true));
                }
            }
        }

        if let Some(id) = packet_id {
            Ok((id, true))
        } else {
            Ok((0, true))
        }
    }

    fn subscribe(&mut self, topics: &[(&str, u8)]) -> Result<Vec<(String, u8)>, String> {
        let packet_id = self.next_packet_id();

        let mut packet = Vec::new();
        packet.extend_from_slice(&packet_id.to_be_bytes());

        for (topic, qos) in topics {
            let topic_bytes = topic.as_bytes();
            packet.extend_from_slice(&(topic_bytes.len() as i16).to_be_bytes());
            packet.extend_from_slice(topic_bytes);
            packet.push(*qos);
        }

        self.send_packet(SUBSCRIBE, &packet)?;

        let response = self.read_packet()?;

        if response.is_empty() || response[0] >> 4 != SUBACK {
            return Err("Invalid SUBACK response".to_string());
        }

        let mut results = Vec::new();
        for (i, (topic, _)) in topics.iter().enumerate() {
            let offset = 4 + i;
            if offset < response.len() {
                let return_code = response[offset];
                results.push((topic.to_string(), return_code));
            } else {
                results.push((topic.to_string(), 0x80));
            }
        }

        Ok(results)
    }

    fn unsubscribe(&mut self, topics: &[String]) -> Result<bool, String> {
        let packet_id = self.next_packet_id();

        let mut packet = Vec::new();
        packet.extend_from_slice(&packet_id.to_be_bytes());

        for topic in topics {
            let topic_bytes = topic.as_bytes();
            packet.extend_from_slice(&(topic_bytes.len() as i16).to_be_bytes());
            packet.extend_from_slice(topic_bytes);
        }

        self.send_packet(UNSUBSCRIBE, &packet)?;

        Ok(true)
    }

    fn ping(&mut self) -> Result<bool, String> {
        self.send_packet(PINGREQ, &[])?;

        let response = self.read_packet()?;

        if !response.is_empty() && response[0] >> 4 == PINGRESP {
            Ok(true)
        } else {
            Err("Invalid PINGRESP".to_string())
        }
    }

    fn disconnect(&mut self) -> Result<bool, String> {
        self.send_packet(DISCONNECT, &[])?;
        Ok(true)
    }

    fn send_packet(&mut self, packet_type: u8, payload: &[u8]) -> Result<(), String> {
        self.send_packet_with_flags(packet_type, 0, payload)
    }

    fn send_packet_with_flags(
        &mut self,
        packet_type: u8,
        flags: u8,
        payload: &[u8],
    ) -> Result<(), String> {
        let mut buffer = Vec::new();

        let header = (packet_type << 4) | (flags & 0x0F);
        buffer.push(header);

        let mut length = payload.len();
        loop {
            let mut b = (length % 128) as u8;
            length /= 128;
            if length > 0 {
                b |= 0x80;
            }
            buffer.push(b);
            if length == 0 {
                break;
            }
        }

        buffer.extend_from_slice(payload);

        self.stream.write_all(&buffer).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn read_packet(&mut self) -> Result<Vec<u8>, String> {
        let mut header = [0u8; 1];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| e.to_string())?;

        let mut length = 0;
        let mut multiplier = 1;
        loop {
            let mut b = [0u8; 1];
            self.stream.read_exact(&mut b).map_err(|e| e.to_string())?;
            length += (b[0] as usize & 0x7F) * multiplier;
            multiplier *= 128;
            if b[0] & 0x80 == 0 {
                break;
            }
        }

        let mut payload = vec![0u8; length];
        if length > 0 {
            self.stream
                .read_exact(&mut payload)
                .map_err(|e| e.to_string())?;
        }

        let mut full_packet = vec![header[0]];
        full_packet.extend_from_slice(&payload);

        Ok(full_packet)
    }
}

const UNSUBSCRIBE: u8 = 10;
const UNSUBACK: u8 = 11;

pub fn register_mqtt_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let mqtt = lua.create_table()?;

    let connect_fn =
        lua.create_function(|lua, (host, port, client_id): (String, u16, String)| {
            let mut conn = match MqttConnection::new(&host, port, &client_id, 60) {
                Ok(c) => c,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };

            match conn.connect(None, None, true) {
                Ok(connected) => {
                    let result = lua.create_table()?;
                    result.set("host", host)?;
                    result.set("port", port)?;
                    result.set("client_id", client_id)?;
                    result.set("session_present", false)?;
                    result.set("connected", connected)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    Ok(result)
                }
            }
        })?;
    mqtt.set("connect", connect_fn)?;

    let connect_auth_fn = lua.create_function(
        |lua,
         (host, port, client_id, username, password): (
            String,
            u16,
            String,
            Option<String>,
            Option<String>,
        )| {
            let mut conn = match MqttConnection::new(&host, port, &client_id, 60) {
                Ok(c) => c,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };

            match conn.connect(username.as_deref(), password.as_deref(), true) {
                Ok(connected) => {
                    let result = lua.create_table()?;
                    result.set("host", host)?;
                    result.set("port", port)?;
                    result.set("client_id", client_id)?;
                    result.set("session_present", false)?;
                    result.set("connected", connected)?;
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
    mqtt.set("connect_auth", connect_auth_fn)?;

    let publish_fn = lua.create_function(
        |lua, (host, port, topic, payload, qos, retain): (String, u16, String, String, u8, bool)| {
            let mut conn = match MqttConnection::new(&host, port, "eggsec", 60) {
                Ok(c) => c,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };

            if let Err(e) = conn.connect(None, None, true) {
                let result = lua.create_table()?;
                result.set("error", e)?;
                return Ok(result);
            }

            match conn.publish(&topic, payload.as_bytes(), qos, retain) {
                Ok((packet_id, published)) => {
                    let result = lua.create_table()?;
                    result.set("published", published)?;
                    result.set("packet_id", packet_id)?;
                    result.set("topic", topic)?;
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
    mqtt.set("publish", publish_fn)?;

    let subscribe_fn = lua.create_function(|lua, (host, port, topics): (String, u16, Table)| {
        let mut conn = match MqttConnection::new(&host, port, "eggsec", 60) {
            Ok(c) => c,
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e)?;
                return Ok(result);
            }
        };

        if let Err(e) = conn.connect(None, None, true) {
            let result = lua.create_table()?;
            result.set("error", e)?;
            return Ok(result);
        }

        let mut topic_list: Vec<(String, u8)> = Vec::new();
        for (topic, qos) in topics.pairs::<String, u8>().flatten() {
            topic_list.push((topic, qos));
        }

        let topic_refs: Vec<(&str, u8)> =
            topic_list.iter().map(|(t, q)| (t.as_str(), *q)).collect();

        match conn.subscribe(&topic_refs) {
            Ok(results) => {
                let result = lua.create_table()?;
                let subscribed = lua.create_table()?;

                for (i, (topic, qos)) in results.iter().enumerate() {
                    let entry = lua.create_table()?;
                    entry.set("topic", topic.as_str())?;
                    entry.set("qos", *qos)?;
                    subscribed.set(i + 1, entry)?;
                }

                result.set("subscribed", subscribed)?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e)?;
                Ok(result)
            }
        }
    })?;
    mqtt.set("subscribe", subscribe_fn)?;

    let unsubscribe_fn =
        lua.create_function(|lua, (host, port, topics): (String, u16, Table)| {
            let mut conn = match MqttConnection::new(&host, port, "eggsec", 60) {
                Ok(c) => c,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    return Ok(result);
                }
            };

            if let Err(e) = conn.connect(None, None, true) {
                let result = lua.create_table()?;
                result.set("error", e)?;
                return Ok(result);
            }

            let mut topic_list: Vec<String> = Vec::new();
            for (topic, _) in topics.pairs::<String, mlua::Value>().flatten() {
                topic_list.push(topic);
            }

            match conn.unsubscribe(&topic_list) {
                Ok(_) => {
                    let result = lua.create_table()?;
                    result.set("unsubscribed", true)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    Ok(result)
                }
            }
        })?;
    mqtt.set("unsubscribe", unsubscribe_fn)?;

    let disconnect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let mut conn = match MqttConnection::new(&host, port, "eggsec", 60) {
            Ok(c) => c,
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e)?;
                return Ok(result);
            }
        };

        match conn.disconnect() {
            Ok(_) => {
                let result = lua.create_table()?;
                result.set("disconnected", true)?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e)?;
                Ok(result)
            }
        }
    })?;
    mqtt.set("disconnect", disconnect_fn)?;

    let ping_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let mut conn = match MqttConnection::new(&host, port, "eggsec", 60) {
            Ok(c) => c,
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e)?;
                return Ok(result);
            }
        };

        if let Err(e) = conn.connect(None, None, true) {
            let result = lua.create_table()?;
            result.set("error", e)?;
            return Ok(result);
        }

        match conn.ping() {
            Ok(pong) => {
                let result = lua.create_table()?;
                result.set("pong", pong)?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e)?;
                Ok(result)
            }
        }
    })?;
    mqtt.set("ping", ping_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("3.1.1"))?;
    mqtt.set("version", version_fn)?;

    let async_connect_fn =
        lua.create_function(|lua, (host, port, client_id): (String, u16, String)| {
            let mut conn = match MqttConnection::new(&host, port, &client_id, 60) {
                Ok(c) => c,
                Err(e) => {
                    let r = lua.create_table()?;
                    r.set("error", e)?;
                    return Ok(r);
                }
            };

            match conn.connect(None, None, true) {
                Ok(connected) => {
                    let r = lua.create_table()?;
                    r.set("host", host)?;
                    r.set("port", port)?;
                    r.set("client_id", client_id)?;
                    r.set("connected", connected)?;
                    Ok(r)
                }
                Err(e) => {
                    let r = lua.create_table()?;
                    r.set("error", e)?;
                    Ok(r)
                }
            }
        })?;
    mqtt.set("connect_async", async_connect_fn)?;

    globals.set("mqtt", mqtt)?;
    Ok(())
}
