//! NSE tftp library wrapper
//!
//! TFTP (Trivial File Transfer Protocol) client implementation.
//! Based on Nmap's tftp library concepts.

use mlua::{Lua, Result as LuaResult};
use std::net::UdpSocket;
use std::time::Duration;
use tokio::net::UdpSocket as AsyncUdpSocket;

const TFTP_PORT: u16 = 69;
const TFTP_RRQ: u8 = 1;
const TFTP_WRQ: u8 = 2;
const TFTP_DATA: u8 = 3;
const TFTP_ACK: u8 = 4;
const TFTP_ERROR: u8 = 5;

fn build_rrq(filename: &str, mode: &str) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0);
    packet.push(TFTP_RRQ);
    packet.extend_from_slice(filename.as_bytes());
    packet.push(0);
    packet.extend_from_slice(mode.as_bytes());
    packet.push(0);
    packet
}

fn build_ack(block_num: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(0);
    packet.push(TFTP_ACK);
    packet.extend_from_slice(&block_num.to_be_bytes());
    packet
}

pub fn register_tftp_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let tftp = lua.create_table()?;

    let new_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let t = lua.create_table()?;
        t.set("host", host)?;
        t.set("port", port)?;
        t.set("timeout", 5i64)?;
        Ok(t)
    })?;
    tftp.set("new", new_fn)?;

    let get_fn = lua.create_function(
        |lua, (host, file, mode): (String, String, Option<String>)| {
            let result = lua.create_table()?;

            let mode = mode.unwrap_or_else(|| "octet".to_string());

            let addr = format!("{}:{}", host, TFTP_PORT);

            match UdpSocket::bind("0.0.0.0:0") {
                Ok(socket) => {
                    socket.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    socket.set_write_timeout(Some(Duration::from_secs(10))).ok();

                    let rrq = build_rrq(&file, &mode);

                    match socket.send_to(&rrq, &addr) {
                        Ok(_) => {
                            let mut data = Vec::new();
                            let mut block_num = 1u16;
                            let mut last_block = 0u16;
                            let mut attempts = 0;
                            let max_attempts = 10;

                            loop {
                                if attempts >= max_attempts {
                                    break;
                                }

                                let mut buf = [0u8; 516];
                                match socket.recv_from(&mut buf) {
                                    Ok((n, _)) => {
                                        if n < 4 {
                                            result.set("success", false)?;
                                            result.set("error", "Invalid packet")?;
                                            return Ok(result);
                                        }

                                        let opcode = u16::from_be_bytes([buf[0], buf[1]]);

                                        if opcode == TFTP_ERROR as u16 {
                                            let error_code = u16::from_be_bytes([buf[2], buf[3]]);
                                            let error_msg =
                                                String::from_utf8_lossy(&buf[4..n]).to_string();
                                            result.set("success", false)?;
                                            result.set("error_code", error_code)?;
                                            result.set("error", error_msg)?;
                                            return Ok(result);
                                        }

                                        if opcode == TFTP_DATA as u16 {
                                            let received_block =
                                                u16::from_be_bytes([buf[2], buf[3]]);

                                            if received_block == block_num
                                                || received_block == last_block + 1
                                            {
                                                data.extend_from_slice(&buf[4..n]);
                                                last_block = received_block;

                                                let ack = build_ack(received_block);
                                                if socket.send_to(&ack, &addr).is_err() {
                                                    tracing::warn!("Failed to send TFTP ACK for block {}", received_block);
                                                }

                                                if n < 516 {
                                                    break;
                                                }

                                                block_num += 1;
                                                attempts = 0;
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        attempts += 1;

                                        if last_block > 0 {
                                            let ack = build_ack(last_block);
                                            if socket.send_to(&ack, &addr).is_err() {
                                                tracing::warn!("Failed to send TFTP ACK for block {}", last_block);
                                            }
                                        }
                                    }
                                }
                            }

                            result.set("success", true)?;
                            result.set("filename", file)?;
                            result.set("size", data.len())?;

                            use base64::Engine;
                            let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
                            result.set("data", encoded)?;
                        }
                        Err(e) => {
                            result.set("success", false)?;
                            result.set("error", format!("Send failed: {}", e))?;
                        }
                    }
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Socket failed: {}", e))?;
                }
            }

            Ok(result)
        },
    )?;
    tftp.set("get", get_fn)?;

    let put_fn = lua.create_function(
        |lua, (host, file, data, mode): (String, String, String, Option<String>)| {
            let result = lua.create_table()?;

            let mode = mode.unwrap_or_else(|| "octet".to_string());

            let addr = format!("{}:{}", host, TFTP_PORT);

            use base64::Engine;
            let file_data = match base64::engine::general_purpose::STANDARD.decode(&data) {
                Ok(d) => d,
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Failed to decode data: {}", e))?;
                    return Ok(result);
                }
            };

            match UdpSocket::bind("0.0.0.0:0") {
                Ok(socket) => {
                    socket.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    socket.set_write_timeout(Some(Duration::from_secs(10))).ok();

                    let mut wrq = Vec::new();
                    wrq.push(0);
                    wrq.push(TFTP_WRQ);
                    wrq.extend_from_slice(file.as_bytes());
                    wrq.push(0);
                    wrq.extend_from_slice(mode.as_bytes());
                    wrq.push(0);

                    match socket.send_to(&wrq, &addr) {
                        Ok(_) => {
                            let mut block_num = 1u16;
                            let mut offset = 0;
                            let mut attempts = 0;
                            let max_attempts = 10;
                            let block_size = 512;

                            loop {
                                if attempts >= max_attempts {
                                    break;
                                }

                                let mut ack_buf = [0u8; 4];
                                match socket.recv_from(&mut ack_buf) {
                                    Ok((_, src)) => {
                                        let opcode = u16::from_be_bytes([ack_buf[0], ack_buf[1]]);
                                        let ack_block =
                                            u16::from_be_bytes([ack_buf[2], ack_buf[3]]);

                                        if opcode == TFTP_ACK as u16 && ack_block == block_num - 1 {
                                            let chunk =
                                                &file_data[offset..offset.min(file_data.len())];

                                            let mut data_packet = Vec::new();
                                            data_packet.push(0);
                                            data_packet.push(TFTP_DATA);
                                            data_packet.extend_from_slice(&block_num.to_be_bytes());
                                            data_packet.extend_from_slice(chunk);

                                            if socket.send_to(&data_packet, src).is_err() {
                                                result.set("success", false)?;
                                                result.set("error", "Failed to send data")?;
                                                return Ok(result);
                                            }

                                            offset += block_size;
                                            block_num += 1;
                                            attempts = 0;

                                            if offset >= file_data.len() {
                                                break;
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        attempts += 1;
                                    }
                                }
                            }

                            result.set("success", true)?;
                            result.set("filename", file)?;
                            result.set("size", file_data.len())?;
                        }
                        Err(e) => {
                            result.set("success", false)?;
                            result.set("error", format!("Send failed: {}", e))?;
                        }
                    }
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", format!("Socket failed: {}", e))?;
                }
            }

            Ok(result)
        },
    )?;
    tftp.set("put", put_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    tftp.set("version", version_fn)?;

    let async_get_fn = lua.create_function(
        |lua, (host, file, mode): (String, String, Option<String>)| {
            let runtime = tokio::runtime::Handle::current();
            let host_clone = host.clone();
            let file_clone = file.clone();
            let mode = mode.unwrap_or_else(|| "octet".to_string());

            runtime.block_on(async {
                let result = lua.create_table()?;

                match AsyncUdpSocket::bind("0.0.0.0:0").await {
                    Ok(socket) => {
                        let addr = format!("{}:{}", host_clone, TFTP_PORT);
                        let rrq = build_rrq(&file_clone, &mode);

                        match socket.send_to(&rrq, &addr).await {
                            Ok(_) => {
                                let mut data = Vec::new();
                                let mut block_num = 1u16;
                                let mut last_block = 0u16;
                                let mut attempts = 0;
                                let max_attempts = 10;

                                loop {
                                    if attempts >= max_attempts {
                                        break;
                                    }

                                    let mut buf = [0u8; 516];
                                    match socket.recv_from(&mut buf).await {
                                        Ok((n, _)) => {
                                            if n < 4 {
                                                result.set("success", false)?;
                                                result.set("error", "Invalid packet")?;
                                                return Ok(result);
                                            }

                                            let opcode = u16::from_be_bytes([buf[0], buf[1]]);

                                            if opcode == TFTP_ERROR as u16 {
                                                let error_code =
                                                    u16::from_be_bytes([buf[2], buf[3]]);
                                                let error_msg =
                                                    String::from_utf8_lossy(&buf[4..n]).to_string();
                                                result.set("success", false)?;
                                                result.set("error_code", error_code)?;
                                                result.set("error", error_msg)?;
                                                return Ok(result);
                                            }

                                            if opcode == TFTP_DATA as u16 {
                                                let received_block =
                                                    u16::from_be_bytes([buf[2], buf[3]]);

                                                if received_block == block_num
                                                    || received_block == last_block + 1
                                                {
                                                    data.extend_from_slice(&buf[4..n]);
                                                    last_block = received_block;

                                                    let ack = build_ack(received_block);
                                                    if socket.send_to(&ack, &addr).await.is_err() {
                                                        tracing::warn!("Failed to send TFTP ACK for block {}", received_block);
                                                    }

                                                    if n < 516 {
                                                        break;
                                                    }

                                                    block_num += 1;
                                                    attempts = 0;
                                                }
                                            }
                                        }
                                        Err(_) => {
                                            attempts += 1;
                                            if last_block > 0 {
                                                let ack = build_ack(last_block);
                                                if socket.send_to(&ack, &addr).await.is_err() {
                                                    tracing::warn!("Failed to send TFTP ACK for block {}", last_block);
                                                }
                                            }
                                        }
                                    }
                                }

                                result.set("success", true)?;
                                result.set("filename", file_clone)?;
                                result.set("size", data.len())?;

                                use base64::Engine;
                                let encoded =
                                    base64::engine::general_purpose::STANDARD.encode(&data);
                                result.set("data", encoded)?;
                            }
                            Err(e) => {
                                result.set("success", false)?;
                                result.set("error", format!("Send failed: {}", e))?;
                            }
                        }
                    }
                    Err(e) => {
                        result.set("success", false)?;
                        result.set("error", format!("Socket failed: {}", e))?;
                    }
                }

                Ok(result)
            })
        },
    )?;
    tftp.set("get_async", async_get_fn)?;

    globals.set("tftp", tftp)?;
    Ok(())
}
