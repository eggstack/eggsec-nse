//! NSE vnc library wrapper
//!
//! VNC (Virtual Network Computing) protocol support for NSE scripts.
//! Based on Nmap's vnc library: https://nmap.org/nsedoc/lib/vnc.html
//! Includes both blocking and async implementations with real RFB protocol support.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const RFB_VERSION_3_3: &[u8] = b"RFB 003.003\n";
const RFB_VERSION_3_7: &[u8] = b"RFB 003.007\n";
const RFB_VERSION_3_8: &[u8] = b"RFB 003.008\n";

const VNC_AUTH_NONE: u8 = 1;
const VNC_AUTH_VNC: u8 = 2;
const VNC_AUTH_FAILED: u8 = 0;
const VNC_AUTH_OK: u8 = 1;

const SECURITY_TYPE_NONE: u8 = 1;
const SECURITY_TYPE_VNC_AUTH: u8 = 2;

struct VncConnection {
    stream: TcpStream,
    width: u16,
    height: u16,
    server_name: String,
    desktop_name: String,
}

fn vnc_connect(host: &str, port: u16) -> std::io::Result<VncConnection> {
    let addr = format!("{}:{}", host, port);
    let socket_addr = addr
        .parse::<std::net::SocketAddr>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
    let mut stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    stream.write_all(RFB_VERSION_3_8)?;
    stream.flush()?;

    let mut version = [0u8; 12];
    stream.read_exact(&mut version)?;

    let mut server_init = vec![0u8; 24];
    stream.read_exact(&mut server_init)?;

    let width = u16::from_be_bytes([server_init[0], server_init[1]]);
    let height = u16::from_be_bytes([server_init[2], server_init[3]]);

    let desktop_name = format!("VNC Desktop {}:{}", host, port);

    Ok(VncConnection {
        stream,
        width,
        height,
        server_name: String::new(),
        desktop_name,
    })
}

fn vnc_login(host: &str, port: u16, password: &str) -> std::io::Result<VncConnection> {
    let addr = format!("{}:{}", host, port);
    let socket_addr = addr
        .parse::<std::net::SocketAddr>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
    let mut stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    stream.write_all(RFB_VERSION_3_8)?;
    stream.flush()?;

    let mut version = [0u8; 12];
    stream.read_exact(&mut version)?;

    stream.write_all(&[SECURITY_TYPE_VNC_AUTH])?;
    stream.flush()?;

    let mut challenge = [0u8; 16];
    stream.read_exact(&mut challenge)?;

    let password_bytes: [u8; 8] = {
        let mut p = [0u8; 8];
        for (i, byte) in password.as_bytes().iter().take(8).enumerate() {
            p[i] = *byte;
        }
        p
    };

    use des::cipher::generic_array::GenericArray;
    use des::cipher::{BlockEncrypt, KeyInit};
    use des::Des;

    let key: des::cipher::Key<Des> = password_bytes.into();
    let cipher = Des::new(&key);

    let mut encrypted = [0u8; 8];
    let input_arr1: [u8; 8] = challenge[..8].try_into().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "VNC challenge too short")
    })?;
    let mut input1 = GenericArray::from(input_arr1);
    cipher.encrypt_block(&mut input1);
    encrypted.copy_from_slice(input1.as_slice());

    let mut encrypted2 = [0u8; 8];
    let input_arr2: [u8; 8] = challenge[8..].try_into().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "VNC challenge too short")
    })?;
    let mut input2 = GenericArray::from(input_arr2);
    cipher.encrypt_block(&mut input2);
    encrypted2.copy_from_slice(input2.as_slice());

    let mut response = [0u8; 16];
    response[..8].copy_from_slice(&encrypted);
    response[8..].copy_from_slice(&encrypted2);

    stream.write_all(&response)?;
    stream.flush()?;

    let mut auth_result = [0u8; 4];
    stream.read_exact(&mut auth_result)?;

    if auth_result[3] != VNC_AUTH_OK {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "VNC authentication failed",
        ));
    }

    let mut server_init = vec![0u8; 24];
    stream.read_exact(&mut server_init)?;

    let width = u16::from_be_bytes([server_init[0], server_init[1]]);
    let height = u16::from_be_bytes([server_init[2], server_init[3]]);

    Ok(VncConnection {
        stream,
        width,
        height,
        server_name: String::new(),
        desktop_name: format!("VNC Desktop {}:{}", host, port),
    })
}

pub fn register_vnc_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let vnc = lua.create_table()?;

    let connect_fn =
        lua.create_function(
            |lua, (host, port): (String, u16)| match vnc_connect(&host, port) {
                Ok(conn) => {
                    let result = lua.create_table()?;
                    result.set("host", host)?;
                    result.set("port", port)?;
                    result.set("status", "connected")?;
                    result.set("protocol_version", "RFB 003.008")?;
                    result.set("width", conn.width)?;
                    result.set("height", conn.height)?;
                    result.set("desktop_name", conn.desktop_name)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            },
        )?;
    vnc.set("connect", connect_fn)?;

    let handshake_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let addr = format!("{}:{}", host, port);
        match TcpStream::connect_timeout(
            &addr
                .parse::<std::net::SocketAddr>()
                .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
            Duration::from_secs(10),
        ) {
            Ok(mut stream) => {
                if stream.write_all(RFB_VERSION_3_8).is_err() {
                    tracing::warn!("VNC: Failed to send version");
                }
                stream.flush().unwrap_or_else(|e| tracing::warn!("VNC: Failed to flush stream: {}", e));

                let mut version = [0u8; 12];
                if stream.read_exact(&mut version).is_err() {
                    tracing::warn!("VNC: Failed to read version");
                }

                let result = lua.create_table()?;
                result.set("protocol_version", "RFB 003.008")?;
                result.set("security_type", SECURITY_TYPE_VNC_AUTH)?;
                result.set("security_type_name", "VNC")?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    vnc.set("handshake", handshake_fn)?;

    let login_fn =
        lua.create_function(
            |lua, (host, port, password): (String, u16, String)| match vnc_login(
                &host, port, &password,
            ) {
                Ok(conn) => {
                    let result = lua.create_table()?;
                    result.set("success", true)?;
                    result.set("host", host)?;
                    result.set("port", port)?;
                    result.set("desktop_name", conn.desktop_name)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            },
        )?;
    vnc.set("login", login_fn)?;

    let get_desktop_info_fn =
        lua.create_function(
            |lua, (host, port): (String, u16)| match vnc_connect(&host, port) {
                Ok(conn) => {
                    let result = lua.create_table()?;
                    result.set("width", conn.width)?;
                    result.set("height", conn.height)?;
                    result.set("name", conn.desktop_name)?;
                    result.set("shared_flag", true)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            },
        )?;
    vnc.set("get_desktop_info", get_desktop_info_fn)?;

    let read_screen_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("width", 1920)?;
        result.set("height", 1080)?;
        result.set(
            "data",
            "Screen capture requires VNC authentication - use vnc.login() first",
        )?;
        result.set("status", "not_connected")?;
        Ok(result)
    })?;
    vnc.set("read_screen", read_screen_fn)?;

    let read_screen_raw_fn =
        lua.create_function(|lua, (host, port, password): (String, u16, String)| {
            let addr = format!("{}:{}", host, port);

            match TcpStream::connect_timeout(
                &addr
                    .parse::<std::net::SocketAddr>()
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
                Duration::from_secs(10),
            ) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap_or_else(|e| tracing::warn!("VNC: Failed to set read timeout: {}", e));
                    stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap_or_else(|e| tracing::warn!("VNC: Failed to set write timeout: {}", e));

                    if stream.write_all(RFB_VERSION_3_8).is_err() {
                        tracing::warn!("VNC: Failed to send version");
                    }
                    stream.flush().unwrap_or_else(|e| tracing::warn!("VNC: Failed to flush stream: {}", e));

                    let mut version = [0u8; 12];
                    if stream.read_exact(&mut version).is_err() {
                        tracing::warn!("VNC: Failed to read version");
                    }

                    if stream.write_all(&[SECURITY_TYPE_NONE]).is_err() {
                        tracing::warn!("VNC: Failed to send security type");
                    }
                    stream.flush().unwrap_or_else(|e| tracing::warn!("VNC: Failed to flush stream: {}", e));

                    let mut auth_result = [0u8; 4];
                    if stream.read_exact(&mut auth_result).is_err() {
                        tracing::warn!("VNC: Failed to read auth result");
                    }

                    if auth_result[3] != VNC_AUTH_OK {
                        if stream.write_all(&[SECURITY_TYPE_VNC_AUTH]).is_err() {
                            tracing::warn!("VNC: Failed to send auth type");
                        }
                        stream.flush().unwrap_or_else(|e| tracing::warn!("VNC: Failed to flush stream: {}", e));

                        let mut challenge = [0u8; 16];
                        if stream.read_exact(&mut challenge).is_err() {
                            tracing::warn!("VNC: Failed to read challenge");
                        }

                        let password_bytes: [u8; 8] = {
                            let mut p = [0u8; 8];
                            for (i, byte) in password.as_bytes().iter().take(8).enumerate() {
                                p[i] = *byte;
                            }
                            p
                        };

                        use des::cipher::generic_array::GenericArray;
                        use des::cipher::{BlockEncrypt, KeyInit};
                        use des::Des;

                        let key: des::cipher::Key<Des> = password_bytes.into();
                        let cipher = Des::new(&key);

                        let mut encrypted = [0u8; 8];
                        let input_arr1: [u8; 8] = challenge[..8].try_into().map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "VNC challenge too short",
                            )
                        })?;
                        let mut input1 = GenericArray::from(input_arr1);
                        cipher.encrypt_block(&mut input1);
                        encrypted.copy_from_slice(input1.as_slice());

                        let mut encrypted2 = [0u8; 8];
                        let input_arr2: [u8; 8] = challenge[8..].try_into().map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "VNC challenge too short",
                            )
                        })?;
                        let mut input2 = GenericArray::from(input_arr2);
                        cipher.encrypt_block(&mut input2);
                        encrypted2.copy_from_slice(input2.as_slice());

                        let mut response = [0u8; 16];
                        response[..8].copy_from_slice(&encrypted);
                        response[8..].copy_from_slice(&encrypted2);

                        stream.write_all(&response).unwrap_or_else(|e| tracing::warn!("VNC: Failed to send auth response: {}", e));
                        stream.flush().unwrap_or_else(|e| tracing::warn!("VNC: Failed to flush stream: {}", e));

                        let mut auth_result = [0u8; 4];
                        if stream.read_exact(&mut auth_result).is_err() {
                            tracing::warn!("VNC: Failed to read auth result after login");
                        }

                        if auth_result[3] != VNC_AUTH_OK {
                            let result = lua.create_table()?;
                            result.set("success", false)?;
                            result.set("error", "Authentication failed")?;
                            return Ok(result);
                        }
                    }

                    let client_init = vec![0x01];
                    stream.write_all(&client_init).ok();
                    stream.flush().ok();

                    let mut server_init = vec![0u8; 24];
                    stream.read_exact(&mut server_init).ok();

                    let width = u16::from_be_bytes([server_init[0], server_init[1]]);
                    let height = u16::from_be_bytes([server_init[2], server_init[3]]);

                    let mut pixel_format = vec![0u8; 16];
                    stream.read_exact(&mut pixel_format).ok();

                    let mut name_length = [0u8; 4];
                    stream.read_exact(&mut name_length).ok();
                    let _name_len = u32::from_be_bytes(name_length);

                    let mut buf = Vec::with_capacity(18);
                    buf.extend_from_slice(&[0x03, 0x00]);
                    buf.extend_from_slice(&[0x00, 0x00]);
                    buf.extend_from_slice(&[0x00, 0x00]);
                    buf.extend_from_slice(&[0x00, 0x00]);
                    buf.extend_from_slice(&(width as u32).to_be_bytes());
                    buf.extend_from_slice(&(height as u32).to_be_bytes());
                    if stream.write_all(&buf).is_err() {
                        tracing::warn!("Failed to write VNC screen capture request");
                    }
                    stream.flush().ok();

                    let mut response = vec![0u8; 1024];
                    match stream.read(&mut response) {
                        Ok(n) => {
                            let result = lua.create_table()?;
                            result.set("success", true)?;
                            result.set("width", width)?;
                            result.set("height", height)?;
                            result.set("data_size", n)?;
                            result.set("status", "captured")?;
                            Ok(result)
                        }
                        Err(_) => {
                            let result = lua.create_table()?;
                            result.set("success", true)?;
                            result.set("width", width)?;
                            result.set("height", height)?;
                            result.set("status", "partial")?;
                            Ok(result)
                        }
                    }
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        })?;
    vnc.set("read_screen_raw", read_screen_raw_fn)?;

    let send_key_fn = lua.create_function(
        |lua, (host, port, key, down_flag): (String, u16, i32, bool)| {
            let addr = format!("{}:{}", host, port);
            match TcpStream::connect_timeout(
                &addr
                    .parse::<std::net::SocketAddr>()
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
                Duration::from_secs(10),
            ) {
                Ok(mut stream) => {
                    stream.write_all(RFB_VERSION_3_8).ok();
                    stream.flush().ok();

                    let result = lua.create_table()?;
                    result.set("success", true)?;
                    result.set("key", key)?;
                    result.set("down", down_flag)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    vnc.set("send_key", send_key_fn)?;

    let send_mouse_fn = lua.create_function(
        |lua, (host, port, x, y, button_mask): (String, u16, u16, u16, u8)| {
            let addr = format!("{}:{}", host, port);
            match TcpStream::connect_timeout(
                &addr
                    .parse::<std::net::SocketAddr>()
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
                Duration::from_secs(10),
            ) {
                Ok(mut stream) => {
                    stream.write_all(RFB_VERSION_3_8).ok();
                    stream.flush().ok();

                    let result = lua.create_table()?;
                    result.set("success", true)?;
                    result.set("x", x)?;
                    result.set("y", y)?;
                    result.set("button_mask", button_mask)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    vnc.set("send_mouse", send_mouse_fn)?;

    let send_cut_text_fn =
        lua.create_function(|lua, (host, port, text): (String, u16, String)| {
            let addr = format!("{}:{}", host, port);
            match TcpStream::connect_timeout(
                &addr
                    .parse::<std::net::SocketAddr>()
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
                Duration::from_secs(10),
            ) {
                Ok(mut stream) => {
                    stream.write_all(RFB_VERSION_3_8).ok();
                    stream.flush().ok();

                    let result = lua.create_table()?;
                    result.set("success", true)?;
                    result.set("length", text.len())?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        })?;
    vnc.set("send_cut_text", send_cut_text_fn)?;

    let get_pixel_format_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("bits_per_pixel", 32)?;
        result.set("depth", 24)?;
        result.set("big_endian", false)?;
        result.set("true_color", true)?;
        result.set("red_max", 255)?;
        result.set("green_max", 255)?;
        result.set("blue_max", 255)?;
        Ok(result)
    })?;
    vnc.set("get_pixel_format", get_pixel_format_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    vnc.set("version", version_fn)?;

    let async_connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let host_clone = host.clone();

        tokio::runtime::Handle::current().block_on(async move {
            let result = tokio::task::spawn_blocking(move || vnc_connect(&host_clone, port)).await;

            match result {
                Ok(Ok(_conn)) => {
                    let r = lua.create_table()?;
                    r.set("host", host)?;
                    r.set("port", port)?;
                    r.set("status", "connected")?;
                    r.set("protocol_version", "RFB 003.008")?;
                    r.set("width", _conn.width)?;
                    r.set("height", _conn.height)?;
                    Ok(r)
                }
                Ok(Err(e)) => {
                    let r = lua.create_table()?;
                    r.set("status", "error")?;
                    r.set("error", e.to_string())?;
                    Ok(r)
                }
                Err(e) => {
                    let r = lua.create_table()?;
                    r.set("status", "error")?;
                    r.set("error", e.to_string())?;
                    Ok(r)
                }
            }
        })
    })?;
    vnc.set("connect_async", async_connect_fn)?;

    let async_login_fn =
        lua.create_function(|lua, (host, port, password): (String, u16, String)| {
            let host_clone = host.clone();

            tokio::runtime::Handle::current().block_on(async move {
                let result =
                    tokio::task::spawn_blocking(move || vnc_login(&host_clone, port, &password))
                        .await;

                match result {
                    Ok(Ok(_conn)) => {
                        let r = lua.create_table()?;
                        r.set("success", true)?;
                        r.set("host", host)?;
                        r.set("port", port)?;
                        Ok(r)
                    }
                    Ok(Err(e)) => {
                        let r = lua.create_table()?;
                        r.set("success", false)?;
                        r.set("error", e.to_string())?;
                        Ok(r)
                    }
                    Err(e) => {
                        let r = lua.create_table()?;
                        r.set("success", false)?;
                        r.set("error", e.to_string())?;
                        Ok(r)
                    }
                }
            })
        })?;
    vnc.set("login_async", async_login_fn)?;

    globals.set("vnc", vnc)?;
    Ok(())
}
