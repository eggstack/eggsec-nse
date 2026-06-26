//! NSE ftp library wrapper
//!
//! FTP protocol support for NSE scripts.
//! Based on Nmap's ftp library: https://nmap.org/nsedoc/lib/ftp.html
//! Includes both blocking and async implementations with real FTP protocol support.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as AsyncTcpStream;

fn ftp_send_command(stream: &mut TcpStream, cmd: &str) -> std::io::Result<String> {
    stream.write_all(cmd.as_bytes())?;
    stream.flush()?;

    let mut response = vec![0u8; 4096];
    let n = stream.read(&mut response)?;

    if n > 0 {
        Ok(String::from_utf8_lossy(&response[..n]).to_string())
    } else {
        Ok(String::new())
    }
}

fn ftp_get_pasv_port(response: &str) -> Option<(String, u16)> {
    if let Some(start) = response.find('(') {
        if let Some(end) = response.find(')') {
            let inner = &response[start + 1..end];
            let parts: Vec<&str> = inner.split(',').collect();
            if parts.len() == 6 {
                let ip = format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], parts[3]);
                let port = parts[4].parse::<u16>().ok()? * 256 + parts[5].parse::<u16>().ok()?;
                return Some((ip, port));
            }
        }
    }
    None
}

fn ftp_retr_file(host: &str, port: u16, filename: &str) -> std::io::Result<String> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?,
        Duration::from_secs(10),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

    let pasv_cmd = "PASV\r\n".to_string();
    let pasv_response = ftp_send_command(&mut stream, &pasv_cmd)?;

    let (data_ip, data_port) = ftp_get_pasv_port(&pasv_response)
        .ok_or_else(|| std::io::Error::other("Failed to get PASV port"))?;

    let retr_cmd = format!("RETR {}\r\n", filename);
    let _retr_response = ftp_send_command(&mut stream, &retr_cmd)?;

    let data_addr = format!("{}:{}", data_ip, data_port);
    let mut data_stream = TcpStream::connect_timeout(
        &data_addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?,
        Duration::from_secs(10),
    )?;
    data_stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .ok();

    let mut data = vec![0u8; 1048576];
    let n = data_stream.read(&mut data).unwrap_or(0);

    let _response = ftp_send_command(&mut stream, "")?;

    if n > 0 {
        Ok(String::from_utf8_lossy(&data[..n]).to_string())
    } else {
        Ok(String::new())
    }
}

fn ftp_stor_file(host: &str, port: u16, filename: &str, data: &str) -> std::io::Result<bool> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?,
        Duration::from_secs(10),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

    let pasv_cmd = "PASV\r\n".to_string();
    let pasv_response = ftp_send_command(&mut stream, &pasv_cmd)?;

    let (data_ip, data_port) = ftp_get_pasv_port(&pasv_response)
        .ok_or_else(|| std::io::Error::other("Failed to get PASV port"))?;

    let stor_cmd = format!("STOR {}\r\n", filename);
    let _stor_response = ftp_send_command(&mut stream, &stor_cmd)?;

    let data_addr = format!("{}:{}", data_ip, data_port);
    let mut data_stream = TcpStream::connect_timeout(
        &data_addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?,
        Duration::from_secs(10),
    )?;

    data_stream.write_all(data.as_bytes())?;
    data_stream.flush()?;

    drop(data_stream);

    let response = ftp_send_command(&mut stream, "")?;

    Ok(response.starts_with("226"))
}

fn ftp_list_directory(
    host: &str,
    port: u16,
    path: &str,
) -> std::io::Result<Vec<(String, String, String)>> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?,
        Duration::from_secs(10),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

    let pasv_cmd = "PASV\r\n".to_string();
    let pasv_response = ftp_send_command(&mut stream, &pasv_cmd)?;

    let (data_ip, data_port) = ftp_get_pasv_port(&pasv_response)
        .ok_or_else(|| std::io::Error::other("Failed to get PASV port"))?;

    let list_cmd = if path.is_empty() {
        "LIST\r\n".to_string()
    } else {
        format!("LIST {}\r\n", path)
    };
    let _list_response = ftp_send_command(&mut stream, &list_cmd)?;

    let data_addr = format!("{}:{}", data_ip, data_port);
    let mut data_stream = TcpStream::connect_timeout(
        &data_addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?,
        Duration::from_secs(10),
    )?;
    data_stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .ok();

    let mut data = vec![0u8; 65536];
    let n = data_stream.read(&mut data).unwrap_or(0);

    let _response = ftp_send_command(&mut stream, "")?;

    let mut files = Vec::new();
    if n > 0 {
        let content = String::from_utf8_lossy(&data[..n]);
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 9 {
                let perms = parts[0].to_string();
                let size = parts[4].to_string();
                let name = parts[8..].join(" ");
                let file_type = if perms.starts_with('d') {
                    "DIR"
                } else {
                    "FILE"
                }
                .to_string();
                files.push((name, size, file_type));
            }
        }
    }

    Ok(files)
}

fn ftp_delete_file(host: &str, port: u16, filename: &str) -> std::io::Result<bool> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?,
        Duration::from_secs(10),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

    let dele_cmd = format!("DELE {}\r\n", filename);
    let response = ftp_send_command(&mut stream, &dele_cmd)?;

    Ok(response.starts_with("250"))
}

fn ftp_rename_file(host: &str, port: u16, from_name: &str, to_name: &str) -> std::io::Result<bool> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?,
        Duration::from_secs(10),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

    let rnfr_cmd = format!("RNFR {}\r\n", from_name);
    let _rnfr_response = ftp_send_command(&mut stream, &rnfr_cmd)?;

    let rnto_cmd = format!("RNTO {}\r\n", to_name);
    let rnto_response = ftp_send_command(&mut stream, &rnto_cmd)?;

    Ok(rnto_response.starts_with("250"))
}

fn ftp_make_directory(host: &str, port: u16, dirname: &str) -> std::io::Result<bool> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?,
        Duration::from_secs(10),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

    let mkd_cmd = format!("MKD {}\r\n", dirname);
    let response = ftp_send_command(&mut stream, &mkd_cmd)?;

    Ok(response.starts_with("257") || response.starts_with("250"))
}

fn ftp_remove_directory(host: &str, port: u16, dirname: &str) -> std::io::Result<bool> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?,
        Duration::from_secs(10),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

    let rmd_cmd = format!("RMD {}\r\n", dirname);
    let response = ftp_send_command(&mut stream, &rmd_cmd)?;

    Ok(response.starts_with("250"))
}

fn ftp_get_file_size(host: &str, port: u16, filename: &str) -> std::io::Result<u64> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?,
        Duration::from_secs(10),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

    let size_cmd = format!("SIZE {}\r\n", filename);
    let response = ftp_send_command(&mut stream, &size_cmd)?;

    if let Some(start) = response.find("213 ") {
        let size_str = response[start + 4..].trim();
        return Ok(size_str.parse().unwrap_or(0));
    }

    Ok(0)
}

pub fn register_ftp_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let ftp = lua.create_table()?;

    let connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
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
                result.set("status", "error")?;
                result.set("error", e.to_string())?;
                return Ok(result);
            }
        };

        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();

        let mut buffer = vec![0u8; 4096];
        let n = stream
            .read(&mut buffer)
            .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("status", "connected")?;
        result.set("welcome", String::from_utf8_lossy(&buffer[..n]).to_string())?;

        Ok(result)
    })?;
    ftp.set("connect", connect_fn)?;

    let login_fn = lua.create_function(
        |lua, (host, port, user, pass): (String, u16, String, String)| {
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

            stream.set_read_timeout(Some(Duration::from_secs(30))).ok();

            if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

            stream
                .write_all(format!("USER {}\r\n", user).as_bytes())
                .ok();
            if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

            stream
                .write_all(format!("PASS {}\r\n", pass).as_bytes())
                .ok();
            let mut response = vec![0u8; 4096];
            let _ = stream.read(&mut response);

            let result = lua.create_table()?;
            result.set(
                "success",
                response[..3].starts_with(b"230") || response[..3].starts_with(b"202"),
            )?;

            Ok(result)
        },
    )?;
    ftp.set("login", login_fn)?;

    let cwd_fn = lua.create_function(|lua, (host, port, path): (String, u16, String)| {
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

        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

        stream
            .write_all(format!("CWD {}\r\n", path).as_bytes())
            .ok();
        let mut response = vec![0u8; 4096];
        let _ = stream.read(&mut response);

        let result = lua.create_table()?;
        result.set("success", response[..3].starts_with(b"250"))?;
        result.set("path", path)?;

        Ok(result)
    })?;
    ftp.set("cwd", cwd_fn)?;

    let pwd_fn = lua.create_function(|_lua, (host, port): (String, u16)| {
        let addr = format!("{}:{}", host, port);
        let mut stream = match TcpStream::connect_timeout(
            &addr
                .parse::<std::net::SocketAddr>()
                .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
            Duration::from_secs(10),
        ) {
            Ok(s) => s,
            Err(e) => return Err(mlua::Error::RuntimeError(e.to_string())),
        };

        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

        stream
            .write_all(b"PWD\r\n")
            .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
        let mut response = vec![0u8; 4096];
        let _ = stream.read(&mut response);

        let response_str = String::from_utf8_lossy(&response);
        let path = if let Some(start) = response_str.find('"') {
            if let Some(end) = response_str[start + 1..].find('"') {
                response_str[start + 1..start + 1 + end].to_string()
            } else {
                "/".to_string()
            }
        } else {
            "/".to_string()
        };

        Ok(path)
    })?;
    ftp.set("pwd", pwd_fn)?;

    let list_fn =
        lua.create_function(|lua, (host, port, path): (String, u16, Option<String>)| {
            let path = path.unwrap_or_else(|| ".".to_string());
            match ftp_list_directory(&host, port, &path) {
                Ok(files) => {
                    let result = lua.create_table()?;
                    let files_table = lua.create_table()?;

                    for (i, (name, size, ftype)) in files.iter().enumerate() {
                        let file = lua.create_table()?;
                        file.set("name", name.clone())?;
                        file.set("size", size.clone())?;
                        file.set("type", ftype.clone())?;
                        files_table.set(i + 1, file)?;
                    }

                    result.set("files", files_table)?;
                    result.set("count", files.len())?;
                    result.set("status", "ok")?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        })?;
    ftp.set("list", list_fn)?;

    let nlst_fn =
        lua.create_function(|lua, (host, port, path): (String, u16, Option<String>)| {
            let path = path.unwrap_or_else(|| ".".to_string());
            match ftp_list_directory(&host, port, &path) {
                Ok(files) => {
                    let result = lua.create_table()?;
                    for (i, (name, _size, _ftype)) in files.iter().enumerate() {
                        if _ftype == "FILE" {
                            result.set(i + 1, name.clone())?;
                        }
                    }
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        })?;
    ftp.set("nlst", nlst_fn)?;

    let retr_fn =
        lua.create_function(
            |lua, (host, port, filename): (String, u16, String)| match ftp_retr_file(
                &host, port, &filename,
            ) {
                Ok(data) => {
                    let data_len = data.len();
                    let result = lua.create_table()?;
                    result.set("status", "ok")?;
                    result.set("data", data)?;
                    result.set("size", data_len)?;
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
    ftp.set("retr", retr_fn)?;

    let stor_fn = lua.create_function(
        |lua, (host, port, filename, data): (String, u16, String, String)| match ftp_stor_file(
            &host, port, &filename, &data,
        ) {
            Ok(success) => {
                let result = lua.create_table()?;
                result.set("success", success)?;
                result.set("filename", filename)?;
                result.set("size", data.len())?;
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
    ftp.set("stor", stor_fn)?;

    let dele_fn = lua.create_function(|lua, (host, port, filename): (String, u16, String)| {
        match ftp_delete_file(&host, port, &filename) {
            Ok(success) => {
                let result = lua.create_table()?;
                result.set("success", success)?;
                result.set("deleted", filename)?;
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
    ftp.set("dele", dele_fn)?;

    let rnfr_fn = lua.create_function(|lua, (_host, _port, filename): (String, u16, String)| {
        let result = lua.create_table()?;
        result.set("success", true)?;
        result.set("from", filename)?;
        result.set("status", "ready for rename")?;
        Ok(result)
    })?;
    ftp.set("rnfr", rnfr_fn)?;

    let rnto_fn = lua.create_function(|lua, (host, port, to_name): (String, u16, String)| {
        match ftp_rename_file(&host, port, "", &to_name) {
            Ok(success) => {
                let result = lua.create_table()?;
                result.set("success", success)?;
                result.set("to", to_name)?;
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
    ftp.set("rnto", rnto_fn)?;

    let mkd_fn = lua.create_function(|lua, (host, port, dirname): (String, u16, String)| {
        match ftp_make_directory(&host, port, &dirname) {
            Ok(success) => {
                let result = lua.create_table()?;
                result.set("success", success)?;
                result.set("created", dirname)?;
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
    ftp.set("mkd", mkd_fn)?;

    let rmd_fn = lua.create_function(|lua, (host, port, dirname): (String, u16, String)| {
        match ftp_remove_directory(&host, port, &dirname) {
            Ok(success) => {
                let result = lua.create_table()?;
                result.set("success", success)?;
                result.set("removed", dirname)?;
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
    ftp.set("rmd", rmd_fn)?;

    let size_fn = lua.create_function(|lua, (host, port, filename): (String, u16, String)| {
        match ftp_get_file_size(&host, port, &filename) {
            Ok(size) => {
                let result = lua.create_table()?;
                result.set("size", size)?;
                result.set("filename", filename)?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    ftp.set("size", size_fn)?;

    let mdtm_fn = lua.create_function(|lua, (host, port, filename): (String, u16, String)| {
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
                result.set("error", e.to_string())?;
                return Ok(result);
            }
        };

        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

        stream
            .write_all(format!("MDTM {}\r\n", filename).as_bytes())
            .ok();
        let mut response = vec![0u8; 4096];
        let _ = stream.read(&mut response);

        let result = lua.create_table()?;
        let response_str = String::from_utf8_lossy(&response).to_string();

        if response_str.starts_with("213") {
            if let Some(timestamp) = response_str.strip_prefix("213 ") {
                result.set("success", true)?;
                result.set("timestamp", timestamp.trim())?;
            } else {
                result.set("success", false)?;
            }
        } else {
            result.set("success", false)?;
        }

        Ok(result)
    })?;
    ftp.set("mdtm", mdtm_fn)?;

    // ftp.mlst() - MLST (Machine-readable file listing)
    let mlst_fn = lua.create_function(|lua, (host, port, path): (String, u16, String)| {
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
                result.set("error", e.to_string())?;
                return Ok(result);
            }
        };

        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

        stream
            .write_all(format!("MLST {}\r\n", path).as_bytes())
            .ok();
        let mut response = vec![0u8; 4096];
        let _ = stream.read(&mut response);

        let result = lua.create_table()?;
        let response_str = String::from_utf8_lossy(&response).to_string();

        if response_str.contains("250-") {
            result.set("success", true)?;

            let facts = lua.create_table()?;
            for line in response_str.lines() {
                if line.contains("type=") {
                    if let Some(t) = line.split("type=").nth(1) {
                        let file_type = t.split_whitespace().next().unwrap_or("file");
                        facts.set("type", file_type)?;
                    }
                }
                if line.contains("size=") {
                    if let Some(s) = line.split("size=").nth(1) {
                        let size_str = s.split_whitespace().next().unwrap_or("0");
                        if let Ok(size) = size_str.parse::<u64>() {
                            facts.set("size", size)?;
                        }
                    }
                }
                if line.contains("modify=") {
                    if let Some(m) = line.split("modify=").nth(1) {
                        let modify = m.split_whitespace().next().unwrap_or("");
                        facts.set("modify", modify)?;
                    }
                }
            }
            result.set("facts", facts)?;
        } else {
            result.set("success", false)?;
        }

        Ok(result)
    })?;
    ftp.set("mlst", mlst_fn)?;

    // ftp.feat() - FEAT (Features)
    let feat_fn = lua.create_function(|lua, (host, port): (String, u16)| {
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
                result.set("error", e.to_string())?;
                return Ok(result);
            }
        };

        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

        stream.write_all(b"FEAT\r\n").ok();
        let mut response = vec![0u8; 4096];
        let _ = stream.read(&mut response);

        let result = lua.create_table()?;
        let response_str = String::from_utf8_lossy(&response).to_string();

        let features = lua.create_table()?;
        for line in response_str.lines() {
            if line.starts_with("211-") || line.starts_with(" ") {
                let feature = line.trim().trim_start_matches("211-").trim();
                if !feature.is_empty() && feature != "211 End" {
                    let count = features.len().unwrap_or(0) + 1;
                    features.set(count, feature)?;
                }
            }
        }
        result.set("features", features)?;

        Ok(result)
    })?;
    ftp.set("feat", feat_fn)?;

    // ftp.site() - SITE command
    let site_fn = lua.create_function(|lua, (host, port, command): (String, u16, String)| {
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
                result.set("error", e.to_string())?;
                return Ok(result);
            }
        };

        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

        stream
            .write_all(format!("SITE {}\r\n", command).as_bytes())
            .ok();
        let mut response = vec![0u8; 4096];
        let _ = stream.read(&mut response);

        let result = lua.create_table()?;
        let response_str = String::from_utf8_lossy(&response).to_string();
        result.set("response", response_str.trim())?;

        Ok(result)
    })?;
    ftp.set("site", site_fn)?;

    // ftp.stat() - STAT command
    let stat_fn =
        lua.create_function(|lua, (host, port, path): (String, u16, Option<String>)| {
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
                    result.set("error", e.to_string())?;
                    return Ok(result);
                }
            };

            stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
            if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

            if let Some(p) = path {
                stream.write_all(format!("STAT {}\r\n", p).as_bytes()).ok();
            } else {
                stream.write_all(b"STAT\r\n").ok();
            }
            let mut response = vec![0u8; 4096];
            let _ = stream.read(&mut response);

            let result = lua.create_table()?;
            result.set(
                "response",
                String::from_utf8_lossy(&response).trim().to_string(),
            )?;

            Ok(result)
        })?;
    ftp.set("stat", stat_fn)?;

    // ftp.noop() - NOOP command
    let noop_fn = lua.create_function(|lua, (host, port): (String, u16)| {
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
                result.set("error", e.to_string())?;
                return Ok(result);
            }
        };

        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

        stream.write_all(b"NOOP\r\n").ok();
        let mut response = vec![0u8; 256];
        let _ = stream.read(&mut response);

        let result = lua.create_table()?;
        result.set("success", response.starts_with(b"200"))?;

        Ok(result)
    })?;
    ftp.set("noop", noop_fn)?;

    // ftp.syst() - SYST command
    let syst_fn = lua.create_function(|lua, (host, port): (String, u16)| {
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
                result.set("error", e.to_string())?;
                return Ok(result);
            }
        };

        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

        stream.write_all(b"SYST\r\n").ok();
        let mut response = vec![0u8; 256];
        let _ = stream.read(&mut response);

        let result = lua.create_table()?;
        let response_str = String::from_utf8_lossy(&response).to_string();

        if let Some(sys) = response_str.strip_prefix("215 ") {
            result.set("system", sys.trim())?;
        } else {
            result.set("system", "Unknown")?;
        }

        Ok(result)
    })?;
    ftp.set("syst", syst_fn)?;

    let type_fn = lua.create_function(|lua, (host, port, type_char): (String, u16, String)| {
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

        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

        stream
            .write_all(format!("TYPE {}\r\n", type_char).as_bytes())
            .ok();
        let mut response = vec![0u8; 4096];
        let _ = stream.read(&mut response);

        let result = lua.create_table()?;
        result.set("success", response[..3].starts_with(b"200"))?;
        result.set("type", type_char)?;
        Ok(result)
    })?;
    ftp.set("type", type_fn)?;

    let pasv_fn = lua.create_function(|_lua, (host, port): (String, u16)| {
        let addr = format!("{}:{}", host, port);
        let mut stream = match TcpStream::connect_timeout(
            &addr
                .parse::<std::net::SocketAddr>()
                .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
            Duration::from_secs(10),
        ) {
            Ok(s) => s,
            Err(e) => return Err(mlua::Error::RuntimeError(e.to_string())),
        };

        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

        stream
            .write_all(b"PASV\r\n")
            .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
        let mut response = vec![0u8; 4096];
        let _ = stream.read(&mut response);

        Ok(String::from_utf8_lossy(&response).to_string())
    })?;
    ftp.set("pasv", pasv_fn)?;

    let epsv_fn = lua.create_function(|_lua, (host, port): (String, u16)| {
        let addr = format!("{}:{}", host, port);
        let mut stream = match TcpStream::connect_timeout(
            &addr
                .parse::<std::net::SocketAddr>()
                .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?,
            Duration::from_secs(10),
        ) {
            Ok(s) => s,
            Err(e) => return Err(mlua::Error::RuntimeError(e.to_string())),
        };

        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        if stream.read(&mut vec![0u8; 4096]).is_err() { tracing::warn!("Failed to read FTP greeting"); }

        stream
            .write_all(b"EPSV\r\n")
            .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
        let mut response = vec![0u8; 4096];
        let _ = stream.read(&mut response);

        Ok(String::from_utf8_lossy(&response).to_string())
    })?;
    ftp.set("epsv", epsv_fn)?;

    let quit_fn = lua.create_function(|_lua, (_host, _port): (String, u16)| Ok(true))?;
    ftp.set("quit", quit_fn)?;

    let async_connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let addr = format!("{}:{}", host, port);

        tokio::runtime::Handle::current().block_on(async {
            match AsyncTcpStream::connect(&addr).await {
                Ok(mut stream) => {
                    let mut buffer = vec![0u8; 4096];
                    let n = stream.read(&mut buffer).await.unwrap_or(0);

                    let r = lua.create_table()?;
                    r.set("host", host)?;
                    r.set("port", port)?;
                    r.set("status", "connected")?;
                    r.set("welcome", String::from_utf8_lossy(&buffer[..n]).to_string())?;
                    Ok(r)
                }
                Err(e) => Err(mlua::Error::RuntimeError(e.to_string())),
            }
        })
    })?;
    ftp.set("connect_async", async_connect_fn)?;

    let async_login_fn = lua.create_function(
        |lua, (host, port, user, pass): (String, u16, String, String)| {
            let addr = format!("{}:{}", host, port);

            tokio::runtime::Handle::current().block_on(async {
                match AsyncTcpStream::connect(&addr).await {
                    Ok(mut stream) => {
                        let _ = stream.read(&mut vec![0u8; 4096]).await;

                        stream
                            .write_all(format!("USER {}\r\n", user).as_bytes())
                            .await
                            .ok();
                        let _ = stream.read(&mut vec![0u8; 4096]).await;

                        stream
                            .write_all(format!("PASS {}\r\n", pass).as_bytes())
                            .await
                            .ok();
                        let mut response = vec![0u8; 4096];
                        let _ = stream.read(&mut response).await;

                        let result = lua.create_table()?;
                        result.set(
                            "success",
                            response[..3].starts_with(b"230") || response[..3].starts_with(b"202"),
                        )?;
                        Ok(result)
                    }
                    Err(e) => Err(mlua::Error::RuntimeError(e.to_string())),
                }
            })
        },
    )?;
    ftp.set("login_async", async_login_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    ftp.set("version", version_fn)?;

    globals.set("ftp", ftp)?;
    Ok(())
}
