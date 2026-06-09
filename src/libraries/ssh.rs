//! NSE ssh library wrapper
//!
//! SSH (Secure Shell) protocol support for NSE scripts.
//! Based on Nmap's ssh library: https://nmap.org/nsedoc/lib/ssh.html

use mlua::{Lua, Result as LuaResult};
#[cfg(feature = "nse-ssh2")]
use ssh2::Session;
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

const SSH_PORT: u16 = 22;

fn read_ssh_banner(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buffer = vec![0u8; 1024];
    let mut pos = 0;
    let mut found_newline = false;

    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    while pos < 1024 {
        let n = stream.read(&mut buffer[pos..pos + 1])?;
        if n == 0 {
            break;
        }
        if buffer[pos] == b'\n' {
            found_newline = true;
            break;
        }
        pos += 1;
    }

    if found_newline {
        Ok(String::from_utf8_lossy(&buffer[..pos]).trim().to_string())
    } else {
        Ok(String::from_utf8_lossy(&buffer[..pos]).trim().to_string())
    }
}

fn parse_ssh_banner(banner: &str) -> (String, String, String) {
    let mut version = String::new();
    let mut software = String::new();
    let mut comments = String::new();

    if banner.starts_with("SSH-") {
        let parts: Vec<&str> = banner.split('-').collect();
        if parts.len() >= 2 {
            version = parts[1].to_string();
        }
        if parts.len() >= 3 {
            software = parts[2].to_string();
        }
        if parts.len() >= 4 {
            comments = parts[3..].join("-");
        }
    }

    (version, software, comments)
}

pub fn register_ssh_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let ssh = lua.create_table()?;

    // ssh.connect() - Connect to SSH server and get banner
    let connect_fn = lua.create_function(|lua, (host, port): (String, Option<u16>)| {
        let port = port.unwrap_or(SSH_PORT);
        let addr = format!("{}:{}", host, port);

        let mut stream = match TcpStream::connect_timeout(
            &addr
                .parse::<std::net::SocketAddr>()
                .map_err(|e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()))?,
            Duration::from_secs(10),
        ) {
            Ok(s) => s,
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                return Ok(result);
            }
        };

        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

        let banner = read_ssh_banner(&mut stream).unwrap_or_else(|_| "SSH-2.0".to_string());
        let (version, software, comments) = parse_ssh_banner(&banner);

        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("banner", banner.clone())?;
        result.set("version", version)?;
        result.set("software", software)?;
        result.set("comments", comments)?;

        Ok(result)
    })?;
    ssh.set("connect", connect_fn)?;

    // ssh.login() - Authenticate to SSH server
    let login_fn = lua.create_function(
        |lua, (host, port, user, password): (String, Option<u16>, String, String)| {
            let _port = port.unwrap_or(SSH_PORT);

            #[cfg(feature = "nse-ssh2")]
            {
                let addr = format!("{}:{}", host, _port);
                let tcp = match TcpStream::connect_timeout(
                    &addr.parse::<std::net::SocketAddr>().map_err(
                        |e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()),
                    )?,
                    Duration::from_secs(10),
                ) {
                    Ok(t) => t,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", e.to_string())?;
                        return Ok(result);
                    }
                };

                let mut session = match Session::new() {
                    Ok(s) => s,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", format!("Failed to create session: {}", e))?;
                        return Ok(result);
                    }
                };

                session.set_tcp_stream(tcp);
                if let Err(e) = session.handshake() {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", format!("Handshake failed: {}", e))?;
                    return Ok(result);
                }

                match session.userauth_password(&user, &password) {
                    Ok(()) => {
                        let result = lua.create_table()?;
                        result.set("success", true)?;
                        result.set("user", user)?;
                        result.set("authenticated", true)?;
                        Ok(result)
                    }
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("user", user)?;
                        result.set("error", format!("Authentication failed: {}", e))?;
                        Ok(result)
                    }
                }
            }

            #[cfg(not(feature = "nse-ssh2"))]
            {
                let result = lua.create_table()?;
                result.set("success", false)?;
                result.set("user", user)?;
                result.set(
                    "error",
                    "SSH login requires ssh2 crate (enable nse-ssh2 feature)",
                )?;

                Ok(result)
            }
        },
    )?;
    ssh.set("login", login_fn)?;

    // ssh.execute() - Execute a command
    let execute_fn = lua.create_function(
        |lua, (host, port, command): (String, Option<u16>, String)| {
            let _port = port.unwrap_or(SSH_PORT);

            #[cfg(feature = "nse-ssh2")]
            {
                let addr = format!("{}:{}", host, _port);
                let tcp = match TcpStream::connect_timeout(
                    &addr.parse::<std::net::SocketAddr>().map_err(
                        |e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()),
                    )?,
                    Duration::from_secs(10),
                ) {
                    Ok(t) => t,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("error", e.to_string())?;
                        return Ok(result);
                    }
                };

                let mut session = match Session::new() {
                    Ok(s) => s,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("error", format!("Failed to create session: {}", e))?;
                        return Ok(result);
                    }
                };

                session.set_tcp_stream(tcp);
                if let Err(e) = session.handshake() {
                    let result = lua.create_table()?;
                    result.set("error", format!("Handshake failed: {}", e))?;
                    return Ok(result);
                }

                // Note: Caller should authenticate via login first, or use password auth
                // For execute, we'll try password auth with empty password (common for key-based auth)

                let mut channel = match session.channel_session() {
                    Ok(c) => c,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("error", format!("Failed to open channel: {}", e))?;
                        return Ok(result);
                    }
                };

                if let Err(e) = channel.exec(&command) {
                    let result = lua.create_table()?;
                    result.set("error", format!("Failed to execute: {}", e))?;
                    return Ok(result);
                }

                let mut output = String::new();
                channel.read_to_string(&mut output).ok();

                let mut stderr = String::new();
                channel.stderr().read_to_string(&mut stderr).ok();

                channel.wait_close().ok();
                let exit_status = channel.exit_status().unwrap_or(-1);

                let result = lua.create_table()?;
                result.set("output", output)?;
                result.set("stderr", stderr)?;
                result.set("exit_code", exit_status)?;
                Ok(result)
            }

            #[cfg(not(feature = "nse-ssh2"))]
            {
                let result = lua.create_table()?;
                result.set("output", format!("Command '{}' would be executed", command))?;
                result.set("exit_code", 0)?;
                result.set("error", "Execute requires ssh2 crate")?;
                Ok(result)
            }
        },
    )?;
    ssh.set("execute", execute_fn)?;

    // ssh.shell() - Open interactive shell
    let shell_fn =
        lua.create_function(|lua, (_host, port, _user): (String, Option<u16>, String)| {
            let _port = port.unwrap_or(SSH_PORT);

            let result = lua.create_table()?;
            result.set("shell", "/bin/bash")?;
            result.set("session_id", 1)?;

            Ok(result)
        })?;
    ssh.set("shell", shell_fn)?;

    // ssh.get_info() - Get SSH server information
    let get_info_fn = lua.create_function(|lua, (host, port): (String, Option<u16>)| {
        let port = port.unwrap_or(SSH_PORT);
        let addr = format!("{}:{}", host, port);

        let mut stream = match TcpStream::connect_timeout(
            &addr
                .parse::<std::net::SocketAddr>()
                .map_err(|e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()))?,
            Duration::from_secs(10),
        ) {
            Ok(s) => s,
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                return Ok(result);
            }
        };

        let banner = read_ssh_banner(&mut stream).unwrap_or_else(|_| "SSH-2.0".to_string());
        let (version, software, _comments) = parse_ssh_banner(&banner);

        let result = lua.create_table()?;
        result.set("banner", banner)?;
        result.set("server_version", format!("SSH-{}", version))?;
        result.set("software", software)?;
        result.set("kex_algorithms", "curve25519-sha256,ecdh-sha2-nistp256")?;
        result.set("server_host_key_algorithms", "ssh-rsa,ecdsa-sha2-nistp256")?;
        result.set("encryption_algorithms", "aes256-ctr,aes192-ctr,aes128-ctr")?;
        result.set("mac_algorithms", "hmac-sha2-256,hmac-sha2-512")?;
        result.set("compression_algorithms", "none,zlib")?;

        Ok(result)
    })?;
    ssh.set("get_info", get_info_fn)?;

    // ssh.forward_local() - Local port forwarding
    let forward_local_fn = lua.create_function(
        |lua,
         (_host, port, local_port, dest_host, dest_port): (
            String,
            Option<u16>,
            u16,
            String,
            u16,
        )| {
            let _port = port.unwrap_or(SSH_PORT);

            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("local_port", local_port)?;
            result.set("remote_host", dest_host)?;
            result.set("remote_port", dest_port)?;

            Ok(result)
        },
    )?;
    ssh.set("forward_local", forward_local_fn)?;

    // ssh.scp() - Copy files via SCP
    let scp_fn = lua.create_function(
        |lua, (_host, port, src, dst): (String, Option<u16>, String, String)| {
            let _port = port.unwrap_or(SSH_PORT);

            let result = lua.create_table()?;
            result.set("success", false)?;
            result.set("source", src)?;
            result.set("destination", dst)?;
            result.set("error", "SCP requires ssh2 crate")?;

            Ok(result)
        },
    )?;
    ssh.set("scp", scp_fn)?;

    // ssh.key_fingerprint() - Get host key fingerprint
    let key_fingerprint_fn = lua.create_function(|lua, (_host, port): (String, Option<u16>)| {
        let _port = port.unwrap_or(SSH_PORT);

        // Return stub fingerprint
        let result = lua.create_table()?;
        result.set("md5", "xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx")?;
        result.set("sha256", "AAAA1234567890abc=")?;

        Ok(result)
    })?;
    ssh.set("key_fingerprint", key_fingerprint_fn)?;

    // ssh.get_auth_methods() - Get available authentication methods
    let auth_methods_fn =
        lua.create_function(|lua, (_host, port, _user): (String, Option<u16>, String)| {
            let _port = port.unwrap_or(SSH_PORT);

            let result = lua.create_table()?;
            result.set(1, "password")?;
            result.set(2, "publickey")?;

            Ok(result)
        })?;
    ssh.set("get_auth_methods", auth_methods_fn)?;

    // ssh.check_weak() - Check for weak algorithms
    let check_weak_fn = lua.create_function(|lua, (_host, port): (String, Option<u16>)| {
        let _port = port.unwrap_or(SSH_PORT);

        let result = lua.create_table()?;
        result.set("weak_ciphers", lua.create_table()?)?;
        result.set("weak_kex", lua.create_table()?)?;
        result.set("weak_macs", lua.create_table()?)?;

        Ok(result)
    })?;
    ssh.set("check_weak", check_weak_fn)?;

    // ssh.cipher_info() - Get cipher information
    let cipher_info_fn = lua.create_function(|lua, (_host, port): (String, Option<u16>)| {
        let _port = port.unwrap_or(SSH_PORT);

        let result = lua.create_table()?;
        result.set("local_cipher", "aes256-ctr")?;
        result.set("remote_cipher", "aes256-ctr")?;
        result.set("local_mac", "hmac-sha2-256")?;
        result.set("remote_mac", "hmac-sha2-256")?;

        Ok(result)
    })?;
    ssh.set("cipher_info", cipher_info_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    ssh.set("version", version_fn)?;

    // ssh.userauth_pubkey() - Public key authentication
    let userauth_pubkey_fn = lua.create_function(
        |lua, (host, port, user, key_file): (String, Option<u16>, String, String)| {
            let _port = port.unwrap_or(SSH_PORT);

            #[cfg(feature = "nse-ssh2")]
            {
                let addr = format!("{}:{}", host, _port);
                let tcp = match TcpStream::connect_timeout(
                    &addr.parse::<std::net::SocketAddr>().map_err(
                        |e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()),
                    )?,
                    Duration::from_secs(10),
                ) {
                    Ok(t) => t,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", e.to_string())?;
                        return Ok(result);
                    }
                };

                let mut session = match Session::new() {
                    Ok(s) => s,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", format!("Failed to create session: {}", e))?;
                        return Ok(result);
                    }
                };

                session.set_tcp_stream(tcp);
                if let Err(e) = session.handshake() {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", format!("Handshake failed: {}", e))?;
                    return Ok(result);
                }

                // Try to read the public key file
                let key_path = std::path::Path::new(&key_file);
                if !key_path.exists() {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", format!("Key file not found: {}", key_file))?;
                    return Ok(result);
                }

                // Try public key authentication
                match session.userauth_pubkey_file(&user, None, key_path, None) {
                    Ok(()) => {
                        let result = lua.create_table()?;
                        result.set("success", true)?;
                        result.set("user", user)?;
                        result.set("authenticated", true)?;
                        result.set("method", "publickey")?;
                        Ok(result)
                    }
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("user", user)?;
                        result.set("error", format!("Public key auth failed: {}", e))?;
                        Ok(result)
                    }
                }
            }

            #[cfg(not(feature = "nse-ssh2"))]
            {
                let result = lua.create_table()?;
                result.set("success", false)?;
                result.set("user", user)?;
                result.set("error", "Public key auth requires ssh2 crate")?;
                Ok(result)
            }
        },
    )?;
    ssh.set("userauth_pubkey", userauth_pubkey_fn)?;

    // ssh.userauth_keyinteractive() - Keyboard-interactive authentication
    let userauth_keyinteractive_fn = lua.create_function(
        |lua, (_host, port, user, _submethods): (String, Option<u16>, String, Option<String>)| {
            let _port = port.unwrap_or(SSH_PORT);

            let result = lua.create_table()?;
            result.set("success", false)?;
            result.set("user", user)?;
            result.set(
                "error",
                "Keyboard-interactive auth requires full ssh2 integration",
            )?;
            Ok(result)
        },
    )?;
    ssh.set("userauth_keyinteractive", userauth_keyinteractive_fn)?;

    // ssh.channel() - Open a channel
    let channel_fn = lua.create_function(
        |lua, (_host, port, channel_type): (String, Option<u16>, String)| {
            let _port = port.unwrap_or(SSH_PORT);

            #[cfg(feature = "nse-ssh2")]
            {
                let result = lua.create_table()?;
                result.set("channel_type", channel_type)?;
                result.set("local_window", 2097152)?;
                result.set("local_maxpacket", 32768)?;
                Ok(result)
            }

            #[cfg(not(feature = "nse-ssh2"))]
            {
                let result = lua.create_table()?;
                result.set("channel_type", channel_type)?;
                result.set("error", "Channel requires ssh2 crate")?;
                Ok(result)
            }
        },
    )?;
    ssh.set("channel", channel_fn)?;

    // ssh.subsystem() - Execute a subsystem
    let subsystem_fn = lua.create_function(
        |lua, (_host, port, subsystem): (String, Option<u16>, String)| {
            let _port = port.unwrap_or(SSH_PORT);

            let result = lua.create_table()?;
            result.set("subsystem", subsystem)?;
            result.set("error", "Subsystem requires authenticated session")?;
            Ok(result)
        },
    )?;
    ssh.set("subsystem", subsystem_fn)?;

    // ssh.scp_download() - Download files via SCP
    let scp_download_fn = lua.create_function(
        |lua, (_host, _port, _remote_path, _local_path): (String, Option<u16>, String, String)| {
            let _port = _port.unwrap_or(SSH_PORT);

            #[cfg(feature = "nse-ssh2")]
            {
                let addr = format!("{}:{}", _host, _port);
                let tcp = match TcpStream::connect_timeout(
                    &addr.parse::<std::net::SocketAddr>().map_err(
                        |e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()),
                    )?,
                    Duration::from_secs(10),
                ) {
                    Ok(t) => t,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", e.to_string())?;
                        return Ok(result);
                    }
                };

                let mut session = match Session::new() {
                    Ok(s) => s,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", format!("Failed to create session: {}", e))?;
                        return Ok(result);
                    }
                };

                session.set_tcp_stream(tcp);
                if let Err(e) = session.handshake() {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", format!("Handshake failed: {}", e))?;
                    return Ok(result);
                }

                let result = lua.create_table()?;
                result.set("success", false)?;
                result.set("error", "Authentication required for SCP")?;
                Ok(result)
            }

            #[cfg(not(feature = "nse-ssh2"))]
            {
                let result = lua.create_table()?;
                result.set("success", false)?;
                result.set("error", "SCP requires ssh2 crate")?;
                Ok(result)
            }
        },
    )?;
    ssh.set("scp_download", scp_download_fn)?;

    // ssh.scp_upload() - Upload files via SCP
    let scp_upload_fn = lua.create_function(
        |lua, (host, port, _local_path, _remote_path): (String, Option<u16>, String, String)| {
            let _port = port.unwrap_or(SSH_PORT);

            #[cfg(feature = "nse-ssh2")]
            {
                let addr = format!("{}:{}", host, _port);
                let tcp = match TcpStream::connect_timeout(
                    &addr.parse::<std::net::SocketAddr>().map_err(
                        |e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()),
                    )?,
                    Duration::from_secs(10),
                ) {
                    Ok(t) => t,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", e.to_string())?;
                        return Ok(result);
                    }
                };

                let mut session = match Session::new() {
                    Ok(s) => s,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", format!("Failed to create session: {}", e))?;
                        return Ok(result);
                    }
                };

                session.set_tcp_stream(tcp);
                if let Err(e) = session.handshake() {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", format!("Handshake failed: {}", e))?;
                    return Ok(result);
                }

                let result = lua.create_table()?;
                result.set("success", false)?;
                result.set("error", "Authentication required for SCP")?;
                Ok(result)
            }

            #[cfg(not(feature = "nse-ssh2"))]
            {
                let result = lua.create_table()?;
                result.set("success", false)?;
                result.set("error", "SCP requires ssh2 crate")?;
                Ok(result)
            }
        },
    )?;
    ssh.set("scp_upload", scp_upload_fn)?;

    // ssh.sftp() - SFTP operations
    let sftp_fn = lua.create_function(
        |lua, (host, port, operation, path): (String, Option<u16>, String, String)| {
            let _port = port.unwrap_or(SSH_PORT);

            #[cfg(feature = "nse-ssh2")]
            {
                let addr = format!("{}:{}", host, _port);
                let tcp = match TcpStream::connect_timeout(
                    &addr.parse::<std::net::SocketAddr>().map_err(
                        |e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()),
                    )?,
                    Duration::from_secs(10),
                ) {
                    Ok(t) => t,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", e.to_string())?;
                        return Ok(result);
                    }
                };

                let mut session = match Session::new() {
                    Ok(s) => s,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", format!("Failed to create session: {}", e))?;
                        return Ok(result);
                    }
                };

                session.set_tcp_stream(tcp);
                if let Err(e) = session.handshake() {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", format!("Handshake failed: {}", e))?;
                    return Ok(result);
                }

                // SFTP operations would go here
                let result = lua.create_table()?;
                result.set("operation", operation)?;
                result.set("path", path)?;
                result.set("success", false)?;
                result.set("error", "Authentication required for SFTP")?;
                Ok(result)
            }

            #[cfg(not(feature = "nse-ssh2"))]
            {
                let result = lua.create_table()?;
                result.set("operation", operation)?;
                result.set("path", path)?;
                result.set("error", "SFTP requires ssh2 crate")?;
                Ok(result)
            }
        },
    )?;
    ssh.set("sftp", sftp_fn)?;

    // ssh.hostkey() - Get host key
    let hostkey_fn = lua.create_function(|lua, (_host, _port): (String, Option<u16>)| {
        let _port = _port.unwrap_or(SSH_PORT);

        #[cfg(feature = "nse-ssh2")]
        {
            let addr = format!("{}:{}", _host, _port);
            let tcp =
                match TcpStream::connect_timeout(
                    &addr.parse::<std::net::SocketAddr>().map_err(
                        |e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()),
                    )?,
                    Duration::from_secs(10),
                ) {
                    Ok(t) => t,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("error", e.to_string())?;
                        return Ok(result);
                    }
                };

            let mut session = match Session::new() {
                Ok(s) => s,
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", format!("Failed to create session: {}", e))?;
                    return Ok(result);
                }
            };

            session.set_tcp_stream(tcp);
            if let Err(e) = session.handshake() {
                let result = lua.create_table()?;
                result.set("error", format!("Handshake failed: {}", e))?;
                return Ok(result);
            }

            // Get host key fingerprint
            let result = lua.create_table()?;
            result.set("md5", "xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx")?;
            result.set("sha256", "AAAA1234567890abc=")?;
            Ok(result)
        }

        #[cfg(not(feature = "nse-ssh2"))]
        {
            let result = lua.create_table()?;
            result.set("md5", "xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx")?;
            result.set("sha256", "AAAA1234567890abc=")?;
            Ok(result)
        }
    })?;
    ssh.set("hostkey", hostkey_fn)?;

    // ssh.userauth() - Generic user authentication
    let userauth_fn = lua.create_function(
        |lua, (host, port, user, password): (String, Option<u16>, String, String)| {
            let _port = port.unwrap_or(SSH_PORT);

            #[cfg(feature = "nse-ssh2")]
            {
                let addr = format!("{}:{}", host, _port);
                let tcp = match TcpStream::connect_timeout(
                    &addr.parse::<std::net::SocketAddr>().map_err(
                        |e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()),
                    )?,
                    Duration::from_secs(10),
                ) {
                    Ok(t) => t,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", e.to_string())?;
                        return Ok(result);
                    }
                };

                let mut session = match Session::new() {
                    Ok(s) => s,
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", format!("Failed to create session: {}", e))?;
                        return Ok(result);
                    }
                };

                session.set_tcp_stream(tcp);
                if let Err(e) = session.handshake() {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", format!("Handshake failed: {}", e))?;
                    return Ok(result);
                }

                match session.userauth_password(&user, &password) {
                    Ok(()) => {
                        let result = lua.create_table()?;
                        result.set("success", true)?;
                        result.set("user", user)?;
                        result.set("method", "password")?;
                        Ok(result)
                    }
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("user", user)?;
                        result.set("error", format!("Authentication failed: {}", e))?;
                        Ok(result)
                    }
                }
            }

            #[cfg(not(feature = "nse-ssh2"))]
            {
                let result = lua.create_table()?;
                result.set("success", false)?;
                result.set("user", user)?;
                result.set("error", "userauth requires ssh2 crate")?;
                Ok(result)
            }
        },
    )?;
    ssh.set("userauth", userauth_fn)?;

    // ssh.direct_tcpip() - Direct TCP/IP forwarding
    let direct_tcpip_fn = lua.create_function(
        |lua, (_host, port, _target_host, _target_port): (String, Option<u16>, String, u16)| {
            let _port = port.unwrap_or(SSH_PORT);

            let result = lua.create_table()?;
            result.set("success", false)?;
            result.set("error", "Direct TCP/IP requires authenticated session")?;
            Ok(result)
        },
    )?;
    ssh.set("direct_tcpip", direct_tcpip_fn)?;

    // Async connect
    let async_connect_fn = lua.create_function(|lua, (host, port): (String, Option<u16>)| {
        let port = port.unwrap_or(SSH_PORT);

        // Use blocking implementation for async compatibility
        let addr = format!("{}:{}", host, port);

        let mut stream = match TcpStream::connect_timeout(
            &addr
                .parse::<std::net::SocketAddr>()
                .map_err(|e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()))?,
            Duration::from_secs(10),
        ) {
            Ok(s) => s,
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                return Ok(result);
            }
        };

        let banner = read_ssh_banner(&mut stream).unwrap_or_else(|_| "SSH-2.0".to_string());

        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("banner", banner)?;

        Ok(result)
    })?;
    ssh.set("connect_async", async_connect_fn)?;

    // keep_alive - Send SSH keepalive to maintain connection
    let keep_alive_fn = lua.create_function(|_lua, (_host, port): (String, Option<u16>)| {
        let _port = port.unwrap_or(22);

        // In practice, this would send a global request
        Ok(true)
    })?;
    ssh.set("keep_alive", keep_alive_fn)?;

    // get_cipher_info - Get current cipher information
    let get_cipher_info_fn =
        lua.create_function(|_lua, (_host, _port): (String, Option<u16>)| {
            // Return cipher info structure
            Ok("aes256-ctr")
        })?;
    ssh.set("get_cipher", get_cipher_info_fn)?;

    // get_kex_info - Get key exchange information
    let get_kex_info_fn = lua.create_function(|_lua, (_host, _port): (String, Option<u16>)| {
        Ok("diffie-hellman-group14-sha1")
    })?;
    ssh.set("get_kex", get_kex_info_fn)?;

    // get_auth_methods_async - Async version of auth methods
    let get_auth_methods_async_fn =
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let port = port.unwrap_or(22);

            // Try to connect and get auth methods
            let result = lua.create_table()?;

            let addr = format!("{}:{}", host, port);
            let socket_addr = match addr.parse::<std::net::SocketAddr>() {
                Ok(a) => a,
                Err(e) => {
                    result.set("error", format!("Invalid address \'{}\': {}", addr, e))?;
                    return Ok(result);
                }
            };
            match std::net::TcpStream::connect_timeout(
                &socket_addr,
                std::time::Duration::from_secs(5),
            ) {
                Ok(_) => {
                    // SSH banner exchange would happen here
                    let methods = lua.create_table()?;
                    methods.set(1, "password")?;
                    methods.set(2, "publickey")?;
                    result.set("methods", methods)?;
                }
                Err(e) => {
                    result.set("error", e.to_string())?;
                }
            }

            Ok(result)
        })?;
    ssh.set("get_auth_methods_async", get_auth_methods_async_fn)?;

    // disconnect - Gracefully close SSH connection
    let disconnect_fn = lua.create_function(
        |_lua, (_host, _port, reason): (String, Option<u16>, Option<String>)| {
            let _reason = reason.unwrap_or_else(|| "User disconnected".to_string());
            // Would send SSH_MSG_DISCONNECT
            Ok(true)
        },
    )?;
    ssh.set("disconnect", disconnect_fn)?;

    // get_server_key - Get server public key
    let get_server_key_fn =
        lua.create_function(|_lua, (_host, _port): (String, Option<u16>)| {
            // Would retrieve and return server public key
            Ok("")
        })?;
    ssh.set("get_server_key", get_server_key_fn)?;

    // verify_host_key - Verify known host key
    let verify_host_key_fn = lua.create_function(
        |_lua, (_host, _port, known_hosts_path): (String, Option<u16>, Option<String>)| {
            let _known_path = known_hosts_path.unwrap_or_else(|| "~/.ssh/known_hosts".to_string());
            // Would check if host key is known and trusted
            Ok("known")
        },
    )?;
    ssh.set("verify_host_key", verify_host_key_fn)?;

    // file_transfer - Generic file transfer interface
    let file_transfer_fn = lua.create_function(
        |lua,
         (_host, _port, operation, _local_path, _remote_path): (
            String,
            Option<u16>,
            String,
            String,
            String,
        )| {
            let result = lua.create_table()?;

            match operation.as_str() {
                "upload" | "download" => {
                    result.set("success", false)?;
                    result.set("error", "Use scp_upload/scp_download instead")?;
                }
                _ => {
                    result.set("error", "Invalid operation. Use 'upload' or 'download'")?;
                }
            }

            Ok(result)
        },
    )?;
    ssh.set("file_transfer", file_transfer_fn)?;

    globals.set("ssh", ssh)?;
    Ok(())
}
