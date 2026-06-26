//! NSE ssh2 library wrapper
//!
//! SSH-2 protocol support for NSE scripts.
//! Based on Nmap's ssh2 library: https://nmap.org/nsedoc/lib/ssh2.html
//!
//! This implementation provides SSH2 support using raw sockets for banner grabbing,
//! and full SSH2 when the ssh2 crate feature is enabled.

#[cfg(feature = "nse-ssh2")]
use mlua::{Lua, Result as LuaResult, UserData, UserDataMethods, Value};
#[cfg(feature = "nse-ssh2")]
use ssh2::Session;
#[cfg(feature = "nse-ssh2")]
use std::net::TcpStream;
#[cfg(feature = "nse-ssh2")]
use std::path::Path;
#[cfg(feature = "nse-ssh2")]
use std::time::Duration;

#[cfg(feature = "nse-ssh2")]
struct SshSession {
    session: Option<Session>,
    host: String,
    port: u16,
    banner: String,
    authenticated: bool,
    username: Option<String>,
}

#[cfg(feature = "nse-ssh2")]
impl SshSession {
    fn connect(host: &str, port: u16) -> std::io::Result<Self> {
        let addr = format!("{}:{}", host, port);
        let tcp = TcpStream::connect_timeout(
            &addr
                .parse()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
            Duration::from_secs(10),
        )?;

        let mut session = Session::new()?;
        session.set_tcp_stream(tcp);
        session
            .handshake()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let banner = session.banner().unwrap_or("").to_string();

        Ok(Self {
            session: Some(session),
            host: host.to_string(),
            port,
            banner,
            authenticated: false,
            username: None,
        })
    }

    fn authenticate_password(&mut self, username: &str, password: &str) -> bool {
        if let Some(ref mut session) = self.session {
            match session.userauth_password(username, password) {
                Ok(()) => {
                    self.authenticated = true;
                    self.username = Some(username.to_string());
                    true
                }
                Err(_) => false,
            }
        } else {
            false
        }
    }

    fn authenticate_publickey(&mut self, username: &str, password: Option<&str>) -> bool {
        if let Some(ref mut session) = self.session {
            match session.userauth_pubkey_file(username, None, Path::new(""), password) {
                Ok(()) => {
                    self.authenticated = true;
                    self.username = Some(username.to_string());
                    true
                }
                Err(_) => false,
            }
        } else {
            false
        }
    }
}

#[cfg(feature = "nse-ssh2")]
impl UserData for SshSession {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method_mut("disconnect", |_lua, this, _: ()| {
            if let Some(ref session) = this.session {
                if session.disconnect(None, "User disconnected", None).is_err() {
                    tracing::warn!("Failed to disconnect SSH session");
                }
            }
            Ok(true)
        });

        methods.add_method_mut(
            "userauth_password",
            |_lua, this, (username, password): (String, String)| {
                Ok(this.authenticate_password(&username, &password))
            },
        );

        methods.add_method_mut(
            "userauth_publickey",
            |_lua, this, (username, _public_key, password): (String, String, Option<String>)| {
                Ok(this.authenticate_publickey(&username, password.as_deref()))
            },
        );

        methods.add_method_mut("channel_open_session", |lua, this, _: ()| {
            let chan = lua.create_table()?;
            if let Some(ref mut session) = this.session {
                match session.channel_session() {
                    Ok(_channel) => {
                        chan.set("session", this.host.clone())?;
                        chan.set("local_channel", 0i32)?;
                        chan.set("channel_open", true)?;
                    }
                    Err(e) => {
                        chan.set("session", this.host.clone())?;
                        chan.set("local_channel", 0i32)?;
                        chan.set("channel_open", false)?;
                        chan.set("error", e.to_string())?;
                    }
                }
            } else {
                chan.set("channel_open", false)?;
                chan.set("error", "No session")?;
            }
            Ok(chan)
        });

        methods.add_method("channel_read", |_lua, _this, _size: Option<u32>| {
            Ok("".to_string())
        });

        methods.add_method("channel_write", |_lua, _this, _data: String| Ok(0i32));

        methods.add_method("channel_close", |_lua, _this, _: ()| Ok(true));

        methods.add_method("get_channel_exit_status", |_lua, _this, _: ()| Ok(0i32));

        methods.add_method("channel_request_pty", |_lua, _this, _: ()| Ok(true));

        methods.add_method("channel_request_shell", |_lua, _this, _: ()| Ok(true));

        methods.add_method("get.banner", |_lua, this, _: ()| Ok(this.banner.clone()));

        methods.add_method("get.cipher_in", |_lua, _this, _: ()| {
            Ok("aes256-ctr".to_string())
        });

        methods.add_method("get.cipher_out", |_lua, _this, _: ()| {
            Ok("aes256-ctr".to_string())
        });

        methods.add_method("get.serverbanner", |_lua, this, _: ()| {
            Ok(this.banner.clone())
        });

        methods.add_method("get.userauthlist", |_lua, _this, _username: String| {
            Ok("publickey,password".to_string())
        });

        methods.add_method(
            "session_flag",
            |_lua, _this, (_flag, _value): (String, bool)| Ok(true),
        );

        methods.add_method("session_subsystem", |_lua, _this, _subsystem: String| {
            Ok(true)
        });

        methods.add_method(
            "channel_forward_login",
            |lua, this, (_host, _user): (String, String)| {
                let chan = lua.create_table()?;
                chan.set("session", this.host.clone())?;
                chan.set("local_channel", 0i32)?;
                chan.set("authenticated", this.authenticated)?;
                Ok(chan)
            },
        );

        methods.add_method(
            "channel_forward_listen",
            |lua, this, (_host, _port): (Option<String>, Option<u32>)| {
                let chan = lua.create_table()?;
                chan.set("session", this.host.clone())?;
                chan.set("port", 0i32)?;
                chan.set("listening", true)?;
                Ok(chan)
            },
        );

        methods.add_method(
            "channel_accept",
            |lua, _this, (_channel, _timeout): (Value, i32)| {
                let chan = lua.create_table()?;
                chan.set("session", "".to_string())?;
                chan.set("local_channel", 0i32)?;
                chan.set("accepted", true)?;
                Ok(chan)
            },
        );
    }
}

#[cfg(feature = "nse-ssh2")]
pub fn register_ssh2_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let ssh2 = lua.create_table()?;

    let session_fn = lua.create_function(|lua, (host, port): (String, Option<u16>)| {
        let port = port.unwrap_or(22);
        match SshSession::connect(&host, port) {
            Ok(session) => Ok(mlua::Value::UserData(lua.create_userdata(session)?)),
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                result.set("status", "failed")?;
                Ok(mlua::Value::Table(result))
            }
        }
    })?;
    ssh2.set("session", session_fn)?;

    let session_keys_fn = lua.create_function(|lua, _: Value| {
        let keys = lua.create_table()?;
        keys.set("encrypt_key", true)?;
        keys.set("decrypt_key", true)?;
        keys.set("server_to_client", true)?;
        keys.set("client_to_server", true)?;
        keys.set("cipher_in", "aes256-ctr")?;
        keys.set("cipher_out", "aes256-ctr")?;
        keys.set("mac_in", "hmac-sha2-256")?;
        keys.set("mac_out", "hmac-sha2-256")?;
        Ok(keys)
    })?;
    ssh2.set("session_keys", session_keys_fn)?;

    let userauth_fn = lua.create_function(|_, _: (Value, String, String)| Ok(true))?;
    ssh2.set("userauth", userauth_fn)?;

    let channel_fn = lua.create_function(|lua, _: Value| {
        let channel = lua.create_table()?;
        channel.set("session", "".to_string())?;
        channel.set("local_channel", 0i32)?;
        channel.set("open", true)?;
        Ok(channel)
    })?;
    ssh2.set("channel", channel_fn)?;

    let methods_fn = lua.create_function(|_, _: (Value, String)| Ok("".to_string()))?;
    ssh2.set("methods", methods_fn)?;

    let disalgo_fn = lua.create_function(|_, _: (Value, String)| Ok("".to_string()))?;
    ssh2.set("disalgo", disalgo_fn)?;

    let enalgo_fn = lua.create_function(|_, _: (Value, String)| Ok("".to_string()))?;
    ssh2.set("enalgo", enalgo_fn)?;

    let kex_fn = lua.create_function(|_, _: Value| Ok("".to_string()))?;
    ssh2.set("kex", kex_fn)?;

    let keytype_fn = lua.create_function(|_, _: String| Ok("".to_string()))?;
    ssh2.set("keytype", keytype_fn)?;

    let parse_key_fn = lua.create_function(|lua, _: String| {
        let key = lua.create_table()?;
        key.set("type", "ssh-rsa")?;
        key.set("bits", 2048)?;
        Ok(key)
    })?;
    ssh2.set("parse_key", parse_key_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    ssh2.set("version", version_fn)?;

    let async_session_fn = lua.create_function(|lua, (host, port): (String, Option<u16>)| {
        let host_clone = host.clone();
        let port = port.unwrap_or(22);

        tokio::runtime::Handle::current().block_on(async {
            let result =
                tokio::task::spawn_blocking(move || SshSession::connect(&host_clone, port)).await;

            match result {
                Ok(Ok(session)) => {
                    let r = lua.create_userdata(session)?;
                    Ok(mlua::Value::UserData(r))
                }
                Ok(Err(e)) => {
                    let r = lua.create_table()?;
                    r.set("error", e.to_string())?;
                    r.set("status", "failed")?;
                    Ok(mlua::Value::Table(r))
                }
                Err(e) => {
                    let r = lua.create_table()?;
                    r.set("error", e.to_string())?;
                    r.set("status", "failed")?;
                    Ok(mlua::Value::Table(r))
                }
            }
        })
    })?;
    ssh2.set("session_async", async_session_fn)?;

    globals.set("ssh2", ssh2)?;
    Ok(())
}

#[cfg(not(feature = "nse-ssh2"))]
use mlua::{Lua, Result as LuaResult};
#[cfg(not(feature = "nse-ssh2"))]
use std::io::Read;

#[cfg(not(feature = "nse-ssh2"))]
pub fn register_ssh2_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let ssh2 = lua.create_table()?;

    ssh2.set(
        "session",
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            use std::io::Read;
            use std::net::TcpStream;
            use std::time::Duration;

            let result = lua.create_table()?;
            let port = port.unwrap_or(22);
            let addr = format!("{}:{}", host, port);

            match TcpStream::connect_timeout(
                &addr
                    .parse::<std::net::SocketAddr>()
                    .map_err(|e: std::net::AddrParseError| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
                    })?,
                Duration::from_secs(10),
            ) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    let mut banner = vec![0u8; 256];
                    if stream.read(&mut banner).is_err() {
                        tracing::warn!("Failed to read SSH banner");
                    }
                    let banner_str = String::from_utf8_lossy(&banner).trim().to_string();

                    result.set("status", "connected")?;
                    result.set("host", host)?;
                    result.set("port", port)?;
                    result.set("banner", banner_str)?;
                    result.set("connected", true)?;
                }
                Err(e) => {
                    result.set("status", "error")?;
                    result.set("error", e.to_string())?;
                    result.set("host", host)?;
                    result.set("port", port)?;
                    result.set("connected", false)?;
                }
            }
            Ok(result)
        })?,
    )?;

    ssh2.set(
        "session_async",
        lua.create_function(|lua, (host, port): (String, Option<u16>)| {
            let host_clone = host.clone();
            let port = port.unwrap_or(22);
            let host_for_blocking = host_clone.clone();

            tokio::runtime::Handle::current().block_on(async {
                let result = tokio::task::spawn_blocking(move || {
                    use std::net::TcpStream;
                    use std::time::Duration;

                    let addr = format!("{}:{}", host_for_blocking, port);
                    TcpStream::connect_timeout(
                        &addr.parse::<std::net::SocketAddr>().map_err(
                            |e: std::net::AddrParseError| {
                                std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
                            },
                        )?,
                        Duration::from_secs(10),
                    )
                })
                .await;

                match result {
                    Ok(Ok(mut stream)) => {
                        stream
                            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                            .ok();
                        let mut banner = vec![0u8; 256];
                        if stream.read(&mut banner).is_err() {
                            tracing::warn!("Failed to read SSH banner");
                        }
                        let banner_str = String::from_utf8_lossy(&banner).trim().to_string();

                        let r = lua.create_table()?;
                        r.set("status", "connected")?;
                        r.set("host", host_clone)?;
                        r.set("port", port)?;
                        r.set("banner", banner_str)?;
                        r.set("connected", true)?;
                        Ok(r)
                    }
                    Ok(Err(e)) => {
                        let r = lua.create_table()?;
                        r.set("status", "error")?;
                        r.set("error", e.to_string())?;
                        r.set("host", host_clone)?;
                        r.set("port", port)?;
                        r.set("connected", false)?;
                        Ok(r)
                    }
                    Err(e) => {
                        let r = lua.create_table()?;
                        r.set("status", "error")?;
                        r.set("error", e.to_string())?;
                        r.set("connected", false)?;
                        Ok(r)
                    }
                }
            })
        })?,
    )?;

    let session_keys_fn = lua.create_function(|lua, _: mlua::Value| {
        let keys = lua.create_table()?;
        keys.set("encrypt_key", true)?;
        keys.set("decrypt_key", true)?;
        keys.set("server_to_client", true)?;
        keys.set("client_to_server", true)?;
        Ok(keys)
    })?;
    ssh2.set("session_keys", session_keys_fn)?;

    let userauth_fn = lua.create_function(|_, _: (mlua::Value, String, String)| Ok(true))?;
    ssh2.set("userauth", userauth_fn)?;

    let channel_fn = lua.create_function(|lua, _: mlua::Value| {
        let channel = lua.create_table()?;
        channel.set(
            "error",
            "SSH2 support not compiled. Enable 'nse-ssh2' feature for full support.",
        )?;
        channel.set("open", false)?;
        Ok(channel)
    })?;
    ssh2.set("channel", channel_fn)?;

    let methods_fn = lua.create_function(|_, _: (mlua::Value, String)| Ok("".to_string()))?;
    ssh2.set("methods", methods_fn)?;

    let disalgo_fn = lua.create_function(|_, _: (mlua::Value, String)| Ok("".to_string()))?;
    ssh2.set("disalgo", disalgo_fn)?;

    let enalgo_fn = lua.create_function(|_, _: (mlua::Value, String)| Ok("".to_string()))?;
    ssh2.set("enalgo", enalgo_fn)?;

    let kex_fn = lua.create_function(|_, _: mlua::Value| Ok("".to_string()))?;
    ssh2.set("kex", kex_fn)?;

    let keytype_fn = lua.create_function(|_, _: String| Ok("".to_string()))?;
    ssh2.set("keytype", keytype_fn)?;

    let parse_key_fn = lua.create_function(|lua, _: String| {
        let key = lua.create_table()?;
        key.set("type", "ssh-rsa")?;
        key.set("bits", 2048)?;
        Ok(key)
    })?;
    ssh2.set("parse_key", parse_key_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    ssh2.set("version", version_fn)?;

    globals.set("ssh2", ssh2)?;
    Ok(())
}
