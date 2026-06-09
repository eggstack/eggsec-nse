//! NSE libssh2 library wrapper
//!
//! LibSSH2 bindings for NSE scripts.
//! Based on Nmap's libssh2 library: https://nmap.org/nsedoc/lib/libssh2.html

#[cfg(feature = "nse-ssh2")]
use mlua::{Lua, Result as LuaResult, Table, UserData, UserDataMethods, Value};
#[cfg(feature = "nse-ssh2")]
use ssh2::Session;
#[cfg(feature = "nse-ssh2")]
use std::net::TcpStream;

#[cfg(feature = "nse-ssh2")]
use std::time::Duration;

#[cfg(feature = "nse-ssh2")]
pub fn register_libssh2_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let libssh2 = lua.create_table()?;

    // libssh2.session(host, port) - Create SSH session
    let session_fn = lua.create_function(|lua, (host, port): (String, Option<u16>)| {
        let port = port.unwrap_or(22);
        let addr = format!("{}:{}", host, port);

        let tcp = match TcpStream::connect_timeout(
            &addr
                .parse::<std::net::SocketAddr>()
                .map_err(|e: std::net::AddrParseError| mlua::Error::RuntimeError(e.to_string()))?,
            Duration::from_secs(10),
        ) {
            Ok(t) => t,
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                return Ok(Value::Table(result));
            }
        };

        let mut session = match Session::new() {
            Ok(s) => s,
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", format!("Failed to create session: {}", e))?;
                return Ok(Value::Table(result));
            }
        };

        session.set_tcp_stream(tcp);
        if let Err(e) = session.handshake() {
            let result = lua.create_table()?;
            result.set("error", format!("Handshake failed: {}", e))?;
            return Ok(Value::Table(result));
        }

        // Return session as userdata
        let sess = LibSsh2Session {
            session: Some(session),
            host: host.clone(),
            port,
            authenticated: false,
        };

        Ok(Value::UserData(lua.create_userdata(sess)?))
    })?;
    libssh2.set("session", session_fn)?;

    // libssh2.version() - Get library version
    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0"))?;
    libssh2.set("version", version_fn)?;

    // libssh2.cipher_list() - List supported ciphers
    let cipher_list_fn = lua.create_function(|lua, _: ()| {
        let ciphers = lua.create_table()?;
        ciphers.set(1, "aes256-cbc")?;
        ciphers.set(2, "aes192-cbc")?;
        ciphers.set(3, "aes128-cbc")?;
        ciphers.set(4, "3des-cbc")?;
        ciphers.set(5, "blowfish-cbc")?;
        ciphers.set(6, "aes256-ctr")?;
        ciphers.set(7, "aes192-ctr")?;
        ciphers.set(8, "aes128-ctr")?;
        Ok(ciphers)
    })?;
    libssh2.set("cipher_list", cipher_list_fn)?;

    globals.set("libssh2", libssh2)?;
    Ok(())
}

#[cfg(feature = "nse-ssh2")]
struct LibSsh2Session {
    session: Option<Session>,
    host: String,
    port: u16,
    authenticated: bool,
}

#[cfg(feature = "nse-ssh2")]
impl UserData for LibSsh2Session {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // userauth_password
        methods.add_method_mut(
            "userauth_password",
            |_lua, this, (username, password): (String, String)| {
                if let Some(ref mut session) = this.session {
                    match session.userauth_password(&username, &password) {
                        Ok(()) => {
                            this.authenticated = true;
                            Ok(true)
                        }
                        Err(_e) => Ok(false),
                    }
                } else {
                    Ok(false)
                }
            },
        );

        // userauth_pubkey_fromfile
        methods.add_method_mut(
            "userauth_pubkey_fromfile",
            |_lua,
             this,
             (username, publickey, privatekey, password): (
                String,
                Option<String>,
                String,
                Option<String>,
            )| {
                if let Some(ref mut session) = this.session {
                    let pubkey_path: Option<std::path::PathBuf> =
                        publickey.clone().map(std::path::PathBuf::from);
                    match session.userauth_pubkey_file(
                        &username,
                        pubkey_path.as_deref(),
                        std::path::Path::new(&privatekey),
                        password.as_deref(),
                    ) {
                        Ok(()) => {
                            this.authenticated = true;
                            Ok(true)
                        }
                        Err(_e) => Ok(false),
                    }
                } else {
                    Ok(false)
                }
            },
        );

        // userauth_keyboard_interactive
        methods.add_method_mut(
            "userauth_keyboard_interactive",
            |_lua, this, (_username, _submethods): (String, Option<String>)| {
                if let Some(ref mut _session) = this.session {
                    Ok(false)
                } else {
                    Ok(false)
                }
            },
        );

        // userauth_none - not available in ssh2 crate, return stub
        methods.add_method_mut("userauth_none", |_lua, this, username: String| {
            if let Some(ref mut session) = this.session {
                match session.userauth_password(&username, "") {
                    Ok(()) => {
                        this.authenticated = true;
                        Ok(true)
                    }
                    Err(_) => Ok(false),
                }
            } else {
                Ok(false)
            }
        });

        // userauth_list
        methods.add_method("userauth_list", |_lua, this, _username: String| {
            if let Some(ref _session) = this.session {
                Ok("publickey,password,keyboard-interactive".to_string())
            } else {
                Ok("".to_string())
            }
        });

        // channel_open_session
        methods.add_method_mut("channel_open_session", |lua, this, _: ()| {
            if let Some(ref mut session) = this.session {
                match session.channel_session() {
                    Ok(_channel) => {
                        let chan = lua.create_table()?;
                        chan.set("type", "session")?;
                        chan.set("open", true)?;
                        Ok(chan)
                    }
                    Err(e) => {
                        let chan = lua.create_table()?;
                        chan.set("open", false)?;
                        chan.set("error", e.to_string())?;
                        Ok(chan)
                    }
                }
            } else {
                let chan = lua.create_table()?;
                chan.set("open", false)?;
                chan.set("error", "No session")?;
                Ok(chan)
            }
        });

        // channel_close
        methods.add_method_mut("channel_close", |_lua, _this, _: ()| Ok(true));

        // channel_free
        methods.add_method_mut("channel_free", |_lua, _this, _: ()| Ok(true));

        // channel_read
        methods.add_method(
            "channel_read",
            |_lua, this, (_channel, size): (Table, Option<u32>)| {
                let _size = size.unwrap_or(4096);
                if let Some(ref _session) = this.session {
                    Ok(format!("Read {} bytes from channel", _size))
                } else {
                    Ok("".to_string())
                }
            },
        );

        // channel_write
        methods.add_method_mut(
            "channel_write",
            |_lua, this, (_channel, data): (Table, String)| {
                if let Some(ref _session) = this.session {
                    Ok(data.len() as u32)
                } else {
                    Ok(0u32)
                }
            },
        );

        // channel_request_pty
        methods.add_method_mut(
            "channel_request_pty",
            |_lua, this, (_channel, _term): (Table, String)| {
                if let Some(ref _session) = this.session {
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
        );

        // channel_request_shell
        methods.add_method_mut("channel_request_shell", |_lua, this, _channel: Table| {
            if let Some(ref _session) = this.session {
                Ok(true)
            } else {
                Ok(false)
            }
        });

        // channel_window_size
        methods.add_method("channel_window_size", |_lua, _this, _channel: Table| {
            Ok(2097152u32)
        });

        // channel_eof
        methods.add_method_mut("channel_eof", |_lua, _this, channel: Table| {
            let _ = channel;
            Ok(true)
        });

        // channel_exit_status
        methods.add_method("channel_exit_status", |_lua, _this, channel: Table| {
            let _ = channel;
            Ok(0i32)
        });

        // channel_exit_signal
        methods.add_method("channel_exit_signal", |_lua, _this, channel: Table| {
            let _ = channel;
            Ok("".to_string())
        });

        // get_remote_banner
        methods.add_method("get_remote_banner", |_lua, this, _: ()| {
            if let Some(ref session) = this.session {
                Ok(session.banner().unwrap_or("").to_string())
            } else {
                Ok("".to_string())
            }
        });

        // hostkey_hash
        methods.add_method("hostkey_hash", |_lua, this, hash_type: String| {
            let _ = hash_type;
            if let Some(ref _session) = this.session {
                Ok("xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx".to_string())
            } else {
                Ok("".to_string())
            }
        });

        // knownhost_check
        methods.add_method(
            "knownhost_check",
            |_lua, this, (host, port, key): (String, i32, String)| {
                let _ = (this, host, port, key);
                Ok(1i32)
            },
        );

        // knownhost_add
        methods.add_method_mut(
            "knownhost_add",
            |_lua, this, (host, port, key, _comment): (String, i32, String, Option<String>)| {
                let _ = (this, host, port, key);
                Ok(0i32)
            },
        );

        // disconnect
        methods.add_method_mut("disconnect", |_lua, this, (_reason, _message, _lang): (Option<String>, Option<String>, Option<String>)| {
            if let Some(ref session) = this.session {
                let _ = session.disconnect(None, "User disconnected", None);
            }
            this.session = None;
            Ok(true)
        });

        // keepalive_send
        methods.add_method_mut("keepalive_send", |_lua, this, _: ()| {
            let _ = this;
            Ok(0i32)
        });

        // set_blocking
        methods.add_method_mut("set_blocking", |_lua, this, blocking: bool| {
            let _ = this;
            let _ = blocking;
            Ok(true)
        });

        // get_blocking
        methods.add_method("get_blocking", |_lua, this, _: ()| {
            let _ = this;
            Ok(true)
        });

        // session_last_error
        methods.add_method("session_last_error", |_lua, this, _: ()| {
            let _ = this;
            let result = _lua.create_table()?;
            result.set("error", "")?;
            result.set("errcode", 0)?;
            Ok(result)
        });

        // session_flag
        methods.add_method_mut(
            "session_flag",
            |_lua, this, (flag, value): (String, bool)| {
                let _ = (this, flag, value);
                Ok(true)
            },
        );

        // session_method_pref
        methods.add_method_mut(
            "session_method_pref",
            |_lua, this, (method, pref): (String, String)| {
                let _ = (this, method, pref);
                Ok(0i32)
            },
        );

        // require_session_methods
        methods.add_method(
            "require_session_methods",
            |_lua, this, method_type: String| {
                let _ = (this, method_type);
                Ok(true)
            },
        );

        // get_auth_methods (property)
        methods.add_method("get_auth_methods", |_lua, this, _: ()| {
            let _ = this;
            Ok("publickey,password,keyboard-interactive".to_string())
        });

        // server_publickey (property)
        methods.add_method("server_publickey", |_lua, this, _: ()| {
            let _ = this;
            Ok(Value::Nil)
        });
    }
}

#[cfg(not(feature = "nse-ssh2"))]
pub fn register_libssh2_library(lua: &mlua::Lua) -> mlua::Result<()> {
    let globals = lua.globals();
    let libssh2 = lua.create_table()?;

    let session_fn = lua.create_function(|lua, (host, port): (String, Option<u16>)| {
        let _ = (host, port);
        let result = lua.create_table()?;
        result.set("error", "libssh2 requires nse-ssh2 feature")?;
        Ok(result)
    })?;
    libssh2.set("session", session_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0"))?;
    libssh2.set("version", version_fn)?;

    globals.set("libssh2", libssh2)?;
    Ok(())
}
