//! NSE socket library wrapper
//!
//! Low-level socket operations for NSE scripts.
//! Based on Nmap's socket library concepts.

use ipnetwork::IpNetwork;
use mlua::{Lua, Result as LuaResult, UserData, UserDataMethods, Value};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

enum StreamType {
    Tcp(TcpStream),
    Udp(std::net::UdpSocket),
}

struct SocketHandle {
    stream: Option<StreamType>,
    host: String,
    port: u16,
    timeout: Duration,
    socket_type: String,
    udp_connected: bool,
    sandbox_enabled: bool,
    log_violations: bool,
    allowed_networks: Vec<IpNetwork>,
}

impl SocketHandle {
    fn new_with_sandbox(
        sandbox_enabled: bool,
        log_violations: bool,
        allowed_networks: Vec<IpNetwork>,
    ) -> Self {
        Self {
            stream: None,
            host: String::new(),
            port: 0,
            timeout: Duration::from_secs(10),
            socket_type: "tcp".to_string(),
            udp_connected: false,
            sandbox_enabled,
            log_violations,
            allowed_networks,
        }
    }

    fn is_host_allowed(&self, host: &str) -> bool {
        if !self.sandbox_enabled || self.allowed_networks.is_empty() {
            return true;
        }

        let addr = format!("{}:0", host);
        let Ok(socket_addrs) = addr.to_socket_addrs() else {
            return false;
        };

        socket_addrs.into_iter().any(|sa| {
            self.allowed_networks
                .iter()
                .any(|net| net.contains(sa.ip()))
        })
    }

    fn connect(&mut self, host: &str, port: u16) -> Result<(), String> {
        if !self.is_host_allowed(host) {
            let msg = format!(
                "[NSE Sandbox] Network violation: {} is not in allowed networks (sandbox enabled)",
                host
            );
            if self.log_violations {
                tracing::warn!("{}", msg);
            }
            return Err(msg);
        }

        let addr = format!("{}:{}", host, port);
        let socket_addr: SocketAddr = addr
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .next()
            .ok_or("No address found")?;

        let stream =
            TcpStream::connect_timeout(&socket_addr, self.timeout).map_err(|e| e.to_string())?;

        let _ = stream.set_read_timeout(Some(self.timeout));
        let _ = stream.set_write_timeout(Some(self.timeout));

        self.stream = Some(StreamType::Tcp(stream));
        self.host = host.to_string();
        self.port = port;
        self.socket_type = "tcp".to_string();

        Ok(())
    }

    fn connect_udp(&mut self, host: &str, port: u16) -> Result<(), String> {
        if !self.is_host_allowed(host) {
            let msg = format!(
                "[NSE Sandbox] Network violation: {} is not in allowed networks (sandbox enabled)",
                host
            );
            if self.log_violations {
                tracing::warn!("{}", msg);
            }
            return Err(msg);
        }

        let addr = format!("{}:{}", host, port);
        let socket_addr: SocketAddr = addr
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .next()
            .ok_or("No address found")?;

        let udp_socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

        udp_socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set read timeout: {}", e))?;

        udp_socket
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| format!("Failed to set write timeout: {}", e))?;

        udp_socket
            .connect(socket_addr)
            .map_err(|e| format!("Failed to connect UDP socket: {}", e))?;

        self.stream = Some(StreamType::Udp(udp_socket));
        self.host = host.to_string();
        self.port = port;
        self.socket_type = "udp".to_string();
        self.udp_connected = true;

        Ok(())
    }

    fn send(&mut self, data: &str) -> Result<usize, String> {
        match self.stream.as_mut() {
            Some(StreamType::Tcp(stream)) => {
                stream.write(data.as_bytes()).map_err(|e| e.to_string())
            }
            Some(StreamType::Udp(socket)) => {
                socket.send(data.as_bytes()).map_err(|e| e.to_string())
            }
            None => Err("Not connected".to_string()),
        }
    }

    fn receive(&mut self, size: usize) -> Result<String, String> {
        match self.stream.as_mut() {
            Some(StreamType::Tcp(stream)) => {
                let size = size.max(1).min(65536);
                let mut buffer = vec![0u8; size];
                let n = stream.read(&mut buffer).map_err(|e| e.to_string())?;
                buffer.truncate(n);
                Ok(String::from_utf8_lossy(&buffer).to_string())
            }
            Some(StreamType::Udp(socket)) => {
                let size = size.max(1).min(65536);
                let mut buffer = vec![0u8; size];
                match socket.recv(&mut buffer) {
                    Ok(n) => {
                        buffer.truncate(n);
                        Ok(String::from_utf8_lossy(&buffer).to_string())
                    }
                    Err(e) => {
                        // For UDP, if no data is available, return empty string
                        // This is more in line with Nmap's behavior
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            Ok(String::new())
                        } else {
                            Err(format!("UDP receive error: {}", e))
                        }
                    }
                }
            }
            None => Err("Not connected".to_string()),
        }
    }

    fn close(&mut self) {
        self.stream = None;
        self.host.clear();
        self.port = 0;
        self.udp_connected = false;
    }

    fn set_timeout(&mut self, timeout_ms: i64) {
        self.timeout = Duration::from_millis(timeout_ms.max(0) as u64);

        // Update timeout on existing socket if connected
        match self.stream.as_mut() {
            Some(StreamType::Tcp(stream)) => {
                let _ = stream.set_read_timeout(Some(self.timeout));
                let _ = stream.set_write_timeout(Some(self.timeout));
            }
            Some(StreamType::Udp(socket)) => {
                let _ = socket.set_read_timeout(Some(self.timeout));
                let _ = socket.set_write_timeout(Some(self.timeout));
            }
            None => {}
        }
    }

    fn get_local_port(&self) -> Option<u16> {
        match self.stream.as_ref() {
            Some(StreamType::Tcp(stream)) => stream.local_addr().ok().map(|a| a.port()),
            Some(StreamType::Udp(socket)) => socket.local_addr().ok().map(|a| a.port()),
            None => None,
        }
    }

    fn get_remote_port(&self) -> Option<u16> {
        Some(self.port)
    }

    fn get_family(&self) -> String {
        "inet".to_string()
    }
}

impl UserData for SocketHandle {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method_mut("connect", |lua, this, (host, port): (String, u16)| {
            this.connect(&host, port)
                .map_err(mlua::Error::RuntimeError)?;

            let result = lua.create_table()?;
            result.set("host", host)?;
            result.set("port", port)?;
            result.set("status", "connected")?;
            Ok(result)
        });

        methods.add_method_mut("send", |lua, this, data: String| {
            let bytes = this.send(&data).map_err(mlua::Error::RuntimeError)?;

            let result = lua.create_table()?;
            result.set("status", "sent")?;
            result.set("bytes", bytes as i32)?;
            Ok(result)
        });

        methods.add_method_mut("receive", |lua, this, size: Option<usize>| {
            let size = size.unwrap_or(1024);
            let data = this.receive(size).map_err(mlua::Error::RuntimeError)?;

            let result = lua.create_table()?;
            result.set("data", data)?;
            result.set("status", "ok")?;
            Ok(result)
        });

        methods.add_method_mut("close", |_lua, this, _: ()| {
            this.close();
            Ok(true)
        });

        methods.add_method_mut("set_timeout", |_lua, this, timeout_ms: i64| {
            this.set_timeout(timeout_ms);
            Ok(true)
        });

        methods.add_method("get_timeout", |_lua, this, _: ()| {
            Ok(this.timeout.as_millis() as i64)
        });

        methods.add_method("is_connected", |_lua, this, _: ()| {
            Ok(this.stream.is_some())
        });

        methods.add_method("get_local_port", |_lua, this, _: ()| {
            Ok(this.get_local_port().unwrap_or(0))
        });

        methods.add_method("get_remote_port", |_lua, this, _: ()| {
            Ok(this.get_remote_port().unwrap_or(0))
        });

        methods.add_method("get_family", |_lua, this, _: ()| Ok(this.get_family()));

        methods.add_method("get_type", |_lua, this, _: ()| Ok(this.socket_type.clone()));

        methods.add_method("is_udp", |_lua, this, _: ()| Ok(this.socket_type == "udp"));
    }
}

pub fn register_socket_library(lua: &Lua, sandbox: &crate::SandboxConfig) -> LuaResult<()> {
    let globals = lua.globals();

    let sandbox_enabled = sandbox.enabled;
    let log_violations = sandbox.log_violations;
    let allowed_networks = sandbox.allowed_networks.clone();

    let socket = lua.create_table()?;

    let tcp_fn = lua.create_function({
        let allowed_networks = allowed_networks.clone();
        move |lua, _: ()| {
            let mut sock = SocketHandle::new_with_sandbox(
                sandbox_enabled,
                log_violations,
                allowed_networks.clone(),
            );
            sock.socket_type = "tcp".to_string();
            if sandbox_enabled && log_violations {
                tracing::info!("[NSE Sandbox] Socket created: TCP (sandbox enabled)");
            }
            lua.create_userdata(sock)
        }
    })?;
    socket.set("tcp", tcp_fn)?;

    let udp_fn = lua.create_function({
        let allowed_networks = allowed_networks.clone();
        move |lua, _: ()| {
            let mut sock = SocketHandle::new_with_sandbox(
                sandbox_enabled,
                log_violations,
                allowed_networks.clone(),
            );
            sock.socket_type = "udp".to_string();
            lua.create_userdata(sock)
        }
    })?;
    socket.set("udp", udp_fn)?;

    let sctp_fn = lua.create_function({
        let allowed_networks = allowed_networks.clone();
        move |lua, _: ()| {
            let mut sock = SocketHandle::new_with_sandbox(
                sandbox_enabled,
                log_violations,
                allowed_networks.clone(),
            );
            sock.socket_type = "sctp".to_string();
            lua.create_userdata(sock)
        }
    })?;
    socket.set("sctp", sctp_fn)?;

    let tcp_connect_fn = lua.create_function({
        let allowed_networks = allowed_networks.clone();
        move |lua, (host, port): (String, u16)| {
            if sandbox_enabled && log_violations {
                tracing::info!("[NSE Sandbox] TCP connect: {}:{} (sandbox enabled)", host, port);
            }

            if !allowed_networks.is_empty() {
                let addr = format!("{}:0", host);
                if let Ok(socket_addrs) = addr.to_socket_addrs() {
                    let all_allowed = socket_addrs.clone().all(|sa| {
                        allowed_networks.iter().any(|net| net.contains(sa.ip()))
                    });
                    if !all_allowed {
                        let msg = format!(
                            "[NSE Sandbox] Network violation: {} is not in allowed networks (sandbox enabled)",
                            host
                        );
                        if log_violations {
                            tracing::warn!("{}", msg);
                        }
                        return Err(mlua::Error::RuntimeError(msg));
                    }
                }
            }

            let mut sock =
                SocketHandle::new_with_sandbox(sandbox_enabled, log_violations, allowed_networks.clone());
            sock.connect(&host, port)
                .map_err(mlua::Error::RuntimeError)?;

            let result = lua.create_table()?;
            result.set("host", host)?;
            result.set("port", port)?;
            result.set("status", "connected")?;
            Ok(result)
        }
    })?;
    socket.set("tcp_connect", tcp_connect_fn)?;

    let connect_fn = lua.create_function({
        let allowed_networks = allowed_networks.clone();
        move |lua, (host, port): (String, u16)| {
            if sandbox_enabled && log_violations {
                tracing::info!("[NSE Sandbox] Socket connect: {}:{} (sandbox enabled)", host, port);
            }

            if !allowed_networks.is_empty() {
                let addr = format!("{}:0", host);
                if let Ok(socket_addrs) = addr.to_socket_addrs() {
                    let all_allowed = socket_addrs.clone().all(|sa| {
                        allowed_networks.iter().any(|net| net.contains(sa.ip()))
                    });
                    if !all_allowed {
                        let msg = format!(
                            "[NSE Sandbox] Network violation: {} is not in allowed networks (sandbox enabled)",
                            host
                        );
                        if log_violations {
                            tracing::warn!("{}", msg);
                        }
                        return Err(mlua::Error::RuntimeError(msg));
                    }
                }
            }

            let mut sock =
                SocketHandle::new_with_sandbox(sandbox_enabled, log_violations, allowed_networks.clone());
            sock.connect(&host, port)
                .map_err(mlua::Error::RuntimeError)?;

            let result = lua.create_table()?;
            result.set("host", host)?;
            result.set("port", port)?;
            result.set("status", "connected")?;
            Ok(result)
        }
    })?;
    socket.set("connect", connect_fn)?;

    let send_fn = lua.create_function(|lua, (socket_val, data): (Value, String)| {
        if let Value::UserData(ud) = socket_val {
            let mut sock = ud
                .borrow_mut::<SocketHandle>()
                .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            let bytes = sock.send(&data).map_err(mlua::Error::RuntimeError)?;

            let result = lua.create_table()?;
            result.set("status", "sent")?;
            result.set("bytes", bytes as i32)?;
            Ok(result)
        } else {
            Err(mlua::Error::RuntimeError("Not a socket".to_string()))
        }
    })?;
    socket.set("send", send_fn)?;

    let receive_fn = lua.create_function(|lua, (socket_val, size): (Value, Option<usize>)| {
        if let Value::UserData(ud) = socket_val {
            let mut sock = ud
                .borrow_mut::<SocketHandle>()
                .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            let data = sock
                .receive(size.unwrap_or(1024))
                .map_err(mlua::Error::RuntimeError)?;

            let result = lua.create_table()?;
            result.set("data", data)?;
            result.set("status", "ok")?;
            Ok(result)
        } else {
            Err(mlua::Error::RuntimeError("Not a socket".to_string()))
        }
    })?;
    socket.set("receive", receive_fn)?;

    let close_fn = lua.create_function(|_lua, socket_val: Value| {
        if let Value::UserData(ud) = socket_val {
            let mut sock = ud
                .borrow_mut::<SocketHandle>()
                .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            sock.close();
            Ok(true)
        } else {
            Err(mlua::Error::RuntimeError("Not a socket".to_string()))
        }
    })?;
    socket.set("close", close_fn)?;

    let set_timeout_fn = lua.create_function(|_lua, (socket_val, timeout): (Value, i64)| {
        if let Value::UserData(ud) = socket_val {
            let mut sock = ud
                .borrow_mut::<SocketHandle>()
                .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            sock.set_timeout(timeout);
            Ok(true)
        } else {
            Err(mlua::Error::RuntimeError("Not a socket".to_string()))
        }
    })?;
    socket.set("set_timeout", set_timeout_fn)?;

    let get_timeout_fn = lua.create_function(|_lua, socket_val: Value| {
        if let Value::UserData(ud) = socket_val {
            let sock = ud
                .borrow::<SocketHandle>()
                .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            Ok(sock.timeout.as_millis() as i64)
        } else {
            Err(mlua::Error::RuntimeError("Not a socket".to_string()))
        }
    })?;
    socket.set("get_timeout", get_timeout_fn)?;

    let is_connected_fn = lua.create_function(|_lua, socket_val: Value| {
        if let Value::UserData(ud) = socket_val {
            let sock = ud
                .borrow::<SocketHandle>()
                .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
            Ok(sock.stream.is_some())
        } else {
            Err(mlua::Error::RuntimeError("Not a socket".to_string()))
        }
    })?;
    socket.set("is_connected", is_connected_fn)?;

    let sendto_fn = lua.create_function(
        |lua, (socket_val, host, port, data): (Value, String, u16, String)| {
            if let Value::UserData(ud) = socket_val {
                let mut sock = ud
                    .borrow_mut::<SocketHandle>()
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

                // For UDP, we may need to connect to a new destination
                if sock.socket_type == "udp" && (sock.host != host || sock.port != port) {
                    // Close existing connection and create new one
                    sock.close();
                    sock.connect_udp(&host, port)
                        .map_err(mlua::Error::RuntimeError)?;
                }

                sock.host = host.clone();
                sock.port = port;

                let bytes = sock.send(&data).map_err(mlua::Error::RuntimeError)?;

                let result = lua.create_table()?;
                result.set("status", "sent")?;
                result.set("bytes", bytes as i32)?;
                Ok(result)
            } else {
                Err(mlua::Error::RuntimeError("Not a socket".to_string()))
            }
        },
    )?;
    socket.set("sendto", sendto_fn)?;

    let receive_from_fn =
        lua.create_function(|lua, (socket_val, size): (Value, Option<usize>)| {
            if let Value::UserData(ud) = socket_val {
                let mut sock = ud
                    .borrow_mut::<SocketHandle>()
                    .map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;

                let size = size.unwrap_or(1024);
                let data = sock.receive(size).map_err(mlua::Error::RuntimeError)?;

                let result = lua.create_table()?;
                result.set("data", data)?;
                result.set("host", sock.host.clone())?;
                result.set("port", sock.port)?;
                result.set("status", "ok")?;
                Ok(result)
            } else {
                Err(mlua::Error::RuntimeError("Not a socket".to_string()))
            }
        })?;
    socket.set("receive_from", receive_from_fn)?;

    // Async TCP connect
    let async_tcp_connect_fn = lua.create_function({
        let allowed_networks = allowed_networks.clone();
        move |lua, (host, port): (String, u16)| {
            if !allowed_networks.is_empty() {
                let addr = format!("{}:0", host);
                if let Ok(socket_addrs) = addr.to_socket_addrs() {
                    let all_allowed = socket_addrs.clone().all(|sa| {
                        allowed_networks.iter().any(|net| net.contains(sa.ip()))
                    });
                    if !all_allowed {
                        let msg = format!(
                            "[NSE Sandbox] Network violation: {} is not in allowed networks (sandbox enabled)",
                            host
                        );
                        if log_violations {
                            tracing::warn!("{}", msg);
                        }
                        return Err(mlua::Error::RuntimeError(msg));
                    }
                }
            }

            let addr = format!("{}:{}", host, port);

            let result = tokio::runtime::Handle::current().block_on(async {
                match tokio::net::TcpStream::connect(&addr).await {
                    Ok(_stream) => {
                        let r = lua.create_table()?;
                        r.set("host", host)?;
                        r.set("port", port)?;
                        r.set("status", "connected")?;
                        Ok(r)
                    }
                    Err(e) => Err(mlua::Error::RuntimeError(e.to_string())),
                }
            });

            result
        }
    })?;
    socket.set("tcp_connect_async", async_tcp_connect_fn)?;

    // Async connect (generic)
    let async_connect_fn = lua.create_function({
        let allowed_networks = allowed_networks.clone();
        move |lua, (host, port): (String, u16)| {
            if !allowed_networks.is_empty() {
                let addr = format!("{}:0", host);
                if let Ok(socket_addrs) = addr.to_socket_addrs() {
                    let all_allowed = socket_addrs.clone().all(|sa| {
                        allowed_networks.iter().any(|net| net.contains(sa.ip()))
                    });
                    if !all_allowed {
                        let msg = format!(
                            "[NSE Sandbox] Network violation: {} is not in allowed networks (sandbox enabled)",
                            host
                        );
                        if log_violations {
                            tracing::warn!("{}", msg);
                        }
                        return Err(mlua::Error::RuntimeError(msg));
                    }
                }
            }

            let addr = format!("{}:{}", host, port);

            let result = tokio::runtime::Handle::current().block_on(async {
                match tokio::net::TcpStream::connect(&addr).await {
                    Ok(_stream) => {
                        let r = lua.create_table()?;
                        r.set("host", host)?;
                        r.set("port", port)?;
                        r.set("status", "connected")?;
                        Ok(r)
                    }
                    Err(e) => Err(mlua::Error::RuntimeError(e.to_string())),
                }
            });

            result
        }
    })?;
    socket.set("connect_async", async_connect_fn)?;

    // Async DNS resolve - also needs network check since it reveals internal network info
    let async_resolve_fn = lua.create_function({
        let allowed_networks = allowed_networks.clone();
        move |lua, host: String| {
            if !allowed_networks.is_empty() {
                let addr = format!("{}:0", host);
                if let Ok(socket_addrs) = addr.to_socket_addrs() {
                    let all_allowed = socket_addrs.clone().all(|sa| {
                        allowed_networks.iter().any(|net| net.contains(sa.ip()))
                    });
                    if !all_allowed {
                        let msg = format!(
                            "[NSE Sandbox] Network violation: DNS resolution for {} is not in allowed networks (sandbox enabled)",
                            host
                        );
                        if log_violations {
                            tracing::warn!("{}", msg);
                        }
                        return Err(mlua::Error::RuntimeError(msg));
                    }
                }
            }

            let result = tokio::runtime::Handle::current().block_on(async {
                match tokio::net::lookup_host(&format!("{}:0", host)).await {
                    Ok(addrs) => {
                        let r = lua.create_table()?;
                        let mut index = 1;
                        for addr in addrs {
                            r.set(index, addr.ip().to_string())?;
                            index += 1;
                        }
                        Ok(r)
                    }
                    Err(e) => Err(mlua::Error::RuntimeError(e.to_string())),
                }
            });

            result
        }
    })?;
    socket.set("resolve_async", async_resolve_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    socket.set("version", version_fn)?;

    globals.set("socket", socket)?;
    Ok(())
}
