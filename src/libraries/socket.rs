//! NSE socket library wrapper
//!
//! Low-level socket operations for NSE scripts.
//! Based on Nmap's socket library concepts.
//!
//! M005B: connects go through the authority-preserving provider broker
//! (resolve -> policy-select concrete endpoint -> connect exact endpoint).
//! Handles store opaque [`NseTcpConnection`]/[`NseUdpSocket`] trait objects
//! plus the approved endpoint identity; no direct `std::net`/Tokio calls
//! remain in this module.

use ipnetwork::IpNetwork;
use mlua::{Lua, Result as LuaResult, UserData, UserDataMethods, Value};
use std::time::Duration;

use crate::capabilities::NseCapabilityContext;
use crate::providers::{
    broker_dns_lookup, broker_resolve_and_select, broker_tcp_connect_endpoint, broker_tcp_receive,
    broker_tcp_send, broker_udp_connect_endpoint, broker_udp_receive, broker_udp_send,
    endpoint_in_networks, NseDnsRecordType, NseHostServices, NseResolvedEndpoint, NseTcpConnection,
    NseTransportProtocol, NseUdpSocket,
};

enum StreamHandle {
    Tcp(Box<dyn NseTcpConnection>),
    Udp(Box<dyn NseUdpSocket>),
}

struct SocketHandle {
    stream: Option<StreamHandle>,
    endpoint: Option<NseResolvedEndpoint>,
    host: String,
    port: u16,
    timeout: Duration,
    socket_type: String,
    udp_connected: bool,
    sandbox_enabled: bool,
    log_violations: bool,
    allowed_networks: Vec<IpNetwork>,
    capability_ctx: Option<NseCapabilityContext>,
    services: NseHostServices,
}

impl SocketHandle {
    fn new_with_sandbox(
        sandbox_enabled: bool,
        log_violations: bool,
        allowed_networks: Vec<IpNetwork>,
        capability_ctx: Option<NseCapabilityContext>,
        services: NseHostServices,
    ) -> Self {
        Self {
            stream: None,
            endpoint: None,
            host: String::new(),
            port: 0,
            timeout: Duration::from_secs(10),
            socket_type: "tcp".to_string(),
            udp_connected: false,
            sandbox_enabled,
            log_violations,
            allowed_networks,
            capability_ctx,
            services,
        }
    }

    fn ctx(&self) -> Result<NseCapabilityContext, String> {
        self.capability_ctx
            .clone()
            .ok_or_else(|| "capability context unavailable".to_string())
    }

    /// Legacy sandbox gate, evaluated against the concrete selected
    /// endpoint (no re-resolution).
    fn is_endpoint_allowed(&self, endpoint: &NseResolvedEndpoint) -> bool {
        if !self.sandbox_enabled {
            return true;
        }
        endpoint_in_networks(endpoint, &self.allowed_networks)
    }

    fn connect(&mut self, host: &str, port: u16) -> Result<(), String> {
        let ctx = self.ctx()?;
        // Authority-preserving selection: the broker resolves, evaluates
        // policy per concrete candidate, and returns the approved endpoint.
        let endpoint = broker_resolve_and_select(
            &ctx,
            &self.services,
            host,
            port,
            NseTransportProtocol::Tcp,
            "socket.connect",
        )?;

        if !self.is_endpoint_allowed(&endpoint) {
            let msg = format!(
                "[NSE Sandbox] Network violation: {} is not in allowed networks (sandbox enabled)",
                host
            );
            if self.log_violations {
                tracing::warn!("{}", msg);
            }
            return Err(msg);
        }

        // Connect exactly the selected endpoint (no second resolution).
        let handle = broker_tcp_connect_endpoint(
            &ctx,
            &self.services,
            &endpoint,
            self.timeout,
            "socket.connect",
        )?;

        self.stream = Some(StreamHandle::Tcp(handle));
        self.endpoint = Some(endpoint);
        self.host = host.to_string();
        self.port = port;
        self.socket_type = "tcp".to_string();

        Ok(())
    }

    fn connect_udp(&mut self, host: &str, port: u16) -> Result<(), String> {
        let ctx = self.ctx()?;
        let endpoint = broker_resolve_and_select(
            &ctx,
            &self.services,
            host,
            port,
            NseTransportProtocol::Udp,
            "socket.connect_udp",
        )?;

        if !self.is_endpoint_allowed(&endpoint) {
            let msg = format!(
                "[NSE Sandbox] Network violation: {} is not in allowed networks (sandbox enabled)",
                host
            );
            if self.log_violations {
                tracing::warn!("{}", msg);
            }
            return Err(msg);
        }

        let handle = broker_udp_connect_endpoint(
            &ctx,
            &self.services,
            &endpoint,
            self.timeout,
            "socket.connect_udp",
        )?;

        self.stream = Some(StreamHandle::Udp(handle));
        self.endpoint = Some(endpoint);
        self.host = host.to_string();
        self.port = port;
        self.socket_type = "udp".to_string();
        self.udp_connected = true;

        Ok(())
    }

    fn send(&mut self, data: &str) -> Result<usize, String> {
        let ctx = self.ctx()?;
        match self.stream.as_mut() {
            Some(StreamHandle::Tcp(handle)) => {
                broker_tcp_send(&ctx, handle.as_mut(), data.as_bytes(), "socket.send")
            }
            Some(StreamHandle::Udp(handle)) => {
                broker_udp_send(&ctx, handle.as_mut(), data.as_bytes(), "socket.send")
            }
            None => Err("Not connected".to_string()),
        }
    }

    fn receive(&mut self, size: usize) -> Result<String, String> {
        let ctx = self.ctx()?;
        let bytes = match self.stream.as_mut() {
            Some(StreamHandle::Tcp(handle)) => {
                broker_tcp_receive(&ctx, handle.as_mut(), size, "socket.receive")?
            }
            Some(StreamHandle::Udp(handle)) => {
                broker_udp_receive(&ctx, handle.as_mut(), size, "socket.receive")?
            }
            None => return Err("Not connected".to_string()),
        };
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    fn close(&mut self) {
        self.stream = None;
        self.endpoint = None;
        self.host.clear();
        self.port = 0;
        self.udp_connected = false;
    }

    fn set_timeout(&mut self, timeout_ms: i64) {
        self.timeout = Duration::from_millis(timeout_ms.max(0) as u64);

        // Update timeout on existing handle if connected (warn-and-continue
        // preserves the legacy behavior).
        match self.stream.as_mut() {
            Some(StreamHandle::Tcp(handle)) => {
                if let Err(e) = handle.set_timeouts(self.timeout) {
                    tracing::warn!("Failed to set TCP timeouts: {}", e);
                }
            }
            Some(StreamHandle::Udp(handle)) => {
                if let Err(e) = handle.set_timeouts(self.timeout) {
                    tracing::warn!("Failed to set UDP timeouts: {}", e);
                }
            }
            None => {}
        }
    }

    fn get_local_port(&self) -> Option<u16> {
        match self.stream.as_ref() {
            Some(StreamHandle::Tcp(handle)) => handle.local_port(),
            Some(StreamHandle::Udp(handle)) => handle.local_port(),
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

pub fn register_socket_library(
    lua: &Lua,
    sandbox: &crate::SandboxConfig,
    capability_ctx: &NseCapabilityContext,
) -> LuaResult<()> {
    register_socket_library_with_services(lua, sandbox, capability_ctx, &NseHostServices::native())
}

/// Provider-backed socket registration.
///
/// `services` backs every connect/send/receive/resolve path; deterministic
/// tests inject scripted DNS/socket providers.
pub fn register_socket_library_with_services(
    lua: &Lua,
    sandbox: &crate::SandboxConfig,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();

    let sandbox_enabled = sandbox.enabled;
    let log_violations = sandbox.log_violations;
    let allowed_networks = sandbox.allowed_networks.clone();
    let capability_ctx = capability_ctx.clone();

    let socket = lua.create_table()?;

    let tcp_fn = lua.create_function({
        let allowed_networks = allowed_networks.clone();
        let capability_ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, _: ()| {
            let mut sock = SocketHandle::new_with_sandbox(
                sandbox_enabled,
                log_violations,
                allowed_networks.clone(),
                Some(capability_ctx.clone()),
                services.clone(),
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
        let capability_ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, _: ()| {
            let mut sock = SocketHandle::new_with_sandbox(
                sandbox_enabled,
                log_violations,
                allowed_networks.clone(),
                Some(capability_ctx.clone()),
                services.clone(),
            );
            sock.socket_type = "udp".to_string();
            lua.create_userdata(sock)
        }
    })?;
    socket.set("udp", udp_fn)?;

    let sctp_fn = lua.create_function({
        let allowed_networks = allowed_networks.clone();
        let capability_ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, _: ()| {
            let mut sock = SocketHandle::new_with_sandbox(
                sandbox_enabled,
                log_violations,
                allowed_networks.clone(),
                Some(capability_ctx.clone()),
                services.clone(),
            );
            sock.socket_type = "sctp".to_string();
            lua.create_userdata(sock)
        }
    })?;
    socket.set("sctp", sctp_fn)?;

    let tcp_connect_fn = lua.create_function({
        let allowed_networks = allowed_networks.clone();
        let capability_ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port): (String, u16)| {
            if sandbox_enabled && log_violations {
                tracing::info!(
                    "[NSE Sandbox] TCP connect: {}:{} (sandbox enabled)",
                    host,
                    port
                );
            }

            // Capability, DNS, sandbox, and accounting sequencing all live
            // inside the brokered connect below.
            let mut sock = SocketHandle::new_with_sandbox(
                sandbox_enabled,
                log_violations,
                allowed_networks.clone(),
                Some(capability_ctx.clone()),
                services.clone(),
            );
            sock.connect(&host, port)
                .map_err(mlua::Error::RuntimeError)?;

            // Return the SocketHandle as UserData so methods (send, receive, close, etc.) work
            lua.create_userdata(sock)
        }
    })?;
    socket.set("tcp_connect", tcp_connect_fn)?;

    let connect_fn = lua.create_function({
        let allowed_networks = allowed_networks.clone();
        let capability_ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port): (String, u16)| {
            if sandbox_enabled && log_violations {
                tracing::info!(
                    "[NSE Sandbox] Socket connect: {}:{} (sandbox enabled)",
                    host,
                    port
                );
            }

            let mut sock = SocketHandle::new_with_sandbox(
                sandbox_enabled,
                log_violations,
                allowed_networks.clone(),
                Some(capability_ctx.clone()),
                services.clone(),
            );
            sock.connect(&host, port)
                .map_err(mlua::Error::RuntimeError)?;

            // Return the SocketHandle as UserData so methods (send, receive, close, etc.) work
            lua.create_userdata(sock)
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

    // Async TCP connect: brokered sync provider flow (bounded by the
    // connect timeout); returns the status shape only, like before.
    let async_tcp_connect_fn = lua.create_function({
        let allowed_networks = allowed_networks.clone();
        let capability_ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port): (String, u16)| {
            let mut sock = SocketHandle::new_with_sandbox(
                sandbox_enabled,
                log_violations,
                allowed_networks.clone(),
                Some(capability_ctx.clone()),
                services.clone(),
            );
            match sock.connect(&host, port) {
                Ok(()) => {
                    let r = lua.create_table()?;
                    r.set("host", host)?;
                    r.set("port", port)?;
                    r.set("status", "connected")?;
                    Ok(r)
                }
                Err(e) => Err(mlua::Error::RuntimeError(e)),
            }
        }
    })?;
    socket.set("tcp_connect_async", async_tcp_connect_fn)?;

    // Async connect (generic): same brokered flow and status shape.
    let async_connect_fn = lua.create_function({
        let allowed_networks = allowed_networks.clone();
        let capability_ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port): (String, u16)| {
            let mut sock = SocketHandle::new_with_sandbox(
                sandbox_enabled,
                log_violations,
                allowed_networks.clone(),
                Some(capability_ctx.clone()),
                services.clone(),
            );
            match sock.connect(&host, port) {
                Ok(()) => {
                    let r = lua.create_table()?;
                    r.set("host", host)?;
                    r.set("port", port)?;
                    r.set("status", "connected")?;
                    Ok(r)
                }
                Err(e) => Err(mlua::Error::RuntimeError(e)),
            }
        }
    })?;
    socket.set("connect_async", async_connect_fn)?;

    // Async DNS resolve: provider-backed A+AAAA merge (no Tokio lookups).
    let async_resolve_fn = lua.create_function({
        let capability_ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, host: String| {
            let mut addrs = broker_dns_lookup(
                &capability_ctx,
                &services,
                &host,
                NseDnsRecordType::A,
                "socket.resolve_async",
            )
            .map_err(mlua::Error::RuntimeError)?
            .displays();
            let aaaa = broker_dns_lookup(
                &capability_ctx,
                &services,
                &host,
                NseDnsRecordType::Aaaa,
                "socket.resolve_async",
            )
            .map_err(mlua::Error::RuntimeError)?
            .displays();
            addrs.extend(aaaa);

            let r = lua.create_table()?;
            for (index, addr) in addrs.iter().enumerate() {
                r.set(index + 1, addr.clone())?;
            }
            Ok(r)
        }
    })?;
    socket.set("resolve_async", async_resolve_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    socket.set("version", version_fn)?;

    globals.set("socket", socket)?;
    Ok(())
}
