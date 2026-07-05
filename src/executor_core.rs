//! NSE Executor Core - Shared Lua VM setup and library registration
//!
//! Contains the shared logic used by both the synchronous NseExecutor
//! and the asynchronous AsyncNseExecutor. This eliminates code duplication
//! while keeping each executor's specialized methods on their respective types.

use mlua::{Lua, Result as LuaResult, Table, Value};
use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use crate::libraries::shared;
use crate::limits::{
    NseCancellationToken, NseExecutionLimits, NseExecutionStats, NseLimitViolation,
    NseResourceCounters,
};
use crate::profile::{NseModulePolicy, NseScriptPolicy};
use crate::resolver::ScriptResolver;

#[derive(Debug, Clone, Default)]
pub struct SandboxMetrics {
    pub io_handles: usize,
    pub io_violations: usize,
    pub lfs_violations: usize,
    pub os_violations: usize,
}

/// Core Lua VM state shared between sync and async executors.
///
/// Owns the Lua VM, target, script paths, output buffer, and registry.
/// Provides the shared initialization (globals, libraries, require) and
/// common query/mutation methods.
pub struct ExecutorCore {
    pub(crate) lua: Lua,
    pub(crate) target: String,
    pub(crate) scripts_path: Arc<Mutex<Vec<PathBuf>>>,
    pub(crate) output: Mutex<Vec<String>>,
    pub(crate) registry: Mutex<FxHashMap<String, Value>>,
    pub(crate) sandbox: crate::SandboxConfig,
    pub(crate) limits: NseExecutionLimits,
    pub(crate) cancellation: NseCancellationToken,
    pub(crate) resource_counters: Arc<NseResourceCounters>,
    pub(crate) execution_start: Arc<Mutex<Option<Instant>>>,
    pub(crate) lua_instruction_count: Arc<std::sync::atomic::AtomicU64>,
    pub(crate) limit_violation: Arc<Mutex<Option<NseLimitViolation>>>,
    pub(crate) script_policy: NseScriptPolicy,
    pub(crate) module_policy: NseModulePolicy,
}

impl ExecutorCore {
    pub fn new() -> LuaResult<Self> {
        Self::with_sandbox(crate::SandboxConfig::default())
    }

    pub fn with_sandbox(sandbox: crate::SandboxConfig) -> LuaResult<Self> {
        Self::with_policy(
            sandbox,
            NseExecutionLimits::default(),
            NseCancellationToken::new(),
            default_script_policy(),
            default_module_policy(),
        )
    }

    /// Create an executor core with explicit execution limits and cancellation token.
    ///
    /// This is the canonical constructor. Automated surfaces (MCP, agent, REST)
    /// should use `NseExecutionLimits::automated_defaults()` or stricter.
    /// Manual/interactive use should use `NseExecutionLimits::manual_defaults()`.
    pub fn with_policy(
        sandbox: crate::SandboxConfig,
        limits: NseExecutionLimits,
        cancellation: NseCancellationToken,
        script_policy: NseScriptPolicy,
        module_policy: NseModulePolicy,
    ) -> LuaResult<Self> {
        let lua = Lua::new();
        let scripts_path = Arc::new(Mutex::new(vec![]));
        let output = Mutex::new(vec![]);
        let registry = Mutex::new(FxHashMap::default());
        let resource_counters = Arc::new(NseResourceCounters::new());

        let core = Self {
            lua,
            target: String::new(),
            scripts_path: scripts_path.clone(),
            output,
            registry,
            sandbox,
            limits,
            cancellation,
            resource_counters,
            execution_start: Arc::new(Mutex::new(None)),
            lua_instruction_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            limit_violation: Arc::new(Mutex::new(None)),
            script_policy,
            module_policy,
        };

        core.setup_globals()?;
        core.register_libraries()?;
        core.setup_require(scripts_path)?;

        Ok(core)
    }

    /// Create an executor core from a resolved execution profile.
    ///
    /// This is the preferred constructor for surfaces that have an explicit profile.
    pub fn with_profile(profile: &crate::profile::ResolvedNseExecutionProfile) -> LuaResult<Self> {
        Self::with_policy(
            profile.sandbox.clone(),
            profile.limits.clone(),
            NseCancellationToken::new(),
            profile.script_policy.clone(),
            profile.module_policy.clone(),
        )
    }

    pub fn lua(&self) -> &Lua {
        &self.lua
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn set_target(&mut self, target: &str) -> Result<(), String> {
        self.target = target.to_string();
        self.lua
            .globals()
            .get::<Table>("nmap")
            .map_err(|e| e.to_string())?
            .set("target", target)
            .map_err(|e| e.to_string())
    }

    pub fn add_scripts_path(&self, path: PathBuf) {
        if path.exists() && path.is_dir() {
            self.scripts_path.lock().push(path);
        }
    }

    pub fn add_default_scripts_path(&self) {
        if let Ok(home) = std::env::var("HOME") {
            self.add_scripts_path(PathBuf::from(home).join(".nmap").join("nselib"));
        }
        #[cfg(unix)]
        {
            self.add_scripts_path(PathBuf::from("/usr/share/nmap/nselib"));
            self.add_scripts_path(PathBuf::from("/usr/local/share/nmap/nselib"));
        }
        #[cfg(windows)]
        {
            if let Ok(pf) = std::env::var("ProgramFiles") {
                self.add_scripts_path(PathBuf::from(pf).join("Nmap").join("nselib"));
            }
        }
    }

    pub fn set_script_args(&self, args: &str) -> Result<(), String> {
        if args.is_empty() {
            return Ok(());
        }
        let stdnse = self
            .lua
            .globals()
            .get::<Table>("stdnse")
            .map_err(|e| e.to_string())?;
        stdnse.set("script_args", args).map_err(|e| e.to_string())?;
        let args_table = self.lua.create_table().map_err(|e| e.to_string())?;
        for pair in args.split(',') {
            let pair = pair.trim();
            if let Some((key, value)) = pair.split_once('=') {
                args_table
                    .set(key.trim(), value.trim())
                    .map_err(|e| e.to_string())?;
            }
        }
        stdnse.set("args", args_table).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn add_output(&self, output: String) -> Result<(), String> {
        let output_bytes = output.len();

        // Check output size limit
        if let Some(max_output) = self.limits.max_output_bytes {
            let current = self.resource_counters.output_bytes.load(Ordering::Relaxed) as usize;
            if current + output_bytes > max_output {
                *self.limit_violation.lock() = Some(NseLimitViolation::OutputLimitExceeded);
                return Err(format!(
                    "Output limit exceeded: {} + {} > {} bytes",
                    current, output_bytes, max_output
                ));
            }
        }

        self.resource_counters
            .output_bytes
            .fetch_add(output_bytes as u64, Ordering::Relaxed);

        let mut out = self.output.lock();
        out.push(output.clone());
        if let Ok(script_output) = self.lua.globals().get::<Table>("_SCRIPT_OUTPUT") {
            if let Err(e) = script_output.set(out.len(), output) {
                tracing::warn!("NSE add_output: failed to set script output: {}", e);
            }
        }
        Ok(())
    }

    pub fn get_output(&self) -> Vec<String> {
        self.output.lock().clone()
    }

    pub fn get_sandbox_metrics(&self) -> SandboxMetrics {
        let (io_handles, io_violations) = crate::libraries::io::get_io_sandbox_metrics();
        SandboxMetrics {
            io_handles,
            io_violations,
            lfs_violations: crate::libraries::lfs::LFS_SANDBOX_VIOLATIONS
                .load(std::sync::atomic::Ordering::SeqCst),
            os_violations: crate::libraries::os::OS_SANDBOX_VIOLATIONS
                .load(std::sync::atomic::Ordering::SeqCst),
        }
    }

    pub fn get_script_output(&self) -> Result<String, String> {
        let globals = self.lua.globals();
        let script_output = globals
            .get::<Table>("_SCRIPT_OUTPUT")
            .map_err(|e| e.to_string())?;

        let mut result = String::new();
        for (_, v) in script_output.pairs::<Value, Value>().flatten() {
            let val_str = match v {
                Value::String(s) => s.to_string_lossy().to_string(),
                _ => v.to_string().unwrap_or_default(),
            };
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(&val_str);
        }
        Ok(result)
    }

    pub fn run_script(&self, script: &str) -> LuaResult<String> {
        // Pre-check script size limit
        if let Err(violation) = self.limits.check_script_size(script.len()) {
            *self.limit_violation.lock() = Some(violation.clone());
            return Err(mlua::Error::RuntimeError(format!(
                "NSE limit violated: {}",
                violation
            )));
        }

        // Check cancellation before starting
        if self.cancellation.is_cancelled() {
            *self.limit_violation.lock() = Some(NseLimitViolation::ExplicitCancellation);
            return Err(mlua::Error::RuntimeError(
                "Script execution cancelled".into(),
            ));
        }

        // Reset counters and record start time
        *self.execution_start.lock() = Some(Instant::now());
        self.lua_instruction_count.store(0, Ordering::Relaxed);
        self.resource_counters
            .network_operations
            .store(0, Ordering::Relaxed);
        self.resource_counters
            .network_bytes_read
            .store(0, Ordering::Relaxed);
        self.resource_counters
            .network_bytes_written
            .store(0, Ordering::Relaxed);
        self.resource_counters
            .filesystem_operations
            .store(0, Ordering::Relaxed);
        self.resource_counters
            .filesystem_bytes_read
            .store(0, Ordering::Relaxed);
        self.resource_counters
            .output_bytes
            .store(0, Ordering::Relaxed);

        // Install debug hook for cooperative limit enforcement
        self.setup_execution_hook();

        let result = self.lua.load(script).eval::<Value>();

        // Check if a limit was violated during execution
        if let Some(violation) = self.limit_violation.lock().take() {
            return Err(mlua::Error::RuntimeError(format!(
                "NSE limit violated: {}",
                violation
            )));
        }

        match result {
            Ok(result) => {
                if let Ok(output) = self.get_script_output() {
                    if !output.is_empty() {
                        return Ok(output);
                    }
                }
                if !result.is_nil() {
                    return Ok(format!("{:?}", result));
                }
                Ok("Script executed successfully".to_string())
            }
            Err(e) => Err(mlua::Error::RuntimeError(format!(
                "Lua script execution error: {}",
                e
            ))),
        }
    }

    /// Install a Luau interrupt that periodically checks execution limits.
    ///
    /// The interrupt fires periodically (Luau guarantees "eventually", typically
    /// at function calls or loop iterations). On each firing it checks:
    /// - Cancellation token
    /// - Wall-clock deadline
    /// - Lua instruction budget
    fn setup_execution_hook(&self) {
        let cancellation = self.cancellation.clone();
        let deadline = self.limits.wall_clock_timeout.map(|d| {
            let guard = self.execution_start.lock();
            (*guard).unwrap_or_else(Instant::now) + d
        });
        let instruction_budget = self.limits.lua_instruction_budget;
        let instruction_counter = self.lua_instruction_count.clone();
        let violation = self.limit_violation.clone();

        self.lua.set_interrupt(move |_lua| {
            let count = instruction_counter.fetch_add(1, Ordering::Relaxed) + 1;

            // Check cancellation
            if cancellation.is_cancelled() {
                *violation.lock() = Some(NseLimitViolation::ExplicitCancellation);
                return Err(mlua::Error::RuntimeError(
                    "Script execution cancelled".into(),
                ));
            }

            // Check wall-clock deadline
            if let Some(deadline) = deadline {
                if Instant::now() >= deadline {
                    *violation.lock() = Some(NseLimitViolation::WallClockTimeout);
                    return Err(mlua::Error::RuntimeError(
                        "Script execution timed out".into(),
                    ));
                }
            }

            // Check instruction budget
            if let Some(budget) = instruction_budget {
                if count >= budget {
                    *violation.lock() = Some(NseLimitViolation::LuaInstructionBudgetExceeded);
                    return Err(mlua::Error::RuntimeError(
                        "Lua instruction budget exceeded".into(),
                    ));
                }
            }

            Ok(mlua::VmState::Continue)
        });
    }

    /// Get the current execution stats snapshot.
    pub fn execution_stats(&self) -> NseExecutionStats {
        let guard = self.execution_start.lock();
        let elapsed = (*guard).map(|s| s.elapsed()).unwrap_or_default();
        let instructions = self.lua_instruction_count.load(Ordering::Relaxed);
        let mut stats = self.resource_counters.snapshot(elapsed, instructions);
        stats.limit_violation = self.limit_violation.lock().clone();
        stats
    }

    /// Get a reference to the execution limits.
    pub fn limits(&self) -> &NseExecutionLimits {
        &self.limits
    }

    /// Get a reference to the cancellation token.
    pub fn cancellation_token(&self) -> &NseCancellationToken {
        &self.cancellation
    }

    /// Get a reference to the resource counters.
    pub fn resource_counters(&self) -> &NseResourceCounters {
        &self.resource_counters
    }

    /// Return the names of all libraries that were registered into the Lua VM.
    pub fn registered_library_names(&self) -> Vec<&'static str> {
        vec![
            "stdnse",
            "nmap",
            "http",
            "comm",
            "sslcert",
            "tls",
            "shortport",
            "socket",
            "ssh2",
            "ftp",
            "smtp",
            "mysql",
            "postgres",
            "mssql",
            "redis",
            "mongodb",
            "ldap",
            "snmp",
            "smb",
            "smb2",
            "smbauth",
            "rdp",
            "vnc",
            "ntp",
            "memcached",
            "imap",
            "pop3",
            "netbios",
            "oracle",
            "winrm",
            "radius",
            "dhcp",
            "dhcp6",
            "sip",
            "tftp",
            "upnp",
            "tns",
            "afp",
            "amqp",
            "ajp",
            "ncp",
            "ndmp",
            "nrpc",
            "citrixxml",
            "ospf",
            "asn1",
            "sasl",
            "slaxml",
            "re",
            "httpspider",
            "base64",
            "base32",
            "datetime",
            "rand",
            "url",
            "creds",
            "openssl",
            "pcre",
            "io",
            "os",
            "unittest",
            "target",
            "strbuf",
            "tab",
            "stringaux",
            "bin",
            "bit",
            "vulns",
            "unpwdb",
            "brute",
            "datafiles",
            "json",
            "ssh",
            "ssh1",
            "dns",
            "http2",
            "httppipeline",
            "geoip",
            "rpc",
            "sslv2",
            "msrpc",
            "ike",
            "ipp",
            "coap",
            "idna",
            "pgsql",
            "ipops",
            "iax2",
            "drda",
            "eigrp",
            "giop",
            "iscsi",
            "jdwp",
            "rsync",
            "socks",
            "rtsp",
            "tn3270",
            "xmpp",
            "isns",
            "membase",
            "bitcoin",
            "bittorrent",
            "cassandra",
            "dicom",
            "knx",
            "multicast",
            "nbd",
            "natpmp",
            "proxy",
            "srvloc",
            "wsdd",
            "xdmcp",
            "bjnp",
            "cvs",
            "dnssd",
            "eap",
            "pppoe",
            "rpcap",
            "rmi",
            "ipmi",
            "irc",
            "versant",
            "omp2",
            "gps",
            "mobileme",
            "ls",
            "unicode",
            "bits",
            "formulas",
            "anyconnect",
            "iec61850mms",
            "informix",
            "libssh2_utility",
            "matchs",
            "lpeg_utility",
            "lpeg",
            "lfs",
            "libssh2",
            "msrpcperformance",
            "msrpctypes",
            "oops",
            "outlib",
            "punycode",
            "tableaux",
            "vuzedht",
            "listop",
            "zlib",
        ]
    }

    pub fn load_script(&self, name: &str) -> LuaResult<String> {
        if self.cancellation.is_cancelled() {
            return Err(mlua::Error::RuntimeError(
                "Script loading cancelled".to_string(),
            ));
        }
        let paths = self.scripts_path.lock();
        for base in paths.iter() {
            let lua_path = base.join(format!("{}.lua", name));
            if lua_path.exists() {
                // Validate the canonicalized path is under the base directory
                // to prevent traversal via names like "../etc/passwd"
                if let Ok(canonical) = lua_path.canonicalize() {
                    if let Ok(canonical_base) = base.canonicalize() {
                        if !canonical.starts_with(&canonical_base) {
                            return Err(mlua::Error::RuntimeError(format!(
                                "Script '{}' escapes search root",
                                name
                            )));
                        }
                    }
                }
                return Ok(std::fs::read_to_string(&lua_path)?);
            }
            let nse_path = base.join(format!("{}.nse", name));
            if nse_path.exists() {
                if let Ok(canonical) = nse_path.canonicalize() {
                    if let Ok(canonical_base) = base.canonicalize() {
                        if !canonical.starts_with(&canonical_base) {
                            return Err(mlua::Error::RuntimeError(format!(
                                "Script '{}' escapes search root",
                                name
                            )));
                        }
                    }
                }
                return Ok(std::fs::read_to_string(&nse_path)?);
            }
        }
        Err(mlua::Error::RuntimeError(format!(
            "Script '{}' not found in search paths",
            name
        )))
    }

    pub fn set_host_info(
        &self,
        hostname: Option<String>,
        ip: String,
        mac: Option<String>,
        status: Option<String>,
    ) -> Result<(), String> {
        let globals = self.lua.globals();
        let nmap = globals.get::<Table>("nmap").map_err(|e| e.to_string())?;
        let hostinfo = self.lua.create_table().map_err(|e| e.to_string())?;
        hostinfo.set("ip", ip).map_err(|e| e.to_string())?;
        if let Some(h) = hostname {
            hostinfo.set("hostname", h).map_err(|e| e.to_string())?;
        }
        if let Some(m) = mac {
            hostinfo.set("mac", m).map_err(|e| e.to_string())?;
        }
        if let Some(s) = status {
            hostinfo.set("status", s).map_err(|e| e.to_string())?;
        }
        nmap.set("_hostinfo", hostinfo).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn add_port(
        &self,
        port: u16,
        protocol: &str,
        state: &str,
        service: Option<String>,
    ) -> Result<(), String> {
        let globals = self.lua.globals();
        let nmap = globals.get::<Table>("nmap").map_err(|e| e.to_string())?;
        let ports = nmap.get::<Table>("_ports").map_err(|e| e.to_string())?;
        let key = format!("{}.{}.{}", self.target, port, protocol);
        let info = self.lua.create_table().map_err(|e| e.to_string())?;
        info.set("number", port).map_err(|e| e.to_string())?;
        info.set("protocol", protocol).map_err(|e| e.to_string())?;
        info.set("state", state).map_err(|e| e.to_string())?;
        if let Some(svc) = service {
            info.set("service", svc).map_err(|e| e.to_string())?;
        }
        ports.set(key, info).map_err(|e| e.to_string())?;
        Ok(())
    }

    // ---- private init helpers ----

    fn setup_globals(&self) -> LuaResult<()> {
        let globals = self.lua.globals();

        // All NSE module globals — unified list from both executor variants.
        // This includes the full set from the sync executor plus removes duplicates.
        let module_names: &[&str] = &[
            "stdnse",
            "nmap",
            "http",
            "comm",
            "sslcert",
            "tls",
            "shortport",
            "socket",
            "ftp",
            "smtp",
            "mysql",
            "postgres",
            "pgsql",
            "mssql",
            "sybase",
            "redis",
            "mongodb",
            "ldap",
            "snmp",
            "smb",
            "rdp",
            "vnc",
            "ntp",
            "memcached",
            "imap",
            "pop3",
            "netbios",
            "oracle",
            "winrm",
            "radius",
            "dhcp",
            "dhcp6",
            "sip",
            "tftp",
            "upnp",
            "tns",
            "afp",
            "amqp",
            "ajp",
            "ncp",
            "ndmp",
            "nrpc",
            "citrixxml",
            "ospf",
            "asn1",
            "sasl",
            "slaxml",
            "re",
            "httpspider",
            "base64",
            "base32",
            "datetime",
            "rand",
            "url",
            "creds",
            "openssl",
            "pcre",
            "io",
            "os",
            "unittest",
            "target",
            "strbuf",
            "tab",
            "stringaux",
            "bin",
            "bit",
            "vulns",
            "unpwdb",
            "brute",
            "datafiles",
            "json",
            "ssh",
            "ssh1",
            "ssh2",
            "dns",
            "http2",
            "elasticsearch",
            "kafka",
            "mqtt",
            "websocket",
            "telnet",
            "sftp",
            "whois",
            "finger",
            "stun",
            "packet",
            "nsedebug",
            "strict",
            "geoip",
            "rpc",
            "smb2",
            "smbauth",
            "match",
            "sslv2",
            "msrpc",
            "ike",
            "ipp",
            "coap",
            "idna",
            "ipOps",
            "iax2",
            "drda",
            "eigrp",
            "giop",
            "iscsi",
            "jdwp",
            "rsync",
            "socks",
            "rtsp",
            "tn3270",
            "xmpp",
            "isns",
            "membase",
            "bitcoin",
            "bittorrent",
            "cassandra",
            "dicom",
            "knx",
            "multicast",
            "nbd",
            "natpmp",
            "proxy",
            "srvloc",
            "wsdd",
            "xdmcp",
            "bjnp",
            "cvs",
            "dnssd",
            "eap",
            "pppoe",
            "rpcap",
            "rmi",
            "ipmi",
            "irc",
            "versant",
            "omp2",
            "gps",
            "mobileme",
            "ls",
            "unicode",
            "lpeg",
            "lfs",
            "libssh2",
        ];

        for name in module_names {
            globals.set(*name, self.lua.create_table()?)?;
        }

        globals.set("_REQUIRE_MODULES", self.lua.create_table()?)?;
        globals.set("_SCRIPT_OUTPUT", self.lua.create_table()?)?;

        Ok(())
    }

    fn register_libraries(&self) -> LuaResult<()> {
        crate::libraries::stdnse::register_stdlib(&self.lua)?;
        crate::libraries::nmap::register_nmap_library(&self.lua)?;
        crate::libraries::http::register_http_library(&self.lua)?;
        crate::libraries::comm::register_comm_library(&self.lua)?;
        crate::libraries::sslcert::register_sslcert_library(&self.lua)?;
        crate::libraries::tls::register_tls_library(&self.lua)?;
        crate::libraries::shortport::register_shortport_library(&self.lua)?;
        crate::libraries::socket::register_socket_library(&self.lua, &self.sandbox)?;
        crate::libraries::ssh2::register_ssh2_library(&self.lua)?;
        crate::libraries::ftp::register_ftp_library(&self.lua)?;
        crate::libraries::smtp::register_smtp_library(&self.lua)?;
        crate::libraries::mysql::register_mysql_library(&self.lua)?;
        crate::libraries::postgres::register_postgres_library(&self.lua)?;
        crate::libraries::mssql::register_mssql_library(&self.lua)?;
        crate::libraries::redis::register_redis_library(&self.lua)?;
        crate::libraries::mongodb::register_mongodb_library(&self.lua)?;
        crate::libraries::ldap::register_ldap_library(&self.lua)?;
        crate::libraries::snmp::register_snmp_library(&self.lua)?;
        crate::libraries::smb::register_smb_library(&self.lua)?;
        crate::libraries::smb2::register_smb2_library(&self.lua)?;
        crate::libraries::smbauth::register_smbauth_library(&self.lua)?;
        crate::libraries::rdp::register_rdp_library(&self.lua)?;
        crate::libraries::vnc::register_vnc_library(&self.lua)?;
        crate::libraries::ntp::register_ntp_library(&self.lua)?;
        crate::libraries::memcached::register_memcached_library(&self.lua)?;
        crate::libraries::imap::register_imap_library(&self.lua)?;
        crate::libraries::pop3::register_pop3_library(&self.lua)?;
        crate::libraries::netbios::register_netbios_library(&self.lua)?;
        crate::libraries::oracle::register_oracle_library(&self.lua)?;
        crate::libraries::winrm::register_winrm_library(&self.lua)?;
        crate::libraries::radius::register_radius_library(&self.lua)?;
        crate::libraries::dhcp::register_dhcp_library(&self.lua)?;
        crate::libraries::dhcp6::register_dhcp6_library(&self.lua)?;
        crate::libraries::sip::register_sip_library(&self.lua)?;
        crate::libraries::tftp::register_tftp_library(&self.lua)?;
        crate::libraries::upnp::register_upnp_library(&self.lua)?;
        crate::libraries::tns::register_tns_library(&self.lua)?;
        crate::libraries::afp::register_afp_library(&self.lua)?;
        crate::libraries::amqp::register_amqp_library(&self.lua)?;
        crate::libraries::ajp::register_ajp_library(&self.lua)?;
        crate::libraries::ncp::register_ncp_library(&self.lua)?;
        crate::libraries::ndmp::register_ndmp_library(&self.lua)?;
        crate::libraries::nrpc::register_nrpc_library(&self.lua)?;
        crate::libraries::citrixxml::register_citrixxml_library(&self.lua)?;
        crate::libraries::ospf::register_ospf_library(&self.lua)?;
        crate::libraries::asn1::register_asn1_library(&self.lua)?;
        crate::libraries::sasl::register_sasl_library(&self.lua)?;
        crate::libraries::slaxml::register_slaxml_library(&self.lua)?;
        crate::libraries::re::register_re_library(&self.lua)?;
        crate::libraries::httpspider::register_httpspider_library(&self.lua)?;
        crate::libraries::base64::register_base64_library(&self.lua)?;
        crate::libraries::base32::register_base32_library(&self.lua)?;
        crate::libraries::datetime::register_datetime_library(&self.lua)?;
        crate::libraries::rand::register_rand_library(&self.lua)?;
        crate::libraries::url::register_url_library(&self.lua)?;
        crate::libraries::creds::register_creds_library(&self.lua)?;
        crate::libraries::openssl::register_openssl_library(&self.lua)?;
        crate::libraries::pcre::register_pcre_library(&self.lua)?;
        crate::libraries::io::register_io_library(&self.lua, &self.sandbox)?;
        crate::libraries::os::register_os_library(&self.lua, &self.sandbox)?;
        crate::libraries::unittest::register_unittest_library(&self.lua)?;
        crate::libraries::target::register_target_library(&self.lua)?;
        crate::libraries::strbuf::register_strbuf_library(&self.lua)?;
        crate::libraries::tab::register_tab_library(&self.lua)?;
        crate::libraries::stringaux::register_stringaux_library(&self.lua)?;
        crate::libraries::bin::register_bin_library(&self.lua)?;
        crate::libraries::bit::register_bit_library(&self.lua)?;
        crate::libraries::vulns::register_vulns_library(&self.lua)?;
        crate::libraries::unpwdb::register_unpwdb_library(&self.lua)?;
        crate::libraries::brute::register_brute_library(&self.lua)?;
        crate::libraries::datafiles::register_datafiles_library(&self.lua)?;
        crate::libraries::json::register_json_library(&self.lua)?;
        crate::libraries::ssh::register_ssh_library(&self.lua)?;
        crate::libraries::dns::register_dns_library(&self.lua)?;
        crate::libraries::http2::register_http2_library(&self.lua)?;
        crate::libraries::httppipeline::register_httppipeline_library(&self.lua)?;
        crate::libraries::geoip::register_geoip_library(&self.lua)?;
        crate::libraries::rpc::register_rpc_library(&self.lua)?;
        crate::libraries::ssh1::register_ssh1_library(&self.lua)?;
        crate::libraries::sslv2::register_sslv2_library(&self.lua)?;
        crate::libraries::msrpc::register_msrpc_library(&self.lua)?;
        crate::libraries::ike::register_ike_library(&self.lua)?;
        crate::libraries::ipp::register_ipp_library(&self.lua)?;
        crate::libraries::coap::register_coap_library(&self.lua)?;
        crate::libraries::idna::register_idna_library(&self.lua)?;
        crate::libraries::pgsql::register_pgsql_library(&self.lua)?;
        crate::libraries::ipops::register_ipops_library(&self.lua)?;
        crate::libraries::iax2::register_iax2_library(&self.lua)?;
        crate::libraries::drda::register_drda_library(&self.lua)?;
        crate::libraries::eigrp::register_eigrp_library(&self.lua)?;
        crate::libraries::giop::register_giop_library(&self.lua)?;
        crate::libraries::iscsi::register_iscsi_library(&self.lua)?;
        crate::libraries::jdwp::register_jdwp_library(&self.lua)?;
        crate::libraries::rsync::register_rsync_library(&self.lua)?;
        crate::libraries::socks::register_socks_library(&self.lua)?;
        crate::libraries::rtsp::register_rtsp_library(&self.lua)?;
        crate::libraries::tn3270::register_tn3270_library(&self.lua)?;
        crate::libraries::xmpp::register_xmpp_library(&self.lua)?;
        crate::libraries::isns::register_isns_library(&self.lua)?;
        crate::libraries::membase::register_membase_library(&self.lua)?;
        crate::libraries::bitcoin::register_bitcoin_library(&self.lua)?;
        crate::libraries::bittorrent::register_bittorrent_library(&self.lua)?;
        crate::libraries::cassandra::register_cassandra_library(&self.lua)?;
        crate::libraries::dicom::register_dicom_library(&self.lua)?;
        crate::libraries::knx::register_knx_library(&self.lua)?;
        crate::libraries::multicast::register_multicast_library(&self.lua)?;
        crate::libraries::nbd::register_nbd_library(&self.lua)?;
        crate::libraries::natpmp::register_natpmp_library(&self.lua)?;
        crate::libraries::proxy::register_proxy_library(&self.lua)?;
        crate::libraries::srvloc::register_srvloc_library(&self.lua)?;
        crate::libraries::wsdd::register_wsdd_library(&self.lua)?;
        crate::libraries::xdmcp::register_xdmcp_library(&self.lua)?;
        crate::libraries::bjnp::register_bjnp_library(&self.lua)?;
        crate::libraries::cvs::register_cvs_library(&self.lua)?;
        crate::libraries::dnssd::register_dnssd_library(&self.lua)?;
        crate::libraries::eap::register_eap_library(&self.lua)?;
        crate::libraries::pppoe::register_pppoe_library(&self.lua)?;
        crate::libraries::rpcap::register_rpcap_library(&self.lua)?;
        crate::libraries::rmi::register_rmi_library(&self.lua)?;
        crate::libraries::ipmi::register_ipmi_library(&self.lua)?;
        crate::libraries::irc::register_irc_library(&self.lua)?;
        crate::libraries::versant::register_versant_library(&self.lua)?;
        crate::libraries::omp2::register_omp2_library(&self.lua)?;
        crate::libraries::gps::register_gps_library(&self.lua)?;
        crate::libraries::mobileme::register_mobileme_library(&self.lua)?;
        crate::libraries::ls::register_ls_library(&self.lua)?;
        crate::libraries::unicode::register_unicode_library(&self.lua)?;
        crate::libraries::bits::register_bits_library(&self.lua)?;
        crate::libraries::formulas::register_formulas_library(&self.lua)?;
        crate::libraries::anyconnect::register_anyconnect_library(&self.lua)?;
        crate::libraries::iec61850mms::register_iec61850mms_library(&self.lua)?;
        crate::libraries::informix::register_informix_library(&self.lua)?;
        crate::libraries::libssh2_utility::register_libssh2_utility_library(&self.lua)?;
        crate::libraries::matchs::register_matchs_library(&self.lua)?;
        crate::libraries::lpeg_utility::register_lpeg_utility_library(&self.lua)?;
        crate::libraries::lpeg::register_lpeg_library(&self.lua)?;
        crate::libraries::lfs::register_lfs_library(&self.lua, &self.sandbox)?;
        crate::libraries::libssh2::register_libssh2_library(&self.lua)?;
        crate::libraries::msrpcperformance::register_msrpcperformance_library(&self.lua)?;
        crate::libraries::msrpctypes::register_msrpctypes_library(&self.lua)?;
        crate::libraries::oops::register_oops_library(&self.lua)?;
        crate::libraries::outlib::register_outlib_library(&self.lua)?;
        crate::libraries::punycode::register_punycode_library(&self.lua)?;
        crate::libraries::tableaux::register_tableaux_library(&self.lua)?;
        crate::libraries::vuzedht::register_vuzedht_library(&self.lua)?;
        crate::libraries::listop::register_listop_library(&self.lua)?;
        crate::libraries::zlib::register_zlib_library(&self.lua)?;

        self.sync_require_modules()
    }

    fn sync_require_modules(&self) -> LuaResult<()> {
        shared::sync_require_modules(&self.lua)
    }

    fn setup_require(&self, _scripts_path: Arc<Mutex<Vec<PathBuf>>>) -> LuaResult<()> {
        let cache: Arc<Mutex<FxHashMap<String, Value>>> =
            Arc::new(Mutex::new(FxHashMap::default()));
        let script_policy = self.script_policy.clone();
        let module_policy = self.module_policy.clone();
        let limits = self.limits.clone();
        let cancellation = self.cancellation.clone();

        let require_fn = self.lua.create_function(move |lua, name: String| {
            if cancellation.is_cancelled() {
                return Err(mlua::Error::RuntimeError(
                    "Require cancelled".to_string(),
                ));
            }
            {
                let g = cache.lock();
                if let Some(cached) = g.get(&name) {
                    return Ok(cached.clone());
                }
            }

            let globals = lua.globals();

            // Check _REQUIRE_MODULES
            if let Ok(modules) = globals.get::<Table>("_REQUIRE_MODULES") {
                if let Ok(module) = modules.get::<Table>(name.as_str()) {
                    cache
                        .lock()
                        .insert(name.clone(), Value::Table(module.clone()));
                    return Ok(Value::Table(module));
                }
            }

            // Check global table
            if let Ok(module) = globals.get::<Table>(name.as_str()) {
                if let Ok(modules) = globals.get::<Table>("_REQUIRE_MODULES") {
                    if let Err(e) = modules.set(name.clone(), module.clone()) {
                        tracing::warn!("NSE require: failed to cache module '{}' in _REQUIRE_MODULES: {}", name, e);
                    }
                }
                cache
                    .lock()
                    .insert(name.clone(), Value::Table(module.clone()));
                return Ok(Value::Table(module));
            }

            // Delegate filesystem module loading to ScriptResolver.
            // The resolver enforces: module-name grammar, allow_filesystem_modules,
            // allowed_module_roots, canonical root containment, symlink escape
            // rejection, extension allowlist, and max_required_module_bytes.
            let mut resolver = ScriptResolver::new(
                script_policy.clone(),
                module_policy.clone(),
                limits.clone(),
            );

            match resolver.resolve_module(&name) {
                Ok(Some(resolved)) => {
                    // Evaluate the loaded module content
                    match lua.load(&resolved.content).eval::<Value>() {
                        Ok(value) => {
                            // Cache successful loads in _REQUIRE_MODULES
                            let globals = lua.globals();
                            if let Ok(modules) = globals.get::<Table>("_REQUIRE_MODULES") {
                                if let Err(e) = modules.set(name.clone(), value.clone()) {
                                    tracing::warn!("NSE require: failed to cache module '{}' in _REQUIRE_MODULES: {}", name, e);
                                }
                            }
                            cache.lock().insert(name.clone(), value.clone());
                            return Ok(value);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "NSE require: failed to evaluate module '{}' from '{}': {}",
                                name,
                                resolved.path.as_deref().map(|p| p.display().to_string()).unwrap_or_else(|| "unknown".to_string()),
                                e
                            );
                            return Err(mlua::Error::RuntimeError(format!(
                                "module '{}' eval error: {}",
                                name, e
                            )));
                        }
                    }
                }
                Ok(None) => {
                    // Module not found in filesystem (resolver returned None)
                    // This means either filesystem modules are disallowed by policy,
                    // no module roots are configured, or the module wasn't found.
                    tracing::debug!(
                        "NSE require: module '{}' not found in filesystem (policy: filesystem_modules={})",
                        name,
                        module_policy.allow_filesystem_modules
                    );
                }
                Err(e) => {
                    tracing::warn!("NSE require: resolver rejected module '{}': {}", name, e);
                    return Err(mlua::Error::RuntimeError(format!(
                        "module '{}' not found: {}",
                        name, e
                    )));
                }
            }

            Err(mlua::Error::RuntimeError(format!(
                "module '{}' not found",
                name
            )))
        })?;

        self.lua.globals().set("require", require_fn)?;
        Ok(())
    }
}

/// Permissive script policy for manual/interactive use.
pub fn default_script_policy() -> NseScriptPolicy {
    NseScriptPolicy {
        allow_builtin_scripts: true,
        allow_script_files: true,
        allowed_script_roots: Vec::new(),
        allow_conventional_nmap_paths: true,
        max_script_bytes: None,
    }
}

/// Permissive module policy for manual/interactive use.
pub fn default_module_policy() -> NseModulePolicy {
    NseModulePolicy {
        allow_builtin_modules: true,
        allow_filesystem_modules: true,
        allowed_module_roots: Vec::new(),
        max_module_bytes: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_creation() {
        let core = ExecutorCore::new();
        assert!(core.is_ok());
    }

    #[test]
    fn test_set_target() {
        let mut core = ExecutorCore::new().unwrap();
        assert!(core.set_target("example.com").is_ok());
        assert_eq!(core.target(), "example.com");
    }
}
