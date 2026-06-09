use rustc_hash::FxHashMap;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct HostInfo {
    pub ip: String,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub os: Option<String>,
    pub address_family: String,
}

impl HostInfo {
    pub fn new(ip: String) -> Self {
        Self {
            ip,
            hostname: None,
            mac: None,
            os: None,
            address_family: "inet".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortInfo {
    pub number: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
}

impl PortInfo {
    pub fn new(number: u16, protocol: String, state: String) -> Self {
        Self {
            number,
            protocol,
            state,
            service: None,
            version: None,
        }
    }

    pub fn to_table(&self, lua: &mlua::Lua) -> mlua::Result<mlua::Table> {
        let table = lua.create_table()?;
        table.set("number", self.number)?;
        table.set("protocol", self.protocol.as_str())?;
        table.set("state", self.state.as_str())?;
        if let Some(ref svc) = self.service {
            table.set("service", svc.as_str())?;
        }
        if let Some(ref ver) = self.version {
            table.set("version", ver.as_str())?;
        }
        Ok(table)
    }
}

#[derive(Debug, Clone)]
pub struct ScriptOutputSection {
    pub key: String,
    pub value: String,
    pub output_type: String,
}

#[derive(Debug, Clone)]
pub struct ScriptOutput {
    pub lines: Vec<String>,
    pub output_table: Option<FxHashMap<String, String>>,
    pub severity: String,
    pub sections: Vec<ScriptOutputSection>,
    pub raw_output: String,
}

impl ScriptOutput {
    pub fn new() -> Self {
        Self {
            lines: Vec::new(),
            output_table: None,
            severity: "ok".to_string(),
            sections: Vec::new(),
            raw_output: String::new(),
        }
    }

    pub fn add_line(&mut self, line: String) {
        self.lines.push(line.clone());
        if !self.raw_output.is_empty() {
            self.raw_output.push('\n');
        }
        self.raw_output.push_str(&line);
    }

    pub fn add_section(&mut self, key: String, value: String) {
        self.sections.push(ScriptOutputSection {
            key: key.clone(),
            value: value.clone(),
            output_type: "table".to_string(),
        });
        let line = format!("{}: {}", key, value);
        self.add_line(line);
    }

    pub fn set_table(&mut self, table: FxHashMap<String, String>) {
        self.output_table = Some(table);
    }

    pub fn to_nse_string(&self) -> String {
        let mut output = String::new();

        for section in &self.sections {
            output.push_str(&section.key);
            output.push_str(": ");
            output.push_str(&section.value);
            output.push('\n');
        }

        if !self.lines.is_empty() {
            output.push_str(&self.lines.join("\n"));
        }

        output
    }

    pub fn clear(&mut self) {
        self.lines.clear();
        self.output_table = None;
        self.sections.clear();
        self.raw_output.clear();
        self.severity = "ok".to_string();
    }
}

impl Default for ScriptOutput {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ScanContext {
    pub host: Option<HostInfo>,
    pub ports: FxHashMap<(u16, String), PortInfo>,
    pub target_port: Option<PortInfo>,
    pub output: ScriptOutput,
    pub registry: FxHashMap<String, mlua::Value>,
    pub script_name: Option<String>,
    pub verbose: Option<i32>,
}

impl ScanContext {
    pub fn new() -> Self {
        Self {
            host: None,
            ports: FxHashMap::default(),
            target_port: None,
            output: ScriptOutput::new(),
            registry: FxHashMap::default(),
            script_name: None,
            verbose: Some(1),
        }
    }

    pub fn with_target(target: &str) -> Self {
        let mut ctx = Self::new();
        ctx.host = Some(HostInfo::new(target.to_string()));
        ctx
    }

    pub fn set_verbose(&mut self, level: i32) {
        self.verbose = Some(level);
    }

    pub fn set_host(&mut self, host: HostInfo) {
        self.host = Some(host);
    }

    pub fn add_port(&mut self, port: PortInfo) {
        self.ports
            .insert((port.number, port.protocol.clone()), port);
    }

    pub fn set_target_port(&mut self, port: PortInfo) {
        self.target_port = Some(port.clone());
        self.add_port(port);
    }

    pub fn get_port(&self, number: u16, protocol: &str) -> Option<&PortInfo> {
        self.ports.get(&(number, protocol.to_string()))
    }

    pub fn get_all_ports(&self) -> Vec<&PortInfo> {
        self.ports.values().collect()
    }

    pub fn add_output(&mut self, line: String) {
        self.output.add_line(line);
    }

    pub fn set_severity(&mut self, severity: &str) {
        self.output.severity = severity.to_string();
    }

    pub fn get_output(&self) -> String {
        self.output.to_nse_string()
    }

    pub fn get_raw_output(&self) -> String {
        self.output.raw_output.clone()
    }

    pub fn add_output_section(&mut self, key: String, value: String) {
        self.output.add_section(key, value);
    }

    pub fn get_output_sections(&self) -> &Vec<ScriptOutputSection> {
        &self.output.sections
    }

    pub fn set_output_table(&mut self, table: FxHashMap<String, String>) {
        self.output.set_table(table);
    }

    pub fn get_output_table(&self) -> Option<&FxHashMap<String, String>> {
        self.output.output_table.as_ref()
    }

    pub fn clear_output(&mut self) {
        self.output.clear();
    }

    pub fn set_registry(&mut self, key: String, value: mlua::Value) {
        self.registry.insert(key, value);
    }

    pub fn get_registry(&self, key: &str) -> Option<&mlua::Value> {
        self.registry.get(key)
    }

    pub fn to_host_table(&self, lua: &mlua::Lua) -> mlua::Result<mlua::Table> {
        let table = lua.create_table()?;

        if let Some(ref host) = self.host {
            table.set("ip", host.ip.as_str())?;

            if let Some(ref hostname) = host.hostname {
                table.set("name", hostname.as_str())?;
                table.set("hostname", hostname.as_str())?;
            }

            if let Some(ref mac) = host.mac {
                table.set("mac", mac.as_str())?;
            }

            if let Some(ref os) = host.os {
                let os_table = lua.create_table()?;
                os_table.set("name", os.as_str())?;
                table.set("os", os_table)?;
            }

            table.set("address_family", host.address_family.as_str())?;

            table.set("binip", host.ip.as_str())?;
        }

        Ok(table)
    }

    pub fn to_port_table(&self, lua: &mlua::Lua) -> mlua::Result<mlua::Table> {
        if let Some(ref port) = self.target_port {
            return port.to_table(lua);
        }
        lua.create_table()
    }
}

impl Default for ScanContext {
    fn default() -> Self {
        Self::new()
    }
}

pub struct NseState {
    pub context: Arc<parking_lot::Mutex<ScanContext>>,
    pub scripts_path: Vec<std::path::PathBuf>,
}

impl NseState {
    pub fn new() -> Self {
        Self {
            context: Arc::new(parking_lot::Mutex::new(ScanContext::new())),
            scripts_path: Vec::new(),
        }
    }

    pub fn with_target(target: &str) -> Self {
        Self {
            context: Arc::new(parking_lot::Mutex::new(ScanContext::with_target(target))),
            scripts_path: Vec::new(),
        }
    }

    pub fn get_context(&self) -> Arc<parking_lot::Mutex<ScanContext>> {
        self.context.clone()
    }

    pub fn add_scripts_path(&mut self, path: std::path::PathBuf) {
        if path.exists() && path.is_dir() {
            self.scripts_path.push(path);
        }
    }
}

impl Default for NseState {
    fn default() -> Self {
        Self::new()
    }
}
