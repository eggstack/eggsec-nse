//! NSE execution profiles for explicit runtime policy selection.
//!
//! Profiles resolve into concrete sandbox, limits, script policy, module policy,
//! and network policy configurations. Manual and automated surfaces no longer
//! share implicit permissive defaults.

use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

use ipnetwork::IpNetwork;

use crate::limits::NseExecutionLimits;
use crate::SandboxConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum NseExecutionProfileKind {
    ManualPermissive,
    ManualStrict,
    AgentSafe,
    CiSafe,
    CompatibilityLab,
}

impl fmt::Display for NseExecutionProfileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManualPermissive => write!(f, "manual-permissive"),
            Self::ManualStrict => write!(f, "manual-strict"),
            Self::AgentSafe => write!(f, "agent-safe"),
            Self::CiSafe => write!(f, "ci-safe"),
            Self::CompatibilityLab => write!(f, "compatibility-lab"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NseNetworkPolicy {
    AllowAllManual,
    DenyAll,
    AllowCidrs(Vec<IpNetwork>),
    AllowResolvedTargetSet(Vec<IpAddr>),
}

#[derive(Debug, Clone)]
pub struct NseScriptPolicy {
    pub allow_builtin_scripts: bool,
    pub allow_script_files: bool,
    pub allowed_script_roots: Vec<PathBuf>,
    pub allow_conventional_nmap_paths: bool,
    pub max_script_bytes: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct NseModulePolicy {
    pub allow_builtin_modules: bool,
    pub allow_filesystem_modules: bool,
    pub allowed_module_roots: Vec<PathBuf>,
    pub max_module_bytes: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct ResolvedNseExecutionProfile {
    pub kind: NseExecutionProfileKind,
    pub sandbox: SandboxConfig,
    pub limits: NseExecutionLimits,
    pub script_policy: NseScriptPolicy,
    pub module_policy: NseModulePolicy,
    pub network_policy: NseNetworkPolicy,
    pub audit_label: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ScopeInput {
    pub target_ip: Option<IpAddr>,
    pub resolved_ips: Vec<IpAddr>,
    pub scope_cidrs: Vec<IpNetwork>,
}

impl ResolvedNseExecutionProfile {
    pub fn manual_permissive(target: Option<&str>) -> Self {
        let mut warnings = Vec::new();

        let sandbox = SandboxConfig {
            enabled: cfg!(feature = "sandbox"),
            allowed_dir: Some(PathBuf::from("/tmp/eggsec-nse")),
            allowed_commands: Vec::new(),
            log_violations: true,
            allowed_networks: Vec::new(),
        };

        if !cfg!(feature = "sandbox") {
            warnings
                .push("sandbox feature not compiled; sandbox enforcement is disabled".to_string());
        }

        let network_policy = match target.and_then(|t| t.parse::<IpAddr>().ok()) {
            Some(ip) => NseNetworkPolicy::AllowResolvedTargetSet(vec![ip]),
            None => NseNetworkPolicy::AllowAllManual,
        };

        Self {
            kind: NseExecutionProfileKind::ManualPermissive,
            sandbox,
            limits: NseExecutionLimits::manual_defaults(),
            script_policy: NseScriptPolicy {
                allow_builtin_scripts: true,
                allow_script_files: true,
                allowed_script_roots: Vec::new(),
                allow_conventional_nmap_paths: true,
                max_script_bytes: None,
            },
            module_policy: NseModulePolicy {
                allow_builtin_modules: true,
                allow_filesystem_modules: true,
                allowed_module_roots: Vec::new(),
                max_module_bytes: None,
            },
            network_policy,
            audit_label: "nse:manual-permissive".to_string(),
            warnings,
        }
    }

    pub fn manual_strict(target: Option<&str>, scope_cidrs: &[IpNetwork]) -> Self {
        let mut warnings = Vec::new();
        warnings.extend(Self::sandbox_warning_if_needed_inner());

        let sandbox = SandboxConfig {
            enabled: cfg!(feature = "sandbox"),
            allowed_dir: Some(PathBuf::from("/tmp/eggsec-nse")),
            allowed_commands: Vec::new(),
            log_violations: false,
            allowed_networks: scope_cidrs.to_vec(),
        };

        let network_policy = if !scope_cidrs.is_empty() {
            NseNetworkPolicy::AllowCidrs(scope_cidrs.to_vec())
        } else if let Some(ip) = target.and_then(|t| t.parse::<IpAddr>().ok()) {
            NseNetworkPolicy::AllowResolvedTargetSet(vec![ip])
        } else {
            NseNetworkPolicy::DenyAll
        };

        Self {
            kind: NseExecutionProfileKind::ManualStrict,
            sandbox,
            limits: NseExecutionLimits {
                wall_clock_timeout: Some(std::time::Duration::from_secs(60)),
                max_filesystem_operations: Some(200),
                max_filesystem_bytes_read: Some(20 * 1024 * 1024),
                ..NseExecutionLimits::default()
            },
            script_policy: NseScriptPolicy {
                allow_builtin_scripts: true,
                allow_script_files: true,
                allowed_script_roots: vec![PathBuf::from("/tmp/eggsec-nse")],
                allow_conventional_nmap_paths: false,
                max_script_bytes: Some(5 * 1024 * 1024),
            },
            module_policy: NseModulePolicy {
                allow_builtin_modules: true,
                allow_filesystem_modules: true,
                allowed_module_roots: vec![PathBuf::from("/tmp/eggsec-nse")],
                max_module_bytes: Some(2 * 1024 * 1024),
            },
            network_policy,
            audit_label: "nse:manual-strict".to_string(),
            warnings,
        }
    }

    pub fn agent_safe(target: &str, scope_cidrs: &[IpNetwork]) -> Self {
        let mut warnings = Vec::new();
        warnings.extend(Self::sandbox_warning_if_needed_inner());

        let sandbox = SandboxConfig {
            enabled: cfg!(feature = "sandbox"),
            allowed_dir: Some(PathBuf::from("/tmp/eggsec-nse")),
            allowed_commands: Vec::new(),
            log_violations: false,
            allowed_networks: scope_cidrs.to_vec(),
        };

        let network_policy = if !scope_cidrs.is_empty() {
            NseNetworkPolicy::AllowCidrs(scope_cidrs.to_vec())
        } else if let Ok(ip) = target.parse::<IpAddr>() {
            NseNetworkPolicy::AllowResolvedTargetSet(vec![ip])
        } else {
            NseNetworkPolicy::DenyAll
        };

        Self {
            kind: NseExecutionProfileKind::AgentSafe,
            sandbox,
            limits: NseExecutionLimits::automated_defaults(),
            script_policy: NseScriptPolicy {
                allow_builtin_scripts: true,
                allow_script_files: false,
                allowed_script_roots: Vec::new(),
                allow_conventional_nmap_paths: false,
                max_script_bytes: Some(1024 * 1024),
            },
            module_policy: NseModulePolicy {
                allow_builtin_modules: true,
                allow_filesystem_modules: false,
                allowed_module_roots: Vec::new(),
                max_module_bytes: Some(512 * 1024),
            },
            network_policy,
            audit_label: "nse:agent-safe".to_string(),
            warnings,
        }
    }

    pub fn ci_safe() -> Self {
        let mut warnings = Vec::new();
        warnings.extend(Self::sandbox_warning_if_needed_inner());

        Self {
            kind: NseExecutionProfileKind::CiSafe,
            sandbox: SandboxConfig {
                enabled: cfg!(feature = "sandbox"),
                allowed_dir: Some(PathBuf::from("/tmp/eggsec-nse")),
                allowed_commands: Vec::new(),
                log_violations: false,
                allowed_networks: Vec::new(),
            },
            limits: NseExecutionLimits {
                wall_clock_timeout: Some(std::time::Duration::from_secs(5)),
                lua_instruction_budget: Some(1_000_000),
                max_output_bytes: Some(512 * 1024),
                max_script_bytes: Some(256 * 1024),
                max_required_module_bytes: Some(128 * 1024),
                max_network_operations: Some(0),
                max_network_bytes_read: Some(0),
                max_network_bytes_written: Some(0),
                max_filesystem_operations: Some(10),
                max_filesystem_bytes_read: Some(1024 * 1024),
                max_lua_memory_bytes: Some(16 * 1024 * 1024),
            },
            script_policy: NseScriptPolicy {
                allow_builtin_scripts: true,
                allow_script_files: false,
                allowed_script_roots: vec![PathBuf::from("/tmp/eggsec-nse/fixtures")],
                allow_conventional_nmap_paths: false,
                max_script_bytes: Some(256 * 1024),
            },
            module_policy: NseModulePolicy {
                allow_builtin_modules: true,
                allow_filesystem_modules: false,
                allowed_module_roots: vec![PathBuf::from("/tmp/eggsec-nse/fixtures")],
                max_module_bytes: Some(128 * 1024),
            },
            network_policy: NseNetworkPolicy::DenyAll,
            audit_label: "nse:ci-safe".to_string(),
            warnings,
        }
    }

    pub fn compatibility_lab(target: Option<&str>) -> Self {
        let mut warnings = Vec::new();
        warnings.push(
            "compatibility-lab profile is not agent-safe; do not use in automated surfaces"
                .to_string(),
        );
        warnings.extend(Self::sandbox_warning_if_needed_inner());

        let network_policy = match target.and_then(|t| t.parse::<IpAddr>().ok()) {
            Some(ip) => NseNetworkPolicy::AllowResolvedTargetSet(vec![ip]),
            None => NseNetworkPolicy::AllowAllManual,
        };

        Self {
            kind: NseExecutionProfileKind::CompatibilityLab,
            sandbox: SandboxConfig {
                enabled: cfg!(feature = "sandbox"),
                allowed_dir: Some(PathBuf::from("/tmp/eggsec-nse")),
                allowed_commands: Vec::new(),
                log_violations: true,
                allowed_networks: Vec::new(),
            },
            limits: NseExecutionLimits::manual_defaults(),
            script_policy: NseScriptPolicy {
                allow_builtin_scripts: true,
                allow_script_files: true,
                allowed_script_roots: vec![
                    PathBuf::from("/tmp/eggsec-nse"),
                    PathBuf::from("/usr/share/nmap/scripts"),
                    PathBuf::from("/usr/local/share/nmap/scripts"),
                ],
                allow_conventional_nmap_paths: true,
                max_script_bytes: Some(10 * 1024 * 1024),
            },
            module_policy: NseModulePolicy {
                allow_builtin_modules: true,
                allow_filesystem_modules: true,
                allowed_module_roots: vec![
                    PathBuf::from("/tmp/eggsec-nse"),
                    PathBuf::from("/usr/share/nmap/nselib"),
                    PathBuf::from("/usr/local/share/nmap/nselib"),
                ],
                max_module_bytes: Some(5 * 1024 * 1024),
            },
            network_policy,
            audit_label: "nse:compatibility-lab".to_string(),
            warnings,
        }
    }

    fn sandbox_warning_if_needed_inner() -> Vec<String> {
        if cfg!(feature = "sandbox") {
            Vec::new()
        } else {
            vec!["sandbox feature not compiled; sandbox enforcement is disabled".to_string()]
        }
    }
}
