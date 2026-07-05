use std::fmt;

use serde::{Deserialize, Serialize};

use crate::limits::{NseExecutionLimits, NseExecutionStats};
use crate::profile::ResolvedNseExecutionProfile;
use crate::resolver::{NseLoadDiagnostic, NseScriptSource};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NseRunReport {
    pub target: String,
    pub script_name: String,
    pub script_source: NseScriptSourceSummary,
    pub profile: NseProfileSummary,
    pub sandbox: NseSandboxSummary,
    pub limits: NseLimitsSummary,
    pub stats: NseExecutionStatsSummary,
    pub resolver: NseResolverSummary,
    pub libraries: Vec<NseLibraryUseReport>,
    pub rules: Vec<NseRuleEvaluationReport>,
    pub output: NseOutputSummary,
    pub compatibility: NseCompatibilitySummary,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NseScriptSourceSummary {
    pub kind: String,
    pub label: String,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NseProfileSummary {
    pub kind: String,
    pub audit_label: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NseSandboxSummary {
    pub enabled: bool,
    pub feature_compiled: bool,
    pub allowed_dir: Option<String>,
    pub allowed_commands_count: usize,
    pub allowed_networks_count: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NseLimitsSummary {
    pub wall_clock_timeout_secs: Option<f64>,
    pub lua_instruction_budget: Option<u64>,
    pub max_output_bytes: Option<usize>,
    pub max_script_bytes: Option<usize>,
    pub max_required_module_bytes: Option<usize>,
    pub max_network_operations: Option<u64>,
    pub max_filesystem_operations: Option<u64>,
    pub max_lua_memory_bytes: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NseExecutionStatsSummary {
    pub elapsed_secs: f64,
    pub output_bytes: usize,
    pub lua_instruction_count: u64,
    pub network_operations: u64,
    pub network_bytes_read: u64,
    pub network_bytes_written: u64,
    pub filesystem_operations: u64,
    pub filesystem_bytes_read: u64,
    pub limit_violation: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NseResolverSummary {
    pub total_diagnostics: usize,
    pub resolved_count: usize,
    pub blocked_count: usize,
    pub rejected_count: usize,
    pub diagnostics: Vec<NseResolverDiagnosticSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NseResolverDiagnosticSummary {
    pub kind: String,
    pub source: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NseLibraryUseReport {
    pub name: String,
    pub category: String,
    pub registered: bool,
    pub side_effects: Vec<String>,
    pub fallback_behavior: String,
    pub notes: String,
    pub loaded: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NseRuleEvaluationReport {
    pub kind: String,
    pub evaluated: bool,
    pub matched: bool,
    pub exactness: String,
    pub error: Option<String>,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsupported: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NseOutputSummary {
    pub has_output: bool,
    pub content: String,
    pub line_count: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NseCompatibilitySummary {
    pub status: NseRunCompatibilityStatus,
    pub fidelity: NseRunFidelity,
    pub unsupported_features: Vec<String>,
    pub approximations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NseRunCompatibilityStatus {
    Compatible,
    CompatibleWithWarnings,
    Partial,
    Unsupported,
    Failed,
    Unknown,
}

impl fmt::Display for NseRunCompatibilityStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compatible => write!(f, "compatible"),
            Self::CompatibleWithWarnings => write!(f, "compatible-with-warnings"),
            Self::Partial => write!(f, "partial"),
            Self::Unsupported => write!(f, "unsupported"),
            Self::Failed => write!(f, "failed"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NseRunFidelity {
    Full,
    Approximate,
    Minimal,
    Unknown,
}

impl fmt::Display for NseRunFidelity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::Approximate => write!(f, "approximate"),
            Self::Minimal => write!(f, "minimal"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl NseRunReport {
    pub fn new(target: &str, script_name: &str) -> Self {
        Self {
            target: target.to_string(),
            script_name: script_name.to_string(),
            script_source: NseScriptSourceSummary {
                kind: "unknown".to_string(),
                label: String::new(),
                size: 0,
            },
            profile: NseProfileSummary {
                kind: "unknown".to_string(),
                audit_label: String::new(),
                warnings: Vec::new(),
            },
            sandbox: NseSandboxSummary {
                enabled: false,
                feature_compiled: false,
                allowed_dir: None,
                allowed_commands_count: 0,
                allowed_networks_count: 0,
            },
            limits: NseLimitsSummary::default(),
            stats: NseExecutionStatsSummary::default(),
            resolver: NseResolverSummary::default(),
            libraries: Vec::new(),
            rules: Vec::new(),
            output: NseOutputSummary {
                has_output: false,
                content: String::new(),
                line_count: 0,
                truncated: false,
            },
            compatibility: NseCompatibilitySummary {
                status: NseRunCompatibilityStatus::Unknown,
                fidelity: NseRunFidelity::Unknown,
                unsupported_features: Vec::new(),
                approximations: Vec::new(),
            },
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn with_profile(mut self, profile: &ResolvedNseExecutionProfile) -> Self {
        self.profile = NseProfileSummary {
            kind: profile.kind.to_string(),
            audit_label: profile.audit_label.clone(),
            warnings: profile.warnings.clone(),
        };
        self.sandbox = NseSandboxSummary {
            enabled: profile.sandbox.enabled,
            feature_compiled: cfg!(feature = "sandbox"),
            allowed_dir: profile
                .sandbox
                .allowed_dir
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            allowed_commands_count: profile.sandbox.allowed_commands.len(),
            allowed_networks_count: profile.sandbox.allowed_networks.len(),
        };
        self.limits = NseLimitsSummary::from(&profile.limits);
        self.warnings.extend(profile.warnings.iter().cloned());
        self
    }

    pub fn with_script_source(mut self, source: &NseScriptSource) -> Self {
        self.script_source = NseScriptSourceSummary::from(source);
        self
    }

    pub fn with_stats(mut self, stats: &NseExecutionStats) -> Self {
        self.stats = NseExecutionStatsSummary::from(stats);
        self
    }

    pub fn with_resolver_diagnostics(mut self, diagnostics: &[NseLoadDiagnostic]) -> Self {
        let mut resolved = 0;
        let mut blocked = 0;
        let mut rejected = 0;
        let mut summaries = Vec::new();

        for diag in diagnostics {
            let (kind_str, source, detail) = match diag {
                NseLoadDiagnostic::Resolved { source, bytes } => {
                    resolved += 1;
                    ("resolved", source.to_string(), format!("{} bytes", bytes))
                }
                NseLoadDiagnostic::Blocked { source, reason } => {
                    blocked += 1;
                    ("blocked", source.to_string(), reason.clone())
                }
                NseLoadDiagnostic::OutsideRoot { path, root } => {
                    rejected += 1;
                    (
                        "outside_root",
                        path.display().to_string(),
                        format!("root: {}", root.display()),
                    )
                }
                NseLoadDiagnostic::SymlinkRejected { path, resolved: r } => {
                    rejected += 1;
                    (
                        "symlink_rejected",
                        path.display().to_string(),
                        format!("-> {}", r.display()),
                    )
                }
                NseLoadDiagnostic::ModuleNameRejected { name, reason } => {
                    rejected += 1;
                    ("module_name_rejected", name.clone(), reason.clone())
                }
                NseLoadDiagnostic::OversizedRejected {
                    source,
                    size,
                    limit,
                } => {
                    rejected += 1;
                    (
                        "oversized_rejected",
                        source.to_string(),
                        format!("{} > {} bytes", size, limit),
                    )
                }
                NseLoadDiagnostic::ModuleLoadFailed {
                    name, path, error, ..
                } => {
                    rejected += 1;
                    (
                        "module_load_failed",
                        name.clone(),
                        format!("{}: {}", path.display(), error),
                    )
                }
            };

            summaries.push(NseResolverDiagnosticSummary {
                kind: kind_str.to_string(),
                source,
                detail,
            });
        }

        self.resolver = NseResolverSummary {
            total_diagnostics: diagnostics.len(),
            resolved_count: resolved,
            blocked_count: blocked,
            rejected_count: rejected,
            diagnostics: summaries,
        };
        self
    }

    pub fn with_rules(mut self, rules: Vec<NseRuleEvaluationReport>) -> Self {
        self.rules = rules;
        self
    }

    pub fn with_libraries(mut self, libraries: Vec<NseLibraryUseReport>) -> Self {
        self.libraries = libraries;
        self
    }

    pub fn with_output(mut self, output: &str) -> Self {
        let line_count = output.lines().count();
        let truncated = output.len() > 10000;
        let content = if truncated {
            format!("{}...(truncated)", &output[..10000])
        } else {
            output.to_string()
        };
        self.output = NseOutputSummary {
            has_output: !output.is_empty(),
            content,
            line_count,
            truncated,
        };
        self
    }

    pub fn with_error(mut self, error: &str) -> Self {
        self.errors.push(error.to_string());
        self
    }

    pub fn compute_compatibility(mut self) -> Self {
        let has_errors = !self.errors.is_empty();
        let has_rejected = self.resolver.rejected_count > 0;
        let has_warnings = !self.warnings.is_empty();
        let has_approxs = self.rules.iter().any(|r| r.exactness == "approximate");

        let status = if has_errors {
            NseRunCompatibilityStatus::Failed
        } else if has_rejected {
            NseRunCompatibilityStatus::Partial
        } else if has_approxs || has_warnings {
            NseRunCompatibilityStatus::CompatibleWithWarnings
        } else {
            NseRunCompatibilityStatus::Compatible
        };

        let fidelity = if has_approxs {
            NseRunFidelity::Approximate
        } else if has_rejected {
            NseRunFidelity::Minimal
        } else {
            NseRunFidelity::Full
        };

        let unsupported_features: Vec<String> = self
            .resolver
            .diagnostics
            .iter()
            .filter(|d| d.kind == "module_name_rejected" || d.kind == "module_load_failed")
            .map(|d| d.source.clone())
            .collect();

        let approximations: Vec<String> = self
            .rules
            .iter()
            .filter(|r| r.exactness == "approximate")
            .map(|r| format!("{}: {}", r.kind, r.summary))
            .collect();

        self.compatibility = NseCompatibilitySummary {
            status,
            fidelity,
            unsupported_features,
            approximations,
        };
        self
    }
}

/// Evaluate a Lua rule result into a structured report.
///
/// Handles errors, nil, boolean true/false, and non-boolean return values,
/// producing a truthful `NseRuleEvaluationReport` instead of collapsing
/// all non-true cases into `false`.
pub fn evaluate_rule(
    kind: &str,
    lua_result: Result<mlua::Value, mlua::Error>,
) -> NseRuleEvaluationReport {
    match lua_result {
        Ok(mlua::Value::Nil) => NseRuleEvaluationReport {
            kind: kind.to_string(),
            evaluated: true,
            matched: false,
            exactness: "exact".to_string(),
            error: None,
            summary: "rule returned nil".to_string(),
            unsupported: None,
        },
        Ok(mlua::Value::Boolean(true)) => NseRuleEvaluationReport {
            kind: kind.to_string(),
            evaluated: true,
            matched: true,
            exactness: "exact".to_string(),
            error: None,
            summary: "rule matched".to_string(),
            unsupported: None,
        },
        Ok(mlua::Value::Boolean(false)) => NseRuleEvaluationReport {
            kind: kind.to_string(),
            evaluated: true,
            matched: false,
            exactness: "exact".to_string(),
            error: None,
            summary: "rule did not match".to_string(),
            unsupported: None,
        },
        Ok(other) => {
            let type_name = match &other {
                mlua::Value::String(_) => "string",
                mlua::Value::Integer(_) => "integer",
                mlua::Value::Number(_) => "number",
                mlua::Value::Table(_) => "table",
                mlua::Value::Function(_) => "function",
                mlua::Value::Thread(_) => "thread",
                mlua::Value::UserData(_) => "userdata",
                mlua::Value::LightUserData(_) => "lightuserdata",
                mlua::Value::Vector(_) => "vector",
                mlua::Value::Buffer(_) => "buffer",
                mlua::Value::Error(_) => "error",
                mlua::Value::Nil | mlua::Value::Boolean(_) => unreachable!(),
                _ => "unknown",
            };
            NseRuleEvaluationReport {
                kind: kind.to_string(),
                evaluated: false,
                matched: false,
                exactness: "unsupported".to_string(),
                error: None,
                summary: format!("expected boolean, got {}", type_name),
                unsupported: Some(format!("expected boolean, got {}", type_name)),
            }
        }
        Err(e) => NseRuleEvaluationReport {
            kind: kind.to_string(),
            evaluated: false,
            matched: false,
            exactness: "exact".to_string(),
            error: Some(e.to_string()),
            summary: format!("rule error: {}", e),
            unsupported: None,
        },
    }
}

impl From<&NseExecutionLimits> for NseLimitsSummary {
    fn from(limits: &NseExecutionLimits) -> Self {
        Self {
            wall_clock_timeout_secs: limits.wall_clock_timeout.map(|d| d.as_secs_f64()),
            lua_instruction_budget: limits.lua_instruction_budget,
            max_output_bytes: limits.max_output_bytes,
            max_script_bytes: limits.max_script_bytes,
            max_required_module_bytes: limits.max_required_module_bytes,
            max_network_operations: limits.max_network_operations,
            max_filesystem_operations: limits.max_filesystem_operations,
            max_lua_memory_bytes: limits.max_lua_memory_bytes,
        }
    }
}

impl From<&NseExecutionStats> for NseExecutionStatsSummary {
    fn from(stats: &NseExecutionStats) -> Self {
        Self {
            elapsed_secs: stats.elapsed.as_secs_f64(),
            output_bytes: stats.output_bytes,
            lua_instruction_count: stats.lua_instruction_count,
            network_operations: stats.network_operations,
            network_bytes_read: stats.network_bytes_read,
            network_bytes_written: stats.network_bytes_written,
            filesystem_operations: stats.filesystem_operations,
            filesystem_bytes_read: stats.filesystem_bytes_read,
            limit_violation: stats.limit_violation.as_ref().map(|v| v.to_string()),
        }
    }
}

impl From<&NseScriptSource> for NseScriptSourceSummary {
    fn from(source: &NseScriptSource) -> Self {
        match source {
            NseScriptSource::Builtin { name } => Self {
                kind: "builtin".to_string(),
                label: name.clone(),
                size: 0,
            },
            NseScriptSource::TrustedRegistry { name } => Self {
                kind: "registry".to_string(),
                label: name.clone(),
                size: 0,
            },
            NseScriptSource::File { path } => Self {
                kind: "file".to_string(),
                label: path.display().to_string(),
                size: 0,
            },
            NseScriptSource::InlineManual { label, content } => Self {
                kind: "inline".to_string(),
                label: label.clone(),
                size: content.len(),
            },
        }
    }
}
