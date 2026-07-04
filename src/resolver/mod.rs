//! Hardened script and module resolver for NSE.
//!
//! All script and module loading flows through `ScriptResolver` to enforce:
//! - Explicit script source kinds
//! - Profile-derived script and module policies
//! - Strict module-name grammar before filesystem access
//! - Canonical path validation under approved roots
//! - Symlink-aware containment checks
//! - File extension allowlists
//! - Maximum script and module sizes
//! - Structured diagnostics for load behavior

pub mod registry;

use std::fmt;
use std::path::{Path, PathBuf};

use crate::limits::NseExecutionLimits;
use crate::profile::{NseModulePolicy, NseScriptPolicy};

// ---------------------------------------------------------------------------
// Module name validation
// ---------------------------------------------------------------------------

/// Validated NSE module name. Guaranteed to contain only safe characters
/// and pass all containment checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NseModuleName(String);

impl NseModuleName {
    /// The validated module name string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for NseModuleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Maximum module name length.
const MAX_MODULE_NAME_LEN: usize = 256;

/// Validate a module name against the strict grammar.
///
/// Rules:
/// - Non-empty
/// - ASCII letters, digits, `_`, `-`, `.`
/// - Must not start with `.`
/// - Must not contain `..` as a path segment
/// - Must not contain `/`, `\`, `:`, `~`, null bytes, glob chars,
///   shell expansion chars, or whitespace
/// - Length <= 256
pub fn validate_nse_module_name(name: &str) -> Result<NseModuleName, NseLoadError> {
    if name.is_empty() {
        return Err(NseLoadError::InvalidModuleName {
            name: name.to_string(),
            reason: "module name is empty".to_string(),
        });
    }

    if name.len() > MAX_MODULE_NAME_LEN {
        return Err(NseLoadError::InvalidModuleName {
            name: name.to_string(),
            reason: format!(
                "module name exceeds maximum length ({} > {})",
                name.len(),
                MAX_MODULE_NAME_LEN
            ),
        });
    }

    if name.starts_with('.') {
        return Err(NseLoadError::InvalidModuleName {
            name: name.to_string(),
            reason: "module name must not start with '.'".to_string(),
        });
    }

    // Check for path traversal markers
    if name.contains("..") {
        return Err(NseLoadError::InvalidModuleName {
            name: name.to_string(),
            reason: "module name must not contain '..'".to_string(),
        });
    }

    // Check for forbidden characters
    for ch in name.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-' && ch != '.' {
            return Err(NseLoadError::InvalidModuleName {
                name: name.to_string(),
                reason: format!("module name contains forbidden character '{}'", ch),
            });
        }
    }

    Ok(NseModuleName(name.to_string()))
}

// ---------------------------------------------------------------------------
// Script source model
// ---------------------------------------------------------------------------

/// Explicit script source kind. All script loading must declare its source.
#[derive(Debug, Clone)]
pub enum NseScriptSource {
    /// Built-in script shipped with eggsec-nse.
    Builtin { name: String },
    /// Future: trusted bundled or generated script registry.
    TrustedRegistry { name: String },
    /// User-provided script file on disk.
    File { path: PathBuf },
    /// Inline script content (tests, manual CLI).
    InlineManual { label: String, content: String },
}

impl fmt::Display for NseScriptSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Builtin { name } => write!(f, "builtin:{}", name),
            Self::TrustedRegistry { name } => write!(f, "registry:{}", name),
            Self::File { path } => write!(f, "file:{}", path.display()),
            Self::InlineManual { label, .. } => write!(f, "inline:{}", label),
        }
    }
}

// ---------------------------------------------------------------------------
// Load error type
// ---------------------------------------------------------------------------

/// Structured error for script/module load failures.
#[derive(Debug, Clone)]
pub enum NseLoadError {
    /// Script or module not found in any allowed location.
    NotFound { source: NseScriptSource },
    /// Script file rejected by profile policy.
    BlockedByPolicy {
        source: NseScriptSource,
        reason: String,
    },
    /// Path is outside all approved roots.
    OutsideRoot {
        path: PathBuf,
        approved_roots: Vec<PathBuf>,
    },
    /// Symlink resolves outside approved roots.
    SymlinkEscape { path: PathBuf, resolved: PathBuf },
    /// File has invalid or disallowed extension.
    InvalidExtension { path: PathBuf, extension: String },
    /// Content exceeds size limit.
    Oversized {
        source: NseScriptSource,
        size: usize,
        limit: usize,
    },
    /// Module name failed grammar validation.
    InvalidModuleName { name: String, reason: String },
    /// Filesystem I/O error during load.
    IoError { path: PathBuf, error: String },
    /// Content failed to evaluate in Lua.
    EvalError {
        source: NseScriptSource,
        error: String,
    },
}

impl fmt::Display for NseLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { source } => write!(f, "not found: {}", source),
            Self::BlockedByPolicy { source, reason } => {
                write!(f, "blocked by policy: {} ({})", source, reason)
            }
            Self::OutsideRoot {
                path,
                approved_roots,
            } => write!(
                f,
                "path outside approved roots: {} (roots: {:?})",
                path.display(),
                approved_roots
            ),
            Self::SymlinkEscape { path, resolved } => write!(
                f,
                "symlink escapes approved roots: {} -> {}",
                path.display(),
                resolved.display()
            ),
            Self::InvalidExtension { path, extension } => {
                write!(f, "invalid extension '{}': {}", extension, path.display())
            }
            Self::Oversized {
                source,
                size,
                limit,
            } => write!(
                f,
                "oversized content from {}: {} bytes (limit: {})",
                source, size, limit
            ),
            Self::InvalidModuleName { name, reason } => {
                write!(f, "invalid module name '{}': {}", name, reason)
            }
            Self::IoError { path, error } => {
                write!(f, "I/O error reading {}: {}", path.display(), error)
            }
            Self::EvalError { source, error } => {
                write!(f, "eval error for {}: {}", source, error)
            }
        }
    }
}

impl std::error::Error for NseLoadError {}

#[cfg(feature = "nse")]
impl From<NseLoadError> for mlua::Error {
    fn from(e: NseLoadError) -> Self {
        mlua::Error::RuntimeError(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Load diagnostic
// ---------------------------------------------------------------------------

/// Diagnostic emitted during script/module loading for visibility.
#[derive(Debug, Clone)]
pub enum NseLoadDiagnostic {
    /// A script source was resolved successfully.
    Resolved {
        source: NseScriptSource,
        bytes: usize,
    },
    /// A script source was blocked by policy.
    Blocked {
        source: NseScriptSource,
        reason: String,
    },
    /// A path was rejected for being outside roots.
    OutsideRoot { path: PathBuf, root: PathBuf },
    /// A symlink was rejected.
    SymlinkRejected { path: PathBuf, resolved: PathBuf },
    /// A module name was rejected before filesystem lookup.
    ModuleNameRejected { name: String, reason: String },
    /// Content was rejected for exceeding size limit.
    OversizedRejected {
        source: NseScriptSource,
        size: usize,
        limit: usize,
    },
    /// Filesystem module load failed (reported, not silently skipped).
    ModuleLoadFailed {
        name: String,
        path: PathBuf,
        error: String,
    },
}

// ---------------------------------------------------------------------------
// Resolved types
// ---------------------------------------------------------------------------

/// A resolved script with its content and metadata.
#[derive(Debug, Clone)]
pub struct ResolvedNseScript {
    /// The original source.
    pub source: NseScriptSource,
    /// The script content.
    pub content: String,
    /// Size in bytes.
    pub size: usize,
}

/// A resolved module with its content and metadata.
#[derive(Debug, Clone)]
pub struct ResolvedNseModule {
    /// The validated module name.
    pub name: NseModuleName,
    /// The module content.
    pub content: String,
    /// Size in bytes.
    pub size: usize,
    /// The path it was loaded from (if filesystem).
    pub path: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// File extension allowlist
// ---------------------------------------------------------------------------

/// Allowed file extensions for scripts and modules.
const ALLOWED_SCRIPT_EXTENSIONS: &[&str] = &["lua", "nse"];
const ALLOWED_MODULE_EXTENSIONS: &[&str] = &["lua", "nse"];

fn has_allowed_extension(path: &Path, allowed: &[&str]) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| allowed.contains(&ext))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Path containment
// ---------------------------------------------------------------------------

/// Canonicalize a path. Returns `None` if the path cannot be canonicalized
/// (e.g., does not exist and parent cannot be resolved).
fn try_canonicalize(path: &Path) -> Option<PathBuf> {
    path.canonicalize().ok()
}

/// Canonicalize a root path. Returns `Some(canonical)` only if the path
/// can be fully resolved. Roots that cannot be canonicalized are rejected
/// to prevent string-prefix fallback authorization.
fn canonicalize_root(path: &Path) -> Option<PathBuf> {
    path.canonicalize().ok()
}

/// Check whether a canonical path is under an approved root using
/// path-component semantics (not string prefix).
fn is_under_root(canonical_path: &Path, canonical_root: &Path) -> bool {
    match canonical_path.strip_prefix(canonical_root) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Validate that an existing file path is under one of the approved roots.
/// Returns the canonical path if allowed, or an error.
///
/// **Read-path helper**: this function only authorizes paths whose canonical
/// form is fully resolvable. Non-existent files cannot be authorized here.
/// Use [`validate_parent_under_roots`] only when write/create semantics
/// require authorizing a path whose target does not yet exist; that helper
/// is intentionally separate and must never be used for read authorization.
///
/// For existing files, the full canonical path is checked against canonical roots
/// using path-component semantics (`Path::strip_prefix`).
/// If the file does not exist or the canonical path is not under any approved
/// root, the path is rejected.
fn validate_existing_path_under_roots(
    path: &Path,
    approved_roots: &[PathBuf],
) -> Result<PathBuf, NseLoadError> {
    let canonical = try_canonicalize(path).ok_or_else(|| NseLoadError::IoError {
        path: path.to_path_buf(),
        error: "path does not exist or cannot be canonicalized".to_string(),
    })?;

    for root in approved_roots {
        if let Some(canonical_root) = canonicalize_root(root) {
            if is_under_root(&canonical, &canonical_root) {
                return Ok(canonical);
            }
        }
    }

    Err(NseLoadError::OutsideRoot {
        path: path.to_path_buf(),
        approved_roots: approved_roots.to_vec(),
    })
}

/// Validate that a parent directory is under one of the approved roots,
/// returning the canonical child path constructed from that parent.
///
/// **Write-path helper**: this helper authorizes a path by canonicalizing
/// only the parent directory and constructing the child path beneath it.
/// It is intended for create/write semantics where the target does not yet
/// exist. **It must not be used for read authorization** — read paths must
/// always resolve to existing files via [`validate_existing_path_under_roots`].
#[allow(dead_code)]
fn validate_parent_under_roots(
    path: &Path,
    approved_roots: &[PathBuf],
) -> Result<PathBuf, NseLoadError> {
    let parent = path.parent().ok_or_else(|| NseLoadError::OutsideRoot {
        path: path.to_path_buf(),
        approved_roots: approved_roots.to_vec(),
    })?;

    let canonical_parent = try_canonicalize(parent).ok_or_else(|| NseLoadError::OutsideRoot {
        path: path.to_path_buf(),
        approved_roots: approved_roots.to_vec(),
    })?;

    for root in approved_roots {
        if let Some(canonical_root) = canonicalize_root(root) {
            if is_under_root(&canonical_parent, &canonical_root) {
                return Ok(canonical_parent.join(path.file_name().unwrap_or_default()));
            }
        }
    }

    Err(NseLoadError::OutsideRoot {
        path: path.to_path_buf(),
        approved_roots: approved_roots.to_vec(),
    })
}

/// Validate that a symlink resolves within approved roots.
fn validate_symlink_containment(
    path: &Path,
    approved_roots: &[PathBuf],
) -> Result<PathBuf, NseLoadError> {
    let canonical = path.canonicalize().map_err(|e| NseLoadError::IoError {
        path: path.to_path_buf(),
        error: e.to_string(),
    })?;

    for root in approved_roots {
        if let Some(canonical_root) = canonicalize_root(root) {
            if is_under_root(&canonical, &canonical_root) {
                return Ok(canonical);
            }
        }
    }

    Err(NseLoadError::SymlinkEscape {
        path: path.to_path_buf(),
        resolved: canonical,
    })
}

// ---------------------------------------------------------------------------
// Built-in script registry
// ---------------------------------------------------------------------------

/// Names of all built-in scripts.
const BUILTIN_SCRIPT_NAMES: &[&str] = &[
    "default",
    "discovery",
    "banner",
    "http-headers",
    "dns-check",
    "ssl-cert",
];

/// Check whether a name refers to a built-in script.
pub fn is_builtin_script(name: &str) -> bool {
    BUILTIN_SCRIPT_NAMES.contains(&name)
}

// ---------------------------------------------------------------------------
// ScriptResolver
// ---------------------------------------------------------------------------

/// Hardened script and module resolver.
///
/// Enforces profile-derived policies, module name grammar, path containment,
/// size limits, and structured diagnostics for all loading operations.
pub struct ScriptResolver {
    script_policy: NseScriptPolicy,
    module_policy: NseModulePolicy,
    limits: NseExecutionLimits,
    diagnostics: Vec<NseLoadDiagnostic>,
}

impl ScriptResolver {
    /// Create a new resolver from profile policies and execution limits.
    pub fn new(
        script_policy: NseScriptPolicy,
        module_policy: NseModulePolicy,
        limits: NseExecutionLimits,
    ) -> Self {
        Self {
            script_policy,
            module_policy,
            limits,
            diagnostics: Vec::new(),
        }
    }

    /// Get accumulated diagnostics.
    pub fn diagnostics(&self) -> &[NseLoadDiagnostic] {
        &self.diagnostics
    }

    /// Take accumulated diagnostics (consumes them).
    pub fn take_diagnostics(&mut self) -> Vec<NseLoadDiagnostic> {
        std::mem::take(&mut self.diagnostics)
    }

    /// Clear accumulated diagnostics.
    pub fn clear_diagnostics(&mut self) {
        self.diagnostics.clear();
    }

    // -- Script resolution --

    /// Resolve a script source to content.
    ///
    /// Enforces policy, path containment, size limits, and emits diagnostics.
    pub fn resolve_script(
        &mut self,
        source: NseScriptSource,
    ) -> Result<ResolvedNseScript, NseLoadError> {
        match &source {
            NseScriptSource::Builtin { name } => self.resolve_builtin(name.clone()),
            NseScriptSource::TrustedRegistry { name } => {
                // Future: look up in registry
                Err(NseLoadError::NotFound {
                    source: source.clone(),
                })
            }
            NseScriptSource::File { path } => self.resolve_script_file(path.clone(), source),
            NseScriptSource::InlineManual { label, content } => {
                self.resolve_inline(label.clone(), content.clone(), source)
            }
        }
    }

    fn resolve_builtin(&mut self, name: String) -> Result<ResolvedNseScript, NseLoadError> {
        if !self.script_policy.allow_builtin_scripts {
            return Err(NseLoadError::BlockedByPolicy {
                source: NseScriptSource::Builtin { name: name.clone() },
                reason: "builtin scripts not allowed by profile".to_string(),
            });
        }

        // Built-in content is provided by the caller via get_builtin_script()
        // The resolver validates policy; the actual content is injected externally.
        // For now, return a marker - the caller fills in content.
        let source = NseScriptSource::Builtin { name };
        let content = String::new(); // Caller replaces with actual content
        let size = 0;

        self.diagnostics.push(NseLoadDiagnostic::Resolved {
            source: source.clone(),
            bytes: size,
        });

        Ok(ResolvedNseScript {
            source,
            content,
            size,
        })
    }

    fn resolve_script_file(
        &mut self,
        path: PathBuf,
        source: NseScriptSource,
    ) -> Result<ResolvedNseScript, NseLoadError> {
        // 1. Check policy allows script files
        if !self.script_policy.allow_script_files {
            self.diagnostics.push(NseLoadDiagnostic::Blocked {
                source: source.clone(),
                reason: "script files not allowed by profile".to_string(),
            });
            return Err(NseLoadError::BlockedByPolicy {
                source: source.clone(),
                reason: "script files not allowed by profile".to_string(),
            });
        }

        // 2. Check file exists
        if !path.exists() {
            return Err(NseLoadError::NotFound {
                source: source.clone(),
            });
        }

        // 3. Check extension
        if !has_allowed_extension(&path, ALLOWED_SCRIPT_EXTENSIONS) {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_string();
            return Err(NseLoadError::InvalidExtension {
                path: path.clone(),
                extension: ext,
            });
        }

        // 4. Validate path under approved roots (if any are specified).
        //
        // Empty roots + manual profile means unrestricted manual file selection
        // (see `NseScriptPolicy` doc comments for the empty-roots semantic
        // table); skip the root check entirely. Non-empty roots always require
        // canonical containment via the read-path helper.
        if !self.script_policy.allowed_script_roots.is_empty() {
            validate_existing_path_under_roots(&path, &self.script_policy.allowed_script_roots)?;
        }

        // 5. Validate symlink containment — only when roots are configured.
        // Without configured roots, symlink containment is not enforceable
        // and would incorrectly reject normal files under manual permissive.
        let canonical = if self.script_policy.allowed_script_roots.is_empty() {
            // Manual unrestricted: canonicalize the existing file (no root containment).
            path.canonicalize().map_err(|e| NseLoadError::IoError {
                path: path.clone(),
                error: e.to_string(),
            })?
        } else {
            validate_symlink_containment(&path, &self.script_policy.allowed_script_roots)?
        };

        // 6. Read content
        let content = std::fs::read_to_string(&canonical).map_err(|e| NseLoadError::IoError {
            path: canonical.clone(),
            error: e.to_string(),
        })?;

        // 7. Check size limit
        let size = content.len();
        if let Some(max) = self.limits.max_script_bytes {
            if size > max {
                self.diagnostics.push(NseLoadDiagnostic::OversizedRejected {
                    source: source.clone(),
                    size,
                    limit: max,
                });
                return Err(NseLoadError::Oversized {
                    source: source.clone(),
                    size,
                    limit: max,
                });
            }
        }
        if let Some(max) = self.script_policy.max_script_bytes {
            if size > max {
                self.diagnostics.push(NseLoadDiagnostic::OversizedRejected {
                    source: source.clone(),
                    size,
                    limit: max,
                });
                return Err(NseLoadError::Oversized {
                    source: source.clone(),
                    size,
                    limit: max,
                });
            }
        }

        self.diagnostics.push(NseLoadDiagnostic::Resolved {
            source: source.clone(),
            bytes: size,
        });

        Ok(ResolvedNseScript {
            source,
            content,
            size,
        })
    }

    fn resolve_inline(
        &mut self,
        _label: String,
        content: String,
        source: NseScriptSource,
    ) -> Result<ResolvedNseScript, NseLoadError> {
        let size = content.len();

        // Check size limit for inline scripts
        if let Some(max) = self.limits.max_script_bytes {
            if size > max {
                self.diagnostics.push(NseLoadDiagnostic::OversizedRejected {
                    source: source.clone(),
                    size,
                    limit: max,
                });
                return Err(NseLoadError::Oversized {
                    source: source.clone(),
                    size,
                    limit: max,
                });
            }
        }
        if let Some(max) = self.script_policy.max_script_bytes {
            if size > max {
                self.diagnostics.push(NseLoadDiagnostic::OversizedRejected {
                    source: source.clone(),
                    size,
                    limit: max,
                });
                return Err(NseLoadError::Oversized {
                    source: source.clone(),
                    size,
                    limit: max,
                });
            }
        }

        self.diagnostics.push(NseLoadDiagnostic::Resolved {
            source: source.clone(),
            bytes: size,
        });

        Ok(ResolvedNseScript {
            source,
            content,
            size,
        })
    }

    // -- Module resolution --

    /// Validate a module name and resolve it from filesystem roots.
    ///
    /// Returns `None` if the module should be loaded from built-in registry
    /// (caller handles that). Returns `Some(ResolvedNseModule)` for filesystem modules.
    pub fn resolve_module(
        &mut self,
        name: &str,
    ) -> Result<Option<ResolvedNseModule>, NseLoadError> {
        // 1. Validate module name grammar
        let validated_name = validate_nse_module_name(name).map_err(|e| {
            self.diagnostics
                .push(NseLoadDiagnostic::ModuleNameRejected {
                    name: name.to_string(),
                    reason: e.to_string(),
                });
            e
        })?;

        // 2. Check if filesystem modules are allowed
        if !self.module_policy.allow_filesystem_modules {
            return Ok(None);
        }

        // 3. If no module roots are configured, can't load from filesystem
        if self.module_policy.allowed_module_roots.is_empty() {
            return Ok(None);
        }

        // 4. Try to find the module in approved roots
        for root in &self.module_policy.allowed_module_roots {
            let Some(canonical_root) = canonicalize_root(root) else {
                // Root cannot be canonicalized — skip it (do not fall back to string prefix)
                continue;
            };

            for ext in ALLOWED_MODULE_EXTENSIONS {
                let candidate = canonical_root.join(format!("{}.{}", validated_name.as_str(), ext));

                if !candidate.exists() {
                    continue;
                }

                // Validate path containment
                match validate_existing_path_under_roots(
                    &candidate,
                    &self.module_policy.allowed_module_roots,
                ) {
                    Ok(canonical_path) => {
                        // Validate symlink containment
                        match validate_symlink_containment(
                            &canonical_path,
                            &self.module_policy.allowed_module_roots,
                        ) {
                            Ok(safe_path) => {
                                // Read content
                                match std::fs::read_to_string(&safe_path) {
                                    Ok(content) => {
                                        let size = content.len();

                                        // Check size limit
                                        if let Some(max) = self.limits.max_required_module_bytes {
                                            if size > max {
                                                self.diagnostics.push(
                                                    NseLoadDiagnostic::OversizedRejected {
                                                        source: NseScriptSource::File {
                                                            path: safe_path.clone(),
                                                        },
                                                        size,
                                                        limit: max,
                                                    },
                                                );
                                                return Err(NseLoadError::Oversized {
                                                    source: NseScriptSource::File {
                                                        path: safe_path.clone(),
                                                    },
                                                    size,
                                                    limit: max,
                                                });
                                            }
                                        }
                                        if let Some(max) = self.module_policy.max_module_bytes {
                                            if size > max {
                                                self.diagnostics.push(
                                                    NseLoadDiagnostic::OversizedRejected {
                                                        source: NseScriptSource::File {
                                                            path: safe_path.clone(),
                                                        },
                                                        size,
                                                        limit: max,
                                                    },
                                                );
                                                return Err(NseLoadError::Oversized {
                                                    source: NseScriptSource::File {
                                                        path: safe_path.clone(),
                                                    },
                                                    size,
                                                    limit: max,
                                                });
                                            }
                                        }

                                        self.diagnostics.push(NseLoadDiagnostic::Resolved {
                                            source: NseScriptSource::File {
                                                path: safe_path.clone(),
                                            },
                                            bytes: size,
                                        });

                                        return Ok(Some(ResolvedNseModule {
                                            name: validated_name,
                                            content,
                                            size,
                                            path: Some(safe_path),
                                        }));
                                    }
                                    Err(e) => {
                                        self.diagnostics.push(
                                            NseLoadDiagnostic::ModuleLoadFailed {
                                                name: name.to_string(),
                                                path: safe_path,
                                                error: e.to_string(),
                                            },
                                        );
                                        // Continue searching other roots
                                    }
                                }
                            }
                            Err(NseLoadError::SymlinkEscape { path, resolved }) => {
                                self.diagnostics
                                    .push(NseLoadDiagnostic::SymlinkRejected { path, resolved });
                                // Continue searching other roots
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Err(NseLoadError::OutsideRoot {
                        path,
                        approved_roots,
                    }) => {
                        self.diagnostics.push(NseLoadDiagnostic::OutsideRoot {
                            path,
                            root: approved_roots.first().cloned().unwrap_or_default(),
                        });
                        // Continue searching other roots
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        // Module not found in any approved root
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_module_name_valid() {
        assert!(validate_nse_module_name("stdnse").is_ok());
        assert!(validate_nse_module_name("http").is_ok());
        assert!(validate_nse_module_name("my-module").is_ok());
        assert!(validate_nse_module_name("my_module").is_ok());
        assert!(validate_nse_module_name("module.v2").is_ok());
        assert!(validate_nse_module_name("a1b2c3").is_ok());
    }

    #[test]
    fn test_validate_module_name_empty() {
        assert!(matches!(
            validate_nse_module_name(""),
            Err(NseLoadError::InvalidModuleName { .. })
        ));
    }

    #[test]
    fn test_validate_module_name_starts_with_dot() {
        assert!(matches!(
            validate_nse_module_name(".hidden"),
            Err(NseLoadError::InvalidModuleName { .. })
        ));
    }

    #[test]
    fn test_validate_module_name_traversal() {
        assert!(matches!(
            validate_nse_module_name("..etc/passwd"),
            Err(NseLoadError::InvalidModuleName { .. })
        ));
        assert!(matches!(
            validate_nse_module_name("foo/../bar"),
            Err(NseLoadError::InvalidModuleName { .. })
        ));
    }

    #[test]
    fn test_validate_module_name_forbidden_chars() {
        assert!(validate_nse_module_name("foo/bar").is_err());
        assert!(validate_nse_module_name("foo\\bar").is_err());
        assert!(validate_nse_module_name("foo:bar").is_err());
        assert!(validate_nse_module_name("foo~bar").is_err());
        assert!(validate_nse_module_name("foo\0bar").is_err());
        assert!(validate_nse_module_name("foo bar").is_err());
        assert!(validate_nse_module_name("foo*bar").is_err());
        assert!(validate_nse_module_name("foo?bar").is_err());
        assert!(validate_nse_module_name("foo{bar").is_err());
    }

    #[test]
    fn test_validate_module_name_too_long() {
        let long_name = "a".repeat(257);
        assert!(matches!(
            validate_nse_module_name(&long_name),
            Err(NseLoadError::InvalidModuleName { .. })
        ));
    }

    #[test]
    fn test_validate_module_name_max_length() {
        let max_name = "a".repeat(256);
        assert!(validate_nse_module_name(&max_name).is_ok());
    }

    #[test]
    fn test_script_source_display() {
        assert_eq!(
            NseScriptSource::Builtin {
                name: "default".to_string()
            }
            .to_string(),
            "builtin:default"
        );
        assert_eq!(
            NseScriptSource::File {
                path: PathBuf::from("/tmp/test.lua")
            }
            .to_string(),
            "file:/tmp/test.lua"
        );
        assert_eq!(
            NseLoadError::NotFound {
                source: NseScriptSource::Builtin {
                    name: "x".to_string()
                }
            }
            .to_string(),
            "not found: builtin:x"
        );
    }

    #[test]
    fn test_is_builtin_script() {
        assert!(is_builtin_script("default"));
        assert!(is_builtin_script("discovery"));
        assert!(is_builtin_script("banner"));
        assert!(is_builtin_script("http-headers"));
        assert!(is_builtin_script("dns-check"));
        assert!(is_builtin_script("ssl-cert"));
        assert!(!is_builtin_script("custom"));
        assert!(!is_builtin_script(""));
    }

    #[test]
    fn test_has_allowed_extension() {
        assert!(has_allowed_extension(
            Path::new("test.lua"),
            ALLOWED_SCRIPT_EXTENSIONS
        ));
        assert!(has_allowed_extension(
            Path::new("test.nse"),
            ALLOWED_SCRIPT_EXTENSIONS
        ));
        assert!(!has_allowed_extension(
            Path::new("test.txt"),
            ALLOWED_SCRIPT_EXTENSIONS
        ));
        assert!(!has_allowed_extension(
            Path::new("test"),
            ALLOWED_SCRIPT_EXTENSIONS
        ));
    }

    #[test]
    fn test_resolver_rejects_script_file_when_policy_blocks() {
        let profile = crate::profile::ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
        let mut resolver =
            ScriptResolver::new(profile.script_policy, profile.module_policy, profile.limits);

        let result = resolver.resolve_script(NseScriptSource::File {
            path: PathBuf::from("/tmp/test.lua"),
        });

        assert!(result.is_err());
        match result.unwrap_err() {
            NseLoadError::BlockedByPolicy { reason, .. } => {
                assert!(reason.contains("not allowed"));
            }
            other => panic!("Expected BlockedByPolicy, got {:?}", other),
        }
    }

    #[test]
    fn test_resolver_rejects_oversized_inline_script() {
        let profile = crate::profile::ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
        let mut resolver =
            ScriptResolver::new(profile.script_policy, profile.module_policy, profile.limits);

        // agent_safe has max_script_bytes = 1 MiB
        let large_content = "x".repeat(1024 * 1024 + 1);
        let result = resolver.resolve_script(NseScriptSource::InlineManual {
            label: "test".to_string(),
            content: large_content,
        });

        assert!(result.is_err());
        match result.unwrap_err() {
            NseLoadError::Oversized { size, limit, .. } => {
                assert!(size > limit);
            }
            other => panic!("Expected Oversized, got {:?}", other),
        }
    }

    #[test]
    fn test_resolver_allows_inline_script_within_limits() {
        let profile = crate::profile::ResolvedNseExecutionProfile::manual_permissive(None);
        let mut resolver =
            ScriptResolver::new(profile.script_policy, profile.module_policy, profile.limits);

        let result = resolver.resolve_script(NseScriptSource::InlineManual {
            label: "test".to_string(),
            content: "return 1".to_string(),
        });

        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert_eq!(resolved.content, "return 1");
    }

    #[test]
    fn test_resolver_rejects_module_name_traversal() {
        let profile = crate::profile::ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
        let mut resolver =
            ScriptResolver::new(profile.script_policy, profile.module_policy, profile.limits);

        let result = resolver.resolve_module("../../etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolver_rejects_module_name_slash() {
        let profile = crate::profile::ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
        let mut resolver =
            ScriptResolver::new(profile.script_policy, profile.module_policy, profile.limits);

        let result = resolver.resolve_module("foo/bar");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolver_returns_none_for_module_when_filesystem_disallowed() {
        let profile = crate::profile::ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
        let mut resolver =
            ScriptResolver::new(profile.script_policy, profile.module_policy, profile.limits);

        let result = resolver.resolve_module("stdnse").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_resolver_allows_builtin_script() {
        let profile = crate::profile::ResolvedNseExecutionProfile::manual_permissive(None);
        let mut resolver =
            ScriptResolver::new(profile.script_policy, profile.module_policy, profile.limits);

        let result = resolver.resolve_script(NseScriptSource::Builtin {
            name: "default".to_string(),
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolver_rejects_builtin_when_policy_blocks() {
        let mut script_policy = crate::profile::NseScriptPolicy {
            allow_builtin_scripts: false,
            allow_script_files: false,
            allowed_script_roots: Vec::new(),
            allow_conventional_nmap_paths: false,
            max_script_bytes: None,
        };
        let mut resolver = ScriptResolver::new(
            script_policy,
            crate::profile::NseModulePolicy {
                allow_builtin_modules: true,
                allow_filesystem_modules: false,
                allowed_module_roots: Vec::new(),
                max_module_bytes: None,
            },
            NseExecutionLimits::default(),
        );

        let result = resolver.resolve_script(NseScriptSource::Builtin {
            name: "default".to_string(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_diagnostics_accumulate() {
        let profile = crate::profile::ResolvedNseExecutionProfile::agent_safe("10.0.0.1", &[]);
        let mut resolver =
            ScriptResolver::new(profile.script_policy, profile.module_policy, profile.limits);

        // This will emit a blocked diagnostic
        let _ = resolver.resolve_script(NseScriptSource::File {
            path: PathBuf::from("/tmp/test.lua"),
        });

        let diags = resolver.take_diagnostics();
        assert!(!diags.is_empty());
    }

    // -----------------------------------------------------------------------
    // WS2: Canonical root containment tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_under_root_component_semantics() {
        // /tmp/root2 must NOT match /tmp/root (sibling-prefix bypass)
        let root = PathBuf::from("/tmp/root");
        let child = PathBuf::from("/tmp/root2/file.nse");
        assert!(!is_under_root(&child, &root));

        // /tmp/root/file.nse DOES match /tmp/root
        let child = PathBuf::from("/tmp/root/file.nse");
        assert!(is_under_root(&child, &root));

        // /tmp/root/sub/file.nse DOES match /tmp/root
        let child = PathBuf::from("/tmp/root/sub/file.nse");
        assert!(is_under_root(&child, &root));
    }

    #[test]
    fn test_validate_existing_path_under_roots_rejects_sibling_prefix() {
        let roots = vec![PathBuf::from("/tmp/root")];
        // /tmp/root2/file.nse should NOT be allowed under /tmp/root.
        // Since the file does not exist, the read helper rejects with
        // IoError before any root comparison. (Root mismatch would only be
        // observable for existing files.)
        let result = validate_existing_path_under_roots(Path::new("/tmp/root2/file.nse"), &roots);
        assert!(matches!(result, Err(NseLoadError::IoError { .. })));
    }

    #[test]
    fn test_validate_existing_path_under_roots_rejects_sibling_prefix_existing_file() {
        // Sibling-prefix bypass: /tmp/root2/real.nse must NOT be authorized
        // under /tmp/root even when both directories exist and the file is real.
        let tmp = std::env::temp_dir().join("eggsec-nse-sibling-prefix-test");
        let root = tmp.join("root");
        let evil = tmp.join("root2");
        let _ = std::fs::create_dir_all(&root);
        let _ = std::fs::create_dir_all(&evil);
        std::fs::write(evil.join("real.nse"), "-- content").unwrap();

        let result = validate_existing_path_under_roots(&evil.join("real.nse"), &[root.clone()]);
        assert!(matches!(result, Err(NseLoadError::OutsideRoot { .. })));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_validate_existing_path_under_roots_rejects_nonexistent_path_outside_root() {
        let roots = vec![PathBuf::from("/tmp/root")];
        // Non-existent file outside root should be rejected with IoError
        // (NOT authorized just because parent canonicalizes).
        let result =
            validate_existing_path_under_roots(Path::new("/tmp/outside/secret.lua"), &roots);
        assert!(matches!(result, Err(NseLoadError::IoError { .. })));
    }

    #[test]
    fn test_validate_existing_path_under_roots_rejects_nonexistent_path_inside_root() {
        // Non-existent file inside an approved root must NOT be authorized
        // merely because the root directory exists. The read helper requires
        // the canonical file path to resolve.
        let tmp = std::env::temp_dir().join("eggsec-nse-read-nonexistent-test");
        let _ = std::fs::create_dir_all(&tmp);
        let roots = vec![tmp.clone()];

        let missing = tmp.join("does-not-exist.nse");
        let result = validate_existing_path_under_roots(&missing, &roots);
        assert!(
            matches!(result, Err(NseLoadError::IoError { .. })),
            "Expected IoError for non-existent file, got: {:?}",
            result
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_validate_existing_path_under_roots_accepts_existing_inside_root() {
        let tmp = std::env::temp_dir().join("eggsec-nse-read-existing-test");
        let _ = std::fs::create_dir_all(&tmp);
        let file = tmp.join("real.nse");
        std::fs::write(&file, "-- script").unwrap();

        let roots = vec![tmp.clone()];
        let result = validate_existing_path_under_roots(&file, &roots);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), file.canonicalize().unwrap());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_validate_existing_path_under_roots_rejects_existing_outside_root() {
        // An existing file outside the approved root is rejected even when
        // the root itself exists.
        let tmp = std::env::temp_dir().join("eggsec-nse-read-outside-test");
        let root = tmp.join("root");
        let evil = tmp.join("root_evil");
        let _ = std::fs::create_dir_all(&root);
        let _ = std::fs::create_dir_all(&evil);
        let file = evil.join("real.nse");
        std::fs::write(&file, "-- script").unwrap();

        let roots = vec![root.clone()];
        let result = validate_existing_path_under_roots(&file, &roots);
        assert!(matches!(result, Err(NseLoadError::OutsideRoot { .. })));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_validate_symlink_containment_rejects_escape() {
        // Create a temp directory structure with a symlink
        let tmp = std::env::temp_dir().join("eggsec-nse-symlink-test");
        let allowed = tmp.join("allowed");
        let outside = tmp.join("outside");
        let _ = std::fs::create_dir_all(&allowed);
        let _ = std::fs::create_dir_all(&outside);

        // Create a file outside the allowed root
        std::fs::write(outside.join("secret.txt"), "secret").unwrap();

        // Create a symlink inside allowed pointing to the outside file
        let link = allowed.join("escape.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.join("secret.txt"), &link).unwrap();

        // The symlink should be rejected
        let result = validate_symlink_containment(&link, &[allowed.clone()]);
        assert!(result.is_err());
        match result.unwrap_err() {
            NseLoadError::SymlinkEscape { path, resolved } => {
                assert_eq!(path, link);
                assert!(resolved.starts_with(&outside));
            }
            other => panic!("Expected SymlinkEscape, got {:?}", other),
        }

        // Clean up
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_validate_symlink_containment_allows_internal_symlink() {
        // Create a temp directory with a symlink to another file inside the root
        let tmp = std::env::temp_dir().join("eggsec-nse-symlink-ok-test");
        let allowed = tmp.join("allowed");
        let _ = std::fs::create_dir_all(allowed.join("sub"));

        // Create a real file inside the root
        std::fs::write(allowed.join("real.txt"), "content").unwrap();

        // Create a symlink inside allowed pointing to the real file
        let link = allowed.join("sub").join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(allowed.join("real.txt"), &link).unwrap();

        // The symlink should be allowed (resolves inside root)
        let result = validate_symlink_containment(&link, &[allowed.clone()]);
        assert!(result.is_ok());

        // Clean up
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_validate_existing_path_under_roots_rejects_absolute_traversal() {
        let roots = vec![PathBuf::from("/tmp/root")];
        // Absolute path outside root should be rejected with IoError
        // (since /etc/passwd does not exist in the test environment is possible,
        // but the canonical form is also outside the root).
        let result = validate_existing_path_under_roots(Path::new("/etc/passwd"), &roots);
        assert!(result.is_err());
    }

    #[test]
    fn test_canonicalize_root_rejects_nonexistent() {
        // A root that doesn't exist should return None
        let result = canonicalize_root(Path::new("/tmp/nonexistent-root-eggsec-nse"));
        assert!(result.is_none());
    }

    #[test]
    fn test_canonicalize_root_accepts_existing() {
        // An existing root should return Some
        let tmp = std::env::temp_dir().join("eggsec-nse-root-test");
        let _ = std::fs::create_dir_all(&tmp);
        let result = canonicalize_root(&tmp);
        assert!(result.is_some());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
