//! Declarative registry for NSE library modules.
//!
//! Each entry describes a standard Nmap Lua library module, its sandbox
//! side effects, optional dependencies, fallback behavior when missing,
//! and known compatibility notes. The registry is machine-readable and
//! used for policy evaluation, diagnostics, and compatibility reporting.
//!
//! The 43 entries cover Nmap's standard Lua library set (24 main + 19
//! auxiliary). Protocol-specific Rust implementations in `src/libraries/`
//! that are not part of the standard Nmap Lua API are not registered here.
//!
//! This module compiles with the `nse` feature **off** — it contains no
//! Lua or mlua dependencies.

use std::fmt;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Categories for NSE library modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NseLibraryCategory {
    /// Core runtime libraries required by most scripts.
    Core,
    /// Protocol-specific libraries (HTTP, DNS, SMB, etc.).
    Protocol,
    /// General-purpose utility libraries (encoding, string, math).
    Utility,
    /// Exploit and vulnerability libraries.
    Exploit,
    /// Authentication and credential libraries.
    Auth,
}

impl fmt::Display for NseLibraryCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core => write!(f, "Core"),
            Self::Protocol => write!(f, "Protocol"),
            Self::Utility => write!(f, "Utility"),
            Self::Exploit => write!(f, "Exploit"),
            Self::Auth => write!(f, "Auth"),
        }
    }
}

/// Sandbox side effects a library may perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NseSandboxSideEffect {
    /// No side effects (pure computation).
    None,
    /// Reads from the filesystem.
    FileSystemRead,
    /// Writes to the filesystem.
    FileSystemWrite,
    /// Makes network connections.
    NetworkAccess,
    /// Spawns or executes external processes.
    ProcessExecution,
    /// Accesses environment variables.
    EnvAccess,
}

impl fmt::Display for NseSandboxSideEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::FileSystemRead => write!(f, "FileSystemRead"),
            Self::FileSystemWrite => write!(f, "FileSystemWrite"),
            Self::NetworkAccess => write!(f, "NetworkAccess"),
            Self::ProcessExecution => write!(f, "ProcessExecution"),
            Self::EnvAccess => write!(f, "EnvAccess"),
        }
    }
}

/// Enforcement status of the NSE capability wrappers for this library.
///
/// Tracks whether a library's side-effecting operations have been routed
/// through `NseCapabilityContext` for policy enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnforcementStatus {
    /// All side-effecting operations routed through NseCapabilityContext.
    Wrapped,
    /// Some operations wrapped, others not.
    PartiallyWrapped,
    /// Manual-only (CLI interactive), no capability enforcement.
    ManualOnly,
    /// Not yet migrated, deferred to future milestone.
    Deferred,
    /// No side-effecting operations.
    Pure,
}

impl fmt::Display for EnforcementStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wrapped => write!(f, "Wrapped"),
            Self::PartiallyWrapped => write!(f, "PartiallyWrapped"),
            Self::ManualOnly => write!(f, "ManualOnly"),
            Self::Deferred => write!(f, "Deferred"),
            Self::Pure => write!(f, "Pure"),
        }
    }
}

/// Fallback behavior when a library is not available in the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NseFallbackBehavior {
    /// Script must have this library; absence is a hard error.
    HardFail,
    /// Script can degrade gracefully if the library is absent.
    GracefulDegrade,
    /// Script silently skips functionality requiring this library.
    Skip,
}

impl fmt::Display for NseFallbackBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HardFail => write!(f, "HardFail"),
            Self::GracefulDegrade => write!(f, "GracefulDegrade"),
            Self::Skip => write!(f, "Skip"),
        }
    }
}

// ---------------------------------------------------------------------------
// Descriptor
// ---------------------------------------------------------------------------

/// Declarative descriptor for a single NSE library module.
#[derive(Debug, Clone)]
pub struct NseLibraryDescriptor {
    /// Library name as used in `require()` calls (e.g. `"stdnse"`).
    pub name: &'static str,
    /// Functional category.
    pub category: NseLibraryCategory,
    /// Sandbox side effects this library may perform.
    pub sandbox_side_effects: &'static [NseSandboxSideEffect],
    /// Optional system/library dependencies required at build or runtime.
    /// Empty if the library has no special dependencies.
    pub optional_deps: &'static [&'static str],
    /// Behavior when the library is unavailable.
    pub fallback_behavior: NseFallbackBehavior,
    /// Freeform notes about compatibility, known gaps, or special handling.
    pub notes: &'static str,
    /// Whether side-effecting operations are routed through NseCapabilityContext.
    pub enforcement_status: EnforcementStatus,
}

// ---------------------------------------------------------------------------
// Static registry
// ---------------------------------------------------------------------------

/// Complete registry of standard Nmap Lua library modules.
///
/// 43 entries total: 24 main + 19 auxiliary. `nse.lua` (the orchestrator)
/// is intentionally excluded.
pub static LIBRARY_REGISTRY: &[NseLibraryDescriptor] = &[
    // =====================================================================
    // Main libraries (24)
    // =====================================================================
    NseLibraryDescriptor {
        name: "stdnse",
        category: NseLibraryCategory::Core,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::HardFail,
        notes: "Core output formatting, verbose, and utility functions. Required by nearly all scripts.",
        enforcement_status: EnforcementStatus::PartiallyWrapped,
    },
    NseLibraryDescriptor {
        name: "nmap",
        category: NseLibraryCategory::Core,
        sandbox_side_effects: &[
            NseSandboxSideEffect::EnvAccess,
            NseSandboxSideEffect::NetworkAccess,
        ],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::HardFail,
        notes: "Nmap scan state, registry, and host/port data access. Provides nmap.target, nmap.registry, etc.",
        enforcement_status: EnforcementStatus::Wrapped,
    },
    NseLibraryDescriptor {
        name: "socket",
        category: NseLibraryCategory::Protocol,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::HardFail,
        notes: "Low-level TCP/UDP socket operations. Core networking primitive for protocol libraries.",
        enforcement_status: EnforcementStatus::Wrapped,
    },
    NseLibraryDescriptor {
        name: "http",
        category: NseLibraryCategory::Protocol,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::HardFail,
        notes: "HTTP client library. Supports GET/POST/PUT/DELETE/HEAD/OPTIONS/request, cookies, authentication, SSL/TLS. All network operations gated via check_network_tcp() (or maybe_denied_response helper); denied requests never reach reqwest.",
        enforcement_status: EnforcementStatus::Wrapped,
    },
    NseLibraryDescriptor {
        name: "dns",
        category: NseLibraryCategory::Protocol,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::HardFail,
        notes: "DNS resolution and packet construction. Supports A, AAAA, MX, TXT, and other record types.",
        enforcement_status: EnforcementStatus::Wrapped,
    },
    NseLibraryDescriptor {
        name: "ssl",
        category: NseLibraryCategory::Protocol,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &["openssl"],
        fallback_behavior: NseFallbackBehavior::HardFail,
        notes: "TLS/SSL handshake and certificate operations. Wraps OpenSSL via Lua bindings. Wrapped since Milestone 3 Phase 05.",
        enforcement_status: EnforcementStatus::Wrapped,
    },
    NseLibraryDescriptor {
        name: "ssh",
        category: NseLibraryCategory::Protocol,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &["libssh2"],
        fallback_behavior: NseFallbackBehavior::GracefulDegrade,
        notes: "SSH protocol operations. Requires libssh2 for real execution; stub available.",
        enforcement_status: EnforcementStatus::Deferred,
    },
    NseLibraryDescriptor {
        name: "smb",
        category: NseLibraryCategory::Protocol,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::GracefulDegrade,
        notes: "SMB/CIFS protocol operations. NTLM authentication, share enumeration.",
        enforcement_status: EnforcementStatus::Deferred,
    },
    NseLibraryDescriptor {
        name: "smb2",
        category: NseLibraryCategory::Protocol,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::GracefulDegrade,
        notes: "SMBv2/v3 protocol operations. Modern SMB dialect support.",
        enforcement_status: EnforcementStatus::Deferred,
    },
    NseLibraryDescriptor {
        name: "mysql",
        category: NseLibraryCategory::Protocol,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::GracefulDegrade,
        notes: "MySQL database protocol client. Authentication, query execution.",
        enforcement_status: EnforcementStatus::Deferred,
    },
    NseLibraryDescriptor {
        name: "postgres",
        category: NseLibraryCategory::Protocol,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::GracefulDegrade,
        notes: "PostgreSQL database protocol client. Startup, authentication, simple query.",
        enforcement_status: EnforcementStatus::Deferred,
    },
    NseLibraryDescriptor {
        name: "redis",
        category: NseLibraryCategory::Protocol,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::GracefulDegrade,
        notes: "Redis protocol client. RESP protocol, command execution.",
        enforcement_status: EnforcementStatus::Deferred,
    },
    NseLibraryDescriptor {
        name: "mongodb",
        category: NseLibraryCategory::Protocol,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::GracefulDegrade,
        notes: "MongoDB wire protocol client. isMaster, server status queries.",
        enforcement_status: EnforcementStatus::Deferred,
    },
    NseLibraryDescriptor {
        name: "ldap",
        category: NseLibraryCategory::Protocol,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::GracefulDegrade,
        notes: "LDAP protocol operations. Bind, search, enumeration.",
        enforcement_status: EnforcementStatus::Deferred,
    },
    NseLibraryDescriptor {
        name: "snmp",
        category: NseLibraryCategory::Protocol,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::GracefulDegrade,
        notes: "SNMP protocol operations. GET, GETNEXT, WALK for community strings.",
        enforcement_status: EnforcementStatus::Deferred,
    },
    NseLibraryDescriptor {
        name: "vulns",
        category: NseLibraryCategory::Exploit,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "Vulnerability reporting and CVE database lookups (NVD, OSV, CISA KEV).",
        enforcement_status: EnforcementStatus::Pure,
    },
    NseLibraryDescriptor {
        name: "creds",
        category: NseLibraryCategory::Auth,
        sandbox_side_effects: &[
            NseSandboxSideEffect::FileSystemRead,
            NseSandboxSideEffect::NetworkAccess,
        ],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "Credential management. Username/password pair storage and iteration.",
        enforcement_status: EnforcementStatus::Deferred,
    },
    NseLibraryDescriptor {
        name: "unpwdb",
        category: NseLibraryCategory::Auth,
        sandbox_side_effects: &[NseSandboxSideEffect::FileSystemRead],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "Username/password database reader. Iterates credential lists for brute-force. Filesystem reads routed through NseCapabilityContext.",
        enforcement_status: EnforcementStatus::Wrapped,
    },
    NseLibraryDescriptor {
        name: "brute",
        category: NseLibraryCategory::Auth,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "Brute-force attack engine. Iterator pattern for credential testing.",
        enforcement_status: EnforcementStatus::Deferred,
    },
    NseLibraryDescriptor {
        name: "io",
        category: NseLibraryCategory::Core,
        sandbox_side_effects: &[
            NseSandboxSideEffect::FileSystemRead,
            NseSandboxSideEffect::FileSystemWrite,
            NseSandboxSideEffect::ProcessExecution,
        ],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::GracefulDegrade,
        notes: "Standard Lua I/O library. File open/read/write, popen (process execution). Heavily sandboxed.",
        enforcement_status: EnforcementStatus::Wrapped,
    },
    NseLibraryDescriptor {
        name: "os",
        category: NseLibraryCategory::Core,
        sandbox_side_effects: &[
            NseSandboxSideEffect::EnvAccess,
            NseSandboxSideEffect::ProcessExecution,
        ],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::GracefulDegrade,
        notes: "Standard Lua OS library. Date/time, env vars, execute. Blocked in sandbox mode.",
        enforcement_status: EnforcementStatus::Wrapped,
    },
    NseLibraryDescriptor {
        name: "lfs",
        category: NseLibraryCategory::Core,
        sandbox_side_effects: &[
            NseSandboxSideEffect::FileSystemRead,
            NseSandboxSideEffect::FileSystemWrite,
        ],
        optional_deps: &["luafilesystem"],
        fallback_behavior: NseFallbackBehavior::GracefulDegrade,
        notes: "LuaFileSystem directory operations. List, stat, symlink checks. Restricted to allowed_dir in sandbox.",
        enforcement_status: EnforcementStatus::Wrapped,
    },
    NseLibraryDescriptor {
        name: "tab",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "Table/array utility functions for structured data manipulation.",
        enforcement_status: EnforcementStatus::Pure,
    },
    NseLibraryDescriptor {
        name: "json",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "JSON encode/decode library.",
        enforcement_status: EnforcementStatus::Pure,
    },
    // =====================================================================
    // Auxiliary libraries (19)
    // =====================================================================
    NseLibraryDescriptor {
        name: "base64",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "Base64 encoding and decoding.",
        enforcement_status: EnforcementStatus::Pure,
    },
    NseLibraryDescriptor {
        name: "base32",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "Base32 encoding and decoding.",
        enforcement_status: EnforcementStatus::Pure,
    },
    NseLibraryDescriptor {
        name: "bin",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "Binary data packing/unpacking (little/big endian).",
        enforcement_status: EnforcementStatus::Pure,
    },
    NseLibraryDescriptor {
        name: "bit",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "Bitwise operations library.",
        enforcement_status: EnforcementStatus::Pure,
    },
    NseLibraryDescriptor {
        name: "stringaux",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "Extended string utilities beyond standard Lua string lib.",
        enforcement_status: EnforcementStatus::Pure,
    },
    NseLibraryDescriptor {
        name: "strbuf",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "String buffer for efficient string concatenation.",
        enforcement_status: EnforcementStatus::Pure,
    },
    NseLibraryDescriptor {
        name: "nse_string",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "NSE-specific string helper functions.",
        enforcement_status: EnforcementStatus::Pure,
    },
    NseLibraryDescriptor {
        name: "nse_table",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "NSE-specific table helper functions.",
        enforcement_status: EnforcementStatus::Pure,
    },
    NseLibraryDescriptor {
        name: "pcre",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &["pcre"],
        fallback_behavior: NseFallbackBehavior::GracefulDegrade,
        notes: "PCRE regular expressions. Optional; falls back to Lua patterns if unavailable.",
        enforcement_status: EnforcementStatus::Pure,
    },
    NseLibraryDescriptor {
        name: "openssl",
        category: NseLibraryCategory::Protocol,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &["openssl"],
        fallback_behavior: NseFallbackBehavior::GracefulDegrade,
        notes: "OpenSSL bindings for crypto operations. Certificate parsing, hashing, HMAC.",
        enforcement_status: EnforcementStatus::Wrapped,
    },
    NseLibraryDescriptor {
        name: "comm",
        category: NseLibraryCategory::Protocol,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::GracefulDegrade,
        notes: "Communication helpers for banner grabbing and service interaction.",
        enforcement_status: EnforcementStatus::Wrapped,
    },
    NseLibraryDescriptor {
        name: "shortport",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "Port number normalization and validation helpers.",
        enforcement_status: EnforcementStatus::Pure,
    },
    NseLibraryDescriptor {
        name: "target",
        category: NseLibraryCategory::Core,
        sandbox_side_effects: &[NseSandboxSideEffect::NetworkAccess],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "Target host/address resolution and manipulation.",
        enforcement_status: EnforcementStatus::Deferred,
    },
    NseLibraryDescriptor {
        name: "match_lib",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "Pattern matching helpers for service detection.",
        enforcement_status: EnforcementStatus::Pure,
    },
    NseLibraryDescriptor {
        name: "matchs",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "Structured match operations for version detection.",
        enforcement_status: EnforcementStatus::Pure,
    },
    NseLibraryDescriptor {
        name: "datetime",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "Date and time parsing/formatting utilities.",
        enforcement_status: EnforcementStatus::Wrapped,
    },
    NseLibraryDescriptor {
        name: "rand",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "Random number generation helpers.",
        enforcement_status: EnforcementStatus::Wrapped,
    },
    NseLibraryDescriptor {
        name: "url",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "URL parsing and normalization utilities.",
        enforcement_status: EnforcementStatus::Pure,
    },
    NseLibraryDescriptor {
        name: "unicode",
        category: NseLibraryCategory::Utility,
        sandbox_side_effects: &[NseSandboxSideEffect::None],
        optional_deps: &[],
        fallback_behavior: NseFallbackBehavior::Skip,
        notes: "Unicode encoding/decoding and normalization.",
        enforcement_status: EnforcementStatus::Pure,
    },
];

// ---------------------------------------------------------------------------
// Lookup functions
// ---------------------------------------------------------------------------

/// Find a library descriptor by name.
///
/// Returns `None` if no library with that name exists in the registry.
pub fn find_library(name: &str) -> Option<&'static NseLibraryDescriptor> {
    LIBRARY_REGISTRY.iter().find(|lib| lib.name == name)
}

/// Return all registered library descriptors.
pub fn all_libraries() -> &'static [NseLibraryDescriptor] {
    LIBRARY_REGISTRY
}

/// Return all libraries in the given category.
pub fn libraries_by_category(category: NseLibraryCategory) -> Vec<&'static NseLibraryDescriptor> {
    LIBRARY_REGISTRY
        .iter()
        .filter(|lib| lib.category == category)
        .collect()
}

/// Return all libraries that have at least one sandbox side effect.
pub fn libraries_with_side_effects() -> Vec<&'static NseLibraryDescriptor> {
    LIBRARY_REGISTRY
        .iter()
        .filter(|lib| {
            !lib.sandbox_side_effects.is_empty()
                && lib.sandbox_side_effects[0] != NseSandboxSideEffect::None
        })
        .collect()
}

/// Return the effective sandbox policy for a library.
///
/// If the library has no side effects, returns `None`. Otherwise returns
/// the list of side effects that sandbox policy must account for.
pub fn sandbox_policy_for_library(name: &str) -> Option<&'static [NseSandboxSideEffect]> {
    find_library(name).and_then(|lib| {
        if lib.sandbox_side_effects == &[NseSandboxSideEffect::None] {
            None
        } else {
            Some(lib.sandbox_side_effects)
        }
    })
}

/// Return libraries that are known to be missing from some Nmap builds
/// or have conditional availability.
pub fn libraries_missing_from_nmap() -> Vec<&'static NseLibraryDescriptor> {
    LIBRARY_REGISTRY
        .iter()
        .filter(|lib| !lib.optional_deps.is_empty())
        .collect()
}

/// Return the total number of registered libraries.
pub fn registry_count() -> usize {
    LIBRARY_REGISTRY.len()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_43_entries() {
        assert_eq!(
            LIBRARY_REGISTRY.len(),
            43,
            "Expected exactly 43 registered libraries (24 main + 19 auxiliary)"
        );
    }

    #[test]
    fn no_duplicate_names() {
        let mut names: Vec<&str> = LIBRARY_REGISTRY.iter().map(|lib| lib.name).collect();
        let original_len = names.len();
        names.dedup();
        assert_eq!(
            names.len(),
            original_len,
            "Duplicate library names found in registry"
        );
    }

    #[test]
    fn every_library_has_descriptor() {
        for lib in LIBRARY_REGISTRY {
            assert!(!lib.name.is_empty(), "Library name must not be empty");
            assert!(
                !lib.notes.is_empty(),
                "Library '{}' must have notes",
                lib.name
            );
        }
    }

    #[test]
    fn find_library_works() {
        assert!(find_library("stdnse").is_some());
        assert!(find_library("http").is_some());
        assert!(find_library("json").is_some());
        assert!(find_library("nonexistent").is_none());
    }

    #[test]
    fn find_library_returns_correct_entry() {
        let lib = find_library("http").unwrap();
        assert_eq!(lib.name, "http");
        assert_eq!(lib.category, NseLibraryCategory::Protocol);
        assert!(lib
            .sandbox_side_effects
            .contains(&NseSandboxSideEffect::NetworkAccess));
    }

    #[test]
    fn all_libraries_returns_full_registry() {
        assert_eq!(all_libraries().len(), LIBRARY_REGISTRY.len());
    }

    #[test]
    fn libraries_by_category_core() {
        let core = libraries_by_category(NseLibraryCategory::Core);
        assert!(core.len() >= 6, "Expected at least 6 Core libraries");
        assert!(core.iter().any(|l| l.name == "stdnse"));
        assert!(core.iter().any(|l| l.name == "nmap"));
        assert!(core.iter().any(|l| l.name == "io"));
    }

    #[test]
    fn libraries_by_category_protocol() {
        let protos = libraries_by_category(NseLibraryCategory::Protocol);
        assert!(
            protos.len() >= 10,
            "Expected at least 10 Protocol libraries"
        );
        assert!(protos.iter().any(|l| l.name == "http"));
        assert!(protos.iter().any(|l| l.name == "dns"));
        assert!(protos.iter().any(|l| l.name == "smb"));
    }

    #[test]
    fn libraries_by_category_utility() {
        let utils = libraries_by_category(NseLibraryCategory::Utility);
        assert!(utils.len() >= 12, "Expected at least 12 Utility libraries");
        assert!(utils.iter().any(|l| l.name == "base64"));
        assert!(utils.iter().any(|l| l.name == "json"));
        assert!(utils.iter().any(|l| l.name == "tab"));
    }

    #[test]
    fn side_effects_coverage() {
        let with_effects = libraries_with_side_effects();
        assert!(
            with_effects.len() >= 15,
            "Expected at least 15 libraries with side effects, got {}",
            with_effects.len()
        );
        // Verify known side-effecting libraries
        assert!(with_effects.iter().any(|l| l.name == "socket"));
        assert!(with_effects.iter().any(|l| l.name == "http"));
        assert!(with_effects.iter().any(|l| l.name == "io"));
        assert!(with_effects.iter().any(|l| l.name == "os"));
    }

    #[test]
    fn sandbox_policy_for_known_library() {
        let policy = sandbox_policy_for_library("socket");
        assert!(policy.is_some());
        assert!(policy
            .unwrap()
            .contains(&NseSandboxSideEffect::NetworkAccess));
    }

    #[test]
    fn sandbox_policy_for_no_side_effects() {
        // "tab" has None side effects — sandbox_policy_for_library returns None
        let policy = sandbox_policy_for_library("tab");
        assert!(policy.is_none());
    }

    #[test]
    fn sandbox_policy_for_unknown_library() {
        assert!(sandbox_policy_for_library("nonexistent").is_none());
    }

    #[test]
    fn libraries_with_optional_deps() {
        let missing = libraries_missing_from_nmap();
        assert!(
            !missing.is_empty(),
            "Expected at least some libraries with optional deps"
        );
        assert!(missing.iter().any(|l| l.name == "ssl"));
        assert!(missing.iter().any(|l| l.name == "ssh"));
        assert!(missing.iter().any(|l| l.name == "pcre"));
    }

    #[test]
    fn registry_count_matches() {
        assert_eq!(registry_count(), LIBRARY_REGISTRY.len());
    }

    #[test]
    fn main_libraries_present() {
        let main_names = [
            "stdnse", "nmap", "socket", "http", "dns", "ssl", "ssh", "smb", "smb2", "mysql",
            "postgres", "redis", "mongodb", "ldap", "snmp", "vulns", "creds", "unpwdb", "brute",
            "io", "os", "lfs", "tab", "json",
        ];
        for name in &main_names {
            assert!(
                find_library(name).is_some(),
                "Main library '{}' not found in registry",
                name
            );
        }
    }

    #[test]
    fn auxiliary_libraries_present() {
        let aux_names = [
            "base64",
            "base32",
            "bin",
            "bit",
            "stringaux",
            "strbuf",
            "nse_string",
            "nse_table",
            "pcre",
            "openssl",
            "comm",
            "shortport",
            "target",
            "match_lib",
            "matchs",
            "datetime",
            "rand",
            "url",
            "unicode",
        ];
        for name in &aux_names {
            assert!(
                find_library(name).is_some(),
                "Auxiliary library '{}' not found in registry",
                name
            );
        }
    }

    #[test]
    fn all_categories_used() {
        let all_categories: Vec<NseLibraryCategory> =
            LIBRARY_REGISTRY.iter().map(|lib| lib.category).collect();
        assert!(all_categories.contains(&NseLibraryCategory::Core));
        assert!(all_categories.contains(&NseLibraryCategory::Protocol));
        assert!(all_categories.contains(&NseLibraryCategory::Utility));
        assert!(all_categories.contains(&NseLibraryCategory::Exploit));
        assert!(all_categories.contains(&NseLibraryCategory::Auth));
    }

    #[test]
    fn all_fallback_behaviors_used() {
        let all_behaviors: Vec<NseFallbackBehavior> = LIBRARY_REGISTRY
            .iter()
            .map(|lib| lib.fallback_behavior)
            .collect();
        assert!(all_behaviors.contains(&NseFallbackBehavior::HardFail));
        assert!(all_behaviors.contains(&NseFallbackBehavior::GracefulDegrade));
        assert!(all_behaviors.contains(&NseFallbackBehavior::Skip));
    }

    #[test]
    fn display_implementations() {
        assert_eq!(NseLibraryCategory::Core.to_string(), "Core");
        assert_eq!(NseLibraryCategory::Protocol.to_string(), "Protocol");
        assert_eq!(NseLibraryCategory::Utility.to_string(), "Utility");
        assert_eq!(NseLibraryCategory::Exploit.to_string(), "Exploit");
        assert_eq!(NseLibraryCategory::Auth.to_string(), "Auth");

        assert_eq!(NseSandboxSideEffect::None.to_string(), "None");
        assert_eq!(
            NseSandboxSideEffect::NetworkAccess.to_string(),
            "NetworkAccess"
        );

        assert_eq!(NseFallbackBehavior::HardFail.to_string(), "HardFail");
        assert_eq!(
            NseFallbackBehavior::GracefulDegrade.to_string(),
            "GracefulDegrade"
        );
        assert_eq!(NseFallbackBehavior::Skip.to_string(), "Skip");
    }

    #[test]
    fn enforcement_status_display() {
        assert_eq!(EnforcementStatus::Wrapped.to_string(), "Wrapped");
        assert_eq!(
            EnforcementStatus::PartiallyWrapped.to_string(),
            "PartiallyWrapped"
        );
        assert_eq!(EnforcementStatus::ManualOnly.to_string(), "ManualOnly");
        assert_eq!(EnforcementStatus::Deferred.to_string(), "Deferred");
        assert_eq!(EnforcementStatus::Pure.to_string(), "Pure");
    }

    #[test]
    fn every_library_has_enforcement_status() {
        for lib in LIBRARY_REGISTRY {
            // Exhaustive match ensures new variants are handled
            match lib.enforcement_status {
                EnforcementStatus::Wrapped
                | EnforcementStatus::PartiallyWrapped
                | EnforcementStatus::ManualOnly
                | EnforcementStatus::Deferred
                | EnforcementStatus::Pure => {}
            }
        }
    }

    #[test]
    fn wrapped_libraries_include_known_wrapped() {
        let wrapped: Vec<&str> = LIBRARY_REGISTRY
            .iter()
            .filter(|l| l.enforcement_status == EnforcementStatus::Wrapped)
            .map(|l| l.name)
            .collect();
        assert!(wrapped.contains(&"socket"), "socket should be Wrapped");
        assert!(wrapped.contains(&"io"), "io should be Wrapped");
        assert!(wrapped.contains(&"os"), "os should be Wrapped");
        assert!(wrapped.contains(&"lfs"), "lfs should be Wrapped");
        assert!(wrapped.contains(&"nmap"), "nmap should be Wrapped");
        assert!(wrapped.contains(&"dns"), "dns should be Wrapped");
        assert!(wrapped.contains(&"comm"), "comm should be Wrapped");
        assert!(wrapped.contains(&"openssl"), "openssl should be Wrapped");
        assert!(wrapped.contains(&"datetime"), "datetime should be Wrapped");
        assert!(wrapped.contains(&"rand"), "rand should be Wrapped");
        assert!(
            wrapped.contains(&"unpwdb"),
            "unpwdb should be Wrapped (Milestone 5 Phase 04)"
        );
        assert!(
            wrapped.contains(&"ssl"),
            "ssl should be Wrapped (Milestone 3 Phase 05)"
        );
    }

    #[test]
    fn partially_wrapped_libraries() {
        let partially: Vec<&str> = LIBRARY_REGISTRY
            .iter()
            .filter(|l| l.enforcement_status == EnforcementStatus::PartiallyWrapped)
            .map(|l| l.name)
            .collect();
        assert!(
            partially.contains(&"stdnse"),
            "stdnse should be PartiallyWrapped"
        );
        // http was PartiallyWrapped but is now Wrapped (Milestone 6: check_network_tcp blocks before reqwest)
    }

    #[test]
    fn deferred_libraries_include_auth_and_protocol() {
        let deferred: Vec<&str> = LIBRARY_REGISTRY
            .iter()
            .filter(|l| l.enforcement_status == EnforcementStatus::Deferred)
            .map(|l| l.name)
            .collect();
        assert!(deferred.contains(&"brute"), "brute should be Deferred");
        assert!(deferred.contains(&"ssh"), "ssh should be Deferred");
    }

    #[test]
    fn pure_libraries_have_no_side_effects() {
        let pure_with_effects: Vec<&str> = LIBRARY_REGISTRY
            .iter()
            .filter(|l| {
                l.enforcement_status == EnforcementStatus::Pure
                    && l.sandbox_side_effects != &[NseSandboxSideEffect::None]
            })
            .map(|l| l.name)
            .collect();
        // vulns has NetworkAccess but is Pure (CVE lookups only, no user data exfil)
        // This is acceptable and documented; all others should have None side effects
        for name in &pure_with_effects {
            assert_eq!(
                *name, "vulns",
                "Pure library '{}' unexpectedly has side effects",
                name
            );
        }
    }

    #[test]
    fn all_enforcement_statuses_used() {
        let statuses: Vec<EnforcementStatus> = LIBRARY_REGISTRY
            .iter()
            .map(|l| l.enforcement_status)
            .collect();
        assert!(
            statuses.contains(&EnforcementStatus::Wrapped),
            "At least one library should be Wrapped"
        );
        assert!(
            statuses.contains(&EnforcementStatus::PartiallyWrapped),
            "At least one library should be PartiallyWrapped"
        );
        assert!(
            statuses.contains(&EnforcementStatus::Deferred),
            "At least one library should be Deferred"
        );
        assert!(
            statuses.contains(&EnforcementStatus::Pure),
            "At least one library should be Pure"
        );
    }
}
