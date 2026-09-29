//! Automated library effect manifest (M007A).
//!
//! Provides the authoritative effect/eligibility classification for every
//! Lua library/global registered into the runtime, plus the additive
//! query API used by the registration gate, dynamic `require()` gate, and
//! HTTP authority assurance.
//!
//! ## Background
//!
//! The pre-M007A declarative `LIBRARY_REGISTRY` (43 entries) describes
//! standard Nmap Lua library compatibility metadata. It does not cover
//! the protocol-specific Rust implementations in `src/libraries/`, many
//! of which bypass capability-context consultation in their direct
//! network I/O paths (M005E source audit). For automated profiles to
//! fail closed, every registered Lua library/global must have an
//! effect classification.
//!
//! ## Effect classes
//!
//! Each classification is one of:
//!
//! - [`NseAutomatedLibraryEligibility::Pure`] — no host side effects.
//!   Safe under every profile (AgentSafe/CiSafe/Manual*).
//! - [`NseAutomatedLibraryEligibility::ProviderBacked`] — all
//!   automated-relevant side effects route through the capability-aware
//!   provider broker. Safe under AgentSafe and CiSafe.
//! - [`NseAutomatedLibraryEligibility::ManualOnlyDirectIo`] — direct
//!   host I/O remains (no provider injection). Unsafe under
//!   AgentSafe/CiSafe; reachable only under manual profiles.
//! - [`NseAutomatedLibraryEligibility::ManualOnlyAdvisory`] — capability
//!   consultation exists but direct effects remain outside provider
//!   cancellation/accounting/authority. Unsafe under AgentSafe/CiSafe;
//!   reachable only under manual profiles.
//!
//! Unknown or unclassified names are manual-only by default.
//!
//! ## Invariants
//!
//! - This module compiles with the `nse` feature **off** (no Lua/mlua
//!   dependency); see test-only annotations where needed.
//! - Existing `LIBRARY_REGISTRY` descriptor struct layout is untouched.
//! - Adding a new variant requires updating both [`classify`] and
//!   [`automated_library_eligibility_for_profile`], plus tests in
//!   [`tests::every_registration_has_classification`].
//!
//! ## Eligibility API
//!
//! - [`automated_library_eligibility`] — return the raw class for a name.
//! - [`is_automated_library_safe`] — profile-gated safety predicate.
//! - [`eligible_for_profile`] — same predicate without the unsafe suffix.
//! - [`classified_libraries`] — all entries sorted by name for
//!   diagnostics, guard assertions, and report enrichment.
//!
//! The pre-existing `NseLibraryDescriptor::enforcement_status` field
//! remains the source of truth for declarative library compatibility;
//! this manifest only adds automated-profile gating.
//!
//! ## Registration consistency (M007B corrective)
//!
//! M007A recorded a low-severity gap: registration -> manifest coverage was
//! mechanically enforced, but manifest -> registration was not, leaving 12
//! compatibility entries whose modules are never registered. M007B closes
//! that gap in both directions:
//!
//! - `register_fn` on every entry is the exact function called from
//!   `ExecutorCore::register_libraries()` (not a base-name prefix);
//! - the remaining compatibility entries are pinned with a reviewed
//!   rationale in `scripts/nse-registration-compat-entries.txt`, which is
//!   the single source of truth for the reverse direction.
//!
//! Both directions are enforced by `tests::registration_and_manifest_agree`
//! and, for the shell-visible view, by `scripts/check-boundaries.sh`.

use std::fmt;

use crate::profile::NseExecutionProfileKind;

/// Eligibility class for automated (AgentSafe / CiSafe) execution.
///
/// Variants are exhaustive on purpose; adding a new class requires
/// updating every classification match arm and the relevant tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NseAutomatedLibraryEligibility {
    /// No host side effects. Safe under every profile.
    Pure,
    /// All automated-relevant side effects route through the
    /// capability-aware provider broker.
    ProviderBacked,
    /// Direct host I/O remains; no provider injection for the
    /// automated-relevant effects. Manual-only.
    ManualOnlyDirectIo,
    /// Some capability consultation exists but direct effects remain
    /// outside provider cancellation/accounting/authority. Manual-only.
    ManualOnlyAdvisory,
}

impl fmt::Display for NseAutomatedLibraryEligibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pure => write!(f, "Pure"),
            Self::ProviderBacked => write!(f, "ProviderBacked"),
            Self::ManualOnlyDirectIo => write!(f, "ManualOnlyDirectIo"),
            Self::ManualOnlyAdvisory => write!(f, "ManualOnlyAdvisory"),
        }
    }
}

/// Single classification entry: the Lua library/global name, the
/// source Rust module that registers it, and its eligibility class.
///
/// This struct is `Clone + Debug` so that callers can format it in
/// diagnostics, but it is **not** `Serialize` — the manifest is a
/// build-time, in-process security artifact, not a runtime data
/// contract.
#[derive(Debug, Clone)]
pub struct LibraryEffectEntry {
    /// Library/global name as exposed to Lua (e.g. `"http"`,
    /// `"stdnse"`, `"smb"`).
    pub name: &'static str,
    /// Path of the registering Rust source module relative to
    /// `src/`. Used by guard assertions to reconcile the manifest
    /// against the actual `register_libraries()` call site.
    pub source_module: &'static str,
    /// Function name used to register the library into the Lua VM
    /// (e.g. `"register_http_library_with_services"`).
    pub register_fn: &'static str,
    /// Eligibility class for automated profiles.
    pub eligibility: NseAutomatedLibraryEligibility,
    /// One-line note describing the rationale (M005E class, residual
    /// source, scope override, etc.).
    pub rationale: &'static str,
}

/// Complete authoritative classification for every Lua library/global
/// registered by `ExecutorCore::register_libraries()`.
///
/// The static slice is sorted alphabetically by `name`. New entries
/// MUST be appended in sorted order; sorting is enforced by a test.
///
/// M005E classification source: `scripts/nse-specialized-{advisory,
/// ungated}.txt` plus `docs/PROVIDERS.md:451-466`. The mapping below
/// is the **automatic-profile eligibility** view (not the capability
/// wrapper status, which is tracked by `LIBRARY_REGISTRY`).
pub static LIBRARY_EFFECT_MANIFEST: &[LibraryEffectEntry] = &[
    // ===== afp =====
    LibraryEffectEntry {
        name: "afp",
        source_module: "libraries/afp",
        register_fn: "register_afp_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== ajp =====
    LibraryEffectEntry {
        name: "ajp",
        source_module: "libraries/ajp",
        register_fn: "register_ajp_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== amqp =====
    LibraryEffectEntry {
        name: "amqp",
        source_module: "libraries/amqp",
        register_fn: "register_amqp_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== anyconnect =====
    LibraryEffectEntry {
        name: "anyconnect",
        source_module: "libraries/anyconnect",
        register_fn: "register_anyconnect_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== asn1 =====
    LibraryEffectEntry {
        name: "asn1",
        source_module: "libraries/asn1",
        register_fn: "register_asn1_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure ASN.1 BER encode/decode; no I/O.",
    },
    // ===== base32 =====
    LibraryEffectEntry {
        name: "base32",
        source_module: "libraries/base32",
        register_fn: "register_base32_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure encode/decode; no host side effects.",
    },
    // ===== base64 =====
    LibraryEffectEntry {
        name: "base64",
        source_module: "libraries/base64",
        register_fn: "register_base64_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure encode/decode; no host side effects.",
    },
    // ===== bin =====
    LibraryEffectEntry {
        name: "bin",
        source_module: "libraries/bin",
        register_fn: "register_bin_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure pack/unpack; no host side effects.",
    },
    // ===== bit =====
    LibraryEffectEntry {
        name: "bit",
        source_module: "libraries/bit",
        register_fn: "register_bit_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure bitwise ops; no host side effects.",
    },
    // ===== bitcoin =====
    LibraryEffectEntry {
        name: "bitcoin",
        source_module: "libraries/bitcoin",
        register_fn: "register_bitcoin_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== bits =====
    LibraryEffectEntry {
        name: "bits",
        source_module: "libraries/bits",
        register_fn: "register_bits_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure bit-stream utilities; no host side effects.",
    },
    // ===== bittorrent =====
    LibraryEffectEntry {
        name: "bittorrent",
        source_module: "libraries/bittorrent",
        register_fn: "register_bittorrent_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== bjnp =====
    LibraryEffectEntry {
        name: "bjnp",
        source_module: "libraries/bjnp",
        register_fn: "register_bjnp_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Unconnected/broadcast UDP send/recv; not brokered (M005E ungated).",
    },
    // ===== brute =====
    LibraryEffectEntry {
        name: "brute",
        source_module: "libraries/brute",
        register_fn: "register_brute_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: TCP login helpers use BrokeredTcpStream; HTTP-auth probes use broker_http_request; no direct socket effect remains.",
    },
    // ===== cassandra =====
    LibraryEffectEntry {
        name: "cassandra",
        source_module: "libraries/cassandra",
        register_fn: "register_cassandra_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== citrixxml =====
    LibraryEffectEntry {
        name: "citrixxml",
        source_module: "libraries/citrixxml",
        register_fn: "register_citrixxml_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== coap =====
    LibraryEffectEntry {
        name: "coap",
        source_module: "libraries/coap",
        register_fn: "register_coap_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct UDP/TCP framing; no capability ctx (M005E ungated).",
    },
    // ===== comm =====
    LibraryEffectEntry {
        name: "comm",
        source_module: "libraries/comm",
        register_fn: "register_comm_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "All TCP/TLS go through broker_tcp_connect + maybe_denied_response.",
    },
    // ===== creds =====
    LibraryEffectEntry {
        name: "creds",
        source_module: "libraries/creds",
        register_fn: "register_creds_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "In-memory credential store; no FS/network access.",
    },
    // ===== cvs =====
    LibraryEffectEntry {
        name: "cvs",
        source_module: "libraries/cvs",
        register_fn: "register_cvs_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== datafiles =====
    LibraryEffectEntry {
        name: "datafiles",
        source_module: "libraries/datafiles",
        register_fn: "register_datafiles_library",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "Filesystem reads via nse_fs_read_to_string; capability-gated.",
    },
    // ===== datetime =====
    LibraryEffectEntry {
        name: "datetime",
        source_module: "libraries/datetime",
        register_fn: "register_datetime_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "Clock routed through broker_unix_timestamp (provider-backed).",
    },
    // ===== dhcp =====
    LibraryEffectEntry {
        name: "dhcp",
        source_module: "libraries/dhcp",
        register_fn: "register_dhcp_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyAdvisory,
        rationale: "Capability ctx present; UDP send/recv paths bypass provider injection (M005E advisory).",
    },
    // ===== dhcp6 =====
    LibraryEffectEntry {
        name: "dhcp6",
        source_module: "libraries/dhcp6",
        register_fn: "register_dhcp6_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyAdvisory,
        rationale: "Capability ctx present; UDP send/recv paths bypass provider injection (M005E advisory).",
    },
    // ===== dicom =====
    LibraryEffectEntry {
        name: "dicom",
        source_module: "libraries/dicom",
        register_fn: "register_dicom_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== dns =====
    LibraryEffectEntry {
        name: "dns",
        source_module: "libraries/dns",
        register_fn: "register_dns_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "DNS broker + provider authority; resolve-select-connect identity preserved.",
    },
    // ===== dnssd =====
    LibraryEffectEntry {
        name: "dnssd",
        source_module: "libraries/dnssd",
        register_fn: "register_dnssd_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct UDP framing; no capability ctx (M005E ungated).",
    },
    // ===== drda =====
    LibraryEffectEntry {
        name: "drda",
        source_module: "libraries/drda",
        register_fn: "register_drda_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== eap =====
    LibraryEffectEntry {
        name: "eap",
        source_module: "libraries/eap",
        register_fn: "register_eap_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct UDP framing; no capability ctx (M005E ungated).",
    },
    // ===== eigrp =====
    LibraryEffectEntry {
        name: "eigrp",
        source_module: "libraries/eigrp",
        register_fn: "register_eigrp_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Raw packet send/receive; no provider contract (M005E ungated).",
    },
    // ===== finger =====
    LibraryEffectEntry {
        name: "finger",
        source_module: "libraries/finger",
        register_fn: "register_finger_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct TCP framing; no capability ctx (M005E ungated).",
    },
    // ===== formulas =====
    LibraryEffectEntry {
        name: "formulas",
        source_module: "libraries/formulas",
        register_fn: "register_formulas_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure numeric helpers; no host side effects.",
    },
    // ===== ftp =====
    LibraryEffectEntry {
        name: "ftp",
        source_module: "libraries/ftp",
        register_fn: "register_ftp_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: all blocking-TCP core sites use BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== geoip =====
    LibraryEffectEntry {
        name: "geoip",
        source_module: "libraries/geoip",
        register_fn: "register_geoip_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure lookup helpers; no I/O.",
    },
    // ===== giop =====
    LibraryEffectEntry {
        name: "giop",
        source_module: "libraries/giop",
        register_fn: "register_giop_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Stub-only registration; no capability ctx (M005E ungated).",
    },
    // ===== gps =====
    LibraryEffectEntry {
        name: "gps",
        source_module: "libraries/gps",
        register_fn: "register_gps_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct UDP framing; no capability ctx (M005E ungated).",
    },
    // ===== http =====
    LibraryEffectEntry {
        name: "http",
        source_module: "libraries/http",
        register_fn: "register_http_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "All HTTP ops gated via check_network_tcp / maybe_denied_response; broker_http_request authority-bound path required.",
    },
    // ===== http2 =====
    LibraryEffectEntry {
        name: "http2",
        source_module: "libraries/http2",
        register_fn: "register_http2_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "Reuses the http broker + provider.",
    },
    // ===== httppipeline =====
    LibraryEffectEntry {
        name: "httppipeline",
        source_module: "libraries/httppipeline",
        register_fn: "register_httppipeline_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "Pipeline brokered HTTP via broker_http_request.",
    },
    // ===== httpspider =====
    LibraryEffectEntry {
        name: "httpspider",
        source_module: "libraries/httpspider",
        register_fn: "register_httpspider_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Specialized native-HTTP-based crawler; not brokered (M005E specialized HTTP client).",
    },
    // ===== iax2 =====
    LibraryEffectEntry {
        name: "iax2",
        source_module: "libraries/iax2",
        register_fn: "register_iax2_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct UDP framing; no capability ctx (M005E ungated).",
    },
    // ===== idna =====
    LibraryEffectEntry {
        name: "idna",
        source_module: "libraries/idna",
        register_fn: "register_idna_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure IDNA encoding.",
    },
    // ===== iec61850mms =====
    LibraryEffectEntry {
        name: "iec61850mms",
        source_module: "libraries/iec61850mms",
        register_fn: "register_iec61850mms_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== ike =====
    LibraryEffectEntry {
        name: "ike",
        source_module: "libraries/ike",
        register_fn: "register_ike_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct UDP framing; no capability ctx (M005E ungated).",
    },
    // ===== imap =====
    LibraryEffectEntry {
        name: "imap",
        source_module: "libraries/imap",
        register_fn: "register_imap_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== informix =====
    LibraryEffectEntry {
        name: "informix",
        source_module: "libraries/informix",
        register_fn: "register_informix_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== io =====
    LibraryEffectEntry {
        name: "io",
        source_module: "libraries/io",
        register_fn: "register_io_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "FS/process brokers; capability-gated.",
    },
    // ===== ipmi =====
    LibraryEffectEntry {
        name: "ipmi",
        source_module: "libraries/ipmi",
        register_fn: "register_ipmi_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct UDP framing; no capability ctx (M005E ungated).",
    },
    // ===== ipops =====
    LibraryEffectEntry {
        name: "ipops",
        source_module: "libraries/ipops",
        register_fn: "register_ipops_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure IP/CIDR parsing; no host side effects.",
    },
    // ===== ipp =====
    LibraryEffectEntry {
        name: "ipp",
        source_module: "libraries/ipp",
        register_fn: "register_ipp_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== irc =====
    LibraryEffectEntry {
        name: "irc",
        source_module: "libraries/irc",
        register_fn: "register_irc_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== iscsi =====
    LibraryEffectEntry {
        name: "iscsi",
        source_module: "libraries/iscsi",
        register_fn: "register_iscsi_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== isns =====
    LibraryEffectEntry {
        name: "isns",
        source_module: "libraries/isns",
        register_fn: "register_isns_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== jdwp =====
    LibraryEffectEntry {
        name: "jdwp",
        source_module: "libraries/jdwp",
        register_fn: "register_jdwp_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== json =====
    LibraryEffectEntry {
        name: "json",
        source_module: "libraries/json",
        register_fn: "register_json_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure JSON encode/decode.",
    },
    // ===== kafka =====
    LibraryEffectEntry {
        name: "kafka",
        source_module: "libraries/kafka",
        register_fn: "register_kafka_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct TCP framing; no capability ctx (M005E ungated).",
    },
    // ===== knx =====
    LibraryEffectEntry {
        name: "knx",
        source_module: "libraries/knx",
        register_fn: "register_knx_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct UDP framing; no capability ctx (M005E ungated).",
    },
    // ===== ldap =====
    LibraryEffectEntry {
        name: "ldap",
        source_module: "libraries/ldap",
        register_fn: "register_ldap_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== lfs =====
    LibraryEffectEntry {
        name: "lfs",
        source_module: "libraries/lfs",
        register_fn: "register_lfs_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "LuaFileSystem via filesystem broker; sandboxed.",
    },
    // ===== libssh2 =====
    LibraryEffectEntry {
        name: "libssh2",
        source_module: "libraries/libssh2",
        register_fn: "register_libssh2_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyAdvisory,
        rationale: "Capability ctx accepted; native handle handoff to libssh2 remains manual (M005E advisory).",
    },
    // ===== libssh2_utility =====
    LibraryEffectEntry {
        name: "libssh2_utility",
        source_module: "libraries/libssh2_utility",
        register_fn: "register_libssh2_utility_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure utility helpers over libssh2 (no direct I/O).",
    },
    // ===== listop =====
    LibraryEffectEntry {
        name: "listop",
        source_module: "libraries/listop",
        register_fn: "register_listop_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure list operations.",
    },
    // ===== lpeg =====
    LibraryEffectEntry {
        name: "lpeg",
        source_module: "libraries/lpeg",
        register_fn: "register_lpeg_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure parsing expression grammar.",
    },
    // ===== lpeg_utility =====
    LibraryEffectEntry {
        name: "lpeg_utility",
        source_module: "libraries/lpeg_utility",
        register_fn: "register_lpeg_utility_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure LPeg helpers.",
    },
    // ===== ls =====
    LibraryEffectEntry {
        name: "ls",
        source_module: "libraries/ls",
        register_fn: "register_ls_library",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "Filesystem reads via provider; capability-gated.",
    },
    // ===== match_lib =====
    LibraryEffectEntry {
        name: "match_lib",
        source_module: "libraries/match_lib",
        register_fn: "register_match_lib_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure match helpers (not registered as global in current set; defensive).",
    },
    // ===== matchs =====
    LibraryEffectEntry {
        name: "matchs",
        source_module: "libraries/matchs",
        register_fn: "register_matchs_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure structured match helpers.",
    },
    // ===== membase =====
    LibraryEffectEntry {
        name: "membase",
        source_module: "libraries/membase",
        register_fn: "register_membase_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== memcached =====
    LibraryEffectEntry {
        name: "memcached",
        source_module: "libraries/memcached",
        register_fn: "register_memcached_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== mobileme =====
    LibraryEffectEntry {
        name: "mobileme",
        source_module: "libraries/mobileme",
        register_fn: "register_mobileme_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Specialized HTTP client; uses native HTTP client directly (M005E residual).",
    },
    // ===== mongodb =====
    LibraryEffectEntry {
        name: "mongodb",
        source_module: "libraries/mongodb",
        register_fn: "register_mongodb_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== mqtt =====
    LibraryEffectEntry {
        name: "mqtt",
        source_module: "libraries/mqtt",
        register_fn: "register_mqtt_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct TCP framing; no capability ctx (M005E ungated).",
    },
    // ===== msrpc =====
    LibraryEffectEntry {
        name: "msrpc",
        source_module: "libraries/msrpc",
        register_fn: "register_msrpc_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== msrpcperformance =====
    LibraryEffectEntry {
        name: "msrpcperformance",
        source_module: "libraries/msrpcperformance",
        register_fn: "register_msrpcperformance_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== msrpctypes =====
    LibraryEffectEntry {
        name: "msrpctypes",
        source_module: "libraries/msrpctypes",
        register_fn: "register_msrpctypes_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure type definitions; no I/O.",
    },
    // ===== mssql =====
    LibraryEffectEntry {
        name: "mssql",
        source_module: "libraries/mssql",
        register_fn: "register_mssql_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== multicast =====
    LibraryEffectEntry {
        name: "multicast",
        source_module: "libraries/multicast",
        register_fn: "register_multicast_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Unconnected/broadcast UDP; not brokered (M005E ungated).",
    },
    // ===== mysql =====
    LibraryEffectEntry {
        name: "mysql",
        source_module: "libraries/mysql",
        register_fn: "register_mysql_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== natpmp =====
    LibraryEffectEntry {
        name: "natpmp",
        source_module: "libraries/natpmp",
        register_fn: "register_natpmp_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Unconnected UDP send/recv; not brokered (M005E ungated).",
    },
    // ===== nbd =====
    LibraryEffectEntry {
        name: "nbd",
        source_module: "libraries/nbd",
        register_fn: "register_nbd_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== ncp =====
    LibraryEffectEntry {
        name: "ncp",
        source_module: "libraries/ncp",
        register_fn: "register_ncp_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== ndmp =====
    LibraryEffectEntry {
        name: "ndmp",
        source_module: "libraries/ndmp",
        register_fn: "register_ndmp_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== netbios =====
    LibraryEffectEntry {
        name: "netbios",
        source_module: "libraries/netbios",
        register_fn: "register_netbios_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== nmap =====
    LibraryEffectEntry {
        name: "nmap",
        source_module: "libraries/nmap",
        register_fn: "register_nmap_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "Lua-visible clock/random via broker; capability-aware process exec.",
    },
    // ===== nrpc =====
    LibraryEffectEntry {
        name: "nrpc",
        source_module: "libraries/nrpc",
        register_fn: "register_nrpc_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== nse_string =====
    LibraryEffectEntry {
        name: "nse_string",
        source_module: "libraries/nse_string",
        register_fn: "register_nse_string_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure string helpers.",
    },
    // ===== nse_table =====
    LibraryEffectEntry {
        name: "nse_table",
        source_module: "libraries/nse_table",
        register_fn: "register_nse_table_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure table helpers.",
    },
    // ===== ntp =====
    LibraryEffectEntry {
        name: "ntp",
        source_module: "libraries/ntp",
        register_fn: "register_ntp_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyAdvisory,
        rationale: "Capability ctx present; UDP send/receive bypasses provider injection (M005E advisory).",
    },
    // ===== omp2 =====
    LibraryEffectEntry {
        name: "omp2",
        source_module: "libraries/omp2",
        register_fn: "register_omp2_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: connect uses BrokeredTcpStream and the TLS handshake runs over that brokered stream.",
    },
    // ===== oops =====
    LibraryEffectEntry {
        name: "oops",
        source_module: "libraries/oops",
        register_fn: "register_oops_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== openssl =====
    LibraryEffectEntry {
        name: "openssl",
        source_module: "libraries/openssl",
        register_fn: "register_openssl_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: connects use BrokeredTcpStream and the TLS handshake runs over that brokered stream; no native handle escape.",
    },
    // ===== oracle =====
    LibraryEffectEntry {
        name: "oracle",
        source_module: "libraries/oracle",
        register_fn: "register_oracle_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== os =====
    LibraryEffectEntry {
        name: "os",
        source_module: "libraries/os",
        register_fn: "register_os_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "Env/time via brokers; some process exec residuals remain (manual-only under M007A).",
    },
    // ===== ospf =====
    LibraryEffectEntry {
        name: "ospf",
        source_module: "libraries/ospf",
        register_fn: "register_ospf_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Raw packet send/receive; outside provider contract (M005E ungated).",
    },
    // ===== outlib =====
    LibraryEffectEntry {
        name: "outlib",
        source_module: "libraries/outlib",
        register_fn: "register_outlib_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure output helpers.",
    },
    // ===== packet =====
    LibraryEffectEntry {
        name: "packet",
        source_module: "libraries/packet",
        register_fn: "register_packet_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Raw packet send/receive; outside provider contract (M005E ungated).",
    },
    // ===== pcre =====
    LibraryEffectEntry {
        name: "pcre",
        source_module: "libraries/pcre",
        register_fn: "register_pcre_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure regular expressions.",
    },
    // ===== pgsql =====
    LibraryEffectEntry {
        name: "pgsql",
        source_module: "libraries/pgsql",
        register_fn: "register_pgsql_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== pop3 =====
    LibraryEffectEntry {
        name: "pop3",
        source_module: "libraries/pop3",
        register_fn: "register_pop3_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== postgres =====
    LibraryEffectEntry {
        name: "postgres",
        source_module: "libraries/postgres",
        register_fn: "register_postgres_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: struct-held stream and blocking connect use BrokeredTcpStream; spawn_blocking async aliases call the brokered path.",
    },
    // ===== pppoe =====
    LibraryEffectEntry {
        name: "pppoe",
        source_module: "libraries/pppoe",
        register_fn: "register_pppoe_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct framing; no capability ctx (M005E ungated).",
    },
    // ===== proxy =====
    LibraryEffectEntry {
        name: "proxy",
        source_module: "libraries/proxy",
        register_fn: "register_proxy_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== punycode =====
    LibraryEffectEntry {
        name: "punycode",
        source_module: "libraries/punycode",
        register_fn: "register_punycode_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure Punycode encoding.",
    },
    // ===== radius =====
    LibraryEffectEntry {
        name: "radius",
        source_module: "libraries/radius",
        register_fn: "register_radius_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B corrective: connect_async uses broker_udp_connect; the raw tokio UdpSocket bind+connect the audit found is gone, so the module is promoted. The remaining entries are pure stubs.",
    },
    // ===== rand =====
    LibraryEffectEntry {
        name: "rand",
        source_module: "libraries/rand",
        register_fn: "register_rand_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "Random via broker_random_fill (provider-backed).",
    },
    // ===== rdp =====
    LibraryEffectEntry {
        name: "rdp",
        source_module: "libraries/rdp",
        register_fn: "register_rdp_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== re =====
    LibraryEffectEntry {
        name: "re",
        source_module: "libraries/re",
        register_fn: "register_re_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure regex helpers.",
    },
    // ===== redis =====
    LibraryEffectEntry {
        name: "redis",
        source_module: "libraries/redis",
        register_fn: "register_redis_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== rmi =====
    LibraryEffectEntry {
        name: "rmi",
        source_module: "libraries/rmi",
        register_fn: "register_rmi_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== rpc =====
    LibraryEffectEntry {
        name: "rpc",
        source_module: "libraries/rpc",
        register_fn: "register_rpc_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct UDP framing; no capability ctx (M005E ungated).",
    },
    // ===== rpcap =====
    LibraryEffectEntry {
        name: "rpcap",
        source_module: "libraries/rpcap",
        register_fn: "register_rpcap_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== rsync =====
    LibraryEffectEntry {
        name: "rsync",
        source_module: "libraries/rsync",
        register_fn: "register_rsync_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== rtsp =====
    LibraryEffectEntry {
        name: "rtsp",
        source_module: "libraries/rtsp",
        register_fn: "register_rtsp_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== sasl =====
    LibraryEffectEntry {
        name: "sasl",
        source_module: "libraries/sasl",
        register_fn: "register_sasl_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct TCP framing; no capability ctx (M005E ungated).",
    },
    // ===== sftp =====
    LibraryEffectEntry {
        name: "sftp",
        source_module: "libraries/sftp",
        register_fn: "register_sftp_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Native SSH handle handoff; not brokered (M005E ungated).",
    },
    // ===== shortport =====
    LibraryEffectEntry {
        name: "shortport",
        source_module: "libraries/shortport",
        register_fn: "register_shortport_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure port normalization.",
    },
    // ===== sip =====
    LibraryEffectEntry {
        name: "sip",
        source_module: "libraries/sip",
        register_fn: "register_sip_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== slaxml =====
    LibraryEffectEntry {
        name: "slaxml",
        source_module: "libraries/slaxml",
        register_fn: "register_slaxml_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure XML builder/parser.",
    },
    // ===== smb =====
    LibraryEffectEntry {
        name: "smb",
        source_module: "libraries/smb",
        register_fn: "register_smb_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: internal TcpStream plumbing plus async aliases use BrokeredTcpStream; no direct socket effect remains.",
    },
    // ===== smb2 =====
    LibraryEffectEntry {
        name: "smb2",
        source_module: "libraries/smb2",
        register_fn: "register_smb2_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== smbauth =====
    LibraryEffectEntry {
        name: "smbauth",
        source_module: "libraries/smbauth",
        register_fn: "register_smbauth_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Auth helper; no Lua-bound capability consultation (M005E residual).",
    },
    // ===== smtp =====
    LibraryEffectEntry {
        name: "smtp",
        source_module: "libraries/smtp",
        register_fn: "register_smtp_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== snmp =====
    LibraryEffectEntry {
        name: "snmp",
        source_module: "libraries/snmp",
        register_fn: "register_snmp_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyAdvisory,
        rationale: "Capability ctx present; BER encode/decode + UDP send/recv bypass provider injection (M005E advisory).",
    },
    // ===== socket =====
    LibraryEffectEntry {
        name: "socket",
        source_module: "libraries/socket",
        register_fn: "register_socket_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "TCP/UDP via broker_tcp_connect / broker_udp_connect; capability + sandbox aware.",
    },
    // ===== socks =====
    LibraryEffectEntry {
        name: "socks",
        source_module: "libraries/socks",
        register_fn: "register_socks_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== srvloc =====
    LibraryEffectEntry {
        name: "srvloc",
        source_module: "libraries/srvloc",
        register_fn: "register_srvloc_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct UDP framing; no capability ctx (M005E ungated).",
    },
    // ===== ssh =====
    LibraryEffectEntry {
        name: "ssh",
        source_module: "libraries/ssh",
        register_fn: "register_ssh_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyAdvisory,
        rationale: "Capability ctx consulted; native SSH framing uses direct I/O (M005E advisory).",
    },
    // ===== ssh1 =====
    LibraryEffectEntry {
        name: "ssh1",
        source_module: "libraries/ssh1",
        register_fn: "register_ssh1_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== ssh2 =====
    LibraryEffectEntry {
        name: "ssh2",
        source_module: "libraries/ssh2",
        register_fn: "register_ssh2_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Stub-only registration; no capability ctx (M005E ungated).",
    },
    // ===== sslcert =====
    LibraryEffectEntry {
        name: "sslcert",
        source_module: "libraries/sslcert",
        register_fn: "register_sslcert_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: connect uses BrokeredTcpStream and the TLS handshake runs over that brokered stream.",
    },
    // ===== sslv2 =====
    LibraryEffectEntry {
        name: "sslv2",
        source_module: "libraries/sslv2",
        register_fn: "register_sslv2_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== stdnse =====
    LibraryEffectEntry {
        name: "stdnse",
        source_module: "libraries/stdnse",
        register_fn: "register_stdlib_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "Time/random via brokers; capabilities consulted for sleep/etc.",
    },
    // ===== strbuf =====
    LibraryEffectEntry {
        name: "strbuf",
        source_module: "libraries/strbuf",
        register_fn: "register_strbuf_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure string buffer.",
    },
    // ===== stringaux =====
    LibraryEffectEntry {
        name: "stringaux",
        source_module: "libraries/stringaux",
        register_fn: "register_stringaux_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure string utilities.",
    },
    // ===== stun =====
    LibraryEffectEntry {
        name: "stun",
        source_module: "libraries/stun",
        register_fn: "register_stun_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Unconnected UDP send/recv; not brokered (M005E ungated).",
    },
    // ===== tab =====
    LibraryEffectEntry {
        name: "tab",
        source_module: "libraries/tab",
        register_fn: "register_tab_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure table utilities.",
    },
    // ===== tableaux =====
    LibraryEffectEntry {
        name: "tableaux",
        source_module: "libraries/tableaux",
        register_fn: "register_tableaux_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure table inspection.",
    },
    // ===== target =====
    LibraryEffectEntry {
        name: "target",
        source_module: "libraries/target",
        register_fn: "register_target_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "Pure host parsing helpers.",
    },
    // ===== telnet =====
    LibraryEffectEntry {
        name: "telnet",
        source_module: "libraries/telnet",
        register_fn: "register_telnet_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct TCP framing; no capability ctx (M005E ungated).",
    },
    // ===== tftp =====
    LibraryEffectEntry {
        name: "tftp",
        source_module: "libraries/tftp",
        register_fn: "register_tftp_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Unconnected UDP send/recv; not brokered (M005E ungated).",
    },
    // ===== tls =====
    LibraryEffectEntry {
        name: "tls",
        source_module: "libraries/tls",
        register_fn: "register_tls_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: connect uses BrokeredTcpStream and the TLS handshake runs over that brokered stream; connect_tcp stays capability-gated.",
    },
    // ===== tn3270 =====
    LibraryEffectEntry {
        name: "tn3270",
        source_module: "libraries/tn3270",
        register_fn: "register_tn3270_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== tns =====
    LibraryEffectEntry {
        name: "tns",
        source_module: "libraries/tns",
        register_fn: "register_tns_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== unicode =====
    LibraryEffectEntry {
        name: "unicode",
        source_module: "libraries/unicode",
        register_fn: "register_unicode_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure Unicode helpers.",
    },
    // ===== unittest =====
    LibraryEffectEntry {
        name: "unittest",
        source_module: "libraries/unittest",
        register_fn: "register_unittest_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure test framework.",
    },
    // ===== unpwdb =====
    LibraryEffectEntry {
        name: "unpwdb",
        source_module: "libraries/unpwdb",
        register_fn: "register_unpwdb_library",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "Filesystem reads via nse_fs_read_to_string; capability-gated.",
    },
    // ===== upnp =====
    LibraryEffectEntry {
        name: "upnp",
        source_module: "libraries/upnp",
        register_fn: "register_upnp_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: SSDP/SOAP TCP paths use BrokeredTcpStream and description fetch uses broker_http_request; no direct socket effect remains.",
    },
    // ===== url =====
    LibraryEffectEntry {
        name: "url",
        source_module: "libraries/url",
        register_fn: "register_url_library",
        eligibility: NseAutomatedLibraryEligibility::Pure,
        rationale: "Pure URL parsing.",
    },
    // ===== versant =====
    LibraryEffectEntry {
        name: "versant",
        source_module: "libraries/versant",
        register_fn: "register_versant_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== vnc =====
    LibraryEffectEntry {
        name: "vnc",
        source_module: "libraries/vnc",
        register_fn: "register_vnc_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: struct-held streams and blocking connects use BrokeredTcpStream; async aliases call the brokered path directly.",
    },
    // ===== vulns =====
    LibraryEffectEntry {
        name: "vulns",
        source_module: "libraries/vulns",
        register_fn: "register_vulns_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "CVE lookups (NVD/OSV/CISA) via broker_http_request.",
    },
    // ===== vuzedht =====
    LibraryEffectEntry {
        name: "vuzedht",
        source_module: "libraries/vuzedht",
        register_fn: "register_vuzedht_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct UDP framing; no capability ctx (M005E ungated).",
    },
    // ===== websocket =====
    LibraryEffectEntry {
        name: "websocket",
        source_module: "libraries/websocket",
        register_fn: "register_websocket_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Async Tokio I/O; no capability ctx (M005E ungated).",
    },
    // ===== whois =====
    LibraryEffectEntry {
        name: "whois",
        source_module: "libraries/whois",
        register_fn: "register_whois_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Direct TCP framing; no capability ctx (M005E ungated).",
    },
    // ===== winrm =====
    LibraryEffectEntry {
        name: "winrm",
        source_module: "libraries/winrm",
        register_fn: "register_winrm_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== wsdd =====
    LibraryEffectEntry {
        name: "wsdd",
        source_module: "libraries/wsdd",
        register_fn: "register_wsdd_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyDirectIo,
        rationale: "Unconnected/broadcast UDP send/recv; not brokered (M005E ungated).",
    },
    // ===== xdmcp =====
    LibraryEffectEntry {
        name: "xdmcp",
        source_module: "libraries/xdmcp",
        register_fn: "register_xdmcp_library",
        eligibility: NseAutomatedLibraryEligibility::ManualOnlyAdvisory,
        rationale: "Capability ctx present; UDP send/recv bypass provider injection (M005E advisory).",
    },
    // ===== xmpp =====
    LibraryEffectEntry {
        name: "xmpp",
        source_module: "libraries/xmpp",
        register_fn: "register_xmpp_library_with_services",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "M007B: broker-compatible TCP paths fully migrated to BrokeredTcpStream (broker_tcp_connect/send/receive); no direct socket effect remains.",
    },
    // ===== zlib =====
    LibraryEffectEntry {
        name: "zlib",
        source_module: "libraries/zlib",
        register_fn: "register_zlib_library",
        eligibility: NseAutomatedLibraryEligibility::ProviderBacked,
        rationale: "Compression brokered via nse_compress / nse_decompress; capability-gated.",
    },
];

/// Lookup an entry by Lua library/global name.
///
/// Returns `None` for unknown names — callers MUST treat unknown
/// libraries as `ManualOnlyDirectIo` (deny-by-default under automated
/// profiles per ADR-0004 §3).
pub fn classify(name: &str) -> Option<&'static LibraryEffectEntry> {
    LIBRARY_EFFECT_MANIFEST
        .binary_search_by(|e| e.name.cmp(name))
        .ok()
        .map(|idx| &LIBRARY_EFFECT_MANIFEST[idx])
}

/// Return the eligibility class for a Lua library/global name.
///
/// Unknown libraries resolve to [`NseAutomatedLibraryEligibility::ManualOnlyDirectIo`].
pub fn automated_library_eligibility(name: &str) -> NseAutomatedLibraryEligibility {
    classify(name)
        .map(|e| e.eligibility)
        .unwrap_or(NseAutomatedLibraryEligibility::ManualOnlyDirectIo)
}

/// Profile-gated automated safety predicate.
///
/// Returns `true` only when the library is safe under the supplied
/// profile. Manual profiles always permit everything (manual surface
/// preserves compatibility); automated profiles (`AgentSafe` / `CiSafe`)
/// permit only `Pure` and `ProviderBacked` libraries.
pub fn is_automated_library_safe(name: &str, profile: NseExecutionProfileKind) -> bool {
    eligible_for_profile(name, profile)
}

/// Same predicate as [`is_automated_library_safe`] with a name that
/// does not carry the "unsafe" connotation. Provided as a stable alias
/// for callers that want to express the positive intent.
pub fn eligible_for_profile(name: &str, profile: NseExecutionProfileKind) -> bool {
    let eligibility = automated_library_eligibility(name);
    match profile {
        NseExecutionProfileKind::ManualPermissive
        | NseExecutionProfileKind::ManualStrict
        | NseExecutionProfileKind::CompatibilityLab => true,
        NseExecutionProfileKind::AgentSafe | NseExecutionProfileKind::CiSafe => {
            matches!(
                eligibility,
                NseAutomatedLibraryEligibility::Pure
                    | NseAutomatedLibraryEligibility::ProviderBacked
            )
        }
    }
}

/// Return whether the supplied profile is an automated (non-manual)
/// profile.
///
/// Useful for guard scripts that need to gate behavior without
/// re-implementing the variant list.
pub fn is_automated_profile(profile: NseExecutionProfileKind) -> bool {
    matches!(
        profile,
        NseExecutionProfileKind::AgentSafe | NseExecutionProfileKind::CiSafe
    )
}

/// Return all classification entries sorted by name.
///
/// This is the iteration form used by guard scripts that need to
/// serialize the manifest for cross-checking.
pub fn classified_libraries() -> &'static [LibraryEffectEntry] {
    LIBRARY_EFFECT_MANIFEST
}

/// Count entries per eligibility class. Used by tests and guard
/// scripts to detect drift.
pub fn eligibility_counts() -> EligibilityCounts {
    let mut counts = EligibilityCounts::default();
    for entry in LIBRARY_EFFECT_MANIFEST {
        match entry.eligibility {
            NseAutomatedLibraryEligibility::Pure => counts.pure += 1,
            NseAutomatedLibraryEligibility::ProviderBacked => counts.provider_backed += 1,
            NseAutomatedLibraryEligibility::ManualOnlyDirectIo => counts.manual_only_direct_io += 1,
            NseAutomatedLibraryEligibility::ManualOnlyAdvisory => counts.manual_only_advisory += 1,
        }
    }
    counts
}

/// Result of [`eligibility_counts`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EligibilityCounts {
    pub pure: usize,
    pub provider_backed: usize,
    pub manual_only_direct_io: usize,
    pub manual_only_advisory: usize,
}

impl EligibilityCounts {
    /// Total entries across all classes.
    pub fn total(&self) -> usize {
        self.pure + self.provider_backed + self.manual_only_direct_io + self.manual_only_advisory
    }

    /// Entries safe under `AgentSafe` and `CiSafe`.
    pub fn automated_safe(&self) -> usize {
        self.pure + self.provider_backed
    }

    /// Entries manual-only (the M007A residual that remains in
    /// automated profiles until M007B migrates them).
    pub fn manual_only(&self) -> usize {
        self.manual_only_direct_io + self.manual_only_advisory
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_is_sorted_and_unique() {
        let mut last: Option<&'static str> = None;
        let mut seen = std::collections::BTreeSet::new();
        for entry in LIBRARY_EFFECT_MANIFEST {
            if let Some(prev) = last {
                assert!(
                    prev < entry.name,
                    "manifest must be sorted; '{}' should come after '{}'",
                    entry.name,
                    prev
                );
            }
            last = Some(entry.name);
            assert!(
                seen.insert(entry.name),
                "duplicate entry name '{}' in manifest",
                entry.name
            );
        }
    }

    #[test]
    fn every_entry_has_source_and_rationale() {
        for entry in LIBRARY_EFFECT_MANIFEST {
            assert!(
                !entry.source_module.is_empty(),
                "entry '{}' missing source_module",
                entry.name
            );
            assert!(
                !entry.register_fn.is_empty(),
                "entry '{}' missing register_fn",
                entry.name
            );
            assert!(
                !entry.rationale.is_empty(),
                "entry '{}' missing rationale",
                entry.name
            );
        }
    }

    #[test]
    fn eligibility_display_matches_variants() {
        assert_eq!(NseAutomatedLibraryEligibility::Pure.to_string(), "Pure");
        assert_eq!(
            NseAutomatedLibraryEligibility::ProviderBacked.to_string(),
            "ProviderBacked"
        );
        assert_eq!(
            NseAutomatedLibraryEligibility::ManualOnlyDirectIo.to_string(),
            "ManualOnlyDirectIo"
        );
        assert_eq!(
            NseAutomatedLibraryEligibility::ManualOnlyAdvisory.to_string(),
            "ManualOnlyAdvisory"
        );
    }

    #[test]
    fn profile_gating_matches_spec() {
        let pure = "base64";
        let provider_backed = "http";
        // Post-M007B, a still-direct effect is a shape the provider
        // contract cannot represent (unconnected UDP / native socket
        // handoff), not a merely-unmigrated TCP library.
        let manual_advisory = "snmp";
        let manual_direct = "tftp";

        for profile in [
            NseExecutionProfileKind::ManualPermissive,
            NseExecutionProfileKind::ManualStrict,
            NseExecutionProfileKind::CompatibilityLab,
        ] {
            assert!(eligible_for_profile(pure, profile));
            assert!(eligible_for_profile(provider_backed, profile));
            assert!(eligible_for_profile(manual_advisory, profile));
            assert!(eligible_for_profile(manual_direct, profile));
        }

        for profile in [
            NseExecutionProfileKind::AgentSafe,
            NseExecutionProfileKind::CiSafe,
        ] {
            assert!(eligible_for_profile(pure, profile));
            assert!(eligible_for_profile(provider_backed, profile));
            assert!(!eligible_for_profile(manual_advisory, profile));
            assert!(!eligible_for_profile(manual_direct, profile));
        }
    }

    #[test]
    fn unknown_library_fails_closed() {
        for profile in [
            NseExecutionProfileKind::AgentSafe,
            NseExecutionProfileKind::CiSafe,
        ] {
            assert!(
                !eligible_for_profile("not_in_manifest", profile),
                "unknown names must be manual-only under automated profiles"
            );
        }
        // Manual profiles permit unknown names for compatibility.
        assert!(eligible_for_profile(
            "not_in_manifest",
            NseExecutionProfileKind::ManualPermissive
        ));
        assert!(eligible_for_profile(
            "not_in_manifest",
            NseExecutionProfileKind::ManualStrict
        ));
        assert!(eligible_for_profile(
            "not_in_manifest",
            NseExecutionProfileKind::CompatibilityLab
        ));
    }

    #[test]
    fn manifest_covers_known_key_libraries() {
        for name in [
            "stdnse", "nmap", "http", "dns", "comm", "socket", "io", "os", "lfs", "smb", "pop3",
            "ftp", "ssh", "sslcert", "tls",
        ] {
            assert!(
                classify(name).is_some(),
                "library '{}' must have a manifest entry",
                name
            );
        }
    }

    #[test]
    fn counts_make_sense() {
        let counts = eligibility_counts();
        assert_eq!(
            counts.total(),
            LIBRARY_EFFECT_MANIFEST.len(),
            "eligibility_counts() must cover every manifest entry"
        );
        assert_eq!(
            counts.automated_safe() + counts.manual_only(),
            counts.total(),
            "every entry is either automated-safe or manual-only"
        );
        // M007B moved the broker-compatible cohort from manual-only to
        // ProviderBacked. The floor tracks the post-migration residual so
        // the M005E 97-entry count cannot silently return, while an
        // accidental mass re-classification also fails.
        assert!(
            counts.automated_safe() >= 110,
            "expected at least 110 automated-safe entries after the M007B promotion, got {}",
            counts.automated_safe()
        );
        assert!(
            counts.manual_only() >= 40,
            "expected at least 40 manual-only entries (unresolved residual), got {}",
            counts.manual_only()
        );
    }

    #[test]
    fn automated_profile_predicate_is_correct() {
        assert!(is_automated_profile(NseExecutionProfileKind::AgentSafe));
        assert!(is_automated_profile(NseExecutionProfileKind::CiSafe));
        assert!(!is_automated_profile(
            NseExecutionProfileKind::ManualPermissive
        ));
        assert!(!is_automated_profile(NseExecutionProfileKind::ManualStrict));
        assert!(!is_automated_profile(
            NseExecutionProfileKind::CompatibilityLab
        ));
    }

    // -----------------------------------------------------------------
    // M007B corrective: bidirectional registration/manifest consistency.
    // -----------------------------------------------------------------

    /// `(module, register_fn)` pairs actually invoked from
    /// `ExecutorCore::register_libraries()`.
    fn registered_pairs() -> std::collections::BTreeMap<String, String> {
        let source = include_str!("executor_core.rs");
        let body = source
            .split_once("fn register_libraries(&self)")
            .expect("register_libraries() must exist in executor_core.rs")
            .1;
        let mut pairs = std::collections::BTreeMap::new();
        for line in body.lines() {
            let Some(rest) = line.split("crate::libraries::").nth(1) else {
                continue;
            };
            let Some((module, call)) = rest.split_once("::") else {
                continue;
            };
            let call = call.trim_start();
            if !call.starts_with("register_") {
                continue;
            }
            let Some((fn_name, tail)) = call.split_once(['(', ' ']) else {
                continue;
            };
            if tail.contains(')') && !call.contains('(') {
                continue;
            }
            pairs
                .entry(module.to_string())
                .or_insert_with(|| fn_name.to_string());
        }
        pairs
    }

    /// `src/<module path>` entries pinned in the registration compat
    /// allowlist, which is the reviewed source of truth for the
    /// manifest -> registration direction.
    fn registration_compat_entries() -> std::collections::BTreeSet<String> {
        include_str!("../scripts/nse-registration-compat-entries.txt")
            .lines()
            .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
            .filter_map(|l| l.split_whitespace().next())
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn registration_and_manifest_agree() {
        let registered = registered_pairs();

        // registration -> manifest: every registered module has exactly
        // one entry, and its `register_fn` is the function actually called.
        let mut matched = std::collections::BTreeSet::new();
        for entry in LIBRARY_EFFECT_MANIFEST {
            let Some(module) = entry.source_module.strip_prefix("libraries/") else {
                continue;
            };
            let Some(actual_fn) = registered.get(module) else {
                continue;
            };
            assert_eq!(
                entry.register_fn, actual_fn,
                "manifest entry '{}' records register_fn '{}' but executor_core.rs calls '{}'",
                entry.name, entry.register_fn, actual_fn
            );
            assert!(
                matched.insert(module.to_string()),
                "module '{}' is claimed by more than one manifest entry",
                module
            );
        }
        for module in registered.keys() {
            assert!(
                matched.contains(module),
                "registered module '{}' has no effect-manifest entry",
                module
            );
        }

        // manifest -> registration: every compatibility entry must be
        // pinned in the allowlist, and the allowlist must not rot.
        let compat = registration_compat_entries();
        for entry in LIBRARY_EFFECT_MANIFEST {
            let Some(module) = entry.source_module.strip_prefix("libraries/") else {
                continue;
            };
            if registered.contains_key(module) {
                continue;
            }
            let path = format!("src/libraries/{module}.rs");
            assert!(
                compat.contains(&path),
                "manifest entry '{}' ({}) is not registered and is not listed in \
                 scripts/nse-registration-compat-entries.txt",
                entry.name,
                path
            );
        }
        for path in &compat {
            let file = path
                .strip_prefix("src/libraries/")
                .and_then(|p| p.strip_suffix(".rs"));
            let Some(module) = file else {
                panic!("compat entry '{path}' must be a src/libraries/<module>.rs path");
            };
            assert!(
                !registered.contains_key(module),
                "compat entry '{path}' is now registered; remove it from the allowlist"
            );
        }
    }

    #[test]
    fn m005e_baseline_keeps_exactly_one_class() {
        // The frozen M005E baseline (97 files) is history, not current
        // state. Every one of its paths must still carry exactly one
        // final classification in scripts/nse-migration-classes.txt, so a
        // migration can never erase the history it is measured against.
        let baseline: std::collections::BTreeSet<&str> =
            include_str!("../scripts/nse-m005e-direct-io-baseline.txt")
                .lines()
                .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
                .collect();
        assert_eq!(
            baseline.len(),
            97,
            "the M005E baseline must stay frozen at 97 files"
        );

        let mut classified: std::collections::BTreeMap<&str, usize> =
            std::collections::BTreeMap::new();
        for line in include_str!("../scripts/nse-migration-classes.txt").lines() {
            if line.trim_start().starts_with('#') || line.trim().is_empty() {
                continue;
            }
            *classified
                .entry(line.split_whitespace().next().unwrap())
                .or_default() += 1;
        }

        for path in &baseline {
            let count = classified
                .get(path)
                .unwrap_or_else(|| panic!("M005E baseline entry {path} lost its migration class"));
            assert_eq!(
                *count, 1,
                "M005E baseline entry {path} must have exactly one class, found {count}"
            );
        }
    }

    #[test]
    fn migrated_cohort_is_promoted_to_provider_backed() {
        // M007B promoted the broker-compatible cohort. Each name must be
        // `ProviderBacked` so automated profiles get it, which is only
        // sound because every one of its network effects is brokered.
        const PROMOTED: &[&str] = &[
            "afp",
            "ajp",
            "amqp",
            "anyconnect",
            "bitcoin",
            "bittorrent",
            "brute",
            "cassandra",
            "citrixxml",
            "cvs",
            "dicom",
            "drda",
            "ftp",
            "iec61850mms",
            "imap",
            "informix",
            "ipp",
            "irc",
            "iscsi",
            "isns",
            "jdwp",
            "ldap",
            "membase",
            "memcached",
            "mongodb",
            "msrpc",
            "msrpcperformance",
            "mssql",
            "mysql",
            "nbd",
            "ncp",
            "ndmp",
            "netbios",
            "nrpc",
            "omp2",
            "oops",
            "openssl",
            "oracle",
            "pgsql",
            "pop3",
            "postgres",
            "proxy",
            "rdp",
            "redis",
            "rmi",
            "rpcap",
            "rsync",
            "rtsp",
            "sip",
            "smb",
            "smb2",
            "smtp",
            "socks",
            "ssh1",
            "sslcert",
            "sslv2",
            "target",
            "tls",
            "tn3270",
            "tns",
            "upnp",
            "versant",
            "vnc",
            "winrm",
            "xmpp",
        ];
        for name in PROMOTED {
            let entry = classify(name)
                .unwrap_or_else(|| panic!("promoted library '{name}' must have a manifest entry"));
            assert_eq!(
                entry.eligibility,
                NseAutomatedLibraryEligibility::ProviderBacked,
                "'{name}' is in the M007B promoted cohort but is not ProviderBacked"
            );
            assert!(
                eligible_for_profile(name, NseExecutionProfileKind::AgentSafe),
                "'{name}' must be reachable under AgentSafe after promotion"
            );
        }
    }

    #[test]
    fn unresolved_residual_stays_manual_only() {
        // Shapes the current provider contract cannot represent must stay
        // manual-only in both directions (effect class and profile gate).
        const RESIDUAL: &[&str] = &[
            "bjnp", "coap", "dhcp", "dhcp6", "eigrp", "iax2", "ike", "ipmi", "knx", "libssh2",
            "natpmp", "ntp", "packet", "snmp", "srvloc", "ssh", "ssh2", "stun", "tftp", "wsdd",
            "xdmcp",
        ];
        for name in RESIDUAL {
            let entry = classify(name)
                .unwrap_or_else(|| panic!("residual library '{name}' must have a manifest entry"));
            assert!(
                matches!(
                    entry.eligibility,
                    NseAutomatedLibraryEligibility::ManualOnlyDirectIo
                        | NseAutomatedLibraryEligibility::ManualOnlyAdvisory
                ),
                "'{name}' still has a direct host network effect and must stay manual-only, got {}",
                entry.eligibility
            );
            for profile in [
                NseExecutionProfileKind::AgentSafe,
                NseExecutionProfileKind::CiSafe,
            ] {
                assert!(
                    !eligible_for_profile(name, profile),
                    "'{name}' must not be reachable under {profile:?}"
                );
            }
        }
    }
}
