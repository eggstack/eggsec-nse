#!/usr/bin/env bash
set -euo pipefail

# Prerequisite: every guard below uses `rg` for regex matching. Fail fast with
# one actionable diagnostic instead of dozens of `rg: command not found`
# lines if the host runner did not provision ripgrep. CONTRIBUTING.md lists
# ripgrep as a build requirement; .github/workflows/ci.yml installs it on
# Linux/macOS jobs that invoke this script.
#
# This check runs before any external utility (including `dirname` for the
# `cd` below) and emits its diagnostic with the `printf` builtin only, so the
# fail-fast path works in a hermetic no-PATH environment where no external
# binary — including `rg` itself — is resolvable.
if ! command -v rg >/dev/null 2>&1; then
  printf '%s\n' \
    "check-boundaries.sh: required tool 'rg' (ripgrep) is not installed." \
    '' \
    'Install ripgrep (https://github.com/BurntSushi/ripgrep) before running this' \
    'script. On Debian/Ubuntu runners: `apt-get install -y ripgrep`. On macOS' \
    'runners: `brew install ripgrep` or rely on the bundled action. This script' \
    'also fails fast in CI for the same reason; see .github/workflows/ci.yml.' >&2
  exit 127
fi

cd "$(dirname "$0")/.."

if rg -n 'eggsec-(core|report-model|transport|policy|tool-core|runtime|daemon|output|agent|db-lab|web-proxy|mobile-lab|nse)\s*=' Cargo.toml \
  || rg -n '^\s*(use|extern crate)\s+eggsec_(core|report_model|transport|policy|tool_core|runtime|daemon|output|agent|db_lab|web_proxy|mobile_lab)\b' src tests; then
  echo "forbidden Eggsec crate dependency/import in standalone runtime" >&2
  exit 1
fi

if rg -n '(^|/)crates/eggsec-nse|\.\./\.\./README\.md|path\s*=\s*"\.\.' Cargo.toml src tests; then
  echo "standalone runtime contains a workspace-relative source reference" >&2
  exit 1
fi

if rg -n 'version\.workspace|edition\.workspace|license\.workspace|repository\.workspace|rust-version\.workspace|[A-Za-z0-9_-]+\.workspace\s*=' Cargo.toml; then
  echo "standalone manifest inherits workspace metadata or dependencies" >&2
  exit 1
fi

for required in README.md LICENSE CONTRIBUTING.md docs/PROVENANCE.md docs/COMPATIBILITY.md Cargo.lock; do
  test -f "$required" || { echo "missing required standalone asset: $required" >&2; exit 1; }
done

if rg -n 'github\.com/nmap/nmap|svn\.nmap\.org|nselib/' tests/fixtures/nse_corpus --glob '*.nse' --glob '*.lua'; then
  echo "possible upstream Nmap corpus import; review fixture provenance" >&2
  exit 1
fi

# M005A provider broker boundary: migrated clock/random/environment paths must
# go through the capability-aware broker. Native implementations
# (src/providers.rs), tests, and explicitly inventoried fallbacks/residuals
# are the only allow-listed direct host-call sites.
#
# - datetime.rs / rand.rs: zero direct clock/random/env calls.
# - os.rs: no std::env::var (provider-backed getenv); current_dir/set_current_dir
#   remain as 005D residuals (per-run CWD work).
# - stdnse.rs / nmap.rs: no rand::random/thread_rng; direct clock reads only in
#   broker-fallback lines (unwrap_or_else) or nmap internal connection-registry
#   timestamps (created_at residual, not Lua-visible).
# - executor_core.rs: no std::env::var (provider-aware default script paths).
if rg -n 'SystemTime::now|Utc::now|rand::random|thread_rng|std::env::var|std::env::temp_dir' src/libraries/datetime.rs src/libraries/rand.rs; then
  echo "M005A violation: direct clock/random/env call in datetime.rs or rand.rs (use providers broker)" >&2
  exit 1
fi

if rg -n 'std::env::var' src/libraries/os.rs src/executor_core.rs; then
  echo "M005A violation: direct std::env::var in os.rs or executor_core.rs (use environment provider)" >&2
  exit 1
fi

if rg -n 'rand::random|thread_rng' src/libraries/stdnse.rs src/libraries/nmap.rs; then
  echo "M005A violation: direct randomness call in stdnse.rs or nmap.rs (use random provider broker)" >&2
  exit 1
fi

# Direct clock reads outside allow-listed fallback/residual lines fail.
if rg -n 'SystemTime::now|Utc::now' src/libraries/stdnse.rs | rg -v 'unwrap_or_else|broker_unix_timestamp|//'; then
  echo "M005A violation: direct clock call in stdnse.rs outside broker fallback (use clock provider broker)" >&2
  exit 1
fi

# nmap.rs residual: internal connection-registry timestamps (created_at,
# connected_at) remain native SystemTime metadata (not Lua-visible clock
# reads); all Lua-visible clock fns are brokered. Forbid chrono clock outside
# broker fallbacks; SystemTime residuals are inventoried in docs/PROVIDERS.md.
if rg -n 'chrono::Utc::now' src/libraries/nmap.rs | rg -v 'unwrap_or_else|broker_unix_timestamp|//'; then
  echo "M005A violation: direct chrono clock call in nmap.rs outside broker fallback" >&2
  exit 1
fi

# Provider composition boundary: no monolithic host trait.
if rg -n 'trait NseHostProvider|trait HostProvider' src/; then
  echo "M005A violation: monolithic host trait introduced (keep narrow per-domain providers)" >&2
  exit 1
fi

# Broker presence: migrated modules must reference the provider broker.
for f in src/libraries/datetime.rs src/libraries/rand.rs src/libraries/os.rs src/libraries/stdnse.rs src/libraries/nmap.rs; do
  if ! rg -q 'broker_' "$f"; then
    echo "M005A violation: $f contains no broker_ call (migrated modules must use providers broker)" >&2
    exit 1
  fi
done

# M005B authority-preserving network/DNS: migrated core paths must go
# through the provider broker. Native implementations (src/providers.rs) are
# the single allow-listed direct-network zone; narrowly documented
# compatibility shims are the only other direct sites.
#
# - socket.rs / dns.rs: zero direct network calls (opaque handles and
#   provider-backed resolution only; Nse* contract names are allowed).
# - comm.rs: no direct socket/DNS calls; reqwest stays only in tryssl, which
#   is inventoried as the 005C residual.
# - nmap.rs: no connection creation or resolution; native socket types appear
#   only in the add_connection/get_connection compatibility-shim signatures
#   and their doc comments.
# - wrappers.rs: no connection creation or resolution; native handle types
#   remain in compatibility-shim signatures/plumbing only.
if rg -n -e 'std::net::TcpStream' -e 'std::net::UdpSocket' -e 'ToSocketAddrs' -e 'tokio' -e 'hickory' -e 'OnceLock' -e 'connect_timeout' -e 'lookup_host' -e 'SocketAddr' src/libraries/socket.rs src/libraries/dns.rs; then
  echo "M005B violation: direct network call in socket.rs or dns.rs (use network providers broker)" >&2
  exit 1
fi

if rg -n -e 'std::net::TcpStream' -e 'std::net::UdpSocket' -e 'ToSocketAddrs' -e 'tokio' -e 'hickory' -e 'connect_timeout\(' -e 'lookup_host' -e 'UdpSocket::bind' src/libraries/comm.rs; then
  echo "M005B violation: direct socket call in comm.rs (use network providers broker)" >&2
  exit 1
fi

if rg -n -e 'TcpStream::' -e 'connect_timeout' -e 'tokio::net' -e 'ToSocketAddrs' -e 'lookup_host' -e 'hickory' src/libraries/nmap.rs; then
  echo "M005B violation: direct network call in nmap.rs (use network providers broker)" >&2
  exit 1
fi

# nmap.rs keeps native socket types only in the compatibility-shim
# signatures (add_connection/get_connection) and doc comments.
if rg -n -e 'TcpStream' src/libraries/nmap.rs | rg -v 'add_connection|get_connection|//'; then
  echo "M005B violation: TcpStream outside compatibility shims in nmap.rs" >&2
  exit 1
fi

if rg -n -e 'TcpStream::connect' -e 'connect_timeout' -e 'UdpSocket::bind' -e 'ToSocketAddrs' -e 'lookup_host' -e 'hickory' src/wrappers.rs; then
  echo "M005B violation: direct network call in wrappers.rs (use network providers broker)" >&2
  exit 1
fi

# Broker presence (network): migrated modules must reference the broker.
for f in src/libraries/socket.rs src/libraries/comm.rs src/libraries/dns.rs src/wrappers.rs; do
  if ! rg -q 'broker_' "$f"; then
    echo "M005B violation: $f contains no broker_ call (migrated modules must use network providers broker)" >&2
    exit 1
  fi
done

# M005D filesystem/process portability: migrated modules must go through the
# provider broker. Native implementations (src/providers.rs) are the single
# allow-listed direct-execution zone; narrowly documented compatibility
# shims and loader residuals are the only other direct sites.
#
# - No process-global CWD mutation anywhere in src/ (virtual CWD only).
# - io.rs / lfs.rs: zero direct fs/env/os calls (brokered providers only;
#   std::process::id and the env temp_dir fallback in io.tmpfile are
#   inventoried, not bypasses).
# - os.rs: no direct fs removes/renames or CWD mutation (env temp_dir
#   fallback + hostname lookup are inventoried residuals).
# - nmap.rs: no direct child-process spawns (discovery is provider-backed).
# - wrappers.rs: delegated filesystem fns must not call std::fs directly;
#   metadata/read_dir/symlink-metadata/process-exec shims keep native
#   bodies for their leaking signatures (documented, inventoried).
if rg -n 'env::set_current_dir' src/; then
  echo "M005D violation: process-global set_current_dir in src/ (use the virtual per-run CWD provider)" >&2
  exit 1
fi

if rg -n -e 'std::fs::' -e 'std::process::Command' -e 'OpenOptions' -e 'PermissionsExt' -e 'os::unix' -e 'os::windows' -e 'env::current_dir' src/libraries/io.rs; then
  echo "M005D violation: direct fs/process call in io.rs (use filesystem/process providers broker)" >&2
  exit 1
fi

if rg -n -e 'std::fs' -e 'std::env' -e 'std::os' src/libraries/lfs.rs; then
  echo "M005D violation: direct fs/env/os call in lfs.rs (use filesystem providers broker)" >&2
  exit 1
fi

if rg -n -e 'std::fs::' -e 'env::current_dir' src/libraries/os.rs; then
  echo "M005D violation: direct fs/CWD call in os.rs (use filesystem providers broker)" >&2
  exit 1
fi

if rg -n -e 'process::Command' -e 'Command::new' src/libraries/nmap.rs; then
  echo "M005D violation: direct child-process spawn in nmap.rs (use process provider broker)" >&2
  exit 1
fi

# wrappers.rs hosts an inline #[cfg(test)] module whose fixtures may use
# std directly (denial tests must set up files without capability); the
# delegation-shim guard therefore scans only production code above it.
if rg -n -e 'std::fs::read_to_string' -e 'std::fs::read\(' -e 'std::fs::write' -e 'std::fs::remove_file' -e 'std::fs::rename' -e 'std::fs::create_dir_all' -e 'std::fs::remove_dir' -e 'std::fs::hard_link' -e 'std::fs::read_link' -e 'std::fs::set_permissions' -e 'unix::fs::symlink' -e 'PermissionsExt' <(head -n "$(( $(grep -n 'mod tests' src/wrappers.rs | head -n 1 | cut -d: -f1) - 1 ))" src/wrappers.rs); then
  echo "M005D violation: direct fs call in wrappers.rs delegation shims (use filesystem providers broker)" >&2
  exit 1
fi

# Broker presence (filesystem/process): migrated modules must reference it.
for f in src/libraries/io.rs src/libraries/lfs.rs src/libraries/os.rs src/libraries/nmap.rs; do
  if ! rg -q 'broker_' "$f"; then
    echo "M005D violation: $f contains no broker_ call (migrated modules must use filesystem/process providers broker)" >&2
    exit 1
  fi
done

# M005C HTTP provider: migrated HTTP-family libraries must go through the
# provider broker. Native HTTP lives only in src/providers.rs; the
# deprecated no-op TLS-flag shims in http.rs are the only allow-listed
# legacy surface (no behavior, no client).
if rg -n -e 'reqwest' src/libraries/http.rs src/libraries/httppipeline.rs src/libraries/comm.rs src/libraries/brute.rs src/libraries/vulns.rs src/libraries/upnp.rs; then
  echo "M005C violation: direct HTTP client use in migrated HTTP-family library (use HTTP provider broker)" >&2
  exit 1
fi

# Broker presence (HTTP): migrated modules must reference the broker.
for f in src/libraries/http.rs src/libraries/httppipeline.rs src/libraries/comm.rs src/libraries/brute.rs src/libraries/vulns.rs src/libraries/upnp.rs; do
  if ! rg -q 'broker_' "$f"; then
    echo "M005C violation: $f contains no broker_ call (migrated modules must use HTTP provider broker)" >&2
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# M007B specialized direct-I/O residual + migration classification.
# ---------------------------------------------------------------------------
#
# M005E pinned 97 files (72 ungated + 25 advisory) that performed direct host
# socket I/O. M007B migrated the broker-compatible cohort, so the pins had to
# be regenerated from the new source truth. The M005E scan was also too
# coarse to express the migration:
#
#   1. `TcpStream::connect` substring-matches `BrokeredTcpStream::connect`,
#      so every broker-migrated file still looked like a direct residual
#      (this is what made hosted CI red on `699d374`);
#   2. direct DNS resolution (`to_socket_addrs`, `ToSocketAddrs`,
#      `lookup_host`, `hickory`, `tokio::net`) was never covered;
#   3. provider/broker infrastructure (`src/providers.rs`,
#      `src/brokered_stream.rs`) is not a specialized protocol residual.
#
# The corrected scan therefore:
#
# - restricts the *specialized zone* to `src/libraries/**` and
#   `src/public_api/api.rs`;
# - anchors each pattern behind a non-identifier boundary so brokered
#   abstractions (`BrokeredTcpStream::connect`, `broker_udp_connect`, …)
#   never match;
# - scans production code only (above the first `mod tests`) and drops
#   comment-only lines, so prose references are not residual evidence;
# - treats direct DNS resolution as a network effect.
#
# Residual inventory (split by whether the file still consults capability):
#
# - nse-specialized-ungated.txt: direct effect, no capability consultation.
# - nse-specialized-advisory.txt: direct effect, capability consultation
#   present (still outside provider cancellation/accounting/authority).
#
# scripts/nse-migration-classes.txt carries exactly one final
# effect-shape class per baseline M005E entry, and every current residual
# file must have a class. A `BrokerCompatible*` class may never sit on a
# file that still has a direct effect: that is the M007B closure invariant.

# Production-code view of a file: everything above the first `mod tests`.
nse_production_code() {
    if grep -q "mod tests" "$1"; then
        line=$(grep -n "mod tests" "$1" | head -n 1 | cut -d: -f1)
        head -n $((line - 1)) "$1"
    else
        cat "$1"
    fi
}

# Specialized direct host network-effect patterns. Every pattern is anchored
# behind `(^|[^A-Za-z0-9_])` so an identifier prefix (Brokered…, broker_…)
# cannot satisfy it. `rg -v '^[[:space:]]*(//|/\*|\*)'` drops comment-only
# lines. The final stage uses `-c` (count) rather than `-q` so it always
# drains its input: an early-exiting `rg -q` would SIGPIPE the upstream
# stages and, under `set -o pipefail`, silently report "no match".
nse_specialized_effect_hits() {
    nse_production_code "$1" \
        | rg -v -e '^[[:space:]]*(//|/\*|\*)' \
        | rg -c -e '(^|[^A-Za-z0-9_])TcpStream::(connect|connect_timeout)' \
               -e '(^|[^A-Za-z0-9_])UdpSocket::bind' \
               -e '(^|[^A-Za-z0-9_])TcpListener::bind' \
               -e '(^|[^A-Za-z0-9_])AsyncTcpStream::connect' \
               -e '(^|[^A-Za-z0-9_])AsyncUdpSocket::bind' \
               -e '(^|[^A-Za-z0-9_])to_socket_addrs' \
               -e '(^|[^A-Za-z0-9_])ToSocketAddrs' \
               -e '(^|[^A-Za-z0-9_])lookup_host' \
               -e '(^|[^A-Za-z0-9_])hickory' \
               -e '(^|[^A-Za-z0-9_])tokio::net' || true
}

nse_specialized_residual() {
    for f in $(rg -l --no-heading -e 'TcpStream::' -e 'UdpSocket::' -e 'TcpListener::' \
                      -e 'AsyncTcpStream::' -e 'AsyncUdpSocket::' -e 'to_socket_addrs' \
                      -e 'ToSocketAddrs' -e 'lookup_host' -e 'hickory' -e 'tokio::net' \
                      src/libraries src/public_api/api.rs | sort); do
        if [ -n "$(nse_specialized_effect_hits "$f")" ]; then
            echo "$f"
        fi
    done
}

expected_socket_files=$(sort scripts/nse-specialized-advisory.txt scripts/nse-specialized-ungated.txt | uniq)
actual_socket_files=$(nse_specialized_residual)
if [ "$actual_socket_files" != "$expected_socket_files" ]; then
    echo "M007B violation: specialized direct-I/O residual changed (see docs/PROVIDERS.md M007B audit)." >&2
    echo "--- expected (pinned) ---" >&2
    echo "$expected_socket_files" >&2
    echo "--- actual (source) ---" >&2
    echo "$actual_socket_files" >&2
    exit 1
fi

# Advisory-gated files must keep consulting capability (prevents silent
# gate removal; per-entry coverage caveats are documented, not enforced).
while read -r f; do
    if ! rg -q "capability_ctx|cap_ctx|check_capability|wrappers::|maybe_denied" "$f"; then
        echo "M007B violation: advisory file $f lost its capability gate" >&2
        exit 1
    fi
done < scripts/nse-specialized-advisory.txt

# reqwest is allow-listed to the native HTTP zone (providers.rs), the
# public sync API + CVE clients, shared protocol helpers, and
# reference-only mentions (lib.rs docs, registry metadata). Any new file
# importing reqwest fails closed.
expected_reqwest_files=$(sort scripts/nse-reqwest-inventory.txt)
actual_reqwest_files=$(rg -l --no-heading -e 'reqwest' src/ | sort)
if [ "$actual_reqwest_files" != "$expected_reqwest_files" ]; then
    echo "M005E violation: reqwest file set changed (pinned in scripts/nse-reqwest-inventory.txt)" >&2
    echo "--- expected ---" >&2
    echo "$expected_reqwest_files" >&2
    echo "--- actual ---" >&2
    echo "$actual_reqwest_files" >&2
    exit 1
fi

# Portability: platform-specific host modules stay in the native provider
# zone. Production code (above `mod tests`) outside providers.rs must not
# reference os::unix/os::windows/nix/libc; cfg-gated fallbacks that carry
# no os:: path (executor_core script roots, wrappers permission shim,
# nsedebug estimates) are unaffected. (Production-code view is
# `nse_production_code`, defined in the M007B section above.)
platform_violation=""
for f in $(rg -l --no-heading -e 'os::unix' -e 'os::windows' -e 'nix::' -e 'libc::' src/ | sort); do
    case "$f" in src/providers.rs) continue ;; esac
    if nse_production_code "$f" | rg -q -e 'os::unix' -e 'os::windows' -e 'nix::' -e 'libc::'; then
        platform_violation="$platform_violation $f"
    fi
done
if [ -n "$platform_violation" ]; then
    echo "M005E violation: platform host module outside providers.rs:$platform_violation" >&2
    exit 1
fi

# M007A automated library effect gate: complete manifest coverage, no silent
# unsafe expansion, M005E agreement, native HTTP never authority-bound.
#
# - every `register_*_library` call in ExecutorCore::register_libraries()
#   must have a matching manifest entry (by register_fn name);
# - the post-registration scrub must exist and run (covers manual-only libs
#   whose call sites bypass gate_then_register);
# - representative M005E residual libraries must classify ManualOnly;
# - native constructors must default http_authority_bound to false; only
#   with_authority_bound_http() may set it true.
for regfn in $(rg -o --no-heading -e 'register_[a-z0-9_]+_library' src/executor_core.rs | sort -u); do
    if ! rg -q -F "$regfn" src/effect_manifest.rs; then
        echo "M007A violation: $regfn has no effect-manifest entry (see src/effect_manifest.rs)" >&2
        exit 1
    fi
done

if ! rg -q 'fn scrub_ineligible_globals' src/executor_core.rs; then
    echo "M007A violation: scrub_ineligible_globals missing (automated profiles would retain ungated unsafe globals)" >&2
    exit 1
fi

if ! rg -q 'scrub_ineligible_globals\(\)' src/executor_core.rs; then
    echo "M007A violation: scrub_ineligible_globals never called in register_libraries()" >&2
    exit 1
fi

# Representative M007B residuals must stay manual-only in the manifest:
# unconnected/broadcast UDP (`tftp`), native socket handoff (`ssh`), and
# raw/unconnected UDP discovery (`snmp`). These are the shapes the current
# provider contract cannot represent, so promotion would be a false
# authority claim.
for lib in tftp ssh snmp eigrp packet; do
    if ! rg -q -e "name: \"$lib\"" src/effect_manifest.rs; then
        echo "M007B violation: representative residual library '$lib' missing from manifest" >&2
        exit 1
    fi
    if ! grep -A4 -F "name: \"$lib\"" src/effect_manifest.rs | rg -q -e 'Eligibility::ManualOnly'; then
        echo "M007B violation: residual library '$lib' promoted to automated-safe without a provider contract" >&2
        exit 1
    fi
done

# Migration classification (M007B):
#
# 1. every baseline M005E entry keeps exactly one final class, and every
#    class path must be a real source file;
# 2. every current residual file must have a class;
# 3. a `BrokerCompatible*` class may never sit on a file that still has a
#    direct effect (that is the M007B closure invariant);
# 4. a residual file must carry a manual-only class, never a
#    broker-compatible one.
m007b_class_field() {
    # $1 = path, $2 = 1..3 (path, class, rationale start)
    awk -v p="$1" -v f="$2" '
        /^[[:space:]]*#/ { next }
        NF == 0 { next }
        { path[NR] = $1 }
        END { for (i = 1; i <= NR; i++) if (path[i] == p) { print i; return } }
    ' scripts/nse-migration-classes.txt
}

# 3/4: class-vs-residual agreement.
while read -r f; do
    [ -n "$f" ] || continue
    cls=$(awk -v p="$f" '
        /^[[:space:]]*#/ { next }
        NF == 0 { next }
        $1 == p { print $2; exit }
    ' scripts/nse-migration-classes.txt)
    if [ -z "$cls" ]; then
        echo "M007B violation: residual $f has no migration class in scripts/nse-migration-classes.txt" >&2
        exit 1
    fi
    case "$cls" in
        BrokerCompatible*)
            echo "M007B violation: $f is classified $cls but still has a direct host network effect" >&2
            exit 1
            ;;
    esac
done < <(cat scripts/nse-specialized-advisory.txt scripts/nse-specialized-ungated.txt)

# 1/2/5: classification file integrity + coverage of the current residual
# + preservation of the frozen M005E baseline. A classified line is
# `<path> <CLASS> <rationale...>`; the class must be one of the recorded
# effect shapes and the rationale must be present.
known_class() {
    case "$1" in
        BrokerCompatibleTcp | BrokerCompatibleUdpConnected | AsyncDirectIo | \
        UnconnectedDatagram | NativeHandleEscape | RawPacketOrInterface | \
        PublicCompatibilityApi | ProviderBackedDns) return 0 ;;
        *) return 1 ;;
    esac
}

duplicate_classes=$(rg -o -e '^src/[^ ]+' scripts/nse-migration-classes.txt | sort | uniq -d)
if [ -n "$duplicate_classes" ]; then
    echo "M007B violation: duplicate migration classification for: $duplicate_classes" >&2
    exit 1
fi
for p in $(rg -o -e '^src/[^ ]+' scripts/nse-migration-classes.txt | sort -u); do
    if [ ! -f "$p" ]; then
        echo "M007B violation: migration class references missing source file: $p" >&2
        exit 1
    fi
    line=$(awk -v p="$p" '
        /^[[:space:]]*#/ { next }
        NF == 0 { next }
        $1 == p { $1 = ""; $2 = ""; sub(/^  +/, ""); print; exit }
    ' scripts/nse-migration-classes.txt)
    if [ -z "$line" ]; then
        echo "M007B violation: $p has no recognized migration class with rationale" >&2
        exit 1
    fi
    cls=$(awk -v p="$p" '
        /^[[:space:]]*#/ { next }
        NF == 0 { next }
        $1 == p { print $2; exit }
    ' scripts/nse-migration-classes.txt)
    if ! known_class "$cls"; then
        echo "M007B violation: $p has unknown migration class '$cls'" >&2
        exit 1
    fi
done

# 5: the frozen M005E baseline (97 files) must keep exactly one final
# classification, so a migration can never erase the history it is
# measured against.
unclassified_baseline=$(comm -23 \
    <(rg -o -e '^src/[^ ]+' scripts/nse-m005e-direct-io-baseline.txt | sort -u) \
    <(rg -o -e '^src/[^ ]+' scripts/nse-migration-classes.txt | sort -u))
if [ -n "$unclassified_baseline" ]; then
    echo "M007B violation: M005E baseline entries lost their final migration class:" >&2
    printf '%s\n' "$unclassified_baseline" >&2
    exit 1
fi

# Provider/broker infrastructure must never be counted as a specialized
# protocol residual (ADR-0003: the provider zone owns native mechanics).
for infra in src/providers.rs src/brokered_stream.rs; do
    if rg -q -F "$infra" scripts/nse-specialized-advisory.txt scripts/nse-specialized-ungated.txt; then
        echo "M007B violation: provider/broker infrastructure $infra entered the specialized residual pins" >&2
        exit 1
    fi
done

# Reverse manifest -> registration consistency (M007A finding closed in
# M007B). Every `src/libraries/*.rs` module that defines a
# `pub fn register_*` must either be called from
# `ExecutorCore::register_libraries()` or be listed with a reviewed
# rationale in scripts/nse-registration-compat-entries.txt. Stale or
# newly-orphaned modules fail CI.
compat_paths=$(rg -o -e '^src/[^ ]+' scripts/nse-registration-compat-entries.txt | sort -u)
for f in $(rg -l --no-heading -e '^pub fn register_[a-z0-9_]+' src/libraries | sort); do
    mod=$(basename "$f" .rs)
    if rg -q -e "crate::libraries::${mod}::register_[a-z0-9_]+\(" src/executor_core.rs; then
        continue
    fi
    if ! printf '%s\n' "$compat_paths" | rg -q -x -F "$f"; then
        echo "M007B violation: library module $f defines register_* but is never registered and is not listed in scripts/nse-registration-compat-entries.txt" >&2
        exit 1
    fi
done

# The compatibility allowlist must not rot: every listed path must exist
# and must still be genuinely unregistered.
for p in $compat_paths; do
    if [ ! -f "$p" ]; then
        echo "M007B violation: registration compat entry references missing file: $p" >&2
        exit 1
    fi
    mod=$(basename "$p" .rs)
    if rg -q -e "crate::libraries::${mod}::register_[a-z0-9_]+\(" src/executor_core.rs; then
        echo "M007B violation: registration compat entry $p is now registered; remove it from the allowlist" >&2
        exit 1
    fi
done

# Direct-HTTP residual (the reqwest inventory is the pin set) must stay
# manual-only for every library module that appears in the effect
# manifest, so a native-HTTP site can never be promoted to
# automated-safe. Helper modules with no manifest entry (shared client
# builders) are exempt by construction.
manifest_name_for_module() {
    # POSIX-awk only: string-splitting on the quote character, no regex
    # escapes (mawk rejects `\"` inside a regex literal).
    awk -v m="$1" '
        BEGIN { q = sprintf("%c", 34) }
        index($0, "name: " q) > 0 {
            rest = substr($0, index($0, q) + 1)
            name = substr(rest, 1, index(rest, q) - 1)
        }
        index($0, "source_module: " q m q) > 0 { print name; exit }
    ' src/effect_manifest.rs
}
for f in $(rg -l --no-heading -e 'reqwest' src/libraries | sort); do
    mod=$(echo "$f" | sed -e 's|^src/libraries/||' -e 's|\.rs$||')
    name=$(manifest_name_for_module "libraries/$mod")
    [ -n "$name" ] || continue
    if ! grep -A4 -F "name: \"$name\"" src/effect_manifest.rs | rg -q -e 'Eligibility::ManualOnly'; then
        echo "M007B violation: direct-HTTP module $f (manifest name '$name') is not ManualOnly" >&2
        exit 1
    fi
done

# Native HTTP must never default to authority-bound.
if ! rg -q 'http_authority_bound: false' src/providers.rs; then
    echo "M007A violation: native NseHostServices lost its authority-bound=false default" >&2
    exit 1
fi
if rg -n 'http_authority_bound: true' src/providers.rs | rg -v 'with_authority_bound_http|//'; then
    echo "M007A violation: http_authority_bound set true outside with_authority_bound_http()" >&2
    exit 1
fi

echo "standalone boundary and provenance checks passed"
