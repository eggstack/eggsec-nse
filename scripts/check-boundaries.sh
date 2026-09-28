#!/usr/bin/env bash
set -euo pipefail

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

if rg -n -e 'std::net::TcpStream' -e 'std::net::UdpSocket' -e 'ToSocketAddrs' -e 'tokio' -e 'hickory' -e 'connect_timeout' -e 'lookup_host' -e 'UdpSocket::bind' src/libraries/comm.rs; then
  echo "M005B violation: direct socket call in comm.rs (use network providers broker; tryssl stays on reqwest until 005C)" >&2
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

echo "standalone boundary and provenance checks passed"
