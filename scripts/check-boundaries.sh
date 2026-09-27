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

echo "standalone boundary and provenance checks passed"
