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

echo "standalone boundary and provenance checks passed"
