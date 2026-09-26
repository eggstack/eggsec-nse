# Provenance and licensing

## Extraction

This repository was created with a history-preserving `git subtree split` from Eggsec repository `https://github.com/eggstack/eggsec`, path `crates/eggsec-nse/`. Extraction source commit: `d743ef2e6064a2a9d2ab575e1c4e3f996f3f7c61`. The first standalone history commit is `6e5abf5fcb9a9a28df78914495aad1471a17c284`; it represents the crate contents at that Eggsec source revision. The split retained path-local commit history.

Transferred inventory: the crate manifest, all runtime Rust source, runtime-owned integration tests, and `tests/fixtures/nse_corpus/` including its manifest and provenance notes. Eggsec engine adapters (`nse_bridge`, `nse_http_capability`), Eggsec report DTOs, frontend bindings, and upstream Nmap corpus files were not transferred.

## Fixture policy

The test corpus is independently authored, synthetic, and local-only. Fixture files and `manifest.toml` carry category, expected behavior, and provenance information. No Nmap-distributed `.nse` or nselib source is included. The term “upstream-style” refers to a general pattern or behavior category and does not indicate copied upstream code. New fixtures must be original and must record provenance in the manifest.

## License scope

The repository MIT license covers the original Eggstack runtime and original fixtures. Third-party dependency licenses remain those of their respective projects. No third-party Nmap corpus is relicensed or redistributed here.
