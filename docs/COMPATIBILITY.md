# Runtime compatibility

`eggsec-nse` implements a practical, deliberately bounded subset of NSE behavior. Compatibility is reported per run with status, fidelity, unsupported features, approximations, resolver diagnostics, and capability events. A representative clean-room corpus checks supported, partial, approximate, unsupported, denied, and error outcomes.

The corpus is not an exhaustive Nmap conformance suite. The implementation provides curated Lua libraries and selected runtime behavior; unsupported APIs and protocol-specific behavior may be reported or approximated. Never infer full Nmap/NSE compatibility from a passing corpus.

The request/profile/execution/report pipeline is owned by `execute_nse_run`. `NseExecutor` is the lower-level API for integrations that need direct control. `ScriptResolver` must remain the sole script/module loading policy boundary. Profile differences, empty-root semantics, and report contracts are documented in the API docs and enforced by tests.

The corpus is synthetic and local-only. Its manifest records provenance and expected behavior. Runtime qualification uses loopback protocol fixtures; the SSH feature test uses a disposable local OpenSSH endpoint.
