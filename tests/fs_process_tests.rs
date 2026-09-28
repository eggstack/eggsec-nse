//! M005D filesystem/process portability integration tests.
//!
//! Proves brokered filesystem/process execution: DTO mapping, per-run
//! virtual CWD resolution and isolation (never process-global), denial and
//! cancellation before provider invocation, native I/O parity through real
//! NSE execution, bounded process execution, and platform behavior.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eggsec_nse::limits::{NseCancellationToken, NseExecutionLimits, NseResourceCounters};
use eggsec_nse::profile::{
    NseExecutionProfileKind, NseModulePolicy, NseNetworkPolicy, NseScriptPolicy,
};
use eggsec_nse::resolver::NseScriptSource;
use eggsec_nse::{
    broker_fs_current_dir, broker_fs_open, broker_fs_read_to_string, broker_fs_resolve,
    broker_fs_set_current_dir, broker_fs_write, broker_is_privileged, broker_network_interfaces,
    broker_process_run, broker_process_spawn, execute_nse_run, CountingFilesystemProvider,
    CountingProcessProvider, NseCapabilityContext, NseFileMetadata, NseHostServices, NseOpenMode,
    NseProcessSpec, NseRunRequest, ResolvedNseExecutionProfile, SandboxConfig,
};

fn policies() -> (NseScriptPolicy, NseModulePolicy) {
    (
        NseScriptPolicy {
            allow_builtin_scripts: true,
            allow_script_files: false,
            allowed_script_roots: Vec::new(),
            allow_conventional_nmap_paths: false,
            max_script_bytes: None,
        },
        NseModulePolicy {
            allow_builtin_modules: true,
            allow_filesystem_modules: false,
            allowed_module_roots: Vec::new(),
            max_module_bytes: None,
        },
    )
}

fn test_context(
    kind: NseExecutionProfileKind,
    network: NseNetworkPolicy,
    sandbox: SandboxConfig,
) -> (NseCapabilityContext, Arc<NseResourceCounters>) {
    let (scripts, modules) = policies();
    let counters = Arc::new(NseResourceCounters::default());
    let ctx = NseCapabilityContext::new(
        kind,
        network,
        scripts,
        modules,
        sandbox,
        NseExecutionLimits::default(),
        NseCancellationToken::new(),
        counters.clone(),
    );
    (ctx, counters)
}

fn manual_ctx() -> (NseCapabilityContext, Arc<NseResourceCounters>) {
    test_context(
        NseExecutionProfileKind::ManualPermissive,
        NseNetworkPolicy::AllowAllManual,
        SandboxConfig::default(),
    )
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Isolated scratch directory (removed on drop).
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "eggsec-nse-fs-{}-{}-{}",
            label,
            std::process::id(),
            id
        ));
        std::fs::create_dir_all(&path).expect("scratch dir");
        Self { path }
    }

    fn file(&self, name: &str) -> String {
        self.path.join(name).to_string_lossy().to_string()
    }

    fn path_string(&self) -> String {
        self.path.to_string_lossy().to_string()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn manual_profile() -> ResolvedNseExecutionProfile {
    ResolvedNseExecutionProfile::manual_permissive(Some("127.0.0.1"))
}

fn inline_script(label: &str, body: &str) -> NseScriptSource {
    NseScriptSource::InlineManual {
        label: label.to_string(),
        content: body.to_string(),
    }
}

// ---------------------------------------------------------------------------
// DTOs and modes
// ---------------------------------------------------------------------------

#[test]
fn file_metadata_dto_mapping() {
    let dir = TempDir::new("dto");
    let path = dir.file("note.txt");
    std::fs::write(&path, b"hello metadata").expect("seed file");

    let native = std::fs::metadata(&path).expect("native stat");
    let dto = NseFileMetadata::from_std(&native);
    assert_eq!(dto.len, 14);
    assert!(dto.is_file);
    assert!(!dto.is_dir);
    assert!(!dto.is_symlink);
    assert!(!dto.readonly);
    assert!(dto.modified_secs.is_some());
    #[cfg(unix)]
    assert!(dto.unix_mode.is_some(), "unix reports mode bits");
    #[cfg(not(unix))]
    assert!(dto.unix_mode.is_none(), "non-unix reports no mode bits");

    let dir_dto = NseFileMetadata::from_std(&std::fs::metadata(dir.path_string()).expect("dir"));
    assert!(dir_dto.is_dir);
    assert!(!dir_dto.is_file);

    assert_eq!(NseOpenMode::parse("r"), NseOpenMode::Read);
    assert_eq!(NseOpenMode::parse("w+"), NseOpenMode::WriteRead);
    assert_eq!(NseOpenMode::parse("mystery"), NseOpenMode::Read);
    assert!(NseOpenMode::Write.is_write());
    assert!(!NseOpenMode::Read.is_write());
}

// ---------------------------------------------------------------------------
// Virtual CWD: resolution, isolation, run-locality
// ---------------------------------------------------------------------------

#[test]
fn virtual_cwd_resolution_and_isolation() {
    let process_cwd = std::env::current_dir().expect("process cwd");
    let dir_a = TempDir::new("cwd-a");
    let dir_b = TempDir::new("cwd-b");
    let (ctx, _) = manual_ctx();
    let services_a = NseHostServices::native();
    let services_b = NseHostServices::native();

    broker_fs_set_current_dir(&ctx, &services_a, &dir_a.path_string(), "test.cwd")
        .expect("set virtual cwd A");
    broker_fs_set_current_dir(&ctx, &services_b, &dir_b.path_string(), "test.cwd")
        .expect("set virtual cwd B");

    let cwd_a = broker_fs_current_dir(&ctx, &services_a, "test.cwd").expect("cwd A");
    let cwd_b = broker_fs_current_dir(&ctx, &services_b, "test.cwd").expect("cwd B");
    assert_eq!(cwd_a, dir_a.path);
    assert_eq!(cwd_b, dir_b.path);

    let rel_a = broker_fs_resolve(&services_a, "rel.txt", "test.cwd").expect("resolve A");
    let rel_b = broker_fs_resolve(&services_b, "rel.txt", "test.cwd").expect("resolve B");
    assert_eq!(rel_a, dir_a.path.join("rel.txt"));
    assert_eq!(rel_b, dir_b.path.join("rel.txt"));

    let abs = broker_fs_resolve(&services_a, "/etc/hostname", "test.cwd").expect("absolute");
    assert_eq!(abs, PathBuf::from("/etc/hostname"));

    assert_eq!(
        std::env::current_dir().expect("process cwd after"),
        process_cwd,
        "virtual CWD must never mutate the process"
    );
}

#[test]
fn fresh_bundle_has_no_virtual_cwd() {
    let (ctx, _) = manual_ctx();
    let services = NseHostServices::native();
    let cwd = broker_fs_current_dir(&ctx, &services, "test.cwd-fresh").expect("cwd");
    assert_eq!(cwd, std::env::current_dir().expect("process cwd"));
}

#[test]
fn set_cwd_rejects_missing_directory() {
    let (ctx, _) = manual_ctx();
    let services = NseHostServices::native();
    let missing = std::env::temp_dir().join("eggsec-nse-definitely-missing-dir");
    let _ = std::fs::remove_dir_all(&missing);
    assert!(broker_fs_set_current_dir(
        &ctx,
        &services,
        &missing.to_string_lossy(),
        "test.cwd-missing"
    )
    .is_err());
}

// ---------------------------------------------------------------------------
// Denial and cancellation precede provider invocation
// ---------------------------------------------------------------------------

#[test]
fn agent_safe_write_denied_before_provider_call() {
    let (ctx, _) = test_context(
        NseExecutionProfileKind::AgentSafe,
        NseNetworkPolicy::DenyAll,
        SandboxConfig::default(),
    );
    let counting = Arc::new(CountingFilesystemProvider::new());
    let services = NseHostServices::native().with_fs(counting.clone());

    let err = broker_fs_write(
        &ctx,
        &services,
        "/tmp/should-not-exist",
        b"x",
        "test.deny-write",
    )
    .expect_err("AgentSafe write must be denied");
    assert!(
        err.contains("denied") || err.contains("not allowed"),
        "{err}"
    );
    assert_eq!(counting.calls(), 0);

    let err = match broker_fs_open(
        &ctx,
        &services,
        "/tmp/should-not-exist",
        NseOpenMode::Write,
        "test.deny-open",
    ) {
        Ok(_) => panic!("AgentSafe open-for-write must be denied"),
        Err(e) => e,
    };
    assert!(
        err.contains("denied") || err.contains("not allowed"),
        "{err}"
    );
    assert_eq!(counting.calls(), 0);
}

#[test]
fn ci_safe_process_denied_before_provider_call() {
    let (ctx, _) = test_context(
        NseExecutionProfileKind::CiSafe,
        NseNetworkPolicy::DenyAll,
        SandboxConfig::default(),
    );
    let counting = Arc::new(CountingProcessProvider::new());
    let services = NseHostServices::native().with_process(counting.clone());
    let spec = NseProcessSpec::new("echo", vec!["hi".to_string()], Duration::from_secs(5));

    assert!(broker_process_run(&ctx, &services, &spec, "test.deny-run").is_err());
    assert!(broker_process_spawn(&ctx, &services, &spec, "test.deny-spawn").is_err());
    assert!(broker_is_privileged(&ctx, &services, "id", "test.deny-priv").is_err());
    assert!(broker_network_interfaces(&ctx, &services, "ip", "test.deny-if").is_err());
    assert_eq!(counting.calls(), 0);
}

#[test]
fn sandbox_block_denied_before_provider_call() {
    let sandbox = SandboxConfig {
        enabled: true,
        allowed_dir: Some(PathBuf::from("/definitely/not/allowed")),
        ..SandboxConfig::default()
    };
    let (ctx, _) = test_context(
        NseExecutionProfileKind::ManualPermissive,
        NseNetworkPolicy::AllowAllManual,
        sandbox,
    );
    let counting = Arc::new(CountingFilesystemProvider::new());
    let services = NseHostServices::native().with_fs(counting.clone());

    let err = broker_fs_write(&ctx, &services, "/tmp/escape.txt", b"x", "test.sandbox")
        .expect_err("sandbox escape must be blocked");
    assert!(err.contains("blocked by sandbox"), "{err}");
    assert_eq!(counting.calls(), 0);
}

#[test]
fn cancellation_precedes_fs_provider_call() {
    let (scripts, modules) = policies();
    let token = NseCancellationToken::new();
    token.cancel();
    let ctx = NseCapabilityContext::new(
        NseExecutionProfileKind::ManualPermissive,
        NseNetworkPolicy::AllowAllManual,
        scripts,
        modules,
        SandboxConfig::default(),
        NseExecutionLimits::default(),
        token,
        Arc::new(NseResourceCounters::default()),
    );
    let counting = Arc::new(CountingFilesystemProvider::new());
    let services = NseHostServices::native().with_fs(counting.clone());

    assert!(broker_fs_read_to_string(&ctx, &services, "/tmp/x", "test.cancel").is_err());
    assert_eq!(counting.calls(), 0);
}

// ---------------------------------------------------------------------------
// End to end through real NSE execution
// ---------------------------------------------------------------------------

#[test]
fn io_read_write_append_end_to_end() {
    let dir = TempDir::new("io-e2e");
    let target = dir.file("data.txt");
    let services = NseHostServices::native();
    let script = format!(
        r#"
hostrule = function(host) return true end
action = function(host, port)
  local f = io.open("{target}", "w")
  assert(f.fd ~= nil, "open failed: " .. (f.error or "?"))
  assert(io.write(f, "hello ") == 6, "write 1")
  assert(io.write(f, "world") == 5, "write 2")
  io.close(f)
  local g = io.open("{target}", "r")
  local data = io.read(g, 64)
  io.close(g)
  return "data:" .. data
end
"#,
        target = target.replace('\\', "\\\\")
    );
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("io-e2e", &script),
        manual_profile(),
    )
    .with_host_services(services);
    let report = execute_nse_run(request).expect("io run succeeds");
    assert!(
        report.output.content.contains("data:hello world"),
        "io read/write must round-trip, got: {}",
        report.output.content
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("seed check"),
        "hello world"
    );

    // Append mode preserves existing content.
    let script = format!(
        r#"
hostrule = function(host) return true end
action = function(host, port)
  local f = io.open("{target}", "a")
  assert(f.fd ~= nil, "append open failed")
  io.write(f, "!")
  io.close(f)
  return "appended"
end
"#,
        target = target.replace('\\', "\\\\")
    );
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("io-append", &script),
        manual_profile(),
    )
    .with_host_services(NseHostServices::native());
    let report = execute_nse_run(request).expect("append run succeeds");
    assert!(
        report.output.content.contains("appended"),
        "{}",
        report.output.content
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("append check"),
        "hello world!"
    );
}

#[test]
fn io_open_modes_seek_flush_end_to_end() {
    let dir = TempDir::new("io-modes");
    let target = dir.file("modes.bin");
    let script = format!(
        r#"
hostrule = function(host) return true end
action = function(host, port)
  local f = io.open("{target}", "w+")
  assert(f.fd ~= nil, "w+ open failed")
  io.write(f, "abcdef")
  io.flush(f)
  assert(io.seek(f, 2) == 2, "seek")
  local tail = io.read(f, 16)
  assert(io.type(f) == "file", "type")
  io.close(f)
  assert(io.type(f) == "nil", "closed type")
  return "tail:" .. tail
end
"#,
        target = target.replace('\\', "\\\\")
    );
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("io-modes", &script),
        manual_profile(),
    )
    .with_host_services(NseHostServices::native());
    let report = execute_nse_run(request).expect("modes run succeeds");
    assert!(
        report.output.content.contains("tail:cdef"),
        "seek+read must round-trip, got: {}",
        report.output.content
    );
}

#[test]
fn lfs_attributes_dir_chdir_end_to_end() {
    let process_cwd = std::env::current_dir().expect("process cwd");
    let dir = TempDir::new("lfs-e2e");
    let base = dir.path_string();
    let script = format!(
        r#"
hostrule = function(host) return true end
action = function(host, port)
  assert(lfs.touch("{base}/a.txt") == true, "touch")
  local a = lfs.attributes("{base}/a.txt")
  assert(a.is_file == true, "is_file")
  assert(lfs.mkdir("{base}/sub") == true, "mkdir")
  assert(lfs.chdir("{base}/sub") == true, "chdir")
  local cwd = lfs.currentdir()
  assert(lfs.chdir("{base}") == true, "chdir back")
  assert(os.chdir("{base}/sub") == 0, "os chdir")
  assert(os.getcwd():sub(-3) == "sub", "os getcwd: " .. os.getcwd())
  local d = lfs.dir("{base}")
  assert(#d >= 2, "dir entries")
  assert(lfs.remove("{base}/a.txt") == true, "remove")
  assert(os.remove("{base}/sub") == false, "os remove dir-as-file fails")
  return "cwd:" .. cwd .. "|entries:" .. #d
end
"#,
        base = base.replace('\\', "\\\\")
    );
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("lfs-e2e", &script),
        manual_profile(),
    )
    .with_host_services(NseHostServices::native());
    let report = execute_nse_run(request).expect("lfs run succeeds");
    assert!(
        report.output.content.contains("entries:2"),
        "lfs dir must list both entries, got: {}",
        report.output.content
    );
    assert!(
        report.output.content.contains("cwd:") && report.output.content.contains("sub"),
        "virtual chdir must be observable, got: {}",
        report.output.content
    );
    assert_eq!(
        std::env::current_dir().expect("process cwd after"),
        process_cwd,
        "Lua chdir must never mutate the process CWD"
    );
    assert!(
        report
            .capability_events
            .iter()
            .any(|e| e.kind == "filesystem_write" && e.allowed),
        "filesystem capability events must be recorded"
    );
}

#[test]
#[cfg(unix)]
fn lfs_links_and_permissions_unix() {
    let dir = TempDir::new("lfs-links");
    let base = dir.path_string();
    let script = format!(
        r#"
hostrule = function(host) return true end
action = function(host, port)
  assert(lfs.touch("{base}/orig.txt") == true, "touch")
  assert(lfs.link("{base}/orig.txt", "{base}/hard.txt", false) == true, "hard link")
  assert(lfs.link("{base}/orig.txt", "{base}/soft.txt", true) == true, "symlink")
  local s = lfs.symlinkattributes("{base}/soft.txt")
  assert(s.is_link == true, "is_link")
  assert(s.target ~= nil, "target present")
  assert(lfs.set_mode("{base}/orig.txt", "600") == true, "set_mode")
  local a = lfs.attributes("{base}/orig.txt")
  assert(a.readonly == false, "600 is writable")
  assert(lfs.set_mode("{base}/orig.txt", "444") == true, "set_mode ro")
  local b = lfs.attributes("{base}/orig.txt")
  assert(b.readonly == true, "444 is readonly")
  return "links-ok"
end
"#,
        base = base.replace('\\', "\\\\")
    );
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("lfs-links", &script),
        manual_profile(),
    )
    .with_host_services(NseHostServices::native());
    let report = execute_nse_run(request).expect("links run succeeds");
    assert!(
        report.output.content.contains("links-ok"),
        "{}",
        report.output.content
    );
    assert_eq!(
        std::fs::read_link(dir.path.join("soft.txt")).expect("link target"),
        dir.path.join("orig.txt"),
        "symlink target must be the approved absolute path"
    );
}

#[test]
fn popen_returns_handle_table_end_to_end() {
    // Portable no-op command through the platform shell.
    let script = r#"
hostrule = function(host) return true end
action = function(host, port)
  local p = io.popen("echo nse-probe", "r")
  assert(p.type == "process", "popen type")
  assert(p.pid ~= nil, "popen pid")
  assert(p.running == true, "popen running")
  return "popen-ok"
end
"#;
    let request = NseRunRequest::new(
        "127.0.0.1",
        inline_script("popen", script),
        manual_profile(),
    )
    .with_host_services(NseHostServices::native());
    let report = execute_nse_run(request).expect("popen run succeeds");
    assert!(
        report.output.content.contains("popen-ok"),
        "{}",
        report.output.content
    );
}

#[test]
fn agent_safe_lua_denials() {
    let dir = TempDir::new("agent-deny");
    let target = dir.file("denied.txt");
    let script = format!(
        r#"
hostrule = function(host) return true end
action = function(host, port)
  local w = io.open("{target}", "w")
  local p = io.popen("echo hi", "r")
  return "write:" .. (w.error or "opened?!") .. "|popen:" .. (p.error or "spawned?!")
end
"#,
        target = target.replace('\\', "\\\\")
    );
    let profile = ResolvedNseExecutionProfile::agent_safe("127.0.0.1", &[]);
    let request = NseRunRequest::new("127.0.0.1", inline_script("agent-deny", &script), profile)
        .with_host_services(NseHostServices::native());
    let report = execute_nse_run(request).expect("denial run succeeds");
    assert!(
        report.output.content.contains("write:")
            && (report.output.content.contains("denied")
                || report.output.content.contains("not allowed")
                || report.output.content.contains("blocked")),
        "AgentSafe write must be denied, got: {}",
        report.output.content
    );
    assert!(
        report.output.content.contains("popen:")
            && (report.output.content.contains("denied")
                || report.output.content.contains("not allowed")
                || report.output.content.contains("blocked")),
        "AgentSafe popen must be denied, got: {}",
        report.output.content
    );
    assert!(
        !dir.path.join("denied.txt").exists(),
        "denied write must not create the file"
    );
}

// ---------------------------------------------------------------------------
// Native process execution: bounded, portable, no detached children
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn sleep_spec() -> NseProcessSpec {
    NseProcessSpec::new(
        "sh",
        vec!["-c".to_string(), "sleep 30".to_string()],
        Duration::from_millis(300),
    )
}

#[cfg(windows)]
fn sleep_spec() -> NseProcessSpec {
    NseProcessSpec::new(
        "cmd",
        vec!["/C".to_string(), "ping -n 30 127.0.0.1 >NUL".to_string()],
        Duration::from_millis(300),
    )
}

#[cfg(not(unix))]
#[cfg(not(windows))]
fn sleep_spec() -> NseProcessSpec {
    NseProcessSpec::new("", Vec::new(), Duration::from_millis(300))
}

#[test]
fn process_run_portable_echo() {
    let (ctx, _) = manual_ctx();
    let services = NseHostServices::native();
    #[cfg(unix)]
    let spec = NseProcessSpec::new(
        "sh",
        vec!["-c".to_string(), "printf hello-proc".to_string()],
        Duration::from_secs(10),
    );
    #[cfg(windows)]
    let spec = NseProcessSpec::new(
        "cmd",
        vec!["/C".to_string(), "echo hello-proc".to_string()],
        Duration::from_secs(10),
    );
    #[cfg(not(unix))]
    #[cfg(not(windows))]
    let spec = NseProcessSpec::new("", Vec::new(), Duration::from_secs(10));

    let result = broker_process_run(&ctx, &services, &spec, "test.echo").expect("echo runs");
    assert!(result.success);
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("hello-proc"),
        "stdout must carry the echo, got: {:?}",
        result.stdout
    );
}

#[test]
#[cfg(any(unix, windows))]
fn process_run_timeout_kills_child() {
    let (ctx, counters) = manual_ctx();
    let services = NseHostServices::native();
    let ops_before = counters.network_operations.load(Ordering::Relaxed);
    let start = Instant::now();
    let err = broker_process_run(&ctx, &services, &sleep_spec(), "test.timeout")
        .expect_err("overrun must time out");
    assert!(err.contains("timed out"), "{err}");
    assert!(
        start.elapsed() < Duration::from_secs(15),
        "run must stay bounded, took {:?}",
        start.elapsed()
    );
    let _ = ops_before;
}

#[test]
#[cfg(any(unix, windows))]
fn process_spawn_kill_lifecycle() {
    let (ctx, _) = manual_ctx();
    let services = NseHostServices::native();
    let mut child =
        broker_process_spawn(&ctx, &services, &sleep_spec(), "test.spawn").expect("spawn");
    assert!(child.is_running(), "fresh child runs");
    assert!(child.id().is_some(), "child has a pid");
    child.kill();
    // Reap with a grace loop (kill is async on some platforms).
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.is_running() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(!child.is_running(), "killed child must exit");
}

#[test]
fn privilege_and_interfaces_smoke() {
    let (ctx, _) = manual_ctx();
    let services = NseHostServices::native();
    let privileged =
        broker_is_privileged(&ctx, &services, "id", "test.priv").expect("privilege probe");
    let _ = privileged;
    let interfaces =
        broker_network_interfaces(&ctx, &services, "ip", "test.if").expect("interfaces");
    assert!(
        !interfaces.is_empty(),
        "loopback fallback guarantees entries"
    );
}

// ---------------------------------------------------------------------------
// Contention: concurrent runs isolate handles and virtual CWDs
// ---------------------------------------------------------------------------

#[test]
fn concurrent_runs_isolate_handles_and_cwd() {
    let process_cwd = std::env::current_dir().expect("process cwd");
    let mut threads = Vec::new();
    for i in 0..4u64 {
        threads.push(std::thread::spawn(move || {
            let dir = TempDir::new(&format!("concurrent-{i}"));
            let script = format!(
                r#"
hostrule = function(host) return true end
action = function(host, port)
  assert(lfs.chdir("{base}") == true, "chdir")
  local f = io.open("slot.txt", "w")
  assert(f.fd ~= nil, "open")
  io.write(f, "run-{i}")
  io.close(f)
  local g = io.open("slot.txt", "r")
  local data = io.read(g, 16)
  io.close(g)
  return "slot:" .. data .. "|cwd:" .. lfs.currentdir()
end
"#,
                base = dir.path_string().replace('\\', "\\\\"),
                i = i
            );
            let request = NseRunRequest::new(
                "127.0.0.1",
                inline_script(&format!("concurrent-{i}"), &script),
                manual_profile(),
            )
            .with_host_services(NseHostServices::native());
            let report = execute_nse_run(request).expect("concurrent run succeeds");
            assert!(
                report.output.content.contains(&format!("slot:run-{i}")),
                "run {i} must see its own file, got: {}",
                report.output.content
            );
            assert!(
                report.output.content.contains(&format!("concurrent-{i}")),
                "run {i} must see its own virtual CWD, got: {}",
                report.output.content
            );
        }));
    }
    for t in threads {
        t.join().expect("thread joins");
    }
    assert_eq!(
        std::env::current_dir().expect("process cwd after"),
        process_cwd,
        "concurrent virtual chdirs must never mutate the process"
    );
}
