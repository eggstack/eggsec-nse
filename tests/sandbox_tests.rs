use eggsec_nse::SandboxConfig;
use std::net::IpAddr;
use std::path::PathBuf;

#[test]
fn test_sandbox_disabled_allows_all_paths() {
    let config = SandboxConfig {
        enabled: false,
        ..Default::default()
    };
    assert!(config.get_allowed_path("/etc/passwd").is_some());
    assert!(config
        .get_allowed_path("/tmp/eggsec-nse/test.txt")
        .is_some());
}

#[test]
fn test_sandbox_enabled_restricts_paths() {
    let config = SandboxConfig {
        enabled: true,
        allowed_dir: Some(PathBuf::from("/tmp/eggsec-nse")),
        ..Default::default()
    };
    assert!(config
        .get_allowed_path("/tmp/eggsec-nse/test.txt")
        .is_some());
    assert!(config.is_path_allowed("/tmp/eggsec-nse/test.txt"));
}

#[test]
fn test_sandbox_blocks_outside_allowed_dir() {
    let config = SandboxConfig {
        enabled: true,
        allowed_dir: Some(PathBuf::from("/tmp/eggsec-nse")),
        ..Default::default()
    };
    // These paths are outside the allowed directory
    assert!(config.get_allowed_path("/etc/passwd").is_none());
    assert!(config.get_allowed_path("/tmp/other/file.txt").is_none());
}

#[test]
fn test_sandbox_disabled_allows_all_commands() {
    let config = SandboxConfig {
        enabled: false,
        ..Default::default()
    };
    assert!(config.is_command_allowed("ls"));
    assert!(config.is_command_allowed("curl http://example.com"));
    assert!(config.is_command_allowed("cat /etc/passwd"));
}

#[test]
fn test_sandbox_blocks_all_commands_when_allowlist_empty() {
    let config = SandboxConfig {
        enabled: true,
        allowed_commands: Vec::new(),
        ..Default::default()
    };
    assert!(!config.is_command_allowed("ls"));
    assert!(!config.is_command_allowed("curl"));
    assert!(!config.is_command_allowed("cat"));
}

#[test]
fn test_sandbox_respects_command_allowlist() {
    let config = SandboxConfig {
        enabled: true,
        allowed_commands: vec!["ls".to_string(), "cat".to_string()],
        ..Default::default()
    };
    assert!(config.is_command_allowed("ls"));
    assert!(config.is_command_allowed("ls -la"));
    assert!(config.is_command_allowed("cat /tmp/file"));
    assert!(!config.is_command_allowed("curl http://example.com"));
    assert!(!config.is_command_allowed("rm -rf /"));
}

#[test]
fn test_sandbox_disabled_allows_all_networks() {
    let config = SandboxConfig {
        enabled: false,
        ..Default::default()
    };
    assert!(config.is_network_allowed("127.0.0.1".parse().unwrap()));
    assert!(config.is_network_allowed("10.0.0.1".parse().unwrap()));
    assert!(config.is_network_allowed("192.168.1.1".parse().unwrap()));
}

#[test]
fn test_sandbox_empty_networks_allows_all() {
    let config = SandboxConfig {
        enabled: true,
        allowed_networks: Vec::new(),
        ..Default::default()
    };
    assert!(config.is_network_allowed("127.0.0.1".parse().unwrap()));
    assert!(config.is_network_allowed("10.0.0.1".parse().unwrap()));
}

#[test]
fn test_sandbox_respects_network_allowlist() {
    use ipnetwork::IpNetwork;
    let config = SandboxConfig {
        enabled: true,
        allowed_networks: vec![
            "10.0.0.0/8".parse::<IpNetwork>().unwrap(),
            "192.168.1.0/24".parse::<IpNetwork>().unwrap(),
        ],
        ..Default::default()
    };
    assert!(config.is_network_allowed("10.0.0.1".parse().unwrap()));
    assert!(config.is_network_allowed("10.255.255.255".parse().unwrap()));
    assert!(config.is_network_allowed("192.168.1.1".parse().unwrap()));
    assert!(config.is_network_allowed("192.168.1.254".parse().unwrap()));
    assert!(!config.is_network_allowed("172.16.0.1".parse().unwrap()));
    assert!(!config.is_network_allowed("8.8.8.8".parse().unwrap()));
}

#[test]
fn test_sandbox_is_host_allowed_localhost() {
    let config = SandboxConfig {
        enabled: true,
        allowed_networks: Vec::new(),
        ..Default::default()
    };
    // localhost should resolve and be allowed when no networks are restricted
    assert!(config.is_host_allowed("localhost"));
}

#[test]
fn test_sandbox_resolve_host_localhost() {
    let config = SandboxConfig {
        enabled: true,
        allowed_networks: Vec::new(),
        ..Default::default()
    };
    let addrs = config.resolve_host("localhost");
    assert!(!addrs.is_empty());
}

#[test]
fn test_sandbox_resolve_host_filters_by_network() {
    use ipnetwork::IpNetwork;
    let config = SandboxConfig {
        enabled: true,
        allowed_networks: vec!["127.0.0.0/8".parse::<IpNetwork>().unwrap()],
        ..Default::default()
    };
    let addrs = config.resolve_host("localhost");
    assert!(!addrs.is_empty());
    for addr in &addrs {
        assert!(config.is_network_allowed(*addr));
    }
}

#[test]
fn test_sandbox_resolve_host_no_networks_returns_all() {
    let config = SandboxConfig {
        enabled: true,
        allowed_networks: Vec::new(),
        ..Default::default()
    };
    let addrs = config.resolve_host("localhost");
    assert!(!addrs.is_empty());
}

#[test]
fn test_sandbox_disabled_resolve_host() {
    let config = SandboxConfig {
        enabled: false,
        ..Default::default()
    };
    let addrs = config.resolve_host("localhost");
    assert!(!addrs.is_empty());
}

#[test]
fn test_sandbox_command_parsing() {
    let config = SandboxConfig {
        enabled: true,
        allowed_commands: vec!["nmap".to_string()],
        ..Default::default()
    };
    // Command with arguments should match on command name
    assert!(config.is_command_allowed("nmap -sV -p 80 target"));
    assert!(config.is_command_allowed("nmap"));
    assert!(!config.is_command_allowed("nmaping"));
    assert!(!config.is_command_allowed("other nmap"));
}

#[test]
fn test_sandbox_get_allowed_path_returns_canonical() {
    let config = SandboxConfig {
        enabled: true,
        allowed_dir: Some(PathBuf::from("/tmp/eggsec-nse")),
        ..Default::default()
    };
    // Path inside allowed dir should return a valid path
    if let Some(path) = config.get_allowed_path("/tmp/eggsec-nse/test.txt") {
        assert!(path.starts_with("/tmp/eggsec-nse"));
    }
}

#[test]
fn test_sandbox_config_clone() {
    let config = SandboxConfig {
        enabled: true,
        allowed_dir: Some(PathBuf::from("/tmp/test")),
        allowed_commands: vec!["ls".to_string()],
        log_violations: false,
        allowed_networks: vec!["10.0.0.0/8".parse().unwrap()],
    };
    let cloned = config.clone();
    assert_eq!(cloned.enabled, true);
    assert_eq!(cloned.allowed_dir, Some(PathBuf::from("/tmp/test")));
    assert_eq!(cloned.allowed_commands, vec!["ls".to_string()]);
    assert_eq!(cloned.log_violations, false);
}
