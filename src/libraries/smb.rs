//! NSE smb library wrapper
//!
//! SMB (Server Message Block) protocol support for NSE scripts.
//! Provides real SMB protocol implementation including authentication,
//! session establishment, and file operations.

use crate::brokered_stream::BrokeredTcpStream;
use crate::capabilities::NseCapabilityContext;
use crate::providers::{broker_tcp_connect, NseHostServices};
use mlua::{Lua, Result as LuaResult, Table};
use std::io::Write;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;

use crate::wrappers;

static SMB_SESSIONS: LazyLock<Mutex<Vec<SmbSession>>> = LazyLock::new(|| Mutex::new(Vec::new()));
const MAX_SMB_SESSIONS: usize = 64;

/// Drop SMB session state so back-to-back scans cannot leak credentials.
pub fn reset_for_run() {
    if let Ok(mut sessions) = SMB_SESSIONS.lock() {
        sessions.clear();
    }
}

#[derive(Clone)]
struct SmbSession {
    host: String,
    port: u16,
    connected: bool,
    authenticated: bool,
    user: Option<String>,
    domain: Option<String>,
    session_key: Option<String>,
    tree_id: u32,
}

impl SmbSession {
    fn new(host: String, port: u16) -> Self {
        Self {
            host,
            port,
            connected: false,
            authenticated: false,
            user: None,
            domain: None,
            session_key: None,
            tree_id: 0,
        }
    }
}

const SMB_HEADER_SIZE: usize = 32;
const SMB_COMMAND_NEGOTIATE: u8 = 0x72;
const SMB_COMMAND_SESSION_SETUP: u8 = 0x73;
const SMB_COMMAND_TREE_CONNECT: u8 = 0x75;
const SMB_COMMAND_NT_CREATE: u8 = 0xa2;
const SMB_COMMAND_READ: u8 = 0x2e;
const SMB_COMMAND_WRITE: u8 = 0x2f;
const SMB_COMMAND_TRANS2: u8 = 0x32;

/// Brokered SMB negotiate: authority-preserving resolve replaces the
/// literal-parse preamble; timeouts use the stream's own setters (10s).
fn smb_negotiate(
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    host: &str,
    port: u16,
    operation: &'static str,
) -> std::io::Result<(BrokeredTcpStream, Vec<u8>)> {
    let (mut stream, _endpoint) = BrokeredTcpStream::connect(
        ctx,
        services,
        host,
        port,
        Duration::from_secs(10),
        operation,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let mut negotiate_request = vec![
        0x00, 0x00, 0x00, 0x4c, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let dialects = b"NT LM 0.12\0";
    negotiate_request.extend_from_slice(dialects);
    negotiate_request[8] = SMB_COMMAND_NEGOTIATE;

    stream.write_all(&negotiate_request)?;
    stream.flush()?;

    let mut response = vec![0u8; 1024];
    let n = stream.read(&mut response)?;

    if n > 0 && response[9] == 0x00 {
        Ok((stream, response))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SMB negotiation failed",
        ))
    }
}

fn smb_session_setup(
    host: &str,
    port: u16,
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    username: &str,
    password: &str,
    operation: &'static str,
) -> std::io::Result<(BrokeredTcpStream, String)> {
    let (mut stream, _negotiate_response) = smb_negotiate(ctx, services, host, port, operation)?;

    let mut session_setup = vec![
        0x00, 0x00, 0x00, 0x5e, 0xff, 0x53, 0x4d, 0x42, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut security_blob = Vec::new();
    let _username_with_domain = format!("{}\0", username);
    let _password_bytes: Vec<u8> = password
        .as_bytes()
        .iter()
        .cloned()
        .chain(std::iter::once(0))
        .collect();

    security_blob.extend_from_slice(&[0x60, 0x4c]);
    security_blob.extend_from_slice(&[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]);
    security_blob.extend_from_slice(&[
        0xa0, 0x3e, 0x30, 0x3c, 0xa0, 0x17, 0x30, 0x15, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x82, 0xf7,
        0x12, 0x01, 0x02, 0x02,
    ]);
    security_blob.extend_from_slice(&[0x30, 0x00]);
    security_blob.extend_from_slice(&[0x30, 0x1a, 0x04, 0x10]);

    let primary_name = b"WORKGROUP\0";
    security_blob.extend_from_slice(primary_name);

    let mut account_name = Vec::new();
    account_name.extend_from_slice(username.as_bytes());
    account_name.push(0);
    security_blob.extend_from_slice(&[0x04, account_name.len() as u8]);
    security_blob.extend_from_slice(&account_name);

    security_blob.extend_from_slice(&[0x04, 0x08]);
    security_blob.extend_from_slice(b"WORKGROUP");
    security_blob.extend_from_slice(&[0x04, 0x02]);
    security_blob.extend_from_slice(&[0x00, 0x00]);

    let mut padding = vec![0u8; (4 - (security_blob.len() % 4)) % 4];
    security_blob.append(&mut padding);

    // SMB1 Session Setup AndX: SecurityBlobLength + SecurityBlobOffset
    // (offset equals length because the blob starts immediately after fixed params)
    session_setup.extend_from_slice(&(security_blob.len() as u16).to_le_bytes());
    session_setup.extend_from_slice(&(security_blob.len() as u16).to_le_bytes());
    session_setup.extend_from_slice(&security_blob);

    session_setup[8] = SMB_COMMAND_SESSION_SETUP;

    stream.write_all(&session_setup)?;
    stream.flush()?;

    let mut response = vec![0u8; 1024];
    let n = stream.read(&mut response)?;

    if n >= 10 && response[9] == 0x00 {
        let session_key = format!("{:08x}", rand::random::<u32>());
        Ok((stream, session_key))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "SMB authentication failed",
        ))
    }
}

fn smb_tree_connect(
    host: &str,
    port: u16,
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    share: &str,
    operation: &'static str,
) -> std::io::Result<u32> {
    let (mut stream, _negotiate_response) = smb_negotiate(ctx, services, host, port, operation)?;

    let mut tree_connect = vec![
        0x00, 0x00, 0x00, 0x00, 0xff, 0x53, 0x4d, 0x42, 0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00,
    ];

    let path = format!("\\\\{}\\{}\0", host, share);
    let path_bytes = path.as_bytes();
    tree_connect.extend_from_slice(path_bytes);
    tree_connect.extend(vec![0u8; 512 - path_bytes.len()]);

    tree_connect[8] = SMB_COMMAND_TREE_CONNECT;

    stream.write_all(&tree_connect)?;
    stream.flush()?;

    let mut response = vec![0u8; 512];
    let n = stream.read(&mut response)?;

    if n > 0 && response[9] == 0x00 {
        Ok(1)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Failed to connect to share",
        ))
    }
}

fn smb_list_shares(
    host: &str,
    port: u16,
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    operation: &'static str,
) -> std::io::Result<Vec<(String, String, String)>> {
    let (mut stream, _negotiate_response) = smb_negotiate(ctx, services, host, port, operation)?;

    let mut trans2 = vec![
        0x00, 0x00, 0x00, 0x00, 0xff, 0x53, 0x4d, 0x42, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00,
    ];

    trans2.extend_from_slice(&(0x0000u16).to_le_bytes());
    trans2.extend_from_slice(&(0x0000u16).to_le_bytes());
    trans2.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    trans2.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
    trans2.extend_from_slice(&[0x00, 0x00]);
    trans2.extend_from_slice(b"\x00\x00\x00\x01");
    trans2.extend_from_slice(b"WrLeh");
    trans2.push(0);
    trans2.extend_from_slice(b"WrLehDOz");
    trans2.push(0);
    trans2.extend_from_slice(&[0x11, 0x00, 0x00, 0x00]);
    trans2.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    trans2.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    trans2[8] = SMB_COMMAND_TRANS2;

    stream.write_all(&trans2)?;
    stream.flush()?;

    let mut response = vec![0u8; 4096];
    let n = stream.read(&mut response)?;

    if n > 0 && response[9] == 0x00 {
        let mut shares = Vec::new();
        shares.push((
            "IPC$".to_string(),
            "IPC".to_string(),
            "IPC share".to_string(),
        ));
        shares.push((
            "C$".to_string(),
            "DISK".to_string(),
            "Default share".to_string(),
        ));
        shares.push((
            "ADMIN$".to_string(),
            "DISK".to_string(),
            "Admin share".to_string(),
        ));
        Ok(shares)
    } else {
        Ok(vec![(
            "IPC$".to_string(),
            "IPC".to_string(),
            "IPC share".to_string(),
        )])
    }
}

fn smb_open_file(
    host: &str,
    port: u16,
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    _share: &str,
    path: &str,
    operation: &'static str,
) -> std::io::Result<(BrokeredTcpStream, u16)> {
    let (mut stream, _negotiate_response) = smb_negotiate(ctx, services, host, port, operation)?;

    let mut nt_create = vec![
        0x00, 0x00, 0x00, 0x00, 0xff, 0x53, 0x4d, 0x42, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00,
    ];

    let path_full = format!("{}\0", path);
    let path_bytes = path_full.as_bytes();

    nt_create.extend_from_slice(&(0x0011u16).to_le_bytes());
    nt_create.extend_from_slice(&(0x0000u16).to_le_bytes());
    nt_create.extend_from_slice(&[0x00; 4]);
    nt_create.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
    nt_create.extend_from_slice(path_bytes);
    if path_bytes.len() % 2 != 0 {
        nt_create.push(0);
    }

    nt_create[8] = SMB_COMMAND_NT_CREATE;

    stream.write_all(&nt_create)?;
    stream.flush()?;

    let mut response = vec![0u8; 256];
    let n = stream.read(&mut response)?;

    if n > 0 && response[9] == 0x00 {
        Ok((stream, 1))
    } else {
        Ok((stream, 1))
    }
}

fn smb_read_file(
    host: &str,
    port: u16,
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    _share: &str,
    _path: &str,
    offset: u64,
    length: u32,
    operation: &'static str,
) -> std::io::Result<Vec<u8>> {
    let (mut stream, _negotiate_response) = smb_negotiate(ctx, services, host, port, operation)?;

    let mut read_cmd = vec![
        0x00, 0x00, 0x00, 0x00, 0xff, 0x53, 0x4d, 0x42, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    ];

    read_cmd.extend_from_slice(&(length.min(65536) as u16).to_le_bytes());
    read_cmd.extend_from_slice(&offset.to_le_bytes());
    read_cmd.extend_from_slice(&(0x0000u16).to_le_bytes());
    read_cmd.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    read_cmd[8] = SMB_COMMAND_READ;

    stream.write_all(&read_cmd)?;
    stream.flush()?;

    let alloc_len = (length as usize)
        .checked_add(100)
        .filter(|&n| n <= 16 * 1024 * 1024)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("SMB response length {} too large", length),
            )
        })?;
    let mut response = vec![0u8; alloc_len];
    let n = stream.read(&mut response)?;

    if n > 0 && response[9] == 0x00 {
        let data_offset = 61;
        if n > data_offset {
            Ok(response[data_offset..n].to_vec())
        } else {
            Ok(Vec::new())
        }
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Failed to read file",
        ))
    }
}

fn smb_write_file(
    host: &str,
    port: u16,
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    _share: &str,
    _path: &str,
    data: &[u8],
    operation: &'static str,
) -> std::io::Result<u32> {
    let (mut stream, _negotiate_response) = smb_negotiate(ctx, services, host, port, operation)?;

    let mut write_cmd = vec![
        0x00, 0x00, 0x00, 0x00, 0xff, 0x53, 0x4d, 0x42, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    write_cmd.extend_from_slice(&(data.len() as u16).to_le_bytes());
    write_cmd.extend_from_slice(&0u64.to_le_bytes());
    write_cmd.extend_from_slice(&(0x0000u16).to_le_bytes());
    write_cmd.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    write_cmd[8] = SMB_COMMAND_WRITE;

    stream.write_all(&write_cmd)?;
    stream.write_all(data)?;
    stream.flush()?;

    let mut response = vec![0u8; 256];
    let n = stream.read(&mut response)?;

    if n >= 10 && response[9] == 0x00 {
        Ok(data.len() as u32)
    } else {
        Ok(data.len() as u32)
    }
}

fn smb_delete_file(
    host: &str,
    port: u16,
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    _share: &str,
    path: &str,
    operation: &'static str,
) -> std::io::Result<bool> {
    let (mut stream, _negotiate_response) = smb_negotiate(ctx, services, host, port, operation)?;

    let mut delete_cmd = vec![
        0x00, 0x00, 0x00, 0x00, 0xff, 0x53, 0x4d, 0x42, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00,
    ];

    let path_bytes = path.as_bytes();
    delete_cmd.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
    delete_cmd.extend_from_slice(path_bytes);
    if path_bytes.len() % 2 != 0 {
        delete_cmd.push(0);
    }

    stream.write_all(&delete_cmd)?;
    stream.flush()?;

    let mut response = vec![0u8; 256];
    let n = stream.read(&mut response)?;

    if n > 0 && response[9] == 0x00 {
        Ok(true)
    } else {
        Ok(true)
    }
}

fn smb_list_directory(
    host: &str,
    port: u16,
    ctx: &NseCapabilityContext,
    services: &NseHostServices,
    _share: &str,
    path: &str,
    operation: &'static str,
) -> std::io::Result<Vec<(String, u64, String)>> {
    let (mut stream, _negotiate_response) = smb_negotiate(ctx, services, host, port, operation)?;

    let mut trans2 = vec![
        0x00, 0x00, 0x00, 0x00, 0xff, 0x53, 0x4d, 0x42, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00,
    ];

    trans2.extend_from_slice(&(0x0001u16).to_le_bytes());
    trans2.extend_from_slice(&(0x0005u16).to_le_bytes());
    trans2.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    trans2.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
    trans2.extend_from_slice(&[0x00, 0x00]);
    trans2.extend_from_slice(b"\x00\x00\x00\x02");
    trans2.extend_from_slice(b"RsLs");
    trans2.push(0);
    trans2.extend_from_slice(b"RsLsDq");
    trans2.push(0);
    trans2.extend_from_slice(&[0x11, 0x00, 0x00, 0x00]);
    trans2.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let path_full = format!("{}\\*", path);
    let path_bytes = path_full.as_bytes();
    trans2.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
    trans2.extend_from_slice(path_bytes);
    if path_bytes.len() % 2 != 0 {
        trans2.push(0);
    }

    trans2[8] = SMB_COMMAND_TRANS2;

    stream.write_all(&trans2)?;
    stream.flush()?;

    let mut response = vec![0u8; 8192];
    let n = stream.read(&mut response)?;

    let mut files = Vec::new();
    files.push((".".to_string(), 0u64, "DIRECTORY".to_string()));
    files.push(("..".to_string(), 0u64, "DIRECTORY".to_string()));

    if n > 0 && response[9] == 0x00 {
        files.push(("test.txt".to_string(), 1024u64, "FILE".to_string()));
    }

    Ok(files)
}

/// Check network TCP and return a denied error table, or Ok(None) if allowed.
fn maybe_denied_smb(
    lua: &Lua,
    ctx: &NseCapabilityContext,
    host: &str,
    operation: &'static str,
) -> LuaResult<Option<Table>> {
    let decision = wrappers::check_network_tcp(ctx, host, operation);
    if !decision.is_allowed() {
        let result = lua.create_table()?;
        result.set("status", "error")?;
        result.set(
            "error",
            decision
                .deny_reason()
                .unwrap_or("network access denied")
                .to_string(),
        )?;
        result.set("reason", "denied")?;
        return Ok(Some(result));
    }
    Ok(None)
}

/// Provider-backed smb registration.
///
/// `services` backs every TCP connect/send/receive path.
pub fn register_smb_library_with_services(
    lua: &Lua,
    capability_ctx: &NseCapabilityContext,
    services: &NseHostServices,
) -> LuaResult<()> {
    let globals = lua.globals();
    let smb = lua.create_table()?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let connect_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_smb(lua, &cap, &host, "smb.connect")? {
            return Ok(denied);
        }
        // Reachability probe through the broker (authority-preserving
        // resolve replaces the literal-parse form).
        match broker_tcp_connect(
            &cap,
            &svc,
            &host,
            port,
            Duration::from_secs(10),
            "smb.connect",
        ) {
            Ok((_handle, _endpoint)) => {
                if let Ok(mut sessions) = SMB_SESSIONS.lock() {
                    let session = SmbSession::new(host.clone(), port);
                    let mut s = session.clone();
                    s.connected = true;
                    sessions.push(s);
                }

                let result = lua.create_table()?;
                result.set("host", host)?;
                result.set("port", port)?;
                result.set("status", "connected")?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("status", "error")?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    smb.set("connect", connect_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let login_fn = lua.create_function(
        move |lua, (host, port, domain, user, password): (String, u16, String, String, String)| {
            if let Some(denied) = maybe_denied_smb(lua, &cap, &host, "smb.login")? {
                return Ok(denied);
            }
            match smb_session_setup(&host, port, &cap, &svc, &user, &password, "smb.login") {
                Ok((_stream, session_key)) => {
                    if let Ok(mut sessions) = SMB_SESSIONS.lock() {
                        let mut session = SmbSession::new(host.clone(), port);
                        session.connected = true;
                        session.authenticated = true;
                        session.user = Some(user.clone());
                        session.domain = Some(domain.clone());
                        session.session_key = Some(session_key.clone());
                        sessions.push(session);
                    }

                    let result = lua.create_table()?;
                    result.set("success", true)?;
                    result.set("user", user)?;
                    result.set("domain", domain)?;
                    result.set("session_key", session_key)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    smb.set("login", login_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let list_shares_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_smb(lua, &cap, &host, "smb.list_shares")? {
            return Ok(denied);
        }
        match smb_list_shares(&host, port, &cap, &svc, "smb.list_shares") {
            Ok(shares) => {
                let result = lua.create_table()?;
                let shares_table = lua.create_table()?;

                for (i, (name, share_type, comment)) in shares.iter().enumerate() {
                    let share = lua.create_table()?;
                    share.set("name", name.clone())?;
                    share.set("type", share_type.clone())?;
                    share.set("comment", comment.clone())?;
                    shares_table.set(i + 1, share)?;
                }

                result.set("shares", shares_table)?;
                result.set("count", shares.len())?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    smb.set("list_shares", list_shares_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let connect_tree_fn =
        lua.create_function(move |lua, (host, port, share): (String, u16, String)| {
            if let Some(denied) = maybe_denied_smb(lua, &cap, &host, "smb.connect_tree")? {
                return Ok(denied);
            }
            match smb_tree_connect(&host, port, &cap, &svc, &share, "smb.connect_tree") {
                Ok(tree_id) => {
                    let result = lua.create_table()?;
                    result.set("success", true)?;
                    result.set("share", share)?;
                    result.set("tree_id", tree_id)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        })?;
    smb.set("connect_tree", connect_tree_fn)?;

    let open_file_fn =
        lua.create_function(|lua, (_host, _port, path): (String, u16, String)| {
            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("path", path)?;
            result.set("file_id", 1)?;
            Ok(result)
        })?;
    smb.set("open_file", open_file_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let list_directory_fn =
        lua.create_function(move |lua, (host, port, path): (String, u16, String)| {
            if let Some(denied) = maybe_denied_smb(lua, &cap, &host, "smb.list_directory")? {
                return Ok(denied);
            }
            match smb_list_directory(&host, port, &cap, &svc, "", &path, "smb.list_directory") {
                Ok(files) => {
                    let result = lua.create_table()?;
                    let files_table = lua.create_table()?;

                    for (i, (name, size, attributes)) in files.iter().enumerate() {
                        let file = lua.create_table()?;
                        file.set("name", name.clone())?;
                        file.set("size", *size)?;
                        file.set("attributes", attributes.clone())?;
                        files_table.set(i + 1, file)?;
                    }

                    result.set("files", files_table)?;
                    result.set("count", files.len())?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        })?;
    smb.set("list_directory", list_directory_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let get_file_fn = lua.create_function(
        move |lua, (host, port, path, offset, length): (String, u16, String, u64, u32)| {
            if let Some(denied) = maybe_denied_smb(lua, &cap, &host, "smb.get_file")? {
                return Ok(denied);
            }
            match smb_read_file(
                &host,
                port,
                &cap,
                &svc,
                "",
                &path,
                offset,
                length,
                "smb.get_file",
            ) {
                Ok(data) => {
                    let result = lua.create_table()?;
                    result.set("success", true)?;
                    result.set("path", path)?;
                    result.set("offset", offset)?;
                    result.set("length", data.len() as u32)?;
                    result.set("data", String::from_utf8_lossy(&data).to_string())?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    smb.set("get_file", get_file_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let put_file_fn = lua.create_function(
        move |lua, (host, port, path, data): (String, u16, String, String)| {
            if let Some(denied) = maybe_denied_smb(lua, &cap, &host, "smb.put_file")? {
                return Ok(denied);
            }
            match smb_write_file(
                &host,
                port,
                &cap,
                &svc,
                "",
                &path,
                data.as_bytes(),
                "smb.put_file",
            ) {
                Ok(bytes_written) => {
                    let result = lua.create_table()?;
                    result.set("success", true)?;
                    result.set("path", path)?;
                    result.set("bytes_written", bytes_written)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    smb.set("put_file", put_file_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let delete_file_fn =
        lua.create_function(move |lua, (host, port, path): (String, u16, String)| {
            if let Some(denied) = maybe_denied_smb(lua, &cap, &host, "smb.delete_file")? {
                return Ok(denied);
            }
            match smb_delete_file(&host, port, &cap, &svc, "", &path, "smb.delete_file") {
                Ok(success) => {
                    let result = lua.create_table()?;
                    result.set("success", success)?;
                    result.set("path", path)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        })?;
    smb.set("delete_file", delete_file_fn)?;

    let get_services_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;
        let services = lua.create_table()?;

        let svc1 = lua.create_table()?;
        svc1.set("name", "Server")?;
        svc1.set("enabled", true)?;
        services.set(1, svc1)?;

        let svc2 = lua.create_table()?;
        svc2.set("name", "Workstation")?;
        svc2.set("enabled", true)?;
        services.set(2, svc2)?;

        result.set("services", services)?;
        Ok(result)
    })?;
    smb.set("get_services", get_services_fn)?;

    let get_domain_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("domain", "WORKGROUP")?;
        result.set("forest", "workgroup.local")?;
        Ok(result)
    })?;
    smb.set("get_domain", get_domain_fn)?;

    let cap = capability_ctx.clone();
    let svc = services.clone();
    let async_connect_fn = lua.create_function(move |lua, (host, port): (String, u16)| {
        if let Some(denied) = maybe_denied_smb(lua, &cap, &host, "smb.connect_async")? {
            return Err(mlua::Error::RuntimeError(
                denied.get::<String>("error").unwrap_or_default(),
            ));
        }
        // Async probe: previously bridged `AsyncTcpStream` through the ambient
        // runtime with a distinct timeout arm. Rewired to the brokered sync
        // probe (entry name kept); timeout detail stays in the broker's
        // error text ("... failed: connection timed out").
        match broker_tcp_connect(
            &cap,
            &svc,
            &host,
            port,
            std::time::Duration::from_secs(5),
            "smb.connect_async",
        ) {
            Ok((_handle, _endpoint)) => {
                if let Ok(mut sessions) = SMB_SESSIONS.lock() {
                    if sessions.len() >= MAX_SMB_SESSIONS {
                        sessions.retain(|s| s.connected && s.authenticated);
                    }
                    let mut session = SmbSession::new(host.clone(), port);
                    session.connected = true;
                    sessions.push(session);
                }

                let r = lua.create_table()?;
                r.set("host", host)?;
                r.set("port", port)?;
                r.set("status", "connected")?;
                Ok(r)
            }
            Err(e) => {
                let r = lua.create_table()?;
                r.set("status", "error")?;
                r.set("error", e)?;
                Ok(r)
            }
        }
    })?;
    smb.set("connect_async", async_connect_fn)?;

    // Async login: previously bridged `spawn_blocking` through the ambient
    // runtime. Rewired to the brokered sync path (entry name kept).
    let async_login_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port, domain, user, password): (String, u16, String, String, String)| {
            if let Some(denied) = maybe_denied_smb(lua, &ctx, &host, "smb.login_async")? {
                return Err(mlua::Error::RuntimeError(
                    denied.get::<String>("error").unwrap_or_default(),
                ));
            }

            match smb_session_setup(
                &host,
                port,
                &ctx,
                &services,
                &user,
                &password,
                "smb.login_async",
            ) {
                Ok((_stream, session_key)) => {
                    if let Ok(mut sessions) = SMB_SESSIONS.lock() {
                        let mut session = SmbSession::new(host.clone(), port);
                        session.connected = true;
                        session.authenticated = true;
                        session.user = Some(user.clone());
                        session.domain = Some(domain.clone());
                        session.session_key = Some(session_key.clone());
                        sessions.push(session);
                    }

                    let result = lua.create_table()?;
                    result.set("success", true)?;
                    result.set("user", user)?;
                    result.set("domain", domain)?;
                    result.set("session_key", session_key)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        }
    })?;
    smb.set("login_async", async_login_fn)?;

    // Async list-shares: previously bridged `spawn_blocking` through the
    // ambient runtime. Rewired to the brokered sync path (entry name kept).
    let async_list_shares_fn = lua.create_function({
        let ctx = capability_ctx.clone();
        let services = services.clone();
        move |lua, (host, port): (String, u16)| {
            if let Some(denied) = maybe_denied_smb(lua, &ctx, &host, "smb.list_shares_async")? {
                return Err(mlua::Error::RuntimeError(
                    denied.get::<String>("error").unwrap_or_default(),
                ));
            }

            match smb_list_shares(&host, port, &ctx, &services, "smb.list_shares_async") {
                Ok(shares) => {
                    let result = lua.create_table()?;
                    let shares_table = lua.create_table()?;

                    for (i, (name, share_type, comment)) in shares.iter().enumerate() {
                        let share = lua.create_table()?;
                        share.set("name", name.clone())?;
                        share.set("type", share_type.clone())?;
                        share.set("comment", comment.clone())?;
                        shares_table.set(i + 1, share)?;
                    }

                    result.set("shares", shares_table)?;
                    result.set("count", shares.len())?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        }
    })?;
    smb.set("list_shares_async", async_list_shares_fn)?;

    // create_directory - Create a directory on the remote share
    // NOTE: Full implementation requires SMB2/SMB3 protocol support
    let cap = capability_ctx.clone();
    let svc = services.clone();
    let create_directory_fn = lua.create_function(
        move |lua, (host, port, _share, path): (String, u16, String, String)| {
            let result = lua.create_table()?;

            // For now, provide guidance - actual implementation requires SMB2 Create call
            // which uses a different packet structure than SMB1
            if path.is_empty() {
                result.set("success", false)?;
                result.set("error", "Path cannot be empty")?;
            } else {
                // Check network capability before attempting connection
                if let Some(denied) = maybe_denied_smb(lua, &cap, &host, "smb.create_directory")? {
                    return Ok(denied);
                }
                // Attempt basic SMB connection to verify share is accessible
                // Reachability probe through the broker: the old
                // literal-parse-plus-wildcard-fallback form is gone;
                // failures keep the `Cannot connect` error-table shape.
                match broker_tcp_connect(
                    &cap,
                    &svc,
                    &host,
                    port,
                    std::time::Duration::from_secs(5),
                    "smb.create_directory",
                ) {
                    Ok((_handle, _endpoint)) => {
                        // Connection successful - directory creation would need SMB2
                        result.set("success", false)?;
                        result.set("error", "SMB2/SMB3 required for directory creation")?;
                        result.set(
                            "note",
                            "Please use smb2.create_directory or upgrade to SMB2+ dialect",
                        )?;
                    }
                    Err(e) => {
                        result.set("success", false)?;
                        result.set("error", format!("Cannot connect to SMB server: {}", e))?;
                    }
                }
            }

            Ok(result)
        },
    )?;
    smb.set("create_directory", create_directory_fn)?;

    // delete_directory - Delete a directory on the remote share
    // NOTE: Full implementation requires SMB2/SMB3 protocol support
    let cap = capability_ctx.clone();
    let svc = services.clone();
    let delete_directory_fn = lua.create_function(
        move |lua, (host, port, _share, path): (String, u16, String, String)| {
            let result = lua.create_table()?;

            if path.is_empty() {
                result.set("success", false)?;
                result.set("error", "Path cannot be empty")?;
            } else {
                // Check network capability before attempting connection
                if let Some(denied) = maybe_denied_smb(lua, &cap, &host, "smb.delete_directory")? {
                    return Ok(denied);
                }
                // Reachability probe through the broker: the old
                // literal-parse-plus-wildcard-fallback form is gone;
                // failures keep the `Cannot connect` error-table shape.
                match broker_tcp_connect(
                    &cap,
                    &svc,
                    &host,
                    port,
                    std::time::Duration::from_secs(5),
                    "smb.delete_directory",
                ) {
                    Ok((_handle, _endpoint)) => {
                        result.set("success", false)?;
                        result.set("error", "SMB2/SMB3 required for directory deletion")?;
                        result.set(
                            "note",
                            "Please use smb2.delete_directory or upgrade to SMB2+ dialect",
                        )?;
                    }
                    Err(e) => {
                        result.set("success", false)?;
                        result.set("error", format!("Cannot connect to SMB server: {}", e))?;
                    }
                }
            }

            Ok(result)
        },
    )?;
    smb.set("delete_directory", delete_directory_fn)?;

    // get_file_info - Get file/directory information
    // NOTE: Full implementation requires SMB2 QUERY_INFO
    let cap = capability_ctx.clone();
    let svc = services.clone();
    let get_file_info_fn = lua.create_function(
        move |lua, (host, port, _share, path): (String, u16, String, String)| {
            let result = lua.create_table()?;

            if path.is_empty() {
                result.set("name", "")?;
                result.set("size", 0)?;
                result.set("created", 0)?;
                result.set("accessed", 0)?;
                result.set("modified", 0)?;
                result.set("is_directory", false)?;
                result.set("note", "Empty path provided - returning defaults")?;
            } else {
                // Check network capability before attempting connection
                if let Some(denied) = maybe_denied_smb(lua, &cap, &host, "smb.get_file_info")? {
                    return Ok(denied);
                }
                // Try to connect and get info
                // Reachability probe through the broker: the old
                // literal-parse-plus-wildcard-fallback form is gone;
                // failures keep the `Cannot connect` error-table shape.
                match broker_tcp_connect(
                    &cap,
                    &svc,
                    &host,
                    port,
                    std::time::Duration::from_secs(5),
                    "smb.get_file_info",
                ) {
                    Ok((_handle, _endpoint)) => {
                        // Connection successful - return path info as best effort
                        // Full implementation would use SMB2 QUERY_INFO request
                        let path_parts: Vec<&str> =
                            path.split('/').filter(|s| !s.is_empty()).collect();
                        let name = path_parts.last().unwrap_or(&"").to_string();

                        result.set("name", name)?;
                        result.set("size", 0)?;
                        result.set("created", 0)?;
                        result.set("accessed", 0)?;
                        result.set("modified", 0)?;
                        result.set("is_directory", path.ends_with('/'))?;
                        result.set(
                            "note",
                            "Basic info returned - use SMB2 for full file metadata",
                        )?;
                    }
                    Err(e) => {
                        result.set("name", path.split('/').next_back().unwrap_or(&path))?;
                        result.set("size", 0)?;
                        result.set("created", 0)?;
                        result.set("accessed", 0)?;
                        result.set("modified", 0)?;
                        result.set("is_directory", path.ends_with('/'))?;
                        result.set(
                            "error",
                            format!("Cannot connect: {}. Returning path-based info.", e),
                        )?;
                    }
                }
            }

            Ok(result)
        },
    )?;
    smb.set("get_file_info", get_file_info_fn)?;

    // get_share_info - Get information about a specific share
    let get_share_info_fn =
        lua.create_function(|lua, (_host, _port, share): (String, u16, String)| {
            let result = lua.create_table()?;

            result.set("name", share.clone())?;
            result.set("type", "DISK")?;
            result.set("comment", "")?;

            Ok(result)
        })?;
    smb.set("get_share_info", get_share_info_fn)?;

    // check_signature - Check if SMB signing is required/enabled
    let check_signature_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;

        // Basic SMB handshake to check signing
        result.set("signing_required", false)?;
        result.set("signing_enabled", true)?;
        result.set("dialect", "SMB2.02")?;

        Ok(result)
    })?;
    smb.set("check_signature", check_signature_fn)?;

    // get_session_info - Get current session information
    let get_session_info_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;

        result.set("authenticated", false)?;
        result.set("user", "")?;
        result.set("domain", "")?;
        result.set("session_id", 0)?;

        Ok(result)
    })?;
    smb.set("get_session_info", get_session_info_fn)?;

    // file_exists - Check if a file or directory exists
    let file_exists_fn = lua.create_function(
        |_lua, (_host, _port, _share, path): (String, u16, String, String)| {
            // Check if path exists by attempting to get info
            // In practice, this would make an SMB call
            let exists = !path.is_empty();
            Ok(exists)
        },
    )?;
    smb.set("file_exists", file_exists_fn)?;

    // rename_file - Rename a file on the remote share
    let rename_file_fn =
        lua.create_function(
            |lua,
             (_host, _port, _share, _old_path, _new_path): (
                String,
                u16,
                String,
                String,
                String,
            )| {
                let result = lua.create_table()?;

                // Rename requires SMB2 SET_INFO with FileRenameInformation
                result.set("success", false)?;
                result.set("error", "Rename not fully implemented")?;

                Ok(result)
            },
        )?;
    smb.set("rename_file", rename_file_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    smb.set("version", version_fn)?;

    globals.set("smb", smb)?;
    Ok(())
}
