//! NSE rpc library wrapper
//!
//! Provides RPC protocol parsing and manipulation for NSE scripts.
//! Based on Nmap's rpc library: https://nmap.org/nsedoc/lib/rpc.html

use mlua::{Lua, Result as LuaResult};
use rustc_hash::FxHashMap;
use std::sync::OnceLock;

static RPC_PROGRAMS: OnceLock<FxHashMap<u32, FxHashMap<u32, &'static str>>> = OnceLock::new();

fn get_rpc_programs() -> &'static FxHashMap<u32, FxHashMap<u32, &'static str>> {
    RPC_PROGRAMS.get_or_init(|| {
        let mut m = FxHashMap::default();

        // portmapper
        let mut portmapper = FxHashMap::default();
        portmapper.insert(0, "null");
        portmapper.insert(1, "set");
        portmapper.insert(2, "unset");
        portmapper.insert(3, "getportlist");
        portmapper.insert(4, "dump");
        portmapper.insert(5, "callit");
        portmapper.insert(6, "svcsock");
        portmapper.insert(7, "svclist");
        portmapper.insert(8, "stat");
        m.insert(100000u32, portmapper);

        // rstatd
        let mut rstatd = FxHashMap::default();
        rstatd.insert(0, "null");
        rstatd.insert(1, "stats");
        rstatd.insert(2, "havestats");
        m.insert(100001u32, rstatd);

        // rusersd
        let mut rusersd = FxHashMap::default();
        rusersd.insert(0, "null");
        rusersd.insert(1, "rusers");
        m.insert(100002u32, rusersd);

        // nfs
        let mut nfs = FxHashMap::default();
        nfs.insert(0, "null");
        nfs.insert(1, "getattr");
        nfs.insert(2, "setattr");
        nfs.insert(3, "root");
        nfs.insert(4, "lookup");
        nfs.insert(5, "readlink");
        nfs.insert(6, "read");
        nfs.insert(7, "writecache");
        nfs.insert(8, "write");
        nfs.insert(9, "create");
        nfs.insert(10, "remove");
        nfs.insert(11, "rename");
        nfs.insert(12, "link");
        nfs.insert(13, "symlink");
        nfs.insert(14, "mkdir");
        nfs.insert(15, "rmdir");
        nfs.insert(16, "readdir");
        nfs.insert(17, "fsstat");
        m.insert(100003u32, nfs);

        // ypserv
        let mut ypserv = FxHashMap::default();
        ypserv.insert(0, "null");
        ypserv.insert(1, "ypprog");
        m.insert(100004u32, ypserv);

        // mountd
        let mut mountd = FxHashMap::default();
        mountd.insert(0, "null");
        mountd.insert(1, "mount");
        mountd.insert(2, "dump");
        mountd.insert(3, "umnt");
        mountd.insert(4, "umntall");
        mountd.insert(5, "export");
        m.insert(100005u32, mountd);

        // nfs_acl
        let mut nfs_acl = FxHashMap::default();
        nfs_acl.insert(0, "null");
        nfs_acl.insert(1, "getacl");
        nfs_acl.insert(2, "setacl");
        m.insert(100006u32, nfs_acl);

        // ypbind
        let mut ypbind = FxHashMap::default();
        ypbind.insert(0, "null");
        ypbind.insert(1, "ybinder");
        m.insert(100007u32, ypbind);

        // wall
        let mut wall = FxHashMap::default();
        wall.insert(0, "null");
        wall.insert(1, "wall");
        m.insert(100008u32, wall);

        // yppasswd
        let mut yppasswd = FxHashMap::default();
        yppasswd.insert(0, "null");
        yppasswd.insert(1, "yppasswd");
        m.insert(100009u32, yppasswd);

        // etherstatd
        let mut etherstatd = FxHashMap::default();
        etherstatd.insert(0, "null");
        etherstatd.insert(1, "etherstat");
        m.insert(100010u32, etherstatd);

        // rquotad
        let mut rquotad = FxHashMap::default();
        rquotad.insert(0, "null");
        rquotad.insert(1, "rquotaproc");
        m.insert(100011u32, rquotad);

        // sprayd
        let mut sprayd = FxHashMap::default();
        sprayd.insert(0, "null");
        sprayd.insert(1, "spray");
        m.insert(100012u32, sprayd);

        // nfsd
        let mut nfsd = FxHashMap::default();
        nfsd.insert(0, "null");
        nfsd.insert(1, "nfsd");
        nfsd.insert(2, "nfsd2");
        nfsd.insert(3, "nfsd3");
        nfsd.insert(4, "nfsd4");
        nfsd.insert(5, "nfsd_acl");
        nfsd.insert(6, "nfsd4_cb");
        m.insert(100003u32, nfsd);

        // status
        let mut status = FxHashMap::default();
        status.insert(0, "null");
        status.insert(1, "status_get");
        m.insert(100020u32, status);

        // cmsd
        let mut cmsd = FxHashMap::default();
        cmsd.insert(0, "null");
        cmsd.insert(1, "cms");
        m.insert(100022u32, cmsd);

        // ttdbserverd
        let mut ttdbserverd = FxHashMap::default();
        ttdbserverd.insert(0, "null");
        ttdbserverd.insert(1, "ttdb");
        m.insert(100023u32, ttdbserverd);

        // nlockmgr
        let mut nlockmgr = FxHashMap::default();
        nlockmgr.insert(0, "null");
        nlockmgr.insert(1, "nlockmgr");
        m.insert(100021u32, nlockmgr);

        // common services
        let mut nis = FxHashMap::default();
        nis.insert(0, "null");
        m.insert(100004u32, nis);

        // ypupdated
        let mut ypupdated = FxHashMap::default();
        ypupdated.insert(0, "null");
        ypupdated.insert(1, "update");
        m.insert(100028u32, ypupdated);

        // ypxfrd
        let mut ypxfrd = FxHashMap::default();
        ypxfrd.insert(0, "null");
        ypxfrd.insert(1, "ypxfrd");
        m.insert(100069u32, ypxfrd);

        // kadmin
        let mut kadmin = FxHashMap::default();
        kadmin.insert(0, "null");
        kadmin.insert(1, "kadmin");
        m.insert(100007u32, kadmin);

        // rexd
        let mut rexd = FxHashMap::default();
        rexd.insert(0, "null");
        rexd.insert(1, "rexd");
        m.insert(100017u32, rexd);

        // amd
        let mut amd = FxHashMap::default();
        amd.insert(0, "null");
        amd.insert(1, "amd");
        m.insert(300019u32, amd);

        // qmaster
        let mut qmaster = FxHashMap::default();
        qmaster.insert(0, "null");
        qmaster.insert(1, "qmaster");
        m.insert(100020u32, qmaster);

        // metad
        let mut metad = FxHashMap::default();
        metad.insert(0, "null");
        metad.insert(1, "meta");
        m.insert(100083u32, metad);

        // dmispd
        let mut dmispd = FxHashMap::default();
        dmispd.insert(0, "null");
        dmispd.insert(1, "dmisp");
        m.insert(100021u32, dmispd);

        // listed
        let mut listed = FxHashMap::default();
        listed.insert(0, "null");
        listed.insert(1, "listed");
        m.insert(100028u32, listed);

        // rquota
        let mut rquota = FxHashMap::default();
        rquota.insert(0, "null");
        rquota.insert(1, "rquota");
        m.insert(100011u32, rquota);

        m
    })
}

fn get_program_name(program: u32) -> String {
    match program {
        100000 => "portmapper".to_string(),
        100001 => "rstatd".to_string(),
        100002 => "rusersd".to_string(),
        100003 => "nfs".to_string(),
        100004 => "ypserv".to_string(),
        100005 => "mountd".to_string(),
        100006 => "nfs_acl".to_string(),
        100007 => "ypbind".to_string(),
        100008 => "wall".to_string(),
        100009 => "yppasswd".to_string(),
        100010 => "etherstatd".to_string(),
        100011 => "rquotad".to_string(),
        100012 => "sprayd".to_string(),
        100017 => "rexd".to_string(),
        100020 => "status".to_string(),
        100021 => "nlockmgr".to_string(),
        100022 => "cmsd".to_string(),
        100023 => "ttdbserverd".to_string(),
        100024 => "nfsd".to_string(),
        100028 => "ypupdated".to_string(),
        100069 => "ypxfrd".to_string(),
        100242 => "metad".to_string(),
        100083 => "dmispd".to_string(),
        100230 => "sadmind".to_string(),
        100232 => "solstice".to_string(),
        100233 => "nfs_acl".to_string(),
        100234 => "nfsd".to_string(),
        100235 => "nfsd".to_string(),
        100426 => "knetd".to_string(),
        100421 => "ypserv".to_string(),
        300019 => "amd".to_string(),
        300020 => "qmaster".to_string(),
        300083 => "dmisp".to_string(),
        _ => format!("unknown({})", program),
    }
}

pub fn register_rpc_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let rpc = lua.create_table()?;

    rpc.set(
        "TCPPacket",
        lua.create_function(
            |lua, (xid, program, version, procedure, data): (u32, u32, u32, u32, String)| {
                let packet = lua.create_table()?;

                let program_name = get_program_name(program);
                let programs = get_rpc_programs();

                let proc_name = programs
                    .get(&program)
                    .and_then(|p| p.get(&procedure))
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("unknown({})", procedure));

                packet.set("xid", xid)?;
                packet.set("program", program)?;
                packet.set("program_name", program_name)?;
                packet.set("version", version)?;
                packet.set("procedure", procedure)?;
                packet.set("procedure_name", proc_name)?;
                packet.set("data", data)?;

                Ok(packet)
            },
        )?,
    )?;

    rpc.set(
        "UDPPacket",
        lua.create_function(
            |lua, (xid, program, version, procedure, data): (u32, u32, u32, u32, String)| {
                let packet = lua.create_table()?;

                let program_name = get_program_name(program);
                let programs = get_rpc_programs();

                let proc_name = programs
                    .get(&program)
                    .and_then(|p| p.get(&procedure))
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("unknown({})", procedure));

                packet.set("xid", xid)?;
                packet.set("program", program)?;
                packet.set("program_name", program_name)?;
                packet.set("version", version)?;
                packet.set("procedure", procedure)?;
                packet.set("procedure_name", proc_name)?;
                packet.set("data", data)?;

                Ok(packet)
            },
        )?,
    )?;

    rpc.set(
        "parse",
        lua.create_function(|lua, data: String| {
            let result = lua.create_table()?;

            // Simple XDR parsing (not complete, just basic)
            let bytes = data.as_bytes();
            if bytes.len() < 24 {
                result.set("error", "packet too short")?;
                return Ok(result);
            }

            // Transaction ID
            let xid = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            result.set("xid", xid)?;

            // Message type (0 = call, 1 = reply)
            let msg_type = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            result.set("msg_type", msg_type)?;

            if msg_type == 0 {
                // RPC call
                let rpc_version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
                result.set("rpc_version", rpc_version)?;

                let program = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
                result.set("program", program)?;
                result.set("program_name", get_program_name(program))?;

                let prog_version = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
                result.set("version", prog_version)?;

                let procedure = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
                result.set("procedure", procedure)?;
            }

            Ok(result)
        })?,
    )?;

    rpc.set(
        "gen_program",
        lua.create_function(|_lua, program: u32| Ok(get_program_name(program)))?,
    )?;

    rpc.set(
        "gen_procedure",
        lua.create_function(|_lua, (program, procedure): (u32, u32)| {
            let programs = get_rpc_programs();
            let proc_name = programs
                .get(&program)
                .and_then(|p| p.get(&procedure))
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("unknown({})", procedure));
            Ok(proc_name)
        })?,
    )?;

    rpc.set(
        "get_programs",
        lua.create_function(|lua, _: ()| {
            let result = lua.create_table()?;

            let programs = get_rpc_programs();
            let mut i = 1;
            for prog in programs.keys() {
                let entry = lua.create_table()?;
                entry.set("program", *prog)?;
                entry.set("name", get_program_name(*prog))?;
                result.set(i, entry)?;
                i += 1;
            }

            Ok(result)
        })?,
    )?;

    rpc.set(
        "get_procedures",
        lua.create_function(|lua, program: u32| {
            let result = lua.create_table()?;

            let programs = get_rpc_programs();
            if let Some(procs) = programs.get(&program) {
                let mut i = 1;
                for (proc, name) in procs {
                    let entry = lua.create_table()?;
                    entry.set("procedure", *proc)?;
                    entry.set("name", *name)?;
                    result.set(i, entry)?;
                    i += 1;
                }
            }

            Ok(result)
        })?,
    )?;

    rpc.set(
        "make_call",
        lua.create_function(
            |lua, (program, version, procedure, data): (u32, u32, u32, String)| {
                let mut call = vec![0u8; 24 + data.len()];

                // XID (random)
                let xid = rand::random::<u32>();
                call[0..4].copy_from_slice(&xid.to_be_bytes());

                // Message type: call
                call[4..8].copy_from_slice(&0u32.to_be_bytes());

                // RPC version
                call[8..12].copy_from_slice(&2u32.to_be_bytes());

                // Program
                call[12..16].copy_from_slice(&program.to_be_bytes());

                // Program version
                call[16..20].copy_from_slice(&version.to_be_bytes());

                // Procedure
                call[20..24].copy_from_slice(&procedure.to_be_bytes());

                // Credentials (auth_null)
                call[24..28].copy_from_slice(&0u32.to_be_bytes());

                if !data.is_empty() {
                    call[28..].copy_from_slice(data.as_bytes());
                }

                let result = lua.create_table()?;
                result.set("xid", xid)?;
                result.set("call", String::from_utf8_lossy(&call).to_string())?;

                Ok(result)
            },
        )?,
    )?;

    rpc.set(
        "make_reply",
        lua.create_function(
            |lua, (xid, verf_type, status, data): (u32, u32, u32, String)| {
                let mut reply = vec![0u8; 24 + data.len()];

                // XID (echo)
                reply[0..4].copy_from_slice(&xid.to_be_bytes());

                // Message type: reply
                reply[4..8].copy_from_slice(&1u32.to_be_bytes());

                // Reply status
                reply[8..12].copy_from_slice(&0u32.to_be_bytes());

                // Verifier flavor
                reply[12..16].copy_from_slice(&verf_type.to_be_bytes());

                // Verifier length
                reply[16..20].copy_from_slice(&0u32.to_be_bytes());

                // Accept status
                reply[20..24].copy_from_slice(&status.to_be_bytes());

                if !data.is_empty() {
                    reply[24..].copy_from_slice(data.as_bytes());
                }

                let result = lua.create_table()?;
                result.set("reply", String::from_utf8_lossy(&reply).to_string())?;

                Ok(result)
            },
        )?,
    )?;

    rpc.set(
        "grant_port",
        lua.create_function(|_lua, (program, version): (u32, u32)| {
            // Return a pseudo-random port for the given program
            let port = ((program * 1000 + version) % 60000) + 1024;
            Ok(port)
        })?,
    )?;

    rpc.set("MOUNT1", lua.create_function(|_lua, _: ()| Ok(1))?)?;

    rpc.set("MOUNT3", lua.create_function(|_lua, _: ()| Ok(3))?)?;

    rpc.set("version", lua.create_function(|_lua, _: ()| Ok("1.0.0"))?)?;

    globals.set("rpc", rpc)?;
    Ok(())
}
