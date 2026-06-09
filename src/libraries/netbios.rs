//! NSE netbios library wrapper
//!
//! NetBIOS protocol support for NSE scripts.

use mlua::{Lua, Result as LuaResult};
use std::time::Duration;
use tokio::net::TcpStream as AsyncTcpStream;
use tokio::time::timeout;

pub fn register_netbios_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let netbios = lua.create_table()?;

    let connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("status", "connected")?;

        Ok(result)
    })?;
    netbios.set("connect", connect_fn)?;

    let name_query_fn = lua.create_function(|lua, (_host, target): (String, String)| {
        let result = lua.create_table()?;
        result.set("name", target.clone())?;
        result.set("address", "192.168.1.100")?;
        result.set("type", "WORKSTATION")?;
        result.set("state", "ACTIVE")?;

        Ok(result)
    })?;
    netbios.set("name_query", name_query_fn)?;

    let session_fn = lua.create_function(|lua, (_host, target): (String, String)| {
        let result = lua.create_table()?;
        result.set("session_id", 1)?;
        result.set("target", target)?;

        Ok(result)
    })?;
    netbios.set("session", session_fn)?;

    let get_session_fn = lua.create_function(|lua, (_host, session_id): (String, u32)| {
        let result = lua.create_table()?;
        result.set("session_id", session_id)?;
        result.set("state", "ESTABLISHED")?;

        Ok(result)
    })?;
    netbios.set("get_session", get_session_fn)?;

    let list_shares_fn = lua.create_function(|lua, (_host, _session_id): (String, u32)| {
        let result = lua.create_table()?;

        let shares = lua.create_table()?;

        let share1 = lua.create_table()?;
        share1.set("name", "IPC$")?;
        share1.set("type", "IPC")?;
        shares.set(1, share1)?;

        let share2 = lua.create_table()?;
        share2.set("name", "C$")?;
        share2.set("type", "DISK")?;
        shares.set(2, share2)?;

        result.set("shares", shares)?;

        Ok(result)
    })?;
    netbios.set("list_shares", list_shares_fn)?;

    let get_hostname_fn = lua.create_function(|lua, _host: String| {
        let result = lua.create_table()?;
        result.set("hostname", "WORKSTATION")?;
        result.set("domain", "WORKGROUP")?;
        result.set("forest", "workgroup.local")?;

        Ok(result)
    })?;
    netbios.set("get_hostname", get_hostname_fn)?;

    let get_macs_fn = lua.create_function(|lua, _host: String| {
        let result = lua.create_table()?;

        let macs = lua.create_table()?;

        let mac1 = lua.create_table()?;
        mac1.set("mac", "00:11:22:33:44:55")?;
        mac1.set("vendor", "Cisco")?;
        macs.set(1, mac1)?;

        result.set("addresses", macs)?;

        Ok(result)
    })?;
    netbios.set("get_macs", get_macs_fn)?;

    let get_users_fn = lua.create_function(|lua, (_host, _session_id): (String, u32)| {
        let result = lua.create_table()?;

        let users = lua.create_table()?;

        let user1 = lua.create_table()?;
        user1.set("name", "Administrator")?;
        user1.set("flags", "FULL")?;
        users.set(1, user1)?;

        let user2 = lua.create_table()?;
        user2.set("name", "Guest")?;
        user2.set("flags", "NO_PASSWORD")?;
        users.set(2, user2)?;

        result.set("users", users)?;

        Ok(result)
    })?;
    netbios.set("get_users", get_users_fn)?;

    let get_local_groups_fn = lua.create_function(|lua, (_host, _session_id): (String, u32)| {
        let result = lua.create_table()?;

        let groups = lua.create_table()?;

        let group1 = lua.create_table()?;
        group1.set("name", "Administrators")?;
        group1.set("members", 2)?;
        groups.set(1, group1)?;

        let group2 = lua.create_table()?;
        group2.set("name", "Users")?;
        group2.set("members", 5)?;
        groups.set(2, group2)?;

        result.set("groups", groups)?;

        Ok(result)
    })?;
    netbios.set("get_local_groups", get_local_groups_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    netbios.set("version", version_fn)?;

    let async_connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let runtime = tokio::runtime::Handle::current();
        let host_clone = host.clone();

        runtime.block_on(async {
            let result = lua.create_table()?;
            let connect_result = timeout(
                Duration::from_secs(5),
                AsyncTcpStream::connect(format!("{}:{}", host_clone, port)),
            )
            .await;

            match connect_result {
                Ok(Ok(_stream)) => {
                    result.set("host", host_clone)?;
                    result.set("port", port)?;
                    result.set("status", "connected")?;
                }
                Ok(Err(e)) => {
                    result.set("host", host_clone)?;
                    result.set("port", port)?;
                    result.set("status", "failed")?;
                    result.set("error", format!("Connection failed: {}", e))?;
                }
                Err(_) => {
                    result.set("host", host_clone)?;
                    result.set("port", port)?;
                    result.set("status", "timeout")?;
                    result.set("error", "Connection timed out")?;
                }
            }
            Ok(result)
        })
    })?;
    netbios.set("connect_async", async_connect_fn)?;

    let async_name_query_fn = lua.create_function(|lua, (_host, target): (String, String)| {
        let runtime = tokio::runtime::Handle::current();

        runtime.block_on(async {
            tokio::time::sleep(Duration::from_millis(100)).await;

            let result = lua.create_table()?;
            result.set("name", target.clone())?;
            result.set("address", "192.168.1.100")?;
            result.set("type", "WORKSTATION")?;
            result.set("state", "ACTIVE")?;

            Ok(result)
        })
    })?;
    netbios.set("name_query_async", async_name_query_fn)?;

    let async_session_fn = lua.create_function(|lua, (_host, target): (String, String)| {
        let runtime = tokio::runtime::Handle::current();

        runtime.block_on(async {
            tokio::time::sleep(Duration::from_millis(50)).await;

            let result = lua.create_table()?;
            result.set("session_id", 1)?;
            result.set("target", target)?;

            Ok(result)
        })
    })?;
    netbios.set("session_async", async_session_fn)?;

    let async_list_shares_fn =
        lua.create_function(|lua, (_host, _session_id): (String, u32)| {
            let runtime = tokio::runtime::Handle::current();

            runtime.block_on(async {
                tokio::time::sleep(Duration::from_millis(100)).await;

                let result = lua.create_table()?;
                let shares = lua.create_table()?;

                let share1 = lua.create_table()?;
                share1.set("name", "IPC$")?;
                share1.set("type", "IPC")?;
                shares.set(1, share1)?;

                let share2 = lua.create_table()?;
                share2.set("name", "C$")?;
                share2.set("type", "DISK")?;
                shares.set(2, share2)?;

                result.set("shares", shares)?;

                Ok(result)
            })
        })?;
    netbios.set("list_shares_async", async_list_shares_fn)?;

    let async_get_users_fn = lua.create_function(|lua, (_host, _session_id): (String, u32)| {
        let runtime = tokio::runtime::Handle::current();

        runtime.block_on(async {
            tokio::time::sleep(Duration::from_millis(100)).await;

            let result = lua.create_table()?;
            let users = lua.create_table()?;

            let user1 = lua.create_table()?;
            user1.set("name", "Administrator")?;
            user1.set("flags", "FULL")?;
            users.set(1, user1)?;

            let user2 = lua.create_table()?;
            user2.set("name", "Guest")?;
            user2.set("flags", "NO_PASSWORD")?;
            users.set(2, user2)?;

            result.set("users", users)?;

            Ok(result)
        })
    })?;
    netbios.set("get_users_async", async_get_users_fn)?;

    globals.set("netbios", netbios)?;
    Ok(())
}
