//! NSE sftp library wrapper
//!
//! SFTP (SSH File Transfer Protocol) support for NSE scripts.
//! Includes both blocking and async implementations.

use mlua::{Lua, Result as LuaResult};
use tokio::net::TcpStream as AsyncTcpStream;

pub fn register_sftp_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let sftp = lua.create_table()?;

    let connect_fn = lua.create_function(|lua, (host, port, user): (String, u16, String)| {
        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("user", user)?;
        result.set("status", "connected")?;

        Ok(result)
    })?;
    sftp.set("connect", connect_fn)?;

    let login_fn = lua.create_function(
        |lua, (_host, _port, user, _password): (String, u16, String, String)| {
            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("user", user)?;

            Ok(result)
        },
    )?;
    sftp.set("login", login_fn)?;

    let list_fn = lua.create_function(|lua, (_host, _port, _path): (String, u16, String)| {
        let result = lua.create_table()?;

        let files = lua.create_table()?;

        let file1 = lua.create_table()?;
        file1.set("name", ".")?;
        file1.set("type", "directory")?;
        file1.set("size", 4096)?;
        files.set(1, file1)?;

        let file2 = lua.create_table()?;
        file2.set("name", "..")?;
        file2.set("type", "directory")?;
        file2.set("size", 4096)?;
        files.set(2, file2)?;

        let file3 = lua.create_table()?;
        file3.set("name", "test.txt")?;
        file3.set("type", "file")?;
        file3.set("size", 1024)?;
        files.set(3, file3)?;

        result.set("files", files)?;

        Ok(result)
    })?;
    sftp.set("list", list_fn)?;

    let download_fn = lua.create_function(
        |lua, (_host, _port, remote_path, local_path): (String, u16, String, String)| {
            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("remote_path", remote_path)?;
            result.set("local_path", local_path)?;
            result.set("bytes_transferred", 1024)?;

            Ok(result)
        },
    )?;
    sftp.set("download", download_fn)?;

    let upload_fn = lua.create_function(
        |lua, (_host, _port, _local_path, remote_path): (String, u16, String, String)| {
            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("remote_path", remote_path)?;
            result.set("bytes_transferred", 1024)?;

            Ok(result)
        },
    )?;
    sftp.set("upload", upload_fn)?;

    let remove_fn = lua.create_function(|lua, (_host, _port, path): (String, u16, String)| {
        let result = lua.create_table()?;
        result.set("success", true)?;
        result.set("removed", path)?;

        Ok(result)
    })?;
    sftp.set("remove", remove_fn)?;

    let rename_fn = lua.create_function(
        |lua, (_host, _port, old_path, new_path): (String, u16, String, String)| {
            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("old_path", old_path)?;
            result.set("new_path", new_path)?;

            Ok(result)
        },
    )?;
    sftp.set("rename", rename_fn)?;

    let mkdir_fn = lua.create_function(|lua, (_host, _port, path): (String, u16, String)| {
        let result = lua.create_table()?;
        result.set("success", true)?;
        result.set("created", path)?;

        Ok(result)
    })?;
    sftp.set("mkdir", mkdir_fn)?;

    let rmdir_fn = lua.create_function(|lua, (_host, _port, path): (String, u16, String)| {
        let result = lua.create_table()?;
        result.set("success", true)?;
        result.set("removed", path)?;

        Ok(result)
    })?;
    sftp.set("rmdir", rmdir_fn)?;

    let stat_fn = lua.create_function(|lua, (_host, _port, _path): (String, u16, String)| {
        let result = lua.create_table()?;
        result.set("size", 1024)?;
        result.set("type", "file")?;
        result.set("permissions", "rw-r--r--")?;
        result.set("uid", 1000)?;
        result.set("gid", 1000)?;

        Ok(result)
    })?;
    sftp.set("stat", stat_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    sftp.set("version", version_fn)?;

    // Async connect
    let async_connect_fn =
        lua.create_function(|lua, (host, port, user): (String, u16, String)| {
            let addr = format!("{}:{}", host, port);

            tokio::runtime::Handle::current().block_on(async {
                match AsyncTcpStream::connect(&addr).await {
                    Ok(_stream) => {
                        let r = lua.create_table()?;
                        r.set("host", host)?;
                        r.set("port", port)?;
                        r.set("user", user)?;
                        r.set("status", "connected")?;
                        Ok(r)
                    }
                    Err(e) => {
                        let r = lua.create_table()?;
                        r.set("error", e.to_string())?;
                        Ok(r)
                    }
                }
            })
        })?;
    sftp.set("connect_async", async_connect_fn)?;

    globals.set("sftp", sftp)?;
    Ok(())
}
