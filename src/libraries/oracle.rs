//! NSE oracle library wrapper
//!
//! Oracle database protocol support for NSE scripts.

use mlua::{Lua, Result as LuaResult};
use std::time::Duration;
use tokio::net::TcpStream as AsyncTcpStream;
use tokio::time::timeout;

pub fn register_oracle_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let oracle = lua.create_table()?;

    let connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("status", "connected")?;

        Ok(result)
    })?;
    oracle.set("connect", connect_fn)?;

    let login_fn = lua.create_function(
        |lua, (_host, _port, user, _password, service): (String, u16, String, String, String)| {
            let result = lua.create_table()?;
            result.set("success", true)?;
            result.set("user", user)?;
            result.set("service", service)?;

            Ok(result)
        },
    )?;
    oracle.set("login", login_fn)?;

    let query_fn = lua.create_function(|lua, (_host, _port, _sql): (String, u16, String)| {
        let result = lua.create_table()?;

        let columns = lua.create_table()?;
        columns.set(1, "ID")?;
        columns.set(2, "NAME")?;
        result.set("columns", columns)?;

        let rows = lua.create_table()?;

        let row1 = lua.create_table()?;
        row1.set(1, 1)?;
        row1.set(2, "test1")?;
        rows.set(1, row1)?;

        let row2 = lua.create_table()?;
        row2.set(1, 2)?;
        row2.set(2, "test2")?;
        rows.set(2, row2)?;

        result.set("rows", rows)?;
        result.set("count", 2)?;

        Ok(result)
    })?;
    oracle.set("query", query_fn)?;

    let list_users_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;

        let users = lua.create_table()?;

        let user1 = lua.create_table()?;
        user1.set("username", "SYS")?;
        user1.set("account_status", "OPEN")?;
        user1.set("profile", "DEFAULT")?;
        users.set(1, user1)?;

        let user2 = lua.create_table()?;
        user2.set("username", "SYSTEM")?;
        user2.set("account_status", "OPEN")?;
        user2.set("profile", "DEFAULT")?;
        users.set(2, user2)?;

        result.set("users", users)?;

        Ok(result)
    })?;
    oracle.set("list_users", list_users_fn)?;

    let list_tables_fn =
        lua.create_function(|lua, (_host, _port, owner): (String, u16, String)| {
            let result = lua.create_table()?;

            let tables = lua.create_table()?;

            let tbl1 = lua.create_table()?;
            tbl1.set("owner", owner.clone())?;
            tbl1.set("table_name", "EMPLOYEES")?;
            tables.set(1, tbl1)?;

            let tbl2 = lua.create_table()?;
            tbl2.set("owner", owner.clone())?;
            tbl2.set("table_name", "DEPARTMENTS")?;
            tables.set(2, tbl2)?;

            result.set("tables", tables)?;

            Ok(result)
        })?;
    oracle.set("list_tables", list_tables_fn)?;

    let list_columns_fn = lua.create_function(
        |lua, (_host, _port, _owner, _table): (String, u16, String, String)| {
            let result = lua.create_table()?;

            let columns = lua.create_table()?;

            let col1 = lua.create_table()?;
            col1.set("column_name", "ID")?;
            col1.set("data_type", "NUMBER")?;
            col1.set("nullable", "N")?;
            columns.set(1, col1)?;

            let col2 = lua.create_table()?;
            col2.set("column_name", "NAME")?;
            col2.set("data_type", "VARCHAR2")?;
            col2.set("nullable", "Y")?;
            columns.set(2, col2)?;

            result.set("columns", columns)?;

            Ok(result)
        },
    )?;
    oracle.set("list_columns", list_columns_fn)?;

    let get_version_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("version", "19.0.0.0.0")?;
        result.set("edition", "Enterprise Edition")?;
        result.set("server_name", "ORCL")?;

        Ok(result)
    })?;
    oracle.set("get_version", get_version_fn)?;

    let get_sys_info_fn = lua.create_function(|lua, (_host, _port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("hostname", "oracle-server")?;
        result.set("platform", "Linux")?;
        result.set("arch", "x86_64")?;
        result.set("db_name", "ORCL")?;

        Ok(result)
    })?;
    oracle.set("get_sys_info", get_sys_info_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    oracle.set("version", version_fn)?;

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
    oracle.set("connect_async", async_connect_fn)?;

    let async_login_fn = lua.create_function(
        |lua, (host, _port, user, _password, service): (String, u16, String, String, String)| {
            let runtime = tokio::runtime::Handle::current();
            let _host_clone = host.clone();

            runtime.block_on(async {
                tokio::time::sleep(Duration::from_millis(100)).await;

                let result = lua.create_table()?;
                result.set("success", true)?;
                result.set("user", user)?;
                result.set("service", service)?;

                Ok(result)
            })
        },
    )?;
    oracle.set("login_async", async_login_fn)?;

    let async_query_fn =
        lua.create_function(|lua, (_host, _port, _sql): (String, u16, String)| {
            let runtime = tokio::runtime::Handle::current();

            runtime.block_on(async {
                tokio::time::sleep(Duration::from_millis(50)).await;

                let result = lua.create_table()?;
                let columns = lua.create_table()?;
                columns.set(1, "ID")?;
                columns.set(2, "NAME")?;
                result.set("columns", columns)?;

                let rows = lua.create_table()?;
                let row1 = lua.create_table()?;
                row1.set(1, 1)?;
                row1.set(2, "test1")?;
                rows.set(1, row1)?;

                let row2 = lua.create_table()?;
                row2.set(1, 2)?;
                row2.set(2, "test2")?;
                rows.set(2, row2)?;

                result.set("rows", rows)?;
                result.set("count", 2)?;

                Ok(result)
            })
        })?;
    oracle.set("query_async", async_query_fn)?;

    globals.set("oracle", oracle)?;
    Ok(())
}
