//! NSE creds library wrapper
//!
//! Provides credential storage class for NSE scripts.
//! Based on Nmap's creds library: https://nmap.org/nsedoc/lib/creds.html

use mlua::{Lua, Result as LuaResult};
use rustc_hash::{FxHashMap, FxHashSet};
use std::sync::Mutex;

use crate::capabilities::NseCapabilityContext;

static CREDENTIALS_STORE: std::sync::LazyLock<Mutex<FxHashMap<String, Vec<Credential>>>> =
    std::sync::LazyLock::new(|| Mutex::new(FxHashMap::default()));

#[derive(Clone, Debug)]
struct Credential {
    username: String,
    password: String,
    service: String,
    state: String,
}

pub fn register_creds_library(lua: &Lua, _capability_ctx: &NseCapabilityContext) -> LuaResult<()> {
    let globals = lua.globals();
    let creds = lua.create_table()?;

    let new_fn = lua.create_function(|lua, (service, state): (String, Option<String>)| {
        let cred = lua.create_table()?;
        cred.set("service", service.clone())?;
        cred.set("state", state.unwrap_or_else(|| "unknown".to_string()))?;
        cred.set("user", "")?;
        cred.set("pass", "")?;

        let host_key = "global".to_string();
        if let Ok(mut store) = CREDENTIALS_STORE.lock() {
            store.entry(host_key).or_insert_with(Vec::new);
        }

        Ok(cred)
    })?;
    creds.set("new", new_fn)?;

    let add_fn = lua.create_function(
        |_lua,
         (host, service, username, password, state): (
            Option<String>,
            String,
            String,
            String,
            Option<String>,
        )| {
            let host_key = host.unwrap_or_else(|| "global".to_string());

            if let Ok(mut store) = CREDENTIALS_STORE.lock() {
                let cred = Credential {
                    username: username.clone(),
                    password: password.clone(),
                    service: service.clone(),
                    state: state.clone().unwrap_or_else(|| "unknown".to_string()),
                };
                store.entry(host_key).or_insert_with(Vec::new).push(cred);
            }

            Ok(true)
        },
    )?;
    creds.set("add", add_fn)?;

    let get_fn =
        lua.create_function(|lua, (host, service): (Option<String>, Option<String>)| {
            let host_key = host.unwrap_or_else(|| "global".to_string());
            let result = lua.create_table()?;

            if let Ok(store) = CREDENTIALS_STORE.lock() {
                if let Some(creds) = store.get(&host_key) {
                    let mut i = 1;
                    for cred in creds {
                        let matches_service = service.as_ref().map_or(true, |s| s == &cred.service);

                        if matches_service {
                            let entry = lua.create_table()?;
                            entry.set("service", cred.service.clone())?;
                            entry.set("state", cred.state.clone())?;
                            entry.set("user", cred.username.clone())?;
                            entry.set("pass", cred.password.clone())?;
                            result.set(i, entry)?;
                            i += 1;
                        }
                    }
                }
            }

            Ok(result)
        })?;
    creds.set("get", get_fn)?;

    let get_username_fn = lua.create_function(|lua, host: Option<String>| {
        let host_key = host.unwrap_or_else(|| "global".to_string());
        let result = lua.create_table()?;

        if let Ok(store) = CREDENTIALS_STORE.lock() {
            if let Some(creds) = store.get(&host_key) {
                let mut i = 1;
                let mut seen = FxHashSet::default();
                for cred in creds {
                    if seen.insert(cred.username.clone()) {
                        result.set(i, cred.username.clone())?;
                        i += 1;
                    }
                }
            }
        }

        Ok(result)
    })?;
    creds.set("get_username", get_username_fn)?;

    let get_password_fn = lua.create_function(|lua, host: Option<String>| {
        let host_key = host.unwrap_or_else(|| "global".to_string());
        let result = lua.create_table()?;

        if let Ok(store) = CREDENTIALS_STORE.lock() {
            if let Some(creds) = store.get(&host_key) {
                let mut i = 1;
                let mut seen = FxHashSet::default();
                for cred in creds {
                    if seen.insert(cred.password.clone()) {
                        result.set(i, cred.password.clone())?;
                        i += 1;
                    }
                }
            }
        }

        Ok(result)
    })?;
    creds.set("get_password", get_password_fn)?;

    let clear_fn = lua.create_function(|_lua, host: Option<String>| {
        let host_key = host.unwrap_or_else(|| "global".to_string());

        if let Ok(mut store) = CREDENTIALS_STORE.lock() {
            store.remove(&host_key);
        }

        Ok(true)
    })?;
    creds.set("clear", clear_fn)?;

    let dump_fn = lua.create_function(|lua, _: ()| {
        let result = lua.create_table()?;

        if let Ok(store) = CREDENTIALS_STORE.lock() {
            let mut i = 1;
            for (host, creds) in store.iter() {
                let host_entry = lua.create_table()?;
                host_entry.set("host", host.clone())?;

                let creds_arr = lua.create_table()?;
                let mut j = 1;
                for cred in creds {
                    let cred_entry = lua.create_table()?;
                    cred_entry.set("service", cred.service.clone())?;
                    cred_entry.set("state", cred.state.clone())?;
                    cred_entry.set("user", cred.username.clone())?;
                    cred_entry.set("pass", cred.password.clone())?;
                    creds_arr.set(j, cred_entry)?;
                    j += 1;
                }
                host_entry.set("creds", creds_arr)?;
                result.set(i, host_entry)?;
                i += 1;
            }
        }

        Ok(result)
    })?;
    creds.set("dump", dump_fn)?;

    let create_table_fn =
        lua.create_function(|lua, (service, state): (String, Option<String>)| {
            let table = lua.create_table()?;
            table.set("service", service)?;
            table.set("state", state.unwrap_or_else(|| "unknown".to_string()))?;
            table.set("user", "")?;
            table.set("pass", "")?;
            Ok(table)
        })?;
    creds.set("create", create_table_fn)?;

    globals.set("creds", creds)?;
    Ok(())
}
