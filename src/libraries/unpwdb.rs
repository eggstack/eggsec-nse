//! NSE unpwdb library wrapper
//!
//! Provides username/password brute force utilities for NSE scripts.
//! Based on Nmap's unpwdb library: https://nmap.org/nsedoc/lib/unpwdb.html

use mlua::{Lua, Result as LuaResult};
use std::sync::Mutex;

static USERNAMES: std::sync::LazyLock<Mutex<Vec<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(get_default_usernames()));
static PASSWORDS: std::sync::LazyLock<Mutex<Vec<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(get_default_passwords()));

fn get_default_usernames() -> Vec<String> {
    vec![
        "root".to_string(),
        "admin".to_string(),
        "user".to_string(),
        "test".to_string(),
        "guest".to_string(),
        "administrator".to_string(),
        "oracle".to_string(),
        "postgres".to_string(),
        "mysql".to_string(),
        "ftpuser".to_string(),
        "apache".to_string(),
        "www".to_string(),
        "webadmin".to_string(),
        "operator".to_string(),
        "superuser".to_string(),
        "master".to_string(),
        "daemon".to_string(),
        "www-data".to_string(),
        "nobody".to_string(),
        "sysadmin".to_string(),
    ]
}

fn get_default_passwords() -> Vec<String> {
    vec![
        "password".to_string(),
        "123456".to_string(),
        "12345678".to_string(),
        "123456789".to_string(),
        "qwerty".to_string(),
        "abc123".to_string(),
        "monkey".to_string(),
        "1234567".to_string(),
        "letmein".to_string(),
        "trustno1".to_string(),
        "dragon".to_string(),
        "baseball".to_string(),
        "iloveyou".to_string(),
        "master".to_string(),
        "sunshine".to_string(),
        "ashley".to_string(),
        "bailey".to_string(),
        "passw0rd".to_string(),
        "shadow".to_string(),
        "123123".to_string(),
        "654321".to_string(),
        "superman".to_string(),
        "qazwsx".to_string(),
        "michael".to_string(),
        "football".to_string(),
        "password1".to_string(),
        "password123".to_string(),
        "welcome".to_string(),
        "hello".to_string(),
        "charlie".to_string(),
        "donald".to_string(),
        "admin".to_string(),
        "root".to_string(),
        "toor".to_string(),
        "1234".to_string(),
        "test".to_string(),
        "guest".to_string(),
    ]
}

pub fn register_unpwdb_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let unpwdb = lua.create_table()?;

    let usernames_fn =
        lua.create_function(|lua, (filename, limit): (Option<String>, Option<usize>)| {
            let usernames = lua.create_table()?;

            let user_list = if let Some(ref f) = filename {
                std::fs::read_to_string(f)
                    .ok()
                    .map(|content| {
                        content
                            .lines()
                            .map(|s| s.to_string())
                            .filter(|s| !s.is_empty())
                            .collect()
                    })
                    .unwrap_or_else(get_default_usernames)
            } else {
                get_default_usernames()
            };

            let max = limit.unwrap_or(user_list.len());
            for (i, user) in user_list.iter().take(max).enumerate() {
                usernames.set(i + 1, user.clone())?;
            }

            Ok(usernames)
        })?;
    unpwdb.set("usernames", usernames_fn)?;

    let passwords_fn =
        lua.create_function(|lua, (filename, limit): (Option<String>, Option<usize>)| {
            let passwords = lua.create_table()?;

            let pass_list = if let Some(ref f) = filename {
                std::fs::read_to_string(f)
                    .ok()
                    .map(|content| {
                        content
                            .lines()
                            .map(|s| s.to_string())
                            .filter(|s| !s.is_empty())
                            .collect()
                    })
                    .unwrap_or_else(get_default_passwords)
            } else {
                get_default_passwords()
            };

            let max = limit.unwrap_or(pass_list.len());
            for (i, pass) in pass_list.iter().take(max).enumerate() {
                passwords.set(i + 1, pass.clone())?;
            }

            Ok(passwords)
        })?;
    unpwdb.set("passwords", passwords_fn)?;

    let combined_fn =
        lua.create_function(
            |lua,
             (username_file, password_file, limit): (
                Option<String>,
                Option<String>,
                Option<usize>,
            )| {
                let result = lua.create_table()?;

                let users = if let Some(ref f) = username_file {
                    std::fs::read_to_string(f)
                        .ok()
                        .map(|c| {
                            c.lines()
                                .map(|s| s.to_string())
                                .filter(|s| !s.is_empty())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_else(get_default_usernames)
                } else {
                    get_default_usernames()
                };

                let passes = if let Some(ref f) = password_file {
                    std::fs::read_to_string(f)
                        .ok()
                        .map(|c| {
                            c.lines()
                                .map(|s| s.to_string())
                                .filter(|s| !s.is_empty())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_else(get_default_passwords)
                } else {
                    get_default_passwords()
                };

                let max = limit.unwrap_or(usize::MAX);
                let mut count = 0;

                for user in &users {
                    for pass in &passes {
                        if count >= max {
                            break;
                        }
                        let pair = lua.create_table()?;
                        pair.set("username", user.clone())?;
                        pair.set("password", pass.clone())?;
                        result.set(count + 1, pair)?;
                        count += 1;
                    }
                }

                Ok(result)
            },
        )?;
    unpwdb.set("combined", combined_fn)?;

    let expand_password_fn = lua.create_function(|_lua, password: String| {
        let mut results = vec![password.clone()];

        results.push(format!("{}123", password));
        results.push(format!("{}.*", password));
        results.push(format!("{}!", password));
        results.push(format!("{}1", password));
        results.push(format!("{}01", password));
        results.push(password.to_uppercase());
        results.push(password.to_lowercase());
        results.push(
            password
                .replace("a", "@")
                .replace("e", "3")
                .replace("i", "1")
                .replace("o", "0")
                .replace("s", "$"),
        );

        Ok(results)
    })?;
    unpwdb.set("expand_password", expand_password_fn)?;

    let username_iterator_fn = lua.create_function(|lua, filename: Option<String>| {
        let users = if let Some(ref f) = filename {
            std::fs::read_to_string(f)
                .ok()
                .map(|c| {
                    c.lines()
                        .map(|s| s.to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_else(get_default_usernames)
        } else {
            get_default_usernames()
        };

        let table = lua.create_table()?;
        for (i, user) in users.iter().enumerate() {
            table.set(i + 1, user.clone())?;
        }

        Ok(table)
    })?;
    unpwdb.set("username_iterator", username_iterator_fn)?;

    let password_iterator_fn = lua.create_function(|lua, filename: Option<String>| {
        let passes = if let Some(ref f) = filename {
            std::fs::read_to_string(f)
                .ok()
                .map(|c| {
                    c.lines()
                        .map(|s| s.to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_else(get_default_passwords)
        } else {
            get_default_passwords()
        };

        let table = lua.create_table()?;
        for (i, pass) in passes.iter().enumerate() {
            table.set(i + 1, pass.clone())?;
        }

        Ok(table)
    })?;
    unpwdb.set("password_iterator", password_iterator_fn)?;

    globals.set("unpwdb", unpwdb)?;
    Ok(())
}
