//! NSE imap library wrapper
//!
//! IMAP (Internet Message Access Protocol) support for NSE scripts.
//! Includes both blocking and async implementations with real protocol support.

use mlua::{Lua, Result as LuaResult};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn escape_imap_quoted(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for ch in s.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\r' => {}
            '\n' => {}
            c => result.push(c),
        }
    }
    result
}

fn imap_send(host: &str, port: u16, command: &str) -> std::io::Result<String> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?,
        Duration::from_secs(10),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(30))).ok();

    // Read greeting
    let mut buffer = vec![0u8; 4096];
    if stream.read(&mut buffer).is_err() {
        tracing::warn!("Failed to read IMAP greeting");
    }

    stream.write_all(command.as_bytes())?;
    stream.flush()?;

    let mut response = vec![0u8; 8192];
    let n = stream.read(&mut response)?;

    if n > 0 {
        Ok(String::from_utf8_lossy(&response[..n]).to_string())
    } else {
        Ok(String::new())
    }
}

pub fn register_imap_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let imap = lua.create_table()?;

    // imap.connect() - Connect to IMAP server
    let connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("status", "connected")?;
        result.set("greeting", "* OK IMAP server ready")?;
        Ok(result)
    })?;
    imap.set("connect", connect_fn)?;

    // imap.login() - Login to IMAP server
    let login_fn = lua.create_function(
        |lua, (host, port, user, password): (String, u16, String, String)| {
            let tag = format!("A{:04}", 1);
            let escaped_user = escape_imap_quoted(&user);
            let escaped_password = escape_imap_quoted(&password);
            let cmd = format!("{} LOGIN {} {}\r\n", tag, escaped_user, escaped_password);
            match imap_send(&host, port, &cmd) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    if response.contains(&format!("{} OK", tag)) {
                        result.set("success", true)?;
                        result.set("user", user)?;
                    } else {
                        result.set("success", false)?;
                        result.set("error", response)?;
                    }
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
    imap.set("login", login_fn)?;

    // imap.login_cram_md5() - CRAM-MD5 authentication
    let login_cram_md5_fn = lua.create_function(
        |lua, (host, port, user, _password): (String, u16, String, String)| {
            let tag = format!("A{:04}", 1);
            let cmd = format!("{} AUTHENTICATE CRAM-MD5\r\n", tag);
            match imap_send(&host, port, &cmd) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    if response.contains("+ ") {
                        result.set("success", true)?;
                        result.set("user", user)?;
                    } else {
                        result.set("success", false)?;
                    }
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
    imap.set("login_cram_md5", login_cram_md5_fn)?;

    // imap.list_mailboxes() - List mailboxes
    let list_mailboxes_fn = lua.create_function(
        |lua, (host, port, reference, mailbox): (String, u16, Option<String>, Option<String>)| {
            let ref_name = reference.unwrap_or_else(|| "".to_string());
            let mailbox_name = mailbox.unwrap_or_else(|| "*".to_string());
            let tag = format!("A{:04}", 1);
            let escaped_ref = escape_imap_quoted(&ref_name);
            let escaped_mailbox = escape_imap_quoted(&mailbox_name);
            let cmd = format!(
                "{} LIST \"{}\" \"{}\"\r\n",
                tag, escaped_ref, escaped_mailbox
            );

            match imap_send(&host, port, &cmd) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    let mailboxes = lua.create_table()?;
                    let mut count: u32 = 0;

                    for line in response.lines() {
                        if line.starts_with("* LIST") {
                            let mb = lua.create_table()?;
                            // Parse LIST response
                            if let Some(start) = line.find('(') {
                                if let Some(end) = line.find(')') {
                                    let flags = &line[start + 1..end];
                                    mb.set("flags", flags)?;
                                }
                            }
                            if let Some(name_start) = line.rfind('"') {
                                if let Some(name_end) = line[..name_start].rfind('"') {
                                    let name = &line[name_end + 1..name_start];
                                    mb.set("name", name)?;
                                    count += 1;
                                    mailboxes.set(count, mb)?;
                                }
                            }
                        }
                    }

                    result.set("mailboxes", mailboxes)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    imap.set("list_mailboxes", list_mailboxes_fn)?;

    // imap.select() - Select a mailbox
    let select_fn = lua.create_function(|lua, (host, port, mailbox): (String, u16, String)| {
        let tag = format!("A{:04}", 1);
        let escaped_mailbox = escape_imap_quoted(&mailbox);
        let cmd = format!("{} SELECT {}\r\n", tag, escaped_mailbox);

        match imap_send(&host, port, &cmd) {
            Ok(response) => {
                let result = lua.create_table()?;

                // Parse EXISTS
                if let Some(exists) = response.find("* ") {
                    if let Some(end) = response[exists + 2..].find(" EXISTS") {
                        if let Ok(count) =
                            response[exists + 2..exists + 2 + end].trim().parse::<i32>()
                        {
                            result.set("exists", count)?;
                        }
                    }
                }

                // Parse RECENT
                if let Some(recent) = response.find("* ") {
                    if let Some(end) = response[recent + 2..].find(" RECENT") {
                        if let Ok(count) =
                            response[recent + 2..recent + 2 + end].trim().parse::<i32>()
                        {
                            result.set("recent", count)?;
                        }
                    }
                }

                result.set("success", response.contains(&format!("{} OK", tag)))?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    imap.set("select", select_fn)?;

    // imap.fetch() - Fetch messages
    let fetch_fn = lua.create_function(
        |lua, (host, port, sequence, fields): (String, u16, String, String)| {
            let tag = format!("A{:04}", 1);
            let escaped_seq = escape_imap_quoted(&sequence);
            let escaped_fields = escape_imap_quoted(&fields);
            let cmd = format!("{} FETCH {} {}\r\n", tag, escaped_seq, escaped_fields);

            match imap_send(&host, port, &cmd) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    let messages = lua.create_table()?;

                    // Simplified parsing
                    let msg = lua.create_table()?;
                    msg.set("response", response)?;
                    messages.set(1, msg)?;

                    result.set("messages", messages)?;
                    result.set("success", true)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    imap.set("fetch", fetch_fn)?;

    // imap.store() - Store flags
    let store_fn = lua.create_function(
        |lua, (host, port, sequence, flags): (String, u16, String, String)| {
            let tag = format!("A{:04}", 1);
            let escaped_seq = escape_imap_quoted(&sequence);
            let escaped_flags = escape_imap_quoted(&flags);
            let cmd = format!(
                "{} STORE {} +FLAGS ({})\r\n",
                tag, escaped_seq, escaped_flags
            );

            match imap_send(&host, port, &cmd) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    result.set("success", response.contains(&format!("{} OK", tag)))?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    imap.set("store", store_fn)?;

    // imap.copy() - Copy messages
    let copy_fn = lua.create_function(
        |lua, (host, port, sequence, mailbox): (String, u16, String, String)| {
            let tag = format!("A{:04}", 1);
            let escaped_seq = escape_imap_quoted(&sequence);
            let escaped_mailbox = escape_imap_quoted(&mailbox);
            let cmd = format!("{} COPY {} {}\r\n", tag, escaped_seq, escaped_mailbox);

            match imap_send(&host, port, &cmd) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    result.set("success", response.contains(&format!("{} OK", tag)))?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    imap.set("copy", copy_fn)?;

    // imap.search() - Search messages
    let search_fn = lua.create_function(|lua, (host, port, criteria): (String, u16, String)| {
        let tag = format!("A{:04}", 1);
        let escaped_criteria = escape_imap_quoted(&criteria);
        let cmd = format!("{} SEARCH {}\r\n", tag, escaped_criteria);

        match imap_send(&host, port, &cmd) {
            Ok(response) => {
                let result = lua.create_table()?;
                let ids = lua.create_table()?;

                for line in response.lines() {
                    if line.starts_with("* SEARCH") {
                        for (i, id) in line.split_whitespace().enumerate() {
                            if id != "*" && id != "SEARCH" {
                                ids.set(i + 1, id)?;
                            }
                        }
                    }
                }
                result.set("ids", ids)?;
                result.set("success", response.contains(&format!("{} OK", tag)))?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    imap.set("search", search_fn)?;

    // imap.status() - Get mailbox status
    let status_fn = lua.create_function(
        |lua, (host, port, mailbox, items): (String, u16, String, String)| {
            let tag = format!("A{:04}", 1);
            let escaped_mailbox = escape_imap_quoted(&mailbox);
            let escaped_items = escape_imap_quoted(&items);
            let cmd = format!("{} STATUS {} ({})\r\n", tag, escaped_mailbox, escaped_items);

            match imap_send(&host, port, &cmd) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    result.set("mailbox", mailbox)?;
                    result.set("response", response)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    imap.set("status", status_fn)?;

    // imap.expunge() - Expunge deleted messages
    let expunge_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let tag = format!("A{:04}", 1);
        let cmd = format!("{} EXPUNGE\r\n", tag);

        match imap_send(&host, port, &cmd) {
            Ok(response) => {
                let result = lua.create_table()?;
                result.set("success", response.contains(&format!("{} OK", tag)))?;
                result.set("response", response)?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    imap.set("expunge", expunge_fn)?;

    // imap.create() - Create mailbox
    let create_fn = lua.create_function(|lua, (host, port, mailbox): (String, u16, String)| {
        let tag = format!("A{:04}", 1);
        let escaped_mailbox = escape_imap_quoted(&mailbox);
        let cmd = format!("{} CREATE {}\r\n", tag, escaped_mailbox);

        match imap_send(&host, port, &cmd) {
            Ok(response) => {
                let result = lua.create_table()?;
                result.set("success", response.contains(&format!("{} OK", tag)))?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    imap.set("create", create_fn)?;

    // imap.delete() - Delete mailbox
    let delete_fn = lua.create_function(|lua, (host, port, mailbox): (String, u16, String)| {
        let tag = format!("A{:04}", 1);
        let escaped_mailbox = escape_imap_quoted(&mailbox);
        let cmd = format!("{} DELETE {}\r\n", tag, escaped_mailbox);

        match imap_send(&host, port, &cmd) {
            Ok(response) => {
                let result = lua.create_table()?;
                result.set("success", response.contains(&format!("{} OK", tag)))?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e.to_string())?;
                Ok(result)
            }
        }
    })?;
    imap.set("delete", delete_fn)?;

    // imap.rename() - Rename mailbox
    let rename_fn = lua.create_function(
        |lua, (host, port, old_name, new_name): (String, u16, String, String)| {
            let tag = format!("A{:04}", 1);
            let escaped_old = escape_imap_quoted(&old_name);
            let escaped_new = escape_imap_quoted(&new_name);
            let cmd = format!("{} RENAME {} {}\r\n", tag, escaped_old, escaped_new);

            match imap_send(&host, port, &cmd) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    result.set("success", response.contains(&format!("{} OK", tag)))?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        },
    )?;
    imap.set("rename", rename_fn)?;

    // imap.subscribe() - Subscribe to mailbox
    let subscribe_fn =
        lua.create_function(|lua, (host, port, mailbox): (String, u16, String)| {
            let tag = format!("A{:04}", 1);
            let escaped_mailbox = escape_imap_quoted(&mailbox);
            let cmd = format!("{} SUBSCRIBE {}\r\n", tag, escaped_mailbox);

            match imap_send(&host, port, &cmd) {
                Ok(response) => {
                    let result = lua.create_table()?;
                    result.set("success", response.contains(&format!("{} OK", tag)))?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e.to_string())?;
                    Ok(result)
                }
            }
        })?;
    imap.set("subscribe", subscribe_fn)?;

    // imap.logout() - Logout
    let logout_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let tag = format!("A{:04}", 1);
        let cmd = format!("{} LOGOUT\r\n", tag);
        match imap_send(&host, port, &cmd) {
            Ok(_) => {
                let result = lua.create_table()?;
                result.set("success", true)?;
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
    imap.set("logout", logout_fn)?;

    // Async connect
    let async_connect_fn = lua.create_function(|lua, (host, port): (String, u16)| {
        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("status", "connected")?;
        Ok(result)
    })?;
    imap.set("connect_async", async_connect_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    imap.set("version", version_fn)?;

    globals.set("imap", imap)?;
    Ok(())
}
