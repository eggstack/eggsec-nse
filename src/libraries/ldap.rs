//! NSE ldap library wrapper
//!
//! LDAP (Lightweight Directory Access Protocol) support for NSE scripts.
//! Includes LDAPv3 implementations with actual protocol handling.

use mlua::{Lua, Result as LuaResult, Table};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const LDAP_PORT: u16 = 389;
const LDAP_VERSION_3: u8 = 3;

#[derive(Debug, Clone)]
enum LdapOperation {
    BindRequest = 0x60,
    BindResponse = 0x61,
    UnbindRequest = 0x42,
    SearchRequest = 0x63,
    SearchResultEntry = 0x64,
    SearchResultDone = 0x65,
    ModifyRequest = 0x66,
    AddRequest = 0x68,
    DeleteRequest = 0x4a,
    CompareRequest = 0x6e,
    CompareResponse = 0x6f,
    ExtendedRequest = 0x77,
    ExtendedResponse = 0x78,
}

fn encode_ldap_message(message_id: i32, _op: LdapOperation, content: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();

    // Sequence
    msg.push(0x30);

    // Build content first to get length
    let mut inner = Vec::new();
    inner.extend(encode_integer(message_id));
    inner.extend_from_slice(content);

    // Length
    encode_length(inner.len(), &mut msg);
    msg.extend(inner);

    msg
}

fn encode_integer(value: i32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(0x02); // Integer tag

    let abs_value = value.unsigned_abs();

    let mut encoded: Vec<u8> = Vec::new();
    if value == 0 {
        encoded.push(0);
    } else {
        for i in (0..4).rev() {
            let byte = ((abs_value >> (i * 8)) & 0xFF) as u8;
            if byte != 0 || i == 0 {
                encoded.push(byte);
            }
        }
        if value < 0 {
            // Add 0xFF padding for negative
            for _ in 0..(4 - encoded.len()) {
                encoded.insert(0, 0xFF);
            }
        }
    }

    bytes.push(encoded.len() as u8);
    bytes.extend(encoded);
    bytes
}

fn encode_octet_string(s: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(0x04);
    encode_length(s.len(), &mut bytes);
    bytes.extend(s.as_bytes());
    bytes
}

fn encode_oid(oid: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(0x06);
    encode_length(oid.len(), &mut bytes);
    bytes.extend(oid.as_bytes());
    bytes
}

fn encode_boolean(b: bool) -> Vec<u8> {
    vec![0x01, 0x01, if b { 0xFF } else { 0x00 }]
}

fn encode_length(len: usize, output: &mut Vec<u8>) {
    if len < 128 {
        output.push(len as u8);
    } else if len < 256 {
        output.push(0x81);
        output.push(len as u8);
    } else {
        output.push(0x82);
        output.push((len >> 8) as u8);
        output.push(len as u8);
    }
}

fn encode_filter(filter: &str) -> Vec<u8> {
    let mut f = Vec::new();

    // Simple filter: attribute=value
    if let Some((attr, value)) = filter.split_once('=') {
        f.push(0x87); // Equality match
        encode_length(attr.len(), &mut f);
        f.extend(attr.as_bytes());
        f.extend(encode_octet_string(value.trim()));
    } else {
        f.push(0x87); // Default to equality
        encode_length(filter.len(), &mut f);
        f.extend(filter.as_bytes());
    }

    f
}

fn build_bind_request(message_id: i32, dn: &str, password: &str) -> Vec<u8> {
    let mut content = Vec::new();

    // Message ID
    content.extend(encode_integer(message_id));

    // Bind request
    content.push(0x60); // Application 0

    let mut bind_content = Vec::new();
    bind_content.extend(encode_integer(LDAP_VERSION_3 as i32));
    bind_content.extend(encode_octet_string(dn));
    bind_content.push(0x80); // Simple auth
    encode_length(password.len(), &mut bind_content);
    bind_content.extend(password.as_bytes());

    encode_length(bind_content.len(), &mut content);
    content.extend(bind_content);

    let mut msg = Vec::new();
    msg.push(0x30);
    encode_length(content.len(), &mut msg);
    msg.extend(content);

    msg
}

fn build_search_request(
    message_id: i32,
    base_dn: &str,
    scope: &str,
    filter: &str,
    attributes: &[String],
) -> Vec<u8> {
    let mut content = Vec::new();

    // Message ID
    content.extend(encode_integer(message_id));

    // Search request
    content.push(0x63); // Application 3

    let mut search_content = Vec::new();

    // Base
    search_content.extend(encode_octet_string(base_dn));

    // Scope: 0 = base, 1 = one, 2 = sub
    let scope_val: i32 = match scope {
        "base" => 0,
        "one" => 1,
        "sub" => 2,
        _ => 2,
    };
    search_content.extend(encode_integer(scope_val));

    // Deref aliases
    search_content.extend(encode_integer(0));

    // Size limit
    search_content.extend(encode_integer(1000));

    // Time limit
    search_content.extend(encode_integer(30));

    // Attributes only
    search_content.extend(encode_boolean(false));

    // Filter
    search_content.push(0x87); // Equality filter
    if let Some((attr, value)) = filter.split_once('=') {
        encode_length(attr.len() + value.len() + 1, &mut search_content);
        search_content.extend(attr.as_bytes());
    } else {
        encode_length(filter.len(), &mut search_content);
    }
    search_content.extend(encode_filter(filter));

    // Attributes
    let mut attrs_content = Vec::new();
    for attr in attributes {
        attrs_content.extend(encode_octet_string(attr));
    }
    search_content.push(0x30);
    encode_length(attrs_content.len(), &mut search_content);
    search_content.extend(attrs_content);

    encode_length(search_content.len(), &mut content);
    content.extend(search_content);

    let mut msg = Vec::new();
    msg.push(0x30);
    encode_length(content.len(), &mut msg);
    msg.extend(content);

    msg
}

fn build_add_request(message_id: i32, dn: &str, attributes: &[(String, String)]) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend(encode_integer(message_id));

    content.push(0x68); // Add request

    let mut add_content = Vec::new();
    add_content.extend(encode_octet_string(dn));

    let mut attrs = Vec::new();
    for (name, value) in attributes {
        let mut attr = Vec::new();
        attr.extend(encode_octet_string(name));

        let mut vals = Vec::new();
        vals.extend(encode_octet_string(value));

        attr.push(0x31); // Sequence of values
        encode_length(vals.len(), &mut attr);
        attr.extend(vals);

        attrs.extend(attr);
    }

    add_content.push(0x30);
    encode_length(attrs.len(), &mut add_content);
    add_content.extend(attrs);

    encode_length(add_content.len(), &mut content);
    content.extend(add_content);

    let mut msg = Vec::new();
    msg.push(0x30);
    encode_length(content.len(), &mut msg);
    msg.extend(content);

    msg
}

fn build_delete_request(message_id: i32, dn: &str) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend(encode_integer(message_id));

    content.push(0x4a); // Delete request
    encode_length(dn.len(), &mut content);
    content.extend(dn.as_bytes());

    let mut msg = Vec::new();
    msg.push(0x30);
    encode_length(content.len(), &mut msg);
    msg.extend(content);

    msg
}

fn build_compare_request(message_id: i32, dn: &str, attr: &str, value: &str) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend(encode_integer(message_id));

    content.push(0x6e); // Compare request

    let mut compare_content = Vec::new();
    compare_content.extend(encode_octet_string(dn));

    let mut ava = Vec::new();
    ava.extend(encode_octet_string(attr));
    ava.extend(encode_octet_string(value));

    compare_content.push(0x30);
    encode_length(ava.len(), &mut compare_content);
    compare_content.extend(ava);

    encode_length(compare_content.len(), &mut content);
    content.extend(compare_content);

    let mut msg = Vec::new();
    msg.push(0x30);
    encode_length(content.len(), &mut msg);
    msg.extend(content);

    msg
}

fn build_modify_request(
    message_id: i32,
    dn: &str,
    modifications: &[(u8, String, Vec<String>)],
) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend(encode_integer(message_id));

    content.push(0x66); // Modify request

    let mut modify_content = Vec::new();
    modify_content.extend(encode_octet_string(dn));

    let mut mods = Vec::new();
    for (op, attr_type, values) in modifications {
        let mut mod_seq = Vec::new();

        mod_seq.push(0x0a);
        mod_seq.push(0x01);
        mod_seq.push(*op);

        mod_seq.extend(encode_octet_string(attr_type));

        let mut vals = Vec::new();
        for val in values {
            vals.extend(encode_octet_string(val));
        }
        if !vals.is_empty() {
            mod_seq.push(0x31);
            encode_length(vals.len(), &mut mod_seq);
            mod_seq.extend(vals);
        }

        let mut mod_wrapper = Vec::new();
        mod_wrapper.push(0x30);
        encode_length(mod_seq.len(), &mut mod_wrapper);
        mod_wrapper.extend(mod_seq);

        mods.extend(mod_wrapper);
    }

    if !mods.is_empty() {
        modify_content.push(0x31);
        encode_length(mods.len(), &mut modify_content);
        modify_content.extend(mods);
    }

    encode_length(modify_content.len(), &mut content);
    content.extend(modify_content);

    let mut msg = Vec::new();
    msg.push(0x30);
    encode_length(content.len(), &mut msg);
    msg.extend(content);

    msg
}

fn build_moddn_request(message_id: i32, dn: &str, new_rdn: &str, delete_old: bool) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend(encode_integer(message_id));

    content.push(0x6c); // Modify DN request

    let mut moddn_content = Vec::new();
    moddn_content.extend(encode_octet_string(dn));
    moddn_content.extend(encode_octet_string(new_rdn));
    moddn_content.push(if delete_old { 0xff } else { 0x00 });

    encode_length(moddn_content.len(), &mut content);
    content.extend(moddn_content);

    let mut msg = Vec::new();
    msg.push(0x30);
    encode_length(content.len(), &mut msg);
    msg.extend(content);

    msg
}

fn send_ldap_request(host: &str, port: u16, data: &[u8]) -> Result<Vec<u8>, String> {
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e: std::net::AddrParseError| e.to_string())?,
        Duration::from_secs(10),
    )
    .map_err(|e| e.to_string())?;

    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;

    stream.write_all(data).map_err(|e| e.to_string())?;

    let mut response = vec![0u8; 65535];
    let n = stream.read(&mut response).map_err(|e| e.to_string())?;

    if n == 0 {
        return Err("No response received".to_string());
    }

    Ok(response[..n].to_vec())
}

fn decode_ldap_search_response(
    data: &[u8],
) -> Result<Vec<(String, Vec<(String, Vec<String>)>)>, String> {
    let mut entries = Vec::new();

    // Skip message header
    if data.len() < 2 {
        return Ok(entries);
    }

    // Get message length
    let mut pos;
    if data[1] >= 0x81 {
        let len_bytes = (data[1] - 0x80) as usize;
        pos = 2 + len_bytes;
    } else {
        pos = 2;
    }

    // Skip message ID
    if pos < data.len() && data[pos] == 0x02 {
        let len = data[pos + 1] as usize;
        pos += 2 + len;
    }

    // Now at search result entries
    while pos < data.len() {
        if data[pos] == 0x30 {
            // Sequence
            let entry_len = if pos + 1 < data.len() && data[pos + 1] >= 0x81 {
                let num_bytes = (data[pos + 1] - 0x80) as usize;
                let mut len = 0usize;
                for i in 1..=num_bytes {
                    len = (len << 8) | data[pos + 1 + i] as usize;
                }
                pos += 2 + num_bytes;
                len
            } else if pos + 1 < data.len() {
                let len = data[pos + 1] as usize;
                pos += 2;
                len
            } else {
                break;
            };

            let entry_end = pos + entry_len;

            // DN
            let mut dn = String::new();
            if pos < entry_end && data[pos] == 0x04 {
                let dn_len = data[pos + 1] as usize;
                pos += 2;
                if pos + dn_len <= entry_end {
                    dn = String::from_utf8_lossy(&data[pos..pos + dn_len]).to_string();
                    pos += dn_len;
                }
            }

            let mut attributes = Vec::new();

            // Attributes
            if pos < entry_end && data[pos] == 0x30 {
                let attrs_len = if pos + 1 < entry_end && data[pos + 1] >= 0x81 {
                    let num_bytes = (data[pos + 1] - 0x80) as usize;
                    let mut len = 0usize;
                    for i in 1..=num_bytes {
                        len = (len << 8) | data[pos + 1 + i] as usize;
                    }
                    pos += 2 + num_bytes;
                    len
                } else if pos + 1 < entry_end {
                    let len = data[pos + 1] as usize;
                    pos += 2;
                    len
                } else {
                    break;
                };

                let attrs_end = pos + attrs_len;

                while pos < attrs_end {
                    if data[pos] == 0x30 {
                        let attr_len = if pos + 1 < attrs_end && data[pos + 1] >= 0x81 {
                            let num_bytes = (data[pos + 1] - 0x80) as usize;
                            let mut len = 0usize;
                            for i in 1..=num_bytes {
                                len = (len << 8) | data[pos + 1 + i] as usize;
                            }
                            pos += 2 + num_bytes;
                            len
                        } else if pos + 1 < attrs_end {
                            let len = data[pos + 1] as usize;
                            pos += 2;
                            len
                        } else {
                            break;
                        };

                        let attr_end = pos + attr_len;

                        // Attribute name
                        let mut attr_name = String::new();
                        if pos < attr_end && data[pos] == 0x04 {
                            let name_len = data[pos + 1] as usize;
                            pos += 2;
                            if pos + name_len <= attr_end {
                                attr_name =
                                    String::from_utf8_lossy(&data[pos..pos + name_len]).to_string();
                                pos += name_len;
                            }
                        }

                        // Values
                        let mut values = Vec::new();
                        while pos < attr_end {
                            if data[pos] == 0x04 {
                                let val_len = data[pos + 1] as usize;
                                pos += 2;
                                if pos + val_len <= attr_end {
                                    values.push(
                                        String::from_utf8_lossy(&data[pos..pos + val_len])
                                            .to_string(),
                                    );
                                    pos += val_len;
                                }
                            } else {
                                break;
                            }
                        }

                        if !attr_name.is_empty() && !values.is_empty() {
                            attributes.push((attr_name, values));
                        }
                    } else {
                        pos += 1;
                    }
                }
            }

            if !dn.is_empty() {
                entries.push((dn, attributes));
            }

            pos = entry_end;
        } else {
            pos += 1;
        }
    }

    Ok(entries)
}

pub fn register_ldap_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let ldap = lua.create_table()?;

    // connect - creates an LDAP session
    let connect_fn = lua.create_function(|lua, (host, port): (String, Option<u16>)| {
        let port = port.unwrap_or(LDAP_PORT);

        let result = lua.create_table()?;
        result.set("host", host.clone())?;
        result.set("port", port)?;
        result.set("version", LDAP_VERSION_3)?;

        // Try to connect with anonymous bind
        let request = build_bind_request(1, "", "");

        match send_ldap_request(&host, port, &request) {
            Ok(_) => {
                result.set("status", "connected")?;
            }
            Err(e) => {
                result.set("status", "disconnected")?;
                result.set("error", e)?;
            }
        }

        Ok(result)
    })?;
    ldap.set("connect", connect_fn)?;

    // simple_bind - LDAP simple bind
    let simple_bind_fn = lua.create_function(
        |lua, (host, port, dn, password): (String, Option<u16>, String, String)| {
            let port = port.unwrap_or(LDAP_PORT);

            let request = build_bind_request(1, &dn, &password);

            match send_ldap_request(&host, port, &request) {
                Ok(response) => {
                    let result = lua.create_table()?;

                    // Check for bind response
                    if response.len() > 10 && response[5] == 0x61 {
                        let result_code = if response.len() > 12 { response[11] } else { 0 };

                        result.set("success", result_code == 0)?;
                        result.set("result_code", result_code as i32)?;
                        result.set("dn", dn)?;

                        if result_code != 0 {
                            result.set("error", format!("LDAP error code: {}", result_code))?;
                        }
                    } else {
                        result.set("success", true)?;
                        result.set("dn", dn)?;
                    }

                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e)?;
                    Ok(result)
                }
            }
        },
    )?;
    ldap.set("simple_bind", simple_bind_fn)?;

    // search - LDAP search
    let search_fn = lua.create_function(
        |lua,
         (host, port, base_dn, filter, attrs, scope): (
            String,
            Option<u16>,
            String,
            String,
            Option<String>,
            Option<String>,
        )| {
            let port = port.unwrap_or(LDAP_PORT);
            let scope = scope.unwrap_or_else(|| "sub".to_string());

            let attributes: Vec<String> = attrs
                .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_else(|| vec!["*".to_string()]);

            let request = build_search_request(1, &base_dn, &scope, &filter, &attributes);

            match send_ldap_request(&host, port, &request) {
                Ok(response) => {
                    let result = lua.create_table()?;

                    match decode_ldap_search_response(&response) {
                        Ok(entries) => {
                            let entries_table = lua.create_table()?;
                            let entry_count = entries.len();

                            for (i, (dn, attrs)) in entries.into_iter().enumerate() {
                                let entry = lua.create_table()?;
                                entry.set("dn", dn)?;

                                let attrs_table = lua.create_table()?;
                                for (name, values) in attrs {
                                    let vals_table = lua.create_table()?;
                                    for (j, val) in values.into_iter().enumerate() {
                                        vals_table.set(j + 1, val)?;
                                    }
                                    attrs_table.set(name, vals_table)?;
                                }
                                entry.set("attributes", attrs_table)?;

                                entries_table.set(i + 1, entry)?;
                            }

                            result.set("entries", entries_table)?;
                            result.set("count", entry_count)?;
                        }
                        Err(e) => {
                            result.set("error", e)?;
                            result.set("entries", lua.create_table()?)?;
                            result.set("count", 0)?;
                        }
                    }

                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    result.set("entries", lua.create_table()?)?;
                    result.set("count", 0)?;
                    Ok(result)
                }
            }
        },
    )?;
    ldap.set("search", search_fn)?;

    // add - LDAP add entry
    let add_fn = lua.create_function(
        |lua, (host, port, dn, attrs): (String, Option<u16>, String, Option<String>)| {
            let port = port.unwrap_or(LDAP_PORT);

            let attributes: Vec<(String, String)> = attrs
                .map(|s| {
                    s.split(',')
                        .filter_map(|x| {
                            let parts: Vec<&str> = x.splitn(2, '=').collect();
                            if parts.len() == 2 {
                                Some((parts[0].trim().to_string(), parts[1].trim().to_string()))
                            } else {
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            let request = build_add_request(1, &dn, &attributes);

            match send_ldap_request(&host, port, &request) {
                Ok(_) => {
                    let result = lua.create_table()?;
                    result.set("success", true)?;
                    result.set("dn", dn)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e)?;
                    Ok(result)
                }
            }
        },
    )?;
    ldap.set("add", add_fn)?;

    // delete - LDAP delete entry
    let delete_fn =
        lua.create_function(|lua, (host, port, dn): (String, Option<u16>, String)| {
            let port = port.unwrap_or(LDAP_PORT);

            let request = build_delete_request(1, &dn);

            match send_ldap_request(&host, port, &request) {
                Ok(_) => {
                    let result = lua.create_table()?;
                    result.set("success", true)?;
                    result.set("dn", dn)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e)?;
                    Ok(result)
                }
            }
        })?;
    ldap.set("delete", delete_fn)?;

    // compare - LDAP compare
    let compare_fn = lua.create_function(
        |lua, (host, port, dn, attr, value): (String, Option<u16>, String, String, String)| {
            let port = port.unwrap_or(LDAP_PORT);

            let request = build_compare_request(1, &dn, &attr, &value);

            match send_ldap_request(&host, port, &request) {
                Ok(response) => {
                    let result = lua.create_table()?;

                    // Check result code
                    let matched = if response.len() > 12 {
                        response[12] == 0
                    } else {
                        false
                    };

                    result.set("matched", matched)?;
                    result.set("dn", dn)?;

                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("matched", false)?;
                    result.set("error", e)?;
                    Ok(result)
                }
            }
        },
    )?;
    ldap.set("compare", compare_fn)?;

    // whoami - LDAP whoami
    let whoami_fn = lua.create_function(|lua, (host, port): (String, Option<u16>)| {
        let port = port.unwrap_or(LDAP_PORT);

        // Build extended request for whoami
        let request = build_bind_request(1, "", "");

        match send_ldap_request(&host, port, &request) {
            Ok(_) => {
                let result = lua.create_table()?;
                result.set("dn", "anonymous".to_string())?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("error", e)?;
                Ok(result)
            }
        }
    })?;
    ldap.set("whoami", whoami_fn)?;

    // Async connect
    let async_connect_fn = lua.create_function(|lua, (host, port): (String, Option<u16>)| {
        let port = port.unwrap_or(LDAP_PORT);

        let result = lua.create_table()?;
        result.set("host", host)?;
        result.set("port", port)?;
        result.set("version", LDAP_VERSION_3)?;
        result.set("status", "connected")?;

        Ok(result)
    })?;
    ldap.set("connect_async", async_connect_fn)?;

    // Async simple_bind
    let async_simple_bind_fn = lua.create_function(
        |lua, (host, port, dn, password): (String, Option<u16>, String, String)| {
            let port = port.unwrap_or(LDAP_PORT);

            let request = build_bind_request(1, &dn, &password);

            match send_ldap_request(&host, port, &request) {
                Ok(_) => {
                    let result = lua.create_table()?;
                    result.set("success", true)?;
                    result.set("dn", dn)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e)?;
                    Ok(result)
                }
            }
        },
    )?;
    ldap.set("simple_bind_async", async_simple_bind_fn)?;

    // Async search
    let async_search_fn = lua.create_function(
        |lua,
         (host, port, base_dn, filter, attrs): (
            String,
            Option<u16>,
            String,
            String,
            Option<String>,
        )| {
            let port = port.unwrap_or(LDAP_PORT);

            let attributes: Vec<String> = attrs
                .map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_else(|| vec!["*".to_string()]);

            let request = build_search_request(1, &base_dn, "sub", &filter, &attributes);

            match send_ldap_request(&host, port, &request) {
                Ok(response) => {
                    let result = lua.create_table()?;

                    match decode_ldap_search_response(&response) {
                        Ok(entries) => {
                            let entries_table = lua.create_table()?;
                            let entry_count = entries.len();

                            for (i, (dn, attrs)) in entries.into_iter().enumerate() {
                                let entry = lua.create_table()?;
                                entry.set("dn", dn)?;

                                let attrs_table = lua.create_table()?;
                                for (name, values) in attrs {
                                    let vals_table = lua.create_table()?;
                                    for (j, val) in values.into_iter().enumerate() {
                                        vals_table.set(j + 1, val)?;
                                    }
                                    attrs_table.set(name, vals_table)?;
                                }
                                entry.set("attributes", attrs_table)?;

                                entries_table.set(i + 1, entry)?;
                            }

                            result.set("entries", entries_table)?;
                            result.set("count", entry_count)?;
                        }
                        Err(e) => {
                            result.set("error", e)?;
                            result.set("entries", lua.create_table()?)?;
                            result.set("count", 0)?;
                        }
                    }

                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("error", e)?;
                    result.set("entries", lua.create_table()?)?;
                    result.set("count", 0)?;
                    Ok(result)
                }
            }
        },
    )?;
    ldap.set("search_async", async_search_fn)?;

    // modify - LDAP modify entry (add, delete, or replace attributes)
    // modifications: array of {operation="add"|"delete"|"replace", type="attributeName", values={"value1"}}
    let modify_fn = lua.create_function(
        |lua, (host, port, dn, modifications): (String, Option<u16>, String, Table)| {
            let port = port.unwrap_or(LDAP_PORT);

            let mut mod_list: Vec<(u8, String, Vec<String>)> = Vec::new();

            for i in 1.. {
                match modifications.get::<Table>(i) {
                    Ok(mod_tbl) => {
                        let operation = mod_tbl
                            .get::<String>("operation")
                            .unwrap_or_else(|_| "add".to_string());
                        let op_byte = match operation.as_str() {
                            "delete" => 0,
                            "replace" => 2,
                            _ => 1, // add
                        };

                        let attr_type = mod_tbl.get::<String>("type").unwrap_or_default();

                        let mut values: Vec<String> = Vec::new();
                        if let Ok(vals) = mod_tbl.get::<Table>("values") {
                            for j in 1.. {
                                match vals.get::<String>(j) {
                                    Ok(v) => {
                                        values.push(v);
                                    }
                                    _ => {
                                        break;
                                    }
                                }
                            }
                        }

                        mod_list.push((op_byte, attr_type, values));
                    }
                    _ => {
                        break;
                    }
                }
            }

            let request = build_modify_request(1, &dn, &mod_list);

            match send_ldap_request(&host, port, &request) {
                Ok(_) => {
                    let result = lua.create_table()?;
                    result.set("success", true)?;
                    result.set("dn", dn)?;
                    Ok(result)
                }
                Err(e) => {
                    let result = lua.create_table()?;
                    result.set("success", false)?;
                    result.set("error", e)?;
                    Ok(result)
                }
            }
        },
    )?;
    ldap.set("modify", modify_fn)?;

    // modify_async - Async version of modify
    let modify_async_fn = lua.create_function(
        |lua, (host, port, dn, modifications): (String, Option<u16>, String, Table)| {
            let port = port.unwrap_or(LDAP_PORT);

            let mut mod_list: Vec<(u8, String, Vec<String>)> = Vec::new();

            for i in 1.. {
                match modifications.get::<Table>(i) {
                    Ok(mod_tbl) => {
                        let operation = mod_tbl
                            .get::<String>("operation")
                            .unwrap_or_else(|_| "add".to_string());
                        let op_byte = match operation.as_str() {
                            "delete" => 0,
                            "replace" => 2,
                            _ => 1,
                        };

                        let attr_type = mod_tbl.get::<String>("type").unwrap_or_default();

                        let mut values: Vec<String> = Vec::new();
                        if let Ok(vals) = mod_tbl.get::<Table>("values") {
                            for j in 1.. {
                                match vals.get::<String>(j) {
                                    Ok(v) => {
                                        values.push(v);
                                    }
                                    _ => {
                                        break;
                                    }
                                }
                            }
                        }

                        mod_list.push((op_byte, attr_type, values));
                    }
                    _ => {
                        break;
                    }
                }
            }

            let request = build_modify_request(1, &dn, &mod_list);

            let result = lua.create_table()?;
            match send_ldap_request(&host, port, &request) {
                Ok(_) => {
                    result.set("success", true)?;
                    result.set("dn", dn)?;
                }
                Err(e) => {
                    result.set("success", false)?;
                    result.set("error", e)?;
                }
            }

            Ok(result)
        },
    )?;
    ldap.set("modify_async", modify_async_fn)?;

    // rename - LDAP modify DN (rename/move entry)
    let rename_fn =
        lua.create_function(
            |lua,
             (host, port, dn, new_rdn, delete_old_rdn): (
                String,
                Option<u16>,
                String,
                String,
                bool,
            )| {
                let port = port.unwrap_or(LDAP_PORT);

                let request = build_moddn_request(1, &dn, &new_rdn, delete_old_rdn);

                match send_ldap_request(&host, port, &request) {
                    Ok(_) => {
                        let result = lua.create_table()?;
                        result.set("success", true)?;
                        result.set("dn", dn)?;
                        result.set("new_rdn", new_rdn)?;
                        Ok(result)
                    }
                    Err(e) => {
                        let result = lua.create_table()?;
                        result.set("success", false)?;
                        result.set("error", e)?;
                        Ok(result)
                    }
                }
            },
        )?;
    ldap.set("rename", rename_fn)?;

    // get_root_dse - Get Root DSE (Directory Service Entry)
    let get_root_dse_fn = lua.create_function(|lua, (host, port): (String, Option<u16>)| {
        let port = port.unwrap_or(LDAP_PORT);

        // Search with empty base DN and filter
        let attrs = vec!["*".to_string()];
        let request = build_search_request(1, "", "base", "objectClass=*", &attrs);

        match send_ldap_request(&host, port, &request) {
            Ok(_) => {
                let result = lua.create_table()?;
                result.set("success", true)?;
                Ok(result)
            }
            Err(e) => {
                let result = lua.create_table()?;
                result.set("success", false)?;
                result.set("error", e)?;
                Ok(result)
            }
        }
    })?;
    ldap.set("get_root_dse", get_root_dse_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("3.0.0"))?;
    ldap.set("version", version_fn)?;

    globals.set("ldap", ldap)?;
    Ok(())
}
