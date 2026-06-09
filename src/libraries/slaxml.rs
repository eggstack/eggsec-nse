//! NSE slaxml library wrapper
//!
//! SLAXML - XML SAX-like streaming XML parser for Lua.
//! Based on Nmap's slaxml library concepts.

use mlua::{Function, Lua, Result as LuaResult, Table};

pub fn register_slaxml_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let slaxml = lua.create_table()?;

    let parser_fn = lua.create_function(|lua, (xml, callbacks): (String, Table)| {
        let result = lua.create_table()?;

        let _in_element = false;
        let _current_element = String::new();
        let mut current_text = String::new();
        let mut depth = 0;

        let mut chars_fn: Option<Function> = None;
        let mut start_fn: Option<Function> = None;
        let mut end_fn: Option<Function> = None;

        if let Ok(f) = callbacks.get::<Function>("characters") {
            chars_fn = Some(f);
        }
        if let Ok(f) = callbacks.get::<Function>("startElement") {
            start_fn = Some(f);
        }
        if let Ok(f) = callbacks.get::<Function>("endElement") {
            end_fn = Some(f);
        }

        let mut i = 0;
        let bytes = xml.as_bytes();

        while i < bytes.len() {
            if bytes[i] == b'<' {
                if !current_text.is_empty() {
                    if let Some(ref f) = chars_fn {
                        let _ = f.call::<()>(current_text.clone());
                    }
                    current_text.clear();
                }

                if i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    if let Some(end_pos) = xml[i..].find('>') {
                        let end_tag = &xml[i + 2..i + end_pos];

                        if let Some(ref f) = end_fn {
                            let _ = f.call::<()>(end_tag.to_string());
                        }

                        depth -= 1;
                        i += end_pos + 1;
                        continue;
                    }
                }

                if let Some(tag_end) = xml[i..].find('>') {
                    let tag = &xml[i + 1..i + tag_end];

                    if !tag.starts_with('?') && !tag.starts_with('!') {
                        let (elem_name, attrs) = parse_tag(tag);

                        if let Some(ref f) = start_fn {
                            let attrs_table = lua.create_table()?;
                            for (k, v) in attrs {
                                attrs_table.set(k, v).ok();
                            }
                            let _ = f.call::<mlua::Value>((elem_name.clone(), attrs_table));
                        }

                        depth += 1;
                    }

                    i += tag_end + 1;
                    continue;
                }
            } else {
                let ch = xml.as_bytes()[i];
                current_text.push(ch as char);
            }
            i += 1;
        }

        result.set("success", true)?;
        result.set("elements", depth)?;

        Ok(result)
    })?;
    slaxml.set("parser", parser_fn)?;

    let parse_fn = lua.create_function(|lua, (xml, _callbacks): (String, Table)| {
        let result = lua.create_table()?;

        let children = lua.create_table()?;
        let mut i = 1;

        for line in xml.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                children.set(i, trimmed)?;
                i += 1;
            }
        }

        result.set("success", true)?;
        result.set("children", children)?;
        result.set("line_count", i - 1)?;

        Ok(result)
    })?;
    slaxml.set("parse", parse_fn)?;

    let version_fn = lua.create_function(|_lua, _: ()| Ok("1.0.0"))?;
    slaxml.set("version", version_fn)?;

    globals.set("slaxml", slaxml)?;
    Ok(())
}

fn parse_tag(tag: &str) -> (String, Vec<(String, String)>) {
    let tag = tag.trim_end_matches('/');

    let parts: Vec<&str> = tag.split_whitespace().collect();
    let name = parts.first().unwrap_or(&"").to_string();

    let mut attrs = Vec::new();

    if parts.len() > 1 {
        let attr_str = parts[1..].join(" ");
        let mut key = String::new();
        let mut value = String::new();
        let mut in_key = true;
        let mut in_value = false;
        let mut in_quote = false;

        for c in attr_str.chars() {
            if c == '=' && in_key {
                in_key = false;
                in_value = true;
                continue;
            }

            if c == '"' {
                in_quote = !in_quote;
                if !in_quote && !key.is_empty() {
                    attrs.push((key.clone(), value.clone()));
                    key.clear();
                    value.clear();
                    in_key = true;
                    in_value = false;
                }
                continue;
            }

            if in_key && !in_quote && (c.is_alphanumeric() || c == '-' || c == '_') {
                key.push(c);
            }

            if in_value && in_quote {
                value.push(c);
            }
        }
    }

    (name, attrs)
}
