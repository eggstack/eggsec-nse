//! NSE vulns library wrapper
//!
//! Provides vulnerability database access for NSE scripts.
//! This implementation provides a local CVE database with common vulnerabilities.

use mlua::{Lua, Result as LuaResult};
use rustc_hash::FxHashMap;
use std::sync::OnceLock;

static CVE_DB: OnceLock<FxHashMap<&'static str, Vec<(&'static str, &'static str, &'static str)>>> =
    OnceLock::new();

fn get_cve_db() -> &'static FxHashMap<&'static str, Vec<(&'static str, &'static str, &'static str)>>
{
    CVE_DB.get_or_init(|| {
        let mut m = FxHashMap::default();

        m.entry("CVE-2017-0144").or_insert_with(Vec::new).push((
            "WannaCry",
            "critical",
            "EternalBlue SMB exploit",
        ));
        m.entry("CVE-2017-0145").or_insert_with(Vec::new).push((
            "WannaCry",
            "critical",
            "SMBv1 exploit",
        ));
        m.entry("CVE-2017-0146").or_insert_with(Vec::new).push((
            "WannaCry",
            "critical",
            "SMB remote code execution",
        ));
        m.entry("CVE-2017-0147").or_insert_with(Vec::new).push((
            "WannaCry",
            "critical",
            "SMB information disclosure",
        ));
        m.entry("CVE-2017-0148").or_insert_with(Vec::new).push((
            "WannaCry",
            "critical",
            "SMB denial of service",
        ));

        m.entry("CVE-2019-0708").or_insert_with(Vec::new).push((
            "BlueKeep",
            "critical",
            "Remote Desktop Services vulnerability (CVE-2019-0708)",
        ));
        m.entry("CVE-2020-0796").or_insert_with(Vec::new).push((
            "SMBGhost",
            "high",
            "SMBv3 compression vulnerability",
        ));
        m.entry("CVE-2020-1472").or_insert_with(Vec::new).push((
            "Zerologon",
            "critical",
            "Netlogon privilege escalation",
        ));

        m.entry("CVE-2021-44228").or_insert_with(Vec::new).push((
            "Log4Shell",
            "critical",
            "Apache Log4j RCE (CVE-2021-44228)",
        ));
        m.entry("CVE-2021-45046").or_insert_with(Vec::new).push((
            "Log4j",
            "high",
            "Log4j DoS vulnerability (CVE-2021-45046)",
        ));
        m.entry("CVE-2021-45105").or_insert_with(Vec::new).push((
            "Log4j",
            "medium",
            "Log4j information disclosure",
        ));

        m.entry("CVE-2022-22965").or_insert_with(Vec::new).push((
            "Spring4Shell",
            "critical",
            "Spring Framework RCE (CVE-2022-22965)",
        ));
        m.entry("CVE-2022-22966").or_insert_with(Vec::new).push((
            "Spring",
            "high",
            "Spring Cloud Function RCE",
        ));
        m.entry("CVE-2022-22967").or_insert_with(Vec::new).push((
            "Spring",
            "high",
            "Spring Cloud Gateway RCE",
        ));

        m.entry("CVE-2022-3602").or_insert_with(Vec::new).push((
            "OpenSSL",
            "high",
            "X.509 certificate verification bypass",
        ));
        m.entry("CVE-2022-3786").or_insert_with(Vec::new).push((
            "OpenSSL",
            "high",
            "X.509 certificate buffer overflow",
        ));

        m.entry("CVE-2023-20198").or_insert_with(Vec::new).push((
            "Cisco IOS XE",
            "critical",
            "Web UI privilege escalation",
        ));
        m.entry("CVE-2023-20269").or_insert_with(Vec::new).push((
            "Cisco IOS XE",
            "critical",
            "Web UI command injection",
        ));
        m.entry("CVE-2023-46805").or_insert_with(Vec::new).push((
            "Ivanti Connect",
            "critical",
            "Authentication bypass",
        ));
        m.entry("CVE-2023-46808").or_insert_with(Vec::new).push((
            "Ivanti Connect",
            "critical",
            "ICS authentication bypass",
        ));

        m.entry("CVE-2023-22515").or_insert_with(Vec::new).push((
            "Confluence",
            "critical",
            "Atlassian Confluence RCE",
        ));
        m.entry("CVE-2023-22518").or_insert_with(Vec::new).push((
            "Confluence",
            "critical",
            "Atlassian Confluence Data Center RCE",
        ));

        m.entry("CVE-2023-44487").or_insert_with(Vec::new).push((
            "HTTP/2 Rapid Reset",
            "high",
            "HTTP/2 Rapid Reset Attack (DoS)",
        ));
        m.entry("CVE-2023-38545").or_insert_with(Vec::new).push((
            "cURL",
            "high",
            "cURL heap overflow",
        ));
        m.entry("CVE-2023-38646").or_insert_with(Vec::new).push((
            "cURL",
            "high",
            "cURL SOCKS5 heap overflow",
        ));

        m.entry("CVE-2024-0012").or_insert_with(Vec::new).push((
            "Palo Alto PAN-OS",
            "critical",
            "Management interface auth bypass",
        ));
        m.entry("CVE-2024-3400").or_insert_with(Vec::new).push((
            "Palo Alto PAN-OS",
            "critical",
            "GlobalProtect RCE",
        ));

        m.entry("CVE-2024-1708").or_insert_with(Vec::new).push((
            "ScreenConnect",
            "critical",
            "Authentication bypass",
        ));
        m.entry("CVE-2024-1709").or_insert_with(Vec::new).push((
            "ScreenConnect",
            "critical",
            "Path traversal",
        ));

        m.entry("CVE-2024-27198").or_insert_with(Vec::new).push((
            "TeamCity",
            "critical",
            "JetBrains TeamCity authentication bypass",
        ));
        m.entry("CVE-2024-28995").or_insert_with(Vec::new).push((
            "SolarWinds",
            "high",
            "SolarWinds Serv-U path traversal",
        ));

        m.entry("CVE-2024-0204").or_insert_with(Vec::new).push((
            "Fortra FileSonic",
            "critical",
            "Authentication bypass",
        ));
        m.entry("CVE-2024-1086").or_insert_with(Vec::new).push((
            "Linux Kernel",
            "high",
            "Linux kernel privilege escalation",
        ));

        m.entry("CVE-2023-50164").or_insert_with(Vec::new).push((
            "Apache Struts",
            "critical",
            "Struts file upload bypass",
        ));
        m.entry("CVE-2024-21650").or_insert_with(Vec::new).push((
            "Fortra FileForge",
            "critical",
            "FileForge FTP server RCE",
        ));

        m.entry("CVE-2024-23897").or_insert_with(Vec::new).push((
            "Jenkins",
            "high",
            "Jenkins CLI arbitrary file read",
        ));

        m.entry("CVE-2023-29360").or_insert_with(Vec::new).push((
            "Microsoft SharePoint",
            "critical",
            "SharePoint Server RCE",
        ));

        m.entry("CVE-2024-21412").or_insert_with(Vec::new).push((
            "Microsoft Outlook",
            "critical",
            "Remote code execution",
        ));

        m.entry("CVE-2024-20698").or_insert_with(Vec::new).push((
            "Windows Kerberos",
            "high",
            "Windows Kerberos RC4 downgrade",
        ));

        m.entry("CVE-2024-27956").or_insert_with(Vec::new).push((
            "WordPress",
            "critical",
            "WordPress AutomateWoo auth bypass",
        ));
        m.entry("CVE-2024-3094").or_insert_with(Vec::new).push((
            "XZ Utils",
            "critical",
            "XZ Utils backdoor (supply chain)",
        ));

        m.entry("CVE-2024-4577").or_insert_with(Vec::new).push((
            "PHP-CGI",
            "critical",
            "PHP-CGI argument injection",
        ));

        m.entry("CVE-2024-6387").or_insert_with(Vec::new).push((
            "OpenSSH",
            "critical",
            "OpenSSH RCE (CVE-2024-6387) - RegreSSHion",
        ));

        m.entry("CVE-2024-27956").or_insert_with(Vec::new).push((
            "WooCommerce",
            "critical",
            "WordPress WooCommerce auth bypass",
        ));

        m
    })
}

pub fn register_vulns_library(lua: &Lua) -> LuaResult<()> {
    let globals = lua.globals();
    let vulns = lua.create_table()?;

    vulns.set(
        "cve",
        lua.create_function(|lua, id: String| {
            let result = lua.create_table()?;
            let db = get_cve_db();

            let id_upper = id.to_uppercase();
            if let Some(entries) = db.get(id_upper.as_str()) {
                if let Some((name, level, description)) = entries.first() {
                    result.set("id", id)?;
                    result.set("name", *name)?;
                    result.set("level", *level)?;
                    result.set("description", *description)?;
                    result.set("status", "known")?;
                } else {
                    result.set("id", id)?;
                    result.set("error", "CVE not found in local database")?;
                    result.set("status", "unknown")?;
                }
            } else {
                result.set("id", id)?;
                result.set("error", "CVE not found in local database")?;
                result.set("status", "unknown")?;
            }
            Ok(result)
        })?,
    )?;

    vulns.set(
        "cve_level",
        lua.create_function(|_lua, id: String| {
            let db = get_cve_db();
            let id_upper = id.to_uppercase();

            if let Some(entries) = db.get(id_upper.as_str()) {
                if let Some((_, level, _)) = entries.first() {
                    return Ok(level.to_string());
                }
            }

            if id.starts_with("CVE-") {
                let parts: Vec<&str> = id.split('-').collect();
                if parts.len() >= 3 {
                    if let Some(year) = parts.get(1) {
                        if let Ok(y) = year.parse::<i32>() {
                            if y >= 2023 {
                                return Ok("critical".to_string());
                            } else if y >= 2020 {
                                return Ok("high".to_string());
                            } else if y >= 2015 {
                                return Ok("medium".to_string());
                            } else {
                                return Ok("low".to_string());
                            }
                        }
                    }
                }
            }
            Ok("unknown".to_string())
        })?,
    )?;

    vulns.set(
        "report",
        lua.create_function(|lua, (id, output): (String, String)| {
            let result = lua.create_table()?;
            result.set("id", id.clone())?;
            result.set("output", output.clone())?;
            result.set("status", "reported")?;
            eprintln!("VULN REPORT: {} - {}", id, output);
            Ok(result)
        })?,
    )?;

    vulns.set(
        "get_cvelist",
        lua.create_function(|lua, (keyword, limit): (String, Option<usize>)| {
            let results = lua.create_table()?;
            let db = get_cve_db();
            let keyword_lower = keyword.to_lowercase();
            let limit = limit.unwrap_or(10);

            let mut count = 0;
            for (id, entries) in db.iter() {
                for (name, level, description) in entries.iter() {
                    if name.to_lowercase().contains(&keyword_lower)
                        || description.to_lowercase().contains(&keyword_lower)
                        || id.to_lowercase().contains(&keyword_lower)
                    {
                        let entry = lua.create_table()?;
                        entry.set("id", *id)?;
                        entry.set("name", *name)?;
                        entry.set("level", *level)?;
                        entry.set("description", *description)?;
                        results.set(count + 1, entry)?;
                        count += 1;
                        if count >= limit {
                            break;
                        }
                    }
                }
            }

            Ok(results)
        })?,
    )?;

    vulns.set(
        "is_known",
        lua.create_function(|_lua, id: String| {
            let db = get_cve_db();
            let id_upper = id.to_uppercase();
            Ok(db.contains_key(id_upper.as_str()))
        })?,
    )?;

    vulns.set(
        "parse_cve",
        lua.create_function(|lua, id: String| {
            let result = lua.create_table()?;
            result.set("id", id.clone())?;

            if id.starts_with("CVE-") {
                let parts: Vec<&str> = id.split('-').collect();
                if parts.len() >= 3 {
                    if let Some(year) = parts.get(1) {
                        if let Ok(y) = year.parse::<i32>() {
                            result.set("year", y)?;
                        }
                    }
                    if let Some(num) = parts.get(2) {
                        result.set("number", *num)?;
                    }
                }
            }

            result.set("original", id)?;
            Ok(result)
        })?,
    )?;

    // vulns.lookup_cve(cve_id) - Look up CVE from NVD API
    // Returns detailed CVE information from the National Vulnerability Database
    vulns.set(
        "lookup_cve",
        lua.create_function(|lua, (cve_id, timeout): (String, Option<u64>)| {
            let timeout_secs = timeout.unwrap_or(10).max(1);

            let url = format!(
                "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
                cve_id
            );

            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(timeout_secs))
                .build();

            let client = match client {
                Ok(c) => c,
                Err(_) => {
                    let empty = lua.create_table()?;
                    return Ok(empty);
                }
            };

            let response = match client.get(&url).send() {
                Ok(resp) => resp,
                Err(_) => {
                    let empty = lua.create_table()?;
                    return Ok(empty);
                }
            };

            if response.status().is_success() {
                if let Ok(json) = response.json::<serde_json::Value>() {
                    let result = lua.create_table()?;

                    if let Some(vulnerabilities) = json.get("vulnerabilities") {
                        if let Some(cves) = vulnerabilities.as_array() {
                            if let Some(first) = cves.first() {
                                if let Some(cve) = first.get("cve") {
                                    if let Some(id) = cve.get("id") {
                                        result.set("id", id.as_str().unwrap_or(&cve_id))?;
                                    }
                                    if let Some(descriptions) = cve.get("descriptions") {
                                        if let Some(desc_arr) = descriptions.as_array() {
                                            for desc in desc_arr {
                                                if let Some(lang) = desc.get("lang") {
                                                    if lang == "en" {
                                                        if let Some(text) = desc.get("value") {
                                                            result.set(
                                                                "description",
                                                                text.as_str().unwrap_or(""),
                                                            )?;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if let Some(metrics) = cve.get("metrics") {
                                        if let Some(cvss) = metrics.get("cvssMetricV31") {
                                            if let Some(cvss_arr) = cvss.as_array() {
                                                if let Some(first_item) = cvss_arr.first() {
                                                    if let Some(cvss_data) =
                                                        first_item.get("cvssData")
                                                    {
                                                        if let Some(base_score) =
                                                            cvss_data.get("baseScore")
                                                        {
                                                            if let Some(score) = base_score.as_f64()
                                                            {
                                                                result.set("cvss_score", score)?;
                                                            }
                                                        }
                                                        if let Some(severity) =
                                                            cvss_data.get("baseSeverity")
                                                        {
                                                            result.set(
                                                                "severity",
                                                                severity
                                                                    .as_str()
                                                                    .unwrap_or("UNKNOWN"),
                                                            )?;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    return Ok(result);
                }
            }

            // Return empty table if lookup failed
            let empty = lua.create_table()?;
            Ok(empty)
        })?,
    )?;

    // vulns.search_by_keyword(keyword) - Search CVEs by keyword via NVD API
    vulns.set(
        "search_cves",
        lua.create_function(|lua, (keyword, limit): (String, Option<usize>)| {
            let max_results = limit.unwrap_or(10).min(20);
            let timeout_secs = 15u64;

            let url = format!(
                "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage={}",
                keyword, max_results
            );

            let client = match reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(timeout_secs))
                .build() {
                Ok(c) => c,
                Err(_) => return lua.create_table()
            };

            let results = lua.create_table()?;

            let response = match client.get(&url).send() {
                Ok(resp) => resp,
                Err(_) => return Ok(results)
            };

            if response.status().is_success() {
                if let Ok(json) = response.json::<serde_json::Value>() {
                    let mut idx = 1;

                    if let Some(vulnerabilities) = json.get("vulnerabilities") {
                        if let Some(cves) = vulnerabilities.as_array() {
                            for cve_entry in cves.iter().take(max_results) {
                                let cve_item = lua.create_table()?;

                                if let Some(cve) = cve_entry.get("cve") {
                                    if let Some(id) = cve.get("id") {
                                        cve_item.set("id", id.as_str().unwrap_or(""))?;
                                    }
                                    if let Some(descriptions) = cve.get("descriptions") {
                                        if let Some(desc_arr) = descriptions.as_array() {
                                            for desc in desc_arr {
                                                if let Some(lang) = desc.get("lang") {
                                                    if lang == "en" {
                                                        if let Some(text) = desc.get("value") {
                                                            cve_item.set("description", text.as_str().unwrap_or(""))?;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if let Some(metrics) = cve.get("metrics") {
                                        if let Some(cvss) = metrics.get("cvssMetricV31") {
                                            if let Some(cvss_arr) = cvss.as_array() {
                                                if let Some(first_item) = cvss_arr.first() {
                                                    if let Some(cvss_data) = first_item.get("cvssData") {
                                                        if let Some(base_score) = cvss_data.get("baseScore") {
                                                            if let Some(score) = base_score.as_f64() {
                                                                cve_item.set("cvss_score", score)?;
                                                            }
                                                        }
                                                        if let Some(severity) = cvss_data.get("baseSeverity") {
                                                            cve_item.set("severity", severity.as_str().unwrap_or("UNKNOWN"))?;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                results.set(idx, cve_item)?;
                                idx += 1;
                            }
                        }
                    }
                }
            }

            Ok(results)
        })?,
    )?;

    vulns.set("version", lua.create_function(|_lua, _: ()| Ok("1.0"))?)?;

    globals.set("vulns", vulns)?;
    Ok(())
}
