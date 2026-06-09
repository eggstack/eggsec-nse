//! OSV (Open Source Vulnerabilities) API Client
//!
//! Free API: https://osv.dev/list
//! Documentation: https://google.github.io/osv.dev/api/

use super::{CveClient, CveError, CveRecord, CveSource, SeverityType};
use serde::{Deserialize, Serialize};

pub struct OsvClient {
    client: reqwest::Client,
    base_url: String,
}

impl OsvClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: "https://api.osv.dev/v1".to_string(),
        }
    }
}

impl Default for OsvClient {
    fn default() -> Self {
        Self::new()
    }
}

impl CveClient for OsvClient {
    fn source(&self) -> CveSource {
        CveSource::Osv
    }

    async fn lookup(&self, cve_id: &str) -> Result<Option<CveRecord>, CveError> {
        let url = format!("{}/query", self.base_url);

        let query = OsvQuery {
            commit: None,
            package: None,
            version: None,
            vuln_id: Some(cve_id.to_string()),
            page: None,
        };

        let response = self
            .client
            .post(&url)
            .json(&query)
            .send()
            .await
            .map_err(|e| CveError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(CveError::ApiError(format!(
                "OSV API error: {}",
                response.status()
            )));
        }

        let result: OsvResponse = response
            .json()
            .await
            .map_err(|e| CveError::ParseError(e.to_string()))?;

        if let Some(vulns) = result.vulns {
            if let Some(osv) = vulns.into_iter().next() {
                return Ok(Some(convert_osv_vuln(osv)));
            }
        }

        Ok(None)
    }

    async fn search(&self, query: &str) -> Result<Vec<CveRecord>, CveError> {
        let url = format!("{}/query", self.base_url);

        // Search by package name
        let search_query = OsvQuery {
            commit: None,
            package: Some(OsvPackage {
                name: query.to_string(),
                ecosystem: "".to_string(),
            }),
            version: None,
            vuln_id: None,
            page: None,
        };

        let response = self
            .client
            .post(&url)
            .json(&search_query)
            .send()
            .await
            .map_err(|e| CveError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(CveError::ApiError(format!(
                "OSV API error: {}",
                response.status()
            )));
        }

        let result: OsvResponse = response
            .json()
            .await
            .map_err(|e| CveError::ParseError(e.to_string()))?;

        let records = result
            .vulns
            .unwrap_or_default()
            .into_iter()
            .map(convert_osv_vuln)
            .collect();

        Ok(records)
    }

    async fn get_for_product(
        &self,
        package: &str,
        ecosystem: &str,
    ) -> Result<Vec<CveRecord>, CveError> {
        let url = format!("{}/query", self.base_url);

        let query = OsvQuery {
            commit: None,
            package: Some(OsvPackage {
                name: package.to_string(),
                ecosystem: ecosystem.to_string(),
            }),
            version: None,
            vuln_id: None,
            page: None,
        };

        let response = self
            .client
            .post(&url)
            .json(&query)
            .send()
            .await
            .map_err(|e| CveError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(CveError::ApiError(format!(
                "OSV API error: {}",
                response.status()
            )));
        }

        let result: OsvResponse = response
            .json()
            .await
            .map_err(|e| CveError::ParseError(e.to_string()))?;

        let records = result
            .vulns
            .unwrap_or_default()
            .into_iter()
            .map(convert_osv_vuln)
            .collect();

        Ok(records)
    }
}

#[derive(Debug, Serialize)]
struct OsvQuery {
    #[serde(rename = "commit")]
    commit: Option<String>,
    #[serde(rename = "package")]
    package: Option<OsvPackage>,
    #[serde(rename = "version")]
    version: Option<String>,
    #[serde(rename = "vulnId")]
    vuln_id: Option<String>,
    #[serde(rename = "page")]
    page: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OsvPackage {
    #[serde(rename = "name")]
    name: String,
    #[serde(rename = "ecosystem")]
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(rename = "vulns")]
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    #[serde(rename = "id")]
    id: String,
    #[serde(rename = "summary")]
    summary: Option<String>,
    #[serde(rename = "details")]
    details: Option<String>,
    #[serde(rename = "published")]
    published: Option<String>,
    #[serde(rename = "modified")]
    modified: Option<String>,
    #[serde(rename = "severity")]
    severity: Option<Vec<OsvSeverity>>,
    #[serde(rename = "affected")]
    affected: Option<Vec<OsvAffected>>,
    #[serde(rename = "references")]
    references: Option<Vec<OsvReference>>,
    #[serde(rename = "database_specific")]
    database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    severity_type: Option<String>,
    #[serde(rename = "score")]
    score: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[serde(rename = "package")]
    package: Option<OsvPackage>,
    #[serde(rename = "ranges")]
    ranges: Option<Vec<OsvRange>>,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    range_type: String,
    #[serde(rename = "events")]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    #[serde(rename = "introduced")]
    introduced: Option<String>,
    #[serde(rename = "fixed")]
    fixed: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvReference {
    #[serde(rename = "type")]
    ref_type: String,
    #[serde(rename = "url")]
    url: String,
}

fn convert_osv_vuln(vuln: OsvVuln) -> CveRecord {
    let description = vuln.summary.or(vuln.details).unwrap_or_default();

    let severity = vuln
        .severity
        .as_ref()
        .and_then(|s| s.first())
        .and_then(|s| s.score.as_ref())
        .and_then(|s| s.parse::<f32>().ok());

    let severity_type = vuln
        .severity
        .as_ref()
        .and_then(|s| s.first())
        .and_then(|s| s.severity_type.as_ref())
        .map(|t| match t.as_str() {
            "CVSS_V3" => SeverityType::CvssV3,
            "CVSS_V2" => SeverityType::CvssV2,
            _ => SeverityType::None,
        })
        .unwrap_or(SeverityType::None);

    CveRecord {
        id: vuln.id,
        description,
        severity,
        severity_type,
        published: vuln.published,
        modified: vuln.modified,
        references: vuln
            .references
            .map(|r| r.into_iter().map(|r| r.url).collect())
            .unwrap_or_default(),
        weaknesses: Vec::new(),
        configurations: Vec::new(),
        known_exploited: false,
        vendor_advisories: Vec::new(),
    }
}
