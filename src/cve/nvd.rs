//! NVD (National Vulnerability Database) API Client
//!
//! Free API: 6 requests per minute (without API key)
//! Documentation: https://nvd.nist.gov/developers/vulnerabilities

use super::{CveClient, CveError, CveRecord, CveSource, SeverityType};
use serde::Deserialize;

pub struct NvdClient {
    api_key: Option<String>,
    base_url: String,
    client: reqwest::Client,
}

impl NvdClient {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            api_key,
            base_url: "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string(),
            client: reqwest::Client::new(),
        }
    }

    fn build_request(&self, url: &str) -> reqwest::RequestBuilder {
        let mut builder = self.client.get(url);

        if let Some(ref key) = self.api_key {
            builder = builder.header("apiKey", key);
        }

        builder
    }
}

impl CveClient for NvdClient {
    fn source(&self) -> CveSource {
        CveSource::Nvd
    }

    async fn lookup(&self, cve_id: &str) -> Result<Option<CveRecord>, CveError> {
        let url = format!("{}?cveId={}", self.base_url, cve_id);

        let mut builder = self.build_request(&url);
        builder = builder.header("Accept", "application/json");

        let response = builder
            .send()
            .await
            .map_err(|e| CveError::NetworkError(e.to_string()))?;

        if response.status() == 404 {
            return Ok(None);
        }

        if response.status() == 403 || response.status() == 429 {
            return Err(CveError::RateLimited(
                "NVD API rate limit exceeded".to_string(),
            ));
        }

        if !response.status().is_success() {
            return Err(CveError::ApiError(format!(
                "NVD API error: {}",
                response.status()
            )));
        }

        let data: NvdResponse = response
            .json()
            .await
            .map_err(|e| CveError::ParseError(e.to_string()))?;

        if let Some(item) = data.vulnerabilities.into_iter().next() {
            Ok(Some(convert_nvd_cve(item.cve)))
        } else {
            Ok(None)
        }
    }

    async fn search(&self, query: &str) -> Result<Vec<CveRecord>, CveError> {
        let url = format!(
            "{}?keywordSearch={}",
            self.base_url,
            urlencoding::encode(query)
        );

        let mut builder = self.build_request(&url);
        builder = builder.header("Accept", "application/json");

        let response = builder
            .send()
            .await
            .map_err(|e| CveError::NetworkError(e.to_string()))?;

        if response.status() == 403 || response.status() == 429 {
            return Err(CveError::RateLimited(
                "NVD API rate limit exceeded".to_string(),
            ));
        }

        if !response.status().is_success() {
            return Err(CveError::ApiError(format!(
                "NVD API error: {}",
                response.status()
            )));
        }

        let data: NvdResponse = response
            .json()
            .await
            .map_err(|e| CveError::ParseError(e.to_string()))?;

        let mut results = Vec::new();
        for vuln in data.vulnerabilities {
            results.push(convert_nvd_cve(vuln.cve));
        }

        Ok(results)
    }

    async fn get_for_product(
        &self,
        product: &str,
        _ecosystem: &str,
    ) -> Result<Vec<CveRecord>, CveError> {
        // Use CPE (Common Platform Enumeration) search
        // NVD uses cpeName for product matching
        let cpe_query = format!("cpeName:*:*:*:*:{}:*", urlencoding::encode(product));
        let url = format!("{}?cpeName={}", self.base_url, cpe_query);

        let mut builder = self.build_request(&url);
        builder = builder.header("Accept", "application/json");

        let response = builder
            .send()
            .await
            .map_err(|e| CveError::NetworkError(e.to_string()))?;

        if response.status() == 403 || response.status() == 429 {
            return Err(CveError::RateLimited(
                "NVD API rate limit exceeded".to_string(),
            ));
        }

        if !response.status().is_success() {
            return Err(CveError::ApiError(format!(
                "NVD API error: {}",
                response.status()
            )));
        }

        let data: NvdResponse = response
            .json()
            .await
            .map_err(|e| CveError::ParseError(e.to_string()))?;

        let mut results = Vec::new();
        for vuln in data.vulnerabilities {
            results.push(convert_nvd_cve(vuln.cve));
        }

        Ok(results)
    }
}

#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(rename = "vulnerabilities")]
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    #[serde(rename = "cve")]
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    #[serde(rename = "id")]
    id: String,
    #[serde(rename = "descriptions")]
    descriptions: Vec<NvdDescription>,
    #[serde(rename = "published")]
    published: Option<String>,
    #[serde(rename = "lastModified")]
    last_modified: Option<String>,
    #[serde(rename = "metrics")]
    metrics: Option<NvdMetrics>,
    #[serde(rename = "references")]
    references: Option<Vec<NvdReference>>,
    #[serde(rename = "weaknesses")]
    weaknesses: Option<Vec<NvdWeakness>>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    #[serde(rename = "lang")]
    lang: String,
    #[serde(rename = "value")]
    value: String,
}

#[derive(Debug, Deserialize)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV31")]
    cvss_v31: Option<Vec<NvdCvss>>,
    #[serde(rename = "cvssMetricV30")]
    cvss_v30: Option<Vec<NvdCvss>>,
    #[serde(rename = "cvssMetricV2")]
    cvss_v2: Option<Vec<NvdCvssV2>>,
}

#[derive(Debug, Deserialize)]
struct NvdCvss {
    #[serde(rename = "cvssData")]
    cvss_data: NvdCvssData,
}

#[derive(Debug, Deserialize)]
struct NvdCvssData {
    #[serde(rename = "baseScore")]
    base_score: Option<f32>,
    #[serde(rename = "baseSeverity")]
    base_severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdCvssV2 {
    #[serde(rename = "cvssData")]
    cvss_data: NvdCvssDataV2,
}

#[derive(Debug, Deserialize)]
struct NvdCvssDataV2 {
    #[serde(rename = "baseScore")]
    base_score: Option<f32>,
    #[serde(rename = "severity")]
    severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdReference {
    #[serde(rename = "url")]
    url: String,
    #[serde(rename = "source")]
    source: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdWeakness {
    #[serde(rename = "description")]
    description: Vec<NvdDescription>,
}

fn extract_references(cve: &NvdCve) -> Vec<String> {
    cve.references
        .as_ref()
        .map(|r| r.iter().map(|r| r.url.clone()).collect())
        .unwrap_or_default()
}

fn extract_weaknesses(cve: &NvdCve) -> Vec<String> {
    cve.weaknesses
        .as_ref()
        .map(|w| {
            w.iter()
                .flat_map(|w| w.description.iter())
                .filter(|d| d.lang == "en")
                .map(|d| d.value.clone())
                .collect()
        })
        .unwrap_or_default()
}

fn convert_nvd_cve(cve: NvdCve) -> CveRecord {
    let description = cve
        .descriptions
        .iter()
        .find(|d| d.lang == "en")
        .map(|d| d.value.clone())
        .unwrap_or_default();

    let references = extract_references(&cve);
    let weaknesses = extract_weaknesses(&cve);

    let (severity, severity_type) = if let Some(metrics) = &cve.metrics {
        if let Some(v31) = &metrics.cvss_v31 {
            if let Some(cvss) = v31.first() {
                return CveRecord {
                    id: cve.id,
                    description,
                    severity: cvss.cvss_data.base_score,
                    severity_type: SeverityType::CvssV31,
                    published: cve.published,
                    modified: cve.last_modified,
                    references,
                    weaknesses,
                    configurations: Vec::new(),
                    known_exploited: false,
                    vendor_advisories: Vec::new(),
                };
            }
        }

        if let Some(v30) = &metrics.cvss_v30 {
            if let Some(cvss) = v30.first() {
                return CveRecord {
                    id: cve.id,
                    description,
                    severity: cvss.cvss_data.base_score,
                    severity_type: SeverityType::CvssV3,
                    published: cve.published,
                    modified: cve.last_modified,
                    references,
                    weaknesses,
                    configurations: Vec::new(),
                    known_exploited: false,
                    vendor_advisories: Vec::new(),
                };
            }
        }

        if let Some(v2) = &metrics.cvss_v2 {
            if let Some(cvss) = v2.first() {
                return CveRecord {
                    id: cve.id,
                    description,
                    severity: cvss.cvss_data.base_score,
                    severity_type: SeverityType::CvssV2,
                    published: cve.published,
                    modified: cve.last_modified,
                    references,
                    weaknesses,
                    configurations: Vec::new(),
                    known_exploited: false,
                    vendor_advisories: Vec::new(),
                };
            }
        }

        (None, SeverityType::None)
    } else {
        (None, SeverityType::None)
    };

    CveRecord {
        id: cve.id,
        description,
        severity,
        severity_type,
        published: cve.published,
        modified: cve.last_modified,
        references,
        weaknesses,
        configurations: Vec::new(),
        known_exploited: false,
        vendor_advisories: Vec::new(),
    }
}
