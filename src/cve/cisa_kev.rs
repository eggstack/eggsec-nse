//! CISA Known Exploited Vulnerabilities (KEV) Catalog Client
//!
//! Free data: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
//! Updated frequently with actively exploited vulns

use super::{CveClient, CveError, CveRecord, CveSource, SeverityType, VendorAdvisory};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct CisaKevClient {
    client: reqwest::Client,
    base_url: String,
    catalog: Arc<RwLock<Option<Vec<CisaKevEntry>>>>,
    last_fetch: Arc<RwLock<Option<std::time::Instant>>>,
}

impl CisaKevClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json".to_string(),
            catalog: Arc::new(RwLock::new(None)),
            last_fetch: Arc::new(RwLock::new(None)),
        }
    }

    async fn fetch_catalog(&self) -> Result<(), CveError> {
        // Check if recent fetch exists (read lock only, dropped before network I/O)
        {
            let last_fetch = self.last_fetch.read().await;
            if let Some(last) = *last_fetch {
                if last.elapsed() < std::time::Duration::from_secs(86400) {
                    return Ok(());
                }
            }
        }

        // Network I/O happens outside any lock
        let response = self
            .client
            .get(&self.base_url)
            .send()
            .await
            .map_err(|e| CveError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(CveError::ApiError(format!(
                "CISA KEV API error: {}",
                response.status()
            )));
        }

        let catalog: CisaKevCatalog = response
            .json()
            .await
            .map_err(|e| CveError::ParseError(e.to_string()))?;

        // Acquire write locks only after network I/O completes
        *self.catalog.write().await = Some(catalog.vulnerabilities);
        *self.last_fetch.write().await = Some(std::time::Instant::now());

        Ok(())
    }
}

impl Default for CisaKevClient {
    fn default() -> Self {
        Self::new()
    }
}

impl CveClient for CisaKevClient {
    fn source(&self) -> CveSource {
        CveSource::CisaKev
    }

    async fn lookup(&self, cve_id: &str) -> Result<Option<CveRecord>, CveError> {
        self.fetch_catalog().await?;

        let catalog = self.catalog.read().await;
        if let Some(entries) = catalog.as_ref() {
            for entry in entries {
                if entry.cve_id.to_uppercase() == cve_id.to_uppercase() {
                    return Ok(Some(CveRecord {
                        id: entry.cve_id.clone(),
                        description: entry.short_description.clone(),
                        severity: None,
                        severity_type: SeverityType::None,
                        published: Some(entry.date_added.clone()),
                        modified: None,
                        references: vec![format!(
                            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?cve={}",
                            cve_id
                        )],
                        weaknesses: Vec::new(),
                        configurations: Vec::new(),
                        known_exploited: true,
                        vendor_advisories: vec![VendorAdvisory {
                            vendor: entry.vendor_project.clone(),
                            advisory_url: String::new(),
                            title: Some(entry.vulnerability_name.clone()),
                        }],
                    }));
                }
            }
        }

        Ok(None)
    }

    async fn search(&self, query: &str) -> Result<Vec<CveRecord>, CveError> {
        self.fetch_catalog().await?;

        let catalog = self.catalog.read().await;
        let mut results = Vec::new();
        let query_lower = query.to_lowercase();

        if let Some(entries) = catalog.as_ref() {
            for entry in entries {
                if entry.cve_id.to_lowercase().contains(&query_lower)
                    || entry.product.to_lowercase().contains(&query_lower)
                    || entry.vendor_project.to_lowercase().contains(&query_lower)
                    || entry
                        .short_description
                        .to_lowercase()
                        .contains(&query_lower)
                {
                    results.push(CveRecord {
                        id: entry.cve_id.clone(),
                        description: entry.short_description.clone(),
                        severity: None,
                        severity_type: SeverityType::None,
                        published: Some(entry.date_added.clone()),
                        modified: None,
                        references: vec![format!(
                            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?cve={}",
                            entry.cve_id
                        )],
                        weaknesses: Vec::new(),
                        configurations: Vec::new(),
                        known_exploited: true,
                        vendor_advisories: vec![VendorAdvisory {
                            vendor: entry.vendor_project.clone(),
                            advisory_url: String::new(),
                            title: Some(entry.vulnerability_name.clone()),
                        }],
                    });
                }
            }
        }

        Ok(results)
    }

    async fn get_for_product(
        &self,
        package: &str,
        _ecosystem: &str,
    ) -> Result<Vec<CveRecord>, CveError> {
        self.fetch_catalog().await?;

        let catalog = self.catalog.read().await;
        let mut results = Vec::new();
        let package_lower = package.to_lowercase();

        if let Some(entries) = catalog.as_ref() {
            for entry in entries {
                if entry.product.to_lowercase().contains(&package_lower)
                    || entry.vendor_project.to_lowercase().contains(&package_lower)
                {
                    results.push(CveRecord {
                        id: entry.cve_id.clone(),
                        description: entry.short_description.clone(),
                        severity: None,
                        severity_type: SeverityType::None,
                        published: Some(entry.date_added.clone()),
                        modified: None,
                        references: vec![format!(
                            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?cve={}",
                            entry.cve_id
                        )],
                        weaknesses: Vec::new(),
                        configurations: Vec::new(),
                        known_exploited: true,
                        vendor_advisories: vec![VendorAdvisory {
                            vendor: entry.vendor_project.clone(),
                            advisory_url: String::new(),
                            title: Some(entry.vulnerability_name.clone()),
                        }],
                    });
                }
            }
        }

        Ok(results)
    }
}

#[derive(Debug, Deserialize)]
struct CisaKevCatalog {
    #[serde(rename = "title")]
    title: String,
    #[serde(rename = "catalogVersion")]
    catalog_version: String,
    #[serde(rename = "dateReleased")]
    date_released: String,
    #[serde(rename = "vulnerabilities")]
    vulnerabilities: Vec<CisaKevEntry>,
}

#[derive(Debug, Deserialize)]
struct CisaKevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "vendorProject")]
    vendor_project: String,
    #[serde(rename = "product")]
    product: String,
    #[serde(rename = "vulnerabilityName")]
    vulnerability_name: String,
    #[serde(rename = "dateAdded")]
    date_added: String,
    #[serde(rename = "shortDescription")]
    short_description: String,
    #[serde(rename = "requiredAction")]
    required_action: String,
    #[serde(rename = "dueDate")]
    due_date: String,
    #[serde(rename = "knownRansomwareCampaignUse")]
    known_ransomware_campaign_use: Option<String>,
}
