//! CVE Source Clients
//!
//! Provides multiple CVE/vulnerability data sources for the NSE vulns library.
//! Supports free sources (NVD, OSV, CISA KEV) and configurable paid sources.

pub mod cisa_kev;
pub mod nvd;
pub mod osv;
pub mod traits;

pub use cisa_kev::CisaKevClient;
pub use nvd::NvdClient;
pub use osv::OsvClient;
pub use traits::CveClient;

use parking_lot::RwLock;
use rustc_hash::FxHashMap;
use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub enum CveClientEnum {
    Nvd(NvdClient),
    Osv(OsvClient),
    CisaKev(CisaKevClient),
}

impl CveClientEnum {
    pub fn source(&self) -> CveSource {
        match self {
            CveClientEnum::Nvd(c) => c.source(),
            CveClientEnum::Osv(c) => c.source(),
            CveClientEnum::CisaKev(c) => c.source(),
        }
    }

    pub async fn lookup(&self, cve_id: &str) -> Result<Option<CveRecord>, CveError> {
        match self {
            CveClientEnum::Nvd(c) => c.lookup(cve_id).await,
            CveClientEnum::Osv(c) => c.lookup(cve_id).await,
            CveClientEnum::CisaKev(c) => c.lookup(cve_id).await,
        }
    }

    pub async fn search(&self, query: &str) -> Result<Vec<CveRecord>, CveError> {
        match self {
            CveClientEnum::Nvd(c) => c.search(query).await,
            CveClientEnum::Osv(c) => c.search(query).await,
            CveClientEnum::CisaKev(c) => c.search(query).await,
        }
    }

    pub async fn get_for_product(
        &self,
        package: &str,
        ecosystem: &str,
    ) -> Result<Vec<CveRecord>, CveError> {
        match self {
            CveClientEnum::Nvd(c) => c.get_for_product(package, ecosystem).await,
            CveClientEnum::Osv(c) => c.get_for_product(package, ecosystem).await,
            CveClientEnum::CisaKev(c) => c.get_for_product(package, ecosystem).await,
        }
    }
}

/// CVE data from any source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveRecord {
    pub id: String,
    pub description: String,
    pub severity: Option<f32>,
    pub severity_type: SeverityType,
    pub published: Option<String>,
    pub modified: Option<String>,
    pub references: Vec<String>,
    pub weaknesses: Vec<String>,
    pub configurations: Vec<String>,
    pub known_exploited: bool,
    pub vendor_advisories: Vec<VendorAdvisory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorAdvisory {
    pub vendor: String,
    pub advisory_url: String,
    pub title: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SeverityType {
    CvssV2,
    CvssV3,
    CvssV31,
    #[default]
    None,
}

/// Source configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveSourceConfig {
    pub source: CveSource,
    pub api_key: Option<String>,
    pub enabled: bool,
    pub cache_ttl_seconds: u64,
}

impl Default for CveSourceConfig {
    fn default() -> Self {
        Self {
            source: CveSource::Nvd,
            api_key: None,
            enabled: true,
            cache_ttl_seconds: 3600, // 1 hour
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CveSource {
    #[default]
    Nvd,
    Osv,
    CisaKev,
    All,
}

impl std::fmt::Display for CveSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CveSource::Nvd => write!(f, "NVD (National Vulnerability Database)"),
            CveSource::Osv => write!(f, "OSV (Open Source Vulnerabilities)"),
            CveSource::CisaKev => write!(f, "CISA KEV (Known Exploited Vulnerabilities)"),
            CveSource::All => write!(f, "All sources"),
        }
    }
}

/// Cache for CVE results
pub struct CveCache {
    records: Arc<RwLock<FxHashMap<String, (CveRecord, std::time::Instant)>>>,
    ttl: std::time::Duration,
}

impl CveCache {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            records: Arc::new(RwLock::new(FxHashMap::default())),
            ttl: std::time::Duration::from_secs(ttl_seconds),
        }
    }

    pub async fn get(&self, key: &str) -> Option<CveRecord> {
        let records = self.records.read();
        if let Some((record, time)) = records.get(key) {
            if time.elapsed() < self.ttl {
                return Some(record.clone());
            }
        }
        None
    }

    pub async fn set(&self, key: String, record: CveRecord) {
        let mut records = self.records.write();
        records.insert(key, (record, std::time::Instant::now()));
    }
}

/// Combined CVE client that queries multiple sources
pub struct CveAggregator {
    clients: Vec<CveClientEnum>,
    cache: CveCache,
}

impl CveAggregator {
    pub fn new(sources: Vec<CveSourceConfig>, cache_ttl: u64) -> Self {
        let mut clients: Vec<CveClientEnum> = Vec::new();

        for config in sources {
            if !config.enabled {
                continue;
            }

            match config.source {
                CveSource::Nvd => {
                    clients.push(CveClientEnum::Nvd(NvdClient::new(config.api_key)));
                }
                CveSource::Osv => {
                    clients.push(CveClientEnum::Osv(OsvClient::new()));
                }
                CveSource::CisaKev => {
                    clients.push(CveClientEnum::CisaKev(CisaKevClient::new()));
                }
                CveSource::All => {
                    clients.push(CveClientEnum::Nvd(NvdClient::new(config.api_key.clone())));
                    clients.push(CveClientEnum::Osv(OsvClient::new()));
                    clients.push(CveClientEnum::CisaKev(CisaKevClient::new()));
                }
            }
        }

        Self {
            clients,
            cache: CveCache::new(cache_ttl),
        }
    }

    pub async fn lookup(&self, cve_id: &str) -> Result<Option<CveRecord>, CveError> {
        // Check cache first
        if let Some(cached) = self.cache.get(cve_id).await {
            return Ok(Some(cached));
        }

        // Query all clients
        for client in &self.clients {
            if let Ok(Some(record)) = client.lookup(cve_id).await {
                self.cache.set(cve_id.to_string(), record.clone()).await;
                return Ok(Some(record));
            }
        }

        Ok(None)
    }

    pub async fn search(&self, query: &str) -> Result<Vec<CveRecord>, CveError> {
        let mut results = Vec::new();
        let mut seen = FxHashSet::default();

        for client in &self.clients {
            match client.search(query).await {
                Ok(records) => {
                    for record in records {
                        if !seen.contains(&record.id) {
                            seen.insert(record.id.clone());
                            results.push(record);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Error querying {:?}: {}", client.source(), e);
                }
            }
        }

        Ok(results)
    }

    pub async fn get_for_product(
        &self,
        package: &str,
        ecosystem: &str,
    ) -> Result<Vec<CveRecord>, CveError> {
        let mut results = Vec::new();
        let mut seen = FxHashSet::default();

        for client in &self.clients {
            match client.get_for_product(package, ecosystem).await {
                Ok(records) => {
                    for record in records {
                        if !seen.contains(&record.id) {
                            seen.insert(record.id.clone());
                            results.push(record);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Error querying {:?}: {}", client.source(), e);
                }
            }
        }

        Ok(results)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CveError {
    NotFound(String),
    RateLimited(String),
    NetworkError(String),
    ParseError(String),
    ApiError(String),
    ConfigError(String),
}

impl std::fmt::Display for CveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CveError::NotFound(s) => write!(f, "Not found: {}", s),
            CveError::RateLimited(s) => write!(f, "Rate limited: {}", s),
            CveError::NetworkError(s) => write!(f, "Network error: {}", s),
            CveError::ParseError(s) => write!(f, "Parse error: {}", s),
            CveError::ApiError(s) => write!(f, "API error: {}", s),
            CveError::ConfigError(s) => write!(f, "Config error: {}", s),
        }
    }
}

impl std::error::Error for CveError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_set_and_get() {
        let cache = CveCache::new(300);
        let record = CveRecord {
            id: "CVE-2021-44228".to_string(),
            description: "Log4Shell".to_string(),
            severity: Some(10.0),
            severity_type: SeverityType::CvssV31,
            published: None,
            modified: None,
            references: vec![],
            weaknesses: vec![],
            configurations: vec![],
            known_exploited: false,
            vendor_advisories: vec![],
        };
        cache
            .set("CVE-2021-44228".to_string(), record.clone())
            .await;
        let cached = cache.get("CVE-2021-44228").await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().id, "CVE-2021-44228");
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = CveCache::new(300);
        let result = cache.get("CVE-0000-0000").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_cache_ttl_expiry() {
        let cache = CveCache::new(0); // 0 second TTL
        let record = CveRecord {
            id: "CVE-2021-44228".to_string(),
            description: "Log4Shell".to_string(),
            severity: Some(10.0),
            severity_type: SeverityType::CvssV31,
            published: None,
            modified: None,
            references: vec![],
            weaknesses: vec![],
            configurations: vec![],
            known_exploited: false,
            vendor_advisories: vec![],
        };
        cache.set("CVE-2021-44228".to_string(), record).await;
        // With 0 TTL, record should be expired immediately
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let result = cache.get("CVE-2021-44228").await;
        assert!(result.is_none());
    }

    #[test]
    fn test_severity_type_default() {
        assert_eq!(SeverityType::default(), SeverityType::None);
    }

    #[test]
    fn test_cve_error_display() {
        assert_eq!(
            CveError::NetworkError("timeout".to_string()).to_string(),
            "Network error: timeout"
        );
        assert_eq!(
            CveError::RateLimited("slow down".to_string()).to_string(),
            "Rate limited: slow down"
        );
    }
}
