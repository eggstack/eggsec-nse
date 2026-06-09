//! CVE Client Traits

use super::{CveError, CveRecord, CveSource};

/// Trait for CVE data sources
pub trait CveClient: Send + Sync {
    /// Get source name
    fn source(&self) -> CveSource;

    /// Lookup CVE by ID
    fn lookup(
        &self,
        cve_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<CveRecord>, CveError>> + Send;

    /// Search CVEs by keyword
    fn search(
        &self,
        query: &str,
    ) -> impl std::future::Future<Output = Result<Vec<CveRecord>, CveError>> + Send;

    /// Get vulnerabilities for a product/package
    fn get_for_product(
        &self,
        package: &str,
        ecosystem: &str,
    ) -> impl std::future::Future<Output = Result<Vec<CveRecord>, CveError>> + Send;
}
