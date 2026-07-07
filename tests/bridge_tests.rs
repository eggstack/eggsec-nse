#![cfg(feature = "nse")]

use eggsec_core::types::Severity;
use eggsec_nse::report::*;
use eggsec_output::envelope::EvidenceKind as OutputEvidenceKind;

fn compatible_report_with_evidence(evidence: Vec<NseEvidenceItem>) -> NseRunReport {
    NseRunReport::new("10.0.0.1", "test_script")
        .with_evidence(evidence)
        .compute_compatibility()
}

fn evidence_item(id: &str, kind: NseEvidenceKind, title: &str, summary: &str) -> NseEvidenceItem {
    NseEvidenceItem {
        id: id.to_string(),
        kind,
        title: title.to_string(),
        summary: summary.to_string(),
        target: "10.0.0.1".to_string(),
        port: None,
        service: None,
        confidence: "confirmed".to_string(),
        source: "test_script".to_string(),
        raw_excerpt: None,
        references: Vec::new(),
        tags: Vec::new(),
    }
}

#[test]
fn envelope_has_evidence_manifest() {
    let evidence = vec![
        evidence_item("ev-0", NseEvidenceKind::ScriptOutput, "Output", "3 lines"),
        evidence_item(
            "ev-1",
            NseEvidenceKind::CapabilityDenial,
            "Denied",
            "blocked",
        ),
    ];

    let report = compatible_report_with_evidence(evidence);
    let envelope = eggsec_nse::bridge::to_report_envelope(&report);

    // 2 evidence findings + 1 metadata finding = 3 findings
    assert_eq!(envelope.findings.len(), 3);

    // Manifest should have total_items == number of evidence items across all findings
    // Each finding has 1 evidence item, so 2 evidence items total (metadata has none)
    let manifest = &envelope.evidence_manifest;
    assert_eq!(manifest.total_items, 2);
    assert_eq!(manifest.redacted_items, 0);
}

#[test]
fn envelope_finding_categories() {
    let evidence = vec![
        evidence_item(
            "ev-0",
            NseEvidenceKind::VulnerabilitySignal,
            "Vuln",
            "SQLi detected",
        ),
        evidence_item("ev-1", NseEvidenceKind::ScriptOutput, "Output", "result"),
        evidence_item(
            "ev-2",
            NseEvidenceKind::CompatibilityWarning,
            "Warning",
            "unsupported",
        ),
    ];

    let report = compatible_report_with_evidence(evidence);
    let envelope = eggsec_nse::bridge::to_report_envelope(&report);

    // All evidence-based findings should have nse-* category prefix
    let evidence_findings: Vec<_> = envelope
        .findings
        .iter()
        .filter(|f| f.id != "metadata-nse")
        .collect();
    assert_eq!(evidence_findings.len(), 3);

    for finding in &evidence_findings {
        assert!(
            finding.category.starts_with("nse-"),
            "Finding category '{}' should start with 'nse-'",
            finding.category
        );
    }

    // Verify specific categories
    let categories: Vec<&str> = evidence_findings
        .iter()
        .map(|f| f.category.as_str())
        .collect();
    assert!(categories.contains(&"nse-vulnerability-signal"));
    assert!(categories.contains(&"nse-script-output"));
    assert!(categories.contains(&"nse-compatibility-warning"));
}

#[test]
fn envelope_multiple_evidence_items() {
    let evidence = vec![
        evidence_item(
            "ev-0",
            NseEvidenceKind::ServiceFingerprint,
            "Fingerprint",
            "nginx detected",
        ),
        evidence_item(
            "ev-1",
            NseEvidenceKind::CertificateInfo,
            "Cert",
            "self-signed cert",
        ),
        evidence_item(
            "ev-2",
            NseEvidenceKind::Misconfiguration,
            "Misconfig",
            "server info leaked",
        ),
    ];

    let report = compatible_report_with_evidence(evidence);
    let envelope = eggsec_nse::bridge::to_report_envelope(&report);

    // 3 evidence findings + 1 metadata = 4
    assert_eq!(envelope.findings.len(), 4);

    // Each evidence finding should have exactly 1 evidence item
    let evidence_findings: Vec<_> = envelope
        .findings
        .iter()
        .filter(|f| f.id != "metadata-nse")
        .collect();
    for finding in &evidence_findings {
        assert_eq!(finding.evidence.len(), 1);
    }

    // Verify all 3 evidence items mapped
    let fingerprint = envelope
        .findings
        .iter()
        .find(|f| f.category == "nse-service-fingerprint")
        .unwrap();
    assert_eq!(fingerprint.evidence[0].kind, OutputEvidenceKind::Banner);

    let cert = envelope
        .findings
        .iter()
        .find(|f| f.category == "nse-certificate-info")
        .unwrap();
    assert_eq!(cert.evidence[0].kind, OutputEvidenceKind::Certificate);

    let misconfig = envelope
        .findings
        .iter()
        .find(|f| f.category == "nse-misconfiguration")
        .unwrap();
    assert_eq!(misconfig.evidence[0].kind, OutputEvidenceKind::Generic);
}

#[test]
fn envelope_no_circular_dependencies() {
    // Build a report with multiple evidence items and verify the bridge
    // doesn't create duplicate evidence items
    let evidence = vec![
        evidence_item("ev-0", NseEvidenceKind::ScriptOutput, "Output", "data"),
        evidence_item("ev-1", NseEvidenceKind::ScriptOutput, "Output", "more data"),
        evidence_item(
            "ev-2",
            NseEvidenceKind::CapabilityDenial,
            "Denied",
            "blocked",
        ),
    ];

    let report = compatible_report_with_evidence(evidence);
    let envelope = eggsec_nse::bridge::to_report_envelope(&report);

    // Collect all evidence IDs across all findings
    let mut all_evidence_ids: Vec<&str> = Vec::new();
    for finding in &envelope.findings {
        for ev in &finding.evidence {
            all_evidence_ids.push(&ev.id);
        }
    }

    // No duplicate evidence IDs
    let unique_count = all_evidence_ids.len();
    all_evidence_ids.sort();
    all_evidence_ids.dedup();
    assert_eq!(
        all_evidence_ids.len(),
        unique_count,
        "Found duplicate evidence IDs: {:?}",
        all_evidence_ids
    );

    // Each finding should reference exactly one evidence item
    let evidence_findings: Vec<_> = envelope
        .findings
        .iter()
        .filter(|f| f.id != "metadata-nse")
        .collect();
    assert_eq!(evidence_findings.len(), 3);
    for finding in &evidence_findings {
        assert_eq!(
            finding.evidence.len(),
            1,
            "Finding '{}' has {} evidence items, expected 1",
            finding.id,
            finding.evidence.len()
        );
    }
}
