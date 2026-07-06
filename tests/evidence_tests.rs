#![cfg(feature = "nse")]

use eggsec_nse::report::*;

fn empty_compatibility() -> NseCompatibilitySummary {
    NseCompatibilitySummary {
        status: NseRunCompatibilityStatus::Unknown,
        fidelity: NseRunFidelity::Unknown,
        unsupported_features: Vec::new(),
        approximations: Vec::new(),
    }
}

fn empty_output() -> NseOutputSummary {
    NseOutputSummary {
        has_output: false,
        content: String::new(),
        line_count: 0,
        truncated: false,
    }
}

#[test]
fn evidence_extraction_empty_report() {
    let evidence = extract_evidence(
        "192.168.1.1",
        "test_script",
        &[],
        &empty_compatibility(),
        &[],
        &empty_output(),
    );
    assert!(evidence.is_empty());
}

#[test]
fn evidence_extraction_capability_denial() {
    let events = vec![NseCapabilityEventSummary {
        kind: "process_exec".to_string(),
        operation: "io.popen".to_string(),
        target: Some("ls".to_string()),
        allowed: false,
        reason: Some("denied by AgentSafe policy".to_string()),
    }];

    let evidence = extract_evidence(
        "192.168.1.1",
        "test_script",
        &events,
        &empty_compatibility(),
        &[],
        &empty_output(),
    );

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].kind, NseEvidenceKind::CapabilityDenial);
    assert_eq!(evidence[0].confidence, "confirmed");
    assert!(evidence[0].tags.contains(&"capability".to_string()));
    assert!(evidence[0].tags.contains(&"process_exec".to_string()));
    assert_eq!(evidence[0].target, "ls");
}

#[test]
fn evidence_extraction_compatibility_warning() {
    let compat = NseCompatibilitySummary {
        status: NseRunCompatibilityStatus::Partial,
        fidelity: NseRunFidelity::Minimal,
        unsupported_features: vec!["nmap.socket".to_string(), "stdnse.sleep".to_string()],
        approximations: Vec::new(),
    };

    let evidence = extract_evidence(
        "10.0.0.1",
        "test_script",
        &[],
        &compat,
        &[],
        &empty_output(),
    );

    assert_eq!(evidence.len(), 2);
    assert!(evidence
        .iter()
        .all(|e| e.kind == NseEvidenceKind::CompatibilityWarning));
    assert!(evidence.iter().all(|e| e.confidence == "confirmed"));
    assert!(evidence[0].title.contains("nmap.socket"));
    assert!(evidence[1].title.contains("stdnse.sleep"));
}

#[test]
fn evidence_extraction_approximate_rules() {
    let compat = NseCompatibilitySummary {
        status: NseRunCompatibilityStatus::CompatibleWithWarnings,
        fidelity: NseRunFidelity::Approximate,
        unsupported_features: Vec::new(),
        approximations: vec!["portrule: synthetic host context".to_string()],
    };

    let evidence = extract_evidence(
        "10.0.0.1",
        "test_script",
        &[],
        &compat,
        &[],
        &empty_output(),
    );

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].kind, NseEvidenceKind::CompatibilityWarning);
    assert_eq!(evidence[0].confidence, "likely");
    assert!(evidence[0].tags.contains(&"approximate".to_string()));
}

#[test]
fn evidence_extraction_rule_error() {
    let rules = vec![NseRuleEvaluationReport {
        kind: "portrule".to_string(),
        evaluated: false,
        matched: false,
        exactness: "exact".to_string(),
        error: Some("lua runtime error: attempt to call nil".to_string()),
        summary: "rule error: lua runtime error".to_string(),
        unsupported: None,
        host_context_source: None,
        port_context_source: None,
        service_context_available: None,
        fidelity_reason: None,
    }];

    let evidence = extract_evidence(
        "10.0.0.1",
        "test_script",
        &[],
        &empty_compatibility(),
        &rules,
        &empty_output(),
    );

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].kind, NseEvidenceKind::CompatibilityWarning);
    assert_eq!(evidence[0].confidence, "confirmed");
    assert!(evidence[0].tags.contains(&"rule-error".to_string()));
}

#[test]
fn evidence_extraction_script_output() {
    let output = NseOutputSummary {
        has_output: true,
        content: "HTTP/1.1 200 OK\nServer: nginx/1.18.0".to_string(),
        line_count: 2,
        truncated: false,
    };

    let evidence = extract_evidence(
        "10.0.0.1",
        "test_script",
        &[],
        &empty_compatibility(),
        &[],
        &output,
    );

    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].kind, NseEvidenceKind::ScriptOutput);
    assert_eq!(evidence[0].confidence, "confirmed");
    assert!(evidence[0].raw_excerpt.is_some());
    assert!(evidence[0].tags.contains(&"output".to_string()));
}

#[test]
fn evidence_extraction_combined() {
    let events = vec![NseCapabilityEventSummary {
        kind: "filesystem_write".to_string(),
        operation: "io.write".to_string(),
        target: Some("/tmp/test".to_string()),
        allowed: false,
        reason: Some("denied by CiSafe policy".to_string()),
    }];

    let compat = NseCompatibilitySummary {
        status: NseRunCompatibilityStatus::Partial,
        fidelity: NseRunFidelity::Approximate,
        unsupported_features: vec!["nmap.socket".to_string()],
        approximations: vec!["portrule: synthetic context".to_string()],
    };

    let rules = vec![NseRuleEvaluationReport {
        kind: "portrule".to_string(),
        evaluated: false,
        matched: false,
        exactness: "exact".to_string(),
        error: Some("timeout".to_string()),
        summary: "rule error: timeout".to_string(),
        unsupported: None,
        host_context_source: None,
        port_context_source: None,
        service_context_available: None,
        fidelity_reason: None,
    }];

    let output = NseOutputSummary {
        has_output: true,
        content: "some output".to_string(),
        line_count: 1,
        truncated: false,
    };

    let evidence = extract_evidence("10.0.0.1", "test_script", &events, &compat, &rules, &output);

    // 1 capability denial + 1 unsupported + 1 approximate + 1 rule error + 1 script output = 5
    assert_eq!(evidence.len(), 5);

    let denial_count = evidence
        .iter()
        .filter(|e| e.kind == NseEvidenceKind::CapabilityDenial)
        .count();
    assert_eq!(denial_count, 1);

    let warning_count = evidence
        .iter()
        .filter(|e| e.kind == NseEvidenceKind::CompatibilityWarning)
        .count();
    assert_eq!(warning_count, 3);

    let output_count = evidence
        .iter()
        .filter(|e| e.kind == NseEvidenceKind::ScriptOutput)
        .count();
    assert_eq!(output_count, 1);
}

#[test]
fn evidence_serialization_roundtrip() {
    let events = vec![NseCapabilityEventSummary {
        kind: "process_exec".to_string(),
        operation: "io.popen".to_string(),
        target: Some("ls".to_string()),
        allowed: false,
        reason: Some("denied".to_string()),
    }];

    let evidence = extract_evidence(
        "192.168.1.1",
        "test_script",
        &events,
        &empty_compatibility(),
        &[],
        &empty_output(),
    );

    let json = serde_json::to_string(&evidence).unwrap();
    let deserialized: Vec<NseEvidenceItem> = serde_json::from_str(&json).unwrap();
    assert_eq!(evidence, deserialized);
}

#[test]
fn evidence_builder_with_evidence() {
    let report = NseRunReport::new("10.0.0.1", "test_script");
    assert!(report.evidence.is_empty());

    let evidence = vec![NseEvidenceItem {
        id: "nse-ev-0".to_string(),
        kind: NseEvidenceKind::ScriptOutput,
        title: "Test".to_string(),
        summary: "Test summary".to_string(),
        target: "10.0.0.1".to_string(),
        port: Some(80),
        service: Some("http".to_string()),
        confidence: "confirmed".to_string(),
        source: "test_script".to_string(),
        raw_excerpt: None,
        references: Vec::new(),
        tags: Vec::new(),
    }];

    let report = report.with_evidence(evidence);
    assert_eq!(report.evidence.len(), 1);
    assert_eq!(report.evidence[0].port, Some(80));
    assert_eq!(report.evidence[0].service, Some("http".to_string()));
}

#[test]
fn bridge_to_envelope_basic() {
    let report = NseRunReport::new("10.0.0.1", "ssl-cert")
        .with_evidence(vec![NseEvidenceItem {
            id: "nse-ev-0".to_string(),
            kind: NseEvidenceKind::ScriptOutput,
            title: "Script output captured".to_string(),
            summary: "3 lines of output".to_string(),
            target: "10.0.0.1".to_string(),
            port: None,
            service: None,
            confidence: "confirmed".to_string(),
            source: "ssl-cert".to_string(),
            raw_excerpt: Some("test output".to_string()),
            references: Vec::new(),
            tags: vec!["output".to_string()],
        }])
        .compute_compatibility();

    let envelope = eggsec_nse::bridge::to_report_envelope(&report);

    // Should have 1 evidence finding + 1 metadata finding = 2 findings
    assert_eq!(envelope.findings.len(), 2);
    assert_eq!(envelope.domain_id.as_deref(), Some("nse"));
    assert_eq!(envelope.target.as_deref(), Some("10.0.0.1"));
}

#[test]
fn bridge_to_envelope_empty_evidence() {
    let report = NseRunReport::new("10.0.0.1", "test_script").compute_compatibility();

    let envelope = eggsec_nse::bridge::to_report_envelope(&report);

    // Should have only the metadata finding
    assert_eq!(envelope.findings.len(), 1);
    assert_eq!(envelope.findings[0].id, "metadata-nse");
}

#[test]
fn evidence_confidence_values() {
    let events = vec![
        NseCapabilityEventSummary {
            kind: "process_exec".to_string(),
            operation: "io.popen".to_string(),
            target: None,
            allowed: false,
            reason: None,
        },
        NseCapabilityEventSummary {
            kind: "filesystem_write".to_string(),
            operation: "io.write".to_string(),
            target: None,
            allowed: false,
            reason: Some("denied".to_string()),
        },
    ];

    let compat = NseCompatibilitySummary {
        status: NseRunCompatibilityStatus::Partial,
        fidelity: NseRunFidelity::Approximate,
        unsupported_features: vec!["test_module".to_string()],
        approximations: vec!["test_approx".to_string()],
    };

    let evidence = extract_evidence(
        "10.0.0.1",
        "test_script",
        &events,
        &compat,
        &[],
        &empty_output(),
    );

    let valid_confidences = ["confirmed", "likely", "possible", "low"];
    for ev in &evidence {
        assert!(
            valid_confidences.contains(&ev.confidence.as_str()),
            "Invalid confidence: {}",
            ev.confidence
        );
    }
}
