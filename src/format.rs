use crate::report::NseRunReport;

pub fn format_human_report(report: &NseRunReport) -> String {
    use crate::report::{NseRunCompatibilityStatus, NseRunFidelity};
    use std::fmt::Write;

    let mut out = String::new();

    writeln!(out).unwrap();
    writeln!(out, "NSE Script Report").unwrap();
    writeln!(out, "=================").unwrap();
    writeln!(out, "  Target:    {}", report.target).unwrap();
    writeln!(out, "  Script:    {}", report.script_name).unwrap();
    writeln!(
        out,
        "  Source:    {} ({})",
        report.script_source.label, report.script_source.kind
    )
    .unwrap();
    writeln!(out, "  Profile:   {}", report.profile.kind).unwrap();
    writeln!(out, "  Elapsed:   {:.2}s", report.stats.elapsed_secs).unwrap();

    writeln!(out).unwrap();
    writeln!(out, "Compatibility").unwrap();
    writeln!(out, "-------------").unwrap();
    let status_str = match report.compatibility.status {
        NseRunCompatibilityStatus::Compatible => "COMPATIBLE",
        NseRunCompatibilityStatus::CompatibleWithWarnings => "COMPATIBLE (warnings)",
        NseRunCompatibilityStatus::Partial => "PARTIAL",
        NseRunCompatibilityStatus::Unsupported => "UNSUPPORTED",
        NseRunCompatibilityStatus::Failed => "FAILED",
        NseRunCompatibilityStatus::Unknown => "UNKNOWN",
    };
    writeln!(out, "  Status:  {}", status_str).unwrap();

    let fidelity_str = match report.compatibility.fidelity {
        NseRunFidelity::Full => "full".to_string(),
        NseRunFidelity::Approximate => "~approximate".to_string(),
        NseRunFidelity::Minimal => "~minimal".to_string(),
        NseRunFidelity::Unknown => "unknown".to_string(),
    };
    writeln!(out, "  Fidelity: {}", fidelity_str).unwrap();

    if !report.compatibility.unsupported_features.is_empty() {
        writeln!(
            out,
            "  Unsupported: {}",
            report.compatibility.unsupported_features.join(", ")
        )
        .unwrap();
    }
    if !report.compatibility.approximations.is_empty() {
        writeln!(
            out,
            "  Approximations: {}",
            report.compatibility.approximations.join(", ")
        )
        .unwrap();
    }

    if !report.rules.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "Rule Evaluation").unwrap();
        writeln!(out, "---------------").unwrap();
        for rule in &report.rules {
            let status = if rule.matched {
                "matched"
            } else if rule.evaluated {
                "no match"
            } else {
                "not evaluated"
            };
            writeln!(out, "  [{}] {} ({})", rule.kind, status, rule.exactness).unwrap();
            if !rule.summary.is_empty() {
                writeln!(out, "    {}", rule.summary).unwrap();
            }
            if let Some(ref unsupported) = rule.unsupported {
                writeln!(out, "    unsupported: {}", unsupported).unwrap();
            }
        }
    }

    if !report.libraries.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "Libraries").unwrap();
        writeln!(out, "---------").unwrap();
        for lib in &report.libraries {
            let status = if lib.loaded {
                "loaded"
            } else if lib.registered {
                "registered"
            } else {
                "unregistered"
            };
            let se_str = if lib.side_effects.is_empty() {
                String::new()
            } else {
                format!(" [{}]", lib.side_effects.join(", "))
            };
            writeln!(
                out,
                "  {} ({}, {}{})",
                lib.name, lib.category, status, se_str
            )
            .unwrap();
            for w in &lib.warnings {
                writeln!(out, "    [*] {}", w).unwrap();
            }
        }
    }

    let denials: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| !e.allowed)
        .collect();
    if !denials.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "Capability Denials").unwrap();
        writeln!(out, "------------------").unwrap();
        for denial in &denials {
            let target_str = denial
                .target
                .as_deref()
                .map(|t| format!(" on {}", t))
                .unwrap_or_default();
            writeln!(
                out,
                "  [!] {}{}: {}",
                denial.kind,
                target_str,
                denial.reason.as_deref().unwrap_or("denied by policy")
            )
            .unwrap();
        }
    }

    if !report.evidence.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "Evidence ({} items)", report.evidence.len()).unwrap();
        writeln!(out, "--------------------").unwrap();
        for item in &report.evidence {
            writeln!(
                out,
                "  [{}] {} (confidence: {})",
                item.kind, item.title, item.confidence
            )
            .unwrap();
            writeln!(out, "    {}", item.summary).unwrap();
        }
    }

    if !report.errors.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "Errors").unwrap();
        writeln!(out, "------").unwrap();
        for err in &report.errors {
            writeln!(out, "  - {}", err).unwrap();
        }
    }

    if !report.warnings.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "Warnings").unwrap();
        writeln!(out, "--------").unwrap();
        for warn in &report.warnings {
            writeln!(out, "  [*] {}", warn).unwrap();
        }
    }

    let output_str = report.output.content.trim();
    if !output_str.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "Raw Output").unwrap();
        writeln!(out, "----------").unwrap();
        let lines: Vec<&str> = output_str.lines().collect();
        let max_lines = 20;
        for line in lines.iter().take(max_lines) {
            writeln!(out, "  {}", line).unwrap();
        }
        if lines.len() > max_lines {
            writeln!(
                out,
                "  ... ({} more lines, use --json for full output)",
                lines.len() - max_lines
            )
            .unwrap();
        }
    }

    writeln!(out).unwrap();
    out
}
