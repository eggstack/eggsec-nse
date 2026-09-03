use crate::report::NseRunReport;

/// `writeln_checked!` for infallible `String` buffers.
///
/// `fmt::Write for String` fails only on allocator OOM, so the result is
/// debug-asserted rather than panicked on (`.unwrap()`) or silently
/// discarded (`let _ =`).
macro_rules! writeln_checked {
    ($dst:expr) => {{
        let result: std::fmt::Result = writeln!($dst);
        debug_assert!(
            result.is_ok(),
            "writing to a String buffer is infallible"
        );
    }};
    ($dst:expr, $($arg:tt)*) => {{
        let result: std::fmt::Result = writeln!($dst, $($arg)*);
        debug_assert!(
            result.is_ok(),
            "writing to a String buffer is infallible"
        );
    }};
}

pub fn format_human_report(report: &NseRunReport) -> String {
    use crate::report::{NseRunCompatibilityStatus, NseRunFidelity};
    use std::fmt::Write;

    let mut out = String::new();

    writeln_checked!(out);
    writeln_checked!(out, "NSE Script Report");
    writeln_checked!(out, "=================");
    writeln_checked!(out, "  Target:    {}", report.target);
    writeln_checked!(out, "  Script:    {}", report.script_name);
    writeln_checked!(
        out,
        "  Source:    {} ({})",
        report.script_source.label,
        report.script_source.kind
    );
    writeln_checked!(out, "  Profile:   {}", report.profile.kind);
    writeln_checked!(out, "  Elapsed:   {:.2}s", report.stats.elapsed_secs);

    writeln_checked!(out);
    writeln_checked!(out, "Compatibility");
    writeln_checked!(out, "-------------");
    let status_str = match report.compatibility.status {
        NseRunCompatibilityStatus::Compatible => "COMPATIBLE",
        NseRunCompatibilityStatus::CompatibleWithWarnings => "COMPATIBLE (warnings)",
        NseRunCompatibilityStatus::Partial => "PARTIAL",
        NseRunCompatibilityStatus::Unsupported => "UNSUPPORTED",
        NseRunCompatibilityStatus::Failed => "FAILED",
        NseRunCompatibilityStatus::Unknown => "UNKNOWN",
    };
    writeln_checked!(out, "  Status:  {}", status_str);

    let fidelity_str = match report.compatibility.fidelity {
        NseRunFidelity::Full => "full".to_string(),
        NseRunFidelity::Approximate => "~approximate".to_string(),
        NseRunFidelity::Minimal => "~minimal".to_string(),
        NseRunFidelity::Unknown => "unknown".to_string(),
    };
    writeln_checked!(out, "  Fidelity: {}", fidelity_str);

    if !report.compatibility.unsupported_features.is_empty() {
        writeln_checked!(
            out,
            "  Unsupported: {}",
            report.compatibility.unsupported_features.join(", ")
        );
    }
    if !report.compatibility.approximations.is_empty() {
        writeln_checked!(
            out,
            "  Approximations: {}",
            report.compatibility.approximations.join(", ")
        );
    }

    if !report.rules.is_empty() {
        writeln_checked!(out);
        writeln_checked!(out, "Rule Evaluation");
        writeln_checked!(out, "---------------");
        for rule in &report.rules {
            let status = if rule.matched {
                "matched"
            } else if rule.evaluated {
                "no match"
            } else {
                "not evaluated"
            };
            writeln_checked!(out, "  [{}] {} ({})", rule.kind, status, rule.exactness);
            if !rule.summary.is_empty() {
                writeln_checked!(out, "    {}", rule.summary);
            }
            if let Some(ref unsupported) = rule.unsupported {
                writeln_checked!(out, "    unsupported: {}", unsupported);
            }
        }
    }

    if !report.libraries.is_empty() {
        writeln_checked!(out);
        writeln_checked!(out, "Libraries");
        writeln_checked!(out, "---------");
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
            writeln_checked!(
                out,
                "  {} ({}, {}{})",
                lib.name,
                lib.category,
                status,
                se_str
            );
            for w in &lib.warnings {
                writeln_checked!(out, "    [*] {}", w);
            }
        }
    }

    let denials: Vec<_> = report
        .capability_events
        .iter()
        .filter(|e| !e.allowed)
        .collect();
    if !denials.is_empty() {
        writeln_checked!(out);
        writeln_checked!(out, "Capability Denials");
        writeln_checked!(out, "------------------");
        for denial in &denials {
            let target_str = denial
                .target
                .as_deref()
                .map(|t| format!(" on {}", t))
                .unwrap_or_default();
            writeln_checked!(
                out,
                "  [!] {}{}: {}",
                denial.kind,
                target_str,
                denial.reason.as_deref().unwrap_or("denied by policy")
            );
        }
    }

    if !report.evidence.is_empty() {
        writeln_checked!(out);
        writeln_checked!(out, "Evidence ({} items)", report.evidence.len());
        writeln_checked!(out, "--------------------");
        for item in &report.evidence {
            writeln_checked!(
                out,
                "  [{}] {} (confidence: {})",
                item.kind,
                item.title,
                item.confidence
            );
            writeln_checked!(out, "    {}", item.summary);
        }
    }

    if !report.errors.is_empty() {
        writeln_checked!(out);
        writeln_checked!(out, "Errors");
        writeln_checked!(out, "------");
        for err in &report.errors {
            writeln_checked!(out, "  - {}", err);
        }
    }

    if !report.warnings.is_empty() {
        writeln_checked!(out);
        writeln_checked!(out, "Warnings");
        writeln_checked!(out, "--------");
        for warn in &report.warnings {
            writeln_checked!(out, "  [*] {}", warn);
        }
    }

    let output_str = report.output.content.trim();
    if !output_str.is_empty() {
        writeln_checked!(out);
        writeln_checked!(out, "Raw Output");
        writeln_checked!(out, "----------");
        let lines: Vec<&str> = output_str.lines().collect();
        let max_lines = 20;
        for line in lines.iter().take(max_lines) {
            writeln_checked!(out, "  {}", line);
        }
        if lines.len() > max_lines {
            writeln_checked!(
                out,
                "  ... ({} more lines, use --json for full output)",
                lines.len() - max_lines
            );
        }
    }

    writeln_checked!(out);
    out
}
