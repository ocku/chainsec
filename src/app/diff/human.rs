use std::collections::BTreeMap;

use chainsec::model::AnalysisPoint;

use crate::app::style::{display_package, paint, risk_color};

use super::{DetectionKey, DiffReport};

#[derive(Clone, Copy)]
struct VersionEvent<'a> {
    version: &'a str,
    delta: i128,
}

type VersionEvents<'a> = Vec<VersionEvent<'a>>;

struct AggregateChange<'a> {
    initial_count: usize,
    events: VersionEvents<'a>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChangeKind {
    Added,
    Removed,
}

pub(super) fn render(report: &DiffReport<'_>, color: bool) -> String {
    let mut output = format!(
        "{} {} — {} ({} version(s))\n",
        paint("chainsec diff", "1;36", color),
        report.tool_version,
        report.package,
        report.versions.len(),
    );

    render_issues(&mut output, report, color);

    if report.diffs.is_empty() {
        output.push_str("No prior pullable version was selected for comparison.\n");
        return output;
    }

    render_changes(&mut output, report, color);
    output
}

fn render_issues(output: &mut String, report: &DiffReport<'_>, color: bool) {
    if report.issues.is_empty() {
        return;
    }

    output.push_str(&format!("\n{}\n", paint("Issues", "1;33", color)));
    for version in &report.issues {
        for issue in version.issues {
            output.push_str(&format!(
                "  {} [{}] {}\n",
                version.version, issue.code, issue.message
            ));
        }
    }
    output.push_str(&format!(
        "{}\n",
        paint(
            "Changes involving a version with issues may be incomplete.",
            "33",
            color,
        )
    ));
}

fn render_changes(output: &mut String, report: &DiffReport<'_>, color: bool) {
    render_detection_details(output, report, color);
    render_summary(output, report, color);
}

fn render_summary(output: &mut String, report: &DiffReport<'_>, color: bool) {
    let oldest_version = report
        .versions
        .last()
        .expect("a diff report with comparisons has versions");
    let newest_version = report
        .versions
        .first()
        .expect("a diff report with comparisons has versions");
    let incomplete = report
        .diffs
        .iter()
        .any(|comparison| !comparison.from_complete || !comparison.to_complete);
    let (detections, capabilities) = aggregate_changes(report);

    output.push_str(&format!(
        "\n{}{}\n{} ({})\n",
        paint(
            &format!("Changes  {oldest_version} → {newest_version}"),
            "1",
            color,
        ),
        if incomplete {
            paint(" (incomplete)", "33", color)
        } else {
            String::new()
        },
        paint("Detections", "1", color),
        detections.len(),
    ));
    if detections.is_empty() {
        output.push_str(&format!("  {}\n", paint("none", "2", color)));
    } else {
        output.push('\n');
        render_detection_summary(output, &detections, color);
    }

    output.push_str(&format!(
        "\n{} ({})\n",
        paint("Capabilities", "1", color),
        capabilities.len(),
    ));
    if capabilities.is_empty() {
        output.push_str(&format!("  {}\n", paint("none", "2", color)));
    } else {
        output.push('\n');
        render_capability_changes(output, &capabilities, color);
    }
}

fn render_detection_details(output: &mut String, report: &DiffReport<'_>, color: bool) {
    let comparisons = report
        .diffs
        .iter()
        .filter(|comparison| {
            !comparison.added_findings.is_empty() || !comparison.removed_findings.is_empty()
        })
        .collect::<Vec<_>>();

    if comparisons.is_empty() {
        return;
    }

    output.push_str(&format!("\n{}", paint("Finding details", "1", color)));
    output.push('\n');

    for comparison in comparisons {
        for finding in &comparison.removed_findings {
            output.push_str(&finding_line(finding, ChangeKind::Removed, color));
        }
        for finding in &comparison.added_findings {
            output.push_str(&finding_line(finding, ChangeKind::Added, color));
        }
    }
}

fn finding_line(finding: &AnalysisPoint, kind: ChangeKind, color: bool) -> String {
    let (sign, sign_color) = match kind {
        ChangeKind::Added => ("+", "32"),
        ChangeKind::Removed => ("-", "31"),
    };
    let group = finding.finding_type.rule_group().name();
    let code = finding.matched_code.trim();
    let location = format!(
        "{}:{}:{}",
        finding.file.display(),
        finding.location.start_line,
        finding.location.start_column
    );

    format!(
        "{} {} {} {} {}\n      {}\n\n",
        paint(sign, sign_color, color),
        paint(
            &format!("{:?}", finding.risk),
            risk_color(finding.risk),
            color
        ),
        paint(&format!("{group}:{}", finding.rule_id), "36", color),
        paint(display_package(&finding.package), "1", color),
        paint(&location, "2", color),
        paint(code, sign_color, color),
    )
}

fn aggregate_changes<'a>(
    report: &'a DiffReport<'a>,
) -> (
    BTreeMap<DetectionKey, AggregateChange<'a>>,
    BTreeMap<String, AggregateChange<'a>>,
) {
    let mut detections = BTreeMap::new();
    let mut capabilities = BTreeMap::new();

    // Reports and comparisons are newest-first; reverse them for chronological events.
    for comparison in report.diffs.iter().rev() {
        for change in &comparison.detections.added {
            let key = DetectionKey {
                group: change.group.clone(),
                rule_id: change.rule_id.clone(),
                risk: change.risk,
            };
            let entry = detections.entry(key).or_insert_with(|| AggregateChange {
                initial_count: change.before,
                events: Vec::new(),
            });
            push_event(
                &mut entry.events,
                &comparison.to_version,
                count_delta(change.after - change.before),
            );
        }
        for change in &comparison.detections.removed {
            let key = DetectionKey {
                group: change.group.clone(),
                rule_id: change.rule_id.clone(),
                risk: change.risk,
            };
            let entry = detections.entry(key).or_insert_with(|| AggregateChange {
                initial_count: change.before,
                events: Vec::new(),
            });
            push_event(
                &mut entry.events,
                &comparison.to_version,
                -count_delta(change.before - change.after),
            );
        }
        for change in &comparison.capabilities.added {
            let entry =
                capabilities
                    .entry(change.name.clone())
                    .or_insert_with(|| AggregateChange {
                        initial_count: change.before,
                        events: Vec::new(),
                    });
            push_event(
                &mut entry.events,
                &comparison.to_version,
                count_delta(change.after - change.before),
            );
        }
        for change in &comparison.capabilities.removed {
            let entry =
                capabilities
                    .entry(change.name.clone())
                    .or_insert_with(|| AggregateChange {
                        initial_count: change.before,
                        events: Vec::new(),
                    });
            push_event(
                &mut entry.events,
                &comparison.to_version,
                -count_delta(change.before - change.after),
            );
        }
    }

    (detections, capabilities)
}

fn push_event<'a>(events: &mut VersionEvents<'a>, version: &'a str, delta: i128) {
    events.push(VersionEvent { version, delta });
}

fn count_delta(count: usize) -> i128 {
    i128::try_from(count).expect("match count fits in i128")
}

fn render_detection_summary(
    output: &mut String,
    detections: &BTreeMap<DetectionKey, AggregateChange<'_>>,
    color: bool,
) {
    for (index, (detection, change)) in detections.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        let name = format!("{}:{}", detection.group, detection.rule_id);
        let final_count = (change.initial_count as i128 + total_change(&change.events)) as usize;
        let name_display = if final_count == 0 {
            paint(&name, "36;9", color)
        } else {
            paint(&name, "36", color)
        };
        output.push_str(&format!(
            "  {}  {} {} {} ({} → {})\n",
            render_total_change(total_change(&change.events), color),
            paint(
                &format!("{:?}", detection.risk),
                risk_color(detection.risk),
                color,
            ),
            paint("·", "2", color),
            name_display,
            change.initial_count,
            final_count,
        ));
        render_versions_changed(output, &change.events, color);
    }
}

fn render_capability_changes(
    output: &mut String,
    capabilities: &BTreeMap<String, AggregateChange<'_>>,
    color: bool,
) {
    for (index, (capability, change)) in capabilities.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        let final_count = (change.initial_count as i128 + total_change(&change.events)) as usize;
        let name_display = if final_count == 0 {
            paint(capability, "36;9", color)
        } else {
            paint(capability, "36", color)
        };
        output.push_str(&format!(
            "  {}  {} ({} → {})\n",
            render_total_change(total_change(&change.events), color),
            name_display,
            change.initial_count,
            final_count,
        ));
        render_versions_changed(output, &change.events, color);
    }
}

fn total_change(events: &VersionEvents<'_>) -> i128 {
    events.iter().map(|event| event.delta).sum()
}

pub(super) fn render_total_change(total: i128, color: bool) -> String {
    let (value, color_code) = match total.cmp(&0) {
        std::cmp::Ordering::Greater => (format!("+{total}"), "1;32"),
        std::cmp::Ordering::Less => (total.to_string(), "1;31"),
        std::cmp::Ordering::Equal => ("±0".to_owned(), "2"),
    };
    paint(&value, color_code, color)
}

fn render_versions_changed(output: &mut String, events: &VersionEvents<'_>, color: bool) {
    let versions = events
        .iter()
        .map(|event| event.version)
        .collect::<Vec<_>>()
        .join(", ");
    output.push_str(&format!("      {} {versions}\n", paint("↳", "2", color)));
}
