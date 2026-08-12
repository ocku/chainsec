use std::collections::BTreeMap;

use crate::app::style::{paint, risk_color};

use super::{DetectionKey, DiffReport};

#[derive(Clone, Copy)]
struct VersionEvent<'a> {
    version: &'a str,
    delta: i128,
}

type VersionEvents<'a> = Vec<VersionEvent<'a>>;

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

fn aggregate_changes<'a>(
    report: &'a DiffReport<'a>,
) -> (
    BTreeMap<DetectionKey, VersionEvents<'a>>,
    BTreeMap<String, VersionEvents<'a>>,
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
            push_event(
                &mut detections,
                key,
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
            push_event(
                &mut detections,
                key,
                &comparison.to_version,
                -count_delta(change.before - change.after),
            );
        }
        for change in &comparison.capabilities.added {
            push_event(
                &mut capabilities,
                change.name.clone(),
                &comparison.to_version,
                count_delta(change.after - change.before),
            );
        }
        for change in &comparison.capabilities.removed {
            push_event(
                &mut capabilities,
                change.name.clone(),
                &comparison.to_version,
                -count_delta(change.before - change.after),
            );
        }
    }

    (detections, capabilities)
}

fn push_event<'a, K: Ord>(
    events: &mut BTreeMap<K, VersionEvents<'a>>,
    key: K,
    version: &'a str,
    delta: i128,
) {
    events
        .entry(key)
        .or_default()
        .push(VersionEvent { version, delta });
}

fn count_delta(count: usize) -> i128 {
    i128::try_from(count).expect("match count fits in i128")
}

fn render_detection_summary(
    output: &mut String,
    detections: &BTreeMap<DetectionKey, VersionEvents<'_>>,
    color: bool,
) {
    for (index, (detection, events)) in detections.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        let name = format!("{}:{}", detection.group, detection.rule_id);
        output.push_str(&format!(
            "  {}  {} {} {}\n",
            render_total_change(total_change(events), color),
            paint(
                &format!("{:?}", detection.risk),
                risk_color(detection.risk),
                color,
            ),
            paint("·", "2", color),
            paint(&name, "36", color),
        ));
        render_versions_changed(output, events, color);
    }
}

fn render_capability_changes(
    output: &mut String,
    capabilities: &BTreeMap<String, VersionEvents<'_>>,
    color: bool,
) {
    for (index, (capability, events)) in capabilities.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        output.push_str(&format!(
            "  {}  {}\n",
            render_total_change(total_change(events), color),
            paint(capability, "36", color),
        ));
        render_versions_changed(output, events, color);
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
