use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::Instant,
};

use walkdir::WalkDir;

mod entropy;
mod file_analyzer;
mod filesystem;
mod source_analyzer;

#[cfg(test)]
use entropy::is_structured_literal;
#[cfg(test)]
use filesystem::MAX_NON_SOURCE_ANALYSIS_BYTES;
use filesystem::{
    compile_ignored_paths, included, is_test_fixture, language_for, read_entry_contents,
};
use source_analyzer::{CompiledRule, compile_rules, scan_file};

pub use source_analyzer::validate_rules;

use crate::{
    error::{Error, Result},
    model::{AnalysisPoint, EngineLimits, Language, Rule},
};

#[derive(Debug, Default)]
pub struct ScanOutcome {
    pub findings: Vec<AnalysisPoint>,
    pub scanned_files: u64,
    pub scanned_bytes: u64,
}

struct SourceFile<'a> {
    path: &'a Path,
    package: &'a str,
    language: Language,
    source: &'a [u8],
    size: u64,
}

/// Runs the blocking filesystem and parser scan on Tokio's blocking worker pool.
///
/// The synchronous [`scan`] function remains available for callers that do not
/// already run inside an async runtime.
pub async fn scan_async(
    root: PathBuf,
    package: String,
    rules: Vec<Rule>,
    limits: EngineLimits,
    ignored_paths: Vec<String>,
) -> Result<ScanOutcome> {
    let scan_root = root.clone();
    tokio::task::spawn_blocking(move || {
        scan_with_ignored_paths(&scan_root, &package, &rules, &limits, &ignored_paths)
    })
    .await
    .map_err(|error| Error::Scan {
        path: root,
        message: format!("scan worker failed: {error}"),
    })?
}

pub fn scan(
    root: &Path,
    package: &str,
    rules: &[Rule],
    limits: &EngineLimits,
) -> Result<ScanOutcome> {
    scan_with_ignored_paths(root, package, rules, limits, &[])
}

pub fn scan_with_ignored_paths(
    root: &Path,
    package: &str,
    rules: &[Rule],
    limits: &EngineLimits,
    ignored_paths: &[String],
) -> Result<ScanOutcome> {
    let ignored_paths = compile_ignored_paths(ignored_paths)?;
    let compiled = compile_rules(rules)?;
    let started = Instant::now();
    let mut outcome = ScanOutcome::default();
    let mut deduplicated = HashSet::new();
    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| included(entry, root, ignored_paths.as_ref()));

    for item in walker {
        ensure_within_duration(started, limits)?;
        let entry = item.map_err(|error| Error::Scan {
            path: error.path().unwrap_or(root).to_owned(),
            message: error.to_string(),
        })?;
        if !entry.file_type().is_file() {
            continue;
        }

        let language = language_for(entry.path());
        let (source, file_size) = read_entry_contents(&entry, language, limits)?;
        ensure_within_duration(started, limits)?;
        let relative = entry.path().strip_prefix(root).unwrap_or(entry.path());
        record_file_analysis(
            &mut outcome,
            &mut deduplicated,
            relative,
            package,
            &source,
            file_size,
        );
        ensure_within_duration(started, limits)?;

        if let Some(language) = language {
            let source_file = SourceFile {
                path: relative,
                package,
                language,
                source: &source,
                size: file_size,
            };
            record_source_findings(
                &mut outcome,
                &mut deduplicated,
                source_file,
                limits,
                &compiled,
            )?;
            ensure_within_duration(started, limits)?;
        }
    }

    outcome.findings.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(outcome)
}

fn ensure_within_duration(started: Instant, limits: &EngineLimits) -> Result<()> {
    if started.elapsed() <= limits.max_scan_duration {
        return Ok(());
    }

    Err(Error::LimitExceeded {
        resource: "scan duration seconds".to_owned(),
        limit: limits.max_scan_duration.as_secs(),
    })
}

fn record_file_analysis(
    outcome: &mut ScanOutcome,
    deduplicated: &mut HashSet<String>,
    path: &Path,
    package: &str,
    source: &[u8],
    file_size: u64,
) {
    let Some(finding) = file_analyzer::analyze_with_size(path, package, source, file_size) else {
        return;
    };

    let is_exempt_fixture = is_test_fixture(path)
        && matches!(finding.rule_id.as_str(), "FILE_BINARY" | "FILE_COMPRESSED");
    if !is_exempt_fixture && deduplicated.insert(finding.id.clone()) {
        outcome.findings.push(finding);
    }
}

fn record_source_findings(
    outcome: &mut ScanOutcome,
    deduplicated: &mut HashSet<String>,
    file: SourceFile<'_>,
    limits: &EngineLimits,
    rules: &[CompiledRule<'_>],
) -> Result<()> {
    outcome.scanned_files += 1;
    if outcome.scanned_files > limits.max_source_files {
        return Err(Error::LimitExceeded {
            resource: "source files".to_owned(),
            limit: limits.max_source_files,
        });
    }

    outcome.scanned_bytes = outcome.scanned_bytes.saturating_add(file.size);
    for finding in scan_file(file.path, file.package, file.language, file.source, rules)? {
        if deduplicated.insert(finding.id.clone()) {
            outcome.findings.push(finding);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
