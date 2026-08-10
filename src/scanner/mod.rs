use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use rayon::prelude::*;
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
use source_analyzer::{CompiledRuleSet, compile_rules, scan_file};

pub use source_analyzer::validate_rules;

pub(crate) struct AnalysisResources {
    rules: Vec<CompiledRuleSet>,
    pool: rayon::ThreadPool,
}

impl AnalysisResources {
    pub(crate) fn new(rules: &[Rule], max_threads: usize) -> Result<Self> {
        let rules = compile_rules(rules)?;
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(max_threads.max(1))
            .build()
            .map_err(|error| Error::Scan {
                path: PathBuf::from("<analysis>"),
                message: format!("failed to create analysis worker pool: {error}"),
            })?;
        Ok(Self { rules, pool })
    }
}

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

struct PendingSourceFile {
    path: PathBuf,
    language: Language,
    source: Vec<u8>,
    size: u64,
}

/// Runs the blocking filesystem and parser scan on Tokio's blocking worker pool.
///
/// The synchronous [`scan`] function remains available for callers that do not
/// already run inside an async runtime.
pub(crate) async fn scan_async(
    root: PathBuf,
    package: String,
    resources: Arc<AnalysisResources>,
    limits: EngineLimits,
    ignored_paths: Vec<String>,
) -> Result<ScanOutcome> {
    let scan_root = root.clone();
    tokio::task::spawn_blocking(move || {
        scan_with_resources(&scan_root, &package, &limits, &ignored_paths, &resources)
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
    let threads = std::thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(1);
    scan_with_ignored_paths_with_threads(root, package, rules, limits, ignored_paths, threads)
}

fn scan_with_ignored_paths_with_threads(
    root: &Path,
    package: &str,
    rules: &[Rule],
    limits: &EngineLimits,
    ignored_paths: &[String],
    max_threads: usize,
) -> Result<ScanOutcome> {
    let resources = AnalysisResources::new(rules, max_threads)?;
    scan_with_resources(root, package, limits, ignored_paths, &resources)
}

fn scan_with_resources(
    root: &Path,
    package: &str,
    limits: &EngineLimits,
    ignored_paths: &[String],
    resources: &AnalysisResources,
) -> Result<ScanOutcome> {
    let ignored_paths = compile_ignored_paths(ignored_paths)?;
    let started = Instant::now();
    let mut outcome = ScanOutcome::default();
    let mut deduplicated = HashSet::new();
    let batch_size = resources.pool.current_num_threads().max(1) * 2;
    let mut pending_sources = Vec::with_capacity(batch_size);
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
        if language.is_some()
            && outcome
                .scanned_files
                .saturating_add(pending_sources.len() as u64)
                >= limits.max_source_files
        {
            return Err(Error::LimitExceeded {
                resource: "source files".to_owned(),
                limit: limits.max_source_files,
            });
        }
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
            pending_sources.push(PendingSourceFile {
                path: relative.to_owned(),
                language,
                source,
                size: file_size,
            });
            if pending_sources.len() >= batch_size {
                record_source_batch(
                    resources,
                    &mut outcome,
                    &mut deduplicated,
                    &pending_sources,
                    package,
                    limits,
                    started,
                )?;
                pending_sources.clear();
            }
        }
    }

    record_source_batch(
        resources,
        &mut outcome,
        &mut deduplicated,
        &pending_sources,
        package,
        limits,
        started,
    )?;
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
        && matches!(
            finding.rule_id.as_str(),
            "chainsec.detection.file.binary" | "chainsec.detection.file.compressed"
        );
    if !is_exempt_fixture && deduplicated.insert(finding.id.clone()) {
        outcome.findings.push(finding);
    }
}

fn record_source_batch(
    resources: &AnalysisResources,
    outcome: &mut ScanOutcome,
    deduplicated: &mut HashSet<String>,
    files: &[PendingSourceFile],
    package: &str,
    limits: &EngineLimits,
    started: Instant,
) -> Result<()> {
    if files.is_empty() {
        return Ok(());
    }
    let analyses = resources.pool.install(|| {
        files
            .par_iter()
            .map(|file| {
                ensure_within_duration(started, limits)?;
                scan_file(
                    &file.path,
                    package,
                    file.language,
                    &file.source,
                    &resources.rules,
                )
            })
            .collect::<Result<Vec<_>>>()
    })?;

    for (file, findings) in files.iter().zip(analyses) {
        outcome.scanned_files += 1;
        if outcome.scanned_files > limits.max_source_files {
            return Err(Error::LimitExceeded {
                resource: "source files".to_owned(),
                limit: limits.max_source_files,
            });
        }
        outcome.scanned_bytes = outcome.scanned_bytes.saturating_add(file.size);
        for finding in findings {
            if deduplicated.insert(finding.id.clone()) {
                outcome.findings.push(finding);
            }
        }
    }
    ensure_within_duration(started, limits)
}

#[cfg(test)]
mod tests;
