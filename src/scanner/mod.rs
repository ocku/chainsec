use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicU64},
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
    ScannedFileOpener, compile_ignored_paths, included, is_test_fixture, language_for,
    read_entry_with_opener,
};
use source_analyzer::{
    CompiledRuleSet, SourceScanInput, SourceScanWorker, compile_rules, reserve_finding, scan_file,
};

pub use source_analyzer::validate_rules;

pub(crate) struct AnalysisResources {
    rules: Vec<CompiledRuleSet>,
    pool: rayon::ThreadPool,
}

impl AnalysisResources {
    pub(crate) fn new(rules: &[Rule], max_threads: usize) -> Result<Self> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(max_threads.max(1))
            .build()
            .map_err(|error| Error::Scan {
                path: PathBuf::from("<analysis>"),
                message: format!("failed to create analysis worker pool: {error}"),
            })?;
        let rules = pool.install(|| compile_rules(rules))?;
        Ok(Self { rules, pool })
    }
}

use crate::{
    error::{Error, Result},
    model::{AnalysisPoint, EngineLimits, Language, OperationalIssue, Rule},
};

#[derive(Debug, Default)]
pub struct ScanOutcome {
    pub findings: Vec<AnalysisPoint>,
    pub issues: Vec<OperationalIssue>,
    pub scanned_files: u64,
    pub scanned_bytes: u64,
}

struct PendingSourceFile {
    path: PathBuf,
    language: Language,
    is_tsx: bool,
    source: Vec<u8>,
    size: u64,
}

struct SourceBatch<'a> {
    resources: &'a AnalysisResources,
    package: &'a str,
    limits: &'a EngineLimits,
    started: Instant,
    finding_budget: &'a AtomicU64,
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
    exclude_node_modules: bool,
) -> Result<ScanOutcome> {
    let scan_root = root.clone();
    tokio::task::spawn_blocking(move || {
        scan_with_resources(
            &scan_root,
            &package,
            &limits,
            &ignored_paths,
            exclude_node_modules,
            &resources,
        )
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
    scan_with_resources(root, package, limits, ignored_paths, true, &resources)
}

fn scan_with_resources(
    root: &Path,
    package: &str,
    limits: &EngineLimits,
    ignored_paths: &[String],
    exclude_node_modules: bool,
    resources: &AnalysisResources,
) -> Result<ScanOutcome> {
    let ignored_paths = compile_ignored_paths(ignored_paths)?;
    let started = Instant::now();
    let mut outcome = ScanOutcome::default();
    let mut deduplicated = HashSet::new();
    let finding_budget = Arc::new(AtomicU64::new(0));
    let batch_size = resources
        .pool
        .current_num_threads()
        .max(1)
        .saturating_mul(8);
    let batch = SourceBatch {
        resources,
        package,
        limits,
        started,
        finding_budget: &finding_budget,
    };
    let mut pending_sources = Vec::with_capacity(batch_size);
    let mut file_opener = ScannedFileOpener::new(root)?;
    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| included(entry, root, ignored_paths.as_ref(), exclude_node_modules));

    for item in walker {
        ensure_within_duration(started, limits)?;
        let entry = item.map_err(|error| Error::Scan {
            path: error.path().unwrap_or(root).to_owned(),
            message: error.to_string(),
        })?;
        if !entry.file_type().is_file() {
            continue;
        }

        let extension_language = language_for(entry.path(), &[]);
        if extension_language.is_some()
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
        let (language, source, file_size) =
            read_entry_with_opener(&entry, &mut file_opener, limits, extension_language)?;
        if language.is_some()
            && extension_language.is_none()
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
        ensure_within_duration(started, limits)?;
        let relative = relative_path(entry.path(), root);
        record_file_analysis(
            &mut outcome,
            &mut deduplicated,
            &relative,
            package,
            &source,
            file_size,
            &finding_budget,
            limits.max_findings,
        )?;
        ensure_within_duration(started, limits)?;

        if let Some(language) = language {
            pending_sources.push(PendingSourceFile {
                path: relative.to_owned(),
                is_tsx: entry
                    .path()
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("tsx")),
                language,
                source,
                size: file_size,
            });
            if pending_sources.len() >= batch_size {
                record_source_batch(&batch, &mut outcome, &mut deduplicated, &pending_sources)?;
                pending_sources.clear();
            }
        }
    }

    record_source_batch(&batch, &mut outcome, &mut deduplicated, &pending_sources)?;
    outcome.findings.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(outcome)
}

fn relative_path(path: &Path, root: &Path) -> PathBuf {
    if root.is_file() {
        return PathBuf::from(path.file_name().unwrap_or(root.as_os_str()));
    }
    path.strip_prefix(root).unwrap_or(path).to_owned()
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

#[allow(clippy::too_many_arguments)]
fn record_file_analysis(
    outcome: &mut ScanOutcome,
    deduplicated: &mut HashSet<String>,
    path: &Path,
    package: &str,
    source: &[u8],
    file_size: u64,
    finding_budget: &AtomicU64,
    max_findings: u64,
) -> Result<()> {
    let Some(analysis) = file_analyzer::analyze_with_size(path, package, source, file_size) else {
        return Ok(());
    };

    if !(is_test_fixture(path) && analysis.is_exempt_in_test_fixture)
        && deduplicated.insert(analysis.finding.id.clone())
    {
        reserve_finding(finding_budget, max_findings)?;
        outcome.findings.push(analysis.finding);
    }
    Ok(())
}

fn record_source_batch(
    batch: &SourceBatch,
    outcome: &mut ScanOutcome,
    deduplicated: &mut HashSet<String>,
    files: &[PendingSourceFile],
) -> Result<()> {
    if files.is_empty() {
        return Ok(());
    }
    let analyses = batch.resources.pool.install(|| {
        files
            .par_iter()
            .map_init(SourceScanWorker::new, |worker, file| {
                ensure_within_duration(batch.started, batch.limits)?;
                scan_file(
                    worker,
                    SourceScanInput {
                        path: &file.path,
                        package: batch.package,
                        language: file.language,
                        is_tsx: file.is_tsx,
                        source: &file.source,
                        rule_sets: &batch.resources.rules,
                        fail_on_parse_error: batch.limits.fail_on_parse_error,
                        started: batch.started,
                        max_scan_duration: batch.limits.max_scan_duration,
                    },
                )
            })
            .collect::<Result<Vec<_>>>()
    })?;

    for (file, findings) in files.iter().zip(analyses) {
        outcome.scanned_files += 1;
        if outcome.scanned_files > batch.limits.max_source_files {
            return Err(Error::LimitExceeded {
                resource: "source files".to_owned(),
                limit: batch.limits.max_source_files,
            });
        }
        outcome.scanned_bytes = outcome.scanned_bytes.saturating_add(file.size);
        outcome.issues.extend(findings.issues);
        for finding in findings.findings {
            if deduplicated.insert(finding.id.clone()) {
                reserve_finding(batch.finding_budget, batch.limits.max_findings)?;
                outcome.findings.push(finding);
            }
        }
    }
    ensure_within_duration(batch.started, batch.limits)
}

#[cfg(test)]
mod tests;
