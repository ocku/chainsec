use std::{
    collections::HashSet,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    time::Instant,
};

use globset::{Glob, GlobSet, GlobSetBuilder};
use tree_sitter::{Parser, Query, QueryCursor, StreamingIterator};
use walkdir::{DirEntry, WalkDir};

mod entropy;
mod file_analyzer;

use entropy::has_high_entropy;
#[cfg(test)]
use entropy::is_structured_literal;

const MAX_NON_SOURCE_ANALYSIS_BYTES: u64 = 1024 * 1024;

use crate::{
    error::{Error, Result},
    model::{AnalysisPoint, EngineLimits, Language, Location, Rule},
};

#[derive(Debug, Default)]
pub struct ScanOutcome {
    pub findings: Vec<AnalysisPoint>,
    pub scanned_files: u64,
    pub scanned_bytes: u64,
}

struct CompiledRule<'a> {
    rule: &'a Rule,
    query: Query,
    capture_index: u32,
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
    let started = Instant::now();
    let compiled = compile_rules(rules)?;
    let mut outcome = ScanOutcome::default();
    let mut deduplicated = HashSet::new();
    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| included(entry, root, ignored_paths.as_ref()));
    for item in walker {
        if started.elapsed() > limits.max_scan_duration {
            return Err(Error::LimitExceeded {
                resource: "scan duration seconds".to_owned(),
                limit: limits.max_scan_duration.as_secs(),
            });
        }
        let entry = item.map_err(|error| Error::Scan {
            path: error.path().unwrap_or(root).to_owned(),
            message: error.to_string(),
        })?;
        if !entry.file_type().is_file() {
            continue;
        }
        let language = language_for(entry.path());
        let (source, file_size) = read_entry_contents(&entry, language, limits)?;
        let relative = entry.path().strip_prefix(root).unwrap_or(entry.path());

        record_file_analysis(
            &mut outcome,
            &mut deduplicated,
            relative,
            package,
            &source,
            file_size,
        );

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
        }
    }
    outcome.findings.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(outcome)
}

fn read_entry_contents(
    entry: &DirEntry,
    language: Option<Language>,
    limits: &EngineLimits,
) -> Result<(Vec<u8>, u64)> {
    let metadata = entry.metadata().map_err(|error| Error::Scan {
        path: entry.path().to_owned(),
        message: error.to_string(),
    })?;
    let file_size = metadata.len();

    if language.is_some() && file_size > limits.max_source_file_bytes {
        return Err(Error::LimitExceeded {
            resource: format!("source file bytes ({})", entry.path().display()),
            limit: limits.max_source_file_bytes,
        });
    }

    let contents = match language {
        Some(_) => fs::read(entry.path()).map_err(|error| Error::Scan {
            path: entry.path().to_owned(),
            message: error.to_string(),
        })?,
        None => read_non_source_prefix(entry.path())?,
    };

    Ok((contents, file_size))
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

fn read_non_source_prefix(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|error| Error::Scan {
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_NON_SOURCE_ANALYSIS_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|error| Error::Scan {
            path: path.to_owned(),
            message: error.to_string(),
        })?;
    Ok(bytes)
}

fn compile_ignored_paths(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(
            Glob::new(pattern).map_err(|error| Error::InvalidConfiguration {
                message: format!("invalid ignored path glob {pattern:?}: {error}"),
            })?,
        );
    }
    builder
        .build()
        .map(Some)
        .map_err(|error| Error::InvalidConfiguration {
            message: format!("could not build ignored path globs: {error}"),
        })
}

fn included(entry: &DirEntry, root: &Path, ignored_paths: Option<&GlobSet>) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    let relative = entry.path().strip_prefix(root).unwrap_or(entry.path());
    if ignored_paths.is_some_and(|patterns| patterns.is_match(relative)) {
        return false;
    }
    !matches!(
        entry.file_name().to_str(),
        Some(
            ".git"
                | ".chainsec-cache"
                | "node_modules"
                | "target"
                | ".venv"
                | "venv"
                | "__pycache__"
        )
    )
}

fn is_test_fixture(path: &Path) -> bool {
    let components = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .collect::<Vec<_>>();
    components.iter().any(|component| {
        matches!(
            *component,
            "fixtures" | "fixture" | "testdata" | "__fixtures__"
        )
    }) || components.iter().enumerate().any(|(index, component)| {
        matches!(*component, "test" | "tests")
            && components[index + 1..]
                .iter()
                .any(|component| matches!(*component, "data" | "resources"))
    })
}

fn language_for(path: &Path) -> Option<Language> {
    match path.extension()?.to_str()? {
        "py" => Some(Language::Python),
        "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
        "ts" | "tsx" | "mts" | "cts" => Some(Language::TypeScript),
        _ => None,
    }
}

fn grammar(language: Language) -> tree_sitter::Language {
    match language {
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    }
}

pub fn validate_rules(rules: &[Rule]) -> Result<()> {
    compile_rules(rules).map(|_| ())
}

fn compile_rules(rules: &[Rule]) -> Result<Vec<CompiledRule<'_>>> {
    rules
        .iter()
        .map(|rule| {
            let query =
                Query::new(&grammar(rule.language), &rule.query).map_err(|error| Error::Scan {
                    path: PathBuf::from("<rules>"),
                    message: format!("rule {}: {error}", rule.id),
                })?;
            let capture_index =
                query
                    .capture_index_for_name("match")
                    .ok_or_else(|| Error::Scan {
                        path: PathBuf::from("<rules>"),
                        message: format!("rule {} has no @match capture", rule.id),
                    })?;
            Ok(CompiledRule {
                rule,
                query,
                capture_index,
            })
        })
        .collect()
}

fn scan_file(
    path: &Path,
    package: &str,
    language: Language,
    source: &[u8],
    rules: &[CompiledRule<'_>],
) -> Result<Vec<AnalysisPoint>> {
    let grammar = grammar(language);
    let mut parser = Parser::new();
    parser.set_language(&grammar).map_err(|error| Error::Scan {
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    let tree = parser.parse(source, None).ok_or_else(|| Error::Scan {
        path: path.to_owned(),
        message: "parser returned no syntax tree".to_owned(),
    })?;
    let mut findings = Vec::new();
    for compiled in rules
        .iter()
        .filter(|compiled| compiled.rule.language == language)
    {
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&compiled.query, tree.root_node(), source);
        while let Some(query_match) = matches.next() {
            for capture in query_match
                .captures
                .iter()
                .filter(|capture| capture.index == compiled.capture_index)
            {
                let node = capture.node;
                let start = node.start_position();
                let end = node.end_position();
                let location = Location {
                    start_line: start.row + 1,
                    start_column: start.column + 1,
                    end_line: end.row + 1,
                    end_column: end.column + 1,
                };
                let matched_bytes = &source[node.byte_range()];
                if compiled
                    .rule
                    .entropy
                    .as_ref()
                    .is_some_and(|matcher| !has_high_entropy(matched_bytes, matcher))
                {
                    continue;
                }
                let matched_code = String::from_utf8_lossy(matched_bytes).into_owned();
                let file = path.to_string_lossy();
                findings.push(AnalysisPoint {
                    id: AnalysisPoint::stable_id(
                        &compiled.rule.id,
                        compiled.rule.version,
                        package,
                        &file,
                        &location,
                        &matched_code,
                    ),
                    rule_id: compiled.rule.id.to_owned(),
                    rule_version: compiled.rule.version,
                    finding_type: compiled.rule.finding_type,
                    risk: compiled.rule.risk,
                    confidence: compiled.rule.confidence,
                    rationale: compiled.rule.rationale.to_owned(),
                    remediation: compiled.rule.remediation.to_owned(),
                    package: package.to_owned(),
                    file: path.to_owned(),
                    location,
                    matched_code,
                    suppressed: false,
                });
            }
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests;
