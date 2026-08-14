use std::{
    collections::HashSet,
    ops::ControlFlow,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::Instant,
};

use rayon::prelude::*;
use tree_sitter::{CaptureQuantifier, ParseOptions, Parser, Query, QueryCursor, StreamingIterator};

use super::entropy::has_high_entropy;
use crate::{
    error::{Error, Result},
    model::{AnalysisPoint, Language, Location, OperationalIssue, Rule},
};

pub(crate) struct CompiledRuleSet {
    language: Language,
    is_tsx: bool,
    rules: Vec<Rule>,
    query: Query,
    pattern_rule_indexes: Vec<usize>,
    capture_index: u32,
}

pub fn validate_rules(rules: &[Rule]) -> Result<()> {
    compile_rules(rules).map(|_| ())
}

pub(crate) fn compile_rules(rules: &[Rule]) -> Result<Vec<CompiledRuleSet>> {
    let language_rules: Vec<_> = [Language::Python, Language::JavaScript, Language::TypeScript]
        .into_iter()
        .filter_map(|language| {
            let rules = rules
                .iter()
                .filter(|rule| rule.language == language)
                .cloned()
                .collect::<Vec<_>>();
            (!rules.is_empty()).then_some((language, rules))
        })
        .collect();

    language_rules
        .into_par_iter()
        .map(|(language, rules)| {
            let mut compiled = vec![compile_rule_set(language, false, rules.clone())?];
            if language == Language::TypeScript {
                compiled.push(compile_rule_set(language, true, rules)?);
            }
            Ok(compiled)
        })
        .collect::<Result<Vec<_>>>()
        .map(|compiled| compiled.into_iter().flatten().collect())
}

fn compile_rule_set(language: Language, is_tsx: bool, rules: Vec<Rule>) -> Result<CompiledRuleSet> {
    let grammar = grammar(language, is_tsx);
    let mut combined_query = String::new();
    let mut rule_offsets = Vec::with_capacity(rules.len());
    for rule in &rules {
        if !combined_query.is_empty() {
            combined_query.push('\n');
        }
        rule_offsets.push(combined_query.len());
        combined_query.push_str(&rule.query);
    }

    let query = Query::new(&grammar, &combined_query).map_err(|error| {
        let rule_index = rule_index_for_offset(&rule_offsets, error.offset);
        Error::Scan {
            path: PathBuf::from("<rules>"),
            message: format!("rule {}: {error}", rules[rule_index].id),
        }
    })?;
    let capture_index = query
        .capture_index_for_name("match")
        .ok_or_else(|| Error::Scan {
            path: PathBuf::from("<rules>"),
            message: format!("combined {language:?} rules have no @match capture"),
        })?;
    let mut pattern_rule_indexes = Vec::with_capacity(query.pattern_count());
    let mut rules_with_match_capture = vec![false; rules.len()];

    for pattern_index in 0..query.pattern_count() {
        let rule_index =
            rule_index_for_offset(&rule_offsets, query.start_byte_for_pattern(pattern_index));
        let quantifiers = query.capture_quantifiers(pattern_index);
        rules_with_match_capture[rule_index] |=
            quantifiers[capture_index as usize] != CaptureQuantifier::Zero;
        pattern_rule_indexes.push(rule_index);
    }

    if let Some((rule_index, _)) = rules_with_match_capture
        .iter()
        .enumerate()
        .find(|(_, has_capture)| !**has_capture)
    {
        return Err(Error::Scan {
            path: PathBuf::from("<rules>"),
            message: format!("rule {} has no @match capture", rules[rule_index].id),
        });
    }

    Ok(CompiledRuleSet {
        language,
        is_tsx,
        rules,
        query,
        pattern_rule_indexes,
        capture_index,
    })
}

fn rule_index_for_offset(rule_offsets: &[usize], offset: usize) -> usize {
    rule_offsets.partition_point(|rule_offset| *rule_offset <= offset) - 1
}

pub(super) struct SourceFileScan {
    pub(super) findings: Vec<AnalysisPoint>,
    pub(super) issues: Vec<OperationalIssue>,
}

pub(super) struct SourceScanInput<'a> {
    pub(super) path: &'a Path,
    pub(super) package: &'a str,
    pub(super) language: Language,
    pub(super) is_tsx: bool,
    pub(super) source: &'a [u8],
    pub(super) rule_sets: &'a [CompiledRuleSet],
    pub(super) fail_on_parse_error: bool,
    pub(super) started: Instant,
    pub(super) max_scan_duration: std::time::Duration,
}

pub(super) struct SourceScanWorker {
    parser: Parser,
    cursor: QueryCursor,
}

impl SourceScanWorker {
    pub(super) fn new() -> Self {
        let mut cursor = QueryCursor::new();
        cursor.set_match_limit(65_536);
        Self {
            parser: Parser::new(),
            cursor,
        }
    }
}

pub(super) fn scan_file(
    worker: &mut SourceScanWorker,
    input: SourceScanInput<'_>,
) -> Result<SourceFileScan> {
    let SourceScanInput {
        path,
        package,
        language,
        is_tsx,
        source,
        rule_sets,
        fail_on_parse_error,
        started,
        max_scan_duration,
    } = input;
    ensure_within_duration(started, max_scan_duration, path)?;
    let grammar = grammar(language, is_tsx);
    worker
        .parser
        .set_language(&grammar)
        .map_err(|error| Error::Scan {
            path: path.to_owned(),
            message: error.to_string(),
        })?;
    let cancelled = AtomicUsize::new(0);
    let mut progress_callbacks = 0_u8;
    // Tree-sitter can invoke this callback extremely frequently. Sampling the
    // clock periodically preserves cancellation for long parses without making
    // every parser step perform a system clock read.
    let mut progress: &mut dyn FnMut(&tree_sitter::ParseState) -> ControlFlow<()> = &mut |_| {
        progress_callbacks = progress_callbacks.wrapping_add(1);
        if progress_callbacks != 0 || started.elapsed() <= max_scan_duration {
            ControlFlow::Continue(())
        } else {
            cancelled.store(1, Ordering::Relaxed);
            ControlFlow::Break(())
        }
    };
    let mut read_source = |byte, _| &source[byte..];
    let tree = worker.parser.parse_with_options(
        &mut read_source,
        None,
        Some(ParseOptions::new().progress_callback(&mut progress)),
    );
    if cancelled.load(Ordering::Relaxed) != 0 {
        return Err(Error::LimitExceeded {
            resource: format!("scan duration for {}", path.display()),
            limit: max_scan_duration.as_secs(),
        });
    }
    ensure_within_duration(started, max_scan_duration, path)?;
    let tree = tree.ok_or_else(|| Error::Scan {
        path: path.to_owned(),
        message: "parser returned no syntax tree".to_owned(),
    })?;

    let mut issues = Vec::new();
    if tree.root_node().has_error() {
        let message = format!("source contains syntax errors: {}", path.display());
        issues.push(OperationalIssue {
            code: "parse_error".to_owned(),
            message,
            package: Some(package.to_owned()),
            operation: "source parsing".to_owned(),
            fatal: fail_on_parse_error,
        });
    }

    let mut findings = Vec::new();
    let Some(compiled) = rule_sets
        .iter()
        .find(|compiled| compiled.language == language && compiled.is_tsx == is_tsx)
    else {
        return Ok(SourceFileScan { findings, issues });
    };
    let mut deduplicated = HashSet::new();
    {
        let mut matches = worker
            .cursor
            .matches(&compiled.query, tree.root_node(), source);
        let mut query_matches = 0_u8;
        while let Some(query_match) = matches.next() {
            query_matches = query_matches.wrapping_add(1);
            if query_matches == 0 {
                ensure_within_duration(started, max_scan_duration, path)?;
            }
            let rule_index = compiled.pattern_rule_indexes[query_match.pattern_index];
            let rule = &compiled.rules[rule_index];
            for capture in query_match
                .captures
                .iter()
                .filter(|capture| capture.index == compiled.capture_index)
            {
                if rule.entropy.as_ref().is_some_and(|matcher| {
                    !has_high_entropy(&source[capture.node.byte_range()], matcher)
                }) {
                    continue;
                }
                let finding = make_finding(
                    rule,
                    path,
                    package,
                    source,
                    capture.node.byte_range(),
                    location_for(capture.node.start_position(), capture.node.end_position()),
                );
                if deduplicated.insert(finding.id.clone()) {
                    findings.push(finding);
                }
            }
        }
    }
    ensure_within_duration(started, max_scan_duration, path)?;
    if worker.cursor.did_exceed_match_limit() {
        return Err(Error::LimitExceeded {
            resource: "in-progress query matches".to_owned(),
            limit: 65_536,
        });
    }
    Ok(SourceFileScan { findings, issues })
}

pub(crate) fn ensure_within_duration(
    started: Instant,
    limit: std::time::Duration,
    path: &Path,
) -> Result<()> {
    if started.elapsed() <= limit {
        return Ok(());
    }
    Err(Error::LimitExceeded {
        resource: format!("scan duration for {}", path.display()),
        limit: limit.as_secs(),
    })
}

pub(crate) fn reserve_finding(finding_budget: &AtomicU64, max_findings: u64) -> Result<()> {
    let mut claimed = finding_budget.load(Ordering::Relaxed);
    loop {
        if claimed >= max_findings {
            return Err(Error::LimitExceeded {
                resource: "findings".to_owned(),
                limit: max_findings,
            });
        }
        match finding_budget.compare_exchange_weak(
            claimed,
            claimed + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Ok(()),
            Err(current) => claimed = current,
        }
    }
}

fn make_finding(
    rule: &Rule,
    path: &Path,
    package: &str,
    source: &[u8],
    range: std::ops::Range<usize>,
    location: Location,
) -> AnalysisPoint {
    let matched_bytes = &source[range];
    let matched_code = String::from_utf8_lossy(matched_bytes).into_owned();
    let file = path.to_string_lossy();
    AnalysisPoint {
        id: AnalysisPoint::stable_id(
            &rule.id,
            rule.version,
            package,
            &file,
            &location,
            &matched_code,
        ),
        rule_id: rule.id.to_owned(),
        rule_version: rule.version,
        finding_type: rule.finding_type,
        risk: rule.risk,
        confidence: rule.confidence,
        rationale: rule.rationale.to_owned(),
        remediation: rule.remediation.to_owned(),
        capability: rule.capability,
        package: package.to_owned(),
        file: path.to_owned(),
        location,
        matched_code,
        suppressed: false,
        suppression: None,
    }
}

fn grammar(language: Language, is_tsx: bool) -> tree_sitter::Language {
    match language {
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript if is_tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    }
}

fn location_for(start: tree_sitter::Point, end: tree_sitter::Point) -> Location {
    Location {
        start_line: start.row + 1,
        start_column: start.column + 1,
        end_line: end.row + 1,
        end_column: end.column + 1,
    }
}
