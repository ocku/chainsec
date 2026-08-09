use std::path::{Path, PathBuf};

use tree_sitter::{Parser, Query, QueryCursor, StreamingIterator};

use super::entropy::has_high_entropy;
use crate::{
    error::{Error, Result},
    model::{AnalysisPoint, Language, Location, Rule},
};

use super::semantic;

pub(super) struct CompiledRule<'a> {
    rule: &'a Rule,
    query: Option<Query>,
    capture_index: Option<u32>,
    semantic_matcher: Option<semantic::SemanticMatcher>,
}

pub fn validate_rules(rules: &[Rule]) -> Result<()> {
    compile_rules(rules).map(|_| ())
}

pub(super) fn compile_rules(rules: &[Rule]) -> Result<Vec<CompiledRule<'_>>> {
    rules
        .iter()
        .map(|rule| {
            if let Some(semantic_rule) = &rule.semantic {
                return Ok(CompiledRule {
                    rule,
                    query: None,
                    capture_index: None,
                    semantic_matcher: Some(semantic::compile(semantic_rule)?),
                });
            }
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
                query: Some(query),
                capture_index: Some(capture_index),
                semantic_matcher: None,
            })
        })
        .collect()
}

pub(super) fn scan_file(
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
        match (
            &compiled.rule.semantic,
            &compiled.query,
            compiled.capture_index,
            &compiled.semantic_matcher,
        ) {
            (None, Some(query), Some(capture_index), None) => {
                let mut cursor = QueryCursor::new();
                let mut matches = cursor.matches(query, tree.root_node(), source);
                while let Some(query_match) = matches.next() {
                    for capture in query_match
                        .captures
                        .iter()
                        .filter(|capture| capture.index == capture_index)
                    {
                        push_finding(
                            &mut findings,
                            compiled.rule,
                            path,
                            package,
                            source,
                            capture.node.byte_range(),
                            location_for(
                                capture.node.start_position(),
                                capture.node.end_position(),
                            ),
                        );
                    }
                }
            }
            (Some(_), None, None, Some(matcher)) => {
                let text = std::str::from_utf8(source).map_err(|error| Error::Scan {
                    path: path.to_owned(),
                    message: format!("semantic matching requires valid UTF-8 source: {error}"),
                })?;
                for range in semantic::matches(matcher, text, tree.root_node()) {
                    let location = location_for_offsets(source, &range);
                    push_finding(
                        &mut findings,
                        compiled.rule,
                        path,
                        package,
                        source,
                        range,
                        location,
                    );
                }
            }
            _ => unreachable!("compiled rule does not match its matcher"),
        }
    }
    Ok(findings)
}

fn push_finding(
    findings: &mut Vec<AnalysisPoint>,
    rule: &Rule,
    path: &Path,
    package: &str,
    source: &[u8],
    range: std::ops::Range<usize>,
    location: Location,
) {
    let matched_bytes = &source[range];
    if rule
        .entropy
        .as_ref()
        .is_some_and(|matcher| !has_high_entropy(matched_bytes, matcher))
    {
        return;
    }
    let matched_code = String::from_utf8_lossy(matched_bytes).into_owned();
    let file = path.to_string_lossy();
    findings.push(AnalysisPoint {
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
    });
}

fn grammar(language: Language) -> tree_sitter::Language {
    match language {
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
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

fn location_for_offsets(source: &[u8], range: &std::ops::Range<usize>) -> Location {
    let point_for = |offset: usize| {
        let prefix = &source[..offset];
        let row = prefix.iter().filter(|byte| **byte == b'\n').count();
        let column = prefix
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(prefix.len(), |newline| prefix.len() - newline - 1);
        tree_sitter::Point { row, column }
    };
    location_for(point_for(range.start), point_for(range.end))
}
