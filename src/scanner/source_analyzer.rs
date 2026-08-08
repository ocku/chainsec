use std::path::{Path, PathBuf};

use tree_sitter::{Parser, Query, QueryCursor, StreamingIterator};

use super::entropy::has_high_entropy;
use crate::{
    error::{Error, Result},
    model::{AnalysisPoint, Language, Location, Rule},
};

pub(super) struct CompiledRule<'a> {
    rule: &'a Rule,
    query: Query,
    capture_index: u32,
}

pub fn validate_rules(rules: &[Rule]) -> Result<()> {
    compile_rules(rules).map(|_| ())
}

pub(super) fn compile_rules(rules: &[Rule]) -> Result<Vec<CompiledRule<'_>>> {
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
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&compiled.query, tree.root_node(), source);
        while let Some(query_match) = matches.next() {
            for capture in query_match
                .captures
                .iter()
                .filter(|capture| capture.index == compiled.capture_index)
            {
                let node = capture.node;
                let location = location_for(node.start_position(), node.end_position());
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
