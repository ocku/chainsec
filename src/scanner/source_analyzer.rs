use std::path::{Path, PathBuf};

use tree_sitter::{CaptureQuantifier, Parser, Query, QueryCursor, StreamingIterator};

use super::entropy::has_high_entropy;
use crate::{
    error::{Error, Result},
    model::{AnalysisPoint, Language, Location, Rule},
};

pub(crate) struct CompiledRuleSet {
    language: Language,
    rules: Vec<Rule>,
    query: Query,
    pattern_rule_indexes: Vec<usize>,
    capture_index: u32,
}

pub fn validate_rules(rules: &[Rule]) -> Result<()> {
    compile_rules(rules).map(|_| ())
}

pub(crate) fn compile_rules(rules: &[Rule]) -> Result<Vec<CompiledRuleSet>> {
    [Language::Python, Language::JavaScript, Language::TypeScript]
        .into_iter()
        .filter_map(|language| {
            let language_rules = rules
                .iter()
                .filter(|rule| rule.language == language)
                .cloned()
                .collect::<Vec<_>>();
            (!language_rules.is_empty()).then_some((language, language_rules))
        })
        .map(|(language, language_rules)| compile_rule_set(language, language_rules))
        .collect()
}

fn compile_rule_set(language: Language, rules: Vec<Rule>) -> Result<CompiledRuleSet> {
    let grammar = grammar(language);
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
        rules,
        query,
        pattern_rule_indexes,
        capture_index,
    })
}

fn rule_index_for_offset(rule_offsets: &[usize], offset: usize) -> usize {
    rule_offsets.partition_point(|rule_offset| *rule_offset <= offset) - 1
}

pub(super) fn scan_file(
    path: &Path,
    package: &str,
    language: Language,
    source: &[u8],
    rule_sets: &[CompiledRuleSet],
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
    let Some(compiled) = rule_sets
        .iter()
        .find(|compiled| compiled.language == language)
    else {
        return Ok(findings);
    };
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&compiled.query, tree.root_node(), source);
    while let Some(query_match) = matches.next() {
        let rule_index = compiled.pattern_rule_indexes[query_match.pattern_index];
        let rule = &compiled.rules[rule_index];
        for capture in query_match
            .captures
            .iter()
            .filter(|capture| capture.index == compiled.capture_index)
        {
            push_finding(
                &mut findings,
                rule,
                path,
                package,
                source,
                capture.node.byte_range(),
                location_for(capture.node.start_position(), capture.node.end_position()),
            );
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
