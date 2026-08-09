use regex::Regex;
use tree_sitter::Node;

use crate::{
    error::{Error, Result},
    model::SemanticRule,
};

pub(super) struct SemanticMatcher {
    rule: SemanticRule,
    patterns: Vec<Regex>,
    string_literal_pattern: Option<Regex>,
}

pub(super) fn compile(rule: &SemanticRule) -> Result<SemanticMatcher> {
    let patterns: &[&str] = match rule {
        SemanticRule::JsTsDynamicExecution => &[
            r"(?m)(?:^|[^\w.$])(?:eval|Function)\s*\(",
            r#"(?m)(?:globalThis|window|global)\s*\[\s*['\"](?:eval|Function)['\"]\s*\]\s*\("#,
            r#"(?m)\b(?:setTimeout|setInterval)\s*\(\s*['\"]"#,
            r"(?m)\b(?:vm\s*\.\s*runIn(?:This|New|Context)|runIn(?:This|New|Context))\s*\(",
            r"(?m)\bnew\s+Worker\s*\(\s*(?:URL\s*\.\s*createObjectURL|blob)",
        ],
        SemanticRule::JsTsStringTableObfuscation => &[
            r"(?s)(?:const|let|var)\s+[_$A-Za-z][\w$]*\s*=\s*\[.{20,}?\].{0,600}?(?:\[\s*[_$A-Za-z][\w$]*\s*\]|\.shift\s*\()",
        ],

        SemanticRule::JsTsRc4Decoder => &[
            r"(?s)(?:Array\s*\(\s*256\s*\)|new\s+Array\s*\(\s*256\s*\)).{0,2000}?(?:charCodeAt|fromCharCode).{0,2000}?(?:\^|%\s*256)",
        ],
        SemanticRule::JsTsVirtualMachine => &[
            r"(?s)(?:Uint8Array|DataView|bytecode).{0,2500}?(?:opcode|dispatch|instruction).{0,2500}?(?:switch|while)",
        ],
    };

    let patterns = patterns
        .iter()
        .map(|pattern| {
            Regex::new(pattern).map_err(|error| Error::Scan {
                path: "<rules>".into(),
                message: format!("semantic rule {rule:?}: {error}"),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let string_literal_pattern = matches!(rule, SemanticRule::JsTsStringTableObfuscation)
        .then(|| Regex::new(r#"['\"][^'\"]*['\"]"#).expect("string literal matcher is valid"));

    Ok(SemanticMatcher {
        rule: rule.clone(),
        patterns,
        string_literal_pattern,
    })
}

/// Bounded structural matching. All analysis is local to the parsed source text
/// and never evaluates code.
pub(super) fn matches(
    matcher: &SemanticMatcher,
    source: &str,
    syntax_tree: Node<'_>,
) -> Vec<std::ops::Range<usize>> {
    let mut found = Vec::new();
    for regex in &matcher.patterns {
        found.extend(regex.find_iter(source).map(|matched| matched.range()));
    }

    if matches!(matcher.rule, SemanticRule::JsTsDynamicExecution) {
        found = found
            .into_iter()
            .filter(|range| is_executable_js_match(syntax_tree, source, range.clone()))
            .filter_map(|range| enclosing_js_execution_node(syntax_tree, source, range))
            .collect();
    }
    if matches!(matcher.rule, SemanticRule::JsTsStringTableObfuscation) {
        let string_literal_pattern = matcher
            .string_literal_pattern
            .as_ref()
            .expect("string-table matchers compile a string literal pattern");
        found
            .retain(|range| looks_like_string_table(source, range.clone(), string_literal_pattern));
    }
    found.sort_by_key(|range| range.start);
    found.dedup();
    found
}

/// Keeps this heuristic limited to arrays that actually contain a string table.
/// Ordinary arrays, codec tables, and module lists should not match merely because
/// they are indexed later in the file.
fn looks_like_string_table(
    source: &str,
    range: std::ops::Range<usize>,
    string_literal_pattern: &Regex,
) -> bool {
    let matched = &source[range];
    let Some(open) = matched.find('[') else {
        return false;
    };
    let Some(close) = matched[open + 1..].find(']') else {
        return false;
    };
    let array = &matched[open + 1..open + 1 + close];
    if array.contains("require(") || array.contains("...") {
        return false;
    }

    let string_count = string_literal_pattern.find_iter(array).count();
    string_count >= 5
}

/// Expands a regex hit to the complete syntax node representing the execution
/// invocation, rather than reporting only the text matched by the heuristic.
fn enclosing_js_execution_node(
    syntax_tree: Node<'_>,
    source: &str,
    range: std::ops::Range<usize>,
) -> Option<std::ops::Range<usize>> {
    let start = source_offset_after_whitespace(source, range.start, range.end)?;
    let mut node = syntax_tree.descendant_for_byte_range(start, start + 1)?;
    loop {
        if matches!(node.kind(), "call_expression" | "new_expression") {
            return Some(node.byte_range());
        }
        node = node.parent()?;
    }
}

fn source_offset_after_whitespace(source: &str, start: usize, end: usize) -> Option<usize> {
    (start..end).find(|offset| {
        source
            .as_bytes()
            .get(*offset)
            .is_some_and(|byte| !byte.is_ascii_whitespace())
    })
}

/// Excludes regex hits in lexical and TypeScript-only syntax. Direct `eval`
/// and `Function` calls are also excluded when their identifier is shadowed in
/// the lexical scope containing the call.
fn is_executable_js_match(
    syntax_tree: Node<'_>,
    source: &str,
    range: std::ops::Range<usize>,
) -> bool {
    let Some(mut node) = syntax_tree.descendant_for_byte_range(range.start, range.end) else {
        return false;
    };

    loop {
        if matches!(
            node.kind(),
            "comment"
                | "string"
                | "template_string"
                | "interface_declaration"
                | "type_alias_declaration"
                | "type_annotation"
        ) {
            return false;
        }
        let Some(parent) = node.parent() else {
            break;
        };
        node = parent;
    }

    let matched = &source[range.clone()];
    for name in ["eval", "Function"] {
        if let Some(offset) = matched.rfind(name) {
            let start = range.start + offset;
            let end = start + name.len();
            if !source.is_char_boundary(start) || !source.is_char_boundary(end) {
                return false;
            }
            let identifier = start..end;
            if !identifier_is_called(syntax_tree, identifier.clone())
                || identifier_is_shadowed(syntax_tree, source, identifier, name)
            {
                return false;
            }
        }
    }
    true
}

fn identifier_is_called(syntax_tree: Node<'_>, identifier: std::ops::Range<usize>) -> bool {
    let Some(mut node) = syntax_tree.descendant_for_byte_range(identifier.start, identifier.end)
    else {
        return false;
    };

    loop {
        if matches!(node.kind(), "call_expression" | "new_expression") {
            return true;
        }
        let Some(parent) = node.parent() else {
            return false;
        };
        node = parent;
    }
}

fn identifier_is_shadowed(
    syntax_tree: Node<'_>,
    source: &str,
    identifier: std::ops::Range<usize>,
    name: &str,
) -> bool {
    let Some(mut node) = syntax_tree.descendant_for_byte_range(identifier.start, identifier.end)
    else {
        return false;
    };

    loop {
        if is_scope(node) && scope_declares(node, source, name) {
            return true;
        }
        let Some(parent) = node.parent() else {
            return false;
        };
        node = parent;
    }
}

fn is_scope(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "program"
            | "statement_block"
            | "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "generator_function"
            | "method_definition"
    )
}

fn scope_declares(scope: Node<'_>, source: &str, name: &str) -> bool {
    if matches!(
        scope.kind(),
        "function_declaration" | "function_expression" | "arrow_function"
    ) && scope
        .child_by_field_name("parameters")
        .is_some_and(|parameters| contains_identifier(parameters, source, name))
    {
        return true;
    }

    declares_in_scope(scope, source, name, true)
}

fn declares_in_scope(node: Node<'_>, source: &str, name: &str, is_root: bool) -> bool {
    if matches!(node.kind(), "variable_declarator" | "function_declaration")
        && node
            .child_by_field_name("name")
            .is_some_and(|binding| contains_identifier(binding, source, name))
    {
        return true;
    }
    if !is_root && is_scope(node) {
        return false;
    }

    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| declares_in_scope(child, source, name, false))
}

fn contains_identifier(node: Node<'_>, source: &str, name: &str) -> bool {
    if node.kind() == "identifier" && &source[node.byte_range()] == name {
        return true;
    }
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| contains_identifier(child, source, name))
}
