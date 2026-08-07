use std::{collections::HashMap, sync::LazyLock};

use regex::Regex;
use url::Url;

use crate::model::EntropyMatcher;

pub(super) fn has_high_entropy(literal: &[u8], matcher: &EntropyMatcher) -> bool {
    let Ok(literal) = std::str::from_utf8(literal) else {
        return false;
    };
    let Some(quote_start) = literal.find(['\'', '"']) else {
        return false;
    };
    let quoted = &literal[quote_start..];
    let quote = quoted.as_bytes()[0];
    let delimiter_len = if quoted.as_bytes().starts_with(&[quote, quote, quote]) {
        3
    } else {
        1
    };
    if quoted.len() < delimiter_len * 2
        || !quoted.as_bytes()[quoted.len() - delimiter_len..]
            .iter()
            .all(|byte| *byte == quote)
    {
        return false;
    }
    let value = &quoted[delimiter_len..quoted.len() - delimiter_len];
    let length = value.chars().count();
    let whitespace_ratio = value
        .chars()
        .filter(|character| character.is_whitespace())
        .count() as f64
        / length as f64;
    if length < matcher.minimum_length
        || whitespace_ratio > matcher.maximum_whitespace_ratio
        || is_character_sequence(value)
        || is_structured_literal(value)
    {
        return false;
    }

    let mut frequencies = HashMap::new();
    for character in value.chars() {
        *frequencies.entry(character).or_insert(0usize) += 1;
    }
    let length = length as f64;
    let entropy = frequencies.values().fold(0.0, |entropy, count| {
        let probability = *count as f64 / length;
        entropy - probability * probability.log2()
    });
    entropy >= matcher.minimum_entropy
}

fn is_character_sequence(value: &str) -> bool {
    const RANGES: [(u8, u8); 3] = [(b'0', b'9'), (b'A', b'Z'), (b'a', b'z')];

    (0..RANGES.len()).any(|first| {
        (0..RANGES.len()).any(|second| {
            first != second
                && value
                    .bytes()
                    .eq((RANGES[first].0..=RANGES[first].1)
                        .chain(RANGES[second].0..=RANGES[second].1))
        })
    })
}

pub(super) fn is_structured_literal(value: &str) -> bool {
    let value = value.trim();
    looks_like_url(value)
        || looks_like_sql(value)
        || looks_like_regex(value)
        || looks_like_format_string(value)
        || looks_like_sentence(value)
}

fn looks_like_url(value: &str) -> bool {
    static URL_PATTERN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"(?i)(?:https?|ftp)://[^\s\"'<>]+"#).unwrap());

    URL_PATTERN.find_iter(value).any(|candidate| {
        let Ok(url) = Url::parse(candidate.as_str()) else {
            return false;
        };

        matches!(url.scheme(), "http" | "https" | "ftp") && url.host().is_some()
    })
}

fn looks_like_sql(value: &str) -> bool {
    const STATEMENT_KEYWORDS: &[&str] = &["select", "insert", "update", "delete", "with"];

    let mut words = value.split_whitespace();
    let Some(first_word) = words.next() else {
        return false;
    };
    let first_word = first_word.trim_matches(|character: char| !character.is_ascii_alphabetic());
    let first_word = first_word.to_ascii_lowercase();
    let is_statement = STATEMENT_KEYWORDS.contains(&first_word.as_str());
    is_statement && value.chars().any(char::is_whitespace)
}

fn looks_like_regex(value: &str) -> bool {
    let has_regex_prefix = value.starts_with("r\"")
        || value.starts_with("r'")
        || value.starts_with("(?")
        || value.starts_with('^')
        || value.starts_with('[')
        || value.starts_with("\\A");
    let has_regex_syntax = value.contains('[')
        || value.contains(']')
        || value.contains('(')
        || value.contains(')')
        || value.contains('\\');

    has_regex_prefix && has_regex_syntax
}

fn looks_like_format_string(value: &str) -> bool {
    let has_braced_field = value.split('{').skip(1).any(|field| {
        field
            .split_once('}')
            .is_some_and(|(contents, _)| contents.is_empty() || contents.contains(':'))
    });

    has_braced_field || value.contains("%s") || value.contains("%(")
}

fn looks_like_sentence(value: &str) -> bool {
    value.chars().any(char::is_whitespace) && matches!(value.chars().last(), Some('.' | '!' | '?'))
}
