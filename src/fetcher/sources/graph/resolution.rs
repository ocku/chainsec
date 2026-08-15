use std::path::Path;

use tree_sitter::Parser;
use url::Url;

use crate::error::{Error, Result};

pub(super) fn module_extension(url: &Url) -> &str {
    Path::new(url.path())
        .extension()
        .and_then(|value| value.to_str())
        .filter(|value| {
            matches!(
                *value,
                "js" | "mjs" | "cjs" | "jsx" | "ts" | "mts" | "cts" | "tsx"
            )
        })
        .unwrap_or("ts")
}

enum RemoteModuleResolution {
    Url(Url),
    RegistryNotMaterialized { scheme: &'static str },
    Unsupported { reason: &'static str },
    InvalidRelativeUrl,
}

#[allow(dead_code)]
pub(super) fn resolve_graph_modules(
    base: &Url,
    source: &[u8],
    extension: &str,
) -> Result<Vec<Url>> {
    let mut modules = Vec::new();
    resolve_graph_modules_with_sink(base, source, extension, |module| {
        modules.push(module);
        Ok(())
    })?;
    Ok(modules)
}

pub(super) fn resolve_graph_modules_with_sink<F>(
    base: &Url,
    source: &[u8],
    extension: &str,
    mut sink: F,
) -> Result<()>
where
    F: FnMut(Url) -> Result<()>,
{
    let language = match extension {
        "jsx" | "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
        "ts" | "mts" | "cts" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        _ => tree_sitter_javascript::LANGUAGE.into(),
    };
    let mut parser = Parser::new();
    if parser.set_language(&language).is_err() {
        return Ok(());
    }
    let Some(tree) = parser.parse(source, None) else {
        return Ok(());
    };
    collect_static_module_specifiers(tree.root_node(), source, base, &mut |specifier| {
        match resolve_remote_module(base, &specifier) {
            RemoteModuleResolution::Url(url) => sink(url),
            RemoteModuleResolution::RegistryNotMaterialized { scheme } => Err(Error::Policy {
                operation: "Deno graph resolution".to_owned(),
                message: format!(
                    "static literal {scheme}: specifier {specifier:?} imported by {base} cannot yet be materialized; the Deno graph would be incomplete"
                ),
            }),
            RemoteModuleResolution::Unsupported { reason } => Err(Error::Policy {
                operation: "Deno graph resolution".to_owned(),
                message: format!(
                    "static literal specifier {specifier:?} imported by {base} is unsupported ({reason}); the Deno graph would be incomplete"
                ),
            }),
            RemoteModuleResolution::InvalidRelativeUrl => Err(Error::Policy {
                operation: "Deno graph resolution".to_owned(),
                message: format!(
                    "static URL-relative specifier {specifier:?} imported by {base} is invalid; the Deno graph would be incomplete"
                ),
            }),
        }
    })
}

fn resolve_remote_module(base: &Url, specifier: &str) -> RemoteModuleResolution {
    if specifier.starts_with("./") || specifier.starts_with("../") || specifier.starts_with('/') {
        if has_malformed_percent_encoding(specifier) {
            return RemoteModuleResolution::InvalidRelativeUrl;
        }
        return base
            .join(specifier)
            .map(RemoteModuleResolution::Url)
            .unwrap_or(RemoteModuleResolution::InvalidRelativeUrl);
    }

    match Url::parse(specifier) {
        Ok(url) if matches!(url.scheme(), "http" | "https") => RemoteModuleResolution::Url(url),
        Ok(url) if matches!(url.scheme(), "npm" | "jsr") => {
            RemoteModuleResolution::RegistryNotMaterialized {
                scheme: if url.scheme() == "npm" { "npm" } else { "jsr" },
            }
        }
        Ok(_) => RemoteModuleResolution::Unsupported {
            reason: "this URL scheme is not supported by the graph fetcher",
        },
        Err(_) if specifier.contains(':') => RemoteModuleResolution::Unsupported {
            reason: "the URL specifier is invalid or uses an unsupported custom loader",
        },
        Err(_) => RemoteModuleResolution::Unsupported {
            reason: "bare specifiers are not supported by the graph fetcher",
        },
    }
}

fn has_malformed_percent_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.iter().enumerate().any(|(index, byte)| {
        *byte == b'%'
            && (index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit())
    })
}

fn collect_static_module_specifiers<F>(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    base: &Url,
    sink: &mut F,
) -> Result<()>
where
    F: FnMut(String) -> Result<()>,
{
    if matches!(node.kind(), "import_statement" | "export_statement")
        && let Some(source_node) = node.child_by_field_name("source")
    {
        sink(string_literal_value(source_node, source).map_err(|message| Error::Policy {
            operation: "Deno graph resolution".to_owned(),
            message: format!(
                "could not decode a static literal specifier imported by {base}: {message}; the Deno graph would be incomplete"
            ),
        })?)?;
    }
    if node.kind() == "call_expression"
        && node
            .child_by_field_name("function")
            .is_some_and(|function| function.utf8_text(source).ok() == Some("import"))
        && let Some(arguments) = node.child_by_field_name("arguments")
        && let Some(argument) = arguments.named_child(0)
        && argument.kind() == "string"
    {
        sink(string_literal_value(argument, source).map_err(|message| Error::Policy {
            operation: "Deno graph resolution".to_owned(),
            message: format!(
                "could not decode a static literal specifier imported by {base}: {message}; the Deno graph would be incomplete"
            ),
        })?)?;
    }
    for child in node.named_children(&mut node.walk()) {
        collect_static_module_specifiers(child, source, base, sink)?;
    }
    Ok(())
}

fn string_literal_value(
    node: tree_sitter::Node<'_>,
    source: &[u8],
) -> std::result::Result<String, String> {
    if node.kind() != "string" {
        return Err("the module source is not a string literal".to_owned());
    }
    let raw = node
        .utf8_text(source)
        .map_err(|_| "the string literal is not valid UTF-8".to_owned())?;
    let Some(quote) = raw
        .chars()
        .next()
        .filter(|quote| matches!(quote, '\'' | '"'))
    else {
        return Err("the string literal has no valid quote delimiter".to_owned());
    };
    if !raw.ends_with(quote) || raw.len() < quote.len_utf8() * 2 {
        return Err("the string literal has mismatched quote delimiters".to_owned());
    }
    decode_module_specifier(&raw[quote.len_utf8()..raw.len() - quote.len_utf8()])
}

fn decode_module_specifier(value: &str) -> std::result::Result<String, String> {
    let chars: Vec<char> = value.chars().collect();
    let mut decoded = String::with_capacity(value.len());
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        index += 1;
        if character != '\\' {
            if matches!(character, '\n' | '\r' | '\u{2028}' | '\u{2029}') {
                return Err("the string literal contains an unescaped line terminator".to_owned());
            }
            decoded.push(character);
            continue;
        }

        let Some(escape) = chars.get(index).copied() else {
            return Err("the string literal ends with an incomplete escape".to_owned());
        };
        index += 1;
        match escape {
            '\\' | '\'' | '"' => decoded.push(escape),
            'b' => decoded.push('\u{0008}'),
            'f' => decoded.push('\u{000C}'),
            'n' => decoded.push('\n'),
            'r' => decoded.push('\r'),
            't' => decoded.push('\t'),
            'v' => decoded.push('\u{000B}'),
            '0' => {
                if chars.get(index).is_some_and(char::is_ascii_digit) {
                    return Err("legacy octal escapes are unsupported".to_owned());
                }
                decoded.push('\0');
            }
            '\n' | '\u{2028}' | '\u{2029}' => {}
            '\r' => {
                if chars.get(index) == Some(&'\n') {
                    index += 1;
                }
            }
            'x' => decoded.push(char_from_hex(&chars, &mut index, 2, "hexadecimal")?),
            'u' => decoded.push(unicode_escape(&chars, &mut index)?),
            _ => return Err(format!("unsupported escape sequence \\{escape}")),
        }
    }
    Ok(decoded)
}

fn char_from_hex(
    chars: &[char],
    index: &mut usize,
    length: usize,
    kind: &str,
) -> std::result::Result<char, String> {
    let value = hex_value(chars, index, length, kind)?;
    char::from_u32(value).ok_or_else(|| format!("invalid {kind} escape"))
}

fn unicode_escape(chars: &[char], index: &mut usize) -> std::result::Result<char, String> {
    if chars.get(*index) == Some(&'{') {
        *index += 1;
        let start = *index;
        while chars.get(*index).is_some_and(char::is_ascii_hexdigit) {
            *index += 1;
        }
        let length = *index - start;
        if !(1..=6).contains(&length) || chars.get(*index) != Some(&'}') {
            return Err("invalid Unicode code-point escape".to_owned());
        }
        let mut code_point_index = start;
        let value = hex_value(chars, &mut code_point_index, length, "Unicode code-point")?;
        *index += 1;
        return char::from_u32(value)
            .ok_or_else(|| "Unicode code-point escape is not a valid scalar value".to_owned());
    }

    let value = hex_value(chars, index, 4, "Unicode")?;
    if !(0xD800..=0xDBFF).contains(&value) {
        return char::from_u32(value)
            .ok_or_else(|| "Unicode escape is not a valid scalar value".to_owned());
    }

    if chars.get(*index) != Some(&'\\') || chars.get(*index + 1) != Some(&'u') {
        return Err("Unicode escape contains an unpaired high surrogate".to_owned());
    }
    *index += 2;
    let low = hex_value(chars, index, 4, "Unicode")?;
    if !(0xDC00..=0xDFFF).contains(&low) {
        return Err("Unicode escape contains an invalid surrogate pair".to_owned());
    }
    char::from_u32(0x10000 + ((value - 0xD800) << 10) + (low - 0xDC00))
        .ok_or_else(|| "Unicode escape is not a valid scalar value".to_owned())
}

fn hex_value(
    chars: &[char],
    index: &mut usize,
    length: usize,
    kind: &str,
) -> std::result::Result<u32, String> {
    let end = index.saturating_add(length);
    let Some(digits) = chars.get(*index..end) else {
        return Err(format!("incomplete {kind} escape"));
    };
    let mut value = 0;
    for digit in digits {
        let Some(digit) = digit.to_digit(16) else {
            return Err(format!("invalid {kind} escape"));
        };
        value = value * 16 + digit;
    }
    *index = end;
    Ok(value)
}
