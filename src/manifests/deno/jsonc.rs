pub(in crate::manifests) fn strip_jsonc(input: &str) -> std::result::Result<String, String> {
    let without_comments = remove_comments(input)?;
    Ok(remove_trailing_commas(&without_comments))
}

fn remove_comments(input: &str) -> Result<String, String> {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut strings = StringState::default();

    while let Some(character) = chars.next() {
        if strings.consume(character) {
            output.push(character);
        } else if character == '/' && chars.peek() == Some(&'/') {
            chars.next();
            output.push_str("  ");
            replace_line_comment(&mut chars, &mut output);
        } else if character == '/' && chars.peek() == Some(&'*') {
            chars.next();
            output.push_str("  ");
            replace_block_comment(&mut chars, &mut output)?;
        } else {
            output.push(character);
        }
    }

    (!strings.in_string)
        .then_some(output)
        .ok_or_else(|| "unterminated string".to_owned())
}

fn replace_line_comment(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, output: &mut String) {
    while let Some(character) = chars.next() {
        if matches!(character, '\r' | '\n') {
            output.push(character);
            if character == '\r' && chars.peek() == Some(&'\n') {
                output.push('\n');
                chars.next();
            }
            break;
        }
        output.push(' ');
    }
}

fn replace_block_comment(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    output: &mut String,
) -> Result<(), String> {
    while let Some(character) = chars.next() {
        if character == '*' && chars.peek() == Some(&'/') {
            chars.next();
            output.push_str("  ");
            return Ok(());
        }
        output.push(if matches!(character, '\r' | '\n') {
            character
        } else {
            ' '
        });
    }
    Err("unterminated block comment".to_owned())
}

fn remove_trailing_commas(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut strings = StringState::default();
    let mut pending_comma = false;

    for character in input.chars() {
        let was_in_string = strings.in_string;
        if !was_in_string && character == ',' {
            pending_comma = true;
        } else if pending_comma && character.is_whitespace() {
            output.push(character);
        } else {
            if pending_comma {
                if !matches!(character, '}' | ']') {
                    output.push(',');
                }
                pending_comma = false;
            }
            output.push(character);
        }
        strings.consume(character);
    }
    if pending_comma {
        output.push(',');
    }
    output
}

#[derive(Default)]
struct StringState {
    in_string: bool,
    escaped: bool,
}

impl StringState {
    /// Returns whether `character` is part of a JSON string, including its quotes.
    fn consume(&mut self, character: char) -> bool {
        if !self.in_string {
            if character == '"' {
                self.in_string = true;
                return true;
            }
            return false;
        }

        if self.escaped {
            self.escaped = false;
        } else if character == '\\' {
            self.escaped = true;
        } else if character == '"' {
            self.in_string = false;
        }
        true
    }
}
