use super::*;

#[test]
fn jsonc_handles_comments_strings_trailing_commas_and_line_endings() {
    let input = concat!(
        "{\r\n",
        "  // CRLF comment\r\n",
        "  \"url\": \"https://example.test/a/*literal*///b\",\r",
        "  \"items\": [1, 2, /* block\r\n comment */], // CR comment\r",
        "}\r\n",
    );
    let clean = strip_jsonc(input).unwrap();
    let value: JsonValue = serde_json::from_str(&clean).unwrap();
    assert_eq!(value["url"], "https://example.test/a/*literal*///b");
    assert_eq!(value["items"], json!([1, 2]));
}

#[test]
fn jsonc_rejects_unterminated_constructs() {
    assert_eq!(
        strip_jsonc("{/* never closed").unwrap_err(),
        "unterminated block comment"
    );
    assert_eq!(
        strip_jsonc(r#"{"value":"never closed}"#).unwrap_err(),
        "unterminated string"
    );
}
