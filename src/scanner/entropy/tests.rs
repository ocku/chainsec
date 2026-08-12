use super::{has_high_entropy, shannon_entropy};
use crate::model::EntropyMatcher;

const MATCHER: EntropyMatcher = EntropyMatcher {
    minimum_length: 32,
    minimum_entropy: 5.0,
    maximum_whitespace_ratio: 0.05,
};

#[test]
fn calculates_shannon_entropy_for_arbitrary_symbols() {
    assert_eq!(shannon_entropy("aaaa".chars()), 0.0);
    assert!((shannon_entropy("aabb".chars()) - 1.0).abs() < f64::EPSILON);
    assert!((shannon_entropy(0_u8..=255) - 8.0).abs() < f64::EPSILON);
}

#[test]
fn empty_input_has_zero_entropy() {
    assert_eq!(shannon_entropy(std::iter::empty::<u8>()), 0.0);
}

#[test]
fn standard_encoding_metadata_is_not_high_entropy() {
    let values = [
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
        "0123456789ABCDEFGHIJKLMNOPQRSTUV",
        "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~",
        "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
        "!<tag:yaml.org,2002:binary> AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDE=\\n",
    ];

    for value in values {
        let literal = format!("\"{value}\"");
        assert!(
            !has_high_entropy(literal.as_bytes(), &MATCHER),
            "unexpected high-entropy match: {value}"
        );
    }
}

#[test]
fn opaque_secret_remains_high_entropy() {
    let literal = br#""nQ8zP4vLm7T2rX9aBcDeFgHiJkNoPqRsTuVwY3Z5mK6sA1bC8dE0fG9hI2jL7pR""#;

    assert!(has_high_entropy(literal, &MATCHER));
}

#[test]
fn opaque_template_literal_is_high_entropy() {
    let literal = b"`nQ8zP4vLm7T2rX9aBcDeFgHiJkNoPqRsTuVwY3Z5mK6sA1bC8dE0fG9hI2jL7pR`";

    assert!(has_high_entropy(literal, &MATCHER));
}
