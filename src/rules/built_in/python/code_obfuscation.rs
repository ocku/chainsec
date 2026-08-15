use crate::model::{Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
            "chainsec.py.detection.decoded-payload",
            Language::Python,
            FindingType::CodeObfuscation,
            Risk::High,
            Confidence::Medium,
            "Decoded payloads may conceal executable or exfiltrated data.",
            "Inspect decoded content and avoid executing data obtained at runtime.",
            r#"((call function: (attribute object: (identifier) @codec attribute: (identifier) @method)
                  arguments: (argument_list (string) @payload . (_)*)) @match
                  (#eq? @codec "base64")
                  (#match? @method "^(b64decode|decodebytes|standard_b64decode)$")
                  (#match? @payload "(?i)^['\"][A-Z0-9+/\\r\\n]{80,}={0,2}['\"]$"))"#
        ),
        rule!(
            "chainsec.py.detection.character-assembly",
            Language::Python,
            FindingType::CodeObfuscation,
            Risk::High,
            Confidence::High,
            "A long character sequence or character codes are joined into a runtime string, a common way to conceal a payload or API name.",
            "Replace runtime character assembly with reviewed plain text, or document and validate the generated value.",
            r#"
                    ((call function: (attribute object: (string) @separator attribute: (identifier) @join)) @match
                      (#eq? @join "join")
                      (#match? @separator "^['\"]{2}$")
                      (#match? @match "(?s)((chr|ord)\\s*\\(|\\.join\\s*\\(\\s*\\[(?:[^\\]]*,){7,})"))
                    "#
        ),
        rule!(
            "chainsec.py.detection.encoded-escapes",
            Language::Python,
            FindingType::CodeObfuscation,
            Risk::High,
            Confidence::High,
            "A string literal or concatenation contains a long sequence of hexadecimal, octal, or Unicode escape codes.",
            "Replace encoded literals with reviewed plain text, or document the encoding and validate the decoded value.",
            r#"
                    ((string) @match
                      (#match? @match "(?i)(?:\\\\x[0-9a-f]{2}|\\\\[0-7]{3}|\\\\u[0-9a-f]{4}|\\\\U[0-9a-f]{8}){16,}"))
                    ((binary_operator left: (string) @left right: (string) @right) @match
                      (#match? @left "(?i)(?:\\\\x[0-9a-f]{2}|\\\\[0-7]{3}|\\\\u[0-9a-f]{4}|\\\\U[0-9a-f]{8}){8,}")
                      (#match? @right "(?i)(?:\\\\x[0-9a-f]{2}|\\\\[0-7]{3}|\\\\u[0-9a-f]{4}|\\\\U[0-9a-f]{8}){8,}"))
                    "#
        ),
        rule!(
            "chainsec.py.detection.ambiguous-identifier",
            Language::Python,
            FindingType::CodeObfuscation,
            Risk::Low,
            Confidence::Medium,
            "An identifier resembles a generated hexadecimal name or a visually ambiguous character sequence.",
            "Rename generated or ambiguous identifiers to descriptive names before reviewing or publishing the code.",
            r#"((identifier) @match (#match? @match "(?i)^_?0x[0-9a-f]{4,}$|^[o0il1]{6,}$"))"#
        ),
        rule!(
            "chainsec.py.detection.heuristic.code-protector-marker",
            Language::Python,
            FindingType::CodeObfuscation,
            Risk::High,
            Confidence::High,
            "Python protector or compiler bootstrap markers were found.",
            "Verify the provenance and inspect the original source where available.",
            r#"((identifier) @match (#match? @match "^(__pyarmor__|pyarmor_runtime(_[0-9]+)?|__cython__|__nuitka__)$"))"#
        ),
        rule!(
            "chainsec.py.detection.guarddog.pyarmor",
            Language::Python,
            FindingType::CodeObfuscation,
            Risk::High,
            Confidence::High,
            "The code invokes a PyArmor bootstrap/runtime or verification function.",
            "Require unobfuscated source for review or verify the PyArmor-protected artifact and its publisher independently.",
            r#"(call function: (identifier) @callee
                  (#match? @callee "^(__pyarmor__|pyarmor_runtime|check_armored|assert_armored)$")) @match"#
        ),
        {
            let mut rule = rule!(
                "chainsec.py.detection.heuristic.high-entropy-string",
                Language::Python,
                FindingType::CodeObfuscation,
                Risk::Medium,
                Confidence::Medium,
                "A string literal has unusually high Shannon entropy and may contain encrypted or packed data.",
                "Inspect and decode the value, document its origin, and avoid embedding opaque executable payloads.",
                r#"(string) @match"#
            );
            rule.entropy = Some(crate::model::EntropyMatcher {
                minimum_length: 32,
                minimum_entropy: 5.0,
                maximum_whitespace_ratio: 0.05,
            });
            rule
        },
    ]
}
