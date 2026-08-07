use crate::model::{Confidence, FindingType, Language, Risk, Rule};

const EXECUTION_RATIONALE: &str = "Runtime code or process execution can execute attacker-controlled payloads during package use.";
const EXECUTION_REMEDIATION: &str =
    "Remove dynamic execution or constrain input to a fixed, validated allowlist.";
const ACCESS_REMEDIATION: &str =
    "Confirm the access is necessary and constrain destinations, paths, and data.";

pub fn built_in_rules() -> Vec<Rule> {
    let mut rules = vec![
        rule!(
            "PY001",
            Language::Python,
            FindingType::ArbitraryCodeExecution,
            Risk::High,
            Confidence::High,
            EXECUTION_RATIONALE,
            EXECUTION_REMEDIATION,
            r#"(call function: (identifier) @callee (#match? @callee "^(eval|exec|compile)$")) @match"#
        ),
        rule!(
            "PY002",
            Language::Python,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::Medium,
            "Decoded payloads may conceal executable or exfiltrated data.",
            "Inspect decoded content and avoid executing data obtained at runtime.",
            r#"(call function: (attribute attribute: (identifier) @method (#match? @method "^(b64decode|decodebytes)$"))) @match"#
        ),
        rule!(
            "PY003",
            Language::Python,
            FindingType::ProcessExecution,
            Risk::High,
            Confidence::High,
            EXECUTION_RATIONALE,
            EXECUTION_REMEDIATION,
            r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method) (#match? @module "^(os|subprocess)$") (#match? @method "^(system|popen|run|call|check_call|check_output|Popen)$")) @match"#
        ),
        rule!(
            "PY004",
            Language::Python,
            FindingType::NetworkAccess,
            Risk::Medium,
            Confidence::Medium,
            "Network calls can download payloads or exfiltrate local data.",
            ACCESS_REMEDIATION,
            r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method) (#match? @module "^(requests|urllib|httpx|socket)$")) @match"#
        ),
        rule!(
            "PY005",
            Language::Python,
            FindingType::FilesystemAccess,
            Risk::Medium,
            Confidence::Medium,
            "Filesystem access can read credentials or modify user state.",
            ACCESS_REMEDIATION,
            r#"(call function: (identifier) @callee (#eq? @callee "open")) @match"#
        ),
        rule!(
            "PY006",
            Language::Python,
            FindingType::Deserialization,
            Risk::High,
            Confidence::High,
            "Unsafe deserialization can instantiate attacker-controlled objects.",
            "Use a safe data format such as JSON and validate its schema.",
            r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method) (#match? @module "^(pickle|yaml)$") (#match? @method "^(loads?|load)$")) @match"#
        ),
        rule!(
            "JS001",
            Language::JavaScript,
            FindingType::ArbitraryCodeExecution,
            Risk::High,
            Confidence::High,
            EXECUTION_RATIONALE,
            EXECUTION_REMEDIATION,
            r#"(call_expression function: (identifier) @callee (#match? @callee "^(eval|Function)$")) @match"#
        ),
        rule!(
            "JS002",
            Language::JavaScript,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::Medium,
            "Decoded payloads may conceal executable or exfiltrated data.",
            "Inspect decoded content and avoid executing data obtained at runtime.",
            r#"
            ((call_expression function: (member_expression property: (property_identifier) @method)
              arguments: (arguments (number) (number) . (_)*)) @match
              (#eq? @method "fromCharCode"))
            ((call_expression function: (member_expression property: (property_identifier) @method)) @match
              (#eq? @method "atob"))
            ((call_expression function: (identifier) @callee) @match
              (#eq? @callee "atob"))
            "#
        ),
        rule!(
            "JS003",
            Language::JavaScript,
            FindingType::ProcessExecution,
            Risk::High,
            Confidence::High,
            EXECUTION_RATIONALE,
            EXECUTION_REMEDIATION,
            r#"(call_expression function: (identifier) @callee (#match? @callee "^(exec|execFile|spawn|fork)$")) @match"#
        ),
        rule!(
            "JS004",
            Language::JavaScript,
            FindingType::NetworkAccess,
            Risk::Medium,
            Confidence::Medium,
            "Network calls can download payloads or exfiltrate local data.",
            ACCESS_REMEDIATION,
            r#"(call_expression function: (identifier) @callee (#match? @callee "^(fetch)$")) @match"#
        ),
        rule!(
            "JS005",
            Language::JavaScript,
            FindingType::SecretAccess,
            Risk::Medium,
            Confidence::High,
            "Environment access can expose credentials inherited by the process.",
            "Read only named configuration values and never transmit secrets.",
            r#"(member_expression object: (member_expression object: (identifier) @process property: (property_identifier) @env) (#eq? @process "process") (#eq? @env "env")) @match"#
        ),
        rule!(
            "JS006",
            Language::JavaScript,
            FindingType::DynamicLoading,
            Risk::Medium,
            Confidence::Medium,
            "Dynamic module loading can hide code paths from static review.",
            "Prefer static imports and fixed module specifiers.",
            r#"(call_expression function: (identifier) @callee (#eq? @callee "require") arguments: (arguments (_) @argument) (#not-match? @argument "^['\"]")) @match"#
        ),
        rule!(
            "TS001",
            Language::TypeScript,
            FindingType::ArbitraryCodeExecution,
            Risk::High,
            Confidence::High,
            EXECUTION_RATIONALE,
            EXECUTION_REMEDIATION,
            r#"(call_expression function: (identifier) @callee (#match? @callee "^(eval|Function)$")) @match"#
        ),
        rule!(
            "TS002",
            Language::TypeScript,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::Medium,
            "Decoded payloads may conceal executable or exfiltrated data.",
            "Inspect decoded content and avoid executing data obtained at runtime.",
            r#"
            ((call_expression function: (member_expression property: (property_identifier) @method)
              arguments: (arguments (number) (number) . (_)*)) @match
              (#eq? @method "fromCharCode"))
            ((call_expression function: (member_expression property: (property_identifier) @method)) @match
              (#eq? @method "atob"))
            ((call_expression function: (identifier) @callee) @match
              (#eq? @callee "atob"))
            "#
        ),
        rule!(
            "TS003",
            Language::TypeScript,
            FindingType::ProcessExecution,
            Risk::High,
            Confidence::High,
            EXECUTION_RATIONALE,
            EXECUTION_REMEDIATION,
            r#"(call_expression function: (identifier) @callee (#match? @callee "^(exec|execFile|spawn|fork)$")) @match"#
        ),
        rule!(
            "TS004",
            Language::TypeScript,
            FindingType::NetworkAccess,
            Risk::Medium,
            Confidence::Medium,
            "Network calls can download payloads or exfiltrate local data.",
            ACCESS_REMEDIATION,
            r#"(call_expression function: (identifier) @callee (#match? @callee "^(fetch)$")) @match"#
        ),
        rule!(
            "TS005",
            Language::TypeScript,
            FindingType::SecretAccess,
            Risk::Medium,
            Confidence::High,
            "Environment access can expose credentials inherited by the process.",
            "Read only named configuration values and never transmit secrets.",
            r#"(member_expression object: (member_expression object: (identifier) @process property: (property_identifier) @env) (#eq? @process "process") (#eq? @env "env")) @match"#
        ),
    ];
    rules.extend(super::guarddog::guarddog_rules());
    rules.extend(entropy_rules());
    rules
}

fn entropy_rules() -> Vec<Rule> {
    [
        ("PY_HIGH_ENTROPY_STRING", Language::Python, r#"(string) @match"#),
        ("JS_HIGH_ENTROPY_STRING", Language::JavaScript, r#"(string) @match"#),
        ("TS_HIGH_ENTROPY_STRING", Language::TypeScript, r#"(string) @match"#),
    ]
    .into_iter()
    .map(|(id, language, query)| Rule {
        entropy: Some(crate::model::EntropyMatcher {
            minimum_length: 32,
            minimum_entropy: 5.0,
            maximum_whitespace_ratio: 0.05,
        }),
        ..super::standard_rule(
            id,
            language,
            super::RuleDefinition {
                finding_type: FindingType::CodeObfuscation,
                risk: Risk::Medium,
                confidence: Confidence::Medium,
                rationale: "A string literal has unusually high Shannon entropy and may contain encrypted or packed data.",
                remediation: "Inspect and decode the value, document its origin, and avoid embedding opaque executable payloads.",
                query,
            },
        )
    })
    .collect()
}
