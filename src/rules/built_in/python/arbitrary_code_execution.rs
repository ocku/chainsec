use crate::model::{Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
            "chainsec.py.detection.dynamic-code-execution",
            Language::Python,
            FindingType::ArbitraryCodeExecution,
            Risk::Medium,
            Confidence::High,
            super::super::EXECUTION_RATIONALE,
            super::super::EXECUTION_REMEDIATION,
            r#"(call function: (identifier) @callee (#match? @callee "^(eval|exec|compile)$")) @match"#
        ),
        rule!(
            "chainsec.py.detection.heuristic.opaque-execution-input",
            Language::Python,
            FindingType::ArbitraryCodeExecution,
            Risk::Medium,
            Confidence::High,
            "Decoded, deserialized, or marshalled Python content reaches an execution sink.",
            super::super::EXECUTION_REMEDIATION,
            r#"
                    ((call function: (identifier) @executor
                      arguments: (argument_list (call function: (attribute attribute: (identifier) @decoder)))) @match
                      (#match? @executor "^(eval|exec)$")
                      (#match? @decoder "^(loads|b64decode|decode|decompress)$"))
                    ((call function: (attribute attribute: (identifier) @constructor)
                      arguments: (argument_list (call function: (attribute attribute: (identifier) @decoder)))) @match
                      (#eq? @constructor "FunctionType")
                      (#eq? @decoder "loads"))
                    "#
        ),
        rule!(
            "chainsec.py.detection.guarddog.base64-decoded-execution",
            Language::Python,
            FindingType::ArbitraryCodeExecution,
            Risk::Medium,
            Confidence::High,
            "Base64-decoded data is passed directly to exec or eval.",
            super::super::REVIEW_OBFUSCATION,
            r#"(call function: (identifier) @sink arguments: (argument_list
                  (call function: (attribute object: (identifier) @codec attribute: (identifier) @decoder)))
                  (#match? @sink "^(exec|eval)$") (#eq? @codec "base64")
                  (#match? @decoder "^(b64decode|decodebytes|standard_b64decode)$")) @match"#
        ),
        rule!(
            "chainsec.py.detection.guarddog.dynamic-import",
            Language::Python,
            FindingType::ArbitraryCodeExecution,
            Risk::Medium,
            Confidence::High,
            "A dynamic import or serialized payload loader is nested directly inside exec.",
            super::super::REVIEW_OBFUSCATION,
            r#"
                ((call function: (identifier) @sink arguments: (argument_list
                  (call function: (identifier) @loader))) @match
                  (#eq? @sink "exec") (#eq? @loader "__import__"))
                ((call function: (identifier) @sink arguments: (argument_list
                  (call function: (attribute object: (identifier) @module attribute: (identifier) @loader)))) @match
                  (#eq? @sink "exec") (#eq? @module "marshal") (#eq? @loader "loads"))
                (call function: (attribute object: (call function: (identifier) @import arguments: (argument_list (string) @module)) attribute: (identifier) @sink)
                  (#eq? @import "__import__") (#match? @module "['\"]builtins['\"]") (#eq? @sink "exec")) @match
                "#
        ),
        rule!(
            "chainsec.py.detection.guarddog.reflective-api",
            Language::Python,
            FindingType::ArbitraryCodeExecution,
            Risk::Medium,
            Confidence::High,
            "A dangerous builtin is resolved through getattr and invoked immediately.",
            super::super::REVIEW_OBFUSCATION,
            r#"((call function: (call function: (identifier) @getattr
                  arguments: (argument_list (_) (string) @name))) @match
                  (#eq? @getattr "getattr")
                  (#match? @name "['\"](__import__|exec|eval|compile)['\"]"))"#
        ),
    ]
}
