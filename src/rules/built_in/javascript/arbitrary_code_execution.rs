use crate::model::{Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
            "chainsec.js.detection.dynamic-code-execution",
            Language::JavaScript,
            FindingType::ArbitraryCodeExecution,
            Risk::High,
            Confidence::High,
            super::super::EXECUTION_RATIONALE,
            super::super::EXECUTION_REMEDIATION,
            r#"
                (call_expression function: (identifier) @callee (#match? @callee "^(eval|Function)$")) @match
                (new_expression constructor: (identifier) @callee (#eq? @callee "Function")) @match
                "#
        ),
        rule!(
            "chainsec.js.detection.heuristic.computed-global-execution",
            Language::JavaScript,
            FindingType::ArbitraryCodeExecution,
            Risk::High,
            Confidence::High,
            "A computed global eval or Function access reaches a runtime code-execution sink.",
            super::super::EXECUTION_REMEDIATION,
            r#"
                    (call_expression
                      function: (subscript_expression
                        object: (identifier) @global
                        index: (string) @sink)
                      (#match? @global "^(?:globalThis|window|global)$")
                      (#match? @sink "^['\\\"](?:eval|Function)['\\\"]$")) @match
                    "#
        ),
        rule!(
            "chainsec.js.detection.heuristic.string-timer-execution",
            Language::JavaScript,
            FindingType::ArbitraryCodeExecution,
            Risk::High,
            Confidence::High,
            "A timer receives source code as a string and evaluates it at runtime.",
            super::super::EXECUTION_REMEDIATION,
            r#"
                    (call_expression
                      function: (identifier) @timer
                      arguments: (arguments . (string) @source)
                      (#match? @timer "^(?:setTimeout|setInterval)$")) @match
                    "#
        ),
        rule!(
            "chainsec.js.detection.heuristic.vm-context-execution",
            Language::JavaScript,
            FindingType::ArbitraryCodeExecution,
            Risk::High,
            Confidence::High,
            "A Node VM context execution API evaluates code at runtime.",
            super::super::EXECUTION_REMEDIATION,
            r#"
                    (call_expression
                      function: (member_expression
                        object: (identifier) @vm
                        property: (property_identifier) @method)
                      (#match? @vm "^vm$")
                      (#match? @method "^runIn(?:This|New)?Context$")) @match
                    "#
        ),
        rule!(
            "chainsec.js.detection.heuristic.worker-blob-execution",
            Language::JavaScript,
            FindingType::ArbitraryCodeExecution,
            Risk::High,
            Confidence::High,
            "A Worker is initialized from a Blob or object URL, which can execute generated code.",
            super::super::EXECUTION_REMEDIATION,
            r#"
                    [
                      (new_expression
                        constructor: (identifier) @worker
                        arguments: (arguments
                          (call_expression
                            function: (member_expression
                              object: (identifier) @url
                              property: (property_identifier) @create)))
                        (#eq? @worker "Worker")
                        (#eq? @url "URL")
                        (#eq? @create "createObjectURL")) @match
                      (new_expression
                        constructor: (identifier) @worker
                        arguments: (arguments (identifier) @blob)
                        (#eq? @worker "Worker")
                        (#eq? @blob "blob")) @match
                    ]
                    "#
        ),
        rule!(
            "chainsec.js.detection.guarddog.base64-decoded-execution",
            Language::JavaScript,
            FindingType::ArbitraryCodeExecution,
            Risk::High,
            Confidence::High,
            "Base64-decoded data is passed directly to eval or the Function constructor.",
            super::super::REVIEW_OBFUSCATION,
            r#"
                ((call_expression function: (identifier) @sink arguments: (arguments
                  (call_expression function: (identifier) @decoder))) @match
                  (#eq? @sink "eval") (#eq? @decoder "atob"))
                ((new_expression constructor: (identifier) @sink arguments: (arguments
                  (call_expression function: (identifier) @decoder))) @match
                  (#eq? @sink "Function") (#eq? @decoder "atob"))
                ((call_expression function: (identifier) @sink arguments: (arguments
                  (call_expression function: (member_expression object: (identifier) @buffer property: (property_identifier) @from)
                    arguments: (arguments (_) (string) @encoding)))) @match
                  (#eq? @sink "eval") (#eq? @buffer "Buffer") (#eq? @from "from")
                  (#match? @encoding "['\"]base64['\"]"))
                ((new_expression constructor: (identifier) @sink arguments: (arguments
                  (call_expression function: (member_expression object: (identifier) @buffer property: (property_identifier) @from)
                    arguments: (arguments (_) (string) @encoding)))) @match
                  (#eq? @sink "Function") (#eq? @buffer "Buffer") (#eq? @from "from")
                  (#match? @encoding "['\"]base64['\"]"))
                "#
        ),
        rule!(
            "chainsec.js.detection.guarddog.reflective-api",
            Language::JavaScript,
            FindingType::ArbitraryCodeExecution,
            Risk::High,
            Confidence::High,
            "A property descriptor is resolved reflectively and its value is invoked immediately.",
            super::super::REVIEW_OBFUSCATION,
            r#"((call_expression function: (member_expression
                  object: (call_expression function: (member_expression object: (identifier) @object property: (property_identifier) @resolver))
                  property: (property_identifier) @value)) @match
                  (#eq? @object "Object") (#eq? @resolver "getOwnPropertyDescriptor") (#eq? @value "value"))"#
        ),
    ]
}
