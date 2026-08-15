use crate::model::{Capability, Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
                    "chainsec.js.capability.dynamic-code-execution",
                    Language::JavaScript,
                    FindingType::ArbitraryCodeExecution,
                    Risk::High,
                    Confidence::High,
                    "The code invokes a JavaScript or TypeScript dynamic-code execution API.",
                    super::super::REMOVE_EXECUTION,
                    r#"
                (call_expression function: (identifier) @callee (#match? @callee "^(eval|Function)$")) @match
                (new_expression constructor: (identifier) @callee (#eq? @callee "Function")) @match
                "#
                ).with_capability(Capability::CodeDynamicExecution),
    ]
}
