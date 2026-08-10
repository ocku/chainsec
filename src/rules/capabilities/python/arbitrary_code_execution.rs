use crate::model::{Capability, Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
                "chainsec.py.capability.dynamic-code-execution",
                Language::Python,
                FindingType::ArbitraryCodeExecution,
                Risk::High,
                Confidence::High,
                "The code invokes a Python dynamic-code execution API.",
                super::super::REMOVE_EXECUTION,
                r#"(call function: (identifier) @callee (#match? @callee "^(eval|exec|compile)$")) @match"#
            ).with_capability(Capability::CodeDynamicExecution),
    ]
}
