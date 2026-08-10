//! Rules organized by language and finding type for focused review.
mod javascript;
mod python;
mod typescript;

const EXECUTION_RATIONALE: &str = "Runtime code or process execution can execute attacker-controlled payloads during package use.";
const EXECUTION_REMEDIATION: &str =
    "Remove dynamic execution or constrain input to a fixed, validated allowlist.";
const ACCESS_REMEDIATION: &str =
    "Confirm the access is necessary and constrain destinations, paths, and data.";
const REMOVE_EXECUTION: &str = "Remove runtime execution, or replace it with a fixed command or operation over validated input.";
const REVIEW_OBFUSCATION: &str =
    "Remove the obfuscation and review the decoded or dynamically resolved behavior before use.";

use crate::model::Rule;

pub fn built_in_rules() -> Vec<Rule> {
    let mut rules = Vec::new();
    rules.extend(javascript::rules());
    rules.extend(python::rules());
    rules.extend(typescript::rules());
    rules
}
