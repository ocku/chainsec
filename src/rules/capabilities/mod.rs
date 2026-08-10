//! Rules organized by language and finding type for focused review.
mod javascript;
mod python;
mod typescript;

const LIMIT_ACCESS: &str = "Confirm this capability is required and restrict it to explicit paths, inputs, and destinations.";
const REMOVE_EXECUTION: &str = "Remove runtime execution, or replace it with a fixed command or operation over validated input.";

use crate::model::Rule;

pub fn capability_rules() -> Vec<Rule> {
    let mut rules = Vec::new();
    rules.extend(javascript::rules());
    rules.extend(python::rules());
    rules.extend(typescript::rules());
    rules
}
