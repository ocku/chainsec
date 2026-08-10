mod arbitrary_code_execution;
mod code_obfuscation;
mod deserialization;
mod dynamic_loading;
mod filesystem_access;
mod network_access;
mod process_execution;
mod secret_access;

use crate::model::Rule;

pub(super) fn rules() -> Vec<Rule> {
    let mut rules = Vec::new();
    rules.extend(arbitrary_code_execution::rules());
    rules.extend(code_obfuscation::rules());
    rules.extend(deserialization::rules());
    rules.extend(dynamic_loading::rules());
    rules.extend(filesystem_access::rules());
    rules.extend(network_access::rules());
    rules.extend(process_execution::rules());
    rules.extend(secret_access::rules());
    rules
}
