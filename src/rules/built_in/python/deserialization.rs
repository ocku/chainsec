use crate::model::{Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![rule!(
        "chainsec.py.detection.unsafe-deserialization",
        Language::Python,
        FindingType::Deserialization,
        Risk::High,
        Confidence::High,
        "Unsafe deserialization can instantiate attacker-controlled objects.",
        "Use a safe data format such as JSON and validate its schema.",
        r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method) (#match? @module "^(pickle|yaml)$") (#match? @method "^(loads?|load)$")) @match"#
    )]
}
