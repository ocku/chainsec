use crate::model::{Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![rule!(
        "chainsec.js.detection.read-environment",
        Language::JavaScript,
        FindingType::SecretAccess,
        Risk::High,
        Confidence::High,
        "The code reads a credential-like environment variable or serializes the entire environment, which can expose inherited secrets.",
        "Read only required named settings, avoid logging or transmitting them, and use scoped credentials.",
        r#"
                    (member_expression object: (member_expression object: (identifier) @process property: (property_identifier) @env) property: (property_identifier) @name
                      (#eq? @process "process") (#eq? @env "env")
                      (#match? @name "(?i)(API_?KEY|SECRET|TOKEN|PASS(WORD)?|AUTH|CREDENTIAL|CRED)")) @match
                    (subscript_expression object: (member_expression object: (identifier) @process property: (property_identifier) @env)
                      index: (string) @name
                      (#eq? @process "process") (#eq? @env "env")
                      (#match? @name "(?i)(API_?KEY|SECRET|TOKEN|PASS(WORD)?|AUTH|CREDENTIAL|CRED)")) @match
                    (call_expression function: (member_expression object: (identifier) @json property: (property_identifier) @stringify)
                      arguments: (arguments (member_expression object: (identifier) @process property: (property_identifier) @env))
                      (#eq? @json "JSON") (#eq? @stringify "stringify")
                      (#eq? @process "process") (#eq? @env "env")) @match
                    (call_expression function: (member_expression object: (member_expression object: (identifier) @deno property: (property_identifier) @env) property: (property_identifier) @method)
                      arguments: (arguments (string) @name . (_)* )
                      (#eq? @deno "Deno") (#eq? @env "env") (#eq? @method "get")
                      (#match? @name "(?i)(API_?KEY|SECRET|TOKEN|PASS(WORD)?|AUTH|CREDENTIAL|CRED)")) @match
                    "#
    )]
}
