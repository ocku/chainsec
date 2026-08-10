use crate::model::{Capability, Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
                    "chainsec.js.capability.secret-read-browser-profile",
                    Language::JavaScript,
                    FindingType::SecretAccess,
                    Risk::Medium,
                    Confidence::High,
                    "A browser profile, cookie database, credential store, or cookie extraction package is referenced directly.",
                    super::super::LIMIT_ACCESS,
                    r#"((string) @match (#match? @match "(?i)(Chrome[^\"']*(User Data|Login Data)|Microsoft\\\\Edge\\\\User Data|\\.mozilla/firefox|key4\\.db|cookies\\.sqlite|Cookies\\.binarycookies|Safari/LocalStorage|logins\\.json|chrome-cookies-secure|electron-cookies)"))"#
                ).with_capability(Capability::SecretReadBrowserProfile),
        rule!(
                    "chainsec.js.capability.clipboard-access",
                    Language::JavaScript,
                    FindingType::SecretAccess,
                    Risk::Low,
                    Confidence::High,
                    "The code reads from or writes to the system clipboard.",
                    super::super::LIMIT_ACCESS,
                    r#"
                (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
                  (#match? @module "^(clipboardy|clipboard)$")
                  (#match? @method "^(read|readSync|write|writeSync|readText)$")) @match
                "#
                ).with_capability(Capability::RuntimeReadClipboard),
        rule!(
                    "chainsec.js.capability.secret-read-environment",
                    Language::JavaScript,
                    FindingType::SecretAccess,
                    Risk::Low,
                    Confidence::High,
                    "The code reads environment variables, which may contain inherited credentials.",
                    super::super::LIMIT_ACCESS,
                    r#"
                (member_expression object: (member_expression object: (identifier) @process property: (property_identifier) @environment)
                  (#eq? @process "process") (#eq? @environment "env")) @match
                (call_expression function: (member_expression object: (member_expression object: (identifier) @deno property: (property_identifier) @environment) property: (property_identifier) @method)
                  (#eq? @deno "Deno") (#eq? @environment "env")
                  (#match? @method "^(get|has|toObject)$")) @match
                "#
                ).with_capability(Capability::SecretReadEnvironment),
        rule!(
                    "chainsec.js.capability.secret-read-file",
                    Language::JavaScript,
                    FindingType::SecretAccess,
                    Risk::Medium,
                    Confidence::High,
                    "A path commonly used to store credentials is referenced directly.",
                    super::super::LIMIT_ACCESS,
                    r#"((string) @match (#match? @match "(?i)(\\.ssh/(id_[^/\\\"']+|config)|\\.aws/credentials|\\.config/gcloud|\\.kube/config|\\.npmrc|\\.pypirc|\\.env(?:$|[\\\"']))"))"#
                ).with_capability(Capability::SecretReadFile),
    ]
}
