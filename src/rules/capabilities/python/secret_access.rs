use crate::model::{Capability, Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
                "chainsec.py.capability.secret-read-browser-profile",
                Language::Python,
                FindingType::SecretAccess,
                Risk::Medium,
                Confidence::High,
                "A browser profile, cookie database, or credential store path is referenced directly.",
                super::super::LIMIT_ACCESS,
                r#"((string) @match (#match? @match "(?i)(Chrome[^\"']*(User Data|Login Data)|Microsoft\\\\Edge\\\\User Data|\\.mozilla/firefox|key4\\.db|cookies\\.sqlite|Cookies\\.binarycookies|Safari/LocalStorage|logins\\.json)"))"#
            ).with_capability(Capability::SecretReadBrowserProfile),
        rule!(
                "chainsec.py.capability.clipboard-access",
                Language::Python,
                FindingType::SecretAccess,
                Risk::Low,
                Confidence::High,
                "The code reads from or writes to the system clipboard.",
                super::super::LIMIT_ACCESS,
                r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  (#match? @module "^(pyperclip|pandas|root)$")
                  (#match? @method "^(paste|copy|read_clipboard|clipboard_get)$")) @match"#
            ).with_capability(Capability::RuntimeReadClipboard),
        rule!(
                "chainsec.py.capability.secret-read-environment",
                Language::Python,
                FindingType::SecretAccess,
                Risk::Low,
                Confidence::High,
                "The code reads environment variables, which may contain inherited credentials.",
                super::super::LIMIT_ACCESS,
                r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  (#eq? @module "os") (#eq? @method "getenv")) @match"#
            ).with_capability(Capability::SecretReadEnvironment),
        rule!(
                "chainsec.py.capability.secret-read-file",
                Language::Python,
                FindingType::SecretAccess,
                Risk::Medium,
                Confidence::High,
                "A path commonly used to store credentials is referenced directly.",
                super::super::LIMIT_ACCESS,
                r#"((string) @match (#match? @match "(?i)(\\.ssh/(id_[^/\\\"']+|config)|\\.aws/credentials|\\.config/gcloud|\\.kube/config|\\.npmrc|\\.pypirc|\\.env(?:$|[\\\"']))"))"#
            ).with_capability(Capability::SecretReadFile),
    ]
}
