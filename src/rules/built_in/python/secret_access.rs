use crate::model::{Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
            "chainsec.py.detection.guarddog.screen-capture",
            Language::Python,
            FindingType::SecretAccess,
            Risk::Critical,
            Confidence::High,
            "The code invokes a screen-capture API that can collect sensitive user content.",
            "Remove screen capture from package code or require explicit, visible user consent and local-only handling.",
            r#"
                (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  (#match? @module "^(ImageGrab|pyscreenshot|pyautogui)$")
                  (#match? @method "^(grab|screenshot)$")) @match
                (call function: (attribute object: (attribute object: (identifier) @pil attribute: (identifier) @imagegrab) attribute: (identifier) @method)
                  (#eq? @pil "PIL") (#eq? @imagegrab "ImageGrab") (#eq? @method "grab")) @match
                "#
        ),
        rule!(
            "chainsec.py.detection.guarddog.credential-environment",
            Language::Python,
            FindingType::SecretAccess,
            Risk::High,
            Confidence::High,
            "The code reads a credential-like environment variable.",
            "Read only the required named setting, avoid logging or transmitting it, and use scoped credentials.",
            r#"
                (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  arguments: (argument_list (string) @name . (_)* )
                  (#eq? @module "os") (#eq? @method "getenv")
                  (#match? @name "(?i)(API_?KEY|SECRET|TOKEN|PASS(WORD)?|AUTH|CREDENTIAL|CRED)")) @match
                (subscript value: (attribute object: (identifier) @module attribute: (identifier) @env) subscript: (string) @name
                  (#eq? @module "os") (#eq? @env "environ")
                  (#match? @name "(?i)(API_?KEY|SECRET|TOKEN|PASS(WORD)?|AUTH|CREDENTIAL|CRED)")) @match
                "#
        ),
    ]
}
