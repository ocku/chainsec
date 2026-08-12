use crate::model::{Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
            "chainsec.js.detection.dynamic-require",
            Language::JavaScript,
            FindingType::DynamicLoading,
            Risk::High,
            Confidence::Medium,
            "Dynamic module loading can hide code paths from static review.",
            "Prefer static imports and fixed module specifiers.",
            r#"
                            ((call_expression function: (identifier) @callee
                              arguments: (arguments (_) @argument)
                              (#eq? @callee "require")
                              (#not-match? @argument "^(?:['\"`]|-?[0-9]|\\.)")) @match)
                            ((call_expression function: (identifier) @callee
                              arguments: (arguments (template_string (template_substitution)))
                              (#eq? @callee "require")) @match)
                            "#
        ),
        rule!(
            "chainsec.js.detection.dynamic-import",
            Language::JavaScript,
            FindingType::DynamicLoading,
            Risk::High,
            Confidence::Medium,
            "Dynamic module loading can hide code paths from static review.",
            "Prefer static imports and fixed module specifiers.",
            r#"
                            ((call_expression function: (import)
                              arguments: (arguments (_) @argument)
                              (#not-match? @argument "^(?:['\"`]|-?[0-9]|\\.)")) @match)
                            ((call_expression function: (import)
                              arguments: (arguments (template_string (template_substitution)))) @match)
                            "#
        ),
        rule!(
            "chainsec.js.detection.write-browser-global",
            Language::JavaScript,
            FindingType::DynamicLoading,
            Risk::Medium,
            Confidence::High,
            "A value is written to the browser window object, creating or replacing global runtime state.",
            "Avoid package-controlled global writes; keep state module-local or require an explicit integration API.",
            r#"
                    ((assignment_expression left: (member_expression object: (identifier) @window)) @match
                      (#eq? @window "window"))
                    ((assignment_expression left: (subscript_expression object: (identifier) @window)) @match
                      (#eq? @window "window"))
                    "#
        ),
        rule!(
            "chainsec.js.detection.guarddog.hidden-require",
            Language::JavaScript,
            FindingType::DynamicLoading,
            Risk::High,
            Confidence::High,
            "The require function is aliased through a computed global property, hiding subsequent module loads.",
            "Use direct static imports or fixed require calls and remove the global alias.",
            r#"(assignment_expression
                  left: (subscript_expression object: (identifier) @global index: (string) @alias)
                  right: (identifier) @require
                  (#eq? @global "global") (#eq? @require "require")
                  (#match? @alias "^['\"][A-Za-z0-9_$]{1,6}['\"]$")) @match"#
        ),
    ]
}
