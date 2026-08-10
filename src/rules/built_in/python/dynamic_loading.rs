use crate::model::{Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
            "chainsec.py.detection.dynamic-import",
            Language::Python,
            FindingType::DynamicLoading,
            Risk::High,
            Confidence::Medium,
            "A runtime-computed module name cannot be verified during static review and may load sensitive modules.",
            "Use explicit imports or constrain the module name to a fixed, validated allowlist.",
            r#"
                    ((call function: (identifier) @loader
                      arguments: (argument_list (_) @argument . (_)*)) @match
                      (#eq? @loader "__import__")
                      (#not-match? @argument "^(?:['\"]|-?[0-9]|\\.)"))
                    ((call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                      arguments: (argument_list (_) @argument . (_)*)) @match
                      (#eq? @module "importlib") (#eq? @method "import_module")
                      (#not-match? @argument "^(?:['\"]|-?[0-9]|\\.)"))
                    "#
        ),
        rule!(
            "chainsec.py.detection.reflective-namespace",
            Language::Python,
            FindingType::DynamicLoading,
            Risk::Medium,
            Confidence::High,
            "Reflective namespace properties can expose import capabilities or bypass ordinary module-import review.",
            "Use explicit imports and avoid traversing runtime globals, builtins, loaders, or module specifications.",
            r#"
                    ((attribute object: (_) attribute: (identifier) @property) @match
                      (#match? @property "^(__globals__|__builtins__|__import__|__loader__|__spec__|func_globals)$"))
                    ((call function: (identifier) @function
                      arguments: (argument_list (_) (string) @property)) @match
                      (#match? @function "^(getattr|setattr)$")
                      (#match? @property "^['\"](__globals__|__builtins__|__import__|__loader__|__spec__|func_globals)['\"]$"))
                    "#
        ),
        rule!(
            "chainsec.py.detection.heuristic.dynamic-module",
            Language::Python,
            FindingType::DynamicLoading,
            Risk::High,
            Confidence::High,
            "Python dynamically loads a module or changes import resolution at runtime.",
            "Use explicit, fixed imports and avoid loading code from runtime-controlled paths.",
            r#"
                    ((call function: (identifier) @loader) @match (#eq? @loader "__import__"))
                    ((call function: (attribute object: (identifier) @module attribute: (identifier) @method) @match
                      (#eq? @module "importlib") (#eq? @method "import_module")))
                    ((call function: (attribute object: (identifier) @loader attribute: (identifier) @method) @match
                      (#eq? @loader "loader") (#eq? @method "exec_module")))
                    "#
        ),
    ]
}
