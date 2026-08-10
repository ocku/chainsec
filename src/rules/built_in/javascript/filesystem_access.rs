use crate::model::{Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
            "chainsec.js.detection.guarddog.autostart",
            Language::JavaScript,
            FindingType::FilesystemAccess,
            Risk::High,
            Confidence::High,
            "The code writes directly to a shell, desktop, service, or registry autostart location.",
            "Remove package-controlled persistence and require users to configure startup behavior explicitly.",
            r#"(call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
                  arguments: (arguments (string) @path . (_)* )
                  (#eq? @module "fs") (#match? @method "^(writeFile|writeFileSync|appendFile|appendFileSync)$")
                  (#match? @path "(?i)(\\.bashrc|\\.bash_profile|\\.profile|\\.zshrc|/etc/rc\\.local|/etc/init\\.d/|/etc/profile\\.d/|\\.config/autostart/|LaunchAgents|LaunchDaemons|CurrentVersion\\\\Run|Start Menu\\\\Programs\\\\Startup)")) @match"#
        ),
        rule!(
            "chainsec.js.detection.guarddog.destructive-deletion",
            Language::JavaScript,
            FindingType::FilesystemAccess,
            Risk::High,
            Confidence::High,
            "A recursive deletion or shell wipe targets an absolute or user-rooted path.",
            "Remove destructive package behavior and constrain deletion to a package-owned temporary directory.",
            r#"
                (call_expression function: [(identifier) @callee (member_expression property: (property_identifier) @callee)]
                  arguments: (arguments (string) @path . (_)* )
                  (#match? @callee "^(rimraf|rm|rmSync)$")
                  (#match? @path "^['\"](~|/(home|Users)?(/|['\"]))")) @match
                (call_expression function: [(identifier) @callee (member_expression property: (property_identifier) @callee)]
                  arguments: (arguments [(string) @command (template_string) @command] . (_)* )
                  (#match? @callee "^(exec|execSync|spawn|spawnSync)$")
                  (#match? @command "(?i)(rm[[:space:]]+-rf[[:space:]]+/|dd[[:space:]]+if=/dev/(zero|urandom)|shred[[:space:]]+-)")) @match
                "#
        ),
    ]
}
