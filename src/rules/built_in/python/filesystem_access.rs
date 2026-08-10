use crate::model::{Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
            "chainsec.py.detection.filesystem-open",
            Language::Python,
            FindingType::FilesystemAccess,
            Risk::Medium,
            Confidence::Medium,
            "The package directly opens a credential, account, or shell-startup file outside its own data directory.",
            super::super::ACCESS_REMEDIATION,
            r#"((call function: (identifier) @callee
                  arguments: (argument_list (string) @path . (_)*)) @match
                  (#eq? @callee "open")
                  (#match? @path "(?i)^['\"](?:/etc/(?:passwd|shadow|sudoers)|~?/(?:\\.ssh|\\.aws|\\.config/gcloud)/|~?/\\.(?:bashrc|bash_profile|profile|zshrc)|[^'\"]*(?:id_rsa|id_ed25519|credentials))"))"#
        ),
        rule!(
            "chainsec.py.detection.guarddog.autostart",
            Language::Python,
            FindingType::FilesystemAccess,
            Risk::High,
            Confidence::High,
            "The code writes directly to a shell, desktop, service, or registry autostart location.",
            "Remove package-controlled persistence and require users to configure startup behavior explicitly.",
            r#"
                (call function: (identifier) @open arguments: (argument_list (string) @path (string) @mode)
                  (#eq? @open "open")
                  (#match? @path "(?i)(\\.bashrc|\\.bash_profile|\\.profile|\\.zshrc|/etc/rc\\.local|/etc/init\\.d/|/etc/profile\\.d/|\\.config/autostart/|LaunchAgents|LaunchDaemons|CurrentVersion\\\\Run|Start Menu\\\\Programs\\\\Startup)")
                  (#match? @mode "['\"][wa]\\+?['\"]")) @match
                (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  arguments: (argument_list (_) (string) @path . (_)* )
                  (#eq? @module "winreg") (#eq? @method "SetValueEx")
                  (#match? @path "(?i)(CurrentVersion\\\\Run|CurrentVersion\\\\RunOnce)")) @match
                "#
        ),
        rule!(
            "chainsec.py.detection.guarddog.destructive-deletion",
            Language::Python,
            FindingType::FilesystemAccess,
            Risk::High,
            Confidence::High,
            "A recursive deletion or shell wipe targets an absolute, home, or user-rooted path.",
            "Remove destructive package behavior and constrain deletion to a package-owned temporary directory.",
            r#"
                (call function: (attribute attribute: (identifier) @method) arguments: (argument_list (string) @path . (_)* )
                  (#match? @method "^(rmtree|rm|rmSync)$")
                  (#match? @path "^['\"](~|/(home|Users)?(/|['\"]))")) @match
                (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  arguments: (argument_list (string) @command . (_)* )
                  (#match? @module "^(os|subprocess)$")
                  (#match? @method "^(system|popen|run|call|Popen)$")
                  (#match? @command "(?i)(rm[[:space:]]+-rf[[:space:]]+/|dd[[:space:]]+if=/dev/(zero|urandom)|shred[[:space:]]+-)")) @match
                "#
        ),
    ]
}
