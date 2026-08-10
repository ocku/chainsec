use crate::model::{Capability, Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
                "chainsec.py.capability.process-schedule",
                Language::Python,
                FindingType::ProcessExecution,
                Risk::Medium,
                Confidence::Medium,
                "The code constructs or modifies a scheduled job.",
                "Avoid creating scheduled jobs from package code; require an explicit user-controlled setup step.",
                r#"
                (call function: (identifier) @callee (#eq? @callee "CronTab")) @match
                (call function: (attribute object: (identifier) @cron attribute: (identifier) @method)
                  (#eq? @cron "CronTab") (#eq? @method "new")) @match
                ((string) @match (#match? @match "(?i)(/etc/crontab|/etc/cron\\.d/|/etc/systemd/system/[^\"']*\\.timer)"))
                "#
            ).with_capability(Capability::ProcessSchedule),
        rule!(
                    "chainsec.py.capability.process-spawn",
                    Language::Python,
                    FindingType::ProcessExecution,
                    Risk::High,
                    Confidence::High,
                    "The code invokes a process or dynamic-code execution API.",
                    super::super::REMOVE_EXECUTION,
                    r#"
                (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  (#eq? @module "os")
                  (#match? @method "^(system|popen|spawn.*|exec.*)$")) @match
                (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  (#eq? @module "subprocess")
                  (#match? @method "^(run|call|check_call|check_output|Popen)$")) @match
                "#
                ).with_capability(Capability::ProcessSpawn),
    ]
}
