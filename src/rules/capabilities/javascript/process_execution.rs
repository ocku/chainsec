use crate::model::{Capability, Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
                    "chainsec.js.capability.process-schedule",
                    Language::JavaScript,
                    FindingType::ProcessExecution,
                    Risk::Medium,
                    Confidence::Medium,
                    "The code imports a scheduling package or constructs a scheduled job.",
                    "Avoid creating scheduled jobs from package code; require an explicit user-controlled setup step.",
                    r#"
                (new_expression constructor: (identifier) @callee (#eq? @callee "CronJob")) @match
                (call_expression function: (identifier) @callee (#eq? @callee "scheduleJob")) @match
                (call_expression function: (identifier) @require arguments: (arguments (string) @module)
                  (#eq? @require "require") (#match? @module "['\"](node-cron|cron|node-schedule)['\"]")) @match
                (import_statement source: (string) @module
                  (#match? @module "['\"](node-cron|cron|node-schedule)['\"]")) @match
                "#
                ).with_capability(Capability::ProcessSchedule),
        rule!(
                    "chainsec.js.capability.process-spawn",
                    Language::JavaScript,
                    FindingType::ProcessExecution,
                    Risk::High,
                    Confidence::High,
                    "The code invokes a process or dynamic-code execution API.",
                    super::super::REMOVE_EXECUTION,
                    r#"
                (call_expression function: (identifier) @callee
                  (#match? @callee "^(execSync|execFileSync|spawnSync)$")) @match
                (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @callee)
                  (#match? @module "^(child_process|cp)$")
                  (#match? @callee "^(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)$")) @match
                (call_expression function: (member_expression object: (new_expression constructor: (member_expression object: (identifier) @deno property: (property_identifier) @command)) property: (property_identifier) @method)
                  (#eq? @deno "Deno") (#eq? @command "Command")
                  (#match? @method "^(spawn|output|outputSync)$")) @match
                (new_expression constructor: (identifier) @callee (#eq? @callee "Function")) @match
                "#
                ).with_capability(Capability::ProcessSpawn),
    ]
}
