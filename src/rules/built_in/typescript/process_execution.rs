use crate::model::{Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
            "chainsec.ts.detection.process-spawn",
            Language::TypeScript,
            FindingType::ProcessExecution,
            Risk::Medium,
            Confidence::High,
            super::super::EXECUTION_RATIONALE,
            super::super::EXECUTION_REMEDIATION,
            r#"
                    (call_expression function: (identifier) @callee (#match? @callee "^(exec|execFile|spawn|fork)$")) @match
                    (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @callee)
                      (#match? @module "^(child_process|cp)$")
                      (#match? @callee "^(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)$")) @match
                    ((import_statement source: (string) @module) @match
                      (#match? @module "child_process"))
                    ((variable_declarator
                      name: (identifier) @alias
                      value: (call_expression
                        function: (identifier) @require
                        arguments: (arguments (string) @module))) @match
                      (#eq? @require "require")
                      (#match? @module "child_process"))
                    (call_expression function: (member_expression object: (new_expression constructor: (member_expression object: (identifier) @deno property: (property_identifier) @command)) property: (property_identifier) @method)
                      (#eq? @deno "Deno") (#eq? @command "Command")
                      (#match? @method "^(spawn|output|outputSync)$")) @match
                    "#
        ),
        rule!(
            "chainsec.ts.detection.guarddog.cryptomining",
            Language::TypeScript,
            FindingType::ProcessExecution,
            Risk::High,
            Confidence::High,
            "A string literal names mining software, a mining pool/protocol, or a Monero wallet.",
            "Remove unauthorized mining behavior and investigate the package provenance.",
            r#"((string) @match (#match? @match "(?i)(xmrig|ethminer|cgminer|bfgminer|cpuminer|ccminer|supportxmr\\.com|minexmr\\.com|nanopool\\.org|stratum\\+(tcp|ssl)://|[^1-9A-HJ-NP-Za-km-z]4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}[^1-9A-HJ-NP-Za-km-z])"))"#
        ),
        rule!(
            "chainsec.ts.detection.guarddog.download-and-execute",
            Language::TypeScript,
            FindingType::ProcessExecution,
            Risk::High,
            Confidence::High,
            "A process API directly executes a downloader, package installer, or download-and-shell command.",
            super::super::REMOVE_EXECUTION,
            r#"(call_expression function: [(identifier) @callee (member_expression property: (property_identifier) @callee)]
                  arguments: (arguments [(string) @command (template_string) @command (array (string) @command)] . (_)* )
                  (#match? @callee "^(exec|execSync|execFile|execFileSync|spawn|spawnSync)$")
                  (#match? @command "(?i)((curl|wget|powershell)([^A-Za-z0-9_]|$)|npm[[:space:]]+install|curl[^\"']*\\|[[:space:]]*(bash|sh|python|node)|wget[^\"']*-O[[:space:]]+-[^\"']*\\|)")) @match"#
        ),
        rule!(
            "chainsec.ts.detection.guarddog.encoded-powershell",
            Language::TypeScript,
            FindingType::ProcessExecution,
            Risk::Critical,
            Confidence::High,
            "A process API receives an encoded, hidden, or download-cradle PowerShell command.",
            "Remove the PowerShell payload and investigate the package as potentially compromised.",
            r#"(call_expression function: [(identifier) @callee (member_expression property: (property_identifier) @callee)]
                  arguments: (arguments [(string) @command (template_string) @command (array (string) @command)] . (_)* )
                  (#match? @callee "^(exec|execSync|execFile|execFileSync|spawn|spawnSync)$")
                  (#match? @command "(?i)(powershell.*-(EncodedCommand|enc)[[:space:]]+[A-Za-z0-9+/=]{20,}|powershell.*-WindowStyle[[:space:]]+Hidden|Download(String|File)|Invoke-WebRequest|IEX[[:space:]]*\\()")) @match"#
        ),
    ]
}
