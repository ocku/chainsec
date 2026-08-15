use crate::model::{Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
            "chainsec.py.detection.process-spawn",
            Language::Python,
            FindingType::ProcessExecution,
            Risk::Medium,
            Confidence::High,
            "Shell-backed process execution can interpret metacharacters and attacker-controlled command text.",
            super::super::EXECUTION_REMEDIATION,
            r#"
                (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  (#eq? @module "os") (#match? @method "^(system|popen)$")) @match
                ((call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  arguments: (argument_list (_) . (_)*
                    (keyword_argument name: (identifier) @keyword value: (true) @enabled) . (_)*)) @match
                  (#eq? @module "subprocess")
                  (#match? @method "^(run|call|check_call|check_output|Popen)$")
                  (#eq? @keyword "shell"))
                "#
        ),
        rule!(
            "chainsec.py.detection.guarddog.cryptomining",
            Language::Python,
            FindingType::ProcessExecution,
            Risk::High,
            Confidence::High,
            "A string literal names mining software, a mining pool/protocol, or a Monero wallet.",
            "Remove unauthorized mining behavior and investigate the package provenance.",
            r#"((string) @match (#match? @match "(?i)(xmrig|ethminer|cgminer|bfgminer|cpuminer|ccminer|supportxmr\\.com|minexmr\\.com|nanopool\\.org|stratum\\+(tcp|ssl)://|[^1-9A-HJ-NP-Za-km-z]4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}[^1-9A-HJ-NP-Za-km-z])"))"#
        ),
        rule!(
            "chainsec.py.detection.guarddog.download-and-execute",
            Language::Python,
            FindingType::ProcessExecution,
            Risk::High,
            Confidence::High,
            "A process API directly executes a downloader, package installer, or download-and-shell command.",
            super::super::REMOVE_EXECUTION,
            r#"
                (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  arguments: (argument_list [(string) @command (list) @command (tuple) @command] . (_)* )
                  (#match? @module "^(os|subprocess)$")
                  (#match? @method "^(system|popen|run|call|check_call|Popen)$")
                  (#match? @command "(?i)(curl([^A-Za-z0-9_]|$)|wget([^A-Za-z0-9_]|$)|pip[[:space:]]+install|powershell(\\.exe)?.*(Invoke-WebRequest|iwr|Start-BitsTransfer|Download(String|File)|IEX|Invoke-Expression|Install-(Package|Module|Script))|curl[^\"']*\\|[[:space:]]*(bash|sh|python|node)|wget[^\"']*-O[[:space:]]+-[^\"']*\\|)")) @match
                (call function: (identifier) @exec arguments: (argument_list
                  (call function: (identifier) @compile arguments: (argument_list
                    (call function: (identifier) @open))))
                  (#eq? @exec "exec") (#eq? @compile "compile") (#eq? @open "open")) @match
                "#
        ),
        rule!(
            "chainsec.py.detection.guarddog.encoded-powershell",
            Language::Python,
            FindingType::ProcessExecution,
            Risk::Critical,
            Confidence::High,
            "A process API receives an encoded, hidden, or download-cradle PowerShell command.",
            "Remove the PowerShell payload and investigate the package as potentially compromised.",
            r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  arguments: (argument_list [(string) @command (list (string) @command) (tuple (string) @command)] . (_)* )
                  (#match? @module "^(os|subprocess)$")
                  (#match? @method "^(system|popen|run|call|Popen)$")
                  (#match? @command "(?i)(powershell.*-(EncodedCommand|enc)[[:space:]]+[A-Za-z0-9+/=]{20,}|powershell.*-WindowStyle[[:space:]]+Hidden|Download(String|File)|Invoke-WebRequest|IEX[[:space:]]*\\()")) @match"#
        ),
    ]
}
