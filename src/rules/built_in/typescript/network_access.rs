use crate::model::{Capability, Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
            "chainsec.ts.detection.network-request",
            Language::TypeScript,
            FindingType::NetworkAccess,
            Risk::Low,
            Confidence::High,
            "The code can issue an ordinary web request.",
            super::super::ACCESS_REMEDIATION,
            r#"
                    (call_expression function: (identifier) @callee (#eq? @callee "fetch")) @match
                    (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
                      (#eq? @deno "Deno")
                      (#match? @method "^(http|connect|connectTls|createHttpClient|resolveDns|upgradeWebSocket)$")) @match
                    "#
        ).with_capability(Capability::NetworkConnect),
        rule!(
            "chainsec.ts.detection.network-listen",
            Language::TypeScript,
            FindingType::NetworkAccess,
            Risk::Low,
            Confidence::High,
            "The code can create a network listener.",
            super::super::ACCESS_REMEDIATION,
            r#"
                    (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
                      (#eq? @deno "Deno")
                      (#match? @method "^(serve|serveHttp|listen|listenTls)$")) @match
                    "#
        ).with_capability(Capability::NetworkListen),
        rule!(
            "chainsec.ts.detection.guarddog.messenger-exfiltration",
            Language::TypeScript,
            FindingType::NetworkAccess,
            Risk::High,
            Confidence::High,
            "A hardcoded Telegram credential/API endpoint or Discord webhook/token appears in a string literal.",
            "Remove the credential or webhook, rotate it, and use an approved secret-backed destination.",
            r#"((string) @match (#match? @match "(api\\.telegram\\.org/bot[0-9]+:|discord(app)?\\.com/api/webhooks/[0-9]+/|[0-9]{8,12}:[A-Za-z0-9_-]{30,40}|[A-Za-z0-9]{24,28}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27,})"))"#
        ),
        rule!(
            "chainsec.ts.detection.guarddog.suspicious-network-destination",
            Language::TypeScript,
            FindingType::NetworkAccess,
            Risk::Medium,
            Confidence::High,
            "A string literal contains a URL shortener, tunnel, webhook, paste, transfer, or external-IP service associated with payload delivery or exfiltration.",
            "Replace the destination with a documented, allowlisted service and verify why package code contacts it.",
            r#"((string) @match (#match? @match "(?i)(bit\\.ly|appdomain\\.cloud|ngrok\\.(io|app|dev)|termbin\\.com|localhost\\.run|webhook\\.(site|cool)|oast(ify)?\\.(com|pro|live|site|online|fun|me)|trycloudflare\\.com|pipedream\\.net|dnslog\\.cn|beeceptor\\.com|discord\\.com/api/webhooks|transfer\\.sh|filetransfer\\.io|paste(bin|\\.ee)|api\\.telegram\\.org|ipinfo\\.io|ipify\\.org|ifconfig\\.me|files\\.catbox\\.moe)"))"#
        ),
        rule!(
            "chainsec.ts.detection.guarddog.reverse-shell",
            Language::TypeScript,
            FindingType::NetworkAccess,
            Risk::Critical,
            Confidence::High,
            "A process API receives a literal reverse-shell command.",
            "Remove the remote shell behavior and investigate the package as potentially compromised.",
            r#"(call_expression function: [(identifier) @callee (member_expression property: (property_identifier) @callee)]
                  arguments: (arguments [(string) @command (template_string) @command] . (_)* )
                  (#match? @callee "^(exec|execSync|spawn|spawnSync)$")
                  (#match? @command "(?i)(/dev/(tcp|udp)/|(^|[^A-Za-z])(nc|ncat)[[:space:]].*-e[[:space:]]+/bin/(ba)?sh|bash[[:space:]]+-i)")) @match"#
        ),
    ]
}
