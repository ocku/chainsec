use crate::model::{Capability, Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
            "chainsec.py.detection.network-request",
            Language::Python,
            FindingType::NetworkAccess,
            Risk::Low,
            Confidence::High,
            "The code can issue an ordinary web request.",
            super::super::ACCESS_REMEDIATION,
            r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method) (#match? @module "^(requests|urllib|httpx|socket)$")) @match"#
        ).with_capability(Capability::NetworkConnect),
        rule!(
            "chainsec.py.detection.guarddog.dns-exfiltration",
            Language::Python,
            FindingType::NetworkAccess,
            Risk::High,
            Confidence::High,
            "A dynamically constructed hostname is passed directly to a DNS lookup API, which can encode data in queries.",
            "Do not place local data in DNS names; use a fixed allowlisted hostname and a documented protocol.",
            r#"
                (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  arguments: (argument_list [(string (interpolation)) (binary_operator) (call function: (attribute attribute: (identifier) @format))] @host . (_)* )
                  (#eq? @module "socket")
                  (#match? @method "^(getaddrinfo|gethostbyname)$")) @match
                "#
        ),
        rule!(
            "chainsec.py.detection.guarddog.messenger-exfiltration",
            Language::Python,
            FindingType::NetworkAccess,
            Risk::High,
            Confidence::High,
            "A hardcoded Telegram credential/API endpoint or Discord webhook/token appears in a string literal.",
            "Remove the credential or webhook, rotate it, and use an approved secret-backed destination.",
            r#"((string) @match (#match? @match "(api\\.telegram\\.org/bot[0-9]+:|discord(app)?\\.com/api/webhooks/[0-9]+/|[0-9]{8,12}:[A-Za-z0-9_-]{30,40}|[A-Za-z0-9]{24,28}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27,})"))"#
        ),
        rule!(
            "chainsec.py.detection.guarddog.suspicious-network-destination",
            Language::Python,
            FindingType::NetworkAccess,
            Risk::Medium,
            Confidence::High,
            "A string literal contains a URL shortener, tunnel, webhook, paste, transfer, or external-IP service associated with payload delivery or exfiltration.",
            "Replace the destination with a documented, allowlisted service and verify why package code contacts it.",
            r#"((string) @match (#match? @match "(?i)(bit\\.ly|appdomain\\.cloud|ngrok\\.(io|app|dev)|termbin\\.com|localhost\\.run|webhook\\.(site|cool)|oast(ify)?\\.(com|pro|live|site|online|fun|me)|trycloudflare\\.com|pipedream\\.net|dnslog\\.cn|beeceptor\\.com|discord\\.com/api/webhooks|transfer\\.sh|filetransfer\\.io|paste(bin|\\.ee)|api\\.telegram\\.org|ipinfo\\.io|ipify\\.org|ifconfig\\.me|files\\.catbox\\.moe)"))"#
        ),
        rule!(
            "chainsec.py.detection.guarddog.reverse-shell",
            Language::Python,
            FindingType::NetworkAccess,
            Risk::Critical,
            Confidence::High,
            "A process API receives a literal reverse-shell command.",
            "Remove the remote shell behavior and investigate the package as potentially compromised.",
            r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  arguments: (argument_list [(string) @command (list (string) @command) (tuple (string) @command)] . (_)* )
                  (#match? @module "^(os|subprocess)$")
                  (#match? @method "^(system|popen|run|call|Popen)$")
                  (#match? @command "(?i)(/dev/(tcp|udp)/|(^|[^A-Za-z])(nc|ncat)[[:space:]].*-e[[:space:]]+/bin/(ba)?sh|bash[[:space:]]+-i)")) @match"#
        ),
    ]
}
