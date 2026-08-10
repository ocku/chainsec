use crate::model::{Capability, Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
                    "chainsec.ts.capability.network-listen",
                    Language::TypeScript,
                    FindingType::NetworkAccess,
                    Risk::Low,
                    Confidence::High,
                    "The code creates a network listener.",
                    super::super::LIMIT_ACCESS,
                    r#"
                (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
                  (#match? @module "^(http|https|net|tls|dgram|Deno)$")
                  (#match? @method "^(createServer|listen|serve)$")) @match
                (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
                  (#eq? @module "Bun") (#eq? @method "serve")) @match
                "#
                ).with_capability(Capability::NetworkListen),
        rule!(
                    "chainsec.ts.capability.network-raw-socket",
                    Language::TypeScript,
                    FindingType::NetworkAccess,
                    Risk::Medium,
                    Confidence::High,
                    "The code imports a raw-socket package.",
                    super::super::LIMIT_ACCESS,
                    r#"
                (call_expression function: (identifier) @require arguments: (arguments (string) @module)
                  (#eq? @require "require") (#match? @module "['\\\\\"]raw-socket['\\\\\"]")) @match
                (import_statement source: (string) @module
                  (#match? @module "['\\\\\"]raw-socket['\\\\\"]")) @match
                "#
                ).with_capability(Capability::NetworkRawSocket),
        rule!(
                    "chainsec.ts.capability.network-download",
                    Language::TypeScript,
                    FindingType::NetworkAccess,
                    Risk::Medium,
                    Confidence::High,
                    "The code invokes a common HTTP or file-download API.",
                    super::super::LIMIT_ACCESS,
                    r#"
                (call_expression function: (identifier) @callee
                  (#eq? @callee "got")) @match
                (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
                  (#match? @module "^(http|https|axios)$")
                  (#match? @method "^(get|request|download)$")) @match
                "#
                ).with_capability(Capability::NetworkDownload),
        rule!(
                    "chainsec.ts.capability.network-connect",
                    Language::TypeScript,
                    FindingType::NetworkAccess,
                    Risk::Low,
                    Confidence::High,
                    "The code can issue HTTP requests or DNS lookups.",
                    super::super::LIMIT_ACCESS,
                    r#"
                (call_expression function: (identifier) @fetch
                  (#eq? @fetch "fetch")) @match
                (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
                  (#match? @module "^(axios|http|https|dns)$")
                  (#match? @method "^(get|post|put|delete|patch|request|lookup|resolve|resolve4|resolve6|resolveMx|resolveTxt|resolveNs|resolveCname|resolveSrv|resolvePtr|resolveSoa|resolveNaptr)$")) @match
                (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
                  (#eq? @deno "Deno") (#match? @method "^(connect|connectTls)$")) @match
                "#
                ).with_capability(Capability::NetworkConnect),
        rule!(
                    "chainsec.ts.capability.network-tls",
                    Language::TypeScript,
                    FindingType::NetworkAccess,
                    Risk::Low,
                    Confidence::High,
                    "The code creates or upgrades a connection using an explicit Node or Deno TLS API.",
                    super::super::LIMIT_ACCESS,
                    r#"
                (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
                  (#eq? @module "tls")
                  (#match? @method "^(connect|createServer)$")) @match
                (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
                  (#eq? @module "https")
                  (#match? @method "^(get|request|createServer)$")) @match
                (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
                  (#eq? @module "http2")
                  (#eq? @method "createSecureServer")) @match
                (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
                  (#eq? @deno "Deno")
                  (#match? @method "^(connectTls|listenTls|startTls)$")) @match
                "#
                ).with_capability(Capability::NetworkTls),
        rule!(
                    "chainsec.ts.capability.network-connect-via-lolbas",
                    Language::TypeScript,
                    FindingType::NetworkAccess,
                    Risk::Medium,
                    Confidence::High,
                    "A process API launches a command containing a common transfer or tunneling utility.",
                    super::super::REMOVE_EXECUTION,
                    r#"(call_expression function: [(identifier) @callee (member_expression property: (property_identifier) @callee)]
                  arguments: (arguments [(string) @command (template_string) @command (array (string) @command)])
                  (#match? @callee "^(exec|execSync|execFile|execFileSync|spawn|spawnSync)$")
                  (#match? @command "(?i)(curl|wget|certutil|bitsadmin|Invoke-WebRequest|Invoke-RestMethod|socat|ncat|nc)([^A-Za-z0-9_]|$)")) @match"#
                ).with_capability(Capability::NetworkConnect),
        rule!(
                    "chainsec.ts.capability.network-resolve-dns",
                    Language::TypeScript,
                    FindingType::NetworkAccess,
                    Risk::Low,
                    Confidence::High,
                    "The code resolves DNS names.",
                    super::super::LIMIT_ACCESS,
                    r#"
                (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
                  (#eq? @module "dns") (#match? @method "^(lookup|resolve|resolve4|resolve6|resolveMx|resolveTxt|resolveNs|resolveCname|resolveSrv|resolvePtr|resolveSoa|resolveNaptr)$")) @match
                (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
                  (#eq? @deno "Deno") (#eq? @method "resolveDns")) @match
                "#
                ).with_capability(Capability::NetworkResolveDns),
    ]
}
