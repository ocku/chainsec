use crate::model::{Capability, Confidence, FindingType, Language, Risk, Rule};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        rule!(
                    "chainsec.py.capability.network-listen",
                    Language::Python,
                    FindingType::NetworkAccess,
                    Risk::Low,
                    Confidence::High,
                    "The code binds or listens on a network socket.",
                    super::super::LIMIT_ACCESS,
                    r#"(call function: (attribute object: (_) attribute: (identifier) @method)
                  (#match? @method "^(bind|listen|serve_forever)$")) @match"#
                ).with_capability(Capability::NetworkListen),
        rule!(
                    "chainsec.py.capability.network-raw-socket",
                    Language::Python,
                    FindingType::NetworkAccess,
                    Risk::Medium,
                    Confidence::High,
                    "The code references Python raw-socket support.",
                    super::super::LIMIT_ACCESS,
                    r#"((identifier) @match (#eq? @match "SOCK_RAW"))"#
                ).with_capability(Capability::NetworkRawSocket),
        rule!(
                "chainsec.py.capability.network-download",
                Language::Python,
                FindingType::NetworkAccess,
                Risk::Medium,
                Confidence::High,
                "The code invokes a common HTTP or file-download API.",
                super::super::LIMIT_ACCESS,
                r#"
                (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  (#eq? @module "wget")
                  (#match? @method "^(get|download)$")) @match
                (call function: (attribute object: (attribute object: (identifier) @urllib attribute: (identifier) @request) attribute: (identifier) @method)
                  (#eq? @urllib "urllib") (#eq? @request "request")
                  (#match? @method "^(urlopen|urlretrieve)$")) @match
                "#
            ).with_capability(Capability::NetworkDownload),
        rule!(
                "chainsec.py.capability.network-connect",
                Language::Python,
                FindingType::NetworkAccess,
                Risk::Low,
                Confidence::High,
                "The code can issue HTTP requests, resolve DNS names, or open a stream socket.",
                super::super::LIMIT_ACCESS,
                r#"
                (call function: (attribute object: (attribute object: (identifier) @root attribute: (identifier) @child) attribute: (identifier) @method)
                  (#match? @root "^(urllib|http)$")
                  (#match? @child "^(request|client)$")
                  (#match? @method "^(urlopen|urlretrieve|Request|HTTPConnection|HTTPSConnection)$")) @match
                (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  (#eq? @module "socket")
                  (#eq? @method "create_connection")) @match
                (call function: (attribute object: (identifier) @socket attribute: (identifier) @method)
                  (#match? @socket "^(sock|socket|conn|connection)$")
                  (#eq? @method "connect")) @match
                "#
            ).with_capability(Capability::NetworkConnect),
        rule!(
                    "chainsec.py.capability.network-tls",
                    Language::Python,
                    FindingType::NetworkAccess,
                    Risk::Low,
                    Confidence::High,
                    "The code wraps a socket with a Python TLS context.",
                    super::super::LIMIT_ACCESS,
                    r#"
                (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  (#eq? @module "ssl")
                  (#eq? @method "wrap_socket")) @match
                (call function: (attribute object: (identifier) @context attribute: (identifier) @method)
                  (#match? @context "^(context|ctx|ssl_context)$")
                  (#eq? @method "wrap_socket")) @match
                "#
                ).with_capability(Capability::NetworkTls),
        rule!(
                "chainsec.py.capability.network-connect-via-lolbas",
                Language::Python,
                FindingType::NetworkAccess,
                Risk::Medium,
                Confidence::High,
                "A process API launches a command containing a common transfer or tunneling utility.",
                super::super::REMOVE_EXECUTION,
                r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  arguments: (argument_list [(string) @command (list (string) @command)])
                  (#match? @module "^(os|subprocess)$")
                  (#match? @method "^(system|popen|run|call|check_call|check_output|Popen)$")
                  (#match? @command "(?i)(curl|wget|certutil|bitsadmin|Invoke-WebRequest|Invoke-RestMethod|socat|ncat|nc)([^A-Za-z0-9_]|$)")) @match"#
            ).with_capability(Capability::NetworkConnect),
        rule!(
                "chainsec.py.capability.network-resolve-dns",
                Language::Python,
                FindingType::NetworkAccess,
                Risk::Low,
                Confidence::High,
                "The code resolves DNS names.",
                super::super::LIMIT_ACCESS,
                r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
                  (#match? @module "^(socket|dns)$") (#match? @method "^(gethostbyname|gethostbyname_ex|getaddrinfo|resolve|query)$")) @match"#
            ).with_capability(Capability::NetworkResolveDns),
    ]
}
