//! Informational capability rules. Every rule in this module sets a capability,
//! so its matches are reported as capability evidence rather than findings.
//!
//! Several patterns are derived from the GuardDog source-code analyzer catalog.
//! Credit: DataDog/guarddog, Apache-2.0; see `docs/THIRD_PARTY.md`.

use crate::model::{Capability, Confidence, FindingType, Language, Risk, Rule};

const LIMIT_ACCESS: &str = "Confirm this capability is required and restrict it to explicit paths, inputs, and destinations.";
const REMOVE_EXECUTION: &str = "Remove runtime execution, or replace it with a fixed command or operation over validated input.";

pub fn capability_rules() -> Vec<Rule> {
    let mut rules = Vec::new();

    // Capability: browser credential and cookie stores.
    rules.push(rule!(
        "chainsec.py.capability.secret-read-browser-profile",
        Language::Python,
        FindingType::SecretAccess,
        Risk::Medium,
        Confidence::High,
        "A browser profile, cookie database, or credential store path is referenced directly.",
        LIMIT_ACCESS,
        r#"((string) @match (#match? @match "(?i)(Chrome[^\"']*(User Data|Login Data)|Microsoft\\\\Edge\\\\User Data|\\.mozilla/firefox|key4\\.db|cookies\\.sqlite|Cookies\\.binarycookies|Safari/LocalStorage|logins\\.json)"))"#
    ).with_capability(Capability::SecretReadBrowserProfile));
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.secret-read-browser-profile",
        Capability::SecretReadBrowserProfile,
        FindingType::SecretAccess,
        Risk::Medium,
        Confidence::High,
        "A browser profile, cookie database, credential store, or cookie extraction package is referenced directly.",
        LIMIT_ACCESS,
        r#"((string) @match (#match? @match "(?i)(Chrome[^\"']*(User Data|Login Data)|Microsoft\\\\Edge\\\\User Data|\\.mozilla/firefox|key4\\.db|cookies\\.sqlite|Cookies\\.binarycookies|Safari/LocalStorage|logins\\.json|chrome-cookies-secure|electron-cookies)"))"#
    );

    // Capability: filesystem deletion.
    rules.push(
        rule!(
            "chainsec.py.capability.filesystem-delete",
            Language::Python,
            FindingType::FilesystemAccess,
            Risk::Medium,
            Confidence::High,
            "The code can remove files or directories.",
            LIMIT_ACCESS,
            r#"
        (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
          (#match? @module "^(os|shutil)$")
          (#match? @method "^(remove|unlink|rmdir|rmtree)$")) @match
        (call function: (attribute attribute: (identifier) @method)
          (#eq? @method "unlink")) @match
        "#
        )
        .with_capability(Capability::FilesystemDelete),
    );
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.filesystem-delete",
        Capability::FilesystemDelete,
        FindingType::FilesystemAccess,
        Risk::Medium,
        Confidence::High,
        "The code can remove files or directories.",
        LIMIT_ACCESS,
        r#"
        (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
          (#eq? @module "fs")
          (#match? @method "^(rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)$")) @match
        (call_expression function: (identifier) @callee
          (#match? @callee "^(rimraf|rimrafSync)$")) @match
        (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
          (#eq? @deno "Deno") (#eq? @method "remove")) @match
        "#
    );

    // Capability: filesystem reads.
    rules.push(rule!(
        "chainsec.py.capability.filesystem-read",
        Language::Python,
        FindingType::FilesystemAccess,
        Risk::Low,
        Confidence::Medium,
        "The code explicitly opens a file for reading or uses a pathlib read helper.",
        LIMIT_ACCESS,
        r#"
        (call function: (attribute object: (call function: (identifier) @path) attribute: (identifier) @method)
          (#eq? @path "Path")
          (#match? @method "^read_(text|bytes)$")) @match
        "#
    ).with_capability(Capability::FilesystemRead));
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.filesystem-read",
        Capability::FilesystemRead,
        FindingType::FilesystemAccess,
        Risk::Low,
        Confidence::High,
        "The Node filesystem API is used to read a file or create a read stream.",
        LIMIT_ACCESS,
        r#"
        (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
          (#eq? @module "fs")
          (#match? @method "^(readFile|readFileSync|createReadStream)$")) @match
        (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
          (#eq? @deno "Deno") (#match? @method "^(readFile|readTextFile)$")) @match
        "#
    );

    // Capability: executable permissions.
    rules.push(rule!(
        "chainsec.py.capability.filesystem-set-permissions",
        Language::Python,
        FindingType::FilesystemAccess,
        Risk::Medium,
        Confidence::High,
        "The code changes file mode bits and can make a dropped file executable.",
        "Avoid changing executable bits at runtime; ship reviewed executables through the package build instead.",
        r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
          (#eq? @module "os") (#eq? @method "chmod")) @match"#
    ).with_capability(Capability::FilesystemSetPermissions));
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.filesystem-set-permissions",
        Capability::FilesystemSetPermissions,
        FindingType::FilesystemAccess,
        Risk::Medium,
        Confidence::High,
        "The code changes file mode bits and can make a dropped file executable.",
        "Avoid changing executable bits at runtime; ship reviewed executables through the package build instead.",
        r#"
        (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
          (#eq? @module "fs") (#match? @method "^(chmod|chmodSync)$")) @match
        (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
          (#eq? @deno "Deno") (#eq? @method "chmod")) @match
        "#
    );

    // Capability: filesystem writes, excluding more-specific persistence threats.
    rules.push(
        rule!(
            "chainsec.py.capability.filesystem-write",
            Language::Python,
            FindingType::FilesystemAccess,
            Risk::Low,
            Confidence::High,
            "The code explicitly writes or appends to a file.",
            LIMIT_ACCESS,
            r#"
        (call function: (identifier) @open arguments: (argument_list (_) (string) @mode)
          (#eq? @open "open") (#match? @mode "['\\\"][wax]")) @match
        (call function: (attribute object: (_) attribute: (identifier) @method)
          (#match? @method "^write_(text|bytes)$")) @match
        "#
        )
        .with_capability(Capability::FilesystemWrite),
    );
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.filesystem-write",
        Capability::FilesystemWrite,
        FindingType::FilesystemAccess,
        Risk::Low,
        Confidence::High,
        "The Node filesystem API writes, appends, or creates a write stream.",
        LIMIT_ACCESS,
        r#"
        (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
          (#eq? @module "fs")
          (#match? @method "^(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)$")) @match
        (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
          (#eq? @deno "Deno") (#match? @method "^(writeFile|writeTextFile)$")) @match
        "#
    );

    // Capability: network listeners and raw sockets.
    rules.push(
        rule!(
            "chainsec.py.capability.network-listen",
            Language::Python,
            FindingType::NetworkAccess,
            Risk::Low,
            Confidence::High,
            "The code binds or listens on a network socket.",
            LIMIT_ACCESS,
            r#"(call function: (attribute object: (_) attribute: (identifier) @method)
          (#match? @method "^(bind|listen|serve_forever)$")) @match"#
        )
        .with_capability(Capability::NetworkListen),
    );
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.network-listen",
        Capability::NetworkListen,
        FindingType::NetworkAccess,
        Risk::Low,
        Confidence::High,
        "The code creates a network listener.",
        LIMIT_ACCESS,
        r#"
        (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
          (#match? @module "^(http|https|net|tls|dgram|Deno)$")
          (#match? @method "^(createServer|listen|serve)$")) @match
        (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
          (#eq? @module "Bun") (#eq? @method "serve")) @match
        "#
    );
    rules.push(
        rule!(
            "chainsec.py.capability.network-raw-socket",
            Language::Python,
            FindingType::NetworkAccess,
            Risk::Medium,
            Confidence::High,
            "The code references Python raw-socket support.",
            LIMIT_ACCESS,
            r#"((identifier) @match (#eq? @match "SOCK_RAW"))"#
        )
        .with_capability(Capability::NetworkRawSocket),
    );
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.network-raw-socket",
        Capability::NetworkRawSocket,
        FindingType::NetworkAccess,
        Risk::Medium,
        Confidence::High,
        "The code imports a raw-socket package.",
        LIMIT_ACCESS,
        r#"
        (call_expression function: (identifier) @require arguments: (arguments (string) @module)
          (#eq? @require "require") (#match? @module "['\\\\\"]raw-socket['\\\\\"]")) @match
        (import_statement source: (string) @module
          (#match? @module "['\\\\\"]raw-socket['\\\\\"]")) @match
        "#
    );

    // Capability: network downloads and outbound requests.
    rules.push(rule!(
        "chainsec.py.capability.network-download",
        Language::Python,
        FindingType::NetworkAccess,
        Risk::Medium,
        Confidence::High,
        "The code invokes a common HTTP or file-download API.",
        LIMIT_ACCESS,
        r#"
        (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
          (#eq? @module "wget")
          (#match? @method "^(get|download)$")) @match
        (call function: (attribute object: (attribute object: (identifier) @urllib attribute: (identifier) @request) attribute: (identifier) @method)
          (#eq? @urllib "urllib") (#eq? @request "request")
          (#match? @method "^(urlopen|urlretrieve)$")) @match
        "#
    ).with_capability(Capability::NetworkDownload));
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.network-download",
        Capability::NetworkDownload,
        FindingType::NetworkAccess,
        Risk::Medium,
        Confidence::High,
        "The code invokes a common HTTP or file-download API.",
        LIMIT_ACCESS,
        r#"
        (call_expression function: (identifier) @callee
          (#eq? @callee "got")) @match
        (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
          (#match? @module "^(http|https|axios)$")
          (#match? @method "^(get|request|download)$")) @match
        "#
    );
    rules.push(rule!(
        "chainsec.py.capability.network-connect",
        Language::Python,
        FindingType::NetworkAccess,
        Risk::Low,
        Confidence::High,
        "The code can issue HTTP requests, resolve DNS names, or open a stream socket.",
        LIMIT_ACCESS,
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
    ).with_capability(Capability::NetworkConnect));
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.network-connect",
        Capability::NetworkConnect,
        FindingType::NetworkAccess,
        Risk::Low,
        Confidence::High,
        "The code can issue HTTP requests or DNS lookups.",
        LIMIT_ACCESS,
        r#"
        (call_expression function: (identifier) @fetch
          (#eq? @fetch "fetch")) @match
        (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
          (#match? @module "^(axios|http|https|dns)$")
          (#match? @method "^(get|post|put|delete|patch|request|lookup|resolve|resolve4|resolve6|resolveMx|resolveTxt|resolveNs|resolveCname|resolveSrv|resolvePtr|resolveSoa|resolveNaptr)$")) @match
        (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
          (#eq? @deno "Deno") (#match? @method "^(connect|connectTls)$")) @match
        "#
    );

    // Capability: TLS socket wrapping. This indicates TLS setup, not a completed handshake.
    rules.push(
        rule!(
            "chainsec.py.capability.network-tls",
            Language::Python,
            FindingType::NetworkAccess,
            Risk::Low,
            Confidence::High,
            "The code wraps a socket with a Python TLS context.",
            LIMIT_ACCESS,
            r#"
        (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
          (#eq? @module "ssl")
          (#eq? @method "wrap_socket")) @match
        (call function: (attribute object: (identifier) @context attribute: (identifier) @method)
          (#match? @context "^(context|ctx|ssl_context)$")
          (#eq? @method "wrap_socket")) @match
        "#
        )
        .with_capability(Capability::NetworkTls),
    );
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.network-tls",
        Capability::NetworkTls,
        FindingType::NetworkAccess,
        Risk::Low,
        Confidence::High,
        "The code creates or upgrades a connection using an explicit Node or Deno TLS API.",
        LIMIT_ACCESS,
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
    );

    // Capability: network tools launched through a process API. Composition remains within one call.
    rules.push(rule!(
        "chainsec.py.capability.network-connect-via-lolbas",
        Language::Python,
        FindingType::NetworkAccess,
        Risk::Medium,
        Confidence::High,
        "A process API launches a command containing a common transfer or tunneling utility.",
        REMOVE_EXECUTION,
        r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
          arguments: (argument_list [(string) @command (list (string) @command)])
          (#match? @module "^(os|subprocess)$")
          (#match? @method "^(system|popen|run|call|check_call|check_output|Popen)$")
          (#match? @command "(?i)(curl|wget|certutil|bitsadmin|Invoke-WebRequest|Invoke-RestMethod|socat|ncat|nc)([^A-Za-z0-9_]|$)")) @match"#
    ).with_capability(Capability::NetworkConnect));
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.network-connect-via-lolbas",
        Capability::NetworkConnect,
        FindingType::NetworkAccess,
        Risk::Medium,
        Confidence::High,
        "A process API launches a command containing a common transfer or tunneling utility.",
        REMOVE_EXECUTION,
        r#"(call_expression function: [(identifier) @callee (member_expression property: (property_identifier) @callee)]
          arguments: (arguments [(string) @command (template_string) @command (array (string) @command)])
          (#match? @callee "^(exec|execSync|execFile|execFileSync|spawn|spawnSync)$")
          (#match? @command "(?i)(curl|wget|certutil|bitsadmin|Invoke-WebRequest|Invoke-RestMethod|socat|ncat|nc)([^A-Za-z0-9_]|$)")) @match"#
    );

    // Capability: process scheduling.
    rules.push(rule!(
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
    ).with_capability(Capability::ProcessSchedule));
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.process-schedule",
        Capability::ProcessSchedule,
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
    );

    // Capability: process and runtime code execution.
    rules.push(
        rule!(
            "chainsec.py.capability.process-spawn",
            Language::Python,
            FindingType::ProcessExecution,
            Risk::High,
            Confidence::High,
            "The code invokes a process or dynamic-code execution API.",
            REMOVE_EXECUTION,
            r#"
        (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
          (#match? @module "^(os|subprocess)$")
          (#match? @method "^(spawn.*|exec.*)$")) @match
        "#
        )
        .with_capability(Capability::ProcessSpawn),
    );
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.process-spawn",
        Capability::ProcessSpawn,
        FindingType::ProcessExecution,
        Risk::High,
        Confidence::High,
        "The code invokes a process or dynamic-code execution API.",
        REMOVE_EXECUTION,
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
    );

    // Capability: dynamic code execution.
    rules.push(rule!(
        "chainsec.py.capability.dynamic-code-execution",
        Language::Python,
        FindingType::ArbitraryCodeExecution,
        Risk::High,
        Confidence::High,
        "The code invokes a Python dynamic-code execution API.",
        REMOVE_EXECUTION,
        r#"(call function: (identifier) @callee (#match? @callee "^(eval|exec|compile)$")) @match"#
    ).with_capability(Capability::CodeDynamicExecution));
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.dynamic-code-execution",
        Capability::CodeDynamicExecution,
        FindingType::ArbitraryCodeExecution,
        Risk::High,
        Confidence::High,
        "The code invokes a JavaScript or TypeScript dynamic-code execution API.",
        REMOVE_EXECUTION,
        r#"(call_expression function: (identifier) @callee (#match? @callee "^(eval|Function)$")) @match"#
    );

    // Capability: clipboard access.
    rules.push(rule!(
        "chainsec.py.capability.clipboard-access",
        Language::Python,
        FindingType::SecretAccess,
        Risk::Low,
        Confidence::High,
        "The code reads from or writes to the system clipboard.",
        LIMIT_ACCESS,
        r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
          (#match? @module "^(pyperclip|pandas|root)$")
          (#match? @method "^(paste|copy|read_clipboard|clipboard_get)$")) @match"#
    ).with_capability(Capability::RuntimeReadClipboard));
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.clipboard-access",
        Capability::RuntimeReadClipboard,
        FindingType::SecretAccess,
        Risk::Low,
        Confidence::High,
        "The code reads from or writes to the system clipboard.",
        LIMIT_ACCESS,
        r#"
        (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
          (#match? @module "^(clipboardy|clipboard)$")
          (#match? @method "^(read|readSync|write|writeSync|readText)$")) @match
        "#
    );

    // Capability: environment and credential-file access.
    rules.push(rule!(
        "chainsec.py.capability.secret-read-environment",
        Language::Python,
        FindingType::SecretAccess,
        Risk::Low,
        Confidence::High,
        "The code reads environment variables, which may contain inherited credentials.",
        LIMIT_ACCESS,
        r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
          (#eq? @module "os") (#eq? @method "getenv")) @match"#
    ).with_capability(Capability::SecretReadEnvironment));
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.secret-read-environment",
        Capability::SecretReadEnvironment,
        FindingType::SecretAccess,
        Risk::Low,
        Confidence::High,
        "The code reads environment variables, which may contain inherited credentials.",
        LIMIT_ACCESS,
        r#"
        (member_expression object: (member_expression object: (identifier) @process property: (property_identifier) @environment)
          (#eq? @process "process") (#eq? @environment "env")) @match
        (call_expression function: (member_expression object: (member_expression object: (identifier) @deno property: (property_identifier) @environment) property: (property_identifier) @method)
          (#eq? @deno "Deno") (#eq? @environment "env")
          (#match? @method "^(get|has|toObject)$")) @match
        "#
    );
    rules.push(rule!(
        "chainsec.py.capability.secret-read-file",
        Language::Python,
        FindingType::SecretAccess,
        Risk::Medium,
        Confidence::High,
        "A path commonly used to store credentials is referenced directly.",
        LIMIT_ACCESS,
        r#"((string) @match (#match? @match "(?i)(\.ssh/(id_[^/\\\"']+|config)|\.aws/credentials|\.config/gcloud|\.kube/config|\.npmrc|\.pypirc|\.env(?:$|[\\\"']))"))"#
    ).with_capability(Capability::SecretReadFile));
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.secret-read-file",
        Capability::SecretReadFile,
        FindingType::SecretAccess,
        Risk::Medium,
        Confidence::High,
        "A path commonly used to store credentials is referenced directly.",
        LIMIT_ACCESS,
        r#"((string) @match (#match? @match "(?i)(\.ssh/(id_[^/\\\"']+|config)|\.aws/credentials|\.config/gcloud|\.kube/config|\.npmrc|\.pypirc|\.env(?:$|[\\\"']))"))"#
    );

    // Capability: filesystem discovery and archive handling.
    rules.push(rule!(
        "chainsec.py.capability.filesystem-enumerate",
        Language::Python,
        FindingType::FilesystemAccess,
        Risk::Low,
        Confidence::High,
        "The code enumerates files or directories.",
        LIMIT_ACCESS,
        r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
          (#match? @module "^(os|glob)$") (#match? @method "^(listdir|scandir|walk|glob|iglob)$")) @match"#
    ).with_capability(Capability::FilesystemEnumerate));
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.filesystem-enumerate",
        Capability::FilesystemEnumerate,
        FindingType::FilesystemAccess,
        Risk::Low,
        Confidence::High,
        "The code enumerates files or directories.",
        LIMIT_ACCESS,
        r#"
        (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
          (#eq? @module "fs") (#match? @method "^(readdir|readdirSync|opendir|opendirSync)$")) @match
        (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
          (#eq? @deno "Deno") (#eq? @method "readDir")) @match
        "#
    );
    rules.push(rule!(
        "chainsec.py.capability.filesystem-archive",
        Language::Python,
        FindingType::FilesystemAccess,
        Risk::Low,
        Confidence::High,
        "The code creates or extracts an archive.",
        LIMIT_ACCESS,
        r#"(call function: (attribute object: (_) attribute: (identifier) @method)
          (#match? @method "^(extract|extractall|write|writestr|make_archive|unpack_archive)$")) @match"#
    ).with_capability(Capability::FilesystemArchive));
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.filesystem-archive",
        Capability::FilesystemArchive,
        FindingType::FilesystemAccess,
        Risk::Low,
        Confidence::High,
        "The code creates or extracts an archive.",
        LIMIT_ACCESS,
        r#"(call_expression function: (member_expression property: (property_identifier) @method)
          (#match? @method "^(extract|extractAll|zip|unzip|archive)$")) @match"#
    );

    // Capability: DNS resolution, kept distinct from a general outbound connection.
    rules.push(rule!(
        "chainsec.py.capability.network-resolve-dns",
        Language::Python,
        FindingType::NetworkAccess,
        Risk::Low,
        Confidence::High,
        "The code resolves DNS names.",
        LIMIT_ACCESS,
        r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
          (#match? @module "^(socket|dns)$") (#match? @method "^(gethostbyname|gethostbyname_ex|getaddrinfo|resolve|query)$")) @match"#
    ).with_capability(Capability::NetworkResolveDns));
    js_ts_rules!(
        rules,
        "",
        "chainsec.capability.network-resolve-dns",
        Capability::NetworkResolveDns,
        FindingType::NetworkAccess,
        Risk::Low,
        Confidence::High,
        "The code resolves DNS names.",
        LIMIT_ACCESS,
        r#"
        (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
          (#eq? @module "dns") (#match? @method "^(lookup|resolve|resolve4|resolve6|resolveMx|resolveTxt|resolveNs|resolveCname|resolveSrv|resolvePtr|resolveSoa|resolveNaptr)$")) @match
        (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
          (#eq? @deno "Deno") (#eq? @method "resolveDns")) @match
        "#
    );

    rules
}
