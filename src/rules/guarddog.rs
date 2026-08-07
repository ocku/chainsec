use crate::model::{Confidence, FindingType, Language, Risk, Rule};

macro_rules! js_ts_rules {
    ($rules:expr, $id:literal, $kind:expr, $risk:expr, $confidence:expr, $rationale:expr, $remediation:expr, $query:expr) => {{
        $rules.push(rule!(
            concat!("GD_", $id, "_JS"),
            Language::JavaScript,
            $kind,
            $risk,
            $confidence,
            $rationale,
            $remediation,
            $query
        ));
        $rules.push(rule!(
            concat!("GD_", $id, "_TS"),
            Language::TypeScript,
            $kind,
            $risk,
            $confidence,
            $rationale,
            $remediation,
            $query
        ));
    }};
}

const LIMIT_ACCESS: &str = "Confirm this capability is required and restrict it to explicit paths, inputs, and destinations.";
const REMOVE_EXECUTION: &str = "Remove runtime execution, or replace it with a fixed command or operation over validated input.";
const REVIEW_OBFUSCATION: &str =
    "Remove the obfuscation and review the decoded or dynamically resolved behavior before use.";

pub fn guarddog_rules() -> Vec<Rule> {
    let mut rules = capability_rules();
    rules.extend(threat_rules());
    rules
}

fn capability_rules() -> Vec<Rule> {
    let mut rules = Vec::new();

    // Capability: browser credential and cookie stores.
    rules.push(rule!(
        "GD_CAPABILITY_FILESYSTEM_BROWSER_PY",
        Language::Python,
        FindingType::SecretAccess,
        Risk::Medium,
        Confidence::High,
        "A browser profile, cookie database, or credential store path is referenced directly.",
        LIMIT_ACCESS,
        r#"((string) @match (#match? @match "(?i)(Chrome[^\"']*(User Data|Login Data)|Microsoft\\\\Edge\\\\User Data|\\.mozilla/firefox|key4\\.db|cookies\\.sqlite|Cookies\\.binarycookies|Safari/LocalStorage|logins\\.json)"))"#
    ));
    js_ts_rules!(
        rules,
        "CAPABILITY_FILESYSTEM_BROWSER",
        FindingType::SecretAccess,
        Risk::Medium,
        Confidence::High,
        "A browser profile, cookie database, credential store, or cookie extraction package is referenced directly.",
        LIMIT_ACCESS,
        r#"((string) @match (#match? @match "(?i)(Chrome[^\"']*(User Data|Login Data)|Microsoft\\\\Edge\\\\User Data|\\.mozilla/firefox|key4\\.db|cookies\\.sqlite|Cookies\\.binarycookies|Safari/LocalStorage|logins\\.json|chrome-cookies-secure|electron-cookies)"))"#
    );

    // Capability: filesystem deletion.
    rules.push(rule!(
        "GD_CAPABILITY_FILESYSTEM_DELETE_PY",
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
    ));
    js_ts_rules!(
        rules,
        "CAPABILITY_FILESYSTEM_DELETE",
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
        "#
    );

    // Capability: filesystem reads.
    rules.push(rule!(
        "GD_CAPABILITY_FILESYSTEM_READ_PY",
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
    ));
    js_ts_rules!(
        rules,
        "CAPABILITY_FILESYSTEM_READ",
        FindingType::FilesystemAccess,
        Risk::Low,
        Confidence::High,
        "The Node filesystem API is used to read a file or create a read stream.",
        LIMIT_ACCESS,
        r#"(call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
          (#eq? @module "fs")
          (#match? @method "^(readFile|readFileSync|createReadStream)$")) @match"#
    );

    // Capability: executable permissions.
    rules.push(rule!(
        "GD_CAPABILITY_FILESYSTEM_WRITE_EXECUTABLE_PY",
        Language::Python,
        FindingType::FilesystemAccess,
        Risk::Medium,
        Confidence::High,
        "The code changes file mode bits and can make a dropped file executable.",
        "Avoid changing executable bits at runtime; ship reviewed executables through the package build instead.",
        r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
          (#eq? @module "os") (#eq? @method "chmod")) @match"#
    ));
    js_ts_rules!(
        rules,
        "CAPABILITY_FILESYSTEM_WRITE_EXECUTABLE",
        FindingType::FilesystemAccess,
        Risk::Medium,
        Confidence::High,
        "The code changes file mode bits and can make a dropped file executable.",
        "Avoid changing executable bits at runtime; ship reviewed executables through the package build instead.",
        r#"(call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
          (#eq? @module "fs") (#match? @method "^(chmod|chmodSync)$")) @match"#
    );

    // Capability: network downloads and outbound requests.
    rules.push(rule!(
        "GD_CAPABILITY_NETWORK_DOWNLOAD_PY",
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
    ));
    js_ts_rules!(
        rules,
        "CAPABILITY_NETWORK_DOWNLOAD",
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
        "GD_CAPABILITY_NETWORK_OUTBOUND_PY",
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
        "#
    ));
    js_ts_rules!(
        rules,
        "CAPABILITY_NETWORK_OUTBOUND",
        FindingType::NetworkAccess,
        Risk::Low,
        Confidence::High,
        "The code can issue HTTP requests or DNS lookups.",
        LIMIT_ACCESS,
        r#"
        (call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
          (#match? @module "^(axios|http|https|dns)$")
          (#match? @method "^(get|post|put|delete|patch|request|lookup|resolve|resolve4|resolve6|resolveMx|resolveTxt|resolveNs|resolveCname|resolveSrv|resolvePtr|resolveSoa|resolveNaptr)$")) @match
        "#
    );

    // Capability: network tools launched through a process API. Composition remains within one call.
    rules.push(rule!(
        "GD_CAPABILITY_NETWORK_LOLBAS_PY",
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
    ));
    js_ts_rules!(
        rules,
        "CAPABILITY_NETWORK_LOLBAS",
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
        "GD_CAPABILITY_PROCESS_SCHEDULE_PY",
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
    ));
    js_ts_rules!(
        rules,
        "CAPABILITY_PROCESS_SCHEDULE",
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
    rules.push(rule!(
        "GD_CAPABILITY_PROCESS_SPAWN_PY",
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
    ));
    js_ts_rules!(
        rules,
        "CAPABILITY_PROCESS_SPAWN",
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
        (new_expression constructor: (identifier) @callee (#eq? @callee "Function")) @match
        "#
    );

    // Capability: clipboard access.
    rules.push(rule!(
        "GD_CAPABILITY_RUNTIME_CLIPBOARD_PY",
        Language::Python,
        FindingType::SecretAccess,
        Risk::Low,
        Confidence::High,
        "The code reads from or writes to the system clipboard.",
        LIMIT_ACCESS,
        r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
          (#match? @module "^(pyperclip|pandas|root)$")
          (#match? @method "^(paste|copy|read_clipboard|clipboard_get)$")) @match"#
    ));
    js_ts_rules!(
        rules,
        "CAPABILITY_RUNTIME_CLIPBOARD",
        FindingType::SecretAccess,
        Risk::Low,
        Confidence::High,
        "The code reads from or writes to the system clipboard.",
        LIMIT_ACCESS,
        r#"(call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
          (#match? @module "^(clipboardy|clipboard)$")
          (#match? @method "^(read|readSync|write|writeSync|readText)$")) @match"#
    );

    rules
}

fn threat_rules() -> Vec<Rule> {
    let mut rules = Vec::new();

    // Threat: writes to autostart locations. The path and write operation are in one call.
    rules.push(rule!(
        "GD_THREAT_FILESYSTEM_AUTOSTART_PY",
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
    ));
    js_ts_rules!(
        rules,
        "THREAT_FILESYSTEM_AUTOSTART",
        FindingType::FilesystemAccess,
        Risk::High,
        Confidence::High,
        "The code writes directly to a shell, desktop, service, or registry autostart location.",
        "Remove package-controlled persistence and require users to configure startup behavior explicitly.",
        r#"(call_expression function: (member_expression object: (identifier) @module property: (property_identifier) @method)
          arguments: (arguments (string) @path . (_)* )
          (#eq? @module "fs") (#match? @method "^(writeFile|writeFileSync|appendFile|appendFileSync)$")
          (#match? @path "(?i)(\\.bashrc|\\.bash_profile|\\.profile|\\.zshrc|/etc/rc\\.local|/etc/init\\.d/|/etc/profile\\.d/|\\.config/autostart/|LaunchAgents|LaunchDaemons|CurrentVersion\\\\Run|Start Menu\\\\Programs\\\\Startup)")) @match"#
    );

    // Threat: destructive deletion of absolute roots or explicit wipe commands.
    rules.push(rule!(
        "GD_THREAT_FILESYSTEM_DESTRUCTION_PY",
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
    ));
    js_ts_rules!(
        rules,
        "THREAT_FILESYSTEM_DESTRUCTION",
        FindingType::FilesystemAccess,
        Risk::High,
        Confidence::High,
        "A recursive deletion or shell wipe targets an absolute or user-rooted path.",
        "Remove destructive package behavior and constrain deletion to a package-owned temporary directory.",
        r#"
        (call_expression function: [(identifier) @callee (member_expression property: (property_identifier) @callee)]
          arguments: (arguments (string) @path . (_)* )
          (#match? @callee "^(rimraf|rm|rmSync)$")
          (#match? @path "^['\"](~|/(home|Users)?(/|['\"]))")) @match
        (call_expression function: [(identifier) @callee (member_expression property: (property_identifier) @callee)]
          arguments: (arguments [(string) @command (template_string) @command] . (_)* )
          (#match? @callee "^(exec|execSync|spawn|spawnSync)$")
          (#match? @command "(?i)(rm[[:space:]]+-rf[[:space:]]+/|dd[[:space:]]+if=/dev/(zero|urandom)|shred[[:space:]]+-)")) @match
        "#
    );

    // Threat: constructed hostnames passed directly to DNS resolution.
    rules.push(rule!(
        "GD_THREAT_NETWORK_DNS_EXFIL_PY",
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
    ));

    // Threat: hardcoded messenger credentials and webhook endpoints.
    rules.push(rule!(
        "GD_THREAT_NETWORK_EXFIL_MESSENGER_PY",
        Language::Python,
        FindingType::NetworkAccess,
        Risk::High,
        Confidence::High,
        "A hardcoded Telegram credential/API endpoint or Discord webhook/token appears in a string literal.",
        "Remove the credential or webhook, rotate it, and use an approved secret-backed destination.",
        r#"((string) @match (#match? @match "(api\\.telegram\\.org/bot[0-9]+:|discord(app)?\\.com/api/webhooks/[0-9]+/|[0-9]{8,12}:[A-Za-z0-9_-]{30,40}|[A-Za-z0-9]{24,28}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27,})"))"#
    ));
    js_ts_rules!(
        rules,
        "THREAT_NETWORK_EXFIL_MESSENGER",
        FindingType::NetworkAccess,
        Risk::High,
        Confidence::High,
        "A hardcoded Telegram credential/API endpoint or Discord webhook/token appears in a string literal.",
        "Remove the credential or webhook, rotate it, and use an approved secret-backed destination.",
        r#"((string) @match (#match? @match "(api\\.telegram\\.org/bot[0-9]+:|discord(app)?\\.com/api/webhooks/[0-9]+/|[0-9]{8,12}:[A-Za-z0-9_-]{30,40}|[A-Za-z0-9]{24,28}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27,})"))"#
    );

    // Threat: suspicious fixed network destinations.
    rules.push(rule!(
        "GD_THREAT_NETWORK_OUTBOUND_SHADY_LINKS_PY",
        Language::Python,
        FindingType::NetworkAccess,
        Risk::Medium,
        Confidence::High,
        "A string literal contains a URL shortener, tunnel, webhook, paste, transfer, or external-IP service associated with payload delivery or exfiltration.",
        "Replace the destination with a documented, allowlisted service and verify why package code contacts it.",
        r#"((string) @match (#match? @match "(?i)(bit\\.ly|appdomain\\.cloud|ngrok\\.(io|app|dev)|termbin\\.com|localhost\\.run|webhook\\.(site|cool)|oast(ify)?\\.(com|pro|live|site|online|fun|me)|trycloudflare\\.com|pipedream\\.net|dnslog\\.cn|beeceptor\\.com|discord\\.com/api/webhooks|transfer\\.sh|filetransfer\\.io|paste(bin|\\.ee)|api\\.telegram\\.org|ipinfo\\.io|ipify\\.org|ifconfig\\.me|files\\.catbox\\.moe)"))"#
    ));
    js_ts_rules!(
        rules,
        "THREAT_NETWORK_OUTBOUND_SHADY_LINKS",
        FindingType::NetworkAccess,
        Risk::Medium,
        Confidence::High,
        "A string literal contains a URL shortener, tunnel, webhook, paste, transfer, or external-IP service associated with payload delivery or exfiltration.",
        "Replace the destination with a documented, allowlisted service and verify why package code contacts it.",
        r#"((string) @match (#match? @match "(?i)(bit\\.ly|appdomain\\.cloud|ngrok\\.(io|app|dev)|termbin\\.com|localhost\\.run|webhook\\.(site|cool)|oast(ify)?\\.(com|pro|live|site|online|fun|me)|trycloudflare\\.com|pipedream\\.net|dnslog\\.cn|beeceptor\\.com|discord\\.com/api/webhooks|transfer\\.sh|filetransfer\\.io|paste(bin|\\.ee)|api\\.telegram\\.org|ipinfo\\.io|ipify\\.org|ifconfig\\.me|files\\.catbox\\.moe)"))"#
    );

    // Threat: direct reverse-shell commands passed to process APIs.
    rules.push(rule!(
        "GD_THREAT_NETWORK_REVERSE_SHELL_PY",
        Language::Python,
        FindingType::NetworkAccess,
        Risk::Critical,
        Confidence::High,
        "A process API receives a literal reverse-shell command.",
        "Remove the remote shell behavior and investigate the package as potentially compromised.",
        r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
          arguments: (argument_list [(string) @command (list (string) @command)] . (_)* )
          (#match? @module "^(os|subprocess)$")
          (#match? @method "^(system|popen|run|call|Popen)$")
          (#match? @command "(?i)(/dev/(tcp|udp)/|(^|[^A-Za-z])(nc|ncat)[[:space:]].*-e[[:space:]]+/bin/(ba)?sh|bash[[:space:]]+-i)")) @match"#
    ));
    js_ts_rules!(
        rules,
        "THREAT_NETWORK_REVERSE_SHELL",
        FindingType::NetworkAccess,
        Risk::Critical,
        Confidence::High,
        "A process API receives a literal reverse-shell command.",
        "Remove the remote shell behavior and investigate the package as potentially compromised.",
        r#"(call_expression function: [(identifier) @callee (member_expression property: (property_identifier) @callee)]
          arguments: (arguments [(string) @command (template_string) @command] . (_)* )
          (#match? @callee "^(exec|execSync|spawn|spawnSync)$")
          (#match? @command "(?i)(/dev/(tcp|udp)/|(^|[^A-Za-z])(nc|ncat)[[:space:]].*-e[[:space:]]+/bin/(ba)?sh|bash[[:space:]]+-i)")) @match"#
    );

    // Threat: cryptocurrency miners, pools, protocols, and wallet literals.
    rules.push(rule!(
        "GD_THREAT_PROCESS_CRYPTOMINING_PY",
        Language::Python,
        FindingType::ProcessExecution,
        Risk::High,
        Confidence::High,
        "A string literal names mining software, a mining pool/protocol, or a Monero wallet.",
        "Remove unauthorized mining behavior and investigate the package provenance.",
        r#"((string) @match (#match? @match "(?i)(xmrig|ethminer|cgminer|bfgminer|cpuminer|ccminer|supportxmr\\.com|minexmr\\.com|nanopool\\.org|stratum\\+(tcp|ssl)://|[^1-9A-HJ-NP-Za-km-z]4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}[^1-9A-HJ-NP-Za-km-z])"))"#
    ));
    js_ts_rules!(
        rules,
        "THREAT_PROCESS_CRYPTOMINING",
        FindingType::ProcessExecution,
        Risk::High,
        Confidence::High,
        "A string literal names mining software, a mining pool/protocol, or a Monero wallet.",
        "Remove unauthorized mining behavior and investigate the package provenance.",
        r#"((string) @match (#match? @match "(?i)(xmrig|ethminer|cgminer|bfgminer|cpuminer|ccminer|supportxmr\\.com|minexmr\\.com|nanopool\\.org|stratum\\+(tcp|ssl)://|[^1-9A-HJ-NP-Za-km-z]4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}[^1-9A-HJ-NP-Za-km-z])"))"#
    );

    // Threat: download/installation commands executed directly, plus Python's execute-opened-file chain.
    rules.push(rule!(
        "GD_THREAT_PROCESS_DOWNLOAD_EXEC_PY",
        Language::Python,
        FindingType::ProcessExecution,
        Risk::High,
        Confidence::High,
        "A process API directly executes a downloader, package installer, or download-and-shell command.",
        REMOVE_EXECUTION,
        r#"
        (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
          arguments: (argument_list [(string) @command (list) @command] . (_)* )
          (#match? @module "^(os|subprocess)$")
          (#match? @method "^(system|popen|run|call|check_call|Popen)$")
          (#match? @command "(?i)(curl([^A-Za-z0-9_]|$)|wget([^A-Za-z0-9_]|$)|pip[[:space:]]+install|powershell(\\.exe)?.*(Invoke-WebRequest|iwr|Start-BitsTransfer|Download(String|File)|IEX|Invoke-Expression|Install-(Package|Module|Script))|curl[^\"']*\\|[[:space:]]*(bash|sh|python|node)|wget[^\"']*-O[[:space:]]+-[^\"']*\\|)")) @match
        (call function: (identifier) @exec arguments: (argument_list
          (call function: (identifier) @compile arguments: (argument_list
            (call function: (identifier) @open))))
          (#eq? @exec "exec") (#eq? @compile "compile") (#eq? @open "open")) @match
        "#
    ));
    js_ts_rules!(
        rules,
        "THREAT_PROCESS_DOWNLOAD_EXEC",
        FindingType::ProcessExecution,
        Risk::High,
        Confidence::High,
        "A process API directly executes a downloader, package installer, or download-and-shell command.",
        REMOVE_EXECUTION,
        r#"(call_expression function: [(identifier) @callee (member_expression property: (property_identifier) @callee)]
          arguments: (arguments [(string) @command (template_string) @command (array (string) @command)] . (_)* )
          (#match? @callee "^(exec|execSync|execFile|execFileSync|spawn|spawnSync)$")
          (#match? @command "(?i)((curl|wget|powershell)([^A-Za-z0-9_]|$)|npm[[:space:]]+install|curl[^\"']*\\|[[:space:]]*(bash|sh|python|node)|wget[^\"']*-O[[:space:]]+-[^\"']*\\|)")) @match"#
    );

    // Threat: encoded or hidden PowerShell passed directly to process execution.
    rules.push(rule!(
        "GD_THREAT_PROCESS_POWERSHELL_ENCODED_PY",
        Language::Python,
        FindingType::ProcessExecution,
        Risk::Critical,
        Confidence::High,
        "A process API receives an encoded, hidden, or download-cradle PowerShell command.",
        "Remove the PowerShell payload and investigate the package as potentially compromised.",
        r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method)
          arguments: (argument_list [(string) @command (list (string) @command)] . (_)* )
          (#match? @module "^(os|subprocess)$")
          (#match? @method "^(system|popen|run|call|Popen)$")
          (#match? @command "(?i)(powershell.*-(EncodedCommand|enc)[[:space:]]+[A-Za-z0-9+/=]{20,}|powershell.*-WindowStyle[[:space:]]+Hidden|Download(String|File)|Invoke-WebRequest|IEX[[:space:]]*\\()")) @match"#
    ));
    js_ts_rules!(
        rules,
        "THREAT_PROCESS_POWERSHELL_ENCODED",
        FindingType::ProcessExecution,
        Risk::Critical,
        Confidence::High,
        "A process API receives an encoded, hidden, or download-cradle PowerShell command.",
        "Remove the PowerShell payload and investigate the package as potentially compromised.",
        r#"(call_expression function: [(identifier) @callee (member_expression property: (property_identifier) @callee)]
          arguments: (arguments [(string) @command (template_string) @command (array (string) @command)] . (_)* )
          (#match? @callee "^(exec|execSync|execFile|execFileSync|spawn|spawnSync)$")
          (#match? @command "(?i)(powershell.*-(EncodedCommand|enc)[[:space:]]+[A-Za-z0-9+/=]{20,}|powershell.*-WindowStyle[[:space:]]+Hidden|Download(String|File)|Invoke-WebRequest|IEX[[:space:]]*\\()")) @match"#
    );

    // Threat: decoded data is passed directly to an execution sink.
    rules.push(rule!(
        "GD_THREAT_RUNTIME_OBFUSCATION_BASE64EXEC_PY",
        Language::Python,
        FindingType::ArbitraryCodeExecution,
        Risk::High,
        Confidence::High,
        "Base64-decoded data is passed directly to exec or eval.",
        REVIEW_OBFUSCATION,
        r#"(call function: (identifier) @sink arguments: (argument_list
          (call function: (attribute object: (identifier) @codec attribute: (identifier) @decoder)))
          (#match? @sink "^(exec|eval)$") (#eq? @codec "base64")
          (#match? @decoder "^(b64decode|decodebytes|standard_b64decode)$")) @match"#
    ));
    js_ts_rules!(
        rules,
        "THREAT_RUNTIME_OBFUSCATION_BASE64EXEC",
        FindingType::ArbitraryCodeExecution,
        Risk::High,
        Confidence::High,
        "Base64-decoded data is passed directly to eval or the Function constructor.",
        REVIEW_OBFUSCATION,
        r#"
        ((call_expression function: (identifier) @sink arguments: (arguments
          (call_expression function: (identifier) @decoder))) @match
          (#eq? @sink "eval") (#eq? @decoder "atob"))
        ((new_expression constructor: (identifier) @sink arguments: (arguments
          (call_expression function: (identifier) @decoder))) @match
          (#eq? @sink "Function") (#eq? @decoder "atob"))
        ((call_expression function: (identifier) @sink arguments: (arguments
          (call_expression function: (member_expression object: (identifier) @buffer property: (property_identifier) @from)
            arguments: (arguments (_) (string) @encoding)))) @match
          (#eq? @sink "eval") (#eq? @buffer "Buffer") (#eq? @from "from")
          (#match? @encoding "['\"]base64['\"]"))
        ((new_expression constructor: (identifier) @sink arguments: (arguments
          (call_expression function: (member_expression object: (identifier) @buffer property: (property_identifier) @from)
            arguments: (arguments (_) (string) @encoding)))) @match
          (#eq? @sink "Function") (#eq? @buffer "Buffer") (#eq? @from "from")
          (#match? @encoding "['\"]base64['\"]"))
        "#
    );

    // Threat: dynamic import/decompression chains nested directly under exec.
    rules.push(rule!(
        "GD_THREAT_RUNTIME_OBFUSCATION_IMPORT_EXEC_PY",
        Language::Python,
        FindingType::ArbitraryCodeExecution,
        Risk::High,
        Confidence::High,
        "A dynamic import or serialized payload loader is nested directly inside exec.",
        REVIEW_OBFUSCATION,
        r#"
        ((call function: (identifier) @sink arguments: (argument_list
          (call function: (identifier) @loader))) @match
          (#eq? @sink "exec") (#eq? @loader "__import__"))
        ((call function: (identifier) @sink arguments: (argument_list
          (call function: (attribute object: (identifier) @module attribute: (identifier) @loader)))) @match
          (#eq? @sink "exec") (#eq? @module "marshal") (#eq? @loader "loads"))
        (call function: (attribute object: (call function: (identifier) @import arguments: (argument_list (string) @module)) attribute: (identifier) @sink)
          (#eq? @import "__import__") (#match? @module "['\"]builtins['\"]") (#eq? @sink "exec")) @match
        "#
    ));

    // Threat: reflective resolution immediately invokes a dangerous or hidden API.
    rules.push(rule!(
        "GD_THREAT_RUNTIME_OBFUSCATION_API_PY",
        Language::Python,
        FindingType::ArbitraryCodeExecution,
        Risk::High,
        Confidence::High,
        "A dangerous builtin is resolved through getattr and invoked immediately.",
        REVIEW_OBFUSCATION,
        r#"((call function: (call function: (identifier) @getattr
          arguments: (argument_list (_) (string) @name))) @match
          (#eq? @getattr "getattr")
          (#match? @name "['\"](__import__|exec|eval|compile)['\"]"))"#
    ));
    js_ts_rules!(
        rules,
        "THREAT_RUNTIME_OBFUSCATION_API",
        FindingType::ArbitraryCodeExecution,
        Risk::High,
        Confidence::High,
        "A property descriptor is resolved reflectively and its value is invoked immediately.",
        REVIEW_OBFUSCATION,
        r#"((call_expression function: (member_expression
          object: (call_expression function: (member_expression object: (identifier) @object property: (property_identifier) @resolver))
          property: (property_identifier) @value)) @match
          (#eq? @object "Object") (#eq? @resolver "getOwnPropertyDescriptor") (#eq? @value "value"))"#
    );

    // Threat: require is hidden behind a short computed global property.
    js_ts_rules!(
        rules,
        "THREAT_RUNTIME_OBFUSCATION_HIDDEN_CODE",
        FindingType::DynamicLoading,
        Risk::High,
        Confidence::High,
        "The require function is aliased through a computed global property, hiding subsequent module loads.",
        "Use direct static imports or fixed require calls and remove the global alias.",
        r#"(assignment_expression
          left: (subscript_expression object: (identifier) @global index: (string) @alias)
          right: (identifier) @require
          (#eq? @global "global") (#eq? @require "require")
          (#match? @alias "^['\"][A-Za-z0-9_$]{1,6}['\"]$")) @match"#
    );

    // Threat: PyArmor runtime/bootstrap syntax.
    rules.push(rule!(
        "GD_THREAT_RUNTIME_OBFUSCATION_PYARMOR_PY",
        Language::Python,
        FindingType::CodeObfuscation,
        Risk::Medium,
        Confidence::High,
        "The code invokes a PyArmor bootstrap/runtime or verification function.",
        "Require unobfuscated source for review or verify the PyArmor-protected artifact and its publisher independently.",
        r#"(call function: (identifier) @callee
          (#match? @callee "^(__pyarmor__|pyarmor_runtime|check_armored|assert_armored)$")) @match"#
    ));

    // Threat: screenshot capture APIs.
    rules.push(rule!(
        "GD_THREAT_RUNTIME_SCREENCAPTURE_PY",
        Language::Python,
        FindingType::SecretAccess,
        Risk::Medium,
        Confidence::High,
        "The code invokes a screen-capture API that can collect sensitive user content.",
        "Remove screen capture from package code or require explicit, visible user consent and local-only handling.",
        r#"
        (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
          (#match? @module "^(ImageGrab|pyscreenshot|pyautogui)$")
          (#match? @method "^(grab|screenshot)$")) @match
        (call function: (attribute object: (attribute object: (identifier) @pil attribute: (identifier) @imagegrab) attribute: (identifier) @method)
          (#eq? @pil "PIL") (#eq? @imagegrab "ImageGrab") (#eq? @method "grab")) @match
        "#
    ));

    // Threat: credential-like environment variables and whole-environment serialization.
    rules.push(rule!(
        "GD_THREAT_RUNTIME_ENVIRONMENT_READ_PY",
        Language::Python,
        FindingType::SecretAccess,
        Risk::Medium,
        Confidence::High,
        "The code reads a credential-like environment variable.",
        "Read only the required named setting, avoid logging or transmitting it, and use scoped credentials.",
        r#"
        (call function: (attribute object: (identifier) @module attribute: (identifier) @method)
          arguments: (argument_list (string) @name . (_)* )
          (#eq? @module "os") (#eq? @method "getenv")
          (#match? @name "(?i)(API_?KEY|SECRET|TOKEN|PASS(WORD)?|AUTH|CREDENTIAL|CRED)")) @match
        (subscript value: (attribute object: (identifier) @module attribute: (identifier) @env) subscript: (string) @name
          (#eq? @module "os") (#eq? @env "environ")
          (#match? @name "(?i)(API_?KEY|SECRET|TOKEN|PASS(WORD)?|AUTH|CREDENTIAL|CRED)")) @match
        "#
    ));
    js_ts_rules!(
        rules,
        "THREAT_RUNTIME_ENVIRONMENT_READ",
        FindingType::SecretAccess,
        Risk::Medium,
        Confidence::High,
        "The code reads a credential-like environment variable or serializes the entire environment.",
        "Read only the required named setting, avoid logging or transmitting it, and use scoped credentials.",
        r#"
        (subscript_expression object: (member_expression object: (identifier) @process property: (property_identifier) @env)
          index: (string) @name
          (#eq? @process "process") (#eq? @env "env")
          (#match? @name "(?i)(API_?KEY|SECRET|TOKEN|PASS(WORD)?|AUTH|CREDENTIAL|CRED)")) @match
        (call_expression function: (member_expression object: (identifier) @json property: (property_identifier) @stringify)
          arguments: (arguments (member_expression object: (identifier) @process property: (property_identifier) @env))
          (#eq? @json "JSON") (#eq? @stringify "stringify")
          (#eq? @process "process") (#eq? @env "env")) @match
        "#
    );

    rules
}
