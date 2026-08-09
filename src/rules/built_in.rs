use crate::model::{Confidence, FindingType, Language, Risk, Rule};

const EXECUTION_RATIONALE: &str = "Runtime code or process execution can execute attacker-controlled payloads during package use.";
const EXECUTION_REMEDIATION: &str =
    "Remove dynamic execution or constrain input to a fixed, validated allowlist.";
const ACCESS_REMEDIATION: &str =
    "Confirm the access is necessary and constrain destinations, paths, and data.";
const REMOVE_EXECUTION: &str = "Remove runtime execution, or replace it with a fixed command or operation over validated input.";
const REVIEW_OBFUSCATION: &str =
    "Remove the obfuscation and review the decoded or dynamically resolved behavior before use.";

pub fn built_in_rules() -> Vec<Rule> {
    let mut rules = vec![
        rule!(
            "chainsec.py.detection.dynamic-code-execution",
            Language::Python,
            FindingType::ArbitraryCodeExecution,
            Risk::High,
            Confidence::High,
            EXECUTION_RATIONALE,
            EXECUTION_REMEDIATION,
            r#"(call function: (identifier) @callee (#match? @callee "^(eval|exec|compile)$")) @match"#
        ),
        rule!(
            "chainsec.py.detection.decoded-payload",
            Language::Python,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::Medium,
            "Decoded payloads may conceal executable or exfiltrated data.",
            "Inspect decoded content and avoid executing data obtained at runtime.",
            r#"(call function: (attribute attribute: (identifier) @method (#match? @method "^(b64decode|decodebytes)$"))) @match"#
        ),
        rule!(
            "chainsec.py.detection.process-spawn",
            Language::Python,
            FindingType::ProcessExecution,
            Risk::High,
            Confidence::High,
            EXECUTION_RATIONALE,
            EXECUTION_REMEDIATION,
            r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method) (#match? @module "^(os|subprocess)$") (#match? @method "^(system|popen|run|call|check_call|check_output|Popen)$")) @match"#
        ),
        rule!(
            "chainsec.py.detection.network-request",
            Language::Python,
            FindingType::NetworkAccess,
            Risk::Medium,
            Confidence::Medium,
            "Network calls can download payloads or exfiltrate local data.",
            ACCESS_REMEDIATION,
            r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method) (#match? @module "^(requests|urllib|httpx|socket)$")) @match"#
        ),
        rule!(
            "chainsec.py.detection.filesystem-open",
            Language::Python,
            FindingType::FilesystemAccess,
            Risk::Medium,
            Confidence::Medium,
            "Filesystem access can read credentials or modify user state.",
            ACCESS_REMEDIATION,
            r#"(call function: (identifier) @callee (#eq? @callee "open")) @match"#
        ),
        rule!(
            "chainsec.py.detection.unsafe-deserialization",
            Language::Python,
            FindingType::Deserialization,
            Risk::High,
            Confidence::High,
            "Unsafe deserialization can instantiate attacker-controlled objects.",
            "Use a safe data format such as JSON and validate its schema.",
            r#"(call function: (attribute object: (identifier) @module attribute: (identifier) @method) (#match? @module "^(pickle|yaml)$") (#match? @method "^(loads?|load)$")) @match"#
        ),
        rule!(
            "chainsec.py.detection.character-assembly",
            Language::Python,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::High,
            "A long character sequence or character codes are joined into a runtime string, a common way to conceal a payload or API name.",
            "Replace runtime character assembly with reviewed plain text, or document and validate the generated value.",
            r#"
            (call function: (attribute object: (string) @separator attribute: (identifier) @join)) @match
            (#eq? @join "join")
            (#match? @separator "^['\"]{2}$")
            (#match? @match "(?s)((chr|ord)\\s*\\(|\\.join\\s*\\(\\s*\\[(?:[^\\]]*,){7,})")
            "#
        ),
        rule!(
            "chainsec.py.detection.encoded-escapes",
            Language::Python,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::High,
            "A string literal or concatenation contains a long sequence of hexadecimal, octal, or Unicode escape codes.",
            "Replace encoded literals with reviewed plain text, or document the encoding and validate the decoded value.",
            r#"
            ((string) @match
              (#match? @match "(?i)(?:\\\\x[0-9a-f]{2}|\\\\[0-7]{3}|\\\\u[0-9a-f]{4}|\\\\U[0-9a-f]{8}){16,}"))
            ((binary_operator left: (string) @left right: (string) @right) @match
              (#match? @left "(?i)(?:\\\\x[0-9a-f]{2}|\\\\[0-7]{3}|\\\\u[0-9a-f]{4}|\\\\U[0-9a-f]{8}){8,}")
              (#match? @right "(?i)(?:\\\\x[0-9a-f]{2}|\\\\[0-7]{3}|\\\\u[0-9a-f]{4}|\\\\U[0-9a-f]{8}){8,}"))
            "#
        ),
        rule!(
            "chainsec.py.detection.ambiguous-identifier",
            Language::Python,
            FindingType::CodeObfuscation,
            Risk::Low,
            Confidence::Medium,
            "An identifier resembles a generated hexadecimal name or a visually ambiguous character sequence.",
            "Rename generated or ambiguous identifiers to descriptive names before reviewing or publishing the code.",
            r#"((identifier) @match (#match? @match "(?i)^_?0x[0-9a-f]{4,}$|^[o0il1]{6,}$"))"#
        ),
        rule!(
            "chainsec.py.detection.reflective-namespace",
            Language::Python,
            FindingType::DynamicLoading,
            Risk::Medium,
            Confidence::High,
            "Reflective namespace properties can expose import capabilities or bypass ordinary module-import review.",
            "Use explicit imports and avoid traversing runtime globals, builtins, loaders, or module specifications.",
            r#"
            ((attribute object: (_) attribute: (identifier) @property) @match
              (#match? @property "^(__globals__|__builtins__|__import__|__loader__|__spec__|func_globals)$"))
            ((call function: (identifier) @function
              arguments: (argument_list (_) (string) @property)) @match
              (#match? @function "^(getattr|setattr)$")
              (#match? @property "^['\"](__globals__|__builtins__|__import__|__loader__|__spec__|func_globals)['\"]$"))
            "#
        ),
        rule!(
            "chainsec.js.detection.dynamic-code-execution",
            Language::JavaScript,
            FindingType::ArbitraryCodeExecution,
            Risk::High,
            Confidence::High,
            EXECUTION_RATIONALE,
            EXECUTION_REMEDIATION,
            r#"(call_expression function: (identifier) @callee (#match? @callee "^(eval|Function)$")) @match"#
        ),
        rule!(
            "chainsec.js.detection.decoded-payload",
            Language::JavaScript,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::Medium,
            "Decoded payloads may conceal executable or exfiltrated data.",
            "Inspect decoded content and avoid executing data obtained at runtime.",
            r#"
            ((call_expression function: (member_expression property: (property_identifier) @method)
              arguments: (arguments (number) (number) . (_)*)) @match
              (#eq? @method "fromCharCode"))
            ((call_expression function: (member_expression property: (property_identifier) @method)) @match
              (#eq? @method "atob"))
            ((call_expression function: (identifier) @callee) @match
              (#eq? @callee "atob"))
            "#
        ),
        rule!(
            "chainsec.js.detection.process-spawn",
            Language::JavaScript,
            FindingType::ProcessExecution,
            Risk::High,
            Confidence::High,
            EXECUTION_RATIONALE,
            EXECUTION_REMEDIATION,
            r#"
            (call_expression function: (identifier) @callee (#match? @callee "^(exec|execFile|spawn|fork)$")) @match
            (call_expression function: (member_expression object: (new_expression constructor: (member_expression object: (identifier) @deno property: (property_identifier) @command)) property: (property_identifier) @method)
              (#eq? @deno "Deno") (#eq? @command "Command")
              (#match? @method "^(spawn|output|outputSync)$")) @match
            "#
        ),
        rule!(
            "chainsec.js.detection.network-request",
            Language::JavaScript,
            FindingType::NetworkAccess,
            Risk::Medium,
            Confidence::Medium,
            "Network calls can download payloads, expose a server, or exfiltrate local data.",
            ACCESS_REMEDIATION,
            r#"
            (call_expression function: (identifier) @callee (#eq? @callee "fetch")) @match
            (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
              (#eq? @deno "Deno")
              (#match? @method "^(http|serve|serveHttp|listen|listenTls|connect|connectTls|createHttpClient|resolveDns|upgradeWebSocket)$")) @match
            "#
        ),
        rule!(
            "chainsec.js.detection.read-environment",
            Language::JavaScript,
            FindingType::SecretAccess,
            Risk::Medium,
            Confidence::High,
            "The code reads a credential-like environment variable or serializes the entire environment, which can expose inherited secrets.",
            "Read only required named settings, avoid logging or transmitting them, and use scoped credentials.",
            r#"
            (member_expression object: (member_expression object: (identifier) @process property: (property_identifier) @env) property: (property_identifier) @name
              (#eq? @process "process") (#eq? @env "env")
              (#match? @name "(?i)(API_?KEY|SECRET|TOKEN|PASS(WORD)?|AUTH|CREDENTIAL|CRED)")) @match
            (subscript_expression object: (member_expression object: (identifier) @process property: (property_identifier) @env)
              index: (string) @name
              (#eq? @process "process") (#eq? @env "env")
              (#match? @name "(?i)(API_?KEY|SECRET|TOKEN|PASS(WORD)?|AUTH|CREDENTIAL|CRED)")) @match
            (call_expression function: (member_expression object: (identifier) @json property: (property_identifier) @stringify)
              arguments: (arguments (member_expression object: (identifier) @process property: (property_identifier) @env))
              (#eq? @json "JSON") (#eq? @stringify "stringify")
              (#eq? @process "process") (#eq? @env "env")) @match
            (call_expression function: (member_expression object: (member_expression object: (identifier) @deno property: (property_identifier) @env) property: (property_identifier) @method)
              arguments: (arguments (string) @name . (_)* )
              (#eq? @deno "Deno") (#eq? @env "env") (#eq? @method "get")
              (#match? @name "(?i)(API_?KEY|SECRET|TOKEN|PASS(WORD)?|AUTH|CREDENTIAL|CRED)")) @match
            "#
        ),
        rule!(
            "chainsec.js.detection.dynamic-require",
            Language::JavaScript,
            FindingType::DynamicLoading,
            Risk::Medium,
            Confidence::Medium,
            "Dynamic module loading can hide code paths from static review.",
            "Prefer static imports and fixed module specifiers.",
            r#"(call_expression function: (identifier) @callee (#eq? @callee "require") arguments: (arguments (_) @argument) (#not-match? @argument "^['\"]")) @match"#
        ),
        rule!(
            "chainsec.js.detection.character-code-assembly",
            Language::JavaScript,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::High,
            "An array is mapped through String.fromCharCode and joined into a runtime string, concealing its contents.",
            "Replace runtime character assembly with reviewed plain text, or document and validate the generated value.",
            r#"
            (call_expression function: (member_expression
              object: (call_expression function: (member_expression object: (array) @array property: (property_identifier) @map)
                arguments: (arguments (_)))
              property: (property_identifier) @join)
              arguments: (arguments)) @match
            (#eq? @map "map") (#eq? @join "join")
            (#match? @array "(?s)(?:[^,\\]]*,){7,}")
            (#match? @match "(?s)String\\s*\\.\\s*fromCharCode")
            "#
        ),
        rule!(
            "chainsec.js.detection.encoded-escapes",
            Language::JavaScript,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::High,
            "A string literal or concatenation contains a long sequence of hexadecimal, octal, or Unicode escape codes.",
            "Replace encoded literals with reviewed plain text, or document the encoding and validate the decoded value.",
            r#"
            ((string) @match
              (#match? @match "(?i)(?:\\\\x[0-9a-f]{2}|\\\\[0-7]{3}|\\\\u[0-9a-f]{4}|\\\\U[0-9a-f]{8}){16,}"))
            ((binary_expression left: (string) @left right: (string) @right) @match
              (#match? @left "(?i)(?:\\\\x[0-9a-f]{2}|\\\\[0-7]{3}|\\\\u[0-9a-f]{4}|\\\\U[0-9a-f]{8}){8,}")
              (#match? @right "(?i)(?:\\\\x[0-9a-f]{2}|\\\\[0-7]{3}|\\\\u[0-9a-f]{4}|\\\\U[0-9a-f]{8}){8,}"))
            "#
        ),
        rule!(
            "chainsec.js.detection.ambiguous-identifier",
            Language::JavaScript,
            FindingType::CodeObfuscation,
            Risk::Low,
            Confidence::Medium,
            "An identifier resembles a generated hexadecimal name or a visually ambiguous character sequence.",
            "Rename generated or ambiguous identifiers to descriptive names before reviewing or publishing the code.",
            r#"((identifier) @match (#match? @match "(?i)^_?0x[0-9a-f]{4,}$|^[o0il1]{6,}$|^(?:\\\\u[0-9a-f]{4}){2,}$"))"#
        ),
        rule!(
            "chainsec.js.detection.write-browser-global",
            Language::JavaScript,
            FindingType::DynamicLoading,
            Risk::Medium,
            Confidence::High,
            "A value is written to the browser window object, creating or replacing global runtime state.",
            "Avoid package-controlled global writes; keep state module-local or require an explicit integration API.",
            r#"
            ((assignment_expression left: (member_expression object: (identifier) @window)) @match
              (#eq? @window "window"))
            ((assignment_expression left: (subscript_expression object: (identifier) @window)) @match
              (#eq? @window "window"))
            "#
        ),
        rule!(
            "chainsec.ts.detection.dynamic-code-execution",
            Language::TypeScript,
            FindingType::ArbitraryCodeExecution,
            Risk::High,
            Confidence::High,
            EXECUTION_RATIONALE,
            EXECUTION_REMEDIATION,
            r#"(call_expression function: (identifier) @callee (#match? @callee "^(eval|Function)$")) @match"#
        ),
        rule!(
            "chainsec.ts.detection.decoded-payload",
            Language::TypeScript,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::Medium,
            "Decoded payloads may conceal executable or exfiltrated data.",
            "Inspect decoded content and avoid executing data obtained at runtime.",
            r#"
            ((call_expression function: (member_expression property: (property_identifier) @method)
              arguments: (arguments (number) (number) . (_)*)) @match
              (#eq? @method "fromCharCode"))
            ((call_expression function: (member_expression property: (property_identifier) @method)) @match
              (#eq? @method "atob"))
            ((call_expression function: (identifier) @callee) @match
              (#eq? @callee "atob"))
            "#
        ),
        rule!(
            "chainsec.ts.detection.process-spawn",
            Language::TypeScript,
            FindingType::ProcessExecution,
            Risk::High,
            Confidence::High,
            EXECUTION_RATIONALE,
            EXECUTION_REMEDIATION,
            r#"
            (call_expression function: (identifier) @callee (#match? @callee "^(exec|execFile|spawn|fork)$")) @match
            (call_expression function: (member_expression object: (new_expression constructor: (member_expression object: (identifier) @deno property: (property_identifier) @command)) property: (property_identifier) @method)
              (#eq? @deno "Deno") (#eq? @command "Command")
              (#match? @method "^(spawn|output|outputSync)$")) @match
            "#
        ),
        rule!(
            "chainsec.ts.detection.network-request",
            Language::TypeScript,
            FindingType::NetworkAccess,
            Risk::Medium,
            Confidence::Medium,
            "Network calls can download payloads, expose a server, or exfiltrate local data.",
            ACCESS_REMEDIATION,
            r#"
            (call_expression function: (identifier) @callee (#eq? @callee "fetch")) @match
            (call_expression function: (member_expression object: (identifier) @deno property: (property_identifier) @method)
              (#eq? @deno "Deno")
              (#match? @method "^(http|serve|serveHttp|listen|listenTls|connect|connectTls|createHttpClient|resolveDns|upgradeWebSocket)$")) @match
            "#
        ),
        rule!(
            "chainsec.ts.detection.read-environment",
            Language::TypeScript,
            FindingType::SecretAccess,
            Risk::Medium,
            Confidence::High,
            "The code reads a credential-like environment variable or serializes the entire environment, which can expose inherited secrets.",
            "Read only required named settings, avoid logging or transmitting them, and use scoped credentials.",
            r#"
            (member_expression object: (member_expression object: (identifier) @process property: (property_identifier) @env) property: (property_identifier) @name
              (#eq? @process "process") (#eq? @env "env")
              (#match? @name "(?i)(API_?KEY|SECRET|TOKEN|PASS(WORD)?|AUTH|CREDENTIAL|CRED)")) @match
            (subscript_expression object: (member_expression object: (identifier) @process property: (property_identifier) @env)
              index: (string) @name
              (#eq? @process "process") (#eq? @env "env")
              (#match? @name "(?i)(API_?KEY|SECRET|TOKEN|PASS(WORD)?|AUTH|CREDENTIAL|CRED)")) @match
            (call_expression function: (member_expression object: (identifier) @json property: (property_identifier) @stringify)
              arguments: (arguments (member_expression object: (identifier) @process property: (property_identifier) @env))
              (#eq? @json "JSON") (#eq? @stringify "stringify")
              (#eq? @process "process") (#eq? @env "env")) @match
            (call_expression function: (member_expression object: (member_expression object: (identifier) @deno property: (property_identifier) @env) property: (property_identifier) @method)
              arguments: (arguments (string) @name . (_)* )
              (#eq? @deno "Deno") (#eq? @env "env") (#eq? @method "get")
              (#match? @name "(?i)(API_?KEY|SECRET|TOKEN|PASS(WORD)?|AUTH|CREDENTIAL|CRED)")) @match
            "#
        ),
        rule!(
            "chainsec.ts.detection.dynamic-require",
            Language::TypeScript,
            FindingType::DynamicLoading,
            Risk::Medium,
            Confidence::Medium,
            "Dynamic module loading can hide code paths from static review.",
            "Prefer static imports and fixed module specifiers.",
            r#"(call_expression function: (identifier) @callee (#eq? @callee "require") arguments: (arguments (_) @argument) (#not-match? @argument "^['\"]")) @match"#
        ),
        rule!(
            "chainsec.ts.detection.character-code-assembly",
            Language::TypeScript,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::High,
            "An array is mapped through String.fromCharCode and joined into a runtime string, concealing its contents.",
            "Replace runtime character assembly with reviewed plain text, or document and validate the generated value.",
            r#"
            (call_expression function: (member_expression
              object: (call_expression function: (member_expression object: (array) @array property: (property_identifier) @map)
                arguments: (arguments (_)))
              property: (property_identifier) @join)
              arguments: (arguments)) @match
            (#eq? @map "map") (#eq? @join "join")
            (#match? @array "(?s)(?:[^,\\]]*,){7,}")
            (#match? @match "(?s)String\\s*\\.\\s*fromCharCode")
            "#
        ),
        rule!(
            "chainsec.ts.detection.encoded-escapes",
            Language::TypeScript,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::High,
            "A string literal or concatenation contains a long sequence of hexadecimal, octal, or Unicode escape codes.",
            "Replace encoded literals with reviewed plain text, or document the encoding and validate the decoded value.",
            r#"
            ((string) @match
              (#match? @match "(?i)(?:\\\\x[0-9a-f]{2}|\\\\[0-7]{3}|\\\\u[0-9a-f]{4}|\\\\U[0-9a-f]{8}){16,}"))
            ((binary_expression left: (string) @left right: (string) @right) @match
              (#match? @left "(?i)(?:\\\\x[0-9a-f]{2}|\\\\[0-7]{3}|\\\\u[0-9a-f]{4}|\\\\U[0-9a-f]{8}){8,}")
              (#match? @right "(?i)(?:\\\\x[0-9a-f]{2}|\\\\[0-7]{3}|\\\\u[0-9a-f]{4}|\\\\U[0-9a-f]{8}){8,}"))
            "#
        ),
        rule!(
            "chainsec.ts.detection.ambiguous-identifier",
            Language::TypeScript,
            FindingType::CodeObfuscation,
            Risk::Low,
            Confidence::Medium,
            "An identifier resembles a generated hexadecimal name or a visually ambiguous character sequence.",
            "Rename generated or ambiguous identifiers to descriptive names before reviewing or publishing the code.",
            r#"((identifier) @match (#match? @match "(?i)^_?0x[0-9a-f]{4,}$|^[o0il1]{6,}$|^(?:\\\\u[0-9a-f]{4}){2,}$"))"#
        ),
        rule!(
            "chainsec.ts.detection.write-browser-global",
            Language::TypeScript,
            FindingType::DynamicLoading,
            Risk::Medium,
            Confidence::High,
            "A value is written to the browser window object, creating or replacing global runtime state.",
            "Avoid package-controlled global writes; keep state module-local or require an explicit integration API.",
            r#"
            (assignment_expression left: (member_expression object: (identifier) @window)) @match
            (#eq? @window "window")
            (assignment_expression left: (subscript_expression object: (identifier) @window)) @match
            (#eq? @window "window")
            "#
        ),
    ];
    rules.extend(guarddog_rules());
    rules.extend(semantic_rules());
    rules.extend(entropy_rules());
    rules
}

fn semantic_rules() -> Vec<Rule> {
    use crate::model::SemanticRule;

    let mut rules = Vec::new();
    for (suffix, language) in [("js", Language::JavaScript), ("ts", Language::TypeScript)] {
        rules.push(semantic_rule!(
            format!("chainsec.detection.heuristic.dynamic-code-execution.{suffix}"),
            language,
            FindingType::ArbitraryCodeExecution,
            Risk::High,
            Confidence::High,
            "Indirect or string-based JavaScript execution reaches a runtime code-execution sink.",
            EXECUTION_REMEDIATION,
            SemanticRule::JsTsDynamicExecution
        ));
        rules.push(semantic_rule!(
            format!("chainsec.detection.heuristic.string-table.{suffix}"),
            language,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::High,
            "A string-table accessor structure is commonly produced by JavaScript obfuscators.",
            "Inspect the table and replace generated opaque code with reviewed source.",
            SemanticRule::JsTsStringTableObfuscation
        ));
        rules.push(semantic_rule!(
            format!("chainsec.detection.heuristic.rc4-decoder.{suffix}"),
            language,
            FindingType::CodeObfuscation,
            Risk::High,
            Confidence::Medium,
            "A 256-byte stream-cipher-like decoder reconstructs runtime strings.",
            "Inspect the decoded content and do not execute reconstructed payloads.",
            SemanticRule::JsTsRc4Decoder
        ));
        rules.push(semantic_rule!(
            format!("chainsec.detection.heuristic.embedded-vm.{suffix}"),
            language,
            FindingType::CodeObfuscation,
            Risk::High,
            Confidence::Medium,
            "Bytecode, opcode, and dispatch structures suggest an embedded virtual machine.",
            "Inspect the bytecode interpreter and recover reviewed source before use.",
            SemanticRule::JsTsVirtualMachine
        ));
        rules.push(rule!(
            format!("chainsec.detection.heuristic.control-flow-flattening.{suffix}").as_str(),
            language,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::High,
            "A loop-and-switch dispatcher resembles control-flow flattening.",
            "Review the dispatcher and restore straightforward control flow before trusting it.",
            r#"(while_statement body: (statement_block (switch_statement body: (switch_body (switch_case))))) @match"#
        ));
    }
    rules.extend([
        rule!(
            "chainsec.py.detection.heuristic.opaque-execution-input",
            Language::Python,
            FindingType::ArbitraryCodeExecution,
            Risk::High,
            Confidence::High,
            "Decoded, deserialized, or marshalled Python content reaches an execution sink.",
            EXECUTION_REMEDIATION,
            r#"
            ((call function: (identifier) @executor
              arguments: (argument_list (call function: (attribute attribute: (identifier) @decoder)))) @match
              (#match? @executor "^(eval|exec)$")
              (#match? @decoder "^(loads|b64decode|decode|decompress)$"))
            ((call function: (attribute attribute: (identifier) @constructor)
              arguments: (argument_list (call function: (attribute attribute: (identifier) @decoder)))) @match
              (#eq? @constructor "FunctionType")
              (#eq? @decoder "loads"))
            "#
        ),
        rule!(
            "chainsec.py.detection.heuristic.dynamic-module",
            Language::Python,
            FindingType::DynamicLoading,
            Risk::High,
            Confidence::High,
            "Python dynamically loads a module or changes import resolution at runtime.",
            "Use explicit, fixed imports and avoid loading code from runtime-controlled paths.",
            r#"
            ((call function: (identifier) @loader) @match (#eq? @loader "__import__"))
            ((call function: (attribute object: (identifier) @module attribute: (identifier) @method) @match
              (#eq? @module "importlib") (#eq? @method "import_module")))
            ((call function: (attribute object: (identifier) @loader attribute: (identifier) @method) @match
              (#eq? @loader "loader") (#eq? @method "exec_module")))
            "#
        ),
        rule!(
            "chainsec.py.detection.heuristic.code-protector-marker",
            Language::Python,
            FindingType::CodeObfuscation,
            Risk::Medium,
            Confidence::High,
            "Python protector or compiler bootstrap markers were found.",
            "Verify the provenance and inspect the original source where available.",
            r#"((identifier) @match (#match? @match "^(__pyarmor__|pyarmor_runtime(_[0-9]+)?|__cython__|__nuitka__)$"))"#
        ),
    ]);
    rules
}

fn entropy_rules() -> Vec<Rule> {
    [
        ("chainsec.py.detection.heuristic.high-entropy-string", Language::Python, r#"(string) @match"#),
        ("chainsec.js.detection.heuristic.high-entropy-string", Language::JavaScript, r#"(string) @match"#),
        ("chainsec.ts.detection.heuristic.high-entropy-string", Language::TypeScript, r#"(string) @match"#),
    ]
    .into_iter()
    .map(|(id, language, query)| Rule {
        entropy: Some(crate::model::EntropyMatcher {
            minimum_length: 32,
            minimum_entropy: 5.0,
            maximum_whitespace_ratio: 0.05,
        }),
        ..super::standard_rule(
            id,
            language,
            super::RuleDefinition {
                finding_type: FindingType::CodeObfuscation,
                risk: Risk::Medium,
                confidence: Confidence::Medium,
                rationale: "A string literal has unusually high Shannon entropy and may contain encrypted or packed data.",
                remediation: "Inspect and decode the value, document its origin, and avoid embedding opaque executable payloads.",
                query,
            },
        )
    })
    .collect()
}

// GuardDog-derived detection rules are independent Tree-sitter implementations.
// Credit: DataDog/guarddog, Apache-2.0; see `docs/THIRD_PARTY.md`.
fn guarddog_rules() -> Vec<Rule> {
    let mut rules = Vec::new();

    // Threat: writes to autostart locations. The path and write operation are in one call.
    rules.push(rule!(
        "chainsec.py.detection.guarddog.autostart",
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
        "chainsec.detection.guarddog.",
        "autostart",
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
        "chainsec.py.detection.guarddog.destructive-deletion",
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
        "chainsec.detection.guarddog.",
        "destructive-deletion",
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
    ));

    // Threat: hardcoded messenger credentials and webhook endpoints.
    rules.push(rule!(
        "chainsec.py.detection.guarddog.messenger-exfiltration",
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
        "chainsec.detection.guarddog.",
        "messenger-exfiltration",
        FindingType::NetworkAccess,
        Risk::High,
        Confidence::High,
        "A hardcoded Telegram credential/API endpoint or Discord webhook/token appears in a string literal.",
        "Remove the credential or webhook, rotate it, and use an approved secret-backed destination.",
        r#"((string) @match (#match? @match "(api\\.telegram\\.org/bot[0-9]+:|discord(app)?\\.com/api/webhooks/[0-9]+/|[0-9]{8,12}:[A-Za-z0-9_-]{30,40}|[A-Za-z0-9]{24,28}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27,})"))"#
    );

    // Threat: suspicious fixed network destinations.
    rules.push(rule!(
        "chainsec.py.detection.guarddog.suspicious-network-destination",
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
        "chainsec.detection.guarddog.",
        "suspicious-network-destination",
        FindingType::NetworkAccess,
        Risk::Medium,
        Confidence::High,
        "A string literal contains a URL shortener, tunnel, webhook, paste, transfer, or external-IP service associated with payload delivery or exfiltration.",
        "Replace the destination with a documented, allowlisted service and verify why package code contacts it.",
        r#"((string) @match (#match? @match "(?i)(bit\\.ly|appdomain\\.cloud|ngrok\\.(io|app|dev)|termbin\\.com|localhost\\.run|webhook\\.(site|cool)|oast(ify)?\\.(com|pro|live|site|online|fun|me)|trycloudflare\\.com|pipedream\\.net|dnslog\\.cn|beeceptor\\.com|discord\\.com/api/webhooks|transfer\\.sh|filetransfer\\.io|paste(bin|\\.ee)|api\\.telegram\\.org|ipinfo\\.io|ipify\\.org|ifconfig\\.me|files\\.catbox\\.moe)"))"#
    );

    // Threat: direct reverse-shell commands passed to process APIs.
    rules.push(rule!(
        "chainsec.py.detection.guarddog.reverse-shell",
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
        "chainsec.detection.guarddog.",
        "reverse-shell",
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
        "chainsec.py.detection.guarddog.cryptomining",
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
        "chainsec.detection.guarddog.",
        "cryptomining",
        FindingType::ProcessExecution,
        Risk::High,
        Confidence::High,
        "A string literal names mining software, a mining pool/protocol, or a Monero wallet.",
        "Remove unauthorized mining behavior and investigate the package provenance.",
        r#"((string) @match (#match? @match "(?i)(xmrig|ethminer|cgminer|bfgminer|cpuminer|ccminer|supportxmr\\.com|minexmr\\.com|nanopool\\.org|stratum\\+(tcp|ssl)://|[^1-9A-HJ-NP-Za-km-z]4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}[^1-9A-HJ-NP-Za-km-z])"))"#
    );

    // Threat: download/installation commands executed directly, plus Python's execute-opened-file chain.
    rules.push(rule!(
        "chainsec.py.detection.guarddog.download-and-execute",
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
        "chainsec.detection.guarddog.",
        "download-and-execute",
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
        "chainsec.py.detection.guarddog.encoded-powershell",
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
        "chainsec.detection.guarddog.",
        "encoded-powershell",
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
        "chainsec.py.detection.guarddog.base64-decoded-execution",
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
        "chainsec.detection.guarddog.",
        "base64-decoded-execution",
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
        "chainsec.py.detection.guarddog.dynamic-import",
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
        "chainsec.py.detection.guarddog.reflective-api",
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
        "chainsec.detection.guarddog.",
        "reflective-api",
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
        "chainsec.detection.guarddog.",
        "hidden-require",
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
        "chainsec.py.detection.guarddog.pyarmor",
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
        "chainsec.py.detection.guarddog.screen-capture",
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
        "chainsec.py.detection.guarddog.credential-environment",
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

    rules
}
