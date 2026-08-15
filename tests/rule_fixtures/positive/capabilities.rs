//! Positive fixtures for capability rules across supported languages.

use crate::common::Case;

pub(crate) const CASES: &[Case] = &[
    // GuardDog capability rules (Python).
    Case {
        rule_id: "chainsec.py.capability.secret-read-browser-profile",
        file: "case.py",
        source: "path = \"~/Library/Safari/LocalStorage\"\n",
    },
    Case {
        rule_id: "chainsec.py.capability.filesystem-delete",
        file: "case.py",
        source: "import shutil\nshutil.rmtree(\"/tmp/stale\")\n",
    },
    Case {
        rule_id: "chainsec.py.capability.filesystem-read",
        file: "case.py",
        source: "from pathlib import Path\nPath(\"data.txt\").read_text()\n",
    },
    Case {
        rule_id: "chainsec.py.capability.filesystem-set-permissions",
        file: "case.py",
        source: "import os\nos.chmod(\"tool.sh\", 0o755)\n",
    },
    Case {
        rule_id: "chainsec.py.capability.filesystem-write",
        file: "case.py",
        source: "open(\"data.txt\", \"w\")\n",
    },
    Case {
        rule_id: "chainsec.py.capability.network-listen",
        file: "case.py",
        source: "server.listen()\n",
    },
    Case {
        rule_id: "chainsec.py.capability.network-raw-socket",
        file: "case.py",
        source: "import socket\nsocket.socket(socket.AF_INET, socket.SOCK_RAW)\n",
    },
    Case {
        rule_id: "chainsec.py.capability.network-download",
        file: "case.py",
        source: "import wget\nwget.download(\"https://example.com/f.bin\")\n",
    },
    Case {
        rule_id: "chainsec.py.capability.network-connect",
        file: "case.py",
        source: "import socket\nsock = socket.socket()\nsock.connect((\"example.com\", 443))\n",
    },
    Case {
        rule_id: "chainsec.py.capability.network-tls",
        file: "case.py",
        source: "import ssl\nssl_context = ssl.create_default_context()\nssl_context.wrap_socket(sock, server_hostname=\"example.com\")\n",
    },
    Case {
        rule_id: "chainsec.py.capability.network-connect-via-lolbas",
        file: "case.py",
        source: "import os\nos.system(\"curl https://example.com/payload\")\n",
    },
    Case {
        rule_id: "chainsec.py.capability.network-connect-via-lolbas",
        file: "case.py",
        source: "import subprocess\nsubprocess.run((\"curl\", \"https://example.com/payload\"))\n",
    },
    Case {
        rule_id: "chainsec.py.capability.process-schedule",
        file: "case.py",
        source: "from crontab import CronTab\nCronTab(user=\"root\")\n",
    },
    Case {
        rule_id: "chainsec.py.capability.process-spawn",
        file: "case.py",
        source: "import os\nos.spawnl(os.P_NOWAIT, \"/bin/ls\")\n",
    },
    Case {
        rule_id: "chainsec.py.capability.dynamic-code-execution",
        file: "case.py",
        source: "eval(payload)\n",
    },
    Case {
        rule_id: "chainsec.py.capability.clipboard-access",
        file: "case.py",
        source: "import pyperclip\npyperclip.paste()\n",
    },
    // GuardDog capability rules (JavaScript/TypeScript share queries).
    Case {
        rule_id: "chainsec.js.capability.secret-read-browser-profile",
        file: "case.js",
        source: "const store = \"chrome-cookies-secure\";\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.secret-read-browser-profile",
        file: "case.ts",
        source: "const store = \"chrome-cookies-secure\";\n",
    },
    Case {
        rule_id: "chainsec.js.capability.filesystem-delete",
        file: "case.js",
        source: "fs.rmSync(\"/tmp/stale\", { recursive: true });\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.filesystem-delete",
        file: "case.ts",
        source: "Deno.remove(\"/tmp/stale\", { recursive: true });\n",
    },
    Case {
        rule_id: "chainsec.js.capability.filesystem-read",
        file: "case.js",
        source: "fs.readFileSync(\"data.txt\");\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.filesystem-read",
        file: "case.ts",
        source: "Deno.readTextFile(\"data.txt\");\n",
    },
    Case {
        rule_id: "chainsec.js.capability.filesystem-set-permissions",
        file: "case.js",
        source: "fs.chmodSync(\"tool.sh\", 0o755);\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.filesystem-set-permissions",
        file: "case.ts",
        source: "Deno.chmod(\"tool.sh\", 0o755);\n",
    },
    Case {
        rule_id: "chainsec.js.capability.filesystem-write",
        file: "case.js",
        source: "fs.writeFileSync(\"data.txt\", \"content\");\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.filesystem-write",
        file: "case.ts",
        source: "Deno.writeTextFile(\"data.txt\", \"content\");\n",
    },
    Case {
        rule_id: "chainsec.js.capability.network-listen",
        file: "case.js",
        source: "http.createServer(handler);\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.network-listen",
        file: "case.ts",
        source: "http.createServer(handler);\n",
    },
    Case {
        rule_id: "chainsec.js.capability.network-raw-socket",
        file: "case.js",
        source: "require(\"raw-socket\");\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.network-raw-socket",
        file: "case.ts",
        source: "import raw from \"raw-socket\";\n",
    },
    Case {
        rule_id: "chainsec.js.capability.network-download",
        file: "case.js",
        source: "got(\"https://example.com/f.bin\");\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.network-download",
        file: "case.ts",
        source: "got(\"https://example.com/f.bin\");\n",
    },
    Case {
        rule_id: "chainsec.js.capability.network-connect",
        file: "case.js",
        source: "dns.lookup(\"example.com\");\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.network-connect",
        file: "case.ts",
        source: "Deno.connect({ hostname: \"example.com\", port: 443 });\n",
    },
    Case {
        rule_id: "chainsec.js.capability.network-tls",
        file: "case.js",
        source: "tls.connect(443, \"example.com\");\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.network-tls",
        file: "case.ts",
        source: "Deno.connectTls({ hostname: \"example.com\", port: 443 });\n",
    },
    Case {
        rule_id: "chainsec.js.capability.network-connect-via-lolbas",
        file: "case.js",
        source: "exec(\"curl https://example.com/payload\");\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.network-connect-via-lolbas",
        file: "case.ts",
        source: "exec(\"curl https://example.com/payload\");\n",
    },
    Case {
        rule_id: "chainsec.js.capability.process-schedule",
        file: "case.js",
        source: "const cron = require(\"node-cron\");\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.process-schedule",
        file: "case.ts",
        source: "import cron from \"node-cron\";\n",
    },
    Case {
        rule_id: "chainsec.js.capability.process-spawn",
        file: "case.js",
        source: "const { exec } = require(\"child_process\");\nexec(\"ls\");\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.process-spawn",
        file: "case.ts",
        source: "const { spawn } = require(\"child_process\");\nspawn(\"ls\");\n",
    },
    Case {
        rule_id: "chainsec.js.capability.dynamic-code-execution",
        file: "case.js",
        source: "eval(payload);\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.dynamic-code-execution",
        file: "case.ts",
        source: "eval(payload);\n",
    },
    Case {
        rule_id: "chainsec.js.capability.clipboard-access",
        file: "case.js",
        source: "clipboardy.readSync();\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.clipboard-access",
        file: "case.ts",
        source: "clipboardy.readSync();\n",
    },
    // Additional capability rules.
    Case {
        rule_id: "chainsec.py.capability.secret-read-environment",
        file: "case.py",
        source: "os.getenv(\"TOKEN\")\n",
    },
    Case {
        rule_id: "chainsec.js.capability.secret-read-environment",
        file: "case.js",
        source: "process.env.TOKEN;\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.secret-read-environment",
        file: "case.ts",
        source: "Deno.env.get(\"TOKEN\");\n",
    },
    Case {
        rule_id: "chainsec.py.capability.secret-read-file",
        file: "case.py",
        source: "path = \"~/.aws/credentials\"\n",
    },
    Case {
        rule_id: "chainsec.js.capability.secret-read-file",
        file: "case.js",
        source: "const path = \"~/.aws/credentials\";\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.secret-read-file",
        file: "case.ts",
        source: "const path = \"~/.aws/credentials\";\n",
    },
    Case {
        rule_id: "chainsec.py.capability.filesystem-enumerate",
        file: "case.py",
        source: "os.listdir(\".\")\n",
    },
    Case {
        rule_id: "chainsec.js.capability.filesystem-enumerate",
        file: "case.js",
        source: "fs.readdirSync(\".\");\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.filesystem-enumerate",
        file: "case.ts",
        source: "fs.readdirSync(\".\");\n",
    },
    Case {
        rule_id: "chainsec.py.capability.filesystem-archive",
        file: "case.py",
        source: "archive.extractall(path)\n",
    },
    Case {
        rule_id: "chainsec.js.capability.filesystem-archive",
        file: "case.js",
        source: "archive.extractAll(path);\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.filesystem-archive",
        file: "case.ts",
        source: "archive.extractAll(path);\n",
    },
    Case {
        rule_id: "chainsec.py.capability.network-resolve-dns",
        file: "case.py",
        source: "socket.gethostbyname(\"example.com\")\n",
    },
    Case {
        rule_id: "chainsec.js.capability.network-resolve-dns",
        file: "case.js",
        source: "dns.lookup(\"example.com\");\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.network-resolve-dns",
        file: "case.ts",
        source: "dns.lookup(\"example.com\");\n",
    },
];
