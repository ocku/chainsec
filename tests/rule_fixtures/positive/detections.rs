//! Positive fixtures for core detections and obfuscation heuristics.

use crate::common::Case;

pub(crate) const CASES: &[Case] = &[
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
        source: "fetch(\"https://example.com\");\n",
    },
    Case {
        rule_id: "chainsec.js.detection.network-listen",
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
    Case {
        rule_id: "chainsec.js.detection.dynamic-import",
        file: "case.js",
        source: "import(moduleName);\n",
    },
    // Built-in TypeScript rules.
    Case {
        rule_id: "chainsec.ts.detection.dynamic-code-execution",
        file: "case.ts",
        source: "eval(input);\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.dynamic-import",
        file: "case.ts",
        source: "import(moduleName);\n",
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
        source: "fetch(\"https://example.com\");\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.network-listen",
        file: "case.ts",
        source: "Deno.listen({ port: 8080 });\n",
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
        source: "const _0x1234 = ['a','b','c','d','e'];\nfunction decode(i) { return _0x1234[i]; }\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.heuristic.string-table",
        file: "case.ts",
        source: "const _0x1234 = ['a','b','c','d','e'];\nfunction decode(i: number) { return _0x1234[i]; }\n",
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
        source: "function decode(input) { const state = Array(256); return String.fromCharCode(input.charCodeAt(0) ^ state[0]); }\n",
    },
    Case {
        rule_id: "chainsec.ts.detection.heuristic.rc4-decoder",
        file: "case.ts",
        source: "function decode(input: string) { const state = Array(256); return String.fromCharCode(input.charCodeAt(0) ^ state[0]); }\n",
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
];
