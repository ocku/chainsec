use crate::common::assert_no_match;

#[test]
fn benchmark_false_positive_shapes_do_not_match() {
    assert_no_match(
        "chainsec.js.detection.dynamic-import",
        "case.js",
        "import(\"fixed-module\");\n",
    );
    assert_no_match(
        "chainsec.ts.detection.dynamic-import",
        "case.ts",
        "import(\"fixed-module\");\n",
    );
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
        "const weekdays = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'];\nfunction firstWeekday() { return weekdays[0]; }\n",
    );
    assert_no_match(
        "chainsec.ts.detection.heuristic.string-table",
        "case.ts",
        "const weekdays = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'];\nfunction firstWeekday(): string { return weekdays[0]; }\n",
    );
    assert_no_match(
        "chainsec.js.detection.heuristic.rc4-decoder",
        "case.js",
        "const scratch = Array(256);\nfunction hash(input) { return input.charCodeAt(0) ^ 0x5a; }\n",
    );
    assert_no_match(
        "chainsec.ts.detection.heuristic.rc4-decoder",
        "case.ts",
        "const scratch = Array(256);\nfunction hash(input: string): number { return input.charCodeAt(0) ^ 0x5a; }\n",
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
