# Heuristics and capability reference

This document is the reference for ChainSec's built-in static-analysis catalog. It describes what each built-in rule can match, not proof that the matched code is malicious or exploitable. Rules never execute, decode, disassemble, or follow data across files.

## How to read this catalog

- **Detections** create findings. Their risk and confidence are included in JSON and SARIF reports and are evaluated by `--fail-on` unless suppressed.
- **Capabilities** are informational evidence of behavior. They appear in the JSON `capabilities` array, do not create findings, and do not affect exit status.
- **Language coverage:** `{py, js, ts}` means one rule per listed language, using `chainsec.py.`, `chainsec.js.`, and `chainsec.ts.` IDs. A listed `js, ts` pair has one JavaScript and one TypeScript rule. Other entries show their exact single-language ID.
- Built-in rules are version `1`. Rule selectors use the finding-type group, not the ID prefix: for example, `--ignore-rule 'obfuscation:chainsec.*high-entropy*'`.

## Prioritization policy

Risk is about the consequence of the behavior, not merely how broad the API match is:

- **Capability / informational:** ordinary web requests, DNS lookups, and other routine access APIs are recorded as capabilities and do not create findings or affect exit status.
- **Medium:** suspicious concealment such as encoded strings, string assembly, and control-flow obfuscation should receive review, but is not by itself proof of compromise. Stronger opaque-payload heuristics can be high risk when they indicate executable behavior.
- **High:** arbitrary code execution, credential or secret access, persistence, destructive filesystem operations, and suspicious exfiltration/download behavior require immediate review.
- **Critical:** highly specific compromise indicators such as reverse shells or encoded command cradles.

Use `--fail-on high` (the default) to fail on the high-impact classes while retaining lower-risk detections in JSON/SARIF, for example when running in CI. Use `--verbose` when reviewing medium findings in human output.

All source rules are Tree-sitter queries. They match parsed syntax only and do not perform cross-file data-flow analysis.

## Detection rules

### Execution, loading, and deserialization

| Rule ID or family | Languages | Risk / confidence | Matches |
| --- | --- | --- | --- |
| `chainsec.<lang>.detection.dynamic-code-execution` | py, js, ts | High / High | Python `eval`, `exec`, or `compile`; JavaScript/TypeScript `eval` calls and `Function` calls, except constructors whose arguments are all static strings of at most 32 characters. |
| `chainsec.<lang>.detection.heuristic.computed-global-execution` | js, ts | High / High | Computed `globalThis`, `window`, or `global` access to `eval` or `Function`. |
| `chainsec.<lang>.detection.heuristic.string-timer-execution` | js, ts | High / High | A string literal passed to `setTimeout` or `setInterval`. |
| `chainsec.<lang>.detection.heuristic.vm-context-execution` | js, ts | High / High | A Node `vm.runIn*Context` API invocation. |
| `chainsec.<lang>.detection.heuristic.worker-blob-execution` | js, ts | High / High | A Worker initialized from `URL.createObjectURL(...)` or an identifier named `blob`. |
| `chainsec.py.detection.heuristic.opaque-execution-input` | py | High / High | A decoded, deserialized, or decompressed value passed directly to `eval`, `exec`, or `FunctionType`. |
| `chainsec.<lang>.detection.guarddog.base64-decoded-execution` | py, js, ts | High / High | Base64-decoded content passed directly to `eval`, `exec`, or `Function`. JS/TS also cover `Buffer.from(..., "base64")`. |
| `chainsec.py.detection.guarddog.dynamic-import` | py | High / High | A dynamic import or serialized payload loader nested directly inside `exec`. |
| `chainsec.py.detection.unsafe-deserialization` | py | High / High | `pickle.load(s)` or `yaml.load(s)`. |
| `chainsec.<lang>.detection.dynamic-require` | js, ts | High / Medium | Node `require` with a non-literal module specifier. |
| `chainsec.py.detection.heuristic.dynamic-module` | py | High / High | `__import__`, `importlib.import_module`, or `loader.exec_module`. |
| `chainsec.py.detection.reflective-namespace` | py | Medium / High | Direct or `getattr`/`setattr` access to `__globals__`, `__builtins__`, `__import__`, loaders, or module specs. |
| `chainsec.<lang>.detection.guarddog.reflective-api` | py, js, ts | High / High | Python dangerous builtins resolved through `getattr` and immediately called; JS/TS reflective `Object.getOwnPropertyDescriptor(...).value` invocation. |
| `chainsec.<lang>.detection.guarddog.hidden-require` | js, ts | High / High | `require` hidden behind a short computed `global[...]` alias. |
| `chainsec.<lang>.detection.write-browser-global` | js, ts | Medium / High | Assignment to `window.property` or `window[...]`. |


### Process, network, filesystem, and secrets

| Rule ID or family | Languages | Risk / confidence | Matches |
| --- | --- | --- | --- |
| `chainsec.<lang>.detection.process-spawn` | py, js, ts | High / High | Python `os`/`subprocess` execution calls; bare JS/TS `exec`, `execFile`, `spawn`, or `fork`; or `new Deno.Command(...).spawn()`/`output()`/`outputSync()`. |
| `chainsec.<lang>.detection.network-request` | py, js, ts | Informational / High | Python `requests`, `urllib`, `httpx`, or `socket` calls; JS/TS `fetch` and Deno network/server APIs. These are informational `network:connect` capabilities, not findings. |
| `chainsec.py.detection.filesystem-open` | py | Medium / Medium | Calls to Python `open`. |
| `chainsec.<lang>.detection.read-environment` | js, ts | High / High | Credential-named `process.env` properties, bracket access, or serializing the complete environment; or credential-named `Deno.env.get` calls. |
| `chainsec.<lang>.detection.guarddog.autostart` | py, js, ts | High / High | Writes to shell profiles, service/autostart paths, or Windows Run registry locations. |
| `chainsec.<lang>.detection.guarddog.destructive-deletion` | py, js, ts | High / High | Recursive deletion of absolute/home paths or literal destructive wipe commands. |
| `chainsec.py.detection.guarddog.dns-exfiltration` | py | High / High | A dynamically constructed hostname passed directly to a Python DNS lookup. |
| `chainsec.<lang>.detection.guarddog.messenger-exfiltration` | py, js, ts | High / High | Telegram bot credentials/endpoints, Discord webhooks, or Discord-token-shaped literals. |
| `chainsec.<lang>.detection.guarddog.suspicious-network-destination` | py, js, ts | Medium / High | Literal tunnel, webhook, paste, transfer, URL-shortener, or external-IP service destinations. |
| `chainsec.<lang>.detection.guarddog.reverse-shell` | py, js, ts | Critical / High | Literal reverse-shell commands passed to process APIs. |
| `chainsec.<lang>.detection.guarddog.cryptomining` | py, js, ts | High / High | Mining software, pools/protocols, or Monero-wallet-shaped string literals. |
| `chainsec.<lang>.detection.guarddog.download-and-execute` | py, js, ts | High / High | A downloader, package installer, or download-and-shell command passed directly to a process API; Python also matches `exec(compile(open(...)))`. |
| `chainsec.<lang>.detection.guarddog.encoded-powershell` | py, js, ts | Critical / High | Encoded, hidden, or download-cradle PowerShell passed to process execution. |
| `chainsec.py.detection.guarddog.screen-capture` | py | High / High | `ImageGrab`, `pyscreenshot`, or `pyautogui` screen-capture APIs. |
| `chainsec.py.detection.guarddog.credential-environment` | py | High / High | Reads of credential-named `os.getenv` or `os.environ` variables. |

### Obfuscation and opaque payloads

| Rule ID or family | Languages | Risk / confidence | Matches |
| --- | --- | --- | --- |
| `chainsec.<lang>.detection.decoded-payload` | py, js, ts | Medium / Medium | Python base64 decode APIs; JS/TS `atob` (bare or member call) and numeric `String.fromCharCode` calls. |
| `chainsec.py.detection.character-assembly` | py | Medium / High | A long array or `chr`/`ord` sequence joined into a runtime string. |
| `chainsec.<lang>.detection.character-code-assembly` | js, ts | Medium / High | An array of at least eight elements mapped through `String.fromCharCode` then joined. |
| `chainsec.<lang>.detection.encoded-escapes` | py, js, ts | Medium / High | At least 16 consecutive hexadecimal, octal, or Unicode escapes in a literal, or two concatenated literals with at least eight each. |
| `chainsec.<lang>.detection.ambiguous-identifier` | py, js, ts | Low / Medium | Generated hexadecimal-like names (for example `_0x1d8f`) or visually ambiguous `O/0/I/l/1` sequences; JS/TS also match repeated Unicode-escape identifiers. |
| `chainsec.<lang>.detection.heuristic.string-table` | js, ts | Medium / High | JavaScript-obfuscator-style string-table accessor structures. |
| `chainsec.<lang>.detection.javascript-obfuscator` | js, ts | Medium / High | The generated `_0x` string-array bootstrap/self-replacing accessor or incremented computed `_$…` accessor object emitted by [javascript-obfuscator](https://github.com/javascript-obfuscator/javascript-obfuscator). |
| `chainsec.<lang>.detection.javascript-obfuscator-vm-identifier` | js, ts | Low / Medium | `vmz_` or `vme_` followed by at least six hexadecimal characters, a generated-name convention associated with javascript-obfuscator VM output. |
| `chainsec.<lang>.detection.heuristic.rc4-decoder` | js, ts | High / Medium | A 256-byte stream-cipher-like decoder that reconstructs strings. |
| `chainsec.<lang>.detection.heuristic.embedded-vm` | js, ts | High / Medium | Bytecode, opcode, and dispatch structures suggesting an embedded VM. |
| `chainsec.<lang>.detection.heuristic.control-flow-flattening` | js, ts | Medium / High | A `while` loop switching over an indexed dispatch sequence whose cursor is updated in the switch expression. |
| `chainsec.py.detection.heuristic.code-protector-marker` | py | Medium / High | PyArmor, Cython, or Nuitka bootstrap/marker identifiers. |
| `chainsec.py.detection.guarddog.pyarmor` | py | Medium / High | PyArmor runtime, bootstrap, or verification calls. |
| `chainsec.<lang>.detection.heuristic.high-entropy-string` | py, js, ts | Medium / Medium | A string-literal value of at least 32 non-whitespace characters, entropy at least 5.0 bits/character, and no more than 5% whitespace. Recognized URLs, encoding alphabets, character tables, structured literals, regular-expression ranges, digest metadata, and serialized binary markers are excluded. |

### Manifest and file heuristics

These checks are not Tree-sitter source rules.

| Rule ID | Risk / confidence | Matches |
| --- | --- | --- |
| `chainsec.py.detection.manifest.install-hook` | Medium / High | A Python `setup.py` installation script. ChainSec identifies it but never runs it. |
| `chainsec.js.detection.manifest.install-hook` | High / High | npm `preinstall`, `install`, or `postinstall` lifecycle scripts. ChainSec identifies them but never runs them. |
| `chainsec.detection.file.compressed` | High / High | Recognized compressed-file signatures, including gzip, bzip2, xz, zip, and zstd. |
| `chainsec.detection.file.native-artifact` | High / High | Recognized ELF, Mach-O, PE, or WebAssembly executable/library signatures. Native artifacts are always high risk; ChainSec identifies the format but does not inspect its instructions. |
| `chainsec.detection.file.binary` | High / High | Unrecognized non-UTF-8 data or NUL bytes when it is not a recognized static asset or native artifact. |
| `chainsec.detection.file.high-entropy-file` | Medium / Medium | An unrecognized file of at least 256 bytes with Shannon entropy at least 7.0 bits/byte. |

File checks examine all scanned files. Supported source files are read in full within `--max-source-file-size`; other files are analyzed from a bounded prefix of up to 1 MiB. Compression and native executable/library formats are recognized before unknown binary and entropy classification. Known static assets with a matching signature, including macOS icon files, are skipped to reduce noise.

## Capability rules

Capability rules use the same syntax-aware matching model but report evidence rather than findings. Unless noted, each capability has Python, JavaScript, and TypeScript rules named `chainsec.<lang>.capability.<suffix>`. The capability name is stable even when several rules contribute evidence.

| Capability | Rule suffix / coverage | Evidence matched |
| --- | --- | --- |
| `network:listen` | `network-listen` — py, js, ts | Python socket bind/listen/server calls; Node HTTP/HTTPS/net/TLS/dgram, Deno, or Bun server creation. |
| `network:raw-socket` | `network-raw-socket` — py, js, ts | Python `SOCK_RAW` or importing/requiring the `raw-socket` package. |
| `network:download` | `network-download` — py, js, ts | Python `wget` or `urllib.request`; JS/TS `got`, or HTTP/HTTPS/Axios get/request/download APIs. |
| `network:connect` | `network-connect` — py, js, ts; `network-connect-via-lolbas` — py, js, ts | Python HTTP/client APIs, `socket.create_connection`, or conventional socket/connection `.connect()` calls; JS/TS `fetch`, HTTP/client/DNS APIs, or Deno `connect`/`connectTls`; or process execution of transfer/tunnel tools such as curl, wget, certutil, bitsadmin, socat, ncat, or nc. |
| `network:tls` | `network-tls` — py, js, ts | Python `ssl.wrap_socket` or `wrap_socket` on conventional TLS-context variables (`context`, `ctx`, or `ssl_context`); Node `tls.connect`/`createServer`, `https` client/server APIs, or `http2.createSecureServer`; Deno `connectTls`, `listenTls`, or `startTls`. This establishes TLS setup behavior, not that a handshake completed or that certificate validation succeeded. |
| `network:resolve-dns` | `network-resolve-dns` — py, js, ts | Python socket/DNS resolvers, Node `dns` lookups/resolvers, or Deno `resolveDns`. |
| `filesystem:read` | `filesystem-read` — py, js, ts | Python `Path.read_text`/`read_bytes`; Node `fs` read APIs and read streams; or Deno `readFile`/`readTextFile`. |
| `filesystem:write` | `filesystem-write` — py, js, ts | Python write/append `open` modes and `Path.write_*`; Node `fs` write, append, or write-stream APIs; or Deno `writeFile`/`writeTextFile`. |
| `filesystem:delete` | `filesystem-delete` — py, js, ts | Python `os`/`shutil` deletion or `Path.unlink`; Node `fs` deletion or `rimraf`; or Deno `remove`. |
| `filesystem:enumerate` | `filesystem-enumerate` — py, js, ts | Python `os`/`glob` enumeration; Node `fs` directory enumeration; or Deno `readDir`. |
| `filesystem:archive` | `filesystem-archive` — py, js, ts | Archive creation/extraction methods. |
| `filesystem:set-permissions` | `filesystem-set-permissions` — py, js, ts | Python `os.chmod`, Node `fs.chmod`, or Deno `chmod`. |
| `process:spawn` | `process-spawn` — py, js, ts | Python spawn/exec methods; Node child-process APIs and sync variants; Deno `new Deno.Command(...).spawn()`/`output()`/`outputSync()`; or `new Function`. |
| `process:schedule` | `process-schedule` — py, js, ts | Cron/systemd timer references or Python `CronTab`; JS/TS cron/scheduling libraries and APIs. |
| `secret:read-environment` | `secret-read-environment` — py, js, ts | Python `os.getenv`, JavaScript/TypeScript `process.env`, or Deno `env.get`/`has`/`toObject`. |
| `secret:read-file` | `secret-read-file` — py, js, ts | Direct literals for common credential locations: SSH, AWS, gcloud, Kubernetes, npm, PyPI, or `.env` files. |
| `secret:read-browser-profile` | `secret-read-browser-profile` — py, js, ts | Browser profile, cookie DB, credential-store paths; JS/TS also detect `chrome-cookies-secure` and `electron-cookies`. |
| `runtime:read-clipboard` | `clipboard-access` — py, js, ts | Clipboard read or write APIs in supported Python and Node packages. |
| `code:dynamic-execution` | `dynamic-code-execution` — py, js, ts | Python `eval`/`exec`/`compile` and JavaScript/TypeScript `eval` or `Function`. |

## Limits and interpretation

A match establishes only that the syntactic construct or bounded heuristic was observed. In particular:

- An API name does not establish that a dangerous argument was attacker controlled.
- A capability is not an alert; legitimate packages can need network, filesystem, or process access.
- Obfuscation, entropy, binary, and compressed-file checks are review signals, not malware verdicts.
- Source rules do not match comments or arbitrary raw bytes. File heuristics are deliberately separate because opaque files cannot be parsed as source.

Use the exact rule ID and its group to tailor policy, for example:

```sh
chainsec scan . --ignore-rule 'network:chainsec.*suspicious-network-destination*'
```

For rule-pack format, suppressions, report fields, and exit-code behavior, see [Rules, reports, and exit status](RULES_AND_REPORTS.md) and [Configuration and CLI reference](CONFIGURATION.md).
