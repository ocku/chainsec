# Rules, reports, and exit status

## Reports

JSON scan reports use schema version `1.2.0`; the schema is in [`schema/report.schema.json`](schema/report.schema.json). Findings include a stable SHA-256 ID, rule ID/version, risk, confidence, rationale, remediation, package identifier, source location, matched code, and suppression state. Resolved package provenance is recorded in separate `packages` records and linked to findings through the finding's package identifier. Operational issues and observed capabilities are structured separately from findings.

JSON version-diff reports use schema version `1.0.0` with `report_type: "version_diff"`; the schema is in [`schema/version-diff.schema.json`](schema/version-diff.schema.json). The `versions` array is newest-first, while each entry in `diffs` compares an adjacent older `from_version` to newer `to_version`. Detection changes contain counts grouped by finding group, rule ID, and risk; capability changes contain evidence counts grouped by capability name. These counts are presentation summaries. Diff finding policy compares oldest/newest occurrence identities using normalized package identity, rule ID and version, file, and matched code, so replacing one occurrence with another cannot pass merely because a grouped count stayed equal, while relocated identical code is not reported as a separate change.

`chainsec` scans dependency source without executing it. The `capabilities` array inventories observed behavior using stable `domain:action[-target]` names: `network:listen`, `network:connect`, `network:tls`, `network:download`, `network:resolve-dns`, `network:raw-socket`, `filesystem:read`, `filesystem:write`, `filesystem:delete`, `filesystem:enumerate`, `filesystem:archive`, `filesystem:set-permissions`, `process:spawn`, `process:schedule`, `secret:read-environment`, `secret:read-file`, `secret:read-browser-profile`, `runtime:read-clipboard`, and `code:dynamic-execution`. Each evidence record includes its stable ID; rule ID, version, type, risk, and confidence; package, source location, and matched code; plus suppression state and an optional suppression reason. Capabilities are informational: they do not count as findings and do not affect `--fail-on` exit status.

`--ignore-rule` removes matching rules before reporting; ignored selectors are not recorded in the current report schema. Configured `[[suppressions]]` leave matching findings in JSON with `suppressed: true` and a `suppression.reason`, but exclude them from human and SARIF output and from `--fail-on` evaluation.

A report may be partial. Manifest, resolution, fetch, extraction, and scan failures are normally recorded in the `issues` array and traversal continues for other packages. A package with an acquisition or scan issue may therefore be absent from `packages`, or may be present without all transitive dependencies analyzed. When the configured finding limit is exceeded, ChainSec retains a deterministic highest-risk bounded subset for each package and records a nonfatal `limit_exceeded` issue instead of discarding the package's completed scan. Capability evidence uses a separate bounded budget, so informational evidence cannot consume visible finding slots. Recovered Tree-sitter syntax errors are different: by default ChainSec logs them at debug level, continues evaluating rules against the recovered syntax tree, and retains resulting findings. `--fail-on-parse-error` (or `fail_on_parse_error = true`) also records each one as a fatal `parse_error` issue but does not skip the file, package, or remaining analysis.

When `--output` is supplied, `chainsec` writes the analysis directly to the specified path instead of stdout; parent directories must already exist, and report publication is not atomic. A report-write failure is reported on stderr and exits with code `3`.

## Example report

Human output is the default report format. It lists unsuppressed findings that meet `--fail-on`, any operational issues, and a final summary of unique capabilities and unique alerts. Capability matching locations and source snippets are intentionally omitted from human output.

```text
chainsec 0.5.2 — 3 package(s), 42 source file(s), 81920 source byte(s), 1 finding(s), 2 capability type(s), 0 issue(s)
High python:chainsec.py.detection.dynamic-code-execution:ArbitraryCodeExecution [root] src/main.py:12:5 — eval(user_input)

Summary
───────
Capabilities (2)
  filesystem:read
  network:connect
Alerts (1)
  High       1  python:chainsec.py.detection.dynamic-code-execution:ArbitraryCodeExecution
```

Each finding line shows the risk, rule as `language:rule_id:FindingType`, package identifier, file and `line:column`, and matched code. JSON and SARIF retain the same stable machine rule IDs. Pass `--verbose` to include findings below `--fail-on`; it does not expose capability evidence locations. Use `--format json` or `--format sarif` for complete machine-readable output. Human reports are colorized only when written directly to a terminal.

A JSON report is a single object with `schema_version`, `tool_version`, `root`, `policy`, `packages`, `findings`, `capabilities`, `issues`, and `statistics`:

```json
{
  "schema_version": "1.2.0",
  "tool_version": "0.5.2",
  "root": "/path/to/project",
  "policy": { "require_lockfile": true, "offline": true, "trust_local_input": false, "allowed_hosts": [], "limits": { } },
  "packages": [
    {
      "package_id": "python:requests@2.32.3",
      "source": "/path/to/cache/...",
      "source_url": "https://files.pythonhosted.org/...",
      "resolved_version": "2.32.3",
      "digest": "sha256:...",
      "depth": 1,
      "dependencies": [],
      "scanned_files": 12,
      "scanned_bytes": 20480
    }
  ],
  "findings": [
    {
      "id": "sha256:...",
      "rule_id": "chainsec.py.detection.dynamic-code-execution",
      "rule_version": 1,
      "finding_type": "arbitrary_code_execution",
      "risk": "high",
      "confidence": "high",
      "rationale": "Runtime code or process execution can execute attacker-controlled payloads during package use.",
      "remediation": "Remove dynamic execution or constrain input to a fixed, validated allowlist.",
      "package": "root",
      "file": "src/main.py",
      "location": { "start_line": 12, "start_column": 5, "end_line": 12, "end_column": 18 },
      "matched_code": "eval(user_input)",
      "suppressed": false
    }
  ],
  "capabilities": [
    {
      "name": "network:connect",
      "evidence": [{ "id": "sha256:...", "rule_id": "chainsec.py.capability.network-connect", "rule_version": 1, "finding_type": "network_access", "risk": "low", "confidence": "high", "package": "root", "file": "src/client.py", "location": { "start_line": 34, "start_column": 9, "end_line": 34, "end_column": 26 }, "matched_code": "requests.get(url)", "suppressed": false }]
    }
  ],
  "issues": [],
  "statistics": { "packages": 3, "source_files": 42, "source_bytes": 81920, "findings": 1, "cache_hits": 1 }
}
```

SARIF output follows SARIF 2.1.0 with one rule per configured rule and one result per finding; paths are relative to each scanned package and `matched_code` snippets are omitted.

## Built-in rules

The default catalog is assembled from two distinct groups:

- `built_in` contains all detection rules, including ChainSec's independent Tree-sitter implementations of GuardDog source-code analyzer patterns. These produce findings and may also declare a capability when a detection supplies useful capability evidence.
- `capabilities` contains informational-only rules that add capability evidence not already supplied by a detection. Every rule in this group declares a capability, so its matches never become findings. This group also includes capability-only patterns derived from GuardDog.

The detection catalog covers dynamic execution, process execution, decoded payloads, common code-obfuscation patterns (including javascript-obfuscator structures), network access (including Deno client/server APIs), filesystem access, environment/secret access, unsafe deserialization, dynamic loading, browser-global mutation, package installation hooks, and GuardDog-derived threat patterns. Manifest checks report `chainsec.py.detection.manifest.install-hook` for `setup.py` and npm `preinstall`, `install`, or `postinstall` entries; these hooks are identified but never executed.

GuardDog-derived source-code rules are implemented only through Tree-sitter syntax queries; their byte-signature and whole-file substring/count analyzers are omitted. Their attribution is recorded in [`docs/THIRD_PARTY.md`](THIRD_PARTY.md). Separate file-level heuristics may still use bounded magic-byte and entropy checks to flag opaque or compressed files.

Built-in dynamic-loading checks also identify direct or `getattr`/`setattr` Python reflective namespace access that can reach import machinery (`__globals__`, `__builtins__`, `__import__`, loaders, or module specifications). Built-in obfuscation heuristics identify character-code assembly (long arrays joined directly or through Python `chr`/`ord`, or long JavaScript/TypeScript arrays mapped through `String.fromCharCode`), string literals containing 16 or more consecutive hexadecimal, octal, or Unicode escapes (including two or more concatenated literals with at least eight escapes each), and generated or visually ambiguous identifiers such as `_0x1d8f` or `OO0O0O`. These are syntax-aware signals, not proof of malicious intent.

High-entropy detection captures string-literal nodes with Tree-sitter and reports non-whitespace values of at least 32 characters whose Shannon entropy is at least 5.0 bits per character. Recognized URLs, encoding alphabets, character tables, structured literals, regular-expression ranges, digest metadata, and serialized binary markers are excluded. The string-literal rules do not inspect comments or arbitrary raw source bytes. Every file is also subject to bounded file-level checks for recognized compressed formats, recognized native artifacts, unknown binary data, and unusually high entropy. ELF, Mach-O, PE, and WebAssembly artifacts always receive a high-risk finding with explicit format information; ChainSec identifies their format but does not inspect native instructions. `chainsec` reads supported source files in full, subject to `--max-source-file-size`; for other files it reads only a prefix, currently up to 1 MiB. These file-level checks are heuristic and do not decode, execute, disassemble, or semantically analyze native code. Rules do not prove either exploitability or safety.

## Rule ID format

Built-in IDs are lowercase, descriptive dotted names. Source-language rules begin with `chainsec.py.`, `chainsec.js.`, or `chainsec.ts.`; language-agnostic file rules begin with `chainsec.`. Detection rules include `.detection.`, including `.detection.guarddog.` for GuardDog-derived patterns; informational rules include `.capability.`. For example, `chainsec.py.detection.dynamic-code-execution` and `chainsec.js.capability.filesystem-delete`. Use a `group:glob` selector to scope by behavior category, for example `filesystem:chainsec.*.capability.filesystem-delete` or `network:chainsec.*.detection.guarddog.reverse-shell`.

## Custom rule packs

Custom rule packs are JSON or YAML objects with a non-empty `rules` array. Each rule supplies `id`, positive `version`, `language`, `finding_type`, `risk`, `confidence`, `rationale`, `remediation`, and a Tree-sitter `query` containing an `@match` capture. Rule IDs may contain letters, digits, `_`, `-`, and `.` and must be unique across built-in and custom packs.

`--ignore-rule` selectors use `group:rule-id-glob`, such as `filesystem:*`; groups are derived from each rule's `finding_type`, and `*` and `?` match the rule ID. An optional `entropy` object further restricts a string-literal match with `minimum_length`, `minimum_entropy` (0–8), and `maximum_whitespace_ratio` (0–1; default `0.05`). Malformed packs, unknown fields, duplicate IDs, invalid entropy limits, invalid selectors, and invalid queries fail before analysis.

## Exit codes

`chainsec` is a dependency chain supply auditing tool that can also be used as a CI component. The exit code reflects whether findings met the `--fail-on` threshold and whether any operational or policy issues occurred. A recovered syntax error does not affect exit status by default. With `--fail-on-parse-error`, it is recorded as a fatal operational issue and produces exit code `3`; analysis still continues against the recovered syntax tree.

| Code | Meaning |
| --- | --- |
| `0` | Scan completed below the finding threshold |
| `1` | At least one finding met the threshold |
| `2` | Invalid input or configuration |
| `3` | Manifest, scan, resolution, or fetch issue |
| `4` | Policy or resource-limit violation |

Exit status precedence is:

1. `4` if any policy or resource-limit issue occurred.
2. `3` if any other operational issue occurred.
3. `1` if no operational issue occurred and an unsuppressed finding meets `--fail-on`.
4. `0` otherwise.

Invalid configuration or failures before a report can be created may produce only an error on stderr rather than a JSON/SARIF report.
