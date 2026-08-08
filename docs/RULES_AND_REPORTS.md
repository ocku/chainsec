# Rules, reports, and exit status

## Reports

JSON reports use schema version `1.0.0`; the schema is in [`schema/report.schema.json`](schema/report.schema.json). Findings include a stable SHA-256 ID, rule ID/version, risk, confidence, rationale, remediation, package identifier, source location, matched code, and suppression state. Resolved package provenance is recorded in separate `packages` records and linked to findings through the finding's package identifier. Operational issues are structured separately from findings.

`--ignore-rule` removes matching rules before reporting; ignored selectors are not recorded in the current report schema. The suppression field is retained for schema compatibility, and emitted findings are unsuppressed because the CLI has no baseline or suppression-file mechanism.

A report may be partial. Manifest, resolution, fetch, extraction, and scan failures are normally recorded in the `issues` array and traversal continues for other packages. A package with an acquisition or scan issue may therefore be absent from `packages`, or may be present without all transitive dependencies analyzed.

When `--output` is supplied, `chainsec` writes the analysis directly to the specified path instead of stdout; parent directories must already exist, and report publication is not atomic. A report-write failure is reported on stderr and exits with code `3`.

## Example report

Human output is the default report format. It is a compact summary followed by one line per finding and issue:

```text
chainsec 0.2.0 — 3 package(s), 2 finding(s), 0 issue(s)
High execution:PY001 [root] src/main.py:12:5 — eval(user_input)
Medium network:PY004 [root] src/client.py:34:9 — requests.get(url)
```

Each finding line shows the risk, rule as `group:rule_id`, package identifier, file and `line:column`, and matched code. Use `--format json` or `--format sarif` for machine-readable output. Human reports are colorized only when written directly to a terminal.

A JSON report is a single object with `schema_version`, `tool_version`, `root`, `policy`, `packages`, `findings`, `issues`, and `statistics`:

```json
{
  "schema_version": "1.0.0",
  "tool_version": "0.2.0",
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
      "rule_id": "PY001",
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
  "issues": [],
  "statistics": { "packages": 3, "source_files": 42, "source_bytes": 81920, "findings": 2, "cache_hits": 1 }
}
```

SARIF output follows SARIF 2.1.0 with one rule per configured rule and one result per finding; paths are relative to each scanned package and `matched_code` snippets are omitted.

## Built-in rules

The built-in catalog covers dynamic execution, process execution, decoded payloads, network access, filesystem access, environment/secret access, unsafe deserialization, dynamic loading, package installation hooks, and syntax-aware equivalents of GuardDog source-code analyzers. Manifest checks report `PY_INSTALL_SCRIPT` for `setup.py` and `NPM_INSTALL_SCRIPT` for npm `preinstall`, `install`, or `postinstall` entries; these hooks are identified but never executed.

GuardDog-inspired source-code rules are implemented only through Tree-sitter syntax queries; their byte-signature and whole-file substring/count analyzers are omitted. Separate file-level heuristics may still use bounded magic-byte and entropy checks to flag opaque or compressed files.

High-entropy detection captures string-literal nodes with Tree-sitter and reports non-whitespace values of at least 32 characters whose Shannon entropy is at least 5.0 bits per character. Literals containing recognized HTTP(S) or FTP URLs are excluded. The string-literal rules do not inspect comments or arbitrary raw source bytes. Every file is also subject to bounded file-level checks for recognized compressed formats, binary data, and unusually high entropy. `chainsec` reads supported source files in full, subject to `--max-source-file`; for other files it reads only a prefix, currently up to 1 MiB. These file-level checks are heuristic and do not decode, execute, disassemble, or semantically analyze native code. Rules do not prove either exploitability or safety.

## Custom rule packs

Custom rule packs are JSON or YAML objects with a non-empty `rules` array. Each rule supplies `id`, positive `version`, `language`, `finding_type`, `risk`, `confidence`, `rationale`, `remediation`, and a Tree-sitter `query` containing an `@match` capture. Rule IDs may contain letters, digits, `_`, `-`, and `.` and must be unique across built-in and custom packs.

`--ignore-rule` selectors use `group:rule-id-glob`, such as `filesystem:*`; groups are derived from each rule's `finding_type`, and `*` and `?` match the rule ID. An optional `entropy` object further restricts a string-literal match with `minimum_length`, `minimum_entropy` (0–8), and `maximum_whitespace_ratio` (0–1; default `0.05`). Malformed packs, unknown fields, duplicate IDs, invalid entropy limits, invalid selectors, and invalid queries fail before analysis.

## Exit codes

`chainsec` is intended to be driven from CI. The exit code reflects whether findings met the `--fail-on` threshold and whether any operational or policy issues occurred.

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
