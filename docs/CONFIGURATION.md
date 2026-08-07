# Configuration and CLI reference

`chainsec` reads an optional `chainsec.toml` file from the root directory passed to the command. The file is loaded once before analysis; configuration files in local or fetched dependencies are never read.

Create a conservative starter file with:

```sh
chainsec --init

# Or initialize a specific project directory:
chainsec /path/to/project --init
```

This writes `chainsec.toml` in the current directory (or specified project directory), does not scan, and refuses to overwrite an existing configuration. Command-line values override values in the file. Relative `rule_packs` paths resolve relative to the configuration file. The target `path` is deliberately not configurable because it determines the one trusted configuration root.

## CLI options

- `--allow-host <host>`: permit an exact host, `*.example.com` for subdomains, or `'*'` for all hosts. Quote globs to prevent shell expansion.
- `--online`: enable HTTP(S) acquisition; requires at least one `--allow-host`. Network is disabled unless this is set.
- `--allow-unlocked`: permit mutable declarations. Registry-backed Python and npm requirements (including Deno `npm:` specifiers) are resolved to matching releases and pinned to registry-published artifact URLs and integrity values; unsupported unlocked forms remain unresolved.
- `--trust-local-input`: permit `file:`/path dependencies to escape the package that declares them; disabled by default.
- `--fail-on <low|medium|high|critical>`: finding threshold for exit code `1` (default `high`).
- `--max-depth`, `--max-packages`, `--max-archive`, `--max-extracted`, `--max-extracted-files`, `--max-source-file`, `--max-scan-seconds`: resource controls (defaults: `3`, `500`, `100MiB`, `500MiB`, `50000`, `2MiB`, `300`). Size values accept bytes and human-readable `K`, `M`, `G`, and `T` forms, including `100m`, `100M`, `100MB`, and `100MiB`; all are binary (1024-based) units, and fractional values such as `1.5G` are accepted.
- `--cache <dir>`: directory used for content-identified dependency source (default `.chainsec-cache`).
- `--format <json|human|sarif>`: report format; JSON is the default. Human reports are colorized only when written directly to a terminal.
- `--output <path>` (short `-o`): write the analysis report to a file rather than stdout. This supports every report format and produces an uncolored human report.
- `RUST_LOG=debug`: enable debug tracing while scanning interactively. Interactive `debug`, `info`, and `error` tracing is emitted to stdout; tracing is disabled when stdout is piped so machine-readable reports remain clean.
- `--rule-pack <path>`: add rules from a JSON or YAML rule pack; repeat for multiple packs.
- `--no-default-rules`: scan only with explicitly supplied rule packs.
- `--ignore-rule <GROUP:GLOB>`: omit matching built-in or custom rules from scanning and reports; repeat for multiple selectors. Groups are `execution`, `obfuscation`, `process`, `network`, `filesystem`, `secret`, `loading`, `deserialization`, `install`, and `file` (with aliases `network-access`, `filesystem-access`, and `fs`). `*` and `?` are supported in the rule-ID glob, so `network:*` ignores all network-access rules. Quote selectors to prevent shell expansion. The former `--exclude-rule` spelling remains an alias. A selector without a group prefix, such as `PY001` or `PY*`, is a glob matched against rule IDs across all groups.

## `chainsec.toml`

```toml
max_depth = 3
max_packages = 500
max_archive_bytes = 104857600
max_extracted_bytes = 524288000
max_extracted_files = 50000
max_source_file_bytes = 2097152
max_scan_seconds = 300

# Network and dependency policy
online = true
allowed_hosts = ["pypi.org", "files.pythonhosted.org", "registry.npmjs.org"]
allow_unlocked = false
trust_local_input = false

# Rules and reporting
rule_packs = ["rules/company.yaml"]
no_default_rules = false
ignored_rules = ["network:*", "filesystem:PY005"]
fail_on = "high"
format = "json"
# cache = ".chainsec-cache"
# output = "report.json"

# Omit matching resolved dependencies before they are fetched or scanned.
# Format: source:name@version; source is python, npm, or deno.
ignored_packages = ["npm:legacy-package@1.2.3", "python:legacy-package@2.0.0"]

# Omit paths from the root project scan only. Dependency source is unaffected.
ignored_paths = ["tests/*", "examples/**"]
```

All scalar and list CLI options except the target `path` have corresponding configuration keys: `max_depth`, `max_packages`, `max_archive_bytes`, `max_extracted_bytes`, `max_extracted_files`, `max_source_file_bytes`, `max_scan_seconds`, `cache`, `allow_unlocked`, `trust_local_input`, `online`, `allowed_hosts`, `rule_packs`, `no_default_rules`, `ignored_rules`, `format`, `fail_on`, and `output`. Size limits in TOML are integer byte counts; the CLI alone accepts human-readable units such as `100MiB`. Unknown keys and malformed ignored package selectors fail the scan before analysis.
