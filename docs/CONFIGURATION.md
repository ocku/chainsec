# Configuration and CLI reference

`chainsec` reads one optional global configuration: `$XDG_CONFIG_HOME/chainsec/config.toml`, or `$HOME/.config/chainsec/config.toml` when `XDG_CONFIG_HOME` is unset (falling back to `chainsec.toml` in that directory for existing setups). When no user configuration exists, it falls back to `/etc/chainsec/chainsec.conf`. It also reads an optional project `chainsec.toml` from the root directory passed to the command. The project configuration overrides global values for keys it defines; global values remain in effect for keys absent from the project configuration. Command-line values override both configuration layers. Configuration files in local or fetched dependencies are never read.

Create a conservative starter file with:

```sh
chainsec --init

# Or initialize a specific project directory:
chainsec /path/to/project --init
```

This writes `chainsec.toml` in the current directory (or specified project directory), appends `.chainsec-cache` to that directory’s `.gitignore`, does not scan, and refuses to overwrite an existing configuration. Command-line values override both configuration layers. A remote scan automatically enables online mode. Relative `rule_packs` paths resolve relative to the configuration file that defines them. The target `path` is deliberately not configurable because it determines the one trusted configuration root.

## CLI options

- `--allow-host <host>`: permit an exact host, `*.example.com` for subdomains, or `'*'` for all hosts. Quote globs to prevent shell expansion.
- `--online`: enable HTTP(S) acquisition. Network is disabled unless this or `--remote` is set; each requested host must also be allowed through `allowed_hosts`, `--allow-host`, a `--remote` selector, or an Artifactory metadata endpoint.
- `--allow-unlocked`: permit mutable declarations. Registry-backed Python and npm requirements (including Deno `npm:` specifiers) are resolved to matching releases and pinned to registry-published artifact URLs and integrity values; unsupported unlocked forms remain unresolved.
- `--remote <source:package>`: fetch and scan a package as the root, rather than scanning the local target path. Supported selectors are `npm:express`, `npm:express@0.1.0`, `pypi:urllib3`, `jsr:@std/fs`, and `github:owner/repository@40_HEX_COMMIT`. It automatically enables online mode and allows the selected source's configured metadata host (or GitHub's archive host); artifact-download hosts returned by metadata still require `--allow-host`. The explicitly selected root is resolved without requiring a lockfile; discovered dependencies retain normal lockfile policy.
- `--trust-local-input`: permit `file:`/path dependencies to escape the package that declares them; disabled by default.
- `--fail-on <low|medium|high|critical>`: finding threshold for exit code `1` and the default human report (default `high`).
- `--max-depth`, `--max-packages`, `--max-archive`, `--max-extracted`, `--max-extracted-files`, `--max-source-file`, `--max-scan-seconds`: resource controls (defaults: `3`, `500`, `100MiB`, `500MiB`, `50000`, `2MiB`, `300`). Size values accept bytes and human-readable `K`, `M`, `G`, and `T` forms, including `100m`, `100M`, `100MB`, and `100MiB`; all are binary (1024-based) units, and fractional values such as `1.5G` are accepted.
- `--cache <dir>`: directory used for content-identified dependency source. By default, ChainSec uses `.chainsec-cache` only when the current directory has `chainsec.toml`; otherwise it uses `$XDG_CACHE_HOME/chainsec`, then `$HOME/.cache/chainsec`, and finally the system temporary directory.
- `--cache-purge`: delete the resolved cache directory and exit without scanning. Combine with `--cache <dir>` to purge a specific cache.
- `--format <json|human|sarif>`: report format; human is the default. Human reports are colorized only when written directly to a terminal.
- `--verbose`: include findings below `--fail-on` in a human report. JSON and SARIF always include all findings.
- `--output <path>` (short `-o`): write the analysis report to a file rather than stdout. This supports every report format and produces an uncolored human report.
- `RUST_LOG=debug`: enable debug tracing while scanning interactively. Interactive `debug`, `info`, and `error` tracing is emitted to stdout; tracing is disabled when stdout is piped so machine-readable reports remain clean.
- `--rule-pack <path>`: add rules from a JSON or YAML rule pack; repeat for multiple packs.
- `--no-default-rules`: scan only with explicitly supplied rule packs.
- `--ignore-rule <GROUP:GLOB>`: omit matching built-in or custom rules from scanning and reports; repeat for multiple selectors. Groups are `execution`, `obfuscation`, `process`, `network`, `filesystem`, `secret`, `loading`, `deserialization`, `install`, and `file`. `*` and `?` are supported in the rule-ID glob, so `network:*` ignores all network rules. Quote selectors to prevent shell expansion. The former `--exclude-rule` spelling remains an alias. A selector without a group prefix, such as `chainsec.py.detection.dynamic-code-execution` or `chainsec.detection.*`, is a glob matched against rule IDs across all groups.
- `--ignore-path <GLOB>`: omit root-project paths matching the glob; repeat for multiple globs. It does not exclude paths in resolved dependency source. `--exclude-path` remains an alias. Set `ignored_paths` in configuration for persistent exclusions.
- `[[suppressions]]`: retain matching findings in JSON reports as suppressed, but exclude them from human/SARIF output and `--fail-on` evaluation. Each entry requires a `rule` selector and non-empty `reason`; optionally scope it to an exact resolved `package` identifier. Suppressions are persistent and have no expiry.

## Configuration files

Use the same TOML keys in `$XDG_CONFIG_HOME/chainsec/config.toml` (or `$HOME/.config/chainsec/config.toml`), `/etc/chainsec/chainsec.conf`, and project `chainsec.toml`. Only one global file is read: the user configuration takes precedence, and the system file is used only when no user configuration exists. A project key replaces the corresponding global key, including a list or an individual `[artifactories.<ecosystem>]` table. `allowed_hosts` is the exception: project hosts extend global hosts, and `--allow-host` values extend both configuration layers. Duplicate hosts are retained only once, in global/project/CLI order.

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

# Optional metadata endpoints for a registry proxy or artifact repository.
# The public npm, PyPI, and JSR endpoints remain the defaults. Artifact URLs
# present in lockfiles remain authoritative and are integrity-checked.
[artifactories.npm]
# metadata_base_url = "https://packages.example/npm"
#
# [artifactories.npm.credential]
# scope = "https://packages.example/"
# bearer_token_env = "PACKAGE_REGISTRY_TOKEN"
#
# [artifactories.pypi]
# metadata_base_url = "https://packages.example/pypi"
#
# [artifactories.jsr]
# metadata_base_url = "https://packages.example/jsr"

# Rules and reporting
rule_packs = ["rules/company.yaml"]
no_default_rules = false
ignored_rules = ["network:*", "filesystem:chainsec.py.detection.filesystem-open"]

[[suppressions]]
rule = "network:chainsec.*.detection.network-request"
package = "npm:telemetry-client@2.1.0"
reason = "Approved telemetry dependency; tracked in SEC-1234"

fail_on = "high"
format = "human"
# cache = ".chainsec-cache"
# output = "report.json"

# Omit matching resolved dependencies before they are fetched or scanned.
# Format: source:name@version; source is python, npm, or deno.
ignored_packages = ["npm:legacy-package@1.2.3", "python:legacy-package@2.0.0"]

# Omit paths from the root project scan only. Dependency source is unaffected.
ignored_paths = ["tests/*", "examples/**"]
```

All scalar and list CLI options except the target `path`, one-off `--remote` selector, and one-off `--verbose` flag have corresponding configuration keys: `max_depth`, `max_packages`, `max_archive_bytes`, `max_extracted_bytes`, `max_extracted_files`, `max_source_file_bytes`, `max_scan_seconds`, `cache`, `allow_unlocked`, `trust_local_input`, `online`, `allowed_hosts`, `rule_packs`, `no_default_rules`, `ignored_rules`, `ignored_paths`, `format`, `fail_on`, and `output`. The `suppressions` table is configuration-only. Size limits in TOML are integer byte counts; the CLI alone accepts human-readable units such as `100MiB`. Unknown keys, malformed rule selectors, empty suppression reasons, and malformed ignored package selectors fail the scan before analysis.

### Artifact repositories

`[artifactories.npm]`, `[artifactories.pypi]`, and `[artifactories.jsr]` decouple package metadata lookup from public registry hosts. Each table supports an npm-, PyPI-, or JSR-compatible proxy or repository manager through its required `metadata_base_url`. These are absolute HTTP(S) base URLs; package names and versions are appended as escaped path segments. When online mode is enabled, configured metadata hosts are automatically allowed. Add any separate artifact-download hosts returned by its metadata service to `allowed_hosts`.

For example, an unlocked npm package requests `<npm_metadata_base_url>/<package>`, while an unlocked Python package requests `<pypi_metadata_base_url>/<package>/json`. Locked Python dependencies without a lockfile artifact URL use `<pypi_metadata_base_url>/<package>/<version>/json`; locked Deno `npm:` dependencies retrieve their tarball URL from the configured npm metadata endpoint instead of assuming `registry.npmjs.org`. Each ecosystem’s metadata and release-selection logic is isolated in its fetcher implementation, while network policy, integrity verification, and extraction remain shared.

#### Credentials

Do not place credentials in `chainsec.toml` or repository URLs.

For a compatible repository that uses bearer-token authorization, add its `[artifactories.<ecosystem>.credential]` table. `scope` is an absolute HTTP(S) URL, and `bearer_token_env` names the environment variable that contains its token; the token itself is never stored in project configuration. A credential is used only when the request has the same scheme, host, port, and a matching path prefix. Credentials are re-evaluated on every redirect and are never forwarded solely because the redirect host is allowed. Credentials are never sent to `codeload.github.com`; private GitHub archive acquisition is unsupported.
