# Configuration and CLI reference

`chainsec` reads one optional global configuration: `$XDG_CONFIG_HOME/chainsec/config.toml`, or `$HOME/.config/chainsec/config.toml` when `XDG_CONFIG_HOME` is unset (falling back to `chainsec.toml` in that directory for existing setups). When no user configuration exists, it falls back to `/etc/chainsec/chainsec.conf`. It also reads an optional project `chainsec.toml` from the root directory passed to the command. The project configuration overrides global values for keys it defines; global values remain in effect for keys absent from the project configuration. Command-line values replace both configuration layers except where documented otherwise; in particular, `allowed_hosts` is additive. Configuration files in local or fetched dependencies are never read.

Create a conservative starter file with:

```sh
chainsec init

# Or initialize a specific project directory:
chainsec init /path/to/project
```

This writes `chainsec.toml` in the current directory (or specified project directory), appends `.chainsec-cache` to that directory’s `.gitignore`, does not scan, and refuses to overwrite an existing configuration. Command-line values replace both configuration layers except for documented additive options such as `--allow-host`. A remote scan automatically enables online mode. Relative `rule_packs` paths resolve relative to the configuration file that defines them. The target `path` is deliberately not configurable because it determines the one trusted configuration root.

## CLI options

- `--allow-host <host>`: add an exact permitted host, `*.example.com` for subdomains, or `'*'` for all hosts. Repeat for multiple hosts and quote globs to prevent shell expansion. This option adds to `allowed_hosts` from global and project configuration; it does not replace or narrow configured hosts.
- `--online`: enable HTTP(S) acquisition for `chainsec scan`. Each requested host must also be allowed through `allowed_hosts`, `--allow-host`, a remote selector, or an Artifactory metadata endpoint. It is unnecessary with `chainsec remote` commands, which enable online mode automatically.
- `--allow-unlocked`: permit mutable declarations. Registry-backed Python and npm requirements (including Deno `npm:` specifiers) are resolved to matching releases and pinned to registry-published artifact URLs and integrity values; unsupported unlocked forms remain unresolved.
- `--allow-insecure-http`: explicitly permit plaintext HTTP only within the exact origin, port, and base path of a configured `localhost` or loopback artifact repository. Redirects cannot broaden that scope, and HTTPS requests cannot downgrade into it. This is intended solely for local development registries. It exposes metadata and artifacts to local on-path attackers and is recorded as `policy.allow_insecure_http` in JSON reports.
- `chainsec remote scan <source:package>`: fetch and scan a package as the root. Supported selectors are `npm:express`, `npm:express@0.1.0`, `pypi:urllib3`, `jsr:@std/fs`, and `github:owner/repository@40_HEX_COMMIT`. It automatically enables online mode and allows the selected source's configured metadata host (or GitHub's archive host). For PyPI, it also allows the configured artifact host (`files.pythonhosted.org` by default); other artifact-download hosts returned by metadata still require `--allow-host`. The explicitly selected root is resolved without requiring a lockfile; discovered dependencies retain normal lockfile policy.
- `chainsec remote diff <source:package> <--last N|--compare FROM TO|--range FROM TO>`: select remote releases and compare detection counts and capability evidence counts between adjacent older → newer reports. `--last N` (where `N >= 2`) begins with the selector's resolved release and proceeds backward in ecosystem-native version order; `--compare FROM TO` scans exactly the two endpoints; `--range FROM TO` scans every pullable published release in the inclusive interval. Exactly one selector is required, and `FROM` must be older than `TO`. Human output uses compact vertical entries that list each detection or capability beside its signed total match-count difference between the oldest and newest selected versions, with every intermediate version where its count changed on an indented `↳` line below. JSON retains each adjacent comparison in [version-diff schema `1.0.0`](schema/version-diff.schema.json) with `report_type: "version_diff"`. npm, PyPI, and JSR selectors are supported; GitHub commits have no registry version history. Human and JSON output are supported; SARIF is not. Human output applies the normal `--fail-on`/`--verbose` finding filter, while JSON includes all detections. `--last` may return fewer than `N` releases when fewer non-yanked releases with supported integrity are available, but fails if fewer than two remain because no comparison baseline exists; explicit endpoints must be published and pullable, while unpullable intermediate range releases are skipped. Once selected, any artifact download, integrity verification, extraction, policy, or limit failure aborts the command rather than silently substituting another release. Operational issues are associated with their version, mark affected comparisons as incomplete, and affect exit status even when they occur in a historical release. Selection fails before downloading root artifacts when the number of versions exceeds `--max-packages`; during analysis, the same limit bounds aggregate unique roots and dependency acquisitions across the batch, with a fatal operational issue instead of an arbitrary partial frontier. Finding-based exit status compares occurrence identities between the oldest and newest endpoints (normalizing package versions), not only the grouped counts shown in the report. The convenience form `chainsec remote scan <source:package> --diff N` is equivalent to `remote diff <source:package> --last N`.
- `--trust-local-input`: permit `file:`/path dependencies to escape the package that declares them; disabled by default.
- `--fail-on <low|medium|high|critical>`: finding threshold for exit code `1` and the default human report (default `high`).
- `--fail-on-parse-error`: mark Tree-sitter-recovered syntax errors as fatal operational issues. ChainSec still analyzes the recovered syntax tree, retains any findings, and continues scanning other files and packages. Without this option, the same parse errors are reported as non-fatal operational issues.
- `--max-package-depth`, `--max-packages`, `--max-network-requests`, `--max-acquisition-seconds`, `--max-archive-size`, `--max-extracted-size`, `--max-extracted-files`, `--max-source-file-size`, `--max-scan-seconds`: resource controls (defaults: `3`, `16384`, `1000`, `300`, `100MiB`, `500MiB`, `50000`, `512MiB`, `300`). `--max-network-requests` and `--max-acquisition-seconds` apply separately to each package acquisition and include redirects and JSR’s manifest-driven per-file downloads; concurrent packages do not share counters or deadlines. `--max-packages` caps each ordinary traversal and, for a remote version diff, both selected roots and aggregate unique root/dependency work across the whole batch. Size values accept bytes and human-readable `K`, `M`, `G`, and `T` forms, including `100m`, `100M`, `100MB`, and `100MiB`; all are binary (1024-based) units, and fractional values such as `1.5G` are accepted.
- `--threads <THREADS>`: maximum number of worker threads used for concurrent package and source-file analysis (default `16`; minimum `1`). This is a command-line-only performance control and does not change report contents or finding policy.
- `--cache <dir>`: directory used for content-identified dependency source. By default, ChainSec uses `.chainsec-cache` only when the current directory has `chainsec.toml`; otherwise it uses `$XDG_CACHE_HOME/chainsec`, then `$HOME/.cache/chainsec`, and finally the system temporary directory.
- `chainsec cache purge`: delete cached contents while retaining the cache directory and its internal `.lock` for lifecycle coordination. Combine with `--cache <dir>` to purge a specific cache.
- `--format <json|human|sarif>`: report format; human is the default. Human reports are colorized only when written directly to a terminal.
- `--verbose`: include findings below `--fail-on` in a human report. It cannot be combined with JSON or SARIF output, which always includes all findings.
- `--output <path>` (short `-o`): write the analysis report to a file rather than stdout. This supports every report format and produces an uncolored human report.
- `RUST_LOG=debug`: enable debug tracing while scanning interactively. Interactive `debug`, `info`, and `error` tracing is emitted to stdout; tracing is disabled when stdout is piped so machine-readable reports remain clean.
- `--rule-pack <path>`: add rules from a JSON or YAML rule pack; repeat for multiple packs.
- `--no-default-rules`: scan only with explicitly supplied rule packs.
- `--ignore-rule <GROUP:GLOB>`: omit matching built-in or custom rules from scanning and reports; repeat for multiple selectors. Groups are `execution`, `obfuscation`, `process`, `network`, `filesystem`, `secret`, `loading`, `deserialization`, `install`, and `file`. `*` and `?` are supported in the rule-ID glob, so `network:*` ignores all network rules. Quote selectors to prevent shell expansion. A selector without a group prefix, such as `chainsec.py.detection.dynamic-code-execution` or `chainsec.detection.*`, is a glob matched against rule IDs across all groups.
- `--ignore-path <GLOB>`: omit root-project paths matching the glob; repeat for multiple globs. It does not exclude paths in resolved dependency source. Set `ignored_paths` in configuration for persistent exclusions.
- `[[suppressions]]`: retain matching findings in JSON reports as suppressed, but exclude them from human/SARIF output and `--fail-on` evaluation. Each entry requires a `rule` selector and non-empty `reason`; optionally scope it to an exact resolved `package` identifier. Suppressions are persistent and have no expiry.

## Configuration files

Use the same TOML keys in `$XDG_CONFIG_HOME/chainsec/config.toml` (or `$HOME/.config/chainsec/config.toml`), `/etc/chainsec/chainsec.conf`, and project `chainsec.toml`. Only one global file is read: the user configuration takes precedence, and the system file is used only when no user configuration exists. A project key replaces the corresponding global key, including a list or an individual `[artifactories.<ecosystem>]` table. `allowed_hosts` deliberately uses additive semantics instead: project hosts extend global hosts, and `--allow-host` values extend both configuration layers. Duplicate hosts are retained only once, in global/project/CLI order. Therefore, supplying `--allow-host` cannot exclude a host allowed by configuration; update or remove the relevant configured `allowed_hosts` entry when a restrictive host policy is required.

## `chainsec.toml`

```toml
max_package_depth = 3
max_packages = 16384
max_network_requests = 1000
max_redirect_hops = 5
request_timeout_seconds = 30
max_acquisition_seconds = 300
max_archive_size = 104857600
# Also contributes to the aggregate per-acquisition download ceiling, which is
# max_archive_size + max_extracted_size.
max_extracted_size = 524288000
max_extracted_files = 50000
max_file_depth = 128
max_manifest_file_size = 2097152
max_source_file_size = 536870912  # 512 MiB
max_source_files = 100000
max_findings = 100000
max_scan_seconds = 300
# Continue analysis in either mode; true marks recovered parse errors as fatal.
fail_on_parse_error = false

# Network and dependency policy
online = true
allowed_hosts = ["pypi.org", "files.pythonhosted.org", "registry.npmjs.org"]
allow_unlocked = false
trust_local_input = false
# Keep false except for a local loopback development registry. HTTP repositories
# are rejected by default and non-loopback HTTP is never permitted.
allow_insecure_http = false

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
# metadata_base_url = "https://metadata.packages.example/pypi"
# artifact_base_url = "https://artifacts.packages.example/packages"
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

All scalar and list scan options except the target `path`, remote package selector, one-off `--verbose` flag, and `--threads` performance control have corresponding configuration keys: `max_package_depth`, `max_packages`, `max_network_requests`, `max_redirect_hops`, `request_timeout_seconds`, `max_acquisition_seconds`, `max_archive_size`, `max_extracted_size`, `max_extracted_files`, `max_file_depth`, `max_manifest_file_size`, `max_source_file_size`, `max_source_files`, `max_findings`, `max_scan_seconds`, `fail_on_parse_error`, `cache`, `allow_unlocked`, `trust_local_input`, `allow_insecure_http`, `online`, `allowed_hosts`, `rule_packs`, `no_default_rules`, `ignored_rules`, `ignored_paths`, `format`, `fail_on`, and `output`. The `suppressions` table is configuration-only. Size limits in TOML are integer byte counts; the CLI alone accepts human-readable units such as `100MiB`. Unknown keys, malformed rule selectors, empty suppression reasons, and malformed ignored package selectors fail the scan before analysis.

### Artifact repositories

`[artifactories.npm]`, `[artifactories.pypi]`, and `[artifactories.jsr]` decouple package metadata lookup from public registry hosts. Each table supports an npm-, PyPI-, or JSR-compatible proxy or repository manager through its required `metadata_base_url`. PyPI also accepts an optional `artifact_base_url` for repository managers that serve metadata and downloads from different endpoints. Without it, the metadata base remains the artifact-base default; public PyPI defaults to `https://pypi.org/pypi` metadata and `https://files.pythonhosted.org` downloads. These must be absolute HTTPS base URLs; package names and versions are appended as escaped path segments. ChainSec rejects HTTP by default because unlocked resolution obtains both an artifact URL and its integrity digest from registry metadata. Migrate repository managers to HTTPS rather than rewriting their URLs automatically. If a local development registry cannot support TLS, set `allow_insecure_http = true`; HTTP remains limited to the exact configured loopback repository origin and base path (including its port), is warned about, and is exposed in the JSON report policy. An HTTPS repository or unrelated URL cannot redirect into plaintext loopback, and an HTTP repository cannot redirect outside its configured base path. HTTPS redirects and HTTPS CDN/artifact destinations remain subject to the normal host allowlist. When online mode is enabled, configured metadata hosts and the configured PyPI artifact host are automatically allowed. Artifact URLs on any other host returned by metadata still require `allowed_hosts` or `--allow-host`.

For example, an unlocked npm package requests `<npm_metadata_base_url>/<package>`, while an unlocked Python package requests `<pypi_metadata_base_url>/<package>/json`. Locked Python dependencies without a lockfile artifact URL use `<pypi_metadata_base_url>/<package>/<version>/json`; locked Deno `npm:` dependencies retrieve their tarball URL from the configured npm metadata endpoint instead of assuming `registry.npmjs.org`. Each ecosystem’s metadata and release-selection logic is isolated in its fetcher implementation, while network policy, integrity verification, and extraction remain shared.

#### Credentials

Do not place credentials in `chainsec.toml` or repository URLs.

For a compatible repository that uses bearer-token authorization, add its `[artifactories.<ecosystem>.credential]` table. `scope` must be an absolute HTTPS URL, and `bearer_token_env` names the environment variable that contains its token; the token itself is never stored in project configuration. A credential is used only for requests generated from the configured or default artifact repositories when the request has the same scheme, host, port, and a matching path prefix. Lockfile-defined URLs never receive configured credentials. Credentials are re-evaluated on every redirect and are never forwarded solely because the redirect host is allowed. Credentials are never sent to `codeload.github.com`; private GitHub archive acquisition is unsupported.
