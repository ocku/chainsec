# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Before `1.0.0`, minor releases may contain breaking API changes; report schema changes are explicitly versioned.


## [0.3.0]

### Breaking changes

- JSON report schema is now `1.1.0`. Reports include a required `capabilities` array; consumers that validate the schema or reject unknown fields must update accordingly.
- Built-in rule IDs now use the `chainsec.*` namespace and rule selectors use canonical finding-type groups. Update `--ignore-rule`, `ignored_rules`, and integrations that match rule IDs.
- Human reports now show only unsuppressed findings at or above `--fail-on` by default, followed by capability and alert summaries. Use `--verbose` to include lower-severity findings.

### Added

- Structured, informational capability reporting for network, filesystem, process, browser-profile, clipboard, and code-execution behavior, with evidence available in JSON reports.
- `--verbose` to include findings below the configured `--fail-on` threshold in human-readable reports.
- Repeated `--ignore-path <GLOB>` root-project exclusions, with `--exclude-path` as a compatibility alias. Persistent exclusions remain available through `ignored_paths` in configuration.
- Persistent `[[suppressions]]`, which retain a required reason in JSON and exclude matching findings from human and SARIF reports and the failure threshold.
- Bounded semantic matchers for JavaScript and TypeScript dynamic execution, string-table obfuscation, RC4-like decoders, and embedded bytecode virtual machines.
- Expanded built-in detection for indirect/computed `eval`, string timers, Node VM APIs, Python reflective import access, Deno network APIs, browser-global mutation, and common code-obfuscation patterns.
- Expanded unit, integration, CLI, semantic-matcher, and fixture coverage for the new reporting, traversal, suppression, exclusion, and rule behaviors.

### Changed

- Analyze packages concurrently by dependency depth while preserving bounded fetching, deterministic report output, and package limits.
- Summarize unique capabilities and alerts in human-readable output; JSON contains all findings and capabilities, while SARIF contains unsuppressed findings.

## [0.2.1]

### Fixed

- Accept Deno lockfile version 5 for locked dependency resolution.

## [0.2.0]

### Breaking changes

- Human-readable output is now the default. Automation that consumes reports must explicitly use `--format json` (or `--format sarif`). Human finding lines now include the package identifier.

### Added

- `--remote <source:package>` for scanning an npm, PyPI, JSR, or public GitHub full-commit package as the traversal root. Remote roots resolve without a lockfile; discovered dependencies retain the normal lockfile policy.
- Layered configuration: `$HOME/.config/chainsec/config.toml` is overlaid by project `chainsec.toml`, with command-line values taking precedence. The legacy global `chainsec.toml` filename remains supported.
- Configurable npm, PyPI, and JSR metadata endpoints for registry proxies and artifact repositories, with scoped bearer tokens sourced from named environment variables.
- PDM lockfile (`pdm.lock`) resolution for Python dependencies.
- `/etc/chainsec/chainsec.toml` as a machine-wide configuration fallback when neither a user-local nor project `chainsec.toml` is available.
- `--cache-purge` to remove the resolved dependency cache without scanning; pair it with `--cache <dir>` to purge a specific cache.

### Changed

- HTTP acquisition is asynchronous; redirects are manually policy-checked and credential scope is re-evaluated at each hop.
- Cache validation now verifies completion metadata, source identity and limits, safe extracted-tree structure, and a deterministic content-tree digest on each hit.
- Source reads enforce the configured byte limit while reading, and scan-duration checks run throughout traversal and analysis.
- Reorganized CLI/application, acquisition, manifest-resolution, and scanner modules into focused components.
- The default dependency cache remains `.chainsec-cache` for a current working directory with `chainsec.toml`; other invocations now use the XDG/user cache directory, falling back to the system temporary directory. `--init` adds `.chainsec-cache` to `.gitignore`.
- `allowed_hosts` now accumulates across global configuration, project configuration, and repeated `--allow-host` options, with duplicate hosts removed in that order.
- `--remote` now enables online mode automatically; online mode without allowed hosts remains valid for local-only scans, while every outbound request remains host-policy checked.

## [0.1.0]

### Changed

- Allow explicitly allowlisted HTTP sources in addition to HTTPS; HTTP remains plaintext and is called out in the security model.
- Clarify that bounded file-level heuristics run on every scanned file, while Tree-sitter rules run only on supported source files.
- Detect bare `atob(...)` calls in JavaScript and TypeScript in addition to member-expression forms such as `window.atob(...)`.

### Security

- Update the locked `bytes` dependency to 1.11.1 to resolve `RUSTSEC-2026-0007` (integer overflow in `BytesMut::reserve`).

### Added

- Repeatable `--ignore-rule <GROUP:GLOB>` CLI option for omitting rule groups or matching rule IDs from scans and reports. `--exclude-rule` remains a compatibility alias.
- Lock-aware resolution for Poetry, Pipfile, uv, npm lock/shrinkwrap versions 1–3, Yarn Classic/Berry, pnpm 5.3/5.4/6/9, and Deno lock versions 1–4.
- In-process HTTP(S) acquisition with offline defaults, host/redirect policy, finite timeouts, response limits, and integrity verification.
- Safe wheel, ZIP, and tar-family extraction with traversal, link, special-file, duplicate-path, depth, count, and expanded-byte controls.
- Bounded Deno HTTP(S) module graphs with syntax-aware JavaScript/TypeScript module resolution, locked Deno npm acquisition, and manifest/per-file verified JSR acquisition.
- Public GitHub dependency acquisition for full immutable commit references without invoking Git.
- Custom JSON/YAML rule packs with strict validation and CLI controls.
- Content-identified atomic cache entries with completion metadata and extracted-tree validation.
- Typed errors, structured operational issues, resolved package provenance, stable finding IDs, confidence, remediation, and report schema `1.0.0`.
- JSON, terminal, and SARIF reports with documented CI exit codes.
- Versioned rules for execution, process, network, filesystem, secret, deserialization, loading, and obfuscation patterns.
- Tree-sitter equivalents for applicable GuardDog source-code analyzers across Python, JavaScript, and TypeScript.
- Syntax-aware high-entropy string detection for potentially encrypted or packed literals.
- Configurable package, depth, artifact, extraction, source-file, and scan-duration limits.
- Fixture-based unit, integration, malicious-archive, and compiled-CLI tests.
- Cross-platform CI for formatting, Clippy, tests, release builds, and dependency auditing.
- Security model and vulnerability reporting policy.
- Per-rule fixture tests covering every built-in rule.
- Initial recursive Python, JavaScript, and TypeScript source scanner skeleton.
