# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Before `1.0.0`, minor releases may contain breaking API changes; report schema changes are explicitly versioned.

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
