# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Before the `chainsec` tool reaches `1.0.0`, minor releases and minor report schema revisions may contain documented breaking changes. Each report schema version is an exact contract: consumers must check the full `schema_version` rather than assume versions with the same major number are compatible. Every schema revision requires explicit changelog and migration notes.


## [0.5.3]

### Changed

- Reorganized the application layer around an explicit `src/app/core` module. `src/app/pipeline.rs` became `src/app/core/orchestration.rs`, and suppression parsing/matching moved into `src/app/core/suppressions.rs`, so presentation modules no longer coordinate the engine and fetcher directly.
- Replaced the README's summary architecture diagram with a descriptive functional map showing the end-to-end scan, fetch, traversal, finalization, and output flow.
- Documented `src/app/core` in the development architecture reference.


## [0.5.2]

### Changed

- Recalibrated rule risk levels across all languages: arbitrary code execution, dynamic loading, and process execution detection and capability rules are now `Medium` (was `High`); `write-browser-global` is now `High` (was `Medium`); `hidden-require` is now `Critical` (was `High`); and file analyzer findings for compressed archives, native artifacts, and unrecognized binary files are now `Critical` (was `High`).
- Version-diff finding identity now matches on package, rule ID and version, file path, and matched code only, without exact line and column positions, so relocated identical code is no longer reported as a separate change.


## [0.5.1]

### Changed

- Human scan output now presents each finding across multiple lines with its risk, rule group and ID, package, file location, and full matched code snippet.
- Remote version-diff human output now lists individual added and removed findings with their locations and code snippets before the aggregate summary. Removed findings are shown before added findings, and package names are displayed without their integrity digest.


## [0.5.0]

### Breaking changes

- JSON report schema is now `1.2.0`, a breaking migration from `1.1.0`; consumers must require and explicitly support the full `schema_version`. In `policy.limits`, migrate `max_depth` to `max_package_depth`, `max_archive_bytes` to `max_archive_size`, `max_extracted_bytes` to `max_extracted_size`, and `max_source_file_bytes` to `max_source_file_size`; the legacy names are not part of schema `1.2.0`. The limits contract also requires `max_network_requests`, `max_redirect_hops`, `request_timeout_seconds`, `max_acquisition_seconds`, `max_file_depth`, `max_manifest_file_size`, `max_findings`, and `fail_on_parse_error`, and `policy` requires `allow_insecure_http`. Capability evidence records now require the same stable ID, rule metadata, risk, confidence, and suppression state as findings. Update validators and field mappings before accepting `1.2.0` reports.
- Replaced the flat CLI with explicit subcommands. Use `chainsec scan [PATH]` instead of `chainsec [PATH]`, `chainsec remote scan <SOURCE:PACKAGE>` instead of `chainsec --remote <SOURCE:PACKAGE>`, `chainsec init [PATH]` instead of `chainsec [PATH] --init`, and `chainsec cache purge` instead of `chainsec --cache-purge`. Scan options now follow the applicable `scan` or `remote` subcommand.
- `--allow-host` is now additive: it extends `allowed_hosts` from global and project configuration rather than replacing them. Supplying `--allow-host` cannot exclude a host allowed by configuration; update or remove the relevant configured `allowed_hosts` entry when a restrictive host policy is required.
- `--max-packages` now defaults to `4096` (was `500`), and `--max-source-file-size` now defaults to `20 MiB` (was `2 MiB`). New limits `--max-network-requests`, `--max-acquisition-seconds`, `--max-file-depth`, `--max-manifest-file-size`, and `--max-findings` are introduced with conservative defaults.
- Recovered source syntax errors are now logged at debug level by default instead of being reported as warnings. `--fail-on-parse-error` (or `fail_on_parse_error = true`) still records them as fatal operational issues without stopping recovered-tree analysis.
- Yarn Berry lockfiles are now rejected rather than parsed. Berry `npm:` lock entries pin the exact release, but their cache checksums are not npm tarball integrity values. ChainSec obtains the pinned release's tarball URL and integrity from the configured npm registry before download, so scans need `--online` and the registry host must be allowed.
- Windows CI has been removed. ChainSec compiles only for Unix targets because fetching, extraction, cache, and workspace operations require descriptor-relative no-follow filesystem primitives.

### Added

- `chainsec remote diff <source:package>` with exactly one version selector: `--last <N>` (minimum 2) scans the newest pullable releases, `--compare <FROM> <TO>` scans only the exact endpoints, and `--range <FROM> <TO>` scans every pullable published version in the inclusive interval and compares adjacent releases. npm, PyPI, and JSR are supported; human output uses compact counted sections with bold signed totals and indented version histories, while JSON reports structured adjacent comparisons. The convenience form `chainsec remote scan <source:package> --diff <N>` has the same behavior as `--last <N>`.
- JSON version-diff report schema `1.0.0` in `docs/schema/version-diff.schema.json` with `report_type: "version_diff"`. The `versions` array is newest-first, while each entry in `diffs` compares an adjacent older `from_version` to newer `to_version`. Detection changes contain counts grouped by finding group, rule ID, and risk; capability changes contain evidence counts grouped by capability name.
- `--allow-insecure-http`/`allow_insecure_http = true` development-only opt-in for plaintext HTTP loopback artifact repositories. HTTP repositories are rejected by default; non-loopback HTTP is never permitted. The opt-in is recorded in JSON report policy.
- `--fail-on-parse-error`/`fail_on_parse_error` to mark Tree-sitter-recovered syntax errors as fatal operational issues. ChainSec still analyzes the recovered syntax tree, retains any findings, and continues scanning other files and packages.
- `--max-network-requests`, `--max-acquisition-seconds`, `--max-file-depth`, `--max-manifest-file-size`, and `--max-findings` resource controls with conservative defaults.
- `--max-redirect-hops` and `--request-timeout-seconds` for finer-grained network policy.
- PyPI `artifact_base_url` configuration for repository managers that serve metadata and downloads from different endpoints.
- Docker-based GitHub Action in `action.yml` for running `chainsec remote diff` from consuming workflows. It compares the latest published releases of a `npm:`, `pypi:`, or `jsr:` package selector, applies the repository's `chainsec.toml` policy, and defaults to `--last 2 --max-package-depth 2`.
- `docs/GITHUB_ACTION.md` reference covering action inputs, configuration merging, version-diff semantics, exit codes, JSON output, and caching.
- Repositioned `chainsec` as a dependency chain supply auditing tool that can also be used as a CI component.

### Changed

- Remote version diffs now download selected roots and acquire their deduplicated dependency union before scanning each unique package source once, while preserving independent per-version reports. The number of selected roots is bounded by `--max-packages` before any root artifacts are downloaded, and aggregate unique roots/dependency acquisitions across the batch share that same bound.
- Registry cache hits now revalidate retained artifacts and safely reconstruct source into fetcher-owned workspaces instead of trusting extracted trees or completion metadata. Retained cache publication uses per-entry locks, preserves valid winners, and atomically quarantines/replaces invalid destinations without racing cache readers. JSR and Deno graph entries are reconstructed from their integrity-bound manifests or lockfile snapshots. Full GitHub commit references have no independent archive digest, so their cache entries are no longer reused.
- Deno URL graph resolution is now fail-closed: any static literal that cannot be materialized—including bare, `npm:`, `jsr:`, `node:`, `data:`, other non-HTTP schemes, custom-loader, or invalid URL-relative specifiers—fails the fetch with a `Deno graph resolution` policy error. A root-only HTTP(S) graph can be acquired with the declared root integrity and no lockfile. A multi-module HTTP(S) graph requires `deno.lock` `remote` integrity entries for every fetched module.
- Tar-family, ZIP/wheel, JSR, and local dependency snapshot paths now share the configured path-component depth limit (128 by default).
- Configured npm, PyPI metadata, PyPI artifact, and JSR repository bases, their redirects, and registry-provided artifact URLs must use HTTPS. Locked artifact URLs remain subject to the normal HTTP(S) and host policy.
- `--max-network-requests` and `--max-acquisition-seconds` apply separately to each package acquisition and include redirects and JSR's manifest-driven per-file downloads; concurrent packages do not share counters or deadlines.
- `--max-packages` caps each ordinary traversal and, for a remote version diff, both selected roots and aggregate unique root/dependency work across the whole batch.
- Manifest and lockfile reads now share one 2 MiB boundary across Python, npm, and Deno parsers. npm and Deno workspace enumeration share the configured dependency-depth and source-file-count budgets.
- Cache purge now retains the cache directory and its internal lifecycle lock, so fetchers and purge operations continue to coordinate on one stable lock without creating a sibling file.
- The cache FAQ now includes guidance on securing the cache directory and explains Unix descriptor-relative no-follow confinement.
- `flate2` now uses `zlib-rs` instead of the system zlib. `libc` and `tempfile` are now direct dependencies. `tree-sitter` is updated to 0.26.12. `rcgen` and `rustls` are added as dev-dependencies for TLS test infrastructure.
- Dev builds now use `opt-level = 3` for faster local iteration.

### Security

- Require PyPI metadata-based release selection to use a non-yanked, SHA-256-pinned source distribution instead of choosing an arbitrary wheel that may not match the install target. Exact lockfile-integrity-pinned wheels remain supported.
- Reject plaintext HTTP configured npm, PyPI, and JSR repository transports by default, including redirects and registry-provided artifact URLs. A visible `--allow-insecure-http`/`allow_insecure_http` development-only opt-in is limited to localhost and loopback IPs and recorded in JSON report policy.
- Snapshot Deno lockfiles once per prepared batch request/acquisition so deduplication, graph verification, and cache addressing cannot observe different lockfile contents.
- Compile Tree-sitter queries before batch dependency acquisition, preventing network and cache side effects for malformed rule catalogs.
- Reconstruct cache hits only from integrity-verified artifacts, preventing modified cache trees and metadata from substituting analyzed source.
- Store lifecycle and per-identity coordination in sibling `<cache>.locks`, with active fetchers holding `lifecycle.lock` shared and purge holding it exclusively. Keep each fetcher's cache operations relative to its pinned open directory, so a later pathname rename or replacement cannot redirect the fetcher and does not make it fail closed; after lifecycle coordination, a later purge clears the regular directory it opened at the configured cache path rather than the detached original. These locks coordinate only cooperating ChainSec processes.
- Bound ZIP size verification to one byte beyond the declared size and count implicit archive parent directories, preventing malformed compressed streams and deeply nested entries from bypassing extraction limits.
- Keep local and otherwise unverified package sources distinct during traversal, preventing equal declaration-derived package IDs from suppressing analysis of different source trees.
- Reject Yarn Berry lockfiles rather than treating their cache checksums as independently verifiable npm artifact integrity.
- Validate that the opened cache root is owned by the effective user and is not group- or world-writable, and that the lock directory is owned by the effective user with mode `0700`.

### Fixed

- Preserve a deterministic highest-risk partial result when finding or capability-evidence limits are exceeded, report truncation explicitly, and prevent lower-risk install hooks from displacing Critical source findings.
- Honor configured analysis concurrency for dependency downloads and use hash-indexed traversal deduplication instead of quadratic frontier scans.
- Resolve npm workspace local dependencies relative to the member that declares them, including package-lock, pnpm, and Yarn enrichment, while retaining the member's confinement boundary.
- Resolve pnpm workspace links relative to their importer, accept compatible Poetry 2.x lock schemas, and retain compatibility aliases for configuration keys generated by 0.4.
- Union independent inherited Python lock resolutions without retaining unresolved cross-context copies, and reject unsupported Pipfile direct-source tables instead of treating them as registry requirements.
- Return exit code `3` for pre-report manifest, scan, resolution, fetch, extraction, and I/O failures while reserving `2` for invalid configuration and `4` for policy or resource-limit violations.
- Reuse integrity-verified JSR cache entries offline when packages were fetched through a configured repository mirror.
- Keep distinct Deno `npm:` requirements separate during batch acquisition even when aliases and pre-resolution package IDs collide.
- Compare endpoint finding occurrence identities for diff exit policy, preventing equal grouped counts from hiding a removed-and-replaced threshold finding.
- Roll back a newly created `chainsec.toml` when initialization cannot update `.gitignore`.
- Return manifest errors for malformed npm dependency sections instead of silently omitting their declarations.
- Discover dependencies declared in Poetry dependency groups and legacy `dev-dependencies`.