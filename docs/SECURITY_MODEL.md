# Security model

This document defines the `chainsec` security contract. Static analysis reduces risk but is not a malware-containment boundary and does not guarantee that source is benign.

## Threat model

The scan root, manifests, lockfiles, dependency names, URLs, downloaded bytes, archives, cache contents, and source text are untrusted. Trusted components are the `chainsec` binary, its Rust dependencies, configured rules, operating system, DNS/TLS stack, and explicitly configured report destination.

`chainsec` analyzes `.py`, `.pyx`, `.pyi`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, and `.cts` files. Supported declaration and lockfile formats are listed in the README. Unsupported lockfile versions produce errors; unsupported resolution forms do not silently fall back to mutable latest versions.

## Enforced invariants

### Package code is never executed

The acquisition path uses an in-process HTTP(S) client and Rust archive readers. It never invokes package installers, build backends, lifecycle hooks, Git, shells, `tar`, or package executables. Source files are processed only in-process by bounded file-level heuristics and Tree-sitter parsers and queries; they are never executed.

Git acquisition never invokes Git or another subprocess. It is limited to public GitHub repositories pinned to a full 40-hex commit and downloads a chainsec-generated `codeload.github.com` archive URL. GitHub, DNS, TLS, and the codeload service are trusted to bind that URL to the requested commit; the downloaded archive's SHA-256 is recorded but is not supplied by the lockfile. Branches, tags, short revisions, other forges, submodules, symlinks, Git LFS objects, and private-repository credentials are unsupported.

### Network is explicit and narrow

Network access defaults off for local scans; `--remote` automatically enables it. `--online` requires an explicit host allowlist. A `--remote` selector automatically allows only the hosts needed to resolve and download that explicitly requested root package: its configured metadata host, GitHub's archive host for a GitHub remote, and the configured PyPI artifact host for a PyPI remote. The PyPI artifact host is not automatically allowed for local/project scans and must otherwise be supplied explicitly with `--allow-host`. Configured Artifactory metadata endpoints automatically allow their own hosts. HTTP and HTTPS are accepted; no other schemes are permitted. Every initial URL, Deno graph URL, and redirect target is checked against the allowlist; redirect count, request duration, declared and observed response size, and Deno graph size are bounded. Ambient HTTP proxy settings are disabled so proxy credentials and routing are not inherited. HTTP transfers are plaintext and provide no transport confidentiality or server authentication; use HTTPS unless an explicitly allowed HTTP source is trusted through another channel (for example, a verified lockfile integrity digest).

Host allowlisting does not defend against compromise of an allowed registry, DNS, certificate authorities, or the TLS implementation. Use narrow exact hosts instead of wildcards. Configured bearer credentials are read only from named environment variables, scoped to their configured URL prefix, and re-evaluated on redirects; they are never sent to GitHub's archive host.

### Resolution and integrity fail closed

Deno graph resolution is syntax-aware. Static string literals in JavaScript/TypeScript `import` declarations, export-from declarations, and dynamic `import()` calls are considered. Absolute HTTP(S) literals and URL-relative literals are followed as HTTP(S) URL modules; bare specifiers, `npm:`, `jsr:`, computed/template expressions, non-HTTP(S) schemes, and custom-loader specifiers are not expanded into URL modules. This prevents a package name or runtime-controlled value from being interpreted as a network URL while still covering the complete static URL-module surface supported by the graph fetcher.

Supported registry lockfiles provide exact versions and integrity. Resolved version plus integrity form canonical package identity for cycle detection and cache keys. Registry archives are verified before extraction. JSR lock integrity verifies the exact package manifest and every downloaded file is checked against that manifest. The narrow GitHub path instead uses a full immutable commit identity and the GitHub trust boundary described above. A mutable declaration absent from its lockfile is a policy issue by default.

`--allow-unlocked` relaxes traversal policy but does not allow unverified remote artifacts. For registry-backed Python requirements, the fetcher queries PyPI, selects the highest matching non-yanked release, and pins the selected artifact URL and published SHA-256 before downloading it. For npm requirements and Deno `npm:` specifiers, it queries the npm registry, applies Node-compatible semver or a named distribution tag, and pins the release tarball and published SHA-256/SHA-512 integrity. Other unlocked remote forms remain unresolved. Local `file:`/path dependencies are marked local/unverified and are never copied into the cache. Their canonical path must remain beneath the declaring package unless the operator explicitly supplies `--trust-local-input`.

### Extraction is confined and bounded

ZIP/wheel and tar-family extraction rejects absolute paths, traversal, symlinks, hard links, special files, and duplicate paths. Tar-family paths are limited to 128 components; ZIP/wheel paths are confined with archive-library traversal checks but do not currently have the same explicit component-depth limit. Extraction creates only regular files/directories beneath a new temporary entry and enforces expanded byte and file limits. Cache publication occurs only after successful verification and extraction.

The current implementation does not separately constrain compression ratio or individual path byte length; total downloaded/expanded bytes and nesting are bounded. ZIP/wheel nesting is not independently capped by a component-count limit.

### Cache is not trusted

Cache keys are SHA-256 hashes of ecosystem, canonical name, resolved version/revision, and integrity. Entries are built in temporary sibling directories and atomically renamed only after a completion manifest is written. Cache reads reject symlinked entries/markers, unsafe metadata paths, package identity mismatches, source escapes, and changes to a deterministic digest of the extracted source tree.

Concurrent processes may independently download the same missing entry; one publication can replace another complete entry. Both must have the same resolved identity and verified content, but cross-process locking is not currently provided.

### Scanning is bounded

Defaults:

| Limit | Scope | Default |
| --- | --- | ---: |
| Dependency depth | Entire traversal | 3 |
| Packages | Entire traversal | 500 |
| Downloaded artifact | Each HTTP response/artifact | 100 MiB |
| Expanded artifact | Each acquired package/graph | 500 MiB |
| Extracted files | Each acquired package/graph | 50,000 |
| Source file | Each source file | 2 MiB |
| Source files | Each package scan | 100,000 |
| Scan duration | Each package scan | 300 seconds |
| Deno URL modules | Each Deno URL graph | 1,000 |
| Redirects | Each HTTP request chain | 5 |
| HTTP request timeout | Each request | 30 seconds |

Directory symlinks are not followed. `.git`, `.chainsec-cache`, `node_modules`, `target`, virtual environments, and Python bytecode cache directories are excluded. There is no overall wall-clock deadline across the complete dependency traversal; per-package scan duration and per-request/network limits do not bound the total time of a multi-package scan.

## Data and report contract

JSON schema `1.1.0` is documented in `docs/schema/report.schema.json`. Findings have stable content-derived IDs, versioned rule IDs, package identifiers, matched code, and source locations. Resolved version, source URL, digest, and source path are recorded in separate package records and linked to findings through the finding's package identifier. The `capabilities` array records informational behavior and its evidence separately from findings. Failures are structured issues with a code, operation, package, message, and fatality rather than findings. `--ignore-rule` omits matching `group:rule-id-glob` selectors from reports; ignored selectors are not represented in the current report schema. Persistent `[[suppressions]]` mark matching findings as suppressed and record their required reason in JSON; suppressed findings are excluded from human and SARIF reports and do not affect the failure threshold.

Reports may be partial: manifest, resolution, fetch, extraction, and scan failures are normally added to `issues` while traversal continues for other packages. Invalid configuration or failures before a report can be created may produce only an error on stderr. With `--output`, the report is written directly to the requested path rather than atomically renamed; parent directories must already exist, and a write failure exits with code `3`.

JSON reports may expose absolute root/cache paths, dependency URLs, matched source snippets, and code that contains secrets. Treat reports as sensitive. SARIF output uses finding paths relative to each scanned package and includes finding rationale, rule metadata, locations, and stable IDs; it does not include `matched_code` snippets.

In addition to Tree-sitter source rules, scanning applies bounded file-level checks to every file. Supported source files are read in full, subject to the per-source-file size limit; non-source files are limited to a 1 MiB prefix. The checks may flag recognized compressed formats, binary data, and high entropy. They do not decode, execute, disassemble, or semantically analyze native code.

Within schema major version `1`, fields may be added, but existing field meanings and types must not change. Breaking changes require a new schema major version and changelog entry.

## Maintainer security checklist

Before publishing a release, complete this checklist:

- [ ] Run `cargo fmt --all --check`.
- [ ] Run `cargo clippy --all-targets --all-features --locked -- -D warnings`.
- [ ] Run `cargo test --all-targets --all-features --locked`.
- [ ] Run `cargo build --release --locked`.
- [ ] Run `cargo audit` against the committed `Cargo.lock`.
- [ ] Triage every audit advisory; do not silently suppress one.
- [ ] Review every dependency and lockfile change.
- [ ] Confirm the invariants in this document still hold after the release's changes.
- [ ] Create the source-only release from a clean, reviewed commit using the pinned Rust toolchain.
- [ ] Confirm the release tag, package version, lockfile package version, and changelog version agree.
- [ ] Record security fixes in the changelog and release notes.

## Remaining boundaries and unsupported behavior

`chainsec` does not provide:

- Complete malicious-code detection, semantic data-flow analysis, native/binary semantic inspection, runtime behavior analysis, or vulnerability matching. File-level heuristics can flag binary, compressed, and high-entropy files, but do not analyze native code.
- Python requirements lock parsing, complete npm/Python workspace semantics, Yarn Berry cache-archive acquisition, or Git acquisition outside public GitHub full-commit references.
- Evaluation of Python environment markers/extras against a target platform.

- Registry signatures, Sigstore/TUF provenance, or resistance to a compromised allowed registry.
- Cross-process cache locking, an overall multi-package wall-clock deadline, memory limits, or parser sandboxing.
- Baseline files, per-finding suppression semantics, or report metadata that records `--ignore-rule` configuration. `--ignore-rule` can omit a rule globally; custom JSON/YAML rule packs are trusted configuration and their Tree-sitter queries run in-process.
