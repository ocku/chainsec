# Security model

This document defines the `chainsec` security contract. Static analysis reduces risk but is not a malware-containment boundary and does not guarantee that source is benign.

## Threat model

The scan root, manifests, lockfiles, dependency names, URLs, downloaded bytes, archives, cache contents, and source text are untrusted. Trusted components are the `chainsec` binary, its Rust dependencies, configured rules, operating system, DNS/TLS stack, and explicitly configured report destination.

Cache contents may be corrupt or contain malicious filesystem objects before ChainSec starts. Place the configured cache in a directory owned by the scanning principal and not writable by other principals; cache locks coordinate only cooperating ChainSec processes and do not stop a process that ignores the lock protocol. ChainSec compiles only for Unix targets because fetching, extraction, cache, and workspace operations require descriptor-relative filesystem primitives. Each path component is resolved beneath an open directory descriptor with no-follow semantics, preventing a replacement after that root is opened from redirecting those operations.

`chainsec` analyzes `.py`, `.pyi`, `.js`, `.mjs`, `.cjs`, `.ts`, `.mts`, and `.cts` files. Supported declaration and lockfile formats are listed in the README. Unsupported lockfile versions produce errors; unsupported resolution forms do not silently fall back to mutable latest versions.

## Enforced invariants

### Package code is never executed

The acquisition path uses an in-process HTTP(S) client and Rust archive readers. It never invokes package installers, build backends, lifecycle hooks, Git, shells, `tar`, or package executables. Source files are processed only in-process by bounded file-level heuristics and Tree-sitter parsers and queries; they are never executed.

Git acquisition never invokes Git or another subprocess. It is limited to public GitHub repositories pinned to a full 40-hex commit and downloads a chainsec-generated `codeload.github.com` archive URL. **This is an origin-pinned acquisition, not independently content-verified:** GitHub, DNS, TLS, and the codeload service are trusted to bind that URL to the requested commit. The downloaded archive's SHA-256 is recorded only after download and is not supplied by the lockfile, so it cannot authenticate a substituted response. Use an npm/PyPI/JSR artifact with a pinned digest when independent artifact verification is required. Branches, tags, short revisions, other forges, submodules, symlinks, Git LFS objects, and private-repository credentials are unsupported.

### Network is explicit and narrow

Network access defaults off for local scans; `chainsec remote scan` and `chainsec remote diff` automatically enable it. `--online` requires an explicit host allowlist. A `chainsec remote` selector automatically allows only the hosts needed to resolve and download that explicitly requested root package: its configured metadata host, GitHub's archive host for a GitHub remote, and the configured PyPI artifact host for a PyPI remote. Configured Artifactory metadata endpoints, plus an explicitly configured PyPI artifact endpoint, automatically allow their own hosts for online scans. A PyPI metadata response cannot add arbitrary artifact hosts to the allowlist; any host other than the configured endpoint still requires `--allow-host`. Configured npm, PyPI metadata, PyPI artifact, and JSR repository bases, their redirects, and registry-provided artifact URLs must use HTTPS. This prevents unlocked resolution from accepting an attacker-supplied artifact URL and digest from plaintext registry metadata. `allow_insecure_http`/`--allow-insecure-http` is an explicit development-only exception limited to the exact origin, port, and path of a configured loopback repository base; it emits a warning and is recorded in report policy metadata. Plaintext permission is scoped from the initial configured repository URL and cannot be gained through a redirect: HTTPS-to-HTTP loopback downgrades and redirects outside the configured HTTP repository base are rejected. HTTPS repository and CDN redirects retain the normal host-allowlist and per-redirect credential checks. Locked artifact URLs and Deno URL modules retain the general HTTP(S) scheme policy, because their integrity is established independently by a lockfile or declared digest. Every initial URL, Deno graph URL, and redirect target is checked against the allowlist; redirect count, request duration, declared and observed response size, and Deno graph size are bounded. Ambient HTTP proxy settings are disabled so proxy credentials and routing are not inherited.

For example, a mirror may explicitly configure `metadata_base_url = "https://metadata.packages.example/pypi"` and `artifact_base_url = "https://artifacts.packages.example/packages"`; those two hosts are authorized, while a third host in returned metadata is not. Host allowlisting does not defend against compromise of an allowed registry, DNS, certificate authorities, or the TLS implementation. Use narrow exact hosts instead of wildcards. Configured bearer credentials are read only from named environment variables, scoped to their configured URL prefix, and re-evaluated on redirects; they are never sent to GitHub's archive host.

### Resolution and integrity fail closed

Deno graph resolution is syntax-aware. Static string literals in JavaScript/TypeScript `import` declarations, export-from declarations, and dynamic `import()` calls are considered. Absolute HTTP(S) literals and URL-relative literals are followed as HTTP(S) URL modules. Any discovered static literal that cannot be materialized—including bare, `npm:`, `jsr:`, `node:`, `data:`, other non-HTTP schemes, custom-loader, and invalid URL-relative specifiers—fails with a `Deno graph resolution` policy error rather than allowing an incomplete successful graph. Computed/template expressions and escaped literals are not static-literal inputs to graph resolution. This prevents a package name or runtime-controlled value from being interpreted as a network URL while ensuring supported static URL-module graphs are complete. A root-only HTTP(S) graph may use its declared root integrity without a Deno lockfile. Every non-root HTTP(S) module requires a matching `remote` lockfile integrity entry; when a lockfile is provided, its root entry is also required in addition to the declared root integrity.

Supported registry lockfiles provide exact versions and integrity. Resolved version plus integrity form canonical package identity for cycle detection and cache keys. Registry archives are verified before extraction. JSR lock integrity verifies the exact package manifest and every downloaded file is checked against that manifest. The sole no-independent-digest exception is a canonical GitHub commit archive: HTTPS, host `codeload.github.com` (without credentials, query, fragment, or a non-443 port), and exactly `/{owner}/{repository}/tar.gz/{40-hex-commit}`. ChainSec reconstructs that canonical URL before downloading it, but does not verify the returned archive against a trusted tree or archive digest; it trusts GitHub, DNS, TLS, and codeload to bind the URL to the full commit. Every other remote artifact requires a verified digest before extraction. A mutable declaration absent from its lockfile is a policy issue by default.

`--allow-unlocked` relaxes traversal policy but does not allow unverified remote artifacts. For registry-backed Python requirements, the fetcher queries PyPI, selects the highest matching release with a non-yanked source distribution, and pins that sdist's URL and published SHA-256 before downloading it. Wheel-only releases are not selected because choosing one without a declared Python, ABI, operating-system, and architecture target could analyze a different artifact from the one an installer chooses; an exact wheel identified by a supported lockfile SHA-256 remains fetchable. For npm requirements and Deno `npm:` specifiers, it queries the npm registry, selects the highest matching non-yanked release for Node-compatible semver requirements, and pins the release tarball and published supported SRI integrity (SHA-256 or SHA-512). When an integrity value lists multiple supported algorithms, verification uses the strongest one listed. Named distribution tags retain their exact target semantics: a tag that targets a yanked release fails resolution rather than selecting another release. Other unlocked remote forms remain unresolved. Local `file:`/path dependencies are marked local/unverified and are never copied into the cache. Their canonical path must remain beneath the declaring package unless the operator explicitly supplies `--trust-local-input`.

### Extraction is confined and bounded

ZIP/wheel and tar-family extraction rejects absolute paths, traversal, symlinks, hard links, special files, and duplicate paths. Tar-family paths are limited to 128 components; ZIP/wheel paths are confined with archive-library traversal checks but do not currently have the same explicit component-depth limit. Extraction creates only regular files/directories beneath a new temporary entry and enforces expanded byte and file limits. Cache publication occurs only after successful verification and extraction.

The current implementation does not separately constrain compression ratio or individual path byte length; total downloaded/expanded bytes and nesting are bounded. ZIP/wheel nesting is not independently capped by a component-count limit.

### Cache is not trusted

Cache keys are SHA-256 hashes of ecosystem, canonical name, resolved version/revision, integrity, and any source URL pinned before acquisition; Deno HTTP graph keys also include an immutable parsed snapshot digest of the applicable lockfile. Retained entries are copied into temporary sibling directories and renamed only after a completion manifest is written. On Unix, each active fetcher records its cache root identity when it acquires the lifecycle lock and rechecks it before cache acquisition, staging, and purge mutations. A detected rename or symlink replacement of the configured cache path fails closed instead of continuing against the replacement. Publication uses a per-identity cross-process lock, while a cache-wide lifecycle lock at `<cache>/.lock` coordinates active fetchers with cache purge. Purge holds that lock exclusively while removing every other child of the anchored cache directory. A valid existing winner is retained and the losing publisher discards only its own staging directory; an invalid or incomplete entry is atomically renamed aside and replaced while the exclusive lock prevents cooperating cache readers from traversing it. Cache reads reject stable symlinked cache components, entries, and markers, as well as malformed completion metadata and package identity mismatches. Restoration type is derived from trusted dependency semantics rather than completion metadata.

Registry archives are retained in the cache. Every hit revalidates the retained archive against lockfile or registry integrity and safely re-extracts it into a unique owner-only workspace outside the cache, under the platform temporary directory, for the lifetime of the `SourceFetcher`. Thus neither extracted source nor completion metadata is trusted as authentication evidence, and cache-root mutations after restoration cannot alter scanner-visible files. JSR entries similarly retain the integrity-bound package manifest and reconstruct only files matching its checksums. Deno HTTP graphs reconstruct modules against the exact parsed lockfile snapshot used for batch deduplication and the cache key; non-root modules without lockfile integrity bindings are rejected both online and during cache reconstruction. Full GitHub commit references pin the request URL but provide no independent archive digest, so GitHub cache entries are not reused.

Concurrent ChainSec processes may independently download or reconstruct the same identity. Shared entry locks protect reconstruction; exclusive entry locks serialize validation and publication. Valid entries are never replaced, while corrupt entries can be quarantined and refreshed without racing a cooperating reader. Per-fetch workspaces are never publication destinations and are removed when their owning `SourceFetcher` is dropped.

### Scanning is bounded

Defaults:

| Limit | Scope | Default |
| --- | --- | ---: |
| Dependency depth | Entire traversal | 3 |
| Packages | One traversal, or the aggregate unique roots/acquisitions in a remote diff batch | 500 |
| Network requests | Each package acquisition, including redirects and JSR files | 1,000 |
| Network acquisition duration | Each package acquisition end to end | 300 seconds |
| Downloaded artifact | Each HTTP response/artifact | 100 MiB |
| Expanded artifact | Each acquired package/graph | 500 MiB |
| Extracted files | Each acquired package/graph | 50,000 |
| Source file | Each source file | 2 MiB |
| Source files | Each package scan | 100,000 |
| Findings | Each package scan | 100,000 |
| Scan duration | Each package scan | 300 seconds |
| Deno URL modules | Each Deno URL graph | 1,000 |
| Redirects | Each HTTP request chain | 5 |
| HTTP request timeout | Each request | 30 seconds |

Directory symlinks are not followed. `.git`, `.chainsec-cache`, `node_modules`, `target`, virtual environments, and Python bytecode cache directories are excluded. There is no overall wall-clock deadline across the complete dependency traversal; per-package scan duration, per-package acquisition duration, and request limits do not bound the total time of a multi-package scan. Acquisition counters and deadlines are created per package rather than globally, so concurrent package work does not consume another package’s budget.

## Data and report contract

JSON scan schema `1.2.0` is documented in `docs/schema/report.schema.json`; version-diff schema `1.0.0` is documented in `docs/schema/version-diff.schema.json`. Findings have stable content-derived IDs, versioned rule IDs, package identifiers, matched code, and source locations. Resolved version, source URL, digest, and source path are recorded in separate package records and linked to findings through the finding's package identifier. The `capabilities` array records informational behavior and its evidence separately from findings. Failures are structured issues with a code, operation, package, message, and fatality rather than findings. `--ignore-rule` omits matching `group:rule-id-glob` selectors from reports; ignored selectors are not represented in the current report schema. Persistent `[[suppressions]]` mark matching findings as suppressed and record their required reason in JSON; suppressed findings are excluded from human and SARIF reports and do not affect the failure threshold.

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
- An overall multi-package wall-clock deadline, memory limits, or parser sandboxing.
- Non-Unix targets; ChainSec requires descriptor-relative no-follow confinement and does not compile for them.
- Baseline files, per-finding suppression semantics, or report metadata that records `--ignore-rule` configuration. `--ignore-rule` can omit a rule globally; custom JSON/YAML rule packs are trusted configuration and their Tree-sitter queries run in-process.
