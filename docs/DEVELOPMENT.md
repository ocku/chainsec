# Development and releases

Every push and pull request runs formatting, Clippy with warnings denied, locked tests, and a locked release build on Linux, macOS, and Windows. Ubuntu CI also runs `cargo audit` against the committed `Cargo.lock`; an audit failure blocks the workflow and must be triaged before merging.

## Local checks

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo build --release --locked
cargo audit
```

## Releases

Releases are source-only and are created manually from a clean, reviewed commit. The release tag, `Cargo.toml` version, `Cargo.lock` package version, and exact `## [VERSION]` changelog heading must agree. Run the complete local checklist with the repository's pinned Rust toolchain before creating the tag, then publish changelog-derived release notes. The project does not build or upload release binaries.

## Architecture

- `src/manifests/`: manifest discovery plus supported lockfile parsing and dependency enrichment.
- `src/fetcher/`: host-policy-controlled HTTP(S), integrity checking, safe extraction, Deno graphs, and cache management.
- `src/scanner/`: bounded source traversal, Tree-sitter query evaluation, file-level checks, locations, and stable finding IDs.
- `src/rules/`: versioned built-in and GuardDog-inspired Tree-sitter rule catalog plus JSON/YAML rule-pack loading.
- `src/engine/`: breadth-first dependency traversal, resolved-identity cycle detection, and partial structured reports.
- `src/model/`: dependency, policy, finding, limits, provenance, and report types.
- `src/app/`: CLI, configuration layering, remote-root selection, report rendering, and report-based exit-status selection.
- `src/error.rs`: typed operational errors.
