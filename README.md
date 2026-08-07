# chainsec

`chainsec` is a recursive static source scanner for Python, JavaScript, and TypeScript projects. It discovers dependency declarations, enriches them from supported lockfiles, safely acquires verified source artifacts, scans source with versioned Tree-sitter rules, and emits JSON, SARIF, or terminal reports.

Package source is parsed, never installed or executed. Acquisition and extraction are implemented in Rust; `chainsec` does not launch `python`, package managers, Git, shell commands, or archive executables.

See the [AI Assistance Notice](AI_NOTICE.md).

![chainsec demo](docs/assets/demo.gif)

## Safe defaults

- Network access is off unless `--online` is supplied.
- Online mode requires one or more explicit `--allow-host` values; redirects are checked against the same policy.
- Dependencies must have a resolved version and integrity from a supported lockfile unless `--allow-unlocked` is supplied.
- HTTP and HTTPS are accepted for remote acquisition; other URL schemes are rejected. Prefer HTTPS because HTTP is plaintext.
- Supported registry and Deno artifact/module integrity values are checked before extraction or analysis. GitHub full-commit archives use the commit as their immutable identity; their downloaded SHA-256 is recorded for provenance but is not lockfile-supplied and cannot be independently checked against a declared artifact digest.
- Archive paths are confined beneath extraction roots; links, special files, and duplicate entries are rejected. Tar-family paths are limited to 128 components; ZIP/wheel paths are traversal-checked but do not have the same explicit component-depth limit.
- Downloads, extraction, source files, package count, graph depth, Deno graph size, redirects, requests, and per-package scan duration are bounded.
- Cache entries use resolved identities, are published atomically, and validate their package identity and extracted-tree digest on every hit.

For the precise trust model and remaining limitations, see [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md). To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## Quick start

Local/offline scan:

```sh
chainsec --max-depth 0
```

Locked dependency scan with an explicit network policy:

```sh
chainsec /path/to/project \
  --online \
  --allow-host pypi.org \
  --allow-host files.pythonhosted.org \
  --allow-host registry.npmjs.org \
  --allow-host deno.land \
  --allow-host jsr.io \
  --allow-host codeload.github.com \
  --format sarif \
  --output report.sarif
```

Create a starter project configuration:

```sh
chainsec --init
```

## Documentation

- [Installation](docs/INSTALLATION.md)
- [Configuration and CLI reference](docs/CONFIGURATION.md)
- [Dependency resolution and acquisition](docs/RESOLUTION.md)
- [Rules, reports, and exit status](docs/RULES_AND_REPORTS.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Development and releases](docs/DEVELOPMENT.md)
- [Third-party notices](docs/THIRD_PARTY.md)
