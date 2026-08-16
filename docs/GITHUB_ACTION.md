# GitHub Action

`chainsec` ships a GitHub Action that scans your current project against your repository's `chainsec.toml` policy. It checks out and analyzes the project, applying findings, capabilities, host allowlists, suppressions, and limits from configuration.

The action is defined in [`action.yml`](../action.yml) and uses the published container image. It does not build `chainsec` in the consuming workflow.

## Basic usage

```yaml
name: Dependency audit

on:
  schedule:
    - cron: "0 6 * * 1"  # every Monday at 06:00 UTC
  workflow_dispatch:

jobs:
  chainsec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ocku/chainsec@main
        with:
          max-package-depth: 2
          allow-host: "registry.npmjs.org"
```

Pin to a tag or full commit SHA rather than `@main` in production to make the action reproducible:

```yaml
- uses: ocku/chainsec@v0.6.0
```

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `max-package-depth` | no | `2` | Maximum dependency traversal depth. `0` scans only the current project. |
| `fail-on` | no | `high` | Finding threshold for exit code `1`. One of `low`, `medium`, `high`, or `critical`. |
| `format` | no | `human` | Report format. `human` or `json`. SARIF is also available. |
| `allow-host` | no | — | Space-separated additional hosts to allow, added to `allowed_hosts` from `chainsec.toml`. |
| `config-dir` | no | `.` | Directory containing `chainsec.toml`, relative to the repository root. |
| `cache` | no | `.chainsec-cache` | Directory used for content-identified dependency source. |
| `threads` | no | `16` | Maximum concurrency for package downloads, package analysis, and source-file analysis. |

## How configuration is merged

The action changes into `config-dir` before running, so `chainsec` reads the repository's `chainsec.toml` and applies it as project configuration.

- Values present in `chainsec.toml` apply to the scan unless an action input overrides the corresponding CLI option.
- `allow-host` is additive: it extends `allowed_hosts` from `chainsec.toml`; it cannot narrow the configured allowlist.
- The action enables online mode via `--online`, so `online = true` is not required in `chainsec.toml`. Artifact and metadata hosts still need to be allowed through configuration or `allow-host`.
- Suppressions, `ignored_rules`, `ignored_packages`, `rule_packs`, and `no_default_rules` from `chainsec.toml` all apply.

If no `chainsec.toml` is present in `config-dir`, the action emits a warning and runs with CLI defaults.

## What the action runs

The action invokes:

```sh
chainsec scan . \
  --online \
  --max-package-depth <max-package-depth> \
  --fail-on <fail-on> \
  --format <format> \
  --threads <threads> \
  --cache <cache> \
  [--allow-host <host> ...]
```

Finding-based exit status compares occurrence identities against the configured `fail-on` threshold. See [Dependency resolution and acquisition](RESOLUTION.md) and [Rules, reports, and exit status](RULES_AND_REPORTS.md) for the exact scan and exit-code semantics.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed below the finding threshold |
| `1` | At least one finding met the threshold |
| `2` | Invalid input or configuration |
| `3` | Manifest, scan, resolution, or fetch issue |
| `4` | Policy or resource-limit violation |

The full precedence rules are in [Rules, reports, and exit status](RULES_AND_REPORTS.md).

## Example: JSON output for downstream processing

```yaml
- uses: ocku/chainsec@v0.6.0
  with:
    max-package-depth: 2
    format: json
    allow-host: "pypi.org files.pythonhosted.org"
```

JSON reports use schema version `1.2.0` and include every detection in the [report schema](schema/report.schema.json).

## Caching

The action writes fetched dependency source to `--cache` inside the runner workspace. To persist it across runs, add a GitHub Actions cache step or reuse the same cache directory; otherwise the cache is discarded when the job ends.
