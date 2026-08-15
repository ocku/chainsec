# GitHub Action

`chainsec` ships a GitHub Action that runs a remote version diff against a package selector. It compares the latest published releases and applies your repository's `chainsec.toml` policy to findings, capabilities, host allowlists, suppressions, and limits.

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
          package: npm:express
          last: 2
          max-package-depth: 2
          allow-host: "registry.npmjs.org"
```

Pin to a tag or full commit SHA rather than `@main` in production to make the action reproducible:

```yaml
- uses: ocku/chainsec@v0.5.0
```

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `package` | yes | — | Package selector: `npm:express`, `npm:express@0.1.0`, `pypi:urllib3`, or `jsr:@std/fs`. GitHub commit selectors are not supported because remote version diffs require registry release history. |
| `last` | no | `2` | Number of latest releases to compare. Minimum 2, and the command fails if fewer than two pullable releases remain. |
| `max-package-depth` | no | `2` | Maximum dependency traversal depth. `0` scans only the selected root package. |
| `fail-on` | no | `high` | Finding threshold for exit code `1`. One of `low`, `medium`, `high`, or `critical`. |
| `format` | no | `human` | Report format. `human` or `json`. SARIF is not available for version diffs. |
| `allow-host` | no | — | Space-separated additional hosts to allow, added to `allowed_hosts` from `chainsec.toml`. |
| `config-dir` | no | `.` | Directory containing `chainsec.toml`, relative to the repository root. |
| `cache` | no | `.chainsec-cache` | Directory used for content-identified dependency source. |
| `threads` | no | `16` | Maximum concurrency for package downloads, package analysis, and source-file analysis. |

## How configuration is merged

The action changes into `config-dir` before running, so `chainsec` reads the repository's `chainsec.toml` and applies it as project configuration.

- Values present in `chainsec.toml` apply to the scan unless an action input overrides the corresponding CLI option.
- `allow-host` is additive: it extends `allowed_hosts` from `chainsec.toml`; it cannot narrow the configured allowlist.
- Remote commands enable online mode automatically, so `online = true` is not required in `chainsec.toml`. Artifact and metadata hosts still need to be allowed through configuration or `allow-host`.
- Suppressions, `ignored_rules`, `ignored_packages`, `rule_packs`, and `no_default_rules` from `chainsec.toml` all apply.

If no `chainsec.toml` is present in `config-dir`, the action emits a warning and runs with CLI defaults.

## Version diffs

The action invokes:

```sh
chainsec remote diff <package> \
  --last <last> \
  --max-package-depth <max-package-depth> \
  --fail-on <fail-on> \
  --format <format> \
  --threads <threads> \
  --cache <cache> \
  [--allow-host <host> ...]
```

`--last N` selects the newest pullable release and up to `N - 1` older integrity-pinnable releases in ecosystem-native version order. With the default `--last 2`, the two most recent pullable releases are compared.

Finding-based exit status compares occurrence identities between the oldest and newest endpoints, normalizing package versions, so a detection that moved between files or versions is recognized as changed even when grouped counts stay equal. See [Dependency resolution and acquisition](RESOLUTION.md) and [Rules, reports, and exit status](RULES_AND_REPORTS.md) for the exact diff and exit-code semantics.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Diff completed below the finding threshold |
| `1` | At least one finding met the threshold |
| `2` | Invalid input or configuration |
| `3` | Manifest, scan, resolution, or fetch issue |
| `4` | Policy or resource-limit violation |

The full precedence rules are in [Rules, reports, and exit status](RULES_AND_REPORTS.md).

## Example: JSON output for downstream processing

```yaml
- uses: ocku/chainsec@v0.5.0
  with:
    package: pypi:urllib3
    last: 2
    max-package-depth: 2
    format: json
    allow-host: "pypi.org files.pythonhosted.org"
```

JSON version-diff reports use schema version `1.0.0` with `report_type: "version_diff"`. They include every detection, regardless of `fail-on`, in the [version-diff schema](schema/version-diff.schema.json).

## Caching

The action writes fetched dependency source to `--cache` inside the runner workspace. To persist it across runs, add a GitHub Actions cache step or reuse the same cache directory; otherwise the cache is discarded when the job ends.
