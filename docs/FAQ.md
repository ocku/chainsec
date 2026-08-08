# Frequently asked questions

## Does `chainsec` install or run the packages it scans?

No. Package source is parsed, never installed or executed. Acquisition and extraction are implemented in Rust; `chainsec` does not launch `python`, package managers, Git, shell commands, or archive executables. Install hooks such as npm `preinstall`/`install`/`postinstall` and `setup.py` are reported as findings but never run.

## Why is network access off by default?

Scanning untrusted dependency source should not require trusting the network. Network access is disabled unless you pass `--online` or select a remote root with `--remote`, and each requested host must be explicitly allowed through `allowed_hosts`, `--allow-host`, a `--remote` selector, or a configured Artifactory metadata endpoint. Artifact hosts returned by registry metadata and redirects are checked against the same allowlist. This keeps the default local-scan path fully offline and auditable.

## What does `--allow-unlocked` do?

By default, a dependency must be fully identified by a supported lockfile (exact version plus integrity). `--allow-unlocked` relaxes that for supported PyPI and npm registry requirements: the highest release matching the declared version range is selected and pinned to the registry-published artifact URL and integrity before download. It never downloads unverified remote artifacts. Unsupported unlocked forms remain unresolved.

## Can I scan only my own project without dependencies?

Yes. `chainsec --max-depth 0` scans only the root project and does not traverse dependencies. This is also the recommended way to verify an installation.

## How do I scan dependencies safely?

Use a locked project and an explicit network policy:

```sh
chainsec /path/to/project \
  --online \
  --allow-host pypi.org \
  --allow-host files.pythonhosted.org \
  --allow-host registry.npmjs.org \
  --format sarif \
  --output report.sarif
```

Narrow exact hosts are safer than wildcards. Prefer HTTPS; HTTP is plaintext.

## What does the exit code mean?

| Code | Meaning |
| --- | --- |
| `0` | Scan completed below the finding threshold |
| `1` | At least one finding met the threshold |
| `2` | Invalid input or configuration |
| `3` | Manifest, scan, resolution, or fetch issue |
| `4` | Policy or resource-limit violation |

See [Rules, reports, and exit status](RULES_AND_REPORTS.md) for the full precedence rules.

## How do I ignore a rule or a package?

- `--ignore-rule <GROUP:GLOB>` omits matching rules from scanning and reports, for example `--ignore-rule network:*` or `--ignore-rule filesystem:PY005`. `--exclude-rule` is a compatibility alias.
- `ignored_packages = ["npm:legacy-package@1.2.3"]` in `chainsec.toml` omits a resolved dependency before it is fetched or scanned.
- `ignored_paths = ["tests/**"]` omits paths from the root project scan only; dependency source is unaffected.

## How do I add my own rules?

Write a JSON or YAML rule pack with a non-empty `rules` array, each rule supplying `id`, `version`, `language`, `finding_type`, `risk`, `confidence`, `rationale`, `remediation`, and a Tree-sitter `query` with an `@match` capture. Load it with `--rule-pack <path>` (repeatable) or `rule_packs` in `chainsec.toml`. See [Rules, reports, and exit status](RULES_AND_REPORTS.md).

## Where is the cache, and can I move or purge it?

When the current directory contains `chainsec.toml`, the default cache is `.chainsec-cache` there. Otherwise, ChainSec uses `$XDG_CACHE_HOME/chainsec`, then `$HOME/.cache/chainsec`, and finally the system temporary directory. Set `--cache <dir>` or `cache` in `chainsec.toml` to choose a different location. Run `chainsec --cache-purge` to delete the resolved cache without scanning, or combine it with `--cache <dir>` to purge a specific cache. Cache entries are content-identified, published atomically, and validated on every hit. The Docker image uses `/cache`.

## Does `chainsec` guarantee a package is safe?

No. Static analysis reduces risk but is not a malware-containment boundary and does not guarantee that source is benign. See the [security model](SECURITY_MODEL.md) for the precise trust model and remaining limitations.

## Which ecosystems and lockfiles are supported?

Python (PEP 621 and Poetry declarations; `poetry.lock`, `Pipfile.lock`, `uv.lock`, `pdm.lock`), npm (lock/shrinkwrap 1–3, Yarn Classic, Yarn Berry 4–8, pnpm 5.3/5.4/6/9), Deno (`deno.lock` versions 1–4), and public GitHub full-commit references. See [Dependency resolution and acquisition](RESOLUTION.md) for details and limitations.
